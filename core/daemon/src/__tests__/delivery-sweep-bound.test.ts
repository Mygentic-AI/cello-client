/**
 * DOD-MP-SWEEP-ALIVE-1 — a hung pass must not disable document delivery forever.
 *
 * The daemon's sweep is guarded against overlap by a boolean that is released in the `finally` of
 * an async body. A `finally` runs when the body SETTLES — so a thrown error is covered (there is a
 * `catch`), and an await that never settles is not. One hung pass therefore wedges the guard
 * permanently: the timer keeps firing every 60s, hits `if (running) return`, and emits NOTHING.
 *
 * Observed live 2026-08-13: the last completion line was 17:06:28, delivery work carrying a `dlv-`
 * correlation id happened at 17:07:38, and no sweep ever completed again. The daemon stayed healthy
 * and kept logging other subsystems throughout, and an edit sat undelivered with nothing attempting
 * it while the document reported healthy.
 *
 * This bounds the CLASS rather than the guessed instance. Which await hung is not established, so a
 * fix that closes only the suspected one would be a guess wearing a fix's clothes.
 */

import { describe, it, expect } from "vitest";
import { runAgentPassBounded } from "../delivery-sweep-bound.js";

function recorder() {
  const events: Array<{ event: string; ctx: Record<string, unknown> }> = [];
  return {
    events,
    logger: { warn: (event: string, ctx: Record<string, unknown>) => { events.push({ event, ctx }); } },
  };
}

/** A pass that never settles — the exact shape a hung dial has. */
const neverSettles = () => new Promise<number>(() => {});

describe("DOD-MP-SWEEP-ALIVE-1 — one hung pass cannot wedge the sweep", () => {
  it("returns instead of hanging when the pass never settles", async () => {
    const r = recorder();
    const res = await runAgentPassBounded(
      { logger: r.logger, timeoutMs: 20, agentName: "alice" },
      neverSettles,
    );
    // THE WHOLE DEFECT IN ONE ASSERTION: before this, the await above never returned, the guard's
    // `finally` never ran, and every subsequent tick returned at the overlap check having logged
    // nothing. Delivery was over for the life of the process.
    expect(res.completed).toBe(false);
  });

  it("says so LOUDLY — a stuck sweep is the one thing this subsystem must never do quietly", async () => {
    const r = recorder();
    await runAgentPassBounded(
      { logger: r.logger, timeoutMs: 20, agentName: "alice" },
      neverSettles,
    );
    const ev = r.events.find((e) => e.event === "document.delivery.pass.stuck");
    expect(ev, "an operator grepping for a silent stall must find a line naming it").toBeDefined();
    expect(ev!.ctx["agentName"]).toBe("alice");
    expect(ev!.ctx["timeoutMs"]).toBe(20);
  });

  it("a SECOND pass still runs after the first one hung — the wedge does not persist", async () => {
    const r = recorder();
    await runAgentPassBounded({ logger: r.logger, timeoutMs: 20, agentName: "alice" }, neverSettles);
    // The recovery clause. A bound that reports the stall but leaves the caller unable to sweep
    // again would trade a silent outage for a loud one, which is not a fix.
    const second = await runAgentPassBounded(
      { logger: r.logger, timeoutMs: 20, agentName: "alice" },
      async () => 7,
    );
    expect(second).toEqual({ completed: true, value: 7 });
  });

  it("a pass that finishes in time is untouched — no bound, no warning, its value returned", async () => {
    const r = recorder();
    const res = await runAgentPassBounded(
      { logger: r.logger, timeoutMs: 1_000, agentName: "alice" },
      async () => 42,
    );
    expect(res).toEqual({ completed: true, value: 42 });
    // A warning on the healthy path teaches an operator to ignore the event that matters.
    expect(r.events).toEqual([]);
  });

  it("a pass that THROWS still propagates — containment belongs to the caller, not the bound", async () => {
    const r = recorder();
    // The daemon's existing `catch` logs `document.delivery.tick.failed` and its `finally` releases
    // the guard. Swallowing the throw here would silently delete that path's error reporting.
    await expect(
      runAgentPassBounded({ logger: r.logger, timeoutMs: 1_000, agentName: "alice" }, async () => {
        throw new Error("dial refused");
      }),
    ).rejects.toThrow("dial refused");
    expect(r.events).toEqual([]);
  });

  it("does not hold the process open waiting for its own timer", async () => {
    const r = recorder();
    const started = Date.now();
    await runAgentPassBounded(
      { logger: r.logger, timeoutMs: 5_000, agentName: "alice" },
      async () => "done",
    );
    // The timer must be cleared when the pass wins the race. Left armed, every sweep would pin a
    // 5s timer per agent per minute forever — and on a daemon whose whole point is to keep running,
    // that is a leak that only shows up in production.
    expect(Date.now() - started).toBeLessThan(1_000);
  });
});
