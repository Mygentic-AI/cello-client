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

import { describe, it, expect, vi } from "vitest";
import { runAgentPassBounded, sweepAgentEvicting } from "../delivery-sweep-bound.js";

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

  it("clears its timer when the pass wins — asserted on the TIMER, not on elapsed time", async () => {
    vi.useFakeTimers();
    try {
      const r = recorder();
      const res = await runAgentPassBounded(
        { logger: r.logger, timeoutMs: 5_000, agentName: "alice" },
        async () => "done",
      );
      expect(res).toEqual({ completed: true, value: "done" });
      // The previous version of this test measured elapsed wall-clock, which stays small whether or
      // not the timer is cleared — it went green with `clearTimeout` removed AND with `unref`
      // removed on top of that, so it could not detect the leak it was named after. A pass per agent
      // per minute, each pinning a 5s timer, is a leak that only shows up on a long-lived daemon.
      expect(vi.getTimerCount(), "the bound's timer must not outlive the pass").toBe(0);
    } finally {
      vi.useRealTimers();
    }
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

});

/**
 * The CALL SITE, which is where the defect actually lives.
 *
 * Every test above exercises the helper. Revert only the daemon wiring — go back to a bare
 * `await tick(...)` — and they all stay green, because none of them can see the guard release. These
 * drive the eviction step against a runner carrying the SAME cached-promise re-entry guard that
 * `DocumentDelivery.tick` has, which is the structure that makes a hang permanent.
 */
describe("DOD-MP-SWEEP-ALIVE-1 — the wedged agent's worker is EVICTED, so it delivers again", () => {
  /** A worker with `DocumentDelivery.tick`'s exact shape: the pass is cached until it settles. */
  function reentrantWorker(run: () => Promise<string>) {
    let inFlight: Promise<string> | null = null;
    let entries = 0;
    return {
      entries: () => entries,
      tick: () => {
        if (inFlight) return inFlight;
        entries += 1;
        const p = run();
        inFlight = p;
        return p.finally(() => { inFlight = null; });
      },
    };
  }

  it("without eviction the agent would never deliver again — with it, the next pass re-enters", async () => {
    const r = recorder();
    const workers = new Map<string, ReturnType<typeof reentrantWorker>>();
    const hang = { on: true };
    const build = () => reentrantWorker(() => (hang.on ? new Promise<string>(() => {}) : Promise.resolve("swept")));
    const workerFor = (name: string) => {
      let w = workers.get(name);
      if (!w) { w = build(); workers.set(name, w); }
      return w;
    };

    const first = await sweepAgentEvicting({
      logger: r.logger, timeoutMs: 20, agentName: "alice",
      workers, run: () => workerFor("alice").tick(),
    });
    expect(first.completed).toBe(false);
    // THE FIX, IN ONE ASSERTION: the wedged worker is gone, so the next tick cannot be handed the
    // same hung promise. Leave it in place and `tick()` returns the cached hang forever — the agent
    // is finished for the life of the process and every later pass burns the full bound on it.
    expect(workers.has("alice"), "the wedged worker must be dropped").toBe(false);

    hang.on = false;
    const second = await sweepAgentEvicting({
      logger: r.logger, timeoutMs: 20, agentName: "alice",
      workers, run: () => workerFor("alice").tick(),
    });
    expect(second).toEqual({ completed: true, value: "swept" });
  });

  it("a healthy pass keeps its worker — eviction is for the wedge, not for everyone", async () => {
    const r = recorder();
    const workers = new Map<string, unknown>();
    workers.set("alice", { kept: true });
    const res = await sweepAgentEvicting({
      logger: r.logger, timeoutMs: 1_000, agentName: "alice",
      workers, run: async () => "fine",
    });
    expect(res).toEqual({ completed: true, value: "fine" });
    // Dropping a healthy worker every pass would discard its in-memory state for no reason.
    expect(workers.has("alice")).toBe(true);
    expect(r.events).toEqual([]);
  });

  it("a pass that fails LATE is still reported — the evidence is not swallowed by the race", async () => {
    const r = recorder();
    const workers = new Map<string, unknown>();
    let boom: (e: Error) => void = () => {};
    const late = new Promise<string>((_res, rej) => { boom = rej; });
    await sweepAgentEvicting({
      logger: r.logger, timeoutMs: 20, agentName: "alice", workers, run: () => late,
    });
    boom(new Error("dial never completed"));
    await new Promise((res) => setTimeout(res, 10));
    // The race has already settled, so this rejection would otherwise vanish — discarding the one
    // piece of evidence that names WHICH await hung, on a defect whose root cause is still open.
    const ev = r.events.find((e) => e.event === "document.delivery.pass.late_failure");
    expect(ev, "a late failure from an abandoned pass must still be logged").toBeDefined();
    expect(String(ev!.ctx["reason"])).toContain("dial never completed");
  });
});
