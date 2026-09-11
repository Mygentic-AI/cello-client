/**
 * DOD-M15-IDLERETRY-1 — **THE WATCHDOG OPENED A RETRY LADDER FOR AGENTS THAT NEED NOTHING.**
 *
 * ─── Found live, not in a test, which is the part worth recording ──────────────────────────────
 *
 * The first real calls between two agents against the deployed fleet, 2026-09-11. Calls worked; the
 * slot was taken on the call and given back at the seal. But afterwards `cello_status` reported
 * `retrying` for BOTH agents, permanently, cleared only by a daemon restart.
 *
 * The chain, established by reading the shipped code and then confirmed by experiment:
 *
 *   1. The reservation watchdog's zero-held branch called `#retryDue(agentName)` FIRST.
 *   2. `#retryDue` does not merely answer a question. On an agent it has not seen it WRITES a retry
 *      entry — `// First sighting — schedule, do not fire.` — logs nothing, and returns false.
 *   3. `getStandingReceiverReachability` asks only whether an entry exists. It existed. So the
 *      field said `retrying` while `attempts` was still 0 and nothing had ever been attempted.
 *   4. Nothing clears that entry when a session ends.
 *
 * **And the INITIATOR of a call can never need what the ladder is for.** 055-ONDEMAND narrowed the
 * reservation to the party being DIALED, deliberately: the initiator dials out, and the connection
 * is bidirectional once made. So for the caller this state was not merely stale, it was never
 * appropriate.
 *
 * ⚠️ **IT IS NOT COSMETIC, which is why this is its own unit and not a status-string patch.** Held
 * past the retry interval, both agents emitted a real `session.standing_receiver.reservation.retry`
 * — the daemon asking relays for slots on behalf of sessions that need none. Churn against the one
 * resource this entire story exists to conserve, produced by the mechanism meant to protect it.
 *
 * ─── What this pins ───────────────────────────────────────────────────────────────────────────
 *
 * The fix is ordering: work out whether ANY live session actually lacks its circuit before touching
 * the budget. A tick with nothing to do must leave no trace — no retry entry, no status change, no
 * ask against a relay.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager } from "../session-node-manager.js";
import { ProductionSessionNodeFactory } from "../daemon.js";
import { seedAgents } from "./helpers/seed-agents.js";
import type { Logger } from "../types.js";

interface LogEvent { event: string; context: Record<string, unknown> }
function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const push = (event: string, context?: Record<string, unknown>) => { events.push({ event, context: context ?? {} }); };
  return { logger: { debug: push, info: push, warn: push, error: push }, events };
}

describe("DOD-M15-IDLERETRY-1: a tick with nothing to re-take leaves no trace", () => {
  let tempDir = "";
  let manager: SessionNodeManager | null = null;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-idleretry-"));
    process.env["CELLO_LISTEN_ADDR"] = "/ip4/127.0.0.1/tcp/0";
  });
  afterEach(async () => {
    delete process.env["CELLO_LISTEN_ADDR"];
    if (manager) await manager.gracefulShutdown();
    manager = null;
    await rm(tempDir, { recursive: true, force: true });
  });

  async function makeManager(logger: Logger): Promise<SessionNodeManager> {
    const m = new SessionNodeManager({
      securityGateway: new PassthroughGatewayClient(),
      factory: new ProductionSessionNodeFactory(),
      logger,
      dbPath: join(tempDir, "sessions.db"),
      standingReceiverRetryDelaysMs: [],
      // A fast watchdog so many ticks land inside the test, and a retry interval short enough that
      // a ladder, if one were opened, would actually FIRE rather than merely be scheduled.
      standingReceiverWatchdogIntervalMs: 60,
      standingReceiverReservationRetryMs: 1,
    });
    await m.initialize();
    await seedAgents(m.getDb(), ["alice"]);
    return m;
  }

  it("★★★ an agent in a session that needs no circuit stays READY, and asks no relay for a slot", async () => {
    const { logger, events } = makeLogger();
    manager = await makeManager(logger);
    await manager.ensureStandingReceiverForAgent("alice");

    /**
     * A live session whose node holds no circuit and has NO persisted relay endpoint — the shape an
     * INITIATOR has. It dialled out; nobody needs to dial it; there is nothing to re-take. Many
     * watchdog ticks pass over it.
     */
    const opened = await manager.createSessionNode(
      "aa".repeat(16), "alice", "cc".repeat(32), "12D3KooWCounterparty", "corr", false,
    );
    expect(opened.ok, JSON.stringify(opened)).toBe(true);

    await new Promise((r) => setTimeout(r, 800)); // ~13 ticks at 60ms

    expect(
      manager.getStandingReceiverReachability("alice"),
      "nothing is being retried, so the field must not say so. Before this fix the first tick wrote " +
        "a retry entry as a side effect of ASKING whether a retry was due, and the status read that " +
        "entry as a fault — permanently, for an agent that was working perfectly",
    ).toBe("ready");

    expect(
      events.filter((e) => e.event === "session.standing_receiver.reservation.retry"),
      "and no relay is asked for a slot on behalf of a session that does not need one. This is the " +
        "half that is not cosmetic: it is churn against the scarce resource the whole story exists " +
        "to conserve, produced by the machinery meant to protect it",
    ).toEqual([]);
  }, 30_000);

  it("★★★ a ladder that was legitimately opened is CLEARED when the session ends", async () => {
    /**
     * ⚠️ **THE SECOND HALF, AND 061 SHIPPED WITHOUT IT.** 061 stopped a ladder being OPENED for a
     * session that needs nothing. A ladder opened for a session that genuinely DID need its circuit
     * back is correct — and becomes moot the moment that session ends. Nothing cleared it, and the
     * entry is the only thing the status field consults, so the agent went on reporting `retrying`
     * and eventually `unreachable` with no session at all.
     *
     * Caught on the shipped 0.0.217 build: an agent with zero live sessions reading `retrying`,
     * which is only reachable through a stale entry.
     */
    const { logger } = makeLogger();
    manager = await makeManager(logger);
    await manager.ensureStandingReceiverForAgent("alice");

    // A session that DOES want a circuit: a persisted relay endpoint and a node holding none.
    // ⚠️ The endpoint is written AFTER the node exists — `createSessionNode` is what inserts the
    // row, so an UPDATE before it silently matches nothing. The first version of this test did
    // exactly that, never opened a ladder, and therefore passed with the fix REMOVED. The
    // precondition below is what makes that impossible to repeat.
    const sid = "bb".repeat(16);
    const opened = await manager.createSessionNode(sid, "alice", "cc".repeat(32), "12D3KooWCp", "corr", false);
    expect(opened.ok, JSON.stringify(opened)).toBe(true);
    manager.getDb().prepare(
      `UPDATE sessions SET relay_peer_id = ?, relay_addrs = ? WHERE session_id = ?`,
    ).run("12D3KooWRelayX", JSON.stringify(["/ip4/127.0.0.1/tcp/4001"]), sid);

    await new Promise((r) => setTimeout(r, 500));
    expect(
      manager.getStandingReceiverReachability("alice"),
      "PRECONDITION: a ladder must actually be open, or this test proves nothing about clearing one",
    ).not.toBe("ready");

    // End it. From here the agent wants nothing at all.
    await manager.destroySessionNode("alice", sid, "sealed");
    await new Promise((r) => setTimeout(r, 500)); // several ticks with no session

    expect(
      manager.getStandingReceiverReachability("alice"),
      "with no session there is nothing to retry, so a ladder left over from one that ended must " +
        "not keep the agent looking broken — it survived a restart-or-nothing before this",
    ).toBe("ready");
  }, 30_000);

  it("an agent with NO live session is untouched by the watchdog, as before", async () => {
    const { logger, events } = makeLogger();
    manager = await makeManager(logger);
    await manager.ensureStandingReceiverForAgent("alice");

    await new Promise((r) => setTimeout(r, 500));

    expect(manager.getStandingReceiverReachability("alice")).toBe("ready");
    expect(events.filter((e) => e.event === "session.standing_receiver.reservation.retry")).toEqual([]);
  }, 30_000);
});
