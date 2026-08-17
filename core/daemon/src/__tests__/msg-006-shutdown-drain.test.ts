/**
 * DOD-M12B-SHUTDOWN-1 — a shutdown that keeps starting new outbound work is not draining.
 *
 * Measured 2026-08-17: `cello logout` reported *"Daemon shutdown did not complete within 5s … it
 * may be stuck closing sessions or its database"*, and the process was still alive **30+ seconds**
 * later. The log shows it was still running `document.reconcile.sweep` DURING shutdown — dialling
 * peers and opening sessions on the way out. The socket had already been removed, so from the
 * operator's side the daemon was down while the process ran on, and it took a signal to exit.
 *
 * `stop()` clears the sweep interval, which stops the NEXT tick. It does nothing about the pass
 * already running: that pass walks every agent, and each step opens sessions. So the fix is a flag
 * the sweep itself honours, not another `clearInterval`.
 *
 * Revert test: delete `stop()`'s body in ReconcileScheduler and the first case fails — a sweep
 * after shutdown reaches `sweepTargets` and attempts a reconcile.
 */
import { describe, it, expect } from "vitest";
import { ReconcileScheduler } from "../document-reconcile-scheduler.js";
import type { Logger } from "../types.js";

interface LogEvent { event: string; context: Record<string, unknown> }

function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const logger: Logger = {
    debug(event, context) { events.push({ event, context: context ?? {} }); },
    info(event, context) { events.push({ event, context: context ?? {} }); },
    warn(event, context) { events.push({ event, context: context ?? {} }); },
    error(event, context) { events.push({ event, context: context ?? {} }); },
  };
  return { logger, events };
}

const OWNER = "owner-agent-id";
const PEER = "peer-agent-id";

/** A scheduler wired to one peer with one document always due, and a counter on the one call that
 *  reaches the network. `initiateReconcile` is what dials and opens a session. */
function makeScheduler(logger: Logger) {
  let now = 1_000_000;
  const calls: string[] = [];
  const scheduler = new ReconcileScheduler({
    now: () => now,
    logger,
    sweepTargets: (ownerAgentId) => {
      calls.push(`sweepTargets:${ownerAgentId}`);
      return new Map([[PEER, ["doc-1"]]]);
    },
    // Never "believed current", so the sweep always has real work to do.
    partySync: () => ({ sync: "diverged" as const, lastSyncedAtMs: null }),
    initiateReconcile: async (_owner, _peer, documentIds) => {
      calls.push(`initiateReconcile:${documentIds.join(",")}`);
      return { ok: true as const };
    },
  });
  return { scheduler, calls, advance: (ms: number) => { now += ms; } };
}

describe("DOD-M12B-SHUTDOWN-1: shutdown stops starting new outbound work", () => {
  it("a sweep after stop() reaches neither the targets nor the network", async () => {
    const { logger } = makeLogger();
    const { scheduler, calls } = makeScheduler(logger);

    // Baseline: the sweep really does reach the network when it is running. Without this the test
    // could pass against a scheduler that never worked at all.
    const before = await scheduler.sweep(OWNER);
    expect(before.attempted, "the fixture must actually attempt a reconcile while running").toBe(1);
    expect(calls).toContain("initiateReconcile:doc-1");

    scheduler.stop();
    calls.length = 0;

    // This is the pass that was still running when the socket had already gone. It must not dial.
    const after = await scheduler.sweep(OWNER);
    expect(after.attempted, "a stopped scheduler must not attempt anything").toBe(0);
    expect(calls, "a stopped scheduler must not even ask what there is to do").toEqual([]);
  });

  it("stop() is idempotent and a stopped scheduler stays stopped", async () => {
    const { logger } = makeLogger();
    const { scheduler, calls, advance } = makeScheduler(logger);
    scheduler.stop();
    scheduler.stop();
    advance(10 * 60_000); // long past any backoff — time must not un-stop it
    const result = await scheduler.sweep(OWNER);
    expect(result.attempted).toBe(0);
    expect(calls).toEqual([]);
  });

  it("the reachability trigger cannot restart sweeping after shutdown", async () => {
    const { logger } = makeLogger();
    const { scheduler, calls } = makeScheduler(logger);
    scheduler.stop();
    calls.length = 0;

    // onReachable zeroes the backoff and sweeps immediately — that is its whole job while running,
    // and it is reachable from the session-created dispatch. A session tearing down during shutdown
    // must not be able to hand the sweeper a fresh reason to dial on the way out.
    await scheduler.onReachable(OWNER, PEER);
    expect(calls, "a shutdown must not be undone by a trigger firing during it").toEqual([]);
  });
});
