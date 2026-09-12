/**
 * DOD-M15-SEALPRECOND-1 — wait for this side's own record to stop moving before signing it.
 *
 * ⚠️ THIS IS NOT A DELAY, AND THE DISTINCTION IS THE WHOLE UNIT. On 2026-09-11 the daemon held the
 * relay's ordering confirmation for 352 milliseconds and signed without it; a 14-millisecond gap
 * and a 14-second gap fail identically, so nothing here may be tuned to a window. What is waited
 * ON is a condition of state — `sealReadiness().ownLeavesOrdered`, the leaves of ours the relay has
 * already ordered and this tree has not placed. The bound exists only so a send that never
 * resolves cannot hold the operator's close forever; it is the escape, not the mechanism.
 *
 * The condition is re-read every poll and the wait returns the instant it clears, which is what a
 * fixed sleep cannot do and what the tests assert.
 */
import type { SessionNodeManager } from "./session-node-manager.js";

/**
 * How long a close may wait for its own in-flight send to take its place in the record.
 *
 * Two seconds against a condition that resolved in 14ms when it was measured. Generous on purpose:
 * the cost of waiting too long is an operator's close taking a moment, and the cost of not waiting
 * is a signature no directory can verify and a receipt that is gone for both parties permanently.
 */
export const SEAL_SETTLE_DEADLINE_MS = 2_000;

/** How often the condition is re-read. Short enough that a settled record is not made to wait. */
const SEAL_SETTLE_POLL_MS = 20;

export type SealSettleOutcome =
  | { settled: true; waitedMs: number }
  | { settled: false; waitedMs: number; ownLeavesOrdered: number };

/**
 * Block until this session has no own leaf the relay has ordered and the tree has not placed.
 *
 * Returns immediately — no timer, no microtask hop beyond the read — when the record is already
 * level, which is every ordinary close.
 */
export async function awaitOwnRecordSettled(
  sessionNodeManager: Pick<SessionNodeManager, "sealReadiness">,
  agentName: string,
  sessionId: string,
  deadlineMs: number = SEAL_SETTLE_DEADLINE_MS,
): Promise<SealSettleOutcome> {
  const started = Date.now();
  let readiness = sessionNodeManager.sealReadiness(agentName, sessionId);
  while (readiness.ownLeavesOrdered > 0 && Date.now() - started < deadlineMs) {
    await new Promise<void>((resolve) => {
      const t = setTimeout(resolve, SEAL_SETTLE_POLL_MS);
      // Never hold the process — or a test runner — open on a session that is going nowhere.
      t.unref?.();
    });
    readiness = sessionNodeManager.sealReadiness(agentName, sessionId);
  }
  const waitedMs = Date.now() - started;
  return readiness.ownLeavesOrdered > 0
    ? { settled: false, waitedMs, ownLeavesOrdered: readiness.ownLeavesOrdered }
    : { settled: true, waitedMs };
}
