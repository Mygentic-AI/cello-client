/**
 * The session starting point a fixture has to supply, and why every content fixture needs one.
 *
 * ─── What production does that a fixture does not ──────────────────────────────────────────────
 *
 * A real session is opened by a directory-brokered, FROST-signed assignment, and the starting point
 * of its chain is derived from that assignment's own fields — the two participants, the session id,
 * and the session timestamp. Both sides derive the SAME value independently, and each writes it to
 * its session row. Nothing about it is negotiable and nothing about it is optional.
 *
 * A fixture that calls `createSessionNode` directly never sees an assignment, so it has no starting
 * point — and since `DOD-M15-SELFCHAIN-1` every message carries two links that must anchor to one.
 * Without this, a send is refused for having nothing to chain to, and an inbound frame is refused
 * for the same reason at the other end. The test would then be exercising a refusal path rather
 * than the behaviour it was written for, and would keep passing if the behaviour were deleted.
 *
 * ─── The two rules that make it work ───────────────────────────────────────────────────────────
 *
 * 1. **BOTH SIDES GET THE SAME VALUE.** The receiver checks the sender's self link against its own
 *    record of what the sender last said, seeded from the starting point. Two sides holding
 *    different values is exactly the shape of a tampered chain, and the receiver will say so.
 * 2. **SEEDED BEFORE `createSessionNode`.** Registering the session is what copies the starting
 *    point into the relay client's acknowledgement state. Seeding afterwards leaves that state
 *    empty and the first send is refused.
 */
import type { SessionNodeManager } from "../../session-node-manager.js";

/**
 * A recognisable fill, not zeros. An all-zero default is what a value that was never set looks
 * like, so a test asserting against zeros cannot tell "we agreed on this" from "nobody set it".
 */
export const TEST_SESSION_GENESIS = new Uint8Array(32).fill(0x9c);

/**
 * Give every participating manager the same session starting point, before any of them creates the
 * session node. Call it once per session, with every manager that takes part.
 */
export function agreeSessionGenesis(
  sessionId: string,
  participants: ReadonlyArray<{ mgr: SessionNodeManager; agentName: string }>,
): void {
  for (const p of participants) {
    p.mgr.setSessionGenesisForTest(p.agentName, sessionId, TEST_SESSION_GENESIS);
  }
}
