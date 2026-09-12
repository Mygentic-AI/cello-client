/**
 * What a session has actually received, read the way production reads it.
 *
 * ── WHY THIS EXISTS ──────────────────────────────────────────────────────────────────────────────
 *
 * Tests used to ask this question with `takeReceivedContent`, a destructive `shift()` off an
 * in-memory arrival buffer. That buffer stopped being how messages reach an agent at DOD-COATTEND-1,
 * when delivery moved onto the durable transcript, and by the time DOD-M15-AWAYSCOPE-1 removed the
 * away responder's peek at it, nothing in production read it at all — it was copying the plaintext
 * of every arriving message into daemon memory for the life of the process with no consumer. It is
 * deleted, and this is what the tests that used it ask instead.
 *
 * ── WHY THE ANSWER IS THE SAME, AND WHERE IT IS STRONGER ────────────────────────────────────────
 *
 * `appendVerifiedContent` writes the transcript row and pushes to the buffer at the same point,
 * behind the same gate — the row first, then the push. So anything that reached the buffer reached
 * the transcript, and anything stopped before the buffer was stopped before the row. The two signals
 * were never able to disagree about whether a message got through.
 *
 * Where they differ, the transcript is the stronger question, and deliberately so: it is what
 * `cello_receive` serves, so a test asking it is asking what the OPERATOR would be handed rather
 * than what a buffer nothing reads happened to hold.
 *
 * ⚠️ `quarantined` IS NOT `received`, and that distinction is load-bearing for the gate and
 * quarantine suites: content the security gateway blocked, or that arrived after a session
 * committed, lands as its own direction. "The agent never sees it" means no RECEIVED row, and a
 * helper that counted quarantined rows too would turn those assertions green for the wrong reason.
 *
 * ── READING IS NOT DRAINING ─────────────────────────────────────────────────────────────────────
 *
 * `takeReceivedContent` removed what it returned, so a test could drain three and then assert the
 * fourth call was null. Nothing is consumed here. The equivalent assertion is a COUNT: three
 * received rows and no more. That is the better shape anyway — a drain-then-null pair passes if the
 * fourth message was never written, and a count does not.
 */

import type { SessionNodeManager } from "../../session-node-manager.js";
import type { TranscriptEntry } from "../../session-node-types.js";

/** Every message this session has received and decrypted, in sequence order. Non-destructive. */
export function receivedRows(
  mgr: Pick<SessionNodeManager, "readTranscript">,
  agentName: string,
  sessionId: string,
): TranscriptEntry[] {
  return mgr.readTranscript(agentName, sessionId).messages.filter((m) => m.direction === "received");
}

/** How many messages reached the agent. `0` is "nothing got through", not "nothing arrived". */
export function receivedCount(
  mgr: Pick<SessionNodeManager, "readTranscript">,
  agentName: string,
  sessionId: string,
): number {
  return receivedRows(mgr, agentName, sessionId).length;
}

/** The text of the n-th received message, or `null` if there is no such message yet. */
export function receivedText(
  mgr: Pick<SessionNodeManager, "readTranscript">,
  agentName: string,
  sessionId: string,
  index = 0,
): string | null {
  return receivedRows(mgr, agentName, sessionId)[index]?.text ?? null;
}
