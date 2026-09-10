/**
 * ─── WHAT "CLOSED" MEANS, IN ONE PLACE — `DOD-M15-CLOSEDSESSION-1` ────────────────────────────
 *
 * A signed, closed conversation cannot be added to. That is what closing it means, and it is the
 * ordinary end of every session rather than an edge case — so the answer to a send into one is a
 * single sentence and an affordance, not a paragraph about relays.
 *
 * **The defect this module exists to remove.** Measured live 2026-09-10 on session `9d253bce…`:
 * the responder's own seal leaf was submitted and auto-acknowledged, and her very next `cello_send`
 * returned `delivered: true`, `witnessed: false`, and guidance about the relay not witnessing the
 * leaf and about ordering divergence. Every word of that was true and none of it was the point.
 * The relay had retired the session at the seal (`relay_session_gone`), the leaf was appended
 * unwitnessed, the bytes reached the peer, and the peer refused them as `ack_hash_unknown_content`
 * — a hash, described where a situation should have been.
 *
 * **The two facts are DELIBERATELY separate, and only one of them is used to refuse:**
 *
 *  - `isClosedStatus` reads THIS SIDE'S OWN persisted session status. Unambiguous, local, and the
 *    only thing this module lets anything refuse on.
 *  - `relay_session_gone` is NOT here, and must not be added. `delivery-session-suspects.ts`
 *    refuses to make it terminal on evidence: the relay defaults to an in-memory store, so a
 *    restart tells every client the same string for sessions that are perfectly alive. Treating it
 *    as closed would retire every live session on one relay bounce.
 *
 * The wording is deliberately the wording already used by the INGEST refusal (`session_committed`
 * in `session-content-ingest.ts`), which said the right thing before this unit existed and was
 * simply not what the send path returned.
 */
import { REFUSAL_KINDS } from "./refusal-reasons.js";
import type { SessionContentPipelineContext } from "./session-content-context.js";
import type { SessionStatus } from "./types.js";

/**
 * The statuses that mean the record is frozen. All three are terminal and none can be added to.
 *
 * `abandoned` belongs here with the two sealed states even though it carries no notarization: a
 * force-abandoned session has left the open list and there is nothing left to append to. The
 * DIFFERENCE between them is carried in the message (`closedSessionImpact` names the status), never
 * in whether the send is refused.
 */
const CLOSED_STATUSES: ReadonlySet<SessionStatus> = new Set<SessionStatus>([
  "sealed",
  "seal_interrupted_pending",
  "abandoned",
]);

export function isClosedStatus(status: SessionStatus): boolean {
  return CLOSED_STATUSES.has(status);
}

/** The one name a send into a closed conversation is refused by. */
export const SESSION_CLOSED_REASON = "session_closed";

/**
 * ⚠️ ONE LINE PLUS ONE AFFORDANCE, and the brevity is the requirement — not a style preference.
 *
 * The thing being fixed is an answer that was long and about the wrong subject. Anything added here
 * about relays, witnesses or ordering re-introduces exactly that: those are a DIFFERENT condition
 * with their own message, and a live session is where they belong.
 */
export const SESSION_CLOSED_GUIDANCE =
  "This session is closed and cannot be added to. Start a new session if there is more to say.";

/**
 * What became of the message, said in the caller's terms. Names the status so an operator can tell
 * a sealed conversation (there is a receipt) from an abandoned one (there is not) without being
 * asked to care about the distinction to understand the refusal.
 */
export function closedSessionImpact(status: SessionStatus): string {
  return `Nothing was sent. This conversation is closed (it ended as "${status}") — a closed conversation is signed and cannot be added to. No message was placed in your record and nothing reached your counterparty.`;
}

/**
 * The same fact while the ceremony is still RUNNING on this side.
 *
 * This is the case actually measured: the status row still read `active` because the seal had not
 * finished writing, and the send therefore sailed past every status check in the daemon. The seal
 * commitment is a signature over the conversation AS IT STANDS, so a message placed after it is
 * outside the thing being signed — the session is closed from the moment this side commits, not
 * from the moment the row is updated.
 */
export const SESSION_SEALING_IMPACT =
  "Nothing was sent. This conversation is being closed right now — this side has already committed its half of the seal, and a seal signs the conversation as it stood at that moment, so nothing can be added to it. No message was placed in your record and nothing reached your counterparty.";

/**
 * ─── IS THIS CONVERSATION OVER? — `DOD-M15-CLOSEDSESSION-1`, and the ORDER is the unit ─────────
 *
 * The check itself is old and was already correct. What changed is WHEN it runs on the direct
 * frame path: it used to sit inside `ingestReceivedContent`, which the stream handler reaches
 * only AFTER verifying the authorship claim. So a message composed after the seal — acknowledging
 * content our now-frozen record does not hold — was answered `ack_hash_unknown_content`, a
 * sentence about a hash where the situation was that the conversation had ended. Measured live on
 * session `9d253bce…`, on the receiving half of the same defect the send gate closes.
 *
 * Extracted rather than copied, because the two callers must not be able to disagree about what
 * "closed" means or about what a refusal retains. Both routes reach it: the frame path calls it
 * before authorship, and the PARK-recovery route still reaches it through `ingestReceivedContent`,
 * which is the only path that has one.
 *
 * ⚠️ RETENTION IS PART OF THE REFUSAL, NOT A SIDE EFFECT. `quarantineRefusedContent` is also what
 * runs the terminal funnel (`DOD-M15-REFUSALTERMINAL-1`) — without it the relay's next redelivery
 * re-armed a park fetch that drained, verified, arrived and was refused again, measured at ~2 per
 * second for 62 hours on one message.
 */
export function refuseIfSessionClosed(
  ctx: SessionContentPipelineContext,
  agentName: string,
  sessionId: string,
  content: Uint8Array,
  contentHashHex: string,
  correlationId?: string,
): { refused: true; retained: boolean } | { refused: false } {
  const record = ctx.queries.getSessionRecord(agentName, sessionId);
  // DOD-TERMINAL-WAKE-1 (review F1): `abandoned` belongs here with the two sealed states. It is
  // terminal and, unlike `interrupted`, can NEVER complete — there is nothing left to append to
  // and no seal to join. Without it, late content for a force-abandoned session was accepted: a
  // leaf was written, the `cello_message` doorbell rang, the away-response and Telegram doorbell
  // fired, and `cello_receive` handed it over as live work. That is the same "agent obeys a
  // directive out of a conversation that has ended" harm as the sealed case, reached with no
  // restart at all.
  //
  // NO RECORD IS NOT CLOSED. A missing row is the ORPHAN case, which has its own triage and its
  // own retention a few lines below the caller — answering it here would take that message's
  // evidence away and tell the operator the wrong thing about it.
  if (!record || !isClosedStatus(record.status)) return { refused: false };
  // `currentStatus` carries the real status onward: the content-park disposition and the operator
  // must be able to tell an abandoned session from a sealed one, and `session_committed` alone is
  // the exit point, not the cause.
  ctx.logger.warn("session.content.cross_check.failed", {
    sessionId,
    reason: "session_committed",
    currentStatus: record.status,
    correlationId,
  });
  // DOD-M15-REFUSEDEVIDENCE-1 — RETAINED. A post-seal straggler on the DIRECT path kept nothing
  // before this: `sealed_session_annex` covers the park-drain and held-drift routes, not this
  // exit. Something arriving into a signed, closed conversation is exactly the kind of thing an
  // operator later wants to produce.
  const retainedSeq = ctx.refusals.quarantineRefusedContent(agentName, sessionId, "session_committed", content, contentHashHex, {
    senderPubkeyHex: record.counterparty_pubkey ?? null, correlationId,
  });
  // DOD-M15-NO-SILENT-REFUSAL-1. The notice must not flatten the three statuses into one claim,
  // so it names the record as frozen rather than asserting which way it ended.
  ctx.notices.noteContentRefusal(agentName, sessionId, "session_committed", {
    kind: REFUSAL_KINDS.REFUSED,
    impact:
      `This conversation is closed (it ended as "${record.status}"), so the message could not be delivered and neither can anything else they send to it. A closed conversation is signed and cannot be added to — that is what closing it means. Nothing is wrong on your side.`,
    guidance:
      "There is nothing to repair here. If they still have something to say, ask them to start a NEW conversation — a closed one cannot be reopened, and it is worth telling them, because they may not realise it ended. Read what was said before it closed with cello_transcript.",
  });
  return { refused: true, retained: retainedSeq !== null };
}
