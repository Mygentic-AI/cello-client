/**
 * Refusal reason codes shared between the site that RECORDS a refusal and the site that EXPLAINS it.
 *
 * DOD-M15-OFFER-SIGNED-1 review N8. These strings were duplicated literals across
 * `inbound-sessions.ts` (which calls `recordRefusal`) and `notification-handlers.ts` (which looks
 * the reason up to attach guidance), with nothing binding them. Rename or mistype either side and
 * the lookup silently misses: the operator gets a bare reason code again, which is exactly the
 * defect the guidance was added to fix — reintroduced by a typo, with every test still green.
 *
 * A shared constant makes that a compile error instead. `REFUSAL_REASONS` is the single source; the
 * guidance table below is keyed by its values, so a reason without guidance cannot be added silently.
 */

/**
 * DOD-M15-NO-SILENT-REFUSAL-1 — WHAT KIND of thing happened to the message.
 *
 * ⚠️ **THE HEADER OVER A LIST OF REFUSALS CANNOT BE ONE SENTENCE, and review F4 measured why.**
 * The `refused` sentence below was written for three hash-verification reasons and every clause
 * of it was true of them: received, not verified, not ingested, not shown, sender never told. Carry
 * that sentence verbatim onto the nine other reasons and each clause breaks somewhere —
 *
 *  - a SCREENER block was verified and IS in the hash chain, and the sender WAS acknowledged;
 *  - a transcript write failure was verified and committed, and the sender IS told;
 *  - `delivery_impaired` is not an inbound message at all — it is this side's own send failing, so
 *    the sentence names the wrong direction of travel and sends the operator to the counterparty
 *    about a fault on their own machine.
 *
 * So the notice carries its kind and the door composes the header from the kinds actually present.
 * The `refused` sentence is unchanged, for the set it was written for.
 */
export const REFUSAL_KINDS = {
  /** Received, could not be accepted. Not ingested, not shown, and the sender was not told. */
  REFUSED: "refused",
  /** Received, verified, RECORDED in the chain and ACKNOWLEDGED — deliberately not shown. */
  BLOCKED: "blocked",
  /** Received; nothing recorded, nothing acknowledged. The sender's daemon redelivers on its own. */
  DEFERRED: "deferred",
  /** Received and committed to the chain, then LOST to a local storage failure. Unrecoverable. */
  LOST: "lost",
  /** Nothing was received. This side's own send or acknowledgement failed to reach them. */
  OUTBOUND: "outbound",
} as const;

export type RefusalKind = (typeof REFUSAL_KINDS)[keyof typeof REFUSAL_KINDS];

/**
 * The header for each kind — total over `RefusalKind`, so a new kind cannot be added without one.
 *
 * ⚠️ IT TRAVELS WITH THE NOTICES, NEVER SEPARATELY. When only one exit carried a header, a catch-up
 * read drained the refusals into a payload with no advice at all, and the operator's next blocking
 * read then said "call again and keep waiting" — the notice was already gone. Every door returns the
 * two together for that reason.
 */
export const REFUSAL_KIND_GUIDANCE: Record<RefusalKind, string> = {
  /**
   * VERBATIM, and deliberately so: this is the sentence the previous unit wrote for exactly this
   * set, it is the one that makes the notice actionable, and a note in the tree records that a
   * catch-up door destroyed it once already.
   */
  [REFUSAL_KINDS.REFUSED]:
    "Message(s) from this counterparty WERE received and REFUSED — they were not verified, so they " +
    "were neither ingested nor shown. See `refusals` for the reason and what to do. Waiting longer " +
    "will not help until it is resolved, and the counterparty has no way to know: from their side the " +
    "message was sent. THE REASON BELOW SAYS WHAT TO DO — do not reach for a resend by default: two " +
    "of the reasons carrying this header are already being redelivered on a loop, and one cannot be " +
    "fixed for this session at all.",
  [REFUSAL_KINDS.BLOCKED]:
    "Message(s) aimed at this agent were BLOCKED by its screener. They were verified and they ARE " +
    "recorded in the conversation's hash chain, and the sender WAS acknowledged — so they do not " +
    "know, they will not resend, and nothing is waiting on you. They were never shown to the agent, " +
    "and that is the protection working. Do not go looking for the blocked text and do not turn " +
    "screening off to read it.",
  [REFUSAL_KINDS.DEFERRED]:
    "Message(s) from this counterparty could not be processed and were NOT accepted — nothing was " +
    "recorded and nothing was acknowledged, so the message is still with them and their daemon will " +
    "redeliver it once the cause clears. DO NOT read the silence as delivery, and do not ask them to " +
    "resend: a resend takes a second position in the record. Fix the cause named below.",
  [REFUSAL_KINDS.LOST]:
    "Message(s) reached this agent, were verified, and were committed to the hash chain — and then " +
    "failed to write to the local transcript, so they can never be delivered. THIS IS A FAULT ON " +
    "THIS MACHINE, not a quiet counterparty. Waiting cannot recover them; the text is gone and only " +
    "its hash remains. Fix the local fault below, then ask them to resend.",
  [REFUSAL_KINDS.OUTBOUND]:
    "NOTHING WAS REFUSED BY THIS AGENT — this is the other direction. A message YOU sent did not get " +
    "through, and could not be saved to send later, so it is gone. Do not go to the counterparty " +
    "about it: they never saw it and there is nothing for them to do. Send it again.",
};

export const REFUSAL_REASONS = {
  /** The session_offer and the session_assignment named different dialers for one session. */
  OFFER_ASSIGNMENT_DIALER_MISMATCH: "offer_assignment_dialer_mismatch",
  /** The directory named a different threshold group key for an already-known counterparty. */
  COUNTERPARTY_PRIMARY_KEY_CHANGED: "counterparty_primary_key_changed",
  /** The inbound assignment failed verification (signature, signer, or shape). */
  INBOUND_ASSIGNMENT_INVALID: "inbound_assignment_invalid",
} as const;

export type RefusalReason = (typeof REFUSAL_REASONS)[keyof typeof REFUSAL_REASONS];

/**
 * The CAPACITY refusals — bounds, not security findings.
 *
 * These deliberately carry no guidance: their codes say what happened, and the cap path already
 * sends the sender their own numbers over the wire. They are declared here anyway so that
 * `recordRefusal` can take a CLOSED union.
 *
 * ⚠️ BYTE-IDENTICAL BY DESIGN. A BLOCKED sender and an over-cap UNKNOWN one must be
 * indistinguishable, or the refusal tells someone they are blocked. Do not add a reason that
 * separates them.
 */
export const CAPACITY_REASONS = {
  ABUSE_BOUND_SESSIONS_PER_SENDER: "abuse_bound_sessions_per_sender",
  ABUSE_BOUND_UNKNOWN_SESSIONS_GLOBAL: "abuse_bound_unknown_sessions_global",
} as const;

export type CapacityReason = (typeof CAPACITY_REASONS)[keyof typeof CAPACITY_REASONS];

/**
 * Every reason a session may be refused with — the CLOSED set.
 *
 * ─── Why this is a union and not `string` ──────────────────────────────────────────────────────
 *
 * `recordRefusal` used to take `reason: string`, because capacity bounds legitimately pass their own
 * codes. A review measured what that permitted: **add a new security refusal recording a free-form
 * `"assignment_epoch_replayed"` and the entire gate stays green** — the guard fires, the operator
 * gets a bare code with no guidance, and nothing notices, because every test enumerates
 * `REFUSAL_REASONS` and the new code was never in it.
 *
 * That is the guard-nobody-hears pattern in its FORWARD direction: not the four occurrences already
 * fixed, but the next one. A test cannot see a code that does not exist yet. A type can.
 *
 * So the set is closed. Adding a refusal now means adding a member here, and a security member
 * without guidance fails to compile against `REFUSAL_GUIDANCE`'s total map. `DOD-M15-GUARD-HEARD-1`.
 */
export type AnyRefusalReason = RefusalReason | CapacityReason;

/**
 * What the operator should DO, per reason.
 *
 * A bare reason code is not an affordance. These are the SECURITY refusals from the inbound
 * assignment path — the ones where the operator needs to know something was refused on purpose,
 * what it means, and (for the identity change) that the next step happens OUTSIDE CELLO.
 *
 * Typed as a total map over `RefusalReason`, so adding a reason without guidance fails to compile.
 *
 * ⚠️ THE READER IS THE RESPONDER'S OPERATOR, and every verb here must be one THEY can perform.
 * Two of these said "Retry" — which is the INITIATOR's move. The person reading this did not start
 * the session and has nothing to retry; telling them to is an affordance that resolves to nothing,
 * which is worse than no advice because they will try to follow it. The retry advice belongs in the
 * `session_refused` frame, which goes to the side that can act on it.
 */
export const REFUSAL_GUIDANCE: Record<RefusalReason, string> = {
  [REFUSAL_REASONS.COUNTERPARTY_PRIMARY_KEY_CHANGED]:
    "REFUSED ON PURPOSE. The directory named a different signing identity for a contact you have " +
    "completed sessions with before. Either they genuinely re-registered — confirm that with them " +
    "OUT OF BAND (a channel that is not this one), then run cello_contact_remove for them, which " +
    "clears the pinned identity so the next session re-pins — or a directory is substituting an " +
    "identity. Do not accept a session from them until you know which.",
  [REFUSAL_REASONS.OFFER_ASSIGNMENT_DIALER_MISMATCH]:
    "REFUSED ON PURPOSE. The directory's session offer named one dialer and the session assignment " +
    "named another, so the two frames for one session disagree. A stale or replayed offer produces " +
    "this too, so one occurrence is not proof of a hostile directory. Nothing was accepted, and " +
    "nothing is wrong on your side — the other party has been told to start a new session. If the " +
    "SAME counterparty keeps failing this way, stop treating it as noise: confirm out of band that " +
    "they are the one dialling you, and until they answer, do not accept a session from them.",
  [REFUSAL_REASONS.INBOUND_ASSIGNMENT_INVALID]:
    "REFUSED ON PURPOSE. The session assignment did not verify, so this agent would have been " +
    "opening its receiver to a peer named by a document it could not check. Nothing was accepted. " +
    "There is nothing for you to retry — the other party holds the session and has been told to " +
    "start a new one. If it repeats for the SAME counterparty, do not accept anything from them " +
    "until you have confirmed out of band that they still control the identity you know them by.",
};
