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
