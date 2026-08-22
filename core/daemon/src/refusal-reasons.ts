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
 * What the operator should DO, per reason.
 *
 * A bare reason code is not an affordance. These are the SECURITY refusals from the inbound
 * assignment path — the ones where the operator needs to know something was refused on purpose,
 * what it means, and (for the identity change) that the next step happens OUTSIDE CELLO.
 *
 * Typed as a total map over `RefusalReason`, so adding a reason without guidance fails to compile.
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
    "this too, so one occurrence is not proof of a hostile directory. Retry — you may reach a " +
    "different node. If it repeats on the same node, that node is not producing assignments that " +
    "match its own offers.",
  [REFUSAL_REASONS.INBOUND_ASSIGNMENT_INVALID]:
    "REFUSED ON PURPOSE. The session assignment did not verify, so this agent would have been " +
    "opening its receiver to a peer named by a document it could not check. Retry to reach a " +
    "different directory node. If it repeats, either that node is not producing valid assignments, " +
    "or the counterparty re-registered — confirm out of band before accepting anything from them.",
};
