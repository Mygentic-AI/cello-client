/**
 * CELLO-M7-SESSION-003 — client-side session-path liveness → attestation mapping
 * and the liveness-authority seam consumed by the unilateral-seal gate.
 *
 * The unilateral-seal path (seal-manager.ts initiateUnilateralSeal) determines a
 * counterparty attestation from the session-path liveness verdict. The mapping is
 * pure and the ONLY producer of the DELIVERED/ABSENT attestation for the
 * unilateral path:
 *
 *   'gone'    → ABSENT     (positive connection-gone observation)
 *   'alive'   → DELIVERED  (alive-but-silent — WhatsApp double-grey-tick)
 *   'unknown' → DELIVERED  (fail-safe; absence of a positive 'gone' is never ABSENT)
 *
 * It NEVER returns CLEAN or FLAGGED — those require the counterparty's own signed
 * output, which is absent by definition in a unilateral seal (AC-006 / AC-011).
 * The 4-rule "no agent heartbeat" invariant (AC-011) is preserved: liveness is
 * connection/node-level only and can never promote DELIVERED to Active/CLEAN/FLAGGED.
 */

import type { SessionLiveness } from "@cello-protocol/protocol-types";

/** The two attestation values this story's gate can produce. */
export type CounterpartyAttestation = "DELIVERED" | "ABSENT";

/**
 * Map a session-path liveness verdict to a unilateral-seal counterparty attestation.
 * Codomain is exactly {DELIVERED, ABSENT}. ABSENT requires a positive 'gone'.
 */
export function livenessToAttestation(liveness: SessionLiveness): CounterpartyAttestation {
  return liveness === "gone" ? "ABSENT" : "DELIVERED";
}

/**
 * Distinct error reasons for a relay-path liveness query that could not be
 * answered. Each is distinguishable from the others and from existing codes
 * (AC-014). 'liveness_unknown' is the non-determinative response (relay has no
 * tracked entry); it is treated as a fail-safe DELIVERED, never ABSENT (SI-003).
 */
export type LivenessQueryFailureReason =
  | "liveness_query_unreachable"
  | "liveness_query_timeout"
  | "liveness_unknown";

/**
 * The verdict produced by the session-path liveness authority for a session.
 *   - authority 'session_node' : direct sessions — the local per-session flag set
 *     from the session node's onPeerConnect/onPeerDisconnect.
 *   - authority 'relay'        : relay sessions — the relay's session_liveness_response.
 * `failureReason` is set only when a relay query could not be answered; in that
 * case liveness is forced to 'unknown' (fail-safe → DELIVERED) and the
 * session.liveness.query.failed event is emitted by the caller.
 */
export interface LivenessVerdict {
  liveness: SessionLiveness;
  authority: "relay" | "session_node";
  failureReason?: LivenessQueryFailureReason;
}

/**
 * The liveness authority seam injected into SealManager. The implementation reads
 * the session's transport_mode (WIRE-001 — the SOLE disambiguator, never inferred
 * from address format) and consults the correct authority:
 *   - 'direct' → the local per-session counterparty_liveness flag
 *   - 'relay'  → a session_liveness_query to the relay
 * It NEVER reads the directory connection state (SI-002).
 */
export interface LivenessAuthority {
  getCounterpartyLiveness(sessionIdHex: string): Promise<LivenessVerdict>;
}
