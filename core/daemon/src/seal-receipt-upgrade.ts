/**
 * Client-side bilateral upgrade of a stored seal receipt.
 *
 * When the previously-absent party (B) ratifies a unilateral seal and the directory confirms the
 * upgrade to bilateral (seal_upgrade_confirmed, cryptographically verified via verifyUpgradeConfirmedCert),
 * BOTH parties upgrade their OWN already-persisted unilateral receipt: the counterparty that was
 * recorded 'absent' becomes 'recovered' (it has now ratified + proved content possession via the
 * KERNEL gate). This is done CLIENT-SIDE — the directory does not persist the seal leaves/legibility
 * anywhere reachable at upgrade time, so there is nothing new to ship; the bilateral receipt is built
 * from the cert each party already holds. The seal signatures do NOT bind the legibility, so mutating
 * the stored (unsigned) legibility invalidates nothing.
 *
 * Never overstates: only the attestation_mode flips (absent → recovered); frontiers are unchanged
 * (the honest floor). Attestation modes: 'live' | 'recovered' | 'absent' (seal-legibility-tbs.ts).
 */

/**
 * Return the legibility with every participant marked 'absent' re-marked 'recovered'. Mutates in place
 * and returns the same reference. Tolerant: a null/undefined/malformed legibility is returned unchanged
 * rather than throwing (the caller persists whatever it had).
 */
export function upgradeAbsentToRecovered(legibility: unknown): unknown {
  if (!legibility || typeof legibility !== "object") return legibility;
  const participants = (legibility as { participants?: unknown }).participants;
  if (!Array.isArray(participants)) return legibility;
  for (const p of participants) {
    if (p && typeof p === "object" && (p as { attestation_mode?: unknown }).attestation_mode === "absent") {
      (p as { attestation_mode: string }).attestation_mode = "recovered";
    }
  }
  return legibility;
}

/**
 * True if the legibility still has any 'absent' participant — i.e. it has NOT yet been upgraded to
 * bilateral (upgradeAbsentToRecovered flips the sole absent party to 'recovered'). The absent-party
 * 3b persist uses this as a ONE-WAY RATCHET: a re-delivered seal_unilateral_notification (reconnect
 * burst) must not overwrite an already-'recovered' stored receipt back to the stale 'absent' snapshot.
 * A malformed/missing legibility returns false (nothing to protect; let the caller persist).
 */
export function hasAbsentParticipant(legibility: unknown): boolean {
  if (!legibility || typeof legibility !== "object") return false;
  const participants = (legibility as { participants?: unknown }).participants;
  if (!Array.isArray(participants)) return false;
  return participants.some(
    (p) => p && typeof p === "object" && (p as { attestation_mode?: unknown }).attestation_mode === "absent",
  );
}
