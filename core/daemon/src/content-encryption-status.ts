/**
 * WHY A SESSION'S CONTENT IS NOT ENCRYPTED BY CELLO — 006-CRYPTO, `DOD-M15-KEYAGREE-1`.
 *
 * ─── What this is, and what it is not ──────────────────────────────────────────────────────────
 *
 * CELLO agrees a throwaway key per session so that IT controls the confidentiality of a message
 * body, rather than inheriting whatever the transport happens to do. That layer is not finished:
 * `006-CRYPTO` mints the keypair, holds it in memory and destroys it at close; `007-CRYPTO` adds the
 * exchange, the signature over it, and the encryption itself. Until then no message body is
 * encrypted by us.
 *
 * ⚠️ NOT the same question as `content_hashes_salted`. The salt stops a relay CONFIRMING a guess at
 * a stored hash. This stops a relay READING the message. A session can be salted and unencrypted,
 * which is exactly what every session is today.
 *
 * ─── Why a closed set and a total map, for one member ──────────────────────────────────────────
 *
 * The shape is copied from `refusal-reasons.ts`, which exists because a free-form `reason: string`
 * let a new code slip past every test in its own guard file. A `Record` over the union means a
 * reason cannot be added without something for the reader to understand.
 *
 * And it exists NOW, with one member, because the alternative is silence — which is precisely how
 * this half of the feature came to read as finished. The key agreement had tests, a public header
 * claiming forward secrecy, and no caller; nothing anywhere said so. A session that states plainly
 * what protects it cannot make that mistake twice.
 */

export const CONTENT_ENCRYPTION_REASONS = {
  /** This build agrees no session key at all. Content is protected by the transport only. */
  NO_KEY_EXCHANGE: "no_key_exchange",
} as const;

export type ContentEncryptionReason =
  (typeof CONTENT_ENCRYPTION_REASONS)[keyof typeof CONTENT_ENCRYPTION_REASONS];

/**
 * What the operator should understand from each reason. TOTAL over the union by construction.
 *
 * ⚠️ EVERY ENTRY MUST BE TRUE OF WHAT IS ACTUALLY SHIPPING, and must not imply a setting that does
 * not exist. There is nothing an operator can do about this one, so it says so — an affordance that
 * resolves to nothing is worse than none, because they will go looking for it.
 */
export const CONTENT_ENCRYPTION_GUIDANCE: Record<ContentEncryptionReason, string> = {
  [CONTENT_ENCRYPTION_REASONS.NO_KEY_EXCHANGE]:
    "This build does not yet agree a per-session encryption key with your counterparty, so CELLO is " +
    "not encrypting the message body itself. Your messages are still encrypted in transit by the " +
    "transport, and anything waiting in a relay mailbox is separately encrypted to your long-term " +
    "key — the relay cannot read either. What is missing is the layer CELLO controls, which is what " +
    "would protect a recorded conversation from being decrypted years from now. Nothing is wrong " +
    "with your setup or your counterparty's, and there is no setting that turns this on.",
};

/**
 * Render a stored reason for an agent.
 *
 * An UNRECOGNISED reason is described as unrecognised rather than guessed at. The value comes off a
 * database row that an older or newer build may have written, and asserting the wrong cause is how a
 * reader ends up acting on something that was never the problem.
 */
export function contentEncryptionGuidanceFor(reason: string): string {
  const known = CONTENT_ENCRYPTION_GUIDANCE[reason as ContentEncryptionReason];
  if (known !== undefined) return known;
  return (
    `CELLO is not encrypting this session's message bodies, for a reason this build does not ` +
    `recognise (${reason}). That most likely means the session was written by a different version. ` +
    `Your messages are still encrypted in transit by the transport.`
  );
}
