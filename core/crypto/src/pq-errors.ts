/**
 * 001-PQPRIM — the one error type the post-quantum primitives throw.
 *
 * Six reasons, and they are six different things (procedure Invariant 3): a caller that collapses
 * them into "crypto failed" loses the cause. `pq_runtime_unsupported` is what an operator sees if
 * the install-time Node floor was bypassed — the algorithm does not exist in their node:crypto.
 *
 * Verifiers never throw this: `verifyMlDsa` returns false for every rejectable input, and each
 * caller names its own refusal.
 */
export const PQ_CRYPTO_ERROR_REASONS = [
  "ml_kem_seed_invalid",
  "ml_kem_public_key_invalid",
  "ml_kem_ciphertext_invalid",
  "ml_dsa_seed_invalid",
  "pq_context_unknown",
  "pq_runtime_unsupported",
] as const;

export type PqCryptoErrorReason = (typeof PQ_CRYPTO_ERROR_REASONS)[number];

export class PqCryptoError extends Error {
  readonly reason: PqCryptoErrorReason;

  constructor(reason: PqCryptoErrorReason, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "PqCryptoError";
    this.reason = reason;
  }
}

/**
 * Is this `crypto.subtle` rejection "this Node does not implement the algorithm"? Callers map it to
 * `pq_runtime_unsupported`; anything else is theirs to classify.
 *
 * Two shapes, both seen for real:
 *  - Node 24.6 rejects the `raw-seed` / `raw-public` KEY FORMAT before it looks at the algorithm:
 *    TypeError, code ERR_INVALID_ARG_VALUE, "… is not a valid enum value of type KeyFormat."
 *  - An unknown algorithm name: DOMException NotSupportedError.
 */
export function isUnsupportedAlgorithm(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  if (err.name === "NotSupportedError") return true;
  return (err as { code?: unknown }).code === "ERR_INVALID_ARG_VALUE" && /type (KeyFormat|Algorithm)/.test(err.message);
}
