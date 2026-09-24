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
 * Map a rejection from `crypto.subtle` for an algorithm this runtime does not implement to
 * `pq_runtime_unsupported`. Node below 24.7 rejects the algorithm name with a NotSupportedError.
 * Anything else is returned as-is for the caller to classify.
 */
export function isUnsupportedAlgorithm(err: unknown): boolean {
  return err instanceof Error && err.name === "NotSupportedError";
}
