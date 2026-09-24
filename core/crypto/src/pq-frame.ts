/**
 * 001-PQPRIM — Contract 2: the ML-DSA signing frame. The ONLY way to produce or check an ML-DSA
 * signature in the tree (D4, enforced by `d4-single-frame.test.ts`).
 *
 * Every ML-DSA signature is over
 *
 *     utf8(context) ‖ 0x00 ‖ bytes
 *
 * with an EMPTY FIPS 204 context string — the same framing as `buildKeyBindingTbs` and FROST's
 * `frameMessage`. `bytes` come from the same builder the Ed25519 or FROST signature on that
 * artifact uses, so both signatures are over one set of bytes built one way.
 *
 * `frame()` is deliberately NOT exported: an exported builder would be a second route to raw
 * signing. `PqContext` is a closed union, and both functions check it at RUNTIME too, because the
 * type is erased and the client is the adversary's code. Each signing site gets its own member,
 * named `cello-mldsa-<artifact>-v1`; later orders APPEND — never reorder, rename or reuse.
 */
import { webcrypto } from "node:crypto";
import {
  ML_DSA_ALGORITHM,
  ML_DSA_PUBLIC_KEY_BYTES,
  ML_DSA_SIGNATURE_BYTES,
  type MlDsaKeyProvider,
} from "./ml-dsa.js";
import { PqCryptoError } from "./pq-errors.js";

export const PQ_CONTEXTS = [
  // 001-PQPRIM — the connection-package sites.
  "cello-mldsa-pseudonym-binding-v1",
  "cello-mldsa-endorsement-v1",
  "cello-mldsa-attestation-v1",
  // 002-PQKEYS — the four-key registration binding.
  "cello-mldsa-key-binding-v1",
] as const;

export type PqContext = (typeof PQ_CONTEXTS)[number];

function isPqContext(context: unknown): context is PqContext {
  return typeof context === "string" && (PQ_CONTEXTS as readonly string[]).includes(context);
}

function frame(context: PqContext, bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const ctx = new TextEncoder().encode(context);
  const framed = new Uint8Array(ctx.length + 1 + bytes.length);
  framed.set(ctx, 0);
  framed[ctx.length] = 0x00;
  framed.set(bytes, ctx.length + 1);
  return framed;
}

/**
 * Sign `bytes` under `context` with the provider's ML-DSA-44 key. Throws `pq_context_unknown` for a
 * context outside `PQ_CONTEXTS`.
 */
export async function signMlDsa(provider: MlDsaKeyProvider, context: PqContext, bytes: Uint8Array): Promise<Uint8Array> {
  if (!isPqContext(context)) {
    throw new PqCryptoError("pq_context_unknown", `unknown ML-DSA context: ${String(context)}`);
  }
  return provider.sign(frame(context, bytes));
}

/**
 * Verify an ML-DSA-44 signature over `bytes` under `context` and `publicKey`.
 *
 * NEVER throws. Returns false for every rejectable input: a wrong-length key or signature, a key
 * that fails to import, an unknown context, a bad signature. Verifiers are refusal paths and each
 * caller names its own reason; a caller distinguishes "missing" from "wrong" by checking presence
 * BEFORE calling this.
 */
export async function verifyMlDsa(publicKey: Uint8Array, context: PqContext, bytes: Uint8Array, sig: Uint8Array): Promise<boolean> {
  if (!isPqContext(context)) return false;
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== ML_DSA_PUBLIC_KEY_BYTES) return false;
  if (!(sig instanceof Uint8Array) || sig.length !== ML_DSA_SIGNATURE_BYTES) return false;
  if (!(bytes instanceof Uint8Array)) return false;
  try {
    const key = await webcrypto.subtle.importKey("raw-public", new Uint8Array(publicKey), ML_DSA_ALGORITHM, false, ["verify"]);
    return await webcrypto.subtle.verify(ML_DSA_ALGORITHM, key, new Uint8Array(sig), frame(context, bytes));
  } catch {
    // A public key that fails the FIPS 204 import check, or a runtime without ML-DSA-44: a refusal.
    return false;
  }
}
