/**
 * @cello-protocol/crypto — ML-DSA-44 (NIST FIPS 204), on native node:crypto Web Crypto (Node ≥ 24.7).
 *
 * Contract 1 of M9D. Replaces the @oqs/liboqs-js WASM provider. The persisted secret is the 32-byte
 * FIPS 204 seed ξ — not the 2,560-byte expanded key — and the public key is derived from it
 * deterministically. There is no reader for the old expanded format: an identity stored that way is
 * a load failure, and every identity is re-registered when M9D rolls.
 *
 * `MlDsaKeyProvider.sign` is the RAW primitive. Only `signMlDsa` in `pq-frame.ts` may call it, over
 * the Contract 2 frame; `d4-single-frame.test.ts` fails on any other caller in production code.
 *
 * Parameter set is pinned to ML-DSA-44. No runtime selection exists.
 */
import "./pq-warnings.js";
import { createPublicKey, KeyObject, webcrypto } from "node:crypto";
import { PqCryptoError, isUnsupportedAlgorithm } from "./pq-errors.js";

export const ML_DSA_PUBLIC_KEY_BYTES = 1312;
export const ML_DSA_SIGNATURE_BYTES = 2420;
export const ML_DSA_SEED_BYTES = 32;

/** 1312-byte ML-DSA-44 public key */
export type MlDsaPublicKey = Uint8Array;

/** 2420-byte ML-DSA-44 signature */
export type MlDsaSignature = Uint8Array;

/** Provider abstraction: holds the secret in private storage; exposes only public ops. */
export interface MlDsaKeyProvider {
  getPublicKey(): Promise<MlDsaPublicKey>;
  sign(message: Uint8Array): Promise<MlDsaSignature>;
}

/**
 * The parameter-set name, as a LABEL for storage (the daemon's `ml_dsa_algorithm` column). It is the
 * only spelling of "ML-DSA-44" code outside ml-dsa.ts / pq-frame.ts may use, and the D4 scan refuses
 * it as an argument to any sign/verify call.
 */
export const ML_DSA_ALGORITHM_LABEL = "ML-DSA-44";

/** The algorithm identifier, for `pq-frame.ts`'s verifier — the one other file allowed to name it. */
export const ML_DSA_ALGORITHM = { name: ML_DSA_ALGORITHM_LABEL } as const;

function mlDsaUnsupported(err: unknown): PqCryptoError {
  return new PqCryptoError(
    "pq_runtime_unsupported",
    `ML-DSA-44 is not available in this Node (${process.version}); CELLO needs Node >= 24.7`,
    { cause: err },
  );
}

const INSPECT = Symbol.for("nodejs.util.inspect.custom");

/**
 * The in-memory provider. Constructed only through `mlDsaProviderFromSeed`: the constructor takes
 * an already-imported NON-EXTRACTABLE CryptoKey, so the seed never sits in the object and cannot be
 * read back out of the key.
 */
export class InMemoryMlDsaKeyProvider implements MlDsaKeyProvider {
  readonly #key: webcrypto.CryptoKey;
  readonly #publicKey: MlDsaPublicKey;

  private constructor(key: webcrypto.CryptoKey, publicKey: Uint8Array) {
    this.#key = key;
    this.#publicKey = publicKey;
  }

  /** @internal — use `mlDsaProviderFromSeed`. */
  static async fromSeed(seed: Uint8Array): Promise<InMemoryMlDsaKeyProvider> {
    if (!(seed instanceof Uint8Array) || seed.length !== ML_DSA_SEED_BYTES) {
      throw new PqCryptoError("ml_dsa_seed_invalid", `ML-DSA-44 seed must be ${ML_DSA_SEED_BYTES} bytes, got ${seed?.length}`);
    }
    let key: webcrypto.CryptoKey;
    try {
      key = await webcrypto.subtle.importKey("raw-seed", new Uint8Array(seed), ML_DSA_ALGORITHM, false, ["sign"]);
    } catch (err) {
      if (isUnsupportedAlgorithm(err)) throw mlDsaUnsupported(err);
      throw new PqCryptoError("ml_dsa_seed_invalid", "ML-DSA-44 seed import failed", { cause: err });
    }
    // The classic node:crypto derivation of the public key from the private one. `raw-public` export
    // exists from Node 24.7 but is not in @types/node's KeyObject.export overloads yet.
    const pub = createPublicKey(KeyObject.from(key)).export({ format: "raw-public" } as never) as unknown as Buffer;
    return new InMemoryMlDsaKeyProvider(key, new Uint8Array(pub));
  }

  async getPublicKey(): Promise<MlDsaPublicKey> {
    // A copy: the caller cannot mutate the provider's public key.
    return this.#publicKey.slice();
  }

  /** RAW ML-DSA-44 over `message`, empty FIPS 204 context. Call `signMlDsa`, never this. */
  async sign(message: Uint8Array): Promise<MlDsaSignature> {
    return new Uint8Array(await webcrypto.subtle.sign(ML_DSA_ALGORITHM, this.#key, new Uint8Array(message)));
  }

  // Redacted representations — only the public key is ever shown.
  toJSON(): Record<string, string> {
    return { type: "InMemoryMlDsaKeyProvider", publicKey: Buffer.from(this.#publicKey).toString("hex") };
  }

  toString(): string {
    return `InMemoryMlDsaKeyProvider(pubkey=${Buffer.from(this.#publicKey).toString("hex")})`;
  }

  [INSPECT](): string {
    return this.toString();
  }
}

/** 32 random bytes: a fresh FIPS 204 seed ξ. This is the form an identity persists. */
export function mlDsaGenerateSeed(): Uint8Array {
  return webcrypto.getRandomValues(new Uint8Array(ML_DSA_SEED_BYTES));
}

/** A provider for the key the 32-byte seed determines. Deterministic: same seed, same key. */
export async function mlDsaProviderFromSeed(seed: Uint8Array): Promise<MlDsaKeyProvider> {
  return InMemoryMlDsaKeyProvider.fromSeed(seed);
}
