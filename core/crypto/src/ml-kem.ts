/**
 * @cello-protocol/crypto — ML-KEM-768 (NIST FIPS 203), on native node:crypto Web Crypto (Node ≥ 24.7).
 *
 * Contract 1 of M9D. The seed is the FIPS 203 64-byte seed `d ‖ z`, imported with `raw-seed`; the
 * public (encapsulation) key is derived from it deterministically, so the seed is the only thing a
 * caller ever persists.
 *
 * Decapsulation of a wrong-but-well-formed ciphertext does NOT throw: FIPS 203 implicit rejection
 * returns a pseudorandom secret, and the AEAD tag check in the caller is what refuses. Only a
 * wrong-LENGTH ciphertext throws.
 *
 * Nothing module-level holds a seed, a shared secret or a private CryptoKey. Callers zero their
 * own copies where they zero the classical twin.
 */
import "./pq-warnings.js";
import { createPublicKey, KeyObject, webcrypto } from "node:crypto";
import { PqCryptoError, isUnsupportedAlgorithm } from "./pq-errors.js";

export const ML_KEM_PUBLIC_KEY_BYTES = 1184;
export const ML_KEM_CIPHERTEXT_BYTES = 1088;
export const ML_KEM_SEED_BYTES = 64;
export const ML_KEM_SHARED_SECRET_BYTES = 32;

const ALG = { name: "ML-KEM-768" } as const;
const subtle = webcrypto.subtle;

// @types/node (25.9) types the "raw-seed"/"raw-public" key formats but not the KEM methods
// encapsulateBits/decapsulateBits. This is the exact surface Node 24.7+ implements.
interface PqSubtle {
  importKey(format: "raw-seed" | "raw-public", keyData: Uint8Array, algorithm: typeof ALG, extractable: boolean, usages: string[]): Promise<webcrypto.CryptoKey>;
  encapsulateBits(algorithm: typeof ALG, key: webcrypto.CryptoKey): Promise<{ ciphertext: ArrayBuffer; sharedKey: ArrayBuffer }>;
  decapsulateBits(algorithm: typeof ALG, key: webcrypto.CryptoKey, ciphertext: Uint8Array): Promise<ArrayBuffer>;
}
const pq = subtle as unknown as PqSubtle;

function unsupported(err: unknown): PqCryptoError {
  return new PqCryptoError(
    "pq_runtime_unsupported",
    `ML-KEM-768 is not available in this Node (${process.version}); CELLO needs Node >= 24.7`,
    { cause: err },
  );
}

async function importSeed(seed: Uint8Array): Promise<webcrypto.CryptoKey> {
  if (!(seed instanceof Uint8Array) || seed.length !== ML_KEM_SEED_BYTES) {
    throw new PqCryptoError("ml_kem_seed_invalid", `ML-KEM-768 seed must be ${ML_KEM_SEED_BYTES} bytes, got ${seed?.length}`);
  }
  try {
    return await pq.importKey("raw-seed", seed, ALG, false, ["decapsulateBits"]);
  } catch (err) {
    if (isUnsupportedAlgorithm(err)) throw unsupported(err);
    throw new PqCryptoError("ml_kem_seed_invalid", "ML-KEM-768 seed import failed", { cause: err });
  }
}

/** 64 random bytes: a fresh FIPS 203 seed `d ‖ z`. */
export function mlKemGenerateSeed(): Uint8Array {
  return webcrypto.getRandomValues(new Uint8Array(ML_KEM_SEED_BYTES));
}

/** Derive the 1,184-byte encapsulation key from a 64-byte seed. Deterministic. */
export async function mlKemKeypairFromSeed(seed: Uint8Array): Promise<{ publicKey: Uint8Array }> {
  const key = await importSeed(seed);
  const pub = createPublicKey(KeyObject.from(key)).export({ format: "raw-public" } as never) as unknown as Buffer;
  return { publicKey: new Uint8Array(pub) };
}

/** Encapsulate to a peer's encapsulation key. The FIPS 203 key check runs on import. */
export async function mlKemEncapsulate(publicKey: Uint8Array): Promise<{ ciphertext: Uint8Array; sharedSecret: Uint8Array }> {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== ML_KEM_PUBLIC_KEY_BYTES) {
    throw new PqCryptoError("ml_kem_public_key_invalid", `ML-KEM-768 public key must be ${ML_KEM_PUBLIC_KEY_BYTES} bytes, got ${publicKey?.length}`);
  }
  let key: webcrypto.CryptoKey;
  try {
    key = await pq.importKey("raw-public", publicKey, ALG, true, ["encapsulateBits"]);
  } catch (err) {
    if (isUnsupportedAlgorithm(err)) throw unsupported(err);
    throw new PqCryptoError("ml_kem_public_key_invalid", "ML-KEM-768 public key failed the FIPS 203 encapsulation-key check", { cause: err });
  }
  const { ciphertext, sharedKey } = await pq.encapsulateBits(ALG, key);
  return { ciphertext: new Uint8Array(ciphertext), sharedSecret: new Uint8Array(sharedKey) };
}

/** Decapsulate with the 64-byte seed. A wrong-but-well-formed ciphertext yields a pseudorandom secret. */
export async function mlKemDecapsulate(seed: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  // Seed first, so a wrong seed is never reported as a wrong ciphertext.
  const key = await importSeed(seed);
  if (!(ciphertext instanceof Uint8Array) || ciphertext.length !== ML_KEM_CIPHERTEXT_BYTES) {
    throw new PqCryptoError("ml_kem_ciphertext_invalid", `ML-KEM-768 ciphertext must be ${ML_KEM_CIPHERTEXT_BYTES} bytes, got ${ciphertext?.length}`);
  }
  return new Uint8Array(await pq.decapsulateBits(ALG, key, ciphertext));
}
