/**
 * M9D 002-PQKEYS — a REAL post-quantum identity for a fixture that writes a registered `agents` row
 * directly.
 *
 * `loadAgents` refuses a registered row without a 32-byte ML-DSA seed and a 64-byte ML-KEM seed —
 * that is the production rule, and a fixture that registers a row by hand must satisfy it rather
 * than slip past it. Seeds are derived from `label`, so a fixture gets the same keys every run; the
 * keys are real (a real key from a known seed is not a mock).
 */
import { createHash } from "node:crypto";
import { mlDsaProviderFromSeed, mlKemKeypairFromSeed } from "@cello-protocol/crypto";
import type { PqIdentityRecord } from "../../registration-persistence.js";

export async function fixturePqIdentityRecord(label: string): Promise<PqIdentityRecord> {
  const mlDsaSeed = new Uint8Array(createHash("sha256").update(`fixture-row-mldsa:${label}`).digest());
  const mlKemSeed = new Uint8Array(createHash("sha512").update(`fixture-row-mlkem:${label}`).digest());
  const mlDsaPubkey = Buffer.from(await (await mlDsaProviderFromSeed(mlDsaSeed)).getPublicKey()).toString("hex");
  const mlKemPubkey = Buffer.from((await mlKemKeypairFromSeed(mlKemSeed)).publicKey).toString("hex");
  return { mlDsaSeed, mlDsaPubkey, mlKemSeed, mlKemPubkey };
}

/** Registration-state fields a hand-registered fixture row carries for its PQ keys. */
export function registeredPqFields(r: PqIdentityRecord): { mlDsaPubkey: string; mlKemPubkey: string; keyBindingPq: string } {
  // `keyBindingPq` is stored and read back by nothing in the daemon today; a fixed-width value keeps
  // the row the shape a real registration writes.
  return { mlDsaPubkey: r.mlDsaPubkey, mlKemPubkey: r.mlKemPubkey, keyBindingPq: "8e".repeat(2420) };
}
