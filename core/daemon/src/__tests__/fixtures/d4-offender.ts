/**
 * POSITIVE CONTROL for d4-single-frame.test.ts — never imported, only scanned. Every line marked
 * OFFENCE must be reported; if the scan stops seeing them, the scan is blind, not the tree clean.
 *
 * It lives in core/daemon on purpose: here `@cello-protocol/crypto` resolves through node_modules to
 * the built declarations at their REAL path (`core/crypto/dist.nosync/ml-dsa.d.ts` — `dist` is a
 * symlink, the iCloud workaround). That path shape once made every cross-package call invisible to
 * the scan; a fixture inside core/crypto resolves to `dist/…` and would not catch it.
 */
import { webcrypto } from "node:crypto";
import { mlDsaProviderFromSeed, ML_DSA_ALGORITHM_LABEL } from "@cello-protocol/crypto";

export async function offender(key: webcrypto.CryptoKey): Promise<void> {
  const provider = await mlDsaProviderFromSeed(new Uint8Array(32));
  await provider.sign(new Uint8Array([1])); // OFFENCE: raw provider.sign
  await webcrypto.subtle.sign({ name: ML_DSA_ALGORITHM_LABEL }, key, new Uint8Array([1])); // OFFENCE: subtle.sign(ML-DSA)
  void "ML-KEM-768"; // OFFENCE: literal
}
