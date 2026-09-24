/**
 * POSITIVE CONTROL for d4-single-frame.test.ts — never imported, only scanned. Every line carrying
 * the OFFENCE marker comment must be reported (the test checks each marked LINE); if the scan stops
 * seeing one, the scan is blind, not the tree clean.
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
  const msg = new Uint8Array([1]);
  await provider.sign(msg); // OFFENCE: raw provider.sign
  await provider["sign"](msg); // OFFENCE: element access
  await provider.sign.call(provider, msg); // OFFENCE: .call
  const { sign } = provider; // OFFENCE: destructured
  await sign(msg);
  const bound = provider.sign.bind(provider); // OFFENCE: .bind
  await bound(msg);
  await webcrypto.subtle.sign({ name: ML_DSA_ALGORITHM_LABEL }, key, msg); // OFFENCE: subtle.sign(ML-DSA)
  const s = webcrypto.subtle;
  const alg = { name: ML_DSA_ALGORITHM_LABEL } as const;
  await s.sign(alg, key, msg); // OFFENCE: aliased subtle, algorithm in a variable
  await s.verify(alg, key, msg, msg); // OFFENCE: aliased subtle.verify
  void "ML-KEM-768"; // OFFENCE: literal
}
