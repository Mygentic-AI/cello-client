/**
 * 001-PQPRIM — ML-DSA-44 (FIPS 204) on native node:crypto, replacing the @oqs/liboqs-js WASM suite.
 *
 * REAL CRYPTO, no mocks. Correctness is proven against the NIST ACVP known-answer vectors
 * (vectors/acvp-975de31e/SOURCE.md). The sigVer vectors carry an arbitrary FIPS 204 context string,
 * which the Contract 2 frame cannot express, so they are fed to `crypto.subtle.verify` directly —
 * the reference harness proves Node's primitive; the keyGen vectors prove our seed → public key path.
 *
 * The behavioural cases kept from the WASM suite (widths, tampering, empty and large messages,
 * secret confinement) now run through the Contract 2 frame, the only route production code has.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import { inspect } from "node:util";
import {
  mlDsaGenerateSeed,
  mlDsaProviderFromSeed,
  signMlDsa,
  verifyMlDsa,
  ML_DSA_PUBLIC_KEY_BYTES,
  ML_DSA_SIGNATURE_BYTES,
  ML_DSA_SEED_BYTES,
  PqCryptoError,
} from "../index.js";

interface Group<T> { tgId: number; tests: T[] }
function vectors<T>(file: string): { testGroups: Group<T>[] } {
  return JSON.parse(readFileSync(new URL(`./vectors/acvp-975de31e/${file}.json`, import.meta.url), "utf8"));
}
const hex = (s: string): Uint8Array<ArrayBuffer> => new Uint8Array(Buffer.from(s, "hex"));
const toHex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const CTX = "cello-mldsa-endorsement-v1" as const;

async function reason(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(PqCryptoError);
    return (e as PqCryptoError).reason;
  }
  throw new Error("expected a PqCryptoError, got a resolved promise");
}

describe("001-PQPRIM test 7 — ML-DSA-44 keyGen KAT (ACVP tgId 1)", () => {
  const group = vectors<{ tcId: number; seed: string; pk: string }>("ML-DSA-keyGen-FIPS204").testGroups.find((g) => g.tgId === 1)!;

  it("has the 25 ML-DSA-44 vectors", () => {
    expect(group.tests).toHaveLength(25);
  });

  it.each(group.tests.map((t) => [t.tcId, t] as const))("tcId %i: seed → pk through mlDsaProviderFromSeed", async (_id, t) => {
    const provider = await mlDsaProviderFromSeed(hex(t.seed));
    expect(toHex(await provider.getPublicKey())).toBe(t.pk.toLowerCase());
  });
});

describe("001-PQPRIM test 8 — ML-DSA-44 sigVer KAT (ACVP tgId 1: external, pure, with context)", () => {
  const group = vectors<{ tcId: number; testPassed: boolean; pk: string; message: string; context: string; signature: string; reason: string }>(
    "ML-DSA-sigVer-FIPS204",
  ).testGroups.find((g) => g.tgId === 1)!;

  it("has 15 vectors, and some of them must fail", () => {
    expect(group.tests).toHaveLength(15);
    expect(group.tests.some((t) => !t.testPassed)).toBe(true);
  });

  it.each(group.tests.map((t) => [t.tcId, t.reason, t] as const))("tcId %i (%s): subtle.verify = testPassed", async (_id, _r, t) => {
    let ok: boolean;
    try {
      const key = await webcrypto.subtle.importKey("raw-public", hex(t.pk), { name: "ML-DSA-44" }, false, ["verify"]);
      // `context` is the FIPS 204 context string (ContextParams), which @types/node does not type yet.
      ok = await webcrypto.subtle.verify({ name: "ML-DSA-44", context: hex(t.context) } as never, key, hex(t.signature), hex(t.message));
    } catch {
      ok = false;
    }
    expect(ok).toBe(t.testPassed);
  });
});

describe("001-PQPRIM test 9 — widths", () => {
  it("Contract 1 widths: public key 1312, signature 2420, seed 32", async () => {
    expect([ML_DSA_PUBLIC_KEY_BYTES, ML_DSA_SIGNATURE_BYTES, ML_DSA_SEED_BYTES]).toEqual([1312, 2420, 32]);
    const seed = mlDsaGenerateSeed();
    expect(seed.length).toBe(32);
    const p = await mlDsaProviderFromSeed(seed);
    expect((await p.getPublicKey()).length).toBe(1312);
    expect((await signMlDsa(p, CTX, new Uint8Array(8))).length).toBe(2420);
  });

  it.each([31, 33])("a %i-byte seed throws ml_dsa_seed_invalid", async (n) => {
    expect(await reason(mlDsaProviderFromSeed(new Uint8Array(n)))).toBe("ml_dsa_seed_invalid");
  });

  it("the same seed gives the same key; two generated seeds give different keys", async () => {
    const seed = mlDsaGenerateSeed();
    const a = await (await mlDsaProviderFromSeed(seed)).getPublicKey();
    const b = await (await mlDsaProviderFromSeed(seed.slice())).getPublicKey();
    const c = await (await mlDsaProviderFromSeed(mlDsaGenerateSeed())).getPublicKey();
    expect(toHex(a)).toBe(toHex(b));
    expect(toHex(a)).not.toBe(toHex(c));
  });
});

describe("001-PQPRIM test 10 — the old 2,560-byte expanded secret is refused", () => {
  it("mlDsaProviderFromSeed(2560 bytes) throws ml_dsa_seed_invalid", async () => {
    expect(await reason(mlDsaProviderFromSeed(new Uint8Array(2560)))).toBe("ml_dsa_seed_invalid");
  });
});

describe("001-PQPRIM test 11 — no secret in any representation", () => {
  it("JSON.stringify, String() and util.inspect show the public key and not the seed", async () => {
    const seed = new Uint8Array(32).fill(0xa7);
    const p = await mlDsaProviderFromSeed(seed);
    const pubHex = toHex(await p.getPublicKey());
    const seedHex = toHex(seed);
    for (const s of [JSON.stringify(p), String(p), inspect(p, { showHidden: true, depth: 5 })]) {
      expect(s).toContain(pubHex);
      expect(s).not.toContain(seedHex);
    }
  });

  it("the caller's seed buffer can be zeroed after construction without breaking the provider", async () => {
    const seed = mlDsaGenerateSeed();
    const p = await mlDsaProviderFromSeed(seed);
    const pk = await p.getPublicKey();
    seed.fill(0);
    const sig = await signMlDsa(p, CTX, new Uint8Array([1, 2, 3]));
    expect(await verifyMlDsa(pk, CTX, new Uint8Array([1, 2, 3]), sig)).toBe(true);
  });
});

describe("behaviour kept from the WASM suite, now through the Contract 2 frame", () => {
  it("tampered message (one bit in 10 KiB) → false; original → true", async () => {
    const p = await mlDsaProviderFromSeed(mlDsaGenerateSeed());
    const pk = await p.getPublicKey();
    const msg = new Uint8Array(10 * 1024).fill(0xcc);
    const sig = await signMlDsa(p, CTX, msg);
    const tampered = msg.slice();
    tampered[5000] ^= 0x01;
    expect(await verifyMlDsa(pk, CTX, tampered, sig)).toBe(false);
    expect(await verifyMlDsa(pk, CTX, msg, sig)).toBe(true);
  });

  it("empty message and a 100 KiB message both sign and verify", async () => {
    const p = await mlDsaProviderFromSeed(mlDsaGenerateSeed());
    const pk = await p.getPublicKey();
    for (const msg of [new Uint8Array(0), new Uint8Array(100 * 1024).fill(0x42)]) {
      const sig = await signMlDsa(p, CTX, msg);
      expect(sig.length).toBe(2420);
      expect(await verifyMlDsa(pk, CTX, msg, sig)).toBe(true);
    }
  });

  it("an all-zero 2420-byte signature → false, no throw", async () => {
    const p = await mlDsaProviderFromSeed(mlDsaGenerateSeed());
    expect(await verifyMlDsa(await p.getPublicKey(), CTX, new Uint8Array(4), new Uint8Array(2420))).toBe(false);
  });
});
