/**
 * 001-PQPRIM — ML-KEM-768 (FIPS 203) on native node:crypto.
 *
 * REAL CRYPTO, no mocks. Correctness is proven against the NIST ACVP known-answer vectors
 * (vendored, see vectors/acvp-975de31e/SOURCE.md), not against a second call to our own code:
 * agreeing with ourselves proves determinism, not correctness.
 *
 * The decapsulation vectors supply an EXPANDED decapsulation key, which `raw-seed` import cannot
 * take, so the reference harness imports it as PKCS#8 `expandedKey` and calls `crypto.decapsulate`
 * directly. That proves Node's primitive is the FIPS 203 one; the keyGen vectors prove our
 * seed → public key path over the same primitive.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { createPrivateKey, decapsulate } from "node:crypto";
import {
  mlKemGenerateSeed,
  mlKemKeypairFromSeed,
  mlKemEncapsulate,
  mlKemDecapsulate,
  ML_KEM_PUBLIC_KEY_BYTES,
  ML_KEM_CIPHERTEXT_BYTES,
  ML_KEM_SEED_BYTES,
  ML_KEM_SHARED_SECRET_BYTES,
  PqCryptoError,
} from "../index.js";

interface Group<T> { tgId: number; tests: T[] }
function vectors<T>(file: string): { testGroups: Group<T>[] } {
  return JSON.parse(readFileSync(new URL(`./vectors/acvp-975de31e/${file}.json`, import.meta.url), "utf8"));
}
const hex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "hex"));
const toHex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

async function reason(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(PqCryptoError);
    return (e as PqCryptoError).reason;
  }
  throw new Error("expected a PqCryptoError, got a resolved promise");
}

// PKCS#8 wrapper for an ML-KEM-768 expanded decapsulation key (draft-ietf-lamps-kyber-certificates:
// PrivateKey ::= CHOICE { ..., expandedKey OCTET STRING, ... }, OID id-alg-ml-kem-768 2.16.840.1.101.3.4.4.2).
function der(tag: number, body: Buffer): Buffer {
  const n = body.length;
  const len = n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff];
  return Buffer.concat([Buffer.from([tag, ...len]), body]);
}
function expandedDkPkcs8(dk: Uint8Array): Buffer {
  const oid = Buffer.from("0609608648016503040402", "hex");
  return der(0x30, Buffer.concat([Buffer.from([0x02, 0x01, 0x00]), der(0x30, oid), der(0x04, der(0x04, Buffer.from(dk)))]));
}

describe("001-PQPRIM test 1 — ML-KEM-768 keyGen KAT (ACVP tgId 2)", () => {
  const group = vectors<{ tcId: number; d: string; z: string; ek: string }>("ML-KEM-keyGen-FIPS203").testGroups.find((g) => g.tgId === 2)!;

  it("has the 25 ML-KEM-768 vectors", () => {
    expect(group.tests).toHaveLength(25);
  });

  it.each(group.tests.map((t) => [t.tcId, t] as const))("tcId %i: seed d‖z → ek through mlKemKeypairFromSeed", async (_id, t) => {
    const seed = new Uint8Array([...hex(t.d), ...hex(t.z)]);
    const { publicKey } = await mlKemKeypairFromSeed(seed);
    expect(toHex(publicKey)).toBe(t.ek.toLowerCase());
  });
});

describe("001-PQPRIM test 2 — ML-KEM-768 decapsulation KAT (ACVP tgId 5, incl. implicit rejection)", () => {
  const group = vectors<{ tcId: number; dk: string; c: string; k: string; reason: string }>("ML-KEM-encapDecap-FIPS203").testGroups.find((g) => g.tgId === 5)!;

  it("has the 10 decapsulation vectors", () => {
    expect(group.tests).toHaveLength(10);
  });

  it.each(group.tests.map((t) => [t.tcId, t.reason, t] as const))("tcId %i (%s): decapsulate(dk, c) = k", (_id, _r, t) => {
    const key = createPrivateKey({ key: expandedDkPkcs8(hex(t.dk)), format: "der", type: "pkcs8" });
    const k = decapsulate(key, hex(t.c));
    expect(toHex(k)).toBe(t.k.toLowerCase());
  });
});

describe("001-PQPRIM test 3 — ML-KEM-768 encapsulation-key check (ACVP tgId 10)", () => {
  const group = vectors<{ tcId: number; testPassed: boolean; ek: string; reason: string }>("ML-KEM-encapDecap-FIPS203").testGroups.find((g) => g.tgId === 10)!;
  const bad = group.tests.filter((t) => !t.testPassed);
  const good = group.tests.filter((t) => t.testPassed);

  it("has failing vectors to test (the group is not all-pass)", () => {
    expect(bad.length).toBeGreaterThan(0);
  });

  it.each(bad.map((t) => [t.tcId, t.reason, t] as const))("tcId %i (%s): mlKemEncapsulate refuses with ml_kem_public_key_invalid", async (_id, _r, t) => {
    expect(await reason(mlKemEncapsulate(hex(t.ek)))).toBe("ml_kem_public_key_invalid");
  });

  it.each(good.map((t) => [t.tcId, t] as const))("tcId %i (valid key): mlKemEncapsulate accepts", async (_id, t) => {
    const { ciphertext } = await mlKemEncapsulate(hex(t.ek));
    expect(ciphertext.length).toBe(ML_KEM_CIPHERTEXT_BYTES);
  });
});

describe("001-PQPRIM test 4 — round trip against a genuine other party", () => {
  it("A decapsulates to the encapsulated secret; B, a real second key, gets a different one", async () => {
    const seedA = mlKemGenerateSeed();
    const seedB = mlKemGenerateSeed();
    const { publicKey: pkA } = await mlKemKeypairFromSeed(seedA);

    const { ciphertext, sharedSecret } = await mlKemEncapsulate(pkA);
    const byA = await mlKemDecapsulate(seedA, ciphertext);
    const byB = await mlKemDecapsulate(seedB, ciphertext);

    expect(toHex(byA)).toBe(toHex(sharedSecret));
    expect(toHex(byB)).not.toBe(toHex(sharedSecret));
  });
});

describe("001-PQPRIM test 5 — tampered ciphertext (FIPS 203 implicit rejection)", () => {
  it("one flipped byte → a different secret, and no throw", async () => {
    const seed = mlKemGenerateSeed();
    const { publicKey } = await mlKemKeypairFromSeed(seed);
    const { ciphertext, sharedSecret } = await mlKemEncapsulate(publicKey);
    const tampered = ciphertext.slice();
    tampered[500] ^= 0x01;

    const got = await mlKemDecapsulate(seed, tampered);
    expect(got.length).toBe(ML_KEM_SHARED_SECRET_BYTES);
    expect(toHex(got)).not.toBe(toHex(sharedSecret));
  });
});

describe("001-PQPRIM test 6 — widths and refusals", () => {
  it("Contract 1 widths", async () => {
    expect([ML_KEM_PUBLIC_KEY_BYTES, ML_KEM_CIPHERTEXT_BYTES, ML_KEM_SEED_BYTES, ML_KEM_SHARED_SECRET_BYTES]).toEqual([1184, 1088, 64, 32]);
    const seed = mlKemGenerateSeed();
    expect(seed.length).toBe(64);
    const { publicKey } = await mlKemKeypairFromSeed(seed);
    expect(publicKey.length).toBe(1184);
    const { ciphertext, sharedSecret } = await mlKemEncapsulate(publicKey);
    expect(ciphertext.length).toBe(1088);
    expect(sharedSecret.length).toBe(32);
  });

  it("two generated seeds differ", () => {
    expect(toHex(mlKemGenerateSeed())).not.toBe(toHex(mlKemGenerateSeed()));
  });

  it.each([63, 65])("a %i-byte seed throws ml_kem_seed_invalid (keypair and decapsulate)", async (n) => {
    expect(await reason(mlKemKeypairFromSeed(new Uint8Array(n)))).toBe("ml_kem_seed_invalid");
    expect(await reason(mlKemDecapsulate(new Uint8Array(n), new Uint8Array(1088)))).toBe("ml_kem_seed_invalid");
  });

  it("a 1087-byte ciphertext throws ml_kem_ciphertext_invalid", async () => {
    expect(await reason(mlKemDecapsulate(mlKemGenerateSeed(), new Uint8Array(1087)))).toBe("ml_kem_ciphertext_invalid");
  });

  it.each([1183, 1185])("a %i-byte public key throws ml_kem_public_key_invalid", async (n) => {
    expect(await reason(mlKemEncapsulate(new Uint8Array(n)))).toBe("ml_kem_public_key_invalid");
  });
});
