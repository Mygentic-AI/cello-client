/**
 * 001-PQPRIM — the Contract 2 frame: every ML-DSA signature is over utf8(context) ‖ 0x00 ‖ bytes,
 * with an empty FIPS 204 context string.
 *
 * The frame builder is deliberately NOT exported (an exported builder would be a second route to
 * raw signing), so test 13 builds the expected bytes BY HAND and checks `signMlDsa`'s output against
 * them with `crypto.subtle.verify` directly — a reference independent of the code under test.
 *
 * Every negative uses a different party's GENUINE material, never a corrupted blob: a verifier that
 * ignored the key or the context would still refuse a corrupted signature.
 */
import { describe, it, expect } from "vitest";
import { webcrypto, randomBytes } from "node:crypto";
import {
  mlDsaGenerateSeed,
  mlDsaProviderFromSeed,
  signMlDsa,
  verifyMlDsa,
  PQ_CONTEXTS,
  PqCryptoError,
  type PqContext,
} from "../index.js";

const BYTES = new TextEncoder().encode("the artifact's own TBS bytes");

async function party() {
  const provider = await mlDsaProviderFromSeed(mlDsaGenerateSeed());
  return { provider, publicKey: await provider.getPublicKey() };
}

async function subtleVerify(publicKey: Uint8Array, message: Uint8Array, sig: Uint8Array): Promise<boolean> {
  const key = await webcrypto.subtle.importKey("raw-public", publicKey, { name: "ML-DSA-44" }, false, ["verify"]);
  return webcrypto.subtle.verify({ name: "ML-DSA-44" }, key, sig, message);
}

describe("PQ_CONTEXTS", () => {
  it("carries this order's three connection-package members, each cello-mldsa-<artifact>-v1, no duplicates", () => {
    expect(PQ_CONTEXTS).toEqual(expect.arrayContaining([
      "cello-mldsa-pseudonym-binding-v1",
      "cello-mldsa-endorsement-v1",
      "cello-mldsa-attestation-v1",
    ]));
    expect(new Set(PQ_CONTEXTS).size).toBe(PQ_CONTEXTS.length);
    for (const c of PQ_CONTEXTS) expect(c).toMatch(/^cello-mldsa-[a-z0-9-]+-v1$/);
  });
});

describe("001-PQPRIM test 12 — round trip", () => {
  it("signMlDsa then verifyMlDsa, same context and bytes → true", async () => {
    const a = await party();
    const sig = await signMlDsa(a.provider, "cello-mldsa-endorsement-v1", BYTES);
    expect(sig.length).toBe(2420);
    expect(await verifyMlDsa(a.publicKey, "cello-mldsa-endorsement-v1", BYTES, sig)).toBe(true);
  });
});

describe("001-PQPRIM test 13 — the frame, against a hand-built reference", () => {
  it("the signature verifies over utf8(context) ‖ 0x00 ‖ bytes, and NOT over bare bytes", async () => {
    const a = await party();
    const context: PqContext = "cello-mldsa-attestation-v1";
    const sig = await signMlDsa(a.provider, context, BYTES);

    const ctx = Buffer.from(context, "utf8");
    const expected = new Uint8Array(ctx.length + 1 + BYTES.length);
    expected.set(ctx, 0);
    expected[ctx.length] = 0x00;
    expected.set(BYTES, ctx.length + 1);

    expect(await subtleVerify(a.publicKey, expected, sig)).toBe(true);
    expect(await subtleVerify(a.publicKey, BYTES, sig)).toBe(false);
  });
});

describe("001-PQPRIM test 14 — a genuine different party", () => {
  it("a genuine signature by A, verified under genuine key B → false", async () => {
    const a = await party();
    const b = await party();
    const sig = await signMlDsa(a.provider, "cello-mldsa-endorsement-v1", BYTES);
    expect(await verifyMlDsa(b.publicKey, "cello-mldsa-endorsement-v1", BYTES, sig)).toBe(false);
  });
});

describe("001-PQPRIM test 15 — context confusion", () => {
  it("signed under endorsement, verified under attestation, same bytes and signer → false", async () => {
    const a = await party();
    const sig = await signMlDsa(a.provider, "cello-mldsa-endorsement-v1", BYTES);
    expect(await verifyMlDsa(a.publicKey, "cello-mldsa-attestation-v1", BYTES, sig)).toBe(false);
  });
});

describe("001-PQPRIM test 16 — an unknown context at runtime (the type is erased)", () => {
  it("signMlDsa throws pq_context_unknown; verifyMlDsa returns false and does not throw", async () => {
    const a = await party();
    const bogus = "cello-mldsa-bogus-v1" as PqContext;
    let caught: unknown;
    try {
      await signMlDsa(a.provider, bogus, BYTES);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(PqCryptoError);
    expect((caught as PqCryptoError).reason).toBe("pq_context_unknown");

    // A signature a real signer made over the bogus frame, so the ONLY reason to refuse is the context.
    const ctx = Buffer.from(bogus, "utf8");
    const framed = new Uint8Array([...ctx, 0x00, ...BYTES]);
    const sig = await a.provider.sign(framed);
    expect(await subtleVerify(a.publicKey, framed, sig)).toBe(true);
    await expect(verifyMlDsa(a.publicKey, bogus, BYTES, sig)).resolves.toBe(false);
  });
});

describe("001-PQPRIM test 17 — malformed inputs never throw from verify", () => {
  it("1311-byte key, 2419-byte signature, 1312 random bytes as a key → false each", async () => {
    const a = await party();
    const sig = await signMlDsa(a.provider, "cello-mldsa-endorsement-v1", BYTES);
    await expect(verifyMlDsa(a.publicKey.slice(0, 1311), "cello-mldsa-endorsement-v1", BYTES, sig)).resolves.toBe(false);
    await expect(verifyMlDsa(a.publicKey, "cello-mldsa-endorsement-v1", BYTES, sig.slice(0, 2419))).resolves.toBe(false);
    await expect(verifyMlDsa(new Uint8Array(randomBytes(1312)), "cello-mldsa-endorsement-v1", BYTES, sig)).resolves.toBe(false);
  });
});
