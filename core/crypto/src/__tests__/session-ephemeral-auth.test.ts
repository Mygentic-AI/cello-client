/**
 * M9D 003-PQSESSION — the session-ephemeral announce carries a required ML-DSA twin (D11, D16),
 * tests 4–8.
 *
 * One builder produces the bytes both signatures cover:
 *   "cello/session/v2/ephemeral" ‖ u32be(len sid) ‖ sid ‖ x25519_pub(32) ‖ mlkem_pub(1184) ‖ (ct(1088) or empty)
 *
 * Every negative below is a GENUINE signature by the wrong party or over the wrong bytes — never a
 * corrupted blob — because that is what a relay substituting its own key actually sends.
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import { InMemoryKeyProvider } from "../ed25519.js";
import { mlDsaGenerateSeed, mlDsaProviderFromSeed } from "../ml-dsa.js";
import { mlKemGenerateSeed, mlKemKeypairFromSeed, ML_KEM_CIPHERTEXT_BYTES } from "../ml-kem.js";
import { signMlDsa } from "../pq-frame.js";
import { generateSessionEphemeral } from "../session-key-agreement.js";
import {
  ephemeralSigningMessage,
  signSessionEphemeral,
  verifySessionEphemeral,
  EPHEMERAL_AUTH_REFUSALS,
} from "../session-ephemeral-auth.js";

const SID = new Uint8Array(16).fill(0x5a);

async function agent() {
  const kLocal = new InMemoryKeyProvider(new Uint8Array(randomBytes(32)));
  const mlDsa = await mlDsaProviderFromSeed(mlDsaGenerateSeed());
  return { kLocal, mlDsa, pub: await kLocal.getPublicKey(), pqPub: await mlDsa.getPublicKey() };
}

async function announce(ct?: Uint8Array) {
  const eph = await generateSessionEphemeral();
  const { publicKey: mlkemPublic } = await mlKemKeypairFromSeed(mlKemGenerateSeed());
  return { x25519: eph.publicKey, mlkemPublic, ct };
}

describe("003 test 4 — the builder's layout is byte-exact", () => {
  it("with and without ct", () => {
    const x = new Uint8Array(32).fill(0x01);
    const k = new Uint8Array(1184).fill(0x02);
    const ct = new Uint8Array(ML_KEM_CIPHERTEXT_BYTES).fill(0x03);
    const label = Buffer.from("cello/session/v2/ephemeral", "utf8");
    const len = Buffer.from([0, 0, 0, SID.length]);
    const without = Buffer.concat([label, len, SID, x, k]);
    const withCt = Buffer.concat([label, len, SID, x, k, ct]);
    expect(Buffer.from(ephemeralSigningMessage(SID, x, k)).equals(without)).toBe(true);
    expect(Buffer.from(ephemeralSigningMessage(SID, x, k, ct)).equals(withCt)).toBe(true);
  });
});

describe("003 tests 5–8 — both signatures required, each failure named", () => {
  it("genuine announce with ct VERIFIES (control)", async () => {
    const a = await agent();
    const ann = await announce(new Uint8Array(ML_KEM_CIPHERTEXT_BYTES).fill(0x07));
    const { sig, pqSig } = await signSessionEphemeral(a.kLocal, a.mlDsa, SID, ann.x25519, ann.mlkemPublic, ann.ct);
    const v = await verifySessionEphemeral({
      expectedIdentityPublic: a.pub, expectedPqPublic: a.pqPub, sessionId: SID,
      peerEphemeralPublic: ann.x25519, peerMlKemPublic: ann.mlkemPublic, peerCiphertext: ann.ct,
      peerSignature: sig, peerPqSignature: pqSig,
    });
    expect(v).toEqual({ ok: true });
  });

  it("★ test 5 (exemplar): genuine Ed25519 + ANOTHER agent's genuine ML-DSA over the same message → ephemeral_pq_signature_mismatch", async () => {
    const a = await agent();
    const other = await agent();
    const ann = await announce();
    const { sig } = await signSessionEphemeral(a.kLocal, a.mlDsa, SID, ann.x25519, ann.mlkemPublic);
    const otherPq = await signMlDsa(other.mlDsa, "cello-mldsa-session-ephemeral-v1", ephemeralSigningMessage(SID, ann.x25519, ann.mlkemPublic));
    const v = await verifySessionEphemeral({
      expectedIdentityPublic: a.pub, expectedPqPublic: a.pqPub, sessionId: SID,
      peerEphemeralPublic: ann.x25519, peerMlKemPublic: ann.mlkemPublic, peerCiphertext: undefined,
      peerSignature: sig, peerPqSignature: otherPq,
    });
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.reason).toBe(EPHEMERAL_AUTH_REFUSALS.PQ_SIGNATURE_MISMATCH);
  });

  it("★ test 6: genuine ML-DSA + a genuine Ed25519 by a DIFFERENT K_local → ephemeral_signature_mismatch", async () => {
    const a = await agent();
    const other = await agent();
    const ann = await announce();
    const { pqSig } = await signSessionEphemeral(a.kLocal, a.mlDsa, SID, ann.x25519, ann.mlkemPublic);
    const { sig: otherSig } = await signSessionEphemeral(other.kLocal, other.mlDsa, SID, ann.x25519, ann.mlkemPublic);
    const v = await verifySessionEphemeral({
      expectedIdentityPublic: a.pub, expectedPqPublic: a.pqPub, sessionId: SID,
      peerEphemeralPublic: ann.x25519, peerMlKemPublic: ann.mlkemPublic, peerCiphertext: undefined,
      peerSignature: otherSig, peerPqSignature: pqSig,
    });
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.reason).toBe(EPHEMERAL_AUTH_REFUSALS.SIGNATURE_MISMATCH);
  });

  it("★ test 7: a relay swaps mlkem_public (or ct) and keeps both signatures → ephemeral_signature_mismatch", async () => {
    const a = await agent();
    const ann = await announce(new Uint8Array(ML_KEM_CIPHERTEXT_BYTES).fill(0x07));
    const { sig, pqSig } = await signSessionEphemeral(a.kLocal, a.mlDsa, SID, ann.x25519, ann.mlkemPublic, ann.ct);
    const relayKem = (await mlKemKeypairFromSeed(mlKemGenerateSeed())).publicKey;
    const swappedKem = await verifySessionEphemeral({
      expectedIdentityPublic: a.pub, expectedPqPublic: a.pqPub, sessionId: SID,
      peerEphemeralPublic: ann.x25519, peerMlKemPublic: relayKem, peerCiphertext: ann.ct,
      peerSignature: sig, peerPqSignature: pqSig,
    });
    expect(swappedKem.ok).toBe(false);
    if (!swappedKem.ok) expect(swappedKem.reason).toBe(EPHEMERAL_AUTH_REFUSALS.SIGNATURE_MISMATCH);

    const relayCt = new Uint8Array(ML_KEM_CIPHERTEXT_BYTES).fill(0x08);
    const swappedCt = await verifySessionEphemeral({
      expectedIdentityPublic: a.pub, expectedPqPublic: a.pqPub, sessionId: SID,
      peerEphemeralPublic: ann.x25519, peerMlKemPublic: ann.mlkemPublic, peerCiphertext: relayCt,
      peerSignature: sig, peerPqSignature: pqSig,
    });
    expect(swappedCt.ok).toBe(false);
    if (!swappedCt.ok) expect(swappedCt.reason).toBe(EPHEMERAL_AUTH_REFUSALS.SIGNATURE_MISMATCH);
  });

  it("★ test 8: each missing or malformed PQ piece is refused by its own name", async () => {
    const a = await agent();
    const ann = await announce();
    const { sig, pqSig } = await signSessionEphemeral(a.kLocal, a.mlDsa, SID, ann.x25519, ann.mlkemPublic);
    const base = {
      expectedIdentityPublic: a.pub, expectedPqPublic: a.pqPub as Uint8Array | undefined, sessionId: SID,
      peerEphemeralPublic: ann.x25519, peerMlKemPublic: ann.mlkemPublic as Uint8Array | undefined,
      peerCiphertext: undefined as Uint8Array | undefined,
      peerSignature: sig as Uint8Array | undefined, peerPqSignature: pqSig as Uint8Array | undefined,
    };
    const reason = async (over: Partial<typeof base>) => {
      const v = await verifySessionEphemeral({ ...base, ...over });
      return v.ok ? "ok" : v.reason;
    };
    expect(await reason({ peerMlKemPublic: undefined })).toBe(EPHEMERAL_AUTH_REFUSALS.PQ_MISSING);
    expect(await reason({ peerPqSignature: undefined })).toBe(EPHEMERAL_AUTH_REFUSALS.PQ_SIGNATURE_MISSING);
    expect(await reason({ peerMlKemPublic: ann.mlkemPublic.subarray(0, 1183) })).toBe(EPHEMERAL_AUTH_REFUSALS.PQ_MALFORMED);
    expect(await reason({ peerCiphertext: new Uint8Array(1087) })).toBe(EPHEMERAL_AUTH_REFUSALS.PQ_MALFORMED);
    expect(await reason({ expectedPqPublic: undefined })).toBe(EPHEMERAL_AUTH_REFUSALS.PQ_PEER_KEYS_UNKNOWN);
    expect(await reason({})).toBe("ok"); // control
  });
});
