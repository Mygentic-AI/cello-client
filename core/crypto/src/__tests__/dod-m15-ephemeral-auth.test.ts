/**
 * DOD-M15-EPHEMERAL-AUTH-1 — the signed throwaway key, and the AEAD over a message body.
 *
 * ─── The attack, because the tests below only make sense against it ────────────────────────────
 *
 * The key agreement mixes two throwaway keys into a secret that never crosses the wire. Unsigned,
 * an arriving key carries no evidence of who sent it — so the relay keeps yours, forwards its own to
 * your counterparty, does the same in reverse, and ends up sharing one secret with each of you. It
 * reads everything in between and both sides see a conversation that decrypts perfectly.
 *
 * We run the relays, so without this the guarantee is "trust us".
 */

import { describe, it, expect } from "vitest";
import { InMemoryKeyProvider } from "../ed25519.js";
import { randomBytes } from "node:crypto";
import {
  ephemeralSigningMessage,
  signSessionEphemeral,
  verifySessionEphemeral,
  EPHEMERAL_AUTH_REFUSALS,
} from "../session-ephemeral-auth.js";
import {
  sealSessionContent,
  openSessionContent,
  SESSION_CONTENT_SEAL_V1,
  SESSION_CONTENT_SEAL_OVERHEAD_BYTES,
} from "../session-content-seal.js";
import { generateSessionEphemeral } from "../session-key-agreement.js";
import { mlDsaGenerateSeed, mlDsaProviderFromSeed } from "../ml-dsa.js";

const SID = new Uint8Array(16).fill(0x21);

async function alice() {
  const kp = new InMemoryKeyProvider(new Uint8Array(randomBytes(32)));
  const mlDsa = await mlDsaProviderFromSeed(mlDsaGenerateSeed());
  return { kp, mlDsa, pub: await kp.getPublicKey(), pqPub: await mlDsa.getPublicKey() };
}

describe("EPHEMERAL-AUTH: a signed key verifies, and only against the right identity", () => {
  /** A v2 announce (M9D 003-PQSESSION) and the verify call for it; each case overrides one field. */
  async function signed(signerA: Awaited<ReturnType<typeof alice>>, sid: Uint8Array = SID) {
    const eph = await generateSessionEphemeral();
    const { sig, pqSig } = await signSessionEphemeral(signerA.kp, signerA.mlDsa, sid, eph.publicKey, eph.mlKemPublic);
    return { eph, sig, pqSig };
  }
  function check(expected: Awaited<ReturnType<typeof alice>>, over: Record<string, unknown>) {
    return verifySessionEphemeral({
      expectedIdentityPublic: expected.pub, expectedPqPublic: expected.pqPub, sessionId: SID,
      peerEphemeralPublic: undefined, peerMlKemPublic: undefined, peerCiphertext: undefined,
      peerSignature: undefined, peerPqSignature: undefined,
      ...over,
    } as Parameters<typeof verifySessionEphemeral>[0]);
  }

  it("★ a key signed by the counterparty VERIFIES", async () => {
    const a = await alice();
    const { eph, sig, pqSig } = await signed(a);
    expect(await check(a, { peerEphemeralPublic: eph.publicKey, peerMlKemPublic: eph.mlKemPublic, peerSignature: sig, peerPqSignature: pqSig }))
      .toEqual({ ok: true });
  });

  it("★★ a key signed by SOMEONE ELSE is refused — this is the relay substituting its own", async () => {
    // The relay's signatures are VALID — they just are not the counterparty's.
    const a = await alice();
    const relay = await alice();
    const { eph, sig, pqSig } = await signed(relay);
    const res = await check(a, { peerEphemeralPublic: eph.publicKey, peerMlKemPublic: eph.mlKemPublic, peerSignature: sig, peerPqSignature: pqSig });
    expect(res.ok === false && res.reason).toBe(EPHEMERAL_AUTH_REFUSALS.SIGNATURE_MISMATCH);
  });

  it("★★ a MISSING signature takes the same hard-fail path as a wrong one", async () => {
    const a = await alice();
    const { eph, pqSig } = await signed(a);
    const res = await check(a, { peerEphemeralPublic: eph.publicKey, peerMlKemPublic: eph.mlKemPublic, peerPqSignature: pqSig });
    expect(res.ok === false && res.reason).toBe(EPHEMERAL_AUTH_REFUSALS.SIGNATURE_MISSING);
  });

  it("★ a MALFORMED signature or key is refused rather than padded", async () => {
    const a = await alice();
    const { eph, sig, pqSig } = await signed(a);
    const short = await check(a, { peerEphemeralPublic: eph.publicKey, peerMlKemPublic: eph.mlKemPublic, peerSignature: new Uint8Array(32), peerPqSignature: pqSig });
    expect(short.ok === false && short.reason).toBe(EPHEMERAL_AUTH_REFUSALS.MALFORMED);
    const shortKey = await check(a, { peerEphemeralPublic: new Uint8Array(16), peerMlKemPublic: eph.mlKemPublic, peerSignature: sig, peerPqSignature: pqSig });
    expect(shortKey.ok === false && shortKey.reason).toBe(EPHEMERAL_AUTH_REFUSALS.MALFORMED);
  });

  it("★★ a signature from ANOTHER SESSION does not verify — replay is bound out", async () => {
    const a = await alice();
    const { eph, sig, pqSig } = await signed(a, new Uint8Array(16).fill(0x99));
    const res = await check(a, { peerEphemeralPublic: eph.publicKey, peerMlKemPublic: eph.mlKemPublic, peerSignature: sig, peerPqSignature: pqSig });
    expect(res.ok, "a signature from a different session verified here — it can be replayed").toBe(false);
  });

  it("★★ a signature over a DIFFERENT ephemeral does not verify — the key itself is bound", async () => {
    const a = await alice();
    const { eph, sig, pqSig } = await signed(a);
    const substituted = await generateSessionEphemeral();
    const res = await check(a, { peerEphemeralPublic: substituted.publicKey, peerMlKemPublic: eph.mlKemPublic, peerSignature: sig, peerPqSignature: pqSig });
    expect(res.ok, "the signature covered a different key, so it proves nothing about this one").toBe(false);
  });

  it("★ the signed message is LENGTH-PREFIXED, so it cannot be re-split", () => {
    const kem = new Uint8Array(1184).fill(4);
    const a = ephemeralSigningMessage(new Uint8Array([1, 2, 3]), new Uint8Array(32).fill(9), kem);
    const b = ephemeralSigningMessage(new Uint8Array([1, 2]), new Uint8Array([3, ...new Uint8Array(31).fill(9)]), new Uint8Array([9, ...kem]));
    expect(Buffer.from(a).toString("hex"), "two different field splits produced the same signed bytes").not.toBe(Buffer.from(b).toString("hex"));
    const msg = ephemeralSigningMessage(new Uint8Array(16).fill(7), new Uint8Array(32).fill(8), kem);
    const label = new TextEncoder().encode("cello/session/v2/ephemeral");
    expect([...msg.subarray(label.length, label.length + 4)]).toEqual([0, 0, 0, 16]);
  });
});

describe("EPHEMERAL-AUTH: the message body is encrypted under the agreed key", () => {
  const KEY = new Uint8Array(32).fill(0x5a);
  const OTHER = new Uint8Array(32).fill(0x5b);
  const BODY = new TextEncoder().encode("the price is 40,000 and we close on Friday");

  it("★ a sealed body round-trips under the same key", () => {
    const blob = sealSessionContent(KEY, BODY);
    expect(Buffer.from(openSessionContent(KEY, blob)!)).toEqual(Buffer.from(BODY));
  });

  it("★★ the CIPHERTEXT does not contain the plaintext — this is the whole point", () => {
    /**
     * "It round-trips" is satisfied by an implementation that returns the plaintext untouched. Assert
     * the bytes on the wire are not the message.
     */
    const blob = sealSessionContent(KEY, BODY);
    expect(
      Buffer.from(blob).toString("hex").includes(Buffer.from(BODY).toString("hex")),
      "the plaintext is sitting in the frame — nothing was encrypted",
    ).toBe(false);
    expect(blob.length).toBe(BODY.length + SESSION_CONTENT_SEAL_OVERHEAD_BYTES);
  });

  it("★★ a DIFFERENT key cannot open it — and gets null, not a throw", () => {
    const blob = sealSessionContent(KEY, BODY);
    expect(
      openSessionContent(OTHER, blob),
      "a wrong key opened the message, so the key is not actually protecting it",
    ).toBeNull();
  });

  it("★★ a TAMPERED ciphertext is refused, not silently returned", () => {
    const blob = sealSessionContent(KEY, BODY);
    const tampered = Uint8Array.from(blob);
    tampered[tampered.length - 20] ^= 0xff; // inside the ciphertext, before the tag
    expect(
      openSessionContent(KEY, tampered),
      "GCM's tag is what makes a modified message detectable; returning it anyway discards that",
    ).toBeNull();
  });

  it("★★ a tampered TAG is refused too", () => {
    const blob = sealSessionContent(KEY, BODY);
    const tampered = Uint8Array.from(blob);
    tampered[tampered.length - 1] ^= 0x01;
    expect(openSessionContent(KEY, tampered)).toBeNull();
  });

  it("★ two seals of the SAME body differ — the IV is fresh each time", () => {
    // Identical ciphertext for identical plaintext would let a relay tell repeated messages apart
    // without reading them, which is the same correlation the salt exists to prevent.
    const a = sealSessionContent(KEY, BODY);
    const b = sealSessionContent(KEY, BODY);
    expect(Buffer.from(a).toString("hex")).not.toBe(Buffer.from(b).toString("hex"));
  });

  it("★ an UNKNOWN version is refused rather than guessed at", () => {
    const blob = sealSessionContent(KEY, BODY);
    const future = Uint8Array.from(blob);
    future[0] = 0x02;
    expect(
      openSessionContent(KEY, future),
      "a version this build does not know was parsed under this build's layout anyway",
    ).toBeNull();
    expect(blob[0], "and the version byte is where the header says").toBe(SESSION_CONTENT_SEAL_V1);
  });

  it("★ a TRUNCATED blob is refused without indexing past the end", () => {
    for (const len of [0, 1, 12, SESSION_CONTENT_SEAL_OVERHEAD_BYTES - 1]) {
      expect(openSessionContent(KEY, new Uint8Array(len)), `length ${len} must be refused`).toBeNull();
    }
  });

  it("★ a wrong-width key is a LOCAL defect and says so", () => {
    expect(() => sealSessionContent(new Uint8Array(16), BODY)).toThrow(/LOCAL defect/i);
    expect(openSessionContent(new Uint8Array(16), sealSessionContent(KEY, BODY))).toBeNull();
  });

  it("★ an EMPTY body still seals and round-trips", () => {
    const blob = sealSessionContent(KEY, new Uint8Array(0));
    expect(openSessionContent(KEY, blob)).toEqual(new Uint8Array(0));
  });
});
