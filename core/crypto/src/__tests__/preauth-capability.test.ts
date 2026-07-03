/**
 * Tests for the pre-authorization capability (M8B-PREAUTH-CAP).
 *
 * A capability is a signed permission slip authorizing ONE agent registration. Every directory
 * verifies it independently against a pinned issuer pubkey — no DB lookup, no replicated secret.
 * Single-use is enforced downstream (nonce→epoch binding at the directory), NOT here.
 *
 * Crypto reference: RFC 8032 (Ed25519).
 */
import { describe, it, expect } from "vitest";
import { generateKeypair } from "../ed25519.js";
import {
  canonicalCapabilityBody,
  signCapability,
  verifyCapability,
  type PreAuthCapabilityBody,
} from "../preauth-capability.js";

const BASE_BODY: PreAuthCapabilityBody = {
  nonce: "00112233445566778899aabbccddeeff",
  phone_stub_hash: "a".repeat(64),
  email_domain: "example.com",
  issued_at: "2026-07-03T00:00:00.000Z",
  expires_at: "2026-07-03T01:00:00.000Z",
};
const WITHIN = new Date("2026-07-03T00:30:00.000Z");

async function issuer() {
  const kp = generateKeypair();
  const pub = Buffer.from(await kp.getPublicKey()).toString("hex");
  return { kp, pub };
}

describe("canonicalCapabilityBody", () => {
  it("excludes sig and is independent of key insertion order", () => {
    const a = canonicalCapabilityBody({ ...BASE_BODY });
    const reordered: PreAuthCapabilityBody = {
      expires_at: BASE_BODY.expires_at,
      nonce: BASE_BODY.nonce,
      email_domain: BASE_BODY.email_domain,
      issued_at: BASE_BODY.issued_at,
      phone_stub_hash: BASE_BODY.phone_stub_hash,
    };
    const b = canonicalCapabilityBody(reordered);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
    // a `sig` field on the input must not change the signed bytes.
    const withSig = canonicalCapabilityBody({ ...BASE_BODY, sig: "deadbeef" } as PreAuthCapabilityBody);
    expect(Buffer.from(a).equals(Buffer.from(withSig))).toBe(true);
  });
});

describe("signCapability / verifyCapability", () => {
  it("a freshly signed capability verifies against the issuer pubkey within its window", async () => {
    const { kp, pub } = await issuer();
    const cap = await signCapability(BASE_BODY, kp);
    expect(cap.sig).toMatch(/^[0-9a-f]{128}$/);
    expect(verifyCapability(cap, pub, WITHIN)).toEqual({ ok: true });
  });

  it("rejects a capability signed by a different key (signature_invalid)", async () => {
    const { kp } = await issuer();
    const { pub: otherPub } = await issuer();
    const cap = await signCapability(BASE_BODY, kp);
    expect(verifyCapability(cap, otherPub, WITHIN)).toEqual({
      ok: false,
      reason: "capability_signature_invalid",
    });
  });

  it.each(["nonce", "phone_stub_hash", "email_domain", "expires_at"] as const)(
    "rejects a capability whose %s was tampered after signing",
    async (field) => {
      const { kp, pub } = await issuer();
      const cap = await signCapability(BASE_BODY, kp);
      const tampered = { ...cap, [field]: field === "expires_at" ? "2027-01-01T00:00:00.000Z" : "tampered" };
      expect(verifyCapability(tampered, pub, WITHIN)).toEqual({
        ok: false,
        reason: "capability_signature_invalid",
      });
    },
  );

  it("rejects a tampered signature", async () => {
    const { kp, pub } = await issuer();
    const cap = await signCapability(BASE_BODY, kp);
    const flipped = cap.sig.slice(0, -2) + (cap.sig.endsWith("00") ? "01" : "00");
    expect(verifyCapability({ ...cap, sig: flipped }, pub, WITHIN).ok).toBe(false);
  });

  it("rejects a malformed capability (bad sig hex / missing fields) without throwing", async () => {
    const { pub } = await issuer();
    expect(verifyCapability({ ...BASE_BODY, sig: "xyz" }, pub, WITHIN)).toEqual({
      ok: false,
      reason: "capability_malformed",
    });
    // missing required field
    const { sig: _omit, ...noNonceRest } = await (async () => {
      const { kp } = await issuer();
      return signCapability(BASE_BODY, kp);
    })();
    void _omit;
    const missing = { ...noNonceRest, nonce: undefined } as unknown as Parameters<typeof verifyCapability>[0];
    expect(verifyCapability(missing, pub, WITHIN).ok).toBe(false);
  });

  it("rejects an expired capability (now >= expires_at)", async () => {
    const { kp, pub } = await issuer();
    const cap = await signCapability(BASE_BODY, kp);
    const atExpiry = new Date(BASE_BODY.expires_at);
    expect(verifyCapability(cap, pub, atExpiry)).toEqual({ ok: false, reason: "capability_expired" });
    const after = new Date("2026-07-03T02:00:00.000Z");
    expect(verifyCapability(cap, pub, after)).toEqual({ ok: false, reason: "capability_expired" });
  });

  it("never throws on a garbage issuer pubkey", async () => {
    const { kp } = await issuer();
    const cap = await signCapability(BASE_BODY, kp);
    expect(verifyCapability(cap, "nothex", WITHIN).ok).toBe(false);
  });
});
