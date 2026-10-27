/**
 * Tests for the daemon credential and the daemon-key proofs.
 *
 * A credential says "this daemon key belongs to this account", signed by the issuer key so every
 * directory verifies it alone. Each use is also signed by the daemon key, so a copied credential is
 * useless without the machine it was issued to. Every signature is domain-separated.
 *
 * Crypto reference: RFC 8032 (Ed25519).
 */
import { describe, it, expect } from "vitest";
import { generateKeypair } from "../ed25519.js";
import { signCapability, verifyCapability, type PreAuthCapabilityBody } from "../preauth-capability.js";
import {
  signDaemonCredential,
  verifyDaemonCredential,
  registrationProofBytes,
  pairingPollBytes,
  signWithDaemonKey,
  verifyDaemonSignature,
  encodeRegistrationGrant,
  decodeRegistrationGrant,
  REGISTRATION_GRANT_PREFIX,
  type DaemonCredential,
  type DaemonCredentialBody,
} from "../daemon-credential.js";

const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

async function fixture() {
  const issuer = generateKeypair();
  const daemon = generateKeypair();
  const issuerPub = hex(await issuer.getPublicKey());
  const daemonPub = hex(await daemon.getPublicKey());
  const body: DaemonCredentialBody = {
    v: 1,
    daemon_pubkey: daemonPub,
    account_id: "3067c0c1-1111-4222-8333-444455556666",
    nonce: "00112233445566778899aabbccddeeff",
    issued_at: "2026-10-27T00:00:00.000Z",
  };
  const cred = await signDaemonCredential(body, issuer);
  return { issuer, daemon, issuerPub, daemonPub, body, cred };
}

describe("daemon credential", () => {
  it("1. signs and verifies with the issuer key", async () => {
    const { cred, issuerPub } = await fixture();
    expect(verifyDaemonCredential(cred, issuerPub)).toEqual({ ok: true });
  });

  it.each([
    ["v", 2],
    ["daemon_pubkey", "b".repeat(64)],
    ["account_id", "9c8df69a-1111-4222-8333-444455556666"],
    ["nonce", "ffeeddccbbaa99887766554433221100"],
    ["issued_at", "2027-01-01T00:00:00.000Z"],
  ] as const)("2. changing %s after signing breaks the signature", async (field, value) => {
    const { cred, issuerPub } = await fixture();
    const tampered = { ...cred, [field]: value } as unknown as DaemonCredential;
    const r = verifyDaemonCredential(tampered, issuerPub);
    // `v: 2` is also malformed; every other field must fail on the signature.
    expect(r).toEqual({ ok: false, reason: field === "v" ? "credential_malformed" : "credential_signature_invalid" });
  });

  it("3. does not verify against any other key", async () => {
    const { cred } = await fixture();
    const other = hex(await generateKeypair().getPublicKey());
    expect(verifyDaemonCredential(cred, other)).toEqual({ ok: false, reason: "credential_signature_invalid" });
  });

  it("4. every malformed case is refused without throwing", async () => {
    const { cred, issuerPub } = await fixture();
    const noNonce: Record<string, unknown> = { ...cred };
    delete noNonce["nonce"];
    const cases: unknown[] = [
      noNonce,
      { ...cred, v: 2 },
      { ...cred, daemon_pubkey: cred.daemon_pubkey.toUpperCase() },
      { ...cred, nonce: "00112233445566778899aabbccddee" },
      { ...cred, account_id: "not-a-uuid" },
      { ...cred, sig: cred.sig.slice(0, 127) },
      null,
      "a string",
    ];
    for (const c of cases) {
      expect(verifyDaemonCredential(c as DaemonCredential, issuerPub)).toEqual({ ok: false, reason: "credential_malformed" });
    }
  });

  it("5a. the issuer's signature over the credential's JSON WITHOUT the domain label does not verify", async () => {
    // This is what the capability scheme signs. Only the domain label can reject it: the JSON is
    // byte-for-byte the credential's own, so without the label it would verify.
    const { issuer, issuerPub, cred, body } = await fixture();
    const sorted: Record<string, unknown> = {};
    for (const k of Object.keys(body).sort()) sorted[k] = (body as unknown as Record<string, unknown>)[k];
    const unlabelled = hex(await issuer.sign(new TextEncoder().encode(JSON.stringify(sorted))));
    expect(verifyDaemonCredential({ ...cred, sig: unlabelled }, issuerPub)).toEqual({ ok: false, reason: "credential_signature_invalid" });
  });

  it("5. a capability signature and a credential signature never cross-verify", async () => {
    const { issuer, issuerPub, cred } = await fixture();
    // A capability signed by the same issuer: its signature, transplanted onto the credential,
    // must not verify — and the credential's signature must not verify as a capability.
    const capBody: PreAuthCapabilityBody = {
      nonce: cred.nonce, phone_stub_hash: "a".repeat(64), email_domain: "e",
      issued_at: cred.issued_at, expires_at: "2099-01-01T00:00:00.000Z",
    };
    const cap = await signCapability(capBody, issuer);
    expect(verifyDaemonCredential({ ...cred, sig: cap.sig }, issuerPub).ok).toBe(false);
    expect(verifyCapability({ ...cap, sig: cred.sig }, issuerPub).ok).toBe(false);
  });
});

describe("daemon-key proofs", () => {
  it("6. a registration proof binds the agent, the credential nonce and the daemon key", async () => {
    const { daemon, daemonPub, cred } = await fixture();
    const agent = "c".repeat(64);
    const sig = await signWithDaemonKey(registrationProofBytes(agent, cred.nonce), daemon);
    expect(verifyDaemonSignature(registrationProofBytes(agent, cred.nonce), sig, daemonPub)).toBe(true);
    expect(verifyDaemonSignature(registrationProofBytes("d".repeat(64), cred.nonce), sig, daemonPub)).toBe(false);
    expect(verifyDaemonSignature(registrationProofBytes(agent, "f".repeat(32)), sig, daemonPub)).toBe(false);
    const otherDaemon = hex(await generateKeypair().getPublicKey());
    expect(verifyDaemonSignature(registrationProofBytes(agent, cred.nonce), sig, otherDaemon)).toBe(false);
  });

  it("7. a registration proof is not a pairing-poll proof, and the reverse", async () => {
    const { daemon, daemonPub } = await fixture();
    const reg = await signWithDaemonKey(registrationProofBytes("c".repeat(64), "0".repeat(32)), daemon);
    const poll = await signWithDaemonKey(pairingPollBytes("KQ7M-4TXP", 1_800_000_000), daemon);
    expect(verifyDaemonSignature(pairingPollBytes("KQ7M-4TXP", 1_800_000_000), reg, daemonPub)).toBe(false);
    expect(verifyDaemonSignature(registrationProofBytes("c".repeat(64), "0".repeat(32)), poll, daemonPub)).toBe(false);
    expect(verifyDaemonSignature(pairingPollBytes("KQ7M-4TXP", 1_800_000_000), poll, daemonPub)).toBe(true);
  });

  it("verifyDaemonSignature never throws on garbage", () => {
    expect(verifyDaemonSignature(new Uint8Array(1), "zz", "not-hex")).toBe(false);
  });
});

describe("registration grant", () => {
  it("8. round-trips, tolerates wrapping, and refuses everything that is not a grant", async () => {
    const { cred } = await fixture();
    const grant = { credential: cred, proof: "e".repeat(128) };
    const enc = encodeRegistrationGrant(grant);
    expect(enc.startsWith(REGISTRATION_GRANT_PREFIX)).toBe(true);
    expect(decodeRegistrationGrant(enc)).toEqual(grant);
    const wrapped = enc.slice(0, 20) + "\n  " + enc.slice(20, 60) + "\r\n" + enc.slice(60);
    expect(decodeRegistrationGrant(wrapped)).toEqual(grant);
    expect(decodeRegistrationGrant(enc.slice(REGISTRATION_GRANT_PREFIX.length))).toBeNull();
    expect(decodeRegistrationGrant(Buffer.from(JSON.stringify(cred)).toString("base64url"))).toBeNull();
    expect(decodeRegistrationGrant("CELLO-2fh3k4j5h6g7f8d9s0a1q2w3e4r5t6y7u")).toBeNull();
    expect(decodeRegistrationGrant(REGISTRATION_GRANT_PREFIX + "!!!not base64")).toBeNull();
  });
});
