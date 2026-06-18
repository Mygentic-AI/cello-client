/**
 * CELLO-M7-MSG-001 — recipient content sealed-box (E2E encryption for parked content)
 *
 * SI-001: parked content must be ciphertext encrypted to the recipient's stable
 * Ed25519 identity key. The relay holds only ciphertext it cannot decrypt.
 *
 * Construction (implementation_notes): Ed25519→X25519 birational conversion
 * (RFC 7748 §4.1), ephemeral-static ECDH (X25519, RFC 7748), HKDF-SHA256
 * (RFC 5869) key derivation, AES-256-GCM AEAD (NIST SP 800-38D).
 *
 * Tests use REAL crypto — no mocks.
 */

import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sealToRecipient, openSealed, CONTENT_SEAL_OVERHEAD_BYTES } from "../content-seal.js";
import { InMemoryKeyProvider } from "../ed25519.js";

/** A real Ed25519 identity keypair: seed (32 bytes) + public key (32 bytes). */
function generateKeypair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const seed = new Uint8Array(randomBytes(32));
  return { publicKey: ed25519.getPublicKey(seed), secretKey: seed };
}

describe("content-seal — recipient sealed box (MSG-001 SI-001)", () => {
  it("round-trips: recipient decrypts what sender sealed to its identity pubkey", () => {
    const recipient = generateKeypair(); // { publicKey, secretKey(seed) }
    const plaintext = new TextEncoder().encode("hello parked content");

    const sealed = sealToRecipient(recipient.publicKey, plaintext);
    expect(sealed).toBeInstanceOf(Uint8Array);

    const opened = openSealed(recipient.secretKey, sealed);
    expect(opened).not.toBeNull();
    expect(Buffer.from(opened!).toString("utf8")).toBe("hello parked content");
  });

  it("KeyProvider.openContentSeal opens a blob sealed to that provider's identity key", async () => {
    const seed = new Uint8Array(randomBytes(32));
    const provider = new InMemoryKeyProvider(seed);
    const recipientPub = await provider.getPublicKey();
    const plaintext = new TextEncoder().encode("delivered via provider");

    const sealed = sealToRecipient(recipientPub, plaintext);
    const opened = await provider.openContentSeal(sealed);
    expect(opened).not.toBeNull();
    expect(Buffer.from(opened!)).toEqual(Buffer.from(plaintext));

    // A different identity cannot open it.
    const other = new InMemoryKeyProvider(new Uint8Array(randomBytes(32)));
    expect(await other.openContentSeal(sealed)).toBeNull();
  });

  it("ciphertext does not contain the plaintext (SI-001 — relay cannot read)", () => {
    const recipient = generateKeypair();
    const ascii = "SECRET_MARKER_PLAINTEXT_12345";
    const plaintext = new TextEncoder().encode(ascii);

    const sealed = sealToRecipient(recipient.publicKey, plaintext);
    const sealedStr = Buffer.from(sealed).toString("latin1");
    expect(sealedStr.includes(ascii)).toBe(false);
  });

  it("a different recipient key cannot decrypt (wrong key → null, not throw)", () => {
    const recipient = generateKeypair();
    const attacker = generateKeypair();
    const plaintext = new TextEncoder().encode("for recipient only");

    const sealed = sealToRecipient(recipient.publicKey, plaintext);
    const opened = openSealed(attacker.secretKey, sealed);
    expect(opened).toBeNull();
  });

  it("tampered ciphertext fails authentication → null (AEAD integrity)", () => {
    const recipient = generateKeypair();
    const plaintext = new TextEncoder().encode("integrity-protected");

    const sealed = sealToRecipient(recipient.publicKey, plaintext);
    // flip a byte inside the ciphertext region (after eph pub + iv)
    const tampered = Uint8Array.from(sealed);
    tampered[CONTENT_SEAL_OVERHEAD_BYTES] ^= 0xff;
    const opened = openSealed(recipient.secretKey, tampered);
    expect(opened).toBeNull();
  });

  it("each seal of the same plaintext is unique (fresh ephemeral + IV)", () => {
    const recipient = generateKeypair();
    const plaintext = new TextEncoder().encode("same bytes");
    const a = sealToRecipient(recipient.publicKey, plaintext);
    const b = sealToRecipient(recipient.publicKey, plaintext);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
    // both still decrypt
    expect(openSealed(recipient.secretKey, a)).not.toBeNull();
    expect(openSealed(recipient.secretKey, b)).not.toBeNull();
  });

  it("malformed/too-short blob returns null, never throws", () => {
    const recipient = generateKeypair();
    expect(openSealed(recipient.secretKey, new Uint8Array(5))).toBeNull();
    expect(openSealed(recipient.secretKey, new Uint8Array(0))).toBeNull();
  });

  it("round-trips empty plaintext", () => {
    const recipient = generateKeypair();
    const sealed = sealToRecipient(recipient.publicKey, new Uint8Array(0));
    const opened = openSealed(recipient.secretKey, sealed);
    expect(opened).not.toBeNull();
    expect(opened!.length).toBe(0);
  });
});
