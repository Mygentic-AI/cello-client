/**
 * DOD-LOG-1 — transcript at-rest cipher unit tests. Pins: round-trip, ciphertext is not
 * plaintext (real encryption), GCM rejects tamper, and a wrong key cannot decrypt.
 */
import { describe, it, expect } from "vitest";
import { TranscriptCipher } from "../transcript-cipher.js";

describe("DOD-LOG-1: TranscriptCipher", () => {
  it("round-trips plaintext", () => {
    const c = TranscriptCipher.fromKey();
    const msg = new TextEncoder().encode("the readable conversation transcript");
    const blob = c.encrypt(msg);
    expect(c.decrypt(blob)).toEqual(msg);
  });

  it("the blob is actually encrypted (does not contain the plaintext)", () => {
    const c = TranscriptCipher.fromKey();
    const msg = new TextEncoder().encode("SECRET-PLAINTEXT-NEEDLE");
    const blob = Buffer.from(c.encrypt(msg));
    expect(blob.toString("utf8")).not.toContain("SECRET-PLAINTEXT-NEEDLE");
    expect(blob.toString("latin1")).not.toContain("SECRET-PLAINTEXT-NEEDLE");
    // Different ivs → different ciphertext for the same plaintext.
    expect(Buffer.from(c.encrypt(msg)).equals(blob)).toBe(false);
  });

  it("rejects a tampered blob (GCM auth) → null, not garbage", () => {
    const c = TranscriptCipher.fromKey();
    const blob = c.encrypt(new TextEncoder().encode("hello"));
    const tampered = Buffer.from(blob);
    tampered[tampered.length - 1] ^= 0xff; // flip a tag byte
    expect(c.decrypt(tampered)).toBeNull();
    expect(c.decrypt(new Uint8Array(4))).toBeNull(); // too short
  });

  it("a different key cannot decrypt", () => {
    const a = TranscriptCipher.fromKey();
    const b = TranscriptCipher.fromKey();
    const blob = a.encrypt(new TextEncoder().encode("hello"));
    expect(b.decrypt(blob)).toBeNull();
  });
});
