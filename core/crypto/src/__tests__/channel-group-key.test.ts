/**
 * M16 019-MEMBERSHIP Part A — the channel group key.
 *
 * A channel's bodies are encrypted under a per-channel GROUP KEY, and the FETCH KEY derived from it
 * is what the relay checks before it will serve the queue at all. That pairing is the whole reason
 * ejection is a re-key: rotating the group key also rotates the fetch key, so an ejected member
 * cannot read new posts AND cannot even ask for them.
 *
 * Tests 1–5 of the order. Written before the implementation, red first.
 */
import { describe, it, expect } from "vitest";
import { generateKeypair, verify } from "../ed25519.js";
import {
  generateGroupKey,
  encryptBody,
  decryptBody,
  wrapGroupKeyFor,
  unwrapGroupKey,
  deriveFetchKey,
  type GroupKey,
} from "../channel-group-key.js";

const CHANNEL_A = new Uint8Array(Buffer.alloc(32, 0xa1));
const CHANNEL_B = new Uint8Array(Buffer.alloc(32, 0xb2));
const text = (s: string): Uint8Array => new TextEncoder().encode(s);

describe("M16 019 Part A — the group key", () => {
  it("1. a body encrypted under a generation round-trips, and the ciphertext is not the plaintext", () => {
    const gk = generateGroupKey(1);
    const body = encryptBody(gk, CHANNEL_A, 7, text("the announcement"));

    // Not a marker-byte-and-plaintext arrangement: a subscriber's body sits on two relays, and a
    // relay that can read it makes the group key decorative.
    expect(Buffer.from(body).toString("utf-8")).not.toContain("the announcement");

    const opened = decryptBody([gk], CHANNEL_A, 7, body);
    expect(opened.ok, opened.ok ? "" : opened.reason).toBe(true);
    if (!opened.ok) return;
    expect(new TextDecoder().decode(opened.plaintext)).toBe("the announcement");
    expect(opened.generation).toBe(1);
  });

  it("2. a body MOVED to another seq, channel or generation fails auth_failed", () => {
    const gk = generateGroupKey(1);
    const body = encryptBody(gk, CHANNEL_A, 7, text("post seven"));

    /**
     * ⚠️ **THE ASSOCIATED DATA IS WHAT STOPS A RELAY REORDERING A CHANNEL.** Without seq and channel
     * bound into the encryption, a relay could serve post 7's body at position 3, or serve channel
     * A's bodies as channel B's, and every signature would still verify — the signature covers the
     * post, and the post is what the relay is replaying whole.
     */
    expect(decryptBody([gk], CHANNEL_A, 8, body)).toEqual({ ok: false, reason: "auth_failed" });
    expect(decryptBody([gk], CHANNEL_B, 7, body)).toEqual({ ok: false, reason: "auth_failed" });

    // A different key at the SAME generation number is a different key, and says so as auth_failed
    // rather than as an unknown generation — the generation is present, the key is wrong.
    const impostor: GroupKey = { generation: 1, key: generateGroupKey(1).key };
    expect(decryptBody([impostor], CHANNEL_A, 7, body)).toEqual({ ok: false, reason: "auth_failed" });
  });

  it("3. an unknown generation is its OWN reason, and nothing ever throws", () => {
    const gen1 = generateGroupKey(1);
    const gen2 = generateGroupKey(2);
    const body = encryptBody(gen2, CHANNEL_A, 1, text("after the re-key"));

    /**
     * ⚠️ A member who missed a re-key holds only generation 1. That is a RECOVERABLE state — ask for
     * the new key — and it must be distinguishable from a forgery. Folding it into `auth_failed`
     * would have a member who simply missed a message treat the channel as hostile.
     */
    expect(decryptBody([gen1], CHANNEL_A, 1, body)).toEqual({ ok: false, reason: "unknown_generation" });

    // Holding BOTH works, and old generations stay readable for old content.
    const old = encryptBody(gen1, CHANNEL_A, 1, text("before the re-key"));
    const opened = decryptBody([gen1, gen2], CHANNEL_A, 1, old);
    expect(opened.ok && new TextDecoder().decode(opened.plaintext)).toBe("before the re-key");

    // ⚠️ NEVER THROWS, for any input. A relay can hand a subscriber whatever it likes.
    for (const junk of [new Uint8Array(0), new Uint8Array([1]), new Uint8Array(Buffer.alloc(64, 0xff))]) {
      const answer = decryptBody([gen1, gen2], CHANNEL_A, 1, junk);
      expect(answer.ok).toBe(false);
      if (!answer.ok) expect(["malformed", "auth_failed", "unknown_generation"]).toContain(answer.reason);
    }
  });

  it("4. a wrapped key opens for the member it was wrapped for, and for nobody else", async () => {
    const gk = generateGroupKey(3);
    const admin = generateKeypair();
    const member = generateKeypair();
    const stranger = generateKeypair();

    const bundle = await wrapGroupKeyFor(gk, CHANNEL_A, await member.getPublicKey(), admin);

    const opened = await unwrapGroupKey(bundle, CHANNEL_A, member);
    expect(opened.ok, opened.ok ? "" : opened.reason).toBe(true);
    if (!opened.ok) return;
    expect(opened.gk.generation).toBe(3);
    expect(Buffer.from(opened.gk.key).equals(Buffer.from(gk.key))).toBe(true);

    // ⚠️ The bundle is addressed to ONE member. A re-key hands each remaining member their own, and
    // an ejected member is simply not given one — which is only meaningful if theirs cannot be used.
    const byStranger = await unwrapGroupKey(bundle, CHANNEL_A, stranger);
    expect(byStranger.ok).toBe(false);

    // And a bundle for channel A does not open as channel B's, even by its rightful member: the
    // channel is bound in, so a bundle cannot be replayed into another channel's join.
    const wrongChannel = await unwrapGroupKey(bundle, CHANNEL_B, member);
    expect(wrongChannel.ok).toBe(false);
  });

  it("5. the fetch key is DETERMINISTIC per (key, generation, channel) and useless anywhere else", async () => {
    const gk = generateGroupKey(1);

    const first = await deriveFetchKey(gk, CHANNEL_A);
    const again = await deriveFetchKey(gk, CHANNEL_A);
    // ⚠️ DETERMINISTIC: the publisher gives the relay this public key, and every member derives the
    // same private half from the group key. A random one would mean the members could not sign what
    // the relay is checking.
    expect(Buffer.from(first.publicKey).equals(Buffer.from(again.publicKey))).toBe(true);

    // A re-key yields a different fetch key — which is what actually ends an ejected member's
    // access: they cannot fetch, not merely cannot decrypt.
    const nextGen = await deriveFetchKey({ generation: 2, key: gk.key }, CHANNEL_A);
    expect(Buffer.from(nextGen.publicKey).equals(Buffer.from(first.publicKey))).toBe(false);

    // And the channel is bound in, so a member of A cannot sign fetches for B.
    const otherChannel = await deriveFetchKey(gk, CHANNEL_B);
    expect(Buffer.from(otherChannel.publicKey).equals(Buffer.from(first.publicKey))).toBe(false);

    // The derived pair genuinely signs and verifies — it is an Ed25519 key, not a hash that looks
    // like one, and the relay verifies a real signature with it.
    const message = text("since_seq=5");
    const signature = await first.sign(message);
    expect(verify(first.publicKey, message, signature)).toBe(true);
    expect(verify(otherChannel.publicKey, message, signature)).toBe(false);
  });
});
