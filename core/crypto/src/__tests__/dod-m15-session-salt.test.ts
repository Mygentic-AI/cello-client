/**
 * THE SESSION SALT — Decisions Carried #8, #9, #10.
 *
 * ─── The exposure this closes, which is live today ─────────────────────────────────────────────
 *
 * `wireContentHash` is `SHA-256(0x00 ‖ content)` and nothing session-specific enters it. So the same
 * message text is the same 32 bytes in **every conversation, between every pair of agents, forever**.
 * A relay holding stored hashes can guess a short predictable message — "yes", "approved", a price,
 * a name — confirm it, and then find that same message everywhere it ever appeared, across sessions
 * and across agent pairs (`DOD-M15-HASHCORRELATE-1`).
 *
 * ─── The design, and why it is NOT a second output of the key agreement ────────────────────────
 *
 * It was, and that was the defect: the envelope key must be DESTROYED at close, the salt must SURVIVE
 * for the life of the session, and deriving both from one secret tied "must be forgotten" to "must be
 * kept forever". Same exchange, two independent values.
 *
 * ─── Both sides contribute, and the test that matters is the adversarial one ───────────────────
 *
 * A single minter could destroy the property for BOTH parties — the client is open source, so an
 * operator can modify their own build to always send the same salt, or a low-entropy one, and the
 * honest peer cannot tell. Both-contribute means one honest participant is enough.
 */

import { describe, it, expect } from "vitest";
import { createHash, createHmac } from "node:crypto";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  generateSaltContribution,
  deriveSessionSalt,
  saltFingerprint,
  saltedContentHash,
  SESSION_SALT_BYTES,
  SALT_FINGERPRINT_BYTES,
} from "../session-salt.js";

describe("session salt: both sides agree on the same value", () => {
  it("★ the two sides derive an IDENTICAL salt from opposite halves", () => {
    const a = generateSaltContribution();
    const b = generateSaltContribution();
    expect(Buffer.from(deriveSessionSalt(a, b))).toEqual(Buffer.from(deriveSessionSalt(b, a)));
  });

  it("★ order-independent — neither side needs to know who initiated", () => {
    /**
     * The two daemons reach this from different code paths. Ordering by ROLE would mean a
     * disagreement about who started the session produced two different salts — and a salt
     * disagreement is the least debuggable failure here, because the send succeeds and the receiver
     * discards silently.
     */
    const a = new Uint8Array(32).fill(0x11);
    const b = new Uint8Array(32).fill(0x22);
    expect(Buffer.from(deriveSessionSalt(a, b))).toEqual(Buffer.from(deriveSessionSalt(b, a)));
  });

  it("the salt is 32 bytes — asserted as a literal, not the module's own constant", () => {
    expect(deriveSessionSalt(generateSaltContribution(), generateSaltContribution())).toHaveLength(32);
    expect(SESSION_SALT_BYTES).toBe(32);
  });

  it("★ every session gets a DIFFERENT salt — that is what breaks cross-session correlation", () => {
    const s1 = deriveSessionSalt(generateSaltContribution(), generateSaltContribution());
    const s2 = deriveSessionSalt(generateSaltContribution(), generateSaltContribution());
    expect(Buffer.from(s1)).not.toEqual(Buffer.from(s2));
  });
});

describe("session salt: ONE honest participant is enough", () => {
  it("★ a peer that reuses a FIXED contribution cannot fix the salt", () => {
    /**
     * The adversary this design is actually about: a modified open-source client that always sends
     * the same contribution. If the salt were initiator-minted, that client would make every one of
     * its conversations guessable by any relay holding the hashes — for BOTH parties — and the
     * honest peer could never tell.
     *
     * With both contributing, the honest side's fresh randomness carries the property alone.
     */
    const hostileFixed = new Uint8Array(32).fill(0x42);
    const s1 = deriveSessionSalt(generateSaltContribution(), hostileFixed);
    const s2 = deriveSessionSalt(generateSaltContribution(), hostileFixed);
    expect(
      Buffer.from(s1),
      "a peer sending a constant contribution pinned the salt, so every conversation with that " +
        "client shares one salt and the correlation attack is back",
    ).not.toEqual(Buffer.from(s2));
  });

  it("★ our own contribution genuinely changes the result — it is used, not decorative", () => {
    const peer = new Uint8Array(32).fill(0x42);
    const s1 = deriveSessionSalt(new Uint8Array(32).fill(0x01), peer);
    const s2 = deriveSessionSalt(new Uint8Array(32).fill(0x02), peer);
    expect(Buffer.from(s1)).not.toEqual(Buffer.from(s2));
  });

  it("★ an ALL-ZERO peer contribution is REFUSED — it is a peer contributing nothing", () => {
    /**
     * The same posture the key agreement takes toward a small-order point. A peer that contributes
     * nothing has unilaterally decided the salt, which is precisely what both-contribute prevents.
     * Accepting it would look like it worked.
     */
    expect(() => deriveSessionSalt(generateSaltContribution(), new Uint8Array(32))).toThrow(
      /all zeros|contributed nothing/i,
    );
  });

  it("★ a wrong-length peer contribution is refused rather than padded", () => {
    expect(() => deriveSessionSalt(generateSaltContribution(), new Uint8Array(16).fill(9))).toThrow(/32 bytes/);
  });

  it("a wrong-length contribution of OUR OWN says it is a local defect", () => {
    expect(() => deriveSessionSalt(new Uint8Array(8), generateSaltContribution())).toThrow(/local defect/i);
  });
});

describe("session salt: the mismatch check is loud, and never leaks the salt", () => {
  it("★ equal salts produce equal fingerprints", () => {
    const s = deriveSessionSalt(generateSaltContribution(), generateSaltContribution());
    expect(Buffer.from(saltFingerprint(s))).toEqual(Buffer.from(saltFingerprint(s)));
  });

  it("★ different salts produce different fingerprints — the disagreement is detectable at open", () => {
    /**
     * Decision #10. Without this, a salt disagreement fails EVERY message at the receive-path
     * authenticity check — the send succeeds, the sender's log says the frame left, and the receiver
     * discards before logging anything about it. `wire-content-hash.ts` calls that the least
     * debuggable shape there is, and it cost two real daemons to find once already.
     */
    const s1 = deriveSessionSalt(generateSaltContribution(), generateSaltContribution());
    const s2 = deriveSessionSalt(generateSaltContribution(), generateSaltContribution());
    expect(Buffer.from(saltFingerprint(s1))).not.toEqual(Buffer.from(saltFingerprint(s2)));
  });

  it("★ the fingerprint is NOT the salt, and is short enough that nobody mistakes it for one", () => {
    const s = deriveSessionSalt(generateSaltContribution(), generateSaltContribution());
    const fp = saltFingerprint(s);
    expect(fp).toHaveLength(8);
    expect(SALT_FINGERPRINT_BYTES).toBe(8);
    expect(Buffer.from(s).toString("hex")).not.toContain(Buffer.from(fp).toString("hex"));
  });
});

describe("content hash: salted, and HMAC rather than concatenation", () => {
  const salt = new Uint8Array(32).fill(0x33);
  const msg = new TextEncoder().encode("approved");

  it("★ the SAME message under DIFFERENT salts hashes differently — the correlation attack dies", () => {
    /**
     * This is the whole point of HASHCORRELATE-1. Today "approved" is the same 32 bytes in every
     * conversation ever held; salted per session, a relay cannot carry a confirmed guess from one
     * session to another.
     */
    const other = new Uint8Array(32).fill(0x44);
    expect(Buffer.from(saltedContentHash(salt, msg))).not.toEqual(Buffer.from(saltedContentHash(other, msg)));
  });

  it("the same message under the SAME salt is stable — the receiver must be able to recompute it", () => {
    expect(Buffer.from(saltedContentHash(salt, msg))).toEqual(Buffer.from(saltedContentHash(salt, msg)));
  });

  it("★ it is HMAC, not SHA-256(salt || 0x00 || content)", () => {
    /**
     * Decision #9. The naive concatenation is length-extendable: an attacker holding `H(salt ‖ m)`
     * and `|salt|` can compute `H(salt ‖ m ‖ pad ‖ m')` without knowing the salt. Asserting the
     * construction rather than trusting the comment — a comment naming a construction is exactly
     * what this milestone keeps catching.
     */
    const naive = new Uint8Array(
      createHash("sha256").update(salt).update(new Uint8Array([0x00])).update(msg).digest(),
    );
    const got = saltedContentHash(salt, msg);
    expect(Buffer.from(got), "this is the length-extendable construction the decision rules out").not.toEqual(Buffer.from(naive));

    const expectedHmac = new Uint8Array(
      createHmac("sha256", Buffer.from(salt)).update(Buffer.concat([Buffer.from([0x00]), Buffer.from(msg)])).digest(),
    );
    expect(Buffer.from(got), "and it must be exactly HMAC-SHA-256 over 0x00 || content").toEqual(Buffer.from(expectedHmac));
  });

  it("the 0x00 domain byte is inside the HMAC, so salted and unsalted forms cannot collide", () => {
    const withoutDomain = new Uint8Array(
      createHmac("sha256", Buffer.from(salt)).update(Buffer.from(msg)).digest(),
    );
    expect(Buffer.from(saltedContentHash(salt, msg))).not.toEqual(Buffer.from(withoutDomain));
  });
});

describe("session salt: the derivation itself is pinned, byte for byte", () => {
  /**
   * THE REVIEW MEASURED THIS RATHER THAN ARGUING IT: an implementation using **XOR** instead of
   * sorted concatenation passes every one of the eight assertions above.
   *
   * XOR is commutative, so order-independence holds. Both contributions still "matter". A peer
   * reusing a fixed contribution still cannot pin the salt. And yet it is catastrophically broken:
   * **whoever sends SECOND sees the first contribution and sets `b = a XOR target`**, forcing the
   * salt to any pre-agreed constant — one shared in advance with a colluding relay, identical in
   * every session, one rainbow table forever. That is precisely the "a single party unilaterally
   * decides the salt" failure Decision #8 exists to prevent, and the test named "a peer that reuses a
   * FIXED contribution cannot fix the salt" goes GREEN while it happens.
   *
   * The cause is the same one the KEYAGREE review found: every assertion compared the function
   * against ITSELF. Behavioural properties cannot distinguish two commutative combiners. Only the
   * bytes can.
   *
   * Recomputed independently from the module header's construction rather than snapshotted, because
   * a snapshot of XOR is XOR with a test.
   */
  const A = new Uint8Array(32).fill(0x11);
  const B = new Uint8Array(32).fill(0x22);

  function expectedSalt(x: Uint8Array, y: Uint8Array): Uint8Array {
    // sorted(x, y) concatenated — written out here, not imported, so an inverted or absent sort in
    // the module cannot be inherited by the expectation.
    const [first, second] = Buffer.compare(Buffer.from(x), Buffer.from(y)) < 0 ? [x, y] : [y, x];
    const ikm = new Uint8Array(64);
    ikm.set(first, 0);
    ikm.set(second, 32);
    return hkdf(sha256, ikm, new Uint8Array(0), new TextEncoder().encode("cello/session/v1/salt"), 32);
  }

  it("★ the salt is HKDF over sorted(a)‖sorted(b) — not XOR, not either half alone", () => {
    expect(
      Buffer.from(deriveSessionSalt(A, B)).toString("hex"),
      "the combiner is not sorted concatenation. If it is commutative-but-reversible (XOR), the " +
        "second mover can force the salt to a value chosen in advance with a colluding relay.",
    ).toBe(Buffer.from(expectedSalt(A, B)).toString("hex"));
  });

  it("★ and an XOR combiner is explicitly NOT what this produces", () => {
    // The concrete mutant the review ran. Pinned by name so it cannot come back quietly.
    const xored = new Uint8Array(32);
    for (let i = 0; i < 32; i++) xored[i] = (A[i] as number) ^ (B[i] as number);
    const xorSalt = hkdf(sha256, xored, new Uint8Array(0), new TextEncoder().encode("cello/session/v1/salt"), 32);
    expect(Buffer.from(deriveSessionSalt(A, B))).not.toEqual(Buffer.from(xorSalt));
  });

  it("★ the FINGERPRINT is one-way, asserted as bytes rather than as 'not a substring'", () => {
    /**
     * Review F5, also measured: a mutant returning `salt[0..8] XOR 0xff` — the salt's first eight
     * bytes, trivially invertible — passed all four previous assertions in 20,000 of 20,000 trials.
     * The fingerprint travels on the wire at session open, so that mutant publishes 64 bits of the
     * salt to the relay every time.
     */
    const salt = deriveSessionSalt(A, B);
    const want = hkdf(sha256, salt, new Uint8Array(0), new TextEncoder().encode("cello/session/v1/salt-fingerprint"), 8);
    expect(Buffer.from(saltFingerprint(salt)).toString("hex")).toBe(Buffer.from(want).toString("hex"));
  });
});

describe("session salt: refusals are symmetric — a local fault does not blame the peer", () => {
  it("★ our OWN all-zero contribution is refused, and says it is LOCAL", () => {
    /**
     * Review F6. Without this, a daemon with a broken RNG derives happily and the PEER refuses,
     * so the operator whose machine is broken reads a message blaming their counterparty.
     */
    expect(() => deriveSessionSalt(new Uint8Array(32), generateSaltContribution())).toThrow(/LOCAL defect/i);
  });

  it("★ a REFLECTED contribution — the peer echoing ours — is refused", () => {
    const ours = generateSaltContribution();
    expect(() => deriveSessionSalt(ours, Uint8Array.from(ours))).toThrow(/reflection|contributed\s+nothing/i);
  });
});
