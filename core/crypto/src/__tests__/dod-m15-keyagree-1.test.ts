/**
 * DOD-M15-KEYAGREE-1 — CELLO owns its own confidentiality guarantee.
 *
 * ─── Why this is urgent rather than later ──────────────────────────────────────────────────────
 *
 * Live content today is plaintext inside libp2p's Noise session. The confidentiality is real, but it
 * is **libp2p's** key agreement over **libp2p's** ephemeral transport keys — so CELLO cannot upgrade
 * its own guarantee, and a PQ migration would happen on libp2p's timeline with libp2p's algorithm
 * choices.
 *
 * The threat is harvest-now-decrypt-later. Every cross-NAT conversation is relayed today, therefore
 * recordable at fixed endpoints today, and adding this layer later does not protect traffic already
 * sent.
 *
 * ─── The counterbalance, named before the code ─────────────────────────────────────────────────
 *
 * A key-agreement layer can be worse than none. The three ways this could go wrong, each of which
 * has a test below:
 *
 *   1. **Static-static instead of ephemeral-ephemeral.** A key derived only from long-term identity
 *      keys is the same key forever, so anyone who ever obtains an identity key decrypts every
 *      conversation that agent ever had. Strictly worse than today, and `design-problems` already
 *      claims forward secrecy as structural.
 *   2. **A degenerate shared secret accepted silently.** X25519 against a small-order point yields
 *      an all-zero secret. Deriving from it produces a key both sides agree on and an attacker also
 *      knows — encryption that looks like it is working. This must FAIL CLOSED, loudly.
 *   3. **The PQ hook present in prose only.** The line is explicit that the derivation must accept an
 *      additional shared secret FROM DAY ONE, *"before there is a PQ contribution to put in it —
 *      omitting the hook defeats the entire reason for the work."* A parameter nothing exercises is
 *      a comment; the test below proves a different extra secret yields a different key.
 *
 * ─── One agreement, two outputs ────────────────────────────────────────────────────────────────
 *
 * The message-sealing key and the per-session content-hash salt come from the SAME agreement under
 * different HKDF labels. They must never be equal — the salt is disclosed to anyone who can see a
 * content hash, and if it equalled the key that would hand over the key.
 */

import { describe, it, expect } from "vitest";
import { x25519 } from "@noble/curves/ed25519.js";
import {
  generateSessionEphemeral,
  deriveSessionSecrets,
  SESSION_KEY_BYTES,
  SESSION_SALT_BYTES,
} from "../session-key-agreement.js";

const SESSION_ID = new Uint8Array(16).fill(7);

/** A full two-sided handshake, as the two daemons would run it. */
function handshake(opts: { sessionId?: Uint8Array; extraA?: Uint8Array; extraB?: Uint8Array } = {}) {
  const sid = opts.sessionId ?? SESSION_ID;
  const a = generateSessionEphemeral();
  const b = generateSessionEphemeral();
  return {
    a,
    b,
    fromA: deriveSessionSecrets({
      ownEphemeralSecret: a.secretKey,
      peerEphemeralPublic: b.publicKey,
      sessionId: sid,
      ...(opts.extraA ? { extraSharedSecret: opts.extraA } : {}),
    }),
    fromB: deriveSessionSecrets({
      ownEphemeralSecret: b.secretKey,
      peerEphemeralPublic: a.publicKey,
      sessionId: sid,
      ...(opts.extraB ? { extraSharedSecret: opts.extraB } : {}),
    }),
  };
}

describe("DOD-M15-KEYAGREE-1: both sides agree, and nobody else can", () => {
  it("★ the two sides derive the SAME key and salt from opposite halves", () => {
    const { fromA, fromB } = handshake();
    expect(Buffer.from(fromA.contentKey)).toEqual(Buffer.from(fromB.contentKey));
    expect(Buffer.from(fromA.contentSalt)).toEqual(Buffer.from(fromB.contentSalt));
  });

  it("★ the derivation is ORDER-INDEPENDENT — neither side needs to know who initiated", () => {
    /**
     * Both public keys are bound into the derivation in a canonical (sorted) order. Binding them by
     * ROLE would work only if both sides agreed on who the initiator was — and the two daemons reach
     * this point from different code paths, so a role disagreement would produce two different keys
     * and a conversation that fails to decrypt with no explanation.
     */
    const a = generateSessionEphemeral();
    const b = generateSessionEphemeral();
    const one = deriveSessionSecrets({ ownEphemeralSecret: a.secretKey, peerEphemeralPublic: b.publicKey, sessionId: SESSION_ID });
    const two = deriveSessionSecrets({ ownEphemeralSecret: b.secretKey, peerEphemeralPublic: a.publicKey, sessionId: SESSION_ID });
    expect(Buffer.from(one.contentKey)).toEqual(Buffer.from(two.contentKey));
  });

  it("★ the key and the salt are DIFFERENT — the salt is disclosed, the key must not be", () => {
    /**
     * The content-hash salt travels wherever a content hash does; the relay sees it. Deriving both
     * from one agreement is right, but deriving them to the same VALUE would hand the sealing key to
     * everyone who can see a hash.
     */
    const { fromA } = handshake();
    expect(Buffer.from(fromA.contentKey)).not.toEqual(Buffer.from(fromA.contentSalt));
    expect(fromA.contentKey).toHaveLength(SESSION_KEY_BYTES);
    expect(fromA.contentSalt).toHaveLength(SESSION_SALT_BYTES);
  });

  it("★ a THIRD party with both public keys cannot derive it — this is the whole point", () => {
    const a = generateSessionEphemeral();
    const b = generateSessionEphemeral();
    const eve = generateSessionEphemeral();
    const real = deriveSessionSecrets({ ownEphemeralSecret: a.secretKey, peerEphemeralPublic: b.publicKey, sessionId: SESSION_ID });
    const guess = deriveSessionSecrets({ ownEphemeralSecret: eve.secretKey, peerEphemeralPublic: b.publicKey, sessionId: SESSION_ID });
    expect(Buffer.from(real.contentKey)).not.toEqual(Buffer.from(guess.contentKey));
  });
});

describe("DOD-M15-KEYAGREE-1: forward secrecy is structural, not aspirational", () => {
  it("★ every session mints FRESH ephemerals — two handshakes never share a key", () => {
    /**
     * Counterbalance 1. If this ever returned a stable keypair, the derived key would be the same
     * key forever and an identity-key compromise would open every past conversation — strictly worse
     * than the libp2p Noise session this replaces.
     */
    const first = handshake();
    const second = handshake();
    expect(Buffer.from(first.a.publicKey)).not.toEqual(Buffer.from(second.a.publicKey));
    expect(Buffer.from(first.fromA.contentKey)).not.toEqual(Buffer.from(second.fromA.contentKey));
  });

  it("★ the same peers in a DIFFERENT session derive a different key", () => {
    // The session id is bound into the derivation, so even a catastrophic ephemeral reuse cannot
    // make two sessions share a key.
    const a = generateSessionEphemeral();
    const b = generateSessionEphemeral();
    const s1 = deriveSessionSecrets({ ownEphemeralSecret: a.secretKey, peerEphemeralPublic: b.publicKey, sessionId: new Uint8Array(16).fill(1) });
    const s2 = deriveSessionSecrets({ ownEphemeralSecret: a.secretKey, peerEphemeralPublic: b.publicKey, sessionId: new Uint8Array(16).fill(2) });
    expect(Buffer.from(s1.contentKey)).not.toEqual(Buffer.from(s2.contentKey));
  });
});

describe("DOD-M15-KEYAGREE-1: the PQ hook exists and WORKS on day one", () => {
  it("★ an extra shared secret changes the derived key", () => {
    /**
     * Counterbalance 3, and the line is blunt about it: *"Omitting the hook defeats the entire
     * reason for the work."* A parameter that is accepted and ignored is worse than none, because it
     * reads as done. Hybrid PQ must be "mix a second agreed secret into the same derivation" — an
     * addition, not a rewrite.
     */
    const a = generateSessionEphemeral();
    const b = generateSessionEphemeral();
    const base = { ownEphemeralSecret: a.secretKey, peerEphemeralPublic: b.publicKey, sessionId: SESSION_ID };
    const plain = deriveSessionSecrets(base);
    const hybrid = deriveSessionSecrets({ ...base, extraSharedSecret: new Uint8Array(32).fill(9) });
    expect(
      Buffer.from(plain.contentKey),
      "the extra secret was accepted and ignored — the PQ hook is a comment",
    ).not.toEqual(Buffer.from(hybrid.contentKey));
  });

  it("★ both sides supplying the SAME extra secret still agree", () => {
    const extra = new Uint8Array(32).fill(3);
    const { fromA, fromB } = handshake({ extraA: extra, extraB: extra });
    expect(Buffer.from(fromA.contentKey)).toEqual(Buffer.from(fromB.contentKey));
  });

  it("★ a MISMATCHED extra secret yields different keys — it is bound, not decorative", () => {
    /**
     * The direction that matters for a future hybrid: if one side runs a PQ KEM and the other does
     * not, they must NOT silently agree on a classical-only key. They diverge, and the session fails
     * to decrypt — which is the safe failure.
     */
    const { fromA, fromB } = handshake({ extraA: new Uint8Array(32).fill(3), extraB: new Uint8Array(32).fill(4) });
    expect(Buffer.from(fromA.contentKey)).not.toEqual(Buffer.from(fromB.contentKey));
  });

  it("an extra secret of ANY length is accepted — a KEM output is not 32 bytes", () => {
    // ML-KEM-768 shared secrets are 32 bytes, but a hybrid may concatenate more than one
    // contribution. Fixing the length here would force a rewrite for the exact case the hook exists
    // for.
    const a = generateSessionEphemeral();
    const b = generateSessionEphemeral();
    const base = { ownEphemeralSecret: a.secretKey, peerEphemeralPublic: b.publicKey, sessionId: SESSION_ID };
    expect(() => deriveSessionSecrets({ ...base, extraSharedSecret: new Uint8Array(1088).fill(1) })).not.toThrow();
  });
});

describe("DOD-M15-KEYAGREE-1: a degenerate agreement FAILS CLOSED", () => {
  it("★ an all-zero shared secret is REFUSED, not derived from", () => {
    /**
     * Counterbalance 2, and the one that would be silent. X25519 against a small-order point yields
     * an all-zero shared secret — both sides then derive the same key, encryption appears to work,
     * and an attacker who supplied the point knows it too. Encryption that looks like it is working
     * is worse than none, because nobody investigates.
     *
     * The all-zero point is the canonical small-order input (RFC 7748 §6.1 requires implementations
     * to reject the resulting zero output).
     */
    const a = generateSessionEphemeral();
    expect(
      () => deriveSessionSecrets({
        ownEphemeralSecret: a.secretKey,
        peerEphemeralPublic: new Uint8Array(32), // all-zero: a small-order point
        sessionId: SESSION_ID,
      }),
      "a degenerate agreement produced a usable key — the session would encrypt with a key the " +
        "attacker who supplied the point also holds, and nothing would look wrong",
    ).toThrow(/degenerate|zero|small.order|invalid/i);
  });

  it("★ a wrong-length peer key is refused rather than padded", () => {
    const a = generateSessionEphemeral();
    expect(() => deriveSessionSecrets({
      ownEphemeralSecret: a.secretKey,
      peerEphemeralPublic: new Uint8Array(16).fill(2),
      sessionId: SESSION_ID,
    })).toThrow(/32|length/i);
  });

  it("★ an empty session id is refused — the binding must be real", () => {
    const a = generateSessionEphemeral();
    const b = generateSessionEphemeral();
    expect(() => deriveSessionSecrets({
      ownEphemeralSecret: a.secretKey,
      peerEphemeralPublic: b.publicKey,
      sessionId: new Uint8Array(0),
    })).toThrow(/session/i);
  });

  it("the ephemeral public key really is the X25519 public of the secret", () => {
    // Guards against a generator that returns unrelated halves — which would make both sides derive
    // different keys and look like a network fault.
    const e = generateSessionEphemeral();
    expect(Buffer.from(x25519.getPublicKey(e.secretKey))).toEqual(Buffer.from(e.publicKey));
  });
});
