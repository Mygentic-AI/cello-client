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
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  generateSessionEphemeral,
  deriveSessionSecrets,
  SESSION_KEY_BYTES,
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
  it("★ the two sides derive the SAME key from opposite halves", () => {
    const { fromA, fromB } = handshake();
    expect(Buffer.from(fromA.contentKey)).toEqual(Buffer.from(fromB.contentKey));
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

  it("★ this agreement produces ONE output — the salt is not derived here", () => {
    /**
     * Decisions Carried #8. The salt used to be a second HKDF output of this function, and that
     * coupling tied "must be forgotten" (the key, destroyed at close) to "must be kept forever" (the
     * salt, which the transcript needs for its whole life). It lives in `session-salt.ts` now,
     * agreed in the same exchange from both sides' contributions.
     *
     * Asserted rather than left to the header, so a future reader who adds a second output has to
     * delete a test that says why it was removed.
     */
    const { fromA } = handshake();
    expect(Object.keys(fromA)).toEqual(["contentKey"]);
    expect(fromA.contentKey).toHaveLength(32);
    expect(SESSION_KEY_BYTES).toBe(32);
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
     *
     * DELIBERATELY PINS THE PROPERTY, NOT THE PRODUCER. Today `@noble/curves` refuses first
     * ("invalid private or public key received") and our own all-zero check never runs — the revert
     * test proved that by deleting the check and staying green. Asserting *that it is refused*
     * rather than *who refuses* is what keeps this test meaningful across a dependency upgrade: if
     * `@noble` ever stopped rejecting, the backstop would take over and this test would still pass;
     * if BOTH stopped, it goes red, which is the case that matters.
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

describe("DOD-M15-KEYAGREE-1: the derivation itself is pinned, byte for byte", () => {
  /**
   * SIX OF EIGHT MUTANTS SURVIVED the first version of this file. Deleting the pubkey binding,
   * inverting the sort, swapping the two output labels, replacing the content salt with a hardcoded
   * constant, dropping the sessionId from the salt's derivation, and truncating both outputs to 16
   * bytes ALL stayed green.
   *
   * The reason is structural: every behavioural property here — both sides agree, a third party
   * cannot, a different session differs — is satisfied by X25519 alone. Those tests constrain the
   * curve, not this module. Nothing constrained the BYTES.
   *
   * ─── Why this recomputes rather than snapshots ─────────────────────────────────────────────
   *
   * A fixed hex vector captured from the current implementation would pin drift, but it would pin
   * whatever the implementation does today INCLUDING a mistake — a snapshot of a label swap is a
   * label swap with a test. So this expresses the construction INDEPENDENTLY, from the pseudocode in
   * the module header, and checks the module agrees:
   *
   *     shared = X25519(ownSk, peerPk)
   *     ikm    = shared || extra
   *     bind   = sorted(ownPk, peerPk)
   *     out    = HKDF-SHA256(ikm, salt=sessionId, info=label || bind, 32)
   *
   * If the module and this arithmetic disagree, one of them is wrong and the diff says which.
   */
  const hkdfRef = (ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, len: number) => hkdf(sha256, ikm, salt, info, len);

  function expected(ownSk: Uint8Array, peerPk: Uint8Array, sessionId: Uint8Array, extra?: Uint8Array) {
    const shared = x25519.getSharedSecret(ownSk, peerPk);
    const ownPk = x25519.getPublicKey(ownSk);
    const e = extra ?? new Uint8Array(0);
    const ikm = new Uint8Array(shared.length + e.length);
    ikm.set(shared, 0);
    ikm.set(e, shared.length);
    // Sorted lexicographically — written out here rather than imported, so an inverted sort in the
    // module cannot be inherited by the expectation.
    const cmp = Buffer.compare(Buffer.from(ownPk), Buffer.from(peerPk));
    const [first, second] = cmp < 0 ? [ownPk, peerPk] : [peerPk, ownPk];
    const enc = new TextEncoder();
    const withBind = (label: string) => {
      const l = enc.encode(label);
      const out = new Uint8Array(l.length + 64);
      out.set(l, 0); out.set(first, l.length); out.set(second, l.length + 32);
      return out;
    };
    return { contentKey: hkdfRef(ikm, sessionId, withBind("cello/session/v1/content-key"), 32) };
  }

  // Fixed inputs so the case is deterministic and reviewable, not whatever randomness produced.
  const SK_A = new Uint8Array(32).fill(0x11);
  const SK_B = new Uint8Array(32).fill(0x22);
  const SID = new Uint8Array(16).fill(0x33);

  it("★ contentKey matches the construction recomputed from the spec", () => {
    const pkB = x25519.getPublicKey(SK_B);
    const got = deriveSessionSecrets({ ownEphemeralSecret: SK_A, peerEphemeralPublic: pkB, sessionId: SID });
    const want = expected(SK_A, pkB, SID);
    expect(
      Buffer.from(got.contentKey).toString("hex"),
      "the module's content key does not match HKDF-SHA256(shared, salt=sessionId, " +
        "info='cello/session/v1/content-key'||sorted(pubkeys)) — one of the label, the sort order, " +
        "the binding, or the salt assignment has changed",
    ).toBe(Buffer.from(want.contentKey).toString("hex"));
  });

  it("★ the PQ extra secret is mixed in exactly as the spec says", () => {
    const pkB = x25519.getPublicKey(SK_B);
    const extra = new Uint8Array(48).fill(0x44);
    const got = deriveSessionSecrets({ ownEphemeralSecret: SK_A, peerEphemeralPublic: pkB, sessionId: SID, extraSharedSecret: extra });
    expect(Buffer.from(got.contentKey).toString("hex")).toBe(
      Buffer.from(expected(SK_A, pkB, SID, extra).contentKey).toString("hex"),
    );
  });

  it("★ the outputs are 32 bytes — asserted as a LITERAL, not the module's own constant", () => {
    /**
     * The previous length assertion used `SESSION_KEY_BYTES`, so truncating both outputs to 16 and
     * moving the constant with them passed. A self-referential assertion cannot fail.
     */
    const pkB = x25519.getPublicKey(SK_B);
    const got = deriveSessionSecrets({ ownEphemeralSecret: SK_A, peerEphemeralPublic: pkB, sessionId: SID });
    expect(got.contentKey).toHaveLength(32);
    expect(SESSION_KEY_BYTES, "and the exported constant must agree with reality").toBe(32);
  });

});

describe("DOD-M15-KEYAGREE-1: the findings the review found in the code", () => {
  it("★ F4: the ephemeral secret can actually be DESTROYED", async () => {
    /**
     * The DoD clause is *"destroys the ephemerals at close"*, and it existed only as a sentence
     * telling the caller to do it. Forward secrecy is not a property of minting a fresh key; it is a
     * property of the old one being gone.
     */
    const { destroySessionEphemeral } = await import("../session-key-agreement.js");
    const e = generateSessionEphemeral();
    expect(e.secretKey.some((b) => b !== 0), "PRECONDITION: a real secret to destroy").toBe(true);
    destroySessionEphemeral(e);
    expect(
      e.secretKey.every((b) => b === 0),
      "the secret survived destruction, so forward secrecy rests on a sentence in a docstring",
    ).toBe(true);
  });

  it("★ F10: a non-canonical peer key (bit 255 set) is REFUSED, not silently masked", () => {
    /**
     * A one-bit attack with no diagnosis. X25519 masks bit 255 (RFC 7748 §5), so the agreement still
     * succeeds — but the raw bytes are bound into the derivation, so a relay flipping that bit makes
     * the two sides derive different keys and the session never decrypts, with nothing explaining
     * why. Exactly the failure the sorted binding exists to prevent, for one flipped bit.
     */
    const a = generateSessionEphemeral();
    const b = generateSessionEphemeral();
    const tampered = Uint8Array.from(b.publicKey);
    tampered[31] = (tampered[31] as number) | 0x80;

    // The agreement itself would still succeed — that is what makes this silent.
    expect(
      Buffer.from(x25519.getSharedSecret(a.secretKey, tampered)),
      "PRECONDITION: X25519 masks the bit, so ECDH agrees and only the BINDING diverges",
    ).toEqual(Buffer.from(x25519.getSharedSecret(a.secretKey, b.publicKey)));

    expect(() => deriveSessionSecrets({
      ownEphemeralSecret: a.secretKey,
      peerEphemeralPublic: tampered,
      sessionId: SESSION_ID,
    })).toThrow(/non-canonical|bit 255/i);
  });

  it("★ F10b: a reflected key — the peer echoing our own public — is refused", () => {
    const a = generateSessionEphemeral();
    expect(() => deriveSessionSecrets({
      ownEphemeralSecret: a.secretKey,
      peerEphemeralPublic: a.publicKey,
      sessionId: SESSION_ID,
    })).toThrow(/reflection|identical/i);
  });

  it("★ F7: the LIVE degenerate path names CELLO's cause, not the library's", () => {
    /**
     * `@noble` throws "invalid private or public key received" — naming neither CELLO, nor which of
     * the two keys, nor what to do. The message that named the cause properly was on the branch
     * documented as unreachable, so in production the operator got the library's string.
     */
    const a = generateSessionEphemeral();
    let msg = "";
    try {
      deriveSessionSecrets({ ownEphemeralSecret: a.secretKey, peerEphemeralPublic: new Uint8Array(32), sessionId: SESSION_ID });
    } catch (e) { msg = (e as Error).message; }
    expect(msg, "the operator must be told whose key is at fault").toMatch(/peer's ephemeral public key/i);
    expect(msg, "and the upstream cause must survive").toMatch(/small-order|RFC 7748/i);
  });

  it("★ F11: a wrong-length OWN secret says it is a local defect", () => {
    expect(() => deriveSessionSecrets({
      ownEphemeralSecret: new Uint8Array(31),
      peerEphemeralPublic: generateSessionEphemeral().publicKey,
      sessionId: SESSION_ID,
    })).toThrow(/own ephemeral secret|local defect/i);
  });

  it("★ F8: the PQ transcript is bound, so a hybrid can carry the KEM's public material", () => {
    /**
     * `extraSharedSecret` alone is not a complete hybrid combiner: X-Wing binds the KEM ciphertext
     * and public key too, and the current analysis says that is necessary rather than optional. This
     * parameter is where `ct_pq || pk_pq` goes — added now, while there are no callers and no wire
     * format, because adding it later is the wire change the hook exists to avoid.
     */
    const a = generateSessionEphemeral();
    const b = generateSessionEphemeral();
    const base = { ownEphemeralSecret: a.secretKey, peerEphemeralPublic: b.publicKey, sessionId: SESSION_ID };
    const plain = deriveSessionSecrets(base);
    const bound = deriveSessionSecrets({ ...base, pqTranscript: new Uint8Array(64).fill(0xab) });
    expect(
      Buffer.from(plain.contentKey),
      "the transcript was accepted and ignored, which is the same defect as an ignored extra secret",
    ).not.toEqual(Buffer.from(bound.contentKey));

    // And a MISMATCH must diverge, not silently agree — same safe direction as the extra secret.
    const fromB = deriveSessionSecrets({
      ownEphemeralSecret: b.secretKey, peerEphemeralPublic: a.publicKey, sessionId: SESSION_ID,
      pqTranscript: new Uint8Array(64).fill(0xcd),
    });
    expect(Buffer.from(bound.contentKey)).not.toEqual(Buffer.from(fromB.contentKey));
  });
});
