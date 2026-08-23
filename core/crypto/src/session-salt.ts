/**
 * THE SESSION SALT — Decisions Carried #8, #9, #10 (Andre, 2026-08-23).
 *
 * ⚠️ AGREED, STORED, AND VERIFIABLE — BUT NO SENDER SALTS YET. Two revisions of this header have
 * now been overtaken, so it states the boundary precisely rather than a slogan:
 *
 *   `session-salt-agreement.ts` calls `deriveSessionSalt` and `saltFingerprint`; `content_salt` has
 *   a writer and a reader; and `wire-content-hash.ts` DOES import `saltedContentHash` — the RECEIVE
 *   path will verify a frame that names `hmac-sha256-salt-v1` (`DOD-M15-SEALWIRE-1` part B1).
 *
 *   What no code in this build does is SEND one. Every send site still calls `wireContentHash`, so
 *   no message's hash depends on a salt yet, and part B2 is what flips that.
 *
 * The distinction matters to anyone auditing reachability: the salted path is live inbound and dead
 * outbound. A reader who takes "nothing hashes with it" from an older revision of this header would
 * wrongly conclude the salted branch cannot execute in production at all.
 *
 * ─── Why this is a separate file from the key agreement ────────────────────────────────────────
 *
 * It used to be a second output of `deriveSessionSecrets`, and that was the defect. The envelope key
 * and the salt are unrelated goals that merely both need a shared secret:
 *
 *   the **envelope key** stops the relay reading messages in flight, and MUST be destroyed at close;
 *   the **session salt** stops anyone holding stored hashes from confirming a guessed message, and
 *   MUST survive for the life of the session.
 *
 * **Deriving both from one secret tied "must be forgotten" to "must be kept forever."** Every
 * consequence that flowed from it — salt epochs, per-leaf epoch attribution, lockstep switching —
 * was a symptom of that coupling, not a real requirement. Keeping the MOMENT (one exchange) and
 * dropping the DERIVATION removes all of them.
 *
 * ─── What it defends against, and it is live today ─────────────────────────────────────────────
 *
 * `wireContentHash` is `SHA-256(0x00 ‖ content)` with nothing session-specific in it. So the same
 * message text is the same 32 bytes in **every conversation, between every pair of agents, forever**
 * — a relay can correlate one message across sessions and agent pairs, and can build a table of
 * common short messages once and read it everywhere (`DOD-M15-HASHCORRELATE-1`).
 *
 * Chaining would not fix it: the adversary holds the previous hash, so they would compute
 * `hash(previous ‖ guess)`. Chaining hides repeats; it does not hide content. A secret per-session
 * salt does.
 *
 * ─── BOTH SIDES CONTRIBUTE, and why that is a requirement rather than a nicety ─────────────────
 *
 * Not initiator-minted. The client is open source and an operator can modify their own build, so a
 * single minter could unilaterally destroy the property **for both parties** — always send the same
 * salt, or a low-entropy one — and every conversation that client has becomes guessable by any relay
 * holding the hashes. The honest peer cannot detect it and never consented to it.
 *
 * Both-contribute means **one honest participant is enough**: if either side's contribution is
 * unpredictable, the salt is. Each side can also verify its own contribution was actually used.
 * Same principle as the sovereign-node rule — no single party can unilaterally break a guarantee.
 *
 * (The envelope key already has this property structurally: X25519 ephemeral-ephemeral combines both
 * secrets, and `session-key-agreement.ts` refuses the small-order point that is the one way a peer
 * could force a degenerate result. Same guarantee, different mechanism.)
 *
 * ─── 🚨 THE SECRECY HERE IS THE CHANNEL'S, NOT THE CONSTRUCTION'S ──────────────────────────────
 *
 * The single most important thing about this module, and it does NOT resemble the envelope key.
 *
 * The key is a DH secret: a passive relay holding both public keys cannot compute it, and
 * `dod-m15-keyagree-1.test.ts` pins exactly that. **The salt is a function of two values that are
 * SENT.** Anyone who can read both contributions derives it with the same public HKDF label. There
 * is no "a third party cannot derive it" test in this module, and there cannot be one.
 *
 * So "one honest participant is enough" carries a precondition that must never be dropped:
 * unpredictable **to anyone who cannot read the exchange**.
 *
 * ─── THEREFORE, a rule for `DOD-M15-SEALWIRE-1`, which owns the wire ──────────────────────────
 *
 *   The contributions MUST be exchanged on the peer-to-peer `/cello/content/1.0.0` stream. It rides
 *   circuit-relay-v2 carrying its own Noise session, so a relay forwarding it sees ciphertext.
 *
 *   They MUST NEVER appear in `session_offer` / `session_offer_accept`, or anything else a
 *   DIRECTORY brokers. **That is the trap:** today the ONLY round trip at session open runs on the
 *   directory's signaling stream (`session-ceremony.ts`), so it is the natural, obvious place to put
 *   a contribution — one round trip, at open, before any leaf — and it is precisely the channel
 *   Decision #8 forbids. Nothing about this function protects the salt if that rule is broken, and
 *   a session that shipped that way cannot be repaired afterwards: the relay already holds the salt
 *   and the hashes.
 *
 * Residual, and it now covers TWO values rather than one: the contributions are unauthenticated,
 * exactly like the ephemerals, so an ACTIVE on-path attacker who substitutes both sides defeats the
 * salt as well as the key. That is `DOD-M15-EPHEMERAL-AUTH-1`.
 */

import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { randomBytes } from "node:crypto";

/** Contributions and the salt are all 32 bytes. */
export const SALT_CONTRIBUTION_BYTES = 32;
export const SESSION_SALT_BYTES = 32;
/** Enough to detect a disagreement; short enough to be obviously not the salt. */
export const SALT_FINGERPRINT_BYTES = 8;

const ENC = new TextEncoder();
const INFO_SESSION_SALT = ENC.encode("cello/session/v1/salt");
const INFO_SALT_FINGERPRINT = ENC.encode("cello/session/v1/salt-fingerprint");

/** This side's random contribution. Fresh per session; sent to the peer. */
export function generateSaltContribution(): Uint8Array {
  return new Uint8Array(randomBytes(SALT_CONTRIBUTION_BYTES));
}

function isAllZero(b: Uint8Array): boolean {
  let acc = 0;
  for (const x of b) acc |= x;
  return acc === 0;
}

/**
 * Combine the two contributions into the session salt.
 *
 * CANONICAL ORDER (lexicographic), so both sides compute identical bytes without agreeing on who
 * initiated. The two daemons reach this from different code paths; ordering by role would mean a
 * disagreement about "who started it" produced two different salts — and a salt disagreement is the
 * least debuggable failure in this system, because the send succeeds and the receiver discards.
 */
export function deriveSessionSalt(ourContribution: Uint8Array, peerContribution: Uint8Array): Uint8Array {
  /**
   * REFUSE A DEGENERATE PEER CONTRIBUTION — the same posture the key agreement takes toward a
   * small-order point, and for the same reason: a peer that contributes nothing has unilaterally
   * decided the salt, which is exactly the property both-contribute exists to prevent.
   */
  if (peerContribution.length !== SALT_CONTRIBUTION_BYTES) {
    throw new Error(
      `SESSION SALT: the peer's salt contribution must be ${SALT_CONTRIBUTION_BYTES} bytes, got ` +
      `${peerContribution.length}. Refusing rather than padding — a short contribution silently ` +
      "zero-extended is a salt this side did not really help choose.",
    );
  }
  if (isAllZero(peerContribution)) {
    throw new Error(
      "SESSION SALT: the peer's salt contribution is all zeros, which means it contributed nothing " +
      "and the salt would be decided by one side alone. That is the property both-contribute exists " +
      "to prevent: a modified client could then make every one of its conversations guessable by any " +
      "relay holding the hashes, without its peer being able to tell. Refusing.",
    );
  }
  if (ourContribution.length !== SALT_CONTRIBUTION_BYTES) {
    throw new Error(
      `SESSION SALT: our own salt contribution must be ${SALT_CONTRIBUTION_BYTES} bytes, got ` +
      `${ourContribution.length}. This is a local defect, not something the peer did.`,
    );
  }
  /**
   * OUR OWN all-zero contribution is refused too — review F6, and the asymmetry mattered.
   *
   * Without this, a daemon with a broken or patched RNG derives happily while the PEER refuses with
   * *"the peer's salt contribution is all zeros"* — so the operator whose machine is actually broken
   * reads a failure that blames their counterparty. `session-key-agreement.ts` already established
   * the symmetric pattern for lengths ("this is a local defect, not something the peer did"); this
   * file had it for length and not for zero.
   */
  if (isAllZero(ourContribution)) {
    throw new Error(
      "SESSION SALT: our OWN salt contribution is all zeros, so this side contributed nothing. This " +
      "is a LOCAL defect — a broken or patched random source — not something the peer did. Refusing " +
      "rather than deriving a salt one side chose alone.",
    );
  }
  /**
   * A REFLECTED contribution — the peer echoing ours back — is refused, matching
   * `session-key-agreement.ts`'s reflection check. Confidentiality survives (our half is random), so
   * this is hygiene rather than a break; but the module claims each side can verify its contribution
   * was used, and nothing was verifying the PEER contributed at all.
   */
  if (Buffer.compare(Buffer.from(ourContribution), Buffer.from(peerContribution)) === 0) {
    throw new Error(
      "SESSION SALT: the peer's salt contribution is identical to our own — the peer contributed " +
      "nothing to the agreement. Refusing: this is a reflection, not an exchange.",
    );
  }

  const [first, second] = Buffer.compare(Buffer.from(ourContribution), Buffer.from(peerContribution)) < 0
    ? [ourContribution, peerContribution]
    : [peerContribution, ourContribution];

  const ikm = new Uint8Array(first.length + second.length);
  ikm.set(first, 0);
  ikm.set(second, first.length);
  // No salt argument to HKDF here: the session id is not needed to separate sessions, because the
  // contributions are fresh random per session and already do it.
  return hkdf(sha256, ikm, new Uint8Array(0), INFO_SESSION_SALT, SESSION_SALT_BYTES);
}

/**
 * A short, one-way fingerprint of the salt, for the agreement check at session open — Decision #10.
 *
 * **The salt itself is never compared on the wire.** A fingerprint is derived under its own HKDF
 * label, so it cannot be worked back to the salt, and it is deliberately short so nobody mistakes it
 * for key material.
 *
 * Why compare at all: a salt disagreement makes every message fail the receive-path authenticity
 * check, and `wire-content-hash.ts`'s own header calls that the least debuggable shape there is —
 * the send succeeds, `parked: false`, the sender's log says the frame left, and the receiver discards
 * before anything is logged about it. It cost two real daemons to find once. Refusing the session at
 * open, with a named reason, is the difference between a diagnosis and a week.
 */
export function saltFingerprint(salt: Uint8Array): Uint8Array {
  return hkdf(sha256, salt, new Uint8Array(0), INFO_SALT_FINGERPRINT, SALT_FINGERPRINT_BYTES);
}

/**
 * The salted content hash — Decision #9.
 *
 * **HMAC, not `SHA-256(salt ‖ content)`.** The naive concatenation is vulnerable to length
 * extension: an attacker who holds `H(salt ‖ m)` and knows `|salt|` can compute `H(salt ‖ m ‖ pad ‖
 * m')` without knowing the salt. HMAC is the standard construction for exactly this and costs
 * nothing extra here.
 *
 * The `0x00` domain byte is retained inside the message so this stays domain-separated from any
 * other HMAC over the same key, and so the unsalted and salted forms can never collide.
 */
export function saltedContentHash(salt: Uint8Array, content: Uint8Array): Uint8Array {
  const msg = new Uint8Array(1 + content.length);
  msg[0] = 0x00;
  msg.set(content, 1);
  return hmac(sha256, salt, msg);
}
