/**
 * DOD-M15-KEYAGREE-1 — CELLO's own per-session key agreement.
 *
 * ─── Why CELLO needs its own, when Noise already encrypts the link ─────────────────────────────
 *
 * Live content today is plaintext inside libp2p's Noise session. That confidentiality is real — but
 * it is **libp2p's** key agreement over **libp2p's** ephemeral transport keys, so CELLO cannot
 * upgrade its own guarantee: a post-quantum migration would happen on libp2p's timeline, with
 * libp2p's algorithm choices, whenever libp2p chose to make it.
 *
 * The threat is harvest-now-decrypt-later, and it is why this is urgent rather than later: every
 * cross-NAT conversation is relayed today, therefore recordable at fixed endpoints today, and adding
 * this layer next year does not protect traffic already sent.
 *
 * ─── Construction (SPARC Phase P) ──────────────────────────────────────────────────────────────
 *
 *   generateSessionEphemeral():                                     # per SESSION, never reused
 *     1. sk = random X25519 secret                                  # RFC 7748
 *        pk = X25519 base * sk
 *
 *   deriveSessionSecrets(ownSk, peerPk, sessionId, extra?):
 *     1. shared = X25519(ownSk, peerPk)                             # EPHEMERAL-ephemeral ECDH
 *     2. REFUSE if shared is all-zero                               # RFC 7748 §6.1
 *     3. ikm   = shared || extra?                                   # the PQ hook
 *     4. bind  = sort(ownPk, peerPk)                                # canonical, role-independent
 *     5. key   = HKDF-SHA256(ikm, salt=sessionId, info="cello/session/v1/content-key"  || bind, 32)
 *        csalt = HKDF-SHA256(ikm, salt=sessionId, info="cello/session/v1/content-salt" || bind, 32)
 *
 * RFCs: X25519 — RFC 7748. HKDF — RFC 5869. (The AEAD that consumes the key is NIST SP 800-38D,
 * in `content-seal.ts`, which is the in-tree pattern this extends.)
 *
 * ─── The three ways this could be WORSE than no layer at all ───────────────────────────────────
 *
 * Named before the code, and each has a test:
 *
 * **1. Static-static.** A key derived only from long-term identity keys is the same key forever, so
 * anyone who ever obtains an identity key decrypts every conversation that agent ever had — strictly
 * worse than the Noise session it replaces. Hence ephemeral-EPHEMERAL: both sides mint fresh, and
 * the caller destroys the secret at close.
 *
 * **2. A degenerate agreement accepted silently.** X25519 against a small-order point yields an
 * all-zero shared secret; both sides then derive the same key, encryption appears to work, and the
 * attacker who supplied the point knows it too. Encryption that *looks* like it is working is worse
 * than none, because nobody investigates it. This throws.
 *
 * **3. A PQ hook that exists only in prose.** The line is blunt — *"the derivation accepts an
 * additional shared secret from day one… omitting the hook defeats the entire reason for the
 * work."* A parameter that is accepted and ignored reads as done and is not, so a test proves a
 * different extra secret produces a different key.
 *
 * ─── Two outputs, one agreement ────────────────────────────────────────────────────────────────
 *
 * The message-sealing key and the per-session content-hash salt come from the same agreement under
 * different HKDF `info` labels. They must never be EQUAL: the salt travels wherever a content hash
 * does and the relay sees it, so a salt that equalled the key would hand the key to everyone who can
 * see a hash. Domain separation by label is what keeps them independent.
 */

import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

/** X25519 keys and the derived outputs are all 32 bytes. */
const X25519_KEY_BYTES = 32;
export const SESSION_KEY_BYTES = 32;
export const SESSION_SALT_BYTES = 32;

const ENC = new TextEncoder();
/**
 * Distinct labels are the ONLY thing separating the two outputs — same IKM, same salt, same binding.
 * Versioned so a future derivation change is a new label rather than a silent reinterpretation of
 * the same bytes.
 */
const INFO_CONTENT_KEY = ENC.encode("cello/session/v1/content-key");
const INFO_CONTENT_SALT = ENC.encode("cello/session/v1/content-salt");

export interface SessionEphemeral {
  /** X25519 secret. The caller MUST destroy this at session close — that is what forward secrecy is. */
  secretKey: Uint8Array;
  /** X25519 public, sent to the peer in the session handshake. */
  publicKey: Uint8Array;
}

export interface SessionSecrets {
  /** AEAD key for message content (consumed by the `content-seal.ts` AES-256-GCM pattern). */
  contentKey: Uint8Array;
  /** Per-session salt for content hashing, so a relay cannot confirm a guessed short message. */
  contentSalt: Uint8Array;
}

/**
 * Mint this side's per-SESSION ephemeral keypair.
 *
 * Fresh every session, deliberately. Reusing one across sessions would collapse to static-static and
 * void the forward secrecy that `design-problems` already claims as structural.
 */
export function generateSessionEphemeral(): SessionEphemeral {
  const secretKey = x25519.utils.randomSecretKey();
  return { secretKey, publicKey: x25519.getPublicKey(secretKey) };
}

/** Constant-time-ish all-zero check. Not secret-dependent branching — the input is already known bad. */
function isAllZero(b: Uint8Array): boolean {
  let acc = 0;
  for (const x of b) acc |= x;
  return acc === 0;
}

/** Lexicographic compare, so both sides order the two public keys identically. */
function lexLess(a: Uint8Array, b: Uint8Array): boolean {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const x = a[i] as number;
    const y = b[i] as number;
    if (x !== y) return x < y;
  }
  return a.length < b.length;
}

export function deriveSessionSecrets(opts: {
  ownEphemeralSecret: Uint8Array;
  peerEphemeralPublic: Uint8Array;
  /** The session this agreement is for. Bound in as the HKDF salt. */
  sessionId: Uint8Array;
  /**
   * THE PQ HOOK — additional agreed secret, mixed into the IKM.
   *
   * Present from day one, before there is a PQ contribution to put in it, because retrofitting it
   * later is a wire change and a rewrite rather than an addition. Hybrid PQ becomes: run a KEM,
   * pass its shared secret here. Any length — an ML-KEM secret is 32 bytes but a hybrid may
   * concatenate more than one contribution, and fixing the length would force the rewrite this
   * parameter exists to avoid.
   */
  extraSharedSecret?: Uint8Array;
}): SessionSecrets {
  if (opts.peerEphemeralPublic.length !== X25519_KEY_BYTES) {
    throw new Error(
      `KEYAGREE: peer ephemeral public key must be ${X25519_KEY_BYTES} bytes, got ${opts.peerEphemeralPublic.length}. ` +
      "Refusing rather than padding — a short key silently zero-extended is an agreement with something that is not the peer.",
    );
  }
  if (opts.sessionId.length === 0) {
    throw new Error(
      "KEYAGREE: sessionId must not be empty. It is bound in as the HKDF salt, which is what stops " +
      "two sessions between the same peers from ever sharing a key.",
    );
  }

  const shared = x25519.getSharedSecret(opts.ownEphemeralSecret, opts.peerEphemeralPublic);

  /**
   * FAIL CLOSED ON A DEGENERATE AGREEMENT — RFC 7748 §6.1.
   *
   * A small-order peer point drives the shared secret to all zeros. Both sides would then derive the
   * same key, every message would encrypt and decrypt correctly, and whoever supplied the point
   * would hold the key. There is no symptom to notice, which is exactly why this refuses loudly
   * instead of deriving.
   */
  if (isAllZero(shared)) {
    throw new Error(
      "KEYAGREE: degenerate X25519 agreement — the shared secret is all zeros, which means the peer " +
      "supplied a small-order point (RFC 7748 §6.1). Refusing: deriving from it would produce a key " +
      "the attacker who sent that point also knows, while every message appeared to encrypt normally.",
    );
  }

  const ownPublic = x25519.getPublicKey(opts.ownEphemeralSecret);
  /**
   * Both public keys bound into `info`, in CANONICAL (sorted) order.
   *
   * Sorted rather than by role, because the two daemons reach this point from different code paths
   * and a disagreement about who "initiated" would produce two different keys — a conversation that
   * fails to decrypt with nothing anywhere explaining why. Binding both also ties the derivation to
   * this exact pair of ephemerals, so a key from one handshake cannot be replayed into another.
   */
  const [first, second] = lexLess(ownPublic, opts.peerEphemeralPublic)
    ? [ownPublic, opts.peerEphemeralPublic]
    : [opts.peerEphemeralPublic, ownPublic];

  const extra = opts.extraSharedSecret ?? new Uint8Array(0);
  const ikm = new Uint8Array(shared.length + extra.length);
  ikm.set(shared, 0);
  ikm.set(extra, shared.length);

  const info = (label: Uint8Array): Uint8Array => {
    const out = new Uint8Array(label.length + first.length + second.length);
    out.set(label, 0);
    out.set(first, label.length);
    out.set(second, label.length + first.length);
    return out;
  };

  return {
    contentKey: hkdf(sha256, ikm, opts.sessionId, info(INFO_CONTENT_KEY), SESSION_KEY_BYTES),
    contentSalt: hkdf(sha256, ikm, opts.sessionId, info(INFO_CONTENT_SALT), SESSION_SALT_BYTES),
  };
}
