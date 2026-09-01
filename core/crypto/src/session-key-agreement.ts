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
 *     5. key   = HKDF-SHA256(ikm, salt=sessionId, info="cello/session/v1/content-key" || bind, 32)
 *
 *   THERE IS NO SECOND OUTPUT. This block used to specify a `csalt` derived from the same secret;
 *   the salt is agreed INDEPENDENTLY in `session-salt.ts` (Decisions Carried #8). Re-deriving it
 *   here brings back everything #7 was retracted for — epochs, per-leaf attribution, lockstep
 *   switching.
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
 * ─── WHAT THIS DOES NOT DEFEND AGAINST, stated plainly (review F6) ─────────────────────────────
 *
 * The ephemerals here are UNAUTHENTICATED. That is sufficient against the threat the DoD line names
 * — harvest-now-decrypt-later, i.e. a PASSIVE recorder, which is what a relay storing traffic is.
 *
 * It is NOT sufficient against an ACTIVE on-path relay, which can substitute both ephemerals and
 * read everything. Nothing in this API takes an identity key, so there is nowhere to bind the
 * ephemeral to the peer. `DOD-M15-EPHEMERAL-AUTH-1` carries that: the ephemeral public must be
 * signed with the agent's Ed25519 identity and the peer's verified before deriving.
 *
 * Said here because the file's own headline is "CELLO owns its own confidentiality guarantee", and a
 * reader could otherwise conclude MITM is covered. It is not, yet.
 *
 * ─── ONE OUTPUT. The salt used to live here, and that was the defect. ─────────────────────────
 *
 * This module produced a content-hash salt as a second HKDF output, and Andre corrected it before
 * `SEALWIRE-1` encoded anything (Decisions Carried #8, superseding the "one agreement, two outputs"
 * bullet). The two are unrelated goals that merely both need a shared secret:
 *
 *   the **envelope key** stops the relay reading messages in flight and MUST be destroyed at close;
 *   the **session salt** stops anyone holding stored hashes from confirming a guessed message and
 *   MUST survive for the life of the session.
 *
 * **Deriving both from one secret tied "must be forgotten" to "must be kept forever."** Everything
 * that followed — salt epochs, per-leaf epoch attribution, lockstep switching, and my own Decision
 * #7 ruling all of that — was a symptom of the coupling, not a requirement. The salt now lives in
 * `session-salt.ts`, agreed in the SAME exchange from both sides' random contributions, and none of
 * those consequences exist.
 *
 * ─── The remaining output, and its lifetime ───────────────────────────────────────────────────
 *
 **The envelope key NEVER touches disk**, and `destroySessionEphemeral` is how a caller discards the
 * secret behind it at session close. A revived session RE-KEYS (Decisions Carried #5) — and because
 * the salt no longer rides on this secret, re-keying no longer disturbs the transcript's
 * verifiability.
 *
 * ⚠️ THE DESTRUCTION HAS NO CALLER YET, and this file used to read as though it did — *"that is the
 * forward secrecy, and `destroySessionEphemeral` is what makes it real."* Forward secrecy is a
 * property of the old secret being GONE, so a destroy function nothing calls does not provide it.
 * Nothing in the daemon mints an ephemeral, derives a content key, or destroys one: this module is
 * a library with tests and no consumer, deliberately, because binding the ephemeral to the agent's
 * identity comes first (`DOD-M15-EPHEMERAL-AUTH-1`) and there is no point wiring an unauthenticated
 * agreement into the send path.
 *
 * Said plainly because `session-salt.ts` states its own reachability boundary and this file stated
 * none, so the two halves of the same exchange read as though both were live. The salt half IS live;
 * this half is not yet.
 *
 * ─── The key and the salt must never be EQUAL, and what actually keeps them apart ──────────────
 *
 * The salt travels wherever a content hash does and the relay sees it, so a salt that equalled the
 * key would hand the key to everyone who can see a hash.
 *
 * An earlier version said *"domain separation by label is what keeps them independent."* That was
 * true when the salt was a second HKDF output of this function and is not true now. The salt is
 * computed in `session-salt.ts` from a DIFFERENT input — the two sides' random contributions, not
 * this ECDH secret — under its own label, with no HKDF salt. Different inputs, different module,
 * different function. Label separation is not the mechanism; it is not even reachable, because
 * there is only one label here.
 */

import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

/** X25519 keys and the derived outputs are all 32 bytes. */
const X25519_KEY_BYTES = 32;
export const SESSION_KEY_BYTES = 32;

const ENC = new TextEncoder();
/**
 * THE ONE label. Versioned so a future derivation change is a new label rather than a silent
 * reinterpretation of the same bytes.
 *
 * An earlier version read *"distinct labels are the ONLY thing separating the two outputs — same
 * IKM, same salt, same binding."* There are no longer two outputs to separate: the content-hash
 * salt moved to `session-salt.ts` and is derived from different inputs entirely (Decisions Carried
 * #8). The label still earns its place — it is bound into `info`, so it is what a future second
 * output WOULD be separated by — but it is not currently holding two values apart.
 */
const INFO_CONTENT_KEY = ENC.encode("cello/session/v1/content-key");

export interface SessionEphemeral {
  /** X25519 secret. The caller MUST destroy this at session close — that is what forward secrecy is. */
  secretKey: Uint8Array;
  /** X25519 public, sent to the peer in the session handshake. */
  publicKey: Uint8Array;
}

export interface SessionSecrets {
  /**
   * AEAD key for message content (consumed by the `content-seal.ts` AES-256-GCM pattern).
   *
   * The ONLY output. It never touches disk and is destroyed at session close — see
   * `destroySessionEphemeral`. The content-hash salt is NOT here: it is agreed separately in
   * `session-salt.ts`, because its lifetime is the opposite of this one's.
   */
  contentKey: Uint8Array;
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

/**
 * DESTROY THIS SIDE'S EPHEMERAL SECRET — `DOD-M15-KEYAGREE-1`, review F4.
 *
 * The line's clause is *"destroys the ephemerals at close"*, and it existed only as a sentence in a
 * docstring telling the caller to do it. Forward secrecy is not a property of generating a fresh
 * key; it is a property of the old one being GONE. A comment asserting that is the failure mode this
 * milestone has caught five times in seal and persistence code, so it is code now.
 *
 * HONEST LIMIT: JavaScript cannot guarantee no copy survives. The garbage collector may have moved
 * the buffer, and a `Uint8Array` handed across a module boundary may have been copied. Zeroing the
 * buffer we hold removes the value from the one place we control, which is strictly better than not
 * doing it and strictly weaker than the guarantee a language with explicit memory would give.
 */
export function destroySessionEphemeral(e: SessionEphemeral): void {
  e.secretKey.fill(0);
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
  /**
   * THE PQ TRANSCRIPT — review F8, and it is added NOW precisely because it cannot be added later.
   *
   * `extraSharedSecret` alone is not a complete hybrid combiner. Concatenating shared secrets is the
   * right shape and matches TLS's X25519MLKEM768 and NIST SP 800-56C Rev 2 §2 — that part was
   * checked and is sound. What it lacks is the KEM's PUBLIC material: X-Wing's combiner hashes
   * `ss_pq ‖ ss_x ‖ ct_x ‖ pk_x`, binding the ciphertext and public key, and the current analysis
   * ("On the Necessity of Public Contexts in Hybrid KEMs", eprint 2026/140) is that this is
   * NECESSARY rather than belt-and-braces.
   *
   * A caller doing the obvious thing — passing only the ML-KEM shared secret — would get a hybrid
   * whose ciphertext and public key are unbound. This parameter is where `ct_pq ‖ pk_pq` goes.
   *
   * It is empty today and that is the point: the DoD line's whole justification for building the
   * hook before there is anything to put in it is that hybrid PQ must be *"an addition, not a
   * rewrite."* Added after a wire format exists, this is a wire change — the exact rewrite the hook
   * was meant to avoid.
   */
  pqTranscript?: Uint8Array;
}): SessionSecrets {
  if (opts.peerEphemeralPublic.length !== X25519_KEY_BYTES) {
    throw new Error(
      `KEYAGREE: peer ephemeral public key must be ${X25519_KEY_BYTES} bytes, got ${opts.peerEphemeralPublic.length}. ` +
      "Refusing rather than padding — a short key silently zero-extended is an agreement with " +
      "something that is not the peer. This check ALSO keeps the HKDF `info` unambiguous (review " +
      "F9): with a fixed-length label, two exactly-32-byte public keys and a trailing transcript, " +
      "no two different (keys, transcript) inputs can encode to the same info bytes. A " +
      "variable-length public would break that, and two peers whose info collided would derive the " +
      "same key from different material.",
    );
  }
  if (opts.ownEphemeralSecret.length !== X25519_KEY_BYTES) {
    // Review F11: symmetric with the peer check above. `@noble` catches it, but names its own
    // parameter rather than CELLO's key — the same substitution as F7, one layer down.
    throw new Error(
      `KEYAGREE: own ephemeral secret must be ${X25519_KEY_BYTES} bytes, got ${opts.ownEphemeralSecret.length}. ` +
      "This is a local defect, not something the peer did.",
    );
  }
  /**
   * REFUSE A NON-CANONICAL PEER KEY — review F10, and it is a one-bit attack with no diagnosis.
   *
   * RFC 7748 §5 has X25519 MASK bit 255 of the u-coordinate, so `pk` and `pk | 0x80…` produce the
   * SAME shared secret — but they are different BYTES, and the binding below uses the bytes as
   * received, including in the sort comparison.
   *
   * So a relay that flips the top bit of one relayed ephemeral costs itself nothing: ECDH still
   * agrees, but one side binds `pk` and the other binds `pk'`, possibly in a different sorted order.
   * The two derive different keys, the session never decrypts, and nothing anywhere explains why —
   * precisely the failure the sorted binding exists to prevent, achieved for one flipped bit.
   *
   * Refusing rather than masking, deliberately: masking would make the tamper invisible, and a peer
   * sending a non-canonical encoding is either broken or probing. Say so.
   */
  if ((opts.peerEphemeralPublic[31] as number) & 0x80) {
    throw new Error(
      "KEYAGREE: the peer's ephemeral public key is non-canonical — bit 255 is set. X25519 masks " +
      "that bit (RFC 7748 §5) so the agreement would still succeed, but the raw bytes are bound into " +
      "the key derivation, so the two sides would derive DIFFERENT keys and the session would never " +
      "decrypt with nothing explaining why. Refusing: a correct peer never sets it, and a flipped " +
      "bit in transit is exactly what this catches.",
    );
  }
  if (opts.sessionId.length === 0) {
    throw new Error(
      "KEYAGREE: sessionId must not be empty. It is bound in as the HKDF salt — the BACKSTOP against " +
      "catastrophic ephemeral reuse. (Review F13: what ordinarily stops two sessions between the " +
      "same peers sharing a key is the fresh ephemerals, not this. An earlier version of this " +
      "message claimed the stronger thing.)",
    );
  }

  /**
   * WRAPPED — review F7. `@noble` rejects a small-order or otherwise invalid point here, and its
   * message is *"invalid private or public key received"*: it names neither CELLO, nor which of the
   * two keys, nor the session. That is a third-party exit-point label standing in for the cause, on
   * the path that ACTUALLY fires — while the carefully-written message below sits on the branch
   * documented as unreachable.
   */
  let shared: Uint8Array;
  try {
    shared = x25519.getSharedSecret(opts.ownEphemeralSecret, opts.peerEphemeralPublic);
  } catch (err: unknown) {
    throw new Error(
      "KEYAGREE: the peer's ephemeral public key is unusable for X25519 — it is invalid or a " +
      `small-order point (RFC 7748 §6.1), so no session key can be agreed. Peer key began ` +
      `${Buffer.from(opts.peerEphemeralPublic.subarray(0, 8)).toString("hex")}…. This is the peer's ` +
      "key, not yours; a correct client never sends one. Refusing rather than deriving: a degenerate " +
      "agreement yields a key the sender of that point also holds, while every message appears to " +
      "encrypt normally.",
      { cause: err },
    );
  }

  /**
   * FAIL CLOSED ON A DEGENERATE AGREEMENT — RFC 7748 §6.1.
   *
   * A small-order peer point drives the shared secret to all zeros. Both sides would then derive the
   * same key, every message would encrypt and decrypt correctly, and whoever supplied the point
   * would hold the key. There is no symptom to notice.
   *
   * ⚠️ THIS BRANCH IS UNREACHABLE TODAY, and saying so is the point. `@noble/curves` already refuses
   * — `getSharedSecret` throws *"invalid private or public key received"* before control arrives
   * here — which the revert test proved: deleting this check left every test green. So this is a
   * BACKSTOP against that dependency behaviour changing, not the thing currently providing the
   * property, and an earlier version of this comment claimed otherwise.
   *
   * It is kept rather than deleted because the cost is one branch and the failure it guards has no
   * symptom. The test pins the PROPERTY (a degenerate agreement is refused) rather than which layer
   * refuses, so it keeps its teeth either way — and would catch a `@noble` upgrade that stopped
   * rejecting.
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
   * REFLECTION — the peer sent back our own ephemeral public. Standard hygiene: it is not a
   * key-recovery attack against X25519, but it means the "peer" contributed nothing to the
   * agreement, and both sorted halves would be identical. One line, refused.
   */
  if (Buffer.compare(Buffer.from(ownPublic), Buffer.from(opts.peerEphemeralPublic)) === 0) {
    throw new Error(
      "KEYAGREE: the peer's ephemeral public key is identical to our own — the peer contributed " +
      "nothing to the agreement. Refusing: this is a reflection, not a handshake.",
    );
  }
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

  const transcript = opts.pqTranscript ?? new Uint8Array(0);
  const info = (label: Uint8Array): Uint8Array => {
    const out = new Uint8Array(label.length + first.length + second.length + transcript.length);
    out.set(label, 0);
    out.set(first, label.length);
    out.set(second, label.length + first.length);
    // TRAILING, so the label remains recoverable as info[0 : len-64-|transcript|] for a caller that
    // knows the transcript length. It is empty today; when a hybrid fills it, both sides supply the
    // same bytes or they diverge — which is the safe direction.
    out.set(transcript, label.length + first.length + second.length);
    return out;
  };

  return { contentKey: hkdf(sha256, ikm, opts.sessionId, info(INFO_CONTENT_KEY), SESSION_KEY_BYTES) };
}
