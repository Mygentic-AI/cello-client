/**
 * DOD-M15-EPHEMERAL-AUTH-1 — binding the throwaway key to the agent's identity.
 *
 * ─── The attack this closes, step by step ──────────────────────────────────────────────────────
 *
 * The key agreement mixes two throwaway keys into a shared secret, and the secret itself never
 * crosses the wire. But if nobody SIGNS the throwaway key, an arriving one carries no evidence of
 * who sent it:
 *
 *   1. Alice sends her throwaway public key. The relay is carrying the traffic.
 *   2. The relay keeps Alice's and forwards its OWN key to Bob instead.
 *   3. It does the same in the other direction.
 *   4. It now shares one secret with Alice and a different one with Bob.
 *   5. It decrypts everything, reads it, re-encrypts it, and passes it on. Neither side sees
 *      anything wrong, because both halves of the conversation decrypt perfectly.
 *
 * So the unauthenticated layer stops a PASSIVE recorder — which is what harvest-now-decrypt-later
 * is about — and does nothing against the party actually carrying the messages. **And we run the
 * relays**, so without this the guarantee reduces to "trust us", which is the one thing CELLO exists
 * so nobody has to do.
 *
 * ─── What is signed, and why the session id is in it ───────────────────────────────────────────
 *
 *   message = "cello/session/v2/ephemeral" || u32be(len sid) || sid || x25519_pub || mlkem_pub || (ct or empty)
 *
 * Signed twice over the same bytes — Ed25519 by K_local and ML-DSA by the agent's registered key
 * (M9D 003-PQSESSION) — and both must verify.
 *
 * The LABEL makes this signature unusable as any other kind of CELLO signature, and vice versa: an
 * agent signs many things, and a signature that is valid in two contexts is a signature an attacker
 * can move between them.
 *
 * The SESSION ID binds the ephemeral to the conversation it was minted for. Without it, a signed
 * ephemeral captured from one session could be replayed into another between the same two agents —
 * the signature verifies, both sides derive, and the relay that replayed it knows the secret from
 * the session it harvested. The session id is length-prefixed so that `sessionId ‖ ephemeral` cannot
 * be re-split at a different point to produce the same bytes from different inputs.
 *
 * ⚠️ WHAT THIS DOES NOT DO. It proves the ephemeral came from the holder of that identity key. It
 * does not prove the identity key is the agent you meant to talk to — that is the counterparty
 * identity the caller passes in, and the caller must take it from what the OPERATOR asked for, never
 * from a value the directory or the relay handed back. Verifying against a key the attacker chose is
 * relocating the trust rather than closing it.
 */

import { verify as edVerify } from "./ed25519.js";
import type { MlDsaKeyProvider } from "./ml-dsa.js";
import { ML_DSA_PUBLIC_KEY_BYTES, ML_DSA_SIGNATURE_BYTES } from "./ml-dsa.js";
import { ML_KEM_CIPHERTEXT_BYTES, ML_KEM_PUBLIC_KEY_BYTES } from "./ml-kem.js";
import { signMlDsa, verifyMlDsa } from "./pq-frame.js";

const ENC = new TextEncoder();

/**
 * Domain separation. Versioned, so a change is a new label rather than a reinterpretation.
 * M9D 003-PQSESSION: v2 carries the ML-KEM public key and, on the encapsulator's announce, its
 * ciphertext. The v1 label and layout are deleted — there is no old-peer path.
 */
const EPHEMERAL_SIG_LABEL = ENC.encode("cello/session/v2/ephemeral");

/** The ML-DSA context for this artifact (Contract 2). */
const EPHEMERAL_PQ_CONTEXT = "cello-mldsa-session-ephemeral-v1" as const;

/** Ed25519 signatures are 64 bytes; X25519 publics are 32. */
export const EPHEMERAL_SIG_BYTES = 64;
export const EPHEMERAL_PUBLIC_BYTES = 32;

/**
 * The exact bytes BOTH signatures cover, on both sides:
 *
 *   "cello/session/v2/ephemeral" ‖ u32be(len sid) ‖ sid ‖ x25519_pub(32) ‖ mlkem_pub(1184) ‖ (ct(1088) or empty)
 *
 * Written once and used by both directions and by both signatures on purpose. A signer and a
 * verifier that each build the message from their own reading of a spec is how two implementations
 * end up disagreeing about a byte and rejecting each other for a reason neither can see. The session
 * id is LENGTH-PREFIXED so the fields cannot be re-split; every field after it is fixed-width, so the
 * trailing ciphertext is unambiguous.
 */
export function ephemeralSigningMessage(
  sessionId: Uint8Array,
  ephemeralPublic: Uint8Array,
  mlKemPublic: Uint8Array,
  ciphertext?: Uint8Array,
): Uint8Array {
  const ct = ciphertext ?? new Uint8Array(0);
  const out = new Uint8Array(EPHEMERAL_SIG_LABEL.length + 4 + sessionId.length + ephemeralPublic.length + mlKemPublic.length + ct.length);
  let o = 0;
  out.set(EPHEMERAL_SIG_LABEL, o); o += EPHEMERAL_SIG_LABEL.length;
  out[o++] = (sessionId.length >>> 24) & 0xff;
  out[o++] = (sessionId.length >>> 16) & 0xff;
  out[o++] = (sessionId.length >>> 8) & 0xff;
  out[o++] = sessionId.length & 0xff;
  out.set(sessionId, o); o += sessionId.length;
  out.set(ephemeralPublic, o); o += ephemeralPublic.length;
  out.set(mlKemPublic, o); o += mlKemPublic.length;
  out.set(ct, o);
  return out;
}

/**
 * Sign this side's announce with BOTH long-term keys: Ed25519 by K_local and ML-DSA by the agent's
 * registered key, over the same `msg` (D16).
 */
export async function signSessionEphemeral(
  signer: { sign(data: Uint8Array): Promise<Uint8Array> },
  mlDsa: MlDsaKeyProvider,
  sessionId: Uint8Array,
  ephemeralPublic: Uint8Array,
  mlKemPublic: Uint8Array,
  ciphertext?: Uint8Array,
): Promise<{ sig: Uint8Array; pqSig: Uint8Array }> {
  const msg = ephemeralSigningMessage(sessionId, ephemeralPublic, mlKemPublic, ciphertext);
  return { sig: await signer.sign(msg), pqSig: await signMlDsa(mlDsa, EPHEMERAL_PQ_CONTEXT, msg) };
}

/**
 * Why a peer's ephemeral was refused. A CLOSED set — a free-form string is what lets a new code
 * reach a caller with nothing to act on (`refusal-reasons.ts` records what that cost).
 */
export const EPHEMERAL_AUTH_REFUSALS = {
  /** No Ed25519 signature at all. */
  SIGNATURE_MISSING: "ephemeral_signature_missing",
  /** The Ed25519 signature or the X25519 public is the wrong width. */
  MALFORMED: "ephemeral_malformed",
  /** The Ed25519 signature did not verify against the expected identity over these bytes. */
  SIGNATURE_MISMATCH: "ephemeral_signature_mismatch",
  /** No `mlkem_public` — an announce without its post-quantum half. */
  PQ_MISSING: "ephemeral_pq_missing",
  /** A post-quantum field of the wrong width (`mlkem_public`, `mlkem_ciphertext`, `ephemeral_pq_sig`). */
  PQ_MALFORMED: "ephemeral_pq_malformed",
  /** No `ephemeral_pq_sig`. */
  PQ_SIGNATURE_MISSING: "ephemeral_pq_signature_missing",
  /** The ML-DSA signature did not verify against the counterparty's registered ML-DSA key. */
  PQ_SIGNATURE_MISMATCH: "ephemeral_pq_signature_mismatch",
  /** A `mlkem_ciphertext` from the side that is not the encapsulator. */
  PQ_ROLE_VIOLATION: "ephemeral_pq_role_violation",
  /** This machine holds no verified ML-DSA key for the counterparty — a LOCAL fault, never the peer's. */
  PQ_PEER_KEYS_UNKNOWN: "ephemeral_pq_peer_keys_unknown",
} as const;

export type EphemeralAuthRefusal =
  (typeof EPHEMERAL_AUTH_REFUSALS)[keyof typeof EPHEMERAL_AUTH_REFUSALS];

export type EphemeralAuthResult =
  | { ok: true }
  | { ok: false; reason: EphemeralAuthRefusal; detail: string };

/**
 * VERIFY A PEER'S ANNOUNCE BEFORE ANYTHING IS DERIVED FROM IT.
 *
 * Order: presence and widths, then Ed25519, then ML-DSA (D11, D16). Both signatures are required;
 * a genuine Ed25519 beside a missing or wrong ML-DSA one is refused. A relay swapping
 * `mlkem_public` or the ciphertext fails at the Ed25519 check, because that signature covers them.
 *
 * 🚨 MISSING, MALFORMED AND MISMATCHED ALL FAIL. They are separate REASONS because they send an
 * operator to different places, and they are the same OUTCOME because an attacker evading a mismatch
 * check simply supplies no signature at all.
 *
 * Called BEFORE `deriveSessionSecrets`, never alongside it.
 */
export async function verifySessionEphemeral(opts: {
  /** The identity we EXPECT — the counterparty this session is with, never a value the relay sent. */
  expectedIdentityPublic: Uint8Array;
  /** The counterparty's registered ML-DSA key, verified through its key binding. */
  expectedPqPublic: Uint8Array | undefined;
  sessionId: Uint8Array;
  peerEphemeralPublic: Uint8Array | undefined;
  peerMlKemPublic: Uint8Array | undefined;
  peerCiphertext: Uint8Array | undefined;
  peerSignature: Uint8Array | undefined;
  peerPqSignature: Uint8Array | undefined;
}): Promise<EphemeralAuthResult> {
  if (opts.peerSignature === undefined) {
    return {
      ok: false,
      reason: EPHEMERAL_AUTH_REFUSALS.SIGNATURE_MISSING,
      detail:
        "the peer sent a session key with no signature over it, so there is nothing to tie it to " +
        "your counterparty. An unsigned key is exactly what a relay substituting its own would send.",
    };
  }
  if (
    opts.peerSignature.length !== EPHEMERAL_SIG_BYTES ||
    opts.peerEphemeralPublic === undefined ||
    opts.peerEphemeralPublic.length !== EPHEMERAL_PUBLIC_BYTES
  ) {
    return {
      ok: false,
      reason: EPHEMERAL_AUTH_REFUSALS.MALFORMED,
      detail:
        `the peer's session key material is the wrong shape — signature ${opts.peerSignature.length} ` +
        `bytes (expected ${EPHEMERAL_SIG_BYTES}), key ${opts.peerEphemeralPublic?.length ?? 0} bytes ` +
        `(expected ${EPHEMERAL_PUBLIC_BYTES}).`,
    };
  }
  if (opts.peerMlKemPublic === undefined) {
    return {
      ok: false,
      reason: EPHEMERAL_AUTH_REFUSALS.PQ_MISSING,
      detail:
        "the peer's session key has no post-quantum half, so a key agreed from it could be recovered " +
        "from a recording by a quantum computer. Every current build sends one.",
    };
  }
  if (opts.peerPqSignature === undefined) {
    return {
      ok: false,
      reason: EPHEMERAL_AUTH_REFUSALS.PQ_SIGNATURE_MISSING,
      detail: "the peer's session key carries no post-quantum signature, so its post-quantum half is not tied to your counterparty.",
    };
  }
  if (
    opts.peerMlKemPublic.length !== ML_KEM_PUBLIC_KEY_BYTES ||
    (opts.peerCiphertext !== undefined && opts.peerCiphertext.length !== ML_KEM_CIPHERTEXT_BYTES) ||
    opts.peerPqSignature.length !== ML_DSA_SIGNATURE_BYTES
  ) {
    return {
      ok: false,
      reason: EPHEMERAL_AUTH_REFUSALS.PQ_MALFORMED,
      detail:
        `the peer's post-quantum session material is the wrong shape — ML-KEM key ${opts.peerMlKemPublic.length} ` +
        `(expected ${ML_KEM_PUBLIC_KEY_BYTES}), ciphertext ${opts.peerCiphertext?.length ?? "absent"} ` +
        `(expected ${ML_KEM_CIPHERTEXT_BYTES} when present), signature ${opts.peerPqSignature.length} ` +
        `(expected ${ML_DSA_SIGNATURE_BYTES}).`,
    };
  }
  if (opts.expectedPqPublic === undefined || opts.expectedPqPublic.length !== ML_DSA_PUBLIC_KEY_BYTES) {
    return {
      ok: false,
      reason: EPHEMERAL_AUTH_REFUSALS.PQ_PEER_KEYS_UNKNOWN,
      detail:
        "this machine holds no verified post-quantum key for your counterparty, so it cannot check " +
        "their session key. This is a fault on THIS machine — the keys should have been recorded from " +
        "the session assignment — not something the counterparty did.",
    };
  }
  const message = ephemeralSigningMessage(opts.sessionId, opts.peerEphemeralPublic, opts.peerMlKemPublic, opts.peerCiphertext);
  if (!edVerify(opts.expectedIdentityPublic, message, opts.peerSignature)) {
    return {
      ok: false,
      reason: EPHEMERAL_AUTH_REFUSALS.SIGNATURE_MISMATCH,
      detail:
        "the peer's session key is signed, but not by the counterparty this session is with, or not over " +
        "these bytes. That is what a relay substituting its own key looks like. Refusing.",
    };
  }
  if (!(await verifyMlDsa(opts.expectedPqPublic, EPHEMERAL_PQ_CONTEXT, message, opts.peerPqSignature))) {
    return {
      ok: false,
      reason: EPHEMERAL_AUTH_REFUSALS.PQ_SIGNATURE_MISMATCH,
      detail:
        "the peer's session key carries a genuine identity signature but a post-quantum signature that " +
        "is not your counterparty's registered key. Refusing: both signatures must hold.",
    };
  }
  return { ok: true };
}

/** The fields of a `session_key_agreement` frame, extracted in one place (decision 12). */
export interface SessionKeyAgreementFields {
  ephemeralPublic?: Uint8Array;
  mlkemPublic?: Uint8Array;
  mlkemCiphertext?: Uint8Array;
  signature?: Uint8Array;
  pqSignature?: Uint8Array;
}

/**
 * Read a decoded `session_key_agreement` frame. Byte fields that are absent or not bytes come back
 * `undefined`; `verifySessionEphemeral` then names which one.
 */
export function decodeSessionKeyAgreementFrame(frame: Record<string, unknown>): SessionKeyAgreementFields {
  const bytes = (v: unknown): Uint8Array | undefined => (v instanceof Uint8Array ? v : undefined);
  return {
    ephemeralPublic: bytes(frame["ephemeral_public"]),
    mlkemPublic: bytes(frame["mlkem_public"]),
    mlkemCiphertext: bytes(frame["mlkem_ciphertext"]),
    signature: bytes(frame["ephemeral_sig"]),
    pqSignature: bytes(frame["ephemeral_pq_sig"]),
  };
}
