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
 *   message = "cello/session/v1/ephemeral" || sessionId || ephemeralPublic
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

const ENC = new TextEncoder();

/** Domain separation. Versioned, so a future change is a new label rather than a reinterpretation. */
const EPHEMERAL_SIG_LABEL = ENC.encode("cello/session/v1/ephemeral");

/** Ed25519 signatures are 64 bytes; X25519 publics are 32. */
export const EPHEMERAL_SIG_BYTES = 64;
export const EPHEMERAL_PUBLIC_BYTES = 32;

/**
 * The exact bytes both sides sign and verify.
 *
 * Written once and used by BOTH directions on purpose. A signer and a verifier that each build the
 * message from their own reading of a spec is how two implementations end up disagreeing about a
 * byte and rejecting each other for a reason neither can see.
 */
export function ephemeralSigningMessage(sessionId: Uint8Array, ephemeralPublic: Uint8Array): Uint8Array {
  // The session id is LENGTH-PREFIXED (4 bytes, big-endian). Concatenating two variable-length
  // fields lets a crafted pair re-split at a different boundary and produce identical bytes from
  // different inputs — the signature would then cover something other than what it appears to.
  const out = new Uint8Array(EPHEMERAL_SIG_LABEL.length + 4 + sessionId.length + ephemeralPublic.length);
  let o = 0;
  out.set(EPHEMERAL_SIG_LABEL, o); o += EPHEMERAL_SIG_LABEL.length;
  out[o++] = (sessionId.length >>> 24) & 0xff;
  out[o++] = (sessionId.length >>> 16) & 0xff;
  out[o++] = (sessionId.length >>> 8) & 0xff;
  out[o++] = sessionId.length & 0xff;
  out.set(sessionId, o); o += sessionId.length;
  out.set(ephemeralPublic, o);
  return out;
}

/** Sign this side's throwaway public key with the agent's long-term identity key. */
export async function signSessionEphemeral(
  signer: { sign(data: Uint8Array): Promise<Uint8Array> },
  sessionId: Uint8Array,
  ephemeralPublic: Uint8Array,
): Promise<Uint8Array> {
  return signer.sign(ephemeralSigningMessage(sessionId, ephemeralPublic));
}

/**
 * Why a peer's ephemeral was refused. A CLOSED set — a free-form string is what lets a new code
 * reach a caller with nothing to act on (`refusal-reasons.ts` records what that cost).
 */
export const EPHEMERAL_AUTH_REFUSALS = {
  /** No signature at all. */
  SIGNATURE_MISSING: "ephemeral_signature_missing",
  /** Present but the wrong width, or the public key is the wrong width. */
  MALFORMED: "ephemeral_malformed",
  /** Verified against the expected identity and did not match. */
  SIGNATURE_MISMATCH: "ephemeral_signature_mismatch",
} as const;

export type EphemeralAuthRefusal =
  (typeof EPHEMERAL_AUTH_REFUSALS)[keyof typeof EPHEMERAL_AUTH_REFUSALS];

export type EphemeralAuthResult =
  | { ok: true }
  | { ok: false; reason: EphemeralAuthRefusal; detail: string };

/**
 * VERIFY A PEER'S EPHEMERAL BEFORE ANYTHING IS DERIVED FROM IT.
 *
 * 🚨 MISSING, MALFORMED AND MISMATCHED ALL FAIL. They are separate REASONS because they send an
 * operator to different places, and they are the same OUTCOME because an attacker evading a mismatch
 * check simply supplies no signature at all. "We could not tell" must never be more forgiving than
 * "we proved it wrong" — that is the hole, not the mismatch.
 *
 * Called BEFORE `deriveSessionSecrets`, never alongside it. Deriving first and checking after means
 * a key exists, briefly, that was agreed with someone unproven — and every "briefly" in this
 * codebase eventually turns out to be long enough for something to read it.
 */
export function verifySessionEphemeral(opts: {
  /** The identity we EXPECT — from what the operator asked for, never from the directory or relay. */
  expectedIdentityPublic: Uint8Array;
  sessionId: Uint8Array;
  peerEphemeralPublic: Uint8Array | undefined;
  peerSignature: Uint8Array | undefined;
}): EphemeralAuthResult {
  if (opts.peerSignature === undefined) {
    return {
      ok: false,
      reason: EPHEMERAL_AUTH_REFUSALS.SIGNATURE_MISSING,
      detail:
        "the peer sent a session key with no signature over it, so there is nothing to tie it to " +
        "your counterparty. An unsigned key is exactly what a relay substituting its own would send, " +
        "and it is refused on the same path as a wrong signature — a check that is lenient about a " +
        "missing proof is a check an attacker skips.",
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
        `(expected ${EPHEMERAL_PUBLIC_BYTES}). Refusing rather than padding: a short value silently ` +
        "zero-extended is an agreement with something that is not the peer.",
    };
  }
  const message = ephemeralSigningMessage(opts.sessionId, opts.peerEphemeralPublic);
  if (!edVerify(opts.expectedIdentityPublic, message, opts.peerSignature)) {
    return {
      ok: false,
      reason: EPHEMERAL_AUTH_REFUSALS.SIGNATURE_MISMATCH,
      detail:
        "the peer's session key is signed, but not by the counterparty this session is with. That " +
        "is what a relay substituting its own key looks like: it would then share one secret with " +
        "you and another with them, and read everything in between while both sides saw a working " +
        "conversation. Refusing.",
    };
  }
  return { ok: true };
}
