/**
 * DOD-M15-DELIVERYACK-1 — the recipient signs for what their machine received.
 *
 * ─── The claim this closes, and the one it deliberately does not make ──────────────────────────
 *
 * Before this, a delivery acknowledgement was a transport nod: four fields on a Noise-authenticated
 * stream, retained nowhere, leaving nothing a sender could ever hand a third party. So "it never
 * reached me" was unanswerable — and it was unanswerable in BOTH directions, because there are many
 * ordinary reasons a message really does go missing (the relay parked it and never delivered it,
 * the recipient's daemon died between ordering and pull, the per-recipient queue hit its bound and
 * dropped the oldest frame, the screener refused it, it was quarantined on arrival). Every one of
 * those looked exactly like someone choosing not to answer.
 *
 * What the signature below says: **a machine holding this identity key received these exact bytes
 * in this exact session.** That is all. It is signed on INGEST, not when a human reads it, so it
 * says nothing about attention — and it is emphatically not agreement. A seal certificate's
 * `implies_assent` stays the literal `false`, and a delivery acknowledgement must never be
 * presented as consent to anything.
 *
 * ─── What is signed, and why each field is in it ───────────────────────────────────────────────
 *
 *   message = "cello/session/v1/delivery-ack" || u32(len(sessionId)) || sessionId || contentHash
 *
 * The LABEL is domain separation. An agent signs many things with one identity key — its ephemeral,
 * its own authorship claims, park content — and a statement that is valid in two contexts is a
 * statement an attacker moves between them.
 *
 * The SESSION ID stops an acknowledgement being replayed into a different conversation with the
 * same counterparty. The CONTENT HASH is the thing being acknowledged, so a signature cannot be
 * made to cover different bytes. The session id is LENGTH-PREFIXED because it is the one
 * variable-length field: without the prefix, `sessionId ‖ contentHash` could be re-split at a
 * different boundary and two different inputs would produce identical signed bytes.
 *
 * ⚠️ WHO IT IS CHECKED AGAINST IS THE WHOLE POINT. `verifyDeliveryAck` takes the session's RECORDED
 * participant identity keys — which come from the directory-signed assignment, not from anything
 * inside the acknowledgement frame. A signature checked against a key carried in its own frame
 * proves only that somebody owns a keypair, which the frame already claims by existing.
 *
 * Ed25519 — RFC 8032. SHA-256 — FIPS 180-4.
 */

import { verify as edVerify } from "./ed25519.js";

const ENC = new TextEncoder();

/** Domain separation. Versioned, so a future change is a new label rather than a reinterpretation. */
const DELIVERY_ACK_SIG_LABEL = ENC.encode("cello/session/v1/delivery-ack");

/** Ed25519 signatures are 64 bytes; a SHA-256 content hash is 32. */
export const DELIVERY_ACK_SIG_BYTES = 64;
export const DELIVERY_ACK_HASH_BYTES = 32;

/**
 * The exact bytes both sides sign and verify.
 *
 * Written once and used by BOTH directions on purpose — a signer and a verifier that each build the
 * message from their own reading of a spec is how two implementations end up disagreeing about a
 * byte and refusing each other for a reason neither can see.
 */
export function deliveryAckSigningMessage(
  sessionId: Uint8Array,
  contentHash: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(
    DELIVERY_ACK_SIG_LABEL.length + 4 + sessionId.length + contentHash.length,
  );
  let o = 0;
  out.set(DELIVERY_ACK_SIG_LABEL, o);
  o += DELIVERY_ACK_SIG_LABEL.length;
  out[o++] = (sessionId.length >>> 24) & 0xff;
  out[o++] = (sessionId.length >>> 16) & 0xff;
  out[o++] = (sessionId.length >>> 8) & 0xff;
  out[o++] = sessionId.length & 0xff;
  out.set(sessionId, o);
  o += sessionId.length;
  out.set(contentHash, o);
  return out;
}

/** Sign "my machine received these bytes in this session" with the agent's long-term identity key. */
export async function signDeliveryAck(
  signer: { sign(data: Uint8Array): Promise<Uint8Array> },
  sessionId: Uint8Array,
  contentHash: Uint8Array,
): Promise<Uint8Array> {
  return signer.sign(deliveryAckSigningMessage(sessionId, contentHash));
}

/**
 * Why an acknowledgement was refused. A CLOSED set — a free-form string is what lets a new code
 * reach a caller with nothing to act on.
 */
export const DELIVERY_ACK_REFUSALS = {
  /** No signature at all — an old build, or somebody skipping the proof. */
  SIGNATURE_MISSING: "delivery_ack_signature_missing",
  /** Present but the wrong width, or the content hash is the wrong width. */
  MALFORMED: "delivery_ack_malformed",
  /** Checked against every recorded participant key and matched none of them. */
  SIGNATURE_MISMATCH: "delivery_ack_signature_mismatch",
  /** This side holds no participant keys for the session, so there is nothing to check against. */
  NO_PARTICIPANT_KEYS: "delivery_ack_no_participant_keys",
} as const;

export type DeliveryAckRefusal =
  (typeof DELIVERY_ACK_REFUSALS)[keyof typeof DELIVERY_ACK_REFUSALS];

export type DeliveryAckResult =
  | { ok: true; signerPublic: Uint8Array }
  | { ok: false; reason: DeliveryAckRefusal; detail: string };

/**
 * VERIFY AN ACKNOWLEDGEMENT AGAINST THE SESSION'S OWN RECORDED PARTICIPANTS.
 *
 * 🚨 MISSING, MALFORMED AND MISMATCHED ALL FAIL, AND THEY FAIL THE SAME WAY. They are separate
 * REASONS because they send a reader somewhere different; they are one OUTCOME because an attacker
 * evading a mismatch check simply supplies no signature at all. "We could not tell" must never be
 * more forgiving than "we proved it wrong".
 *
 * 🚨 AND AN UNVERIFIABLE ACKNOWLEDGEMENT IS NOT A SECURITY EVENT — it is the ABSENCE of evidence.
 * The caller discards it and is exactly where it was before the frame arrived: holding no proof
 * this message landed. It must not freeze the session, advance anything, or feed a trust signal.
 * A missing acknowledgement is usually innocent, and code that reads one as evasion is a defect.
 *
 * `participantIdentityPublics` are the keys the session RECORDED — from the directory-signed
 * assignment. Never a key read out of the acknowledgement frame.
 */
export function verifyDeliveryAck(opts: {
  /** The session's recorded participant identity keys. Never supplied by the frame being checked. */
  participantIdentityPublics: readonly Uint8Array[];
  sessionId: Uint8Array;
  contentHash: Uint8Array;
  signature: Uint8Array | undefined;
}): DeliveryAckResult {
  if (opts.signature === undefined) {
    return {
      ok: false,
      reason: DELIVERY_ACK_REFUSALS.SIGNATURE_MISSING,
      detail:
        "the acknowledgement carries no signature, so there is nothing tying it to either party " +
        "of this session. It is discarded on the same path as a wrong signature — a check that is " +
        "lenient about a missing proof is a check anyone can skip by omitting the field. Nothing " +
        "is concluded from this: the message may well have arrived, and this side simply holds no " +
        "evidence that it did.",
    };
  }
  if (
    opts.signature.length !== DELIVERY_ACK_SIG_BYTES ||
    opts.contentHash.length !== DELIVERY_ACK_HASH_BYTES
  ) {
    return {
      ok: false,
      reason: DELIVERY_ACK_REFUSALS.MALFORMED,
      detail:
        `the acknowledgement is the wrong shape — signature ${opts.signature.length} bytes ` +
        `(expected ${DELIVERY_ACK_SIG_BYTES}), content hash ${opts.contentHash.length} bytes ` +
        `(expected ${DELIVERY_ACK_HASH_BYTES}). Discarded rather than padded: a short value ` +
        "silently zero-extended is a proof about bytes nobody sent.",
    };
  }
  if (opts.participantIdentityPublics.length === 0) {
    return {
      ok: false,
      reason: DELIVERY_ACK_REFUSALS.NO_PARTICIPANT_KEYS,
      detail:
        "this side holds no recorded participant keys for the session, so there is nothing to " +
        "check the acknowledgement against. Verifying against a key carried inside the frame " +
        "would prove only that somebody owns a keypair, which the frame already claims by " +
        "existing — so it is discarded instead.",
    };
  }
  const message = deliveryAckSigningMessage(opts.sessionId, opts.contentHash);
  for (const candidate of opts.participantIdentityPublics) {
    if (candidate.length !== 32) continue;
    if (edVerify(candidate, message, opts.signature)) {
      return { ok: true, signerPublic: candidate };
    }
  }
  return {
    ok: false,
    reason: DELIVERY_ACK_REFUSALS.SIGNATURE_MISMATCH,
    detail:
      "the acknowledgement is signed, but not by either party recorded for this session, or not " +
      "over this session and this message. A signature can be perfectly valid and still be " +
      "irrelevant — the only one worth keeping is one that checks against a key this side did not " +
      "take from the acknowledgement itself. Discarded; nothing is concluded about the sender.",
  };
}
