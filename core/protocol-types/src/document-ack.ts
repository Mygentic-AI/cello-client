/**
 * DOD-DOC-INBOUND-2 — the document ACK (§16.4).
 *
 * The frame that closes DELIVERY-2's loop. Until it exists, a sent envelope's outcome is
 * `admitted: null` forever: the worker knows the content left and nothing more, so it re-sends on
 * the ack timeout and eventually stalls the document at the unacked ceiling.
 *
 * ── WHY A REJECTION IS AN ACK ─────────────────────────────────────────────────────────────────
 *
 * `admitted: false` is not a failure to acknowledge — it is an acknowledgement that says no. The
 * peer has DECIDED, so the sender must stop retrying and supersede instead (§3.2). Modelling
 * rejection as "no ack" would leave the sender redelivering an envelope the peer has already ruled
 * on, re-triggering their gate and their retry counter until the document stalls for reasons the
 * operator cannot see.
 *
 * ── WHY IT IS SIGNED ──────────────────────────────────────────────────────────────────────────
 *
 * The ack settles an envelope permanently: an acked envelope stops being redelivered and, if the
 * ack says rejected, the sender rolls back local work. Both are consequences an unauthenticated
 * party must not be able to cause. An unsigned ack lets anyone who can reach the channel silence a
 * delivery — the content is dropped from the pending set and neither operator ever learns it was
 * never applied, which is exactly the silent divergence the two-layer design exists to prevent.
 *
 * The signature covers the ENVELOPE HASH, so an ack cannot be moved to a different envelope, and
 * the DOCUMENT ID, so it cannot be moved to a different document. It does not cover `admitted`
 * alone for the same reason a signature never covers one field: the whole statement is the claim.
 *
 * ── CONTRACT FOR THE CONSUMER: SETTLE ONCE ────────────────────────────────────────────────────
 *
 * Nothing here binds an ack to the acker's chain, and nothing at the type level stops one acker
 * producing a valid ADMISSION and a valid REJECTION for the same envelope. Envelopes have
 * `verifyDocumentChainLink` because per-sender ordering matters; acks have no equivalent. So the
 * consumer must settle an envelope ONCE and treat a second, contradicting ack as an ERROR with both
 * signatures retained — never as an update. Applying the later one would let a peer that admitted
 * an envelope later claim it refused it, and the sender would roll back work the peer already has.
 */

import { createHash } from "node:crypto";
import { encodeCbor, decodeCbor } from "./cbor.js";

/** Domain tag in slot 0. Distinct from the update and proposal domains. */
export const DOCUMENT_ACK_DOMAIN = "CELLO-DOCUMENT-ACK-v1";

/**
 * The ack frame version, ON THE WIRE.
 *
 * The `-v1` in the domain string never travels — it lives inside the preimage — so a V2 acker's
 * frame would decode cleanly as V1 and fail SIGNATURE VERIFICATION, sending an operator to key
 * management and peer identity for a version-skew bug. The update envelope refuses `epoch_id` and
 * `update_encoding` by value for exactly this reason: skew that is not SAID becomes silent loss or
 * a misattributed error.
 */
export const DOCUMENT_ACK_VERSION = 1;

/**
 * A rejection reason is peer-controlled text bound for an operator's screen and the policy log.
 * Capped because unbounded peer-controlled display text is not something to hand onward untouched.
 */
export const MAX_REJECTION_REASON_LENGTH = 200;

const HEX32 = /^[0-9a-f]{64}$/;

export interface DocumentAck {
  type: "document_ack";
  /** Always `DOCUMENT_ACK_VERSION` in V1. Carried on the wire so skew is DETECTED, not misread. */
  ack_version: number;
  document_id: string;
  /** The envelope this settles. */
  envelope_hash: string;
  /** Who is answering — the party that received the update. */
  acker_agent_id: string;
  /**
   * `true` admitted, `false` rejected. BOTH settle the envelope; see the header. There is no third
   * value on the wire, because an ack that does not say which is not an answer.
   */
  admitted: boolean;
  /** Present iff `admitted` is false. The §3.2 reason, so the sender can supersede deliberately. */
  rejection_reason?: string;
  acked_at_ms: number;
  /** Ed25519 (RFC 8032) over `buildDocumentAckTbs`. */
  signature: Uint8Array;
}

/**
 * The canonical to-be-signed preimage: a fixed-order CBOR ARRAY with the domain in slot 0.
 *
 * An array rather than a map for the reason `cbor.ts` gives — this encoder is deliberately not
 * deterministic for maps, so a map preimage would make the signature depend on the order the acker
 * happened to build the object in, and two honest implementations would disagree.
 *
 * `rejection_reason` is encoded as `null` when absent rather than omitted, so the slot is always
 * occupied and no field's meaning depends on whether the one before it was present.
 *
 * An earlier version of this comment claimed omission would be "silently absorbed by the next
 * field". That is FALSE for this encoder and worth correcting rather than deleting, because a wrong
 * fact about the wire is what the next structure's justification gets built on: a 6-element array
 * begins `0x86` and a 7-element one `0x87`, so a missing slot is loud, in byte 0. Measured.
 * `cbor.ts` says the same thing — arrays are minimal and order-fixed. The explicit null is still
 * right; the reason is stable slot indices, not collision avoidance.
 */
export function buildDocumentAckTbs(
  ack: DocumentAck,
  opts: { preHash?: boolean } = {},
): Uint8Array {
  assertDocumentAckConsistent(ack);
  const preimage = encodeCbor([
    DOCUMENT_ACK_DOMAIN,
    ack.ack_version,
    ack.document_id,
    ack.envelope_hash,
    ack.acker_agent_id,
    ack.admitted,
    normalizeReason(ack.rejection_reason),
    // BIGINT past 0xffffffff. cbor-x encodes a JS number that large as an IEEE float64 (`fb`)
    // rather than a uint64 (`1b`) — measured: 1700000000000 gives fb4278bcfe56800000, not
    // 1b0000018bcfe56800. A millisecond timestamp is always that large, so any implementation
    // encoding RFC 8949-canonically would compute different TBS bytes and reject a GENUINE ack —
    // surfacing as a signature failure, which reads as forgery. Three sibling builders carry this
    // same coercion and primary-transfer.ts names it as a defect it shipped without.
    typeof ack.acked_at_ms === "number" && ack.acked_at_ms > 0xffffffff
      ? BigInt(ack.acked_at_ms)
      : ack.acked_at_ms,
  ]);
  if (opts.preHash === false) return preimage;
  return new Uint8Array(createHash("sha256").update(preimage).digest());
}

/** Empty string means ABSENT. See `assertDocumentAckConsistent`. */
function normalizeReason(reason: string | undefined): string | null {
  return reason === undefined || reason === "" ? null : reason;
}

/**
 * The cross-field rules, checked on ENCODE as well as decode.
 *
 * On encode too, because a locally-built contradictory ack would otherwise be signed and shipped
 * and fail only on the remote decode: the sender sees a silent stall, the peer sees the error, and
 * the two never meet. The rule belongs where the object is built, not only where it is read.
 */
export function assertDocumentAckConsistent(ack: DocumentAck): void {
  const reason = normalizeReason(ack.rejection_reason);
  if (!ack.admitted && reason === null) {
    // The sender is being told to stop and supersede. Without the reason it cannot know what to
    // change — the failure the whole rejection protocol exists to prevent.
    throw new Error("document_ack_reason: a rejection must carry its reason");
  }
  if (ack.admitted && reason !== null) {
    // A contradiction: whichever field a reader trusts, the other is lying to them.
    throw new Error(
      `document_ack_reason: an admission must not carry a rejection reason, and this one carries "${reason}"`,
    );
  }
  if (reason !== null && reason.length > MAX_REJECTION_REASON_LENGTH) {
    throw new Error(
      `document_ack_reason: a rejection reason may be at most ${MAX_REJECTION_REASON_LENGTH} ` +
        `characters, and this one is ${reason.length}`,
    );
  }
}

export function encodeDocumentAck(ack: DocumentAck): Uint8Array {
  assertDocumentAckConsistent(ack);
  return encodeCbor({
    type: ack.type,
    ack_version: ack.ack_version,
    document_id: ack.document_id,
    envelope_hash: ack.envelope_hash,
    acker_agent_id: ack.acker_agent_id,
    admitted: ack.admitted,
    rejection_reason: normalizeReason(ack.rejection_reason),
    acked_at_ms: ack.acked_at_ms,
    signature: ack.signature,
  });
}

function present(map: Record<string, unknown>, field: string): unknown {
  // `in`, not a nullish check — the same discipline as the update envelope. A defaulted field here
  // is a claim the acker never made, and this frame's whole job is to carry their claim.
  if (!(field in map)) {
    throw new Error(`document_ack_missing_field: ${field} is mandatory and was not present`);
  }
  return map[field];
}

/**
 * Decode and validate. Refuses rather than defaulting on every field.
 *
 * The one that matters most: `admitted` must be a real boolean. Coerced, a truthy string like
 * `"false"` would settle a REJECTED envelope as admitted — the sender would stop retrying, never
 * roll back, and both parties would believe content was applied that the receiver refused.
 */
export function decodeDocumentAck(bytes: Uint8Array): DocumentAck {
  const decoded = decodeCbor(bytes);
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
    throw new Error("document_ack_malformed: not a CBOR map");
  }
  const map = decoded as Record<string, unknown>;

  const type = present(map, "type");
  if (type !== "document_ack") {
    throw new Error(`document_ack_type: expected document_ack, got ${String(type)}`);
  }

  const version = present(map, "ack_version");
  if (typeof version !== "number" || !Number.isInteger(version)) {
    throw new Error("document_ack_version: must be an integer");
  }
  if (version !== DOCUMENT_ACK_VERSION) {
    // Named as SKEW. Without a wire version this frame decoded cleanly and failed signature
    // verification instead, sending an operator to key management for a version problem.
    throw new Error(
      `document_ack_version: this build speaks ack version ${DOCUMENT_ACK_VERSION} and the frame ` +
        `declares ${version} — one of the two clients needs upgrading`,
    );
  }

  const documentId = present(map, "document_id");
  if (typeof documentId !== "string" || !HEX32.test(documentId)) {
    throw new Error(`document_ack_document_id: must be a 32-byte hex digest`);
  }

  const envelopeHash = present(map, "envelope_hash");
  if (typeof envelopeHash !== "string" || !HEX32.test(envelopeHash)) {
    throw new Error("document_ack_envelope_hash: must be a 32-byte hex digest");
  }

  const ackerAgentId = present(map, "acker_agent_id");
  if (typeof ackerAgentId !== "string" || ackerAgentId.length === 0) {
    throw new Error("document_ack_acker: acker_agent_id must be a non-empty text string");
  }

  const admitted = present(map, "admitted");
  if (typeof admitted !== "boolean") {
    throw new Error(`document_ack_admitted: must be a boolean, got ${typeof admitted}`);
  }

  const rawReason = present(map, "rejection_reason");
  if (rawReason !== null && typeof rawReason !== "string") {
    throw new Error("document_ack_reason: rejection_reason must be a text string or explicit null");
  }
  // NORMALIZED ONCE, before the cross-field rules. The empty string meant "absent" on the rejection
  // branch and "present" on the admission branch, so an honest peer written in a language where a
  // non-nullable string field defaults to "" — Go, Rust — had its ADMISSION refused as a
  // contradiction it never expressed. The sender then never settles, retries to the unacked
  // ceiling, and the document stalls: precisely the failure this frame exists to end.
  const reason = rawReason === "" ? null : (rawReason as string | null);

  const ackedAt = present(map, "acked_at_ms");
  // BOUNDED. `Number.isInteger(1e300)` is true, and this is the only field available to order two
  // conflicting acks — leaving it unbounded hands that tiebreak to an attacker-chosen value.
  if (typeof ackedAt !== "number" || !Number.isSafeInteger(ackedAt) || ackedAt <= 0) {
    throw new Error(
      `document_ack_time: acked_at_ms must be a positive safe integer, got ${String(ackedAt)}`,
    );
  }

  const signature = present(map, "signature");
  if (!(signature instanceof Uint8Array)) {
    throw new Error("document_ack_signature: must be a CBOR byte string");
  }

  const ack: DocumentAck = {
    type: "document_ack",
    ack_version: version,
    document_id: documentId,
    envelope_hash: envelopeHash,
    acker_agent_id: ackerAgentId,
    admitted,
    ...(reason === null ? {} : { rejection_reason: reason }),
    acked_at_ms: ackedAt,
    // COPIED — cbor-x returns byte strings as views into the buffer it decoded, so a caller reusing
    // a pooled read buffer would have the signature change after it was verified.
    signature: new Uint8Array(signature),
  };
  // The same cross-field rules the encoder applies. One implementation, so the two surfaces cannot
  // drift into disagreeing about what a valid ack is.
  assertDocumentAckConsistent(ack);
  return ack;
}
