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
 */

import { createHash } from "node:crypto";
import { encodeCbor, decodeCbor } from "./cbor.js";

/** Domain tag in slot 0. Distinct from the update and proposal domains. */
export const DOCUMENT_ACK_DOMAIN = "CELLO-DOCUMENT-ACK-v1";

const HEX32 = /^[0-9a-f]{64}$/;

export interface DocumentAck {
  type: "document_ack";
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
 * `rejection_reason` is encoded as `null` when absent rather than omitted, so an ack that carries a
 * reason and one that does not produce different preimages. Omitting a field shortens the array,
 * which is a shape change the next field would silently absorb.
 */
export function buildDocumentAckTbs(
  ack: DocumentAck,
  opts: { preHash?: boolean } = {},
): Uint8Array {
  const preimage = encodeCbor([
    DOCUMENT_ACK_DOMAIN,
    ack.document_id,
    ack.envelope_hash,
    ack.acker_agent_id,
    ack.admitted,
    ack.rejection_reason ?? null,
    ack.acked_at_ms,
  ]);
  if (opts.preHash === false) return preimage;
  return new Uint8Array(createHash("sha256").update(preimage).digest());
}

export function encodeDocumentAck(ack: DocumentAck): Uint8Array {
  return encodeCbor({
    type: ack.type,
    document_id: ack.document_id,
    envelope_hash: ack.envelope_hash,
    acker_agent_id: ack.acker_agent_id,
    admitted: ack.admitted,
    rejection_reason: ack.rejection_reason ?? null,
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

  const reason = present(map, "rejection_reason");
  if (reason !== null && typeof reason !== "string") {
    throw new Error("document_ack_reason: rejection_reason must be a text string or explicit null");
  }
  if (!admitted && (reason === null || reason === "")) {
    // A refusal with no reason is the failure the whole rejection protocol exists to prevent: the
    // sender is told to stop and supersede, and cannot know what to change.
    throw new Error("document_ack_reason: a rejection must carry its reason");
  }
  if (admitted && reason !== null) {
    // An admission carrying a rejection reason is a contradiction, and whichever field a reader
    // trusts, the other one is lying to them.
    throw new Error("document_ack_reason: an admission must not carry a rejection reason");
  }

  const ackedAt = present(map, "acked_at_ms");
  if (typeof ackedAt !== "number" || !Number.isInteger(ackedAt)) {
    throw new Error("document_ack_time: acked_at_ms must be an integer");
  }

  const signature = present(map, "signature");
  if (!(signature instanceof Uint8Array)) {
    throw new Error("document_ack_signature: must be a CBOR byte string");
  }

  return {
    type: "document_ack",
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
}
