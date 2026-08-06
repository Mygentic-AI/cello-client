/**
 * DOD-DOC-TOOLS-1 — the PROPOSAL ack (§16.3).
 *
 * The consent decision, told to the party who asked for it.
 *
 * ── WHY THIS EXISTS ───────────────────────────────────────────────────────────────────────────
 *
 * Without it the proposer is never told the answer. `cello_doc_list` had to INFER acceptance from
 * "the peer has published into it", which conflates three different situations — refused, never
 * received, and accepted-but-untouched — into one absent flag. Two of those want the operator to
 * act and one does not, and the surface could not tell them apart. A protocol that asks for consent
 * and never reports it is not asking; it is announcing.
 *
 * ── WHY IT IS SEPARATE FROM `document_ack` ────────────────────────────────────────────────────
 *
 * `document_ack` settles an ENVELOPE, identified by its hash in the log. A proposal is not in the
 * envelope log — there is no document yet, which is the whole point — so an ack shaped around an
 * envelope hash would carry a hash of nothing, and its consumer looks the envelope up. Overloading
 * the frame would mean one decoder branching on whether the thing it references exists, which is
 * how a settle-once rule gets applied to the wrong table.
 *
 * ── WHY IT IS SIGNED, AND WHAT THE SIGNATURE COVERS ───────────────────────────────────────────
 *
 * A refusal ack tells the proposer to stop: no retry, no document. Unsigned, anyone reaching the
 * channel could make a proposal appear refused by a party who never saw it, and the two operators
 * would each believe the other had walked away. The signature covers the DOCUMENT ID — which
 * commits to the proposer, the peer, the properties and the nonce — so an ack cannot be moved to
 * another proposal, and the decision itself, because the whole statement is the claim.
 *
 * ── SETTLE ONCE ───────────────────────────────────────────────────────────────────────────────
 *
 * Nothing here orders two acks from one acker, and the same rule `document_ack` states applies: a
 * second, CONTRADICTING ack is an error with both signatures retained, never an update. A peer that
 * accepted must not be able to later claim it refused — the proposer would tear down a document the
 * peer is still editing.
 */

import { createHash } from "node:crypto";
import { encodeCbor, decodeCbor } from "./cbor.js";

/** Domain tag in slot 0. Distinct from the update, ack, proposal and rejection domains. */
export const DOCUMENT_PROPOSAL_ACK_DOMAIN = "CELLO-DOCUMENT-PROPOSAL-ACK-v1";

/**
 * The frame version, ON THE WIRE.
 *
 * The `-v1` in the domain never travels, so a V2 acker's frame would decode cleanly as V1 and fail
 * SIGNATURE verification — sending an operator to key management for a version-skew bug. Skew that
 * is not SAID becomes silent loss or a misattributed error.
 */
export const DOCUMENT_PROPOSAL_ACK_VERSION = 1;

/** A refusal reason is peer-controlled text bound for an operator's screen. Capped for that reason. */
export const MAX_PROPOSAL_REFUSAL_REASON_LENGTH = 200;

const HEX32 = /^[0-9a-f]{64}$/;

export interface DocumentProposalAck {
  type: "document_proposal_ack";
  ack_version: number;
  /** The proposal being answered. Hash of the proposal's own preimage — see `documentIdFromProposal`. */
  document_id: string;
  /** Who decided — the party the proposal was addressed to. */
  acker_agent_id: string;
  /**
   * `true` accepted, `false` refused. Both are ANSWERS; there is no third value, because an ack
   * that does not say which is not a decision.
   */
  accepted: boolean;
  /** Present iff `accepted` is false. The operator's words, or the machine reason that auto-refused. */
  refusal_reason?: string;
  decided_at_ms: number;
  /** Ed25519 (RFC 8032) over `buildDocumentProposalAckTbs`. */
  signature: Uint8Array;
}

/** Empty string means ABSENT — see `assertDocumentProposalAckConsistent`. */
function normalizeReason(reason: string | undefined): string | null {
  return reason === undefined || reason === "" ? null : reason;
}

/**
 * The cross-field rules, checked on ENCODE as well as decode.
 *
 * On encode too, because a locally-built contradictory ack would otherwise be signed and shipped and
 * fail only at the remote decode: the acker sees success, the proposer sees an error, and the two
 * never meet. The rule belongs where the object is built, not only where it is read.
 */
export function assertDocumentProposalAckConsistent(ack: DocumentProposalAck): void {
  const reason = normalizeReason(ack.refusal_reason);
  if (!ack.accepted && reason === null) {
    // A refusal with no reason leaves the proposer unable to propose anything better. That is the
    // failure that makes people give up on a protocol rather than adjust to it.
    throw new Error("document_proposal_ack_reason: a refusal must carry its reason");
  }
  if (ack.accepted && reason !== null) {
    // A contradiction: whichever field a reader trusts, the other is lying to them.
    throw new Error(
      `document_proposal_ack_reason: an acceptance must not carry a refusal reason, and this one carries "${reason}"`,
    );
  }
  if (reason !== null && reason.length > MAX_PROPOSAL_REFUSAL_REASON_LENGTH) {
    throw new Error(
      `document_proposal_ack_reason: a refusal reason may be at most ` +
        `${MAX_PROPOSAL_REFUSAL_REASON_LENGTH} characters, and this one is ${reason.length}`,
    );
  }
  if (!HEX32.test(ack.document_id)) {
    throw new Error(`document_proposal_ack_document_id: expected 64 lowercase hex characters`);
  }
}

/**
 * The canonical to-be-signed preimage: a fixed-order CBOR ARRAY with the domain in slot 0.
 *
 * An array rather than a map for the reason `cbor.ts` gives — this encoder is deliberately not
 * deterministic for maps, so a map preimage would make the signature depend on the order the acker
 * happened to build the object in, and two honest implementations would disagree.
 *
 * `refusal_reason` occupies its slot as `null` when absent, so no field's meaning depends on
 * whether the one before it was present.
 */
export function buildDocumentProposalAckTbs(
  ack: DocumentProposalAck,
  opts: { preHash?: boolean } = {},
): Uint8Array {
  assertDocumentProposalAckConsistent(ack);
  const preimage = encodeCbor([
    DOCUMENT_PROPOSAL_ACK_DOMAIN,
    ack.ack_version,
    ack.document_id,
    ack.acker_agent_id,
    ack.accepted,
    normalizeReason(ack.refusal_reason),
    // BIGINT past 0xffffffff. cbor-x encodes a JS number that large as an IEEE float64 (`fb`)
    // rather than a uint64 (`1b`), so an implementation encoding RFC 8949-canonically would compute
    // different TBS bytes and reject a GENUINE ack — surfacing as a signature failure, which reads
    // as forgery. A millisecond timestamp is always that large. Four sibling builders carry this
    // same coercion.
    typeof ack.decided_at_ms === "number" && ack.decided_at_ms > 0xffffffff
      ? BigInt(ack.decided_at_ms)
      : ack.decided_at_ms,
  ]);
  if (opts.preHash === false) return preimage;
  return new Uint8Array(createHash("sha256").update(preimage).digest());
}

export function encodeDocumentProposalAck(ack: DocumentProposalAck): Uint8Array {
  assertDocumentProposalAckConsistent(ack);
  return encodeCbor({
    type: ack.type,
    ack_version: ack.ack_version,
    document_id: ack.document_id,
    acker_agent_id: ack.acker_agent_id,
    accepted: ack.accepted,
    refusal_reason: normalizeReason(ack.refusal_reason),
    decided_at_ms: ack.decided_at_ms,
    signature: ack.signature,
  });
}

function present(map: Record<string, unknown>, field: string): unknown {
  // `in`, not a nullish check. A defaulted field is a claim the acker never made, and carrying
  // their claim is this frame's entire job.
  if (!(field in map)) {
    throw new Error(`document_proposal_ack_missing_field: ${field} is mandatory and was not present`);
  }
  return map[field];
}

/**
 * Decode and validate. Refuses rather than defaulting on every field.
 *
 * The one that matters most is `accepted`. Coerced, a truthy string like `"false"` would record a
 * REFUSED proposal as accepted, and the proposer would keep a document, keep publishing into it,
 * and keep delivering to a peer who declined — every update refused at the far end for a reason
 * neither operator can see.
 */
export function decodeDocumentProposalAck(bytes: Uint8Array): DocumentProposalAck {
  const decoded = decodeCbor(bytes);
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
    throw new Error("document_proposal_ack_malformed: not a CBOR map");
  }
  const map = decoded as Record<string, unknown>;

  if (present(map, "type") !== "document_proposal_ack") {
    throw new Error(`document_proposal_ack_type: expected document_proposal_ack`);
  }
  const ackVersion = present(map, "ack_version");
  if (typeof ackVersion !== "number" || !Number.isInteger(ackVersion)) {
    throw new Error("document_proposal_ack_version: must be an integer");
  }
  if (ackVersion !== DOCUMENT_PROPOSAL_ACK_VERSION) {
    // REFUSED BY VALUE, and said out loud. A frame from a future build would otherwise decode
    // cleanly and fail signature verification, sending whoever reads the error to key management.
    throw new Error(
      `document_proposal_ack_version_unsupported: this build speaks version ` +
        `${DOCUMENT_PROPOSAL_ACK_VERSION} and the ack declares ${ackVersion} — the peer is running a ` +
        `newer CELLO and one of you needs to upgrade`,
    );
  }

  const documentId = present(map, "document_id");
  if (typeof documentId !== "string" || !HEX32.test(documentId)) {
    throw new Error("document_proposal_ack_document_id: expected 64 lowercase hex characters");
  }
  const ackerAgentId = present(map, "acker_agent_id");
  if (typeof ackerAgentId !== "string" || ackerAgentId.length === 0) {
    throw new Error("document_proposal_ack_acker: must be a non-empty string");
  }
  const accepted = present(map, "accepted");
  if (typeof accepted !== "boolean") {
    throw new Error("document_proposal_ack_accepted: must be a boolean, never a coerced value");
  }
  const refusalReason = present(map, "refusal_reason");
  if (refusalReason !== null && typeof refusalReason !== "string") {
    throw new Error("document_proposal_ack_reason: must be a string or null");
  }
  const decidedAt = present(map, "decided_at_ms");
  if (typeof decidedAt !== "number" || !Number.isFinite(decidedAt)) {
    throw new Error("document_proposal_ack_decided_at: must be a finite number");
  }
  const signature = present(map, "signature");
  if (!(signature instanceof Uint8Array) || signature.length !== 64) {
    throw new Error("document_proposal_ack_signature: expected 64 bytes");
  }

  const ack: DocumentProposalAck = {
    type: "document_proposal_ack",
    ack_version: ackVersion,
    document_id: documentId,
    acker_agent_id: ackerAgentId,
    accepted,
    ...(refusalReason !== null && refusalReason !== "" ? { refusal_reason: refusalReason } : {}),
    decided_at_ms: decidedAt,
    // COPIED out of the decode buffer. cbor-x returns byte strings as VIEWS into the input, so
    // retaining one pins the whole frame and lets a later reuse of that buffer mutate a signature
    // already verified.
    signature: Uint8Array.from(signature),
  };
  assertDocumentProposalAckConsistent(ack);
  return ack;
}
