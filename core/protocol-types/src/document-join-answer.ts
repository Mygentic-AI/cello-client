/**
 * DOD-MP-JOIN-1 — the invitee's ANSWER to a join offer: a signed, settle-once fact.
 *
 * Keyed on the ADMITTING AMENDMENT'S HASH — the amendment is what the invitee answers, and a
 * re-invitation after a refusal is a new amendment with a new hash, so two answers can never be
 * confused. Its own frame for the proposal-ack reason: a join offer is not in the envelope log,
 * so `document_ack` would settle a hash of nothing.
 *
 * Consent is local and final the moment the operator makes it; sending the answer is
 * best-effort, and an unreachable inviter gets no veto over the invitee's choice — the same
 * doctrine as the proposal ack.
 */

import { createHash } from "node:crypto";
import { encodeCbor, decodeCbor } from "./cbor.js";

/** Domain tag in slot 0 of the to-be-signed array. */
export const DOCUMENT_JOIN_ANSWER_DOMAIN = "CELLO-DOCUMENT-JOIN-ANSWER-v1";

export const MAX_JOIN_REFUSAL_REASON_LENGTH = 512;

export interface DocumentJoinAnswer {
  type: "document_join_answer";
  document_id: string;
  /** Hex hash of the admitting `add_holder` amendment — the settle key. */
  amendment_hash: string;
  invitee_agent_id: string;
  accepted: boolean;
  /** Operator prose on a refusal; explicit null on an accept — never absent. */
  refusal_reason: string | null;
  answered_at_ms: number;
  /** Ed25519 (RFC 8032) by the invitee over `buildDocumentJoinAnswerTbs`. */
  signature: Uint8Array;
}

export function buildDocumentJoinAnswerTbs(
  answer: DocumentJoinAnswer,
  opts: { preHash?: boolean } = {},
): Uint8Array {
  const preimage = encodeCbor([
    DOCUMENT_JOIN_ANSWER_DOMAIN,
    answer.document_id,
    answer.amendment_hash,
    answer.invitee_agent_id,
    answer.accepted,
    answer.refusal_reason,
    typeof answer.answered_at_ms === "number" && answer.answered_at_ms > 0xffffffff
      ? BigInt(answer.answered_at_ms)
      : answer.answered_at_ms,
  ]);
  if (opts.preHash === false) return preimage;
  return new Uint8Array(createHash("sha256").update(preimage).digest());
}

export function encodeDocumentJoinAnswer(answer: DocumentJoinAnswer): Uint8Array {
  return encodeCbor({
    type: answer.type,
    document_id: answer.document_id,
    amendment_hash: answer.amendment_hash,
    invitee_agent_id: answer.invitee_agent_id,
    accepted: answer.accepted,
    refusal_reason: answer.refusal_reason,
    answered_at_ms: answer.answered_at_ms,
    signature: answer.signature,
  });
}

function present(map: Record<string, unknown>, field: string): unknown {
  if (!(field in map)) {
    throw new Error(`document_join_answer_missing_field: ${field} is mandatory and was not present`);
  }
  return map[field];
}

function str(map: Record<string, unknown>, field: string): string {
  const v = present(map, field);
  if (typeof v !== "string" || v.length === 0) {
    throw new Error(`document_join_answer_field_type: ${field} must be a non-empty text string`);
  }
  return v;
}

export function decodeDocumentJoinAnswer(input: Uint8Array): DocumentJoinAnswer {
  const decoded = decodeCbor(input);
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
    throw new Error("document_join_answer_malformed: not a CBOR map");
  }
  const map = decoded as Record<string, unknown>;
  const type = str(map, "type");
  if (type !== "document_join_answer") {
    throw new Error(`document_join_answer_type: expected document_join_answer, got ${type}`);
  }
  const accepted = present(map, "accepted");
  if (typeof accepted !== "boolean") {
    throw new Error(
      "document_join_answer_field_type: accepted must be a boolean — consent is never inferred " +
        "from a truthy value",
    );
  }
  const reason = present(map, "refusal_reason");
  if (reason !== null && typeof reason !== "string") {
    throw new Error(
      "document_join_answer_field_type: refusal_reason must be a text string or explicit null",
    );
  }
  if (typeof reason === "string" && reason.length > MAX_JOIN_REFUSAL_REASON_LENGTH) {
    throw new Error(
      `document_join_answer_field_type: refusal_reason exceeds ${MAX_JOIN_REFUSAL_REASON_LENGTH} chars`,
    );
  }
  const answeredAt = present(map, "answered_at_ms");
  if (typeof answeredAt !== "number" || !Number.isInteger(answeredAt)) {
    throw new Error("document_join_answer_field_type: answered_at_ms must be an integer");
  }
  const signature = present(map, "signature");
  if (!(signature instanceof Uint8Array)) {
    throw new Error("document_join_answer_field_type: signature must be a CBOR byte string");
  }
  return {
    type: "document_join_answer",
    document_id: str(map, "document_id"),
    amendment_hash: str(map, "amendment_hash"),
    invitee_agent_id: str(map, "invitee_agent_id"),
    accepted,
    refusal_reason: reason,
    answered_at_ms: answeredAt,
    signature: new Uint8Array(signature),
  };
}
