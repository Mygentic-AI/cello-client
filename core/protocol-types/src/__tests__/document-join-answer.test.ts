/**
 * DOD-MP-JOIN-1 — the invitee's ANSWER: consent is a signed, settle-once fact.
 *
 * Keyed on the ADMITTING AMENDMENT'S HASH, not on a document alone — the amendment is what the
 * invitee is answering, and a re-invitation after a refusal is a new amendment with a new hash,
 * so the two answers can never be confused. Mirrors the proposal-ack pattern (a join offer is
 * not in the envelope log, so `document_ack` would carry a hash of nothing).
 */
import { describe, it, expect } from "vitest";
import { generateKeyPairSync, sign as edSign, verify as edVerify } from "node:crypto";
import { decodeCbor, encodeCbor } from "../cbor.js";
import {
  DOCUMENT_JOIN_ANSWER_DOMAIN,
  buildDocumentJoinAnswerTbs,
  encodeDocumentJoinAnswer,
  decodeDocumentJoinAnswer,
  type DocumentJoinAnswer,
} from "../index.js";

function makeSigner() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  return {
    agentId: Buffer.from(raw).toString("hex"),
    sign: (tbs: Uint8Array): Uint8Array => new Uint8Array(edSign(null, tbs, privateKey)),
    publicKey,
  };
}

function answer(over: Partial<DocumentJoinAnswer> = {}): DocumentJoinAnswer {
  return {
    type: "document_join_answer",
    document_id: "d".repeat(64),
    amendment_hash: "a".repeat(64),
    invitee_agent_id: "c".repeat(64),
    accepted: true,
    refusal_reason: null,
    answered_at_ms: 1_700_000_000_000,
    signature: new Uint8Array(64).fill(3),
    ...over,
  };
}

describe("join answer — TBS and round-trip", () => {
  it("the TBS is a CBOR array with the domain in slot 0, and every agreed field moves it", () => {
    const arr = decodeCbor(buildDocumentJoinAnswerTbs(answer(), { preHash: false })) as unknown[];
    expect(arr[0]).toBe(DOCUMENT_JOIN_ANSWER_DOMAIN);
    const base = buildDocumentJoinAnswerTbs(answer());
    expect(buildDocumentJoinAnswerTbs(answer({ accepted: false, refusal_reason: "no" }))).not.toEqual(base);
    expect(buildDocumentJoinAnswerTbs(answer({ amendment_hash: "b".repeat(64) }))).not.toEqual(base);
    expect(buildDocumentJoinAnswerTbs(answer({ invitee_agent_id: "e".repeat(64) }))).not.toEqual(base);
  });

  it("a REAL signature round-trips and verifies against the invitee", () => {
    const c = makeSigner();
    const a = answer({ invitee_agent_id: c.agentId, signature: new Uint8Array(0) });
    a.signature = c.sign(buildDocumentJoinAnswerTbs(a));
    const decoded = decodeDocumentJoinAnswer(encodeDocumentJoinAnswer(a));
    expect(decoded).toEqual(a);
    expect(edVerify(null, buildDocumentJoinAnswerTbs(decoded), c.publicKey, decoded.signature)).toBe(true);
  });

  it("a refusal carries its reason; an accept carries explicit null — never an absent field", () => {
    const refused = answer({ accepted: false, refusal_reason: "not joining this one" });
    expect(decodeDocumentJoinAnswer(encodeDocumentJoinAnswer(refused)).refusal_reason).toBe(
      "not joining this one",
    );
    const wire = decodeCbor(encodeDocumentJoinAnswer(answer())) as Record<string, unknown>;
    expect("refusal_reason" in wire).toBe(true);
    expect(wire["refusal_reason"]).toBeNull();
  });

  it.each([
    ["amendment_hash", /document_join_answer_missing_field: amendment_hash/],
    ["accepted", /document_join_answer_missing_field: accepted/],
    ["refusal_reason", /document_join_answer_missing_field: refusal_reason/],
    ["signature", /document_join_answer_missing_field: signature/],
  ] as const)("decode refuses a missing %s with the NAMED code", (field, expected) => {
    const wire = decodeCbor(encodeDocumentJoinAnswer(answer())) as Record<string, unknown>;
    delete wire[field];
    expect(() => decodeDocumentJoinAnswer(encodeCbor(wire))).toThrow(expected);
  });

  it("refuses a non-boolean accepted rather than coercing — consent is never inferred", () => {
    const wire = decodeCbor(encodeDocumentJoinAnswer(answer())) as Record<string, unknown>;
    wire["accepted"] = "yes";
    expect(() => decodeDocumentJoinAnswer(encodeCbor(wire))).toThrow(
      /document_join_answer_field_type: accepted/,
    );
  });
});
