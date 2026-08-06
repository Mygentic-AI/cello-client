/**
 * DOD-DOC-REJECT-2 — the rejection's signed preimage.
 *
 * A `0x05` leaf has carried a signature since REJECT-1 and nothing defined what it was over, so the
 * field could only be filled dishonestly. Every binding below exists because a rejection is a claim
 * with consequences for the other party: they stop retrying, roll back local work, and supersede.
 */

import { describe, it, expect } from "vitest";
import { encodeCbor, decodeCbor } from "../cbor.js";
import {
  DOCUMENT_REJECTION_DOMAIN,
  buildDocumentRejectionTbs,
  documentRejectionHash,
  encodeDocumentRejection,
  decodeDocumentRejection,
  type DocumentRejectionEnvelope,
} from "../document-rejection-envelope.js";

const DOC = "aa".repeat(32);
const ENV = "bb".repeat(32);

function rejection(over: Partial<DocumentRejectionEnvelope> = {}): DocumentRejectionEnvelope {
  return {
    type: "document_rejection",
    rejection_version: 1,
    document_id: DOC,
    rejected_envelope_hash: ENV,
    rejecting_agent_id: "agent-b",
    reason: "document_append_only_violation",
    round: 1,
    rejected_at_ms: 1_700_000_000_000,
    signature: new Uint8Array(64).fill(6),
    ...over,
  };
}

describe("document rejection — round-trip and refusals", () => {
  it("round-trips with and without detail", () => {
    expect(decodeDocumentRejection(encodeDocumentRejection(rejection()))).toEqual(rejection());
    const withDetail = rejection({ detail: "the update deletes 12 existing ranges" });
    expect(decodeDocumentRejection(encodeDocumentRejection(withDetail))).toEqual(withDetail);
  });

  it("refuses a rejection with no reason", () => {
    // The sender is being told to stop and supersede; without the reason it cannot know what to
    // change, which is the failure the whole rejection protocol exists to prevent.
    expect(() => encodeDocumentRejection(rejection({ reason: "" }))).toThrow(/must carry its reason/);
  });

  it("refuses a non-positive round", () => {
    for (const bad of [0, -1, 1.5]) {
      expect(() => encodeDocumentRejection(rejection({ round: bad }))).toThrow(/round/);
    }
  });

  it("treats an EMPTY detail as absent, not as a refusal", () => {
    const map = decodeCbor(encodeDocumentRejection(rejection())) as Record<string, unknown>;
    map.detail = "";
    // A peer in a language where a non-nullable string defaults to "" must not be refused for a
    // field it never filled in — the same normalisation the ack needed.
    expect(decodeDocumentRejection(encodeCbor(map)).detail).toBeUndefined();
  });

  it("refuses a version skew by name rather than as a signature failure", () => {
    const map = decodeCbor(encodeDocumentRejection(rejection())) as Record<string, unknown>;
    map.rejection_version = 2;
    expect(() => decodeDocumentRejection(encodeCbor(map))).toThrow(/upgrading/);
  });
});

describe("document rejection — the signature binds every consequence", () => {
  const tbs = (over: Partial<DocumentRejectionEnvelope> = {}) =>
    Buffer.from(buildDocumentRejectionTbs(rejection(over))).toString("hex");

  it("is an ARRAY with its own domain in slot 0", () => {
    const arr = decodeCbor(buildDocumentRejectionTbs(rejection(), { preHash: false })) as unknown[];
    expect(arr[0]).toBe(DOCUMENT_REJECTION_DOMAIN);
    // Not the ack's domain: an ack answers "did you take it" and settles delivery; a rejection is a
    // §3.2 protocol act that goes in the log and carries a retry round. One type for both would
    // need a mode flag, and a mode flag on a signed structure is how a signature over one meaning
    // gets read as the other.
    expect(arr[0]).not.toBe("CELLO-DOCUMENT-ACK-v1");
  });

  it("binds the document and the rejected envelope", () => {
    expect(tbs({ document_id: "cc".repeat(32) })).not.toBe(tbs());
    expect(tbs({ rejected_envelope_hash: "cc".repeat(32) })).not.toBe(tbs());
  });

  it("binds the REASON, which the sender acts on", () => {
    expect(tbs({ reason: "document_update_too_large" })).not.toBe(tbs());
    expect(tbs({ detail: "extra" })).not.toBe(tbs());
  });

  it("binds the ROUND, so a replay cannot drive a document to stalled", () => {
    // Unbound, a captured round-1 rejection replayed twice more reaches the stall threshold without
    // the rejecting party ever having refused again.
    expect(tbs({ round: 2 })).not.toBe(tbs());
    expect(tbs({ round: 3 })).not.toBe(tbs());
  });

  it("binds WHO refused, and when", () => {
    expect(tbs({ rejecting_agent_id: "someone-else" })).not.toBe(tbs());
    expect(tbs({ rejected_at_ms: 1_700_000_000_001 })).not.toBe(tbs());
  });

  it("does not cover its own signature", () => {
    expect(tbs({ signature: new Uint8Array(64).fill(9) })).toBe(tbs());
  });

  it("is stable across field insertion order", () => {
    const a = rejection();
    const b: DocumentRejectionEnvelope = {
      signature: a.signature,
      rejected_at_ms: a.rejected_at_ms,
      round: a.round,
      reason: a.reason,
      rejecting_agent_id: a.rejecting_agent_id,
      rejected_envelope_hash: a.rejected_envelope_hash,
      document_id: a.document_id,
      rejection_version: a.rejection_version,
      type: a.type,
    };
    expect(buildDocumentRejectionTbs(b)).toEqual(buildDocumentRejectionTbs(a));
  });
});

describe("document rejection — the FROZEN vector", () => {
  const FROZEN: DocumentRejectionEnvelope = {
    type: "document_rejection",
    rejection_version: 1,
    document_id: "00".repeat(31) + "01",
    rejected_envelope_hash: "00".repeat(31) + "02",
    rejecting_agent_id: "vector-rejecter",
    reason: "document_append_only_violation",
    round: 2,
    rejected_at_ms: 1_700_000_000_000,
    signature: new Uint8Array(64).fill(0xab),
  };

  it("the leaf hash is byte-for-byte what it was the day it was frozen", () => {
    // Every other TBS test here is differential — "these two differ" — which structurally cannot
    // catch a reordering. Only a frozen vector proves the fields are where they were.
    expect(documentRejectionHash(FROZEN)).toBe("2e0ffc6fb2b3922b48e5b4764e95287a130c0265e13adda0f0e29e33425ac9cf");
  });

  it("the timestamp is a uint64, not an IEEE float64", () => {
    const hex = Buffer.from(buildDocumentRejectionTbs(FROZEN, { preHash: false })).toString("hex");
    // Measured on the ack: without the coercion a millisecond timestamp encodes as fb..., and any
    // implementation encoding canonically computes different TBS bytes and rejects a GENUINE
    // rejection — which reads as forgery.
    expect(hex).toContain("1b0000018bcfe56800");
  });
});
