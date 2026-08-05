/**
 * DOD-DOC-INBOUND-2 — the document ACK, the frame that closes DELIVERY-2's loop.
 *
 * An ack settles an envelope permanently: it stops being redelivered, and if the ack says rejected
 * the sender rolls back local work. Every refusal below exists because the alternative is one of
 * those two consequences happening on a claim nobody made.
 */

import { describe, it, expect } from "vitest";
import { encodeCbor, decodeCbor } from "../cbor.js";
import {
  DOCUMENT_ACK_DOMAIN,
  buildDocumentAckTbs,
  encodeDocumentAck,
  decodeDocumentAck,
  type DocumentAck,
} from "../document-ack.js";

const DOC = "aa".repeat(32);
const ENV = "bb".repeat(32);

function ack(over: Partial<DocumentAck> = {}): DocumentAck {
  return {
    type: "document_ack",
    document_id: DOC,
    envelope_hash: ENV,
    acker_agent_id: "agent-b",
    admitted: true,
    acked_at_ms: 1_700_000_000_000,
    signature: new Uint8Array(64).fill(4),
    ...over,
  };
}

const rejection = (reason = "document_append_only_violation") =>
  ack({ admitted: false, rejection_reason: reason });

describe("document ack — CBOR round-trip", () => {
  it("round-trips an admission", () => {
    expect(decodeDocumentAck(encodeDocumentAck(ack()))).toEqual(ack());
  });

  it("round-trips a rejection with its reason", () => {
    expect(decodeDocumentAck(encodeDocumentAck(rejection()))).toEqual(rejection());
  });

  it("copies the signature out of the wire rather than aliasing it", () => {
    const wire = encodeDocumentAck(ack());
    const decoded = decodeDocumentAck(wire);
    wire.fill(0);
    expect(Array.from(decoded.signature)).toEqual(Array.from(new Uint8Array(64).fill(4)));
  });
});

describe("document ack — the decoder refuses rather than defaulting", () => {
  const raw = (o: Record<string, unknown>): Uint8Array => encodeCbor(o);
  const asMap = (a: DocumentAck): Record<string, unknown> =>
    decodeCbor(encodeDocumentAck(a)) as Record<string, unknown>;

  it("refuses a NON-BOOLEAN admitted rather than coercing it", () => {
    const map = asMap(rejection());
    map.admitted = "false";
    // The string "false" is truthy. Coerced, a REJECTED envelope would settle as admitted: the
    // sender stops retrying, never rolls back, and both parties believe content was applied that
    // the receiver refused.
    expect(() => decodeDocumentAck(raw(map))).toThrow(/document_ack_admitted/);
  });

  it("refuses an absent admitted — there is no default answer", () => {
    const map = asMap(ack());
    delete map.admitted;
    expect(() => decodeDocumentAck(raw(map))).toThrow(/document_ack_missing_field.*admitted/);
  });

  it("refuses a REJECTION with no reason", () => {
    const map = asMap(rejection());
    map.rejection_reason = null;
    // The sender is being told to stop and supersede. Without the reason it cannot know what to
    // change — which is the failure the whole rejection protocol exists to prevent.
    expect(() => decodeDocumentAck(raw(map))).toThrow(/a rejection must carry its reason/);
  });

  it("refuses a rejection whose reason is an empty string", () => {
    const map = asMap(rejection());
    map.rejection_reason = "";
    expect(() => decodeDocumentAck(raw(map))).toThrow(/a rejection must carry its reason/);
  });

  it("refuses an ADMISSION that carries a rejection reason", () => {
    const map = asMap(ack());
    map.rejection_reason = "document_append_only_violation";
    // A contradiction: whichever field a reader trusts, the other one is lying to them.
    expect(() => decodeDocumentAck(raw(map))).toThrow(/must not carry a rejection reason/);
  });

  it("refuses a malformed document id or envelope hash", () => {
    for (const field of ["document_id", "envelope_hash"]) {
      const map = asMap(ack());
      map[field] = "nope";
      expect(() => decodeDocumentAck(raw(map))).toThrow(new RegExp(field));
    }
  });

  it("refuses an empty acker", () => {
    const map = asMap(ack());
    map.acker_agent_id = "";
    expect(() => decodeDocumentAck(raw(map))).toThrow(/document_ack_acker/);
  });
});

describe("document ack — the signature covers the whole claim", () => {
  const tbs = (over: Partial<DocumentAck> = {}) =>
    Buffer.from(buildDocumentAckTbs(ack(over))).toString("hex");

  it("is an ARRAY with the domain in slot 0", () => {
    const arr = decodeCbor(buildDocumentAckTbs(ack(), { preHash: false })) as unknown[];
    expect(Array.isArray(arr)).toBe(true);
    expect(arr[0]).toBe(DOCUMENT_ACK_DOMAIN);
  });

  it("binds the ENVELOPE, so an ack cannot be moved to a different one", () => {
    // Otherwise a captured ack settles whichever envelope an attacker replays it against — and a
    // settled envelope stops being redelivered.
    expect(tbs({ envelope_hash: "cc".repeat(32) })).not.toBe(tbs());
  });

  it("binds the DOCUMENT, so it cannot be moved to a different one", () => {
    expect(tbs({ document_id: "cc".repeat(32) })).not.toBe(tbs());
  });

  it("binds the VERDICT, the acker and the time", () => {
    expect(
      Buffer.from(buildDocumentAckTbs(rejection())).toString("hex"),
    ).not.toBe(tbs());
    expect(tbs({ acker_agent_id: "someone-else" })).not.toBe(tbs());
    expect(tbs({ acked_at_ms: 1 })).not.toBe(tbs());
  });

  it("distinguishes a rejection reason from NO reason", () => {
    const withReason = Buffer.from(buildDocumentAckTbs(rejection("a"))).toString("hex");
    const otherReason = Buffer.from(buildDocumentAckTbs(rejection("b"))).toString("hex");
    // Encoded as explicit null when absent rather than omitted: omitting shortens the array, which
    // is a shape change the next field silently absorbs.
    expect(withReason).not.toBe(otherReason);
  });

  it("does NOT cover its own signature", () => {
    expect(tbs({ signature: new Uint8Array(64).fill(9) })).toBe(tbs());
  });

  it("is stable across field insertion order", () => {
    const a = ack();
    const b: DocumentAck = {
      signature: a.signature,
      acked_at_ms: a.acked_at_ms,
      admitted: a.admitted,
      acker_agent_id: a.acker_agent_id,
      envelope_hash: a.envelope_hash,
      document_id: a.document_id,
      type: a.type,
    };
    // A map preimage would make the signature depend on the order the acker built the object in,
    // and two honest implementations would disagree.
    expect(buildDocumentAckTbs(b)).toEqual(buildDocumentAckTbs(a));
  });

  it("cannot be confused with an UPDATE or a PROPOSAL preimage", () => {
    const arr = decodeCbor(buildDocumentAckTbs(ack(), { preHash: false })) as unknown[];
    expect(arr[0]).not.toBe("CELLO-DOCUMENT-UPDATE-v1");
    expect(arr[0]).not.toBe("CELLO-DOCUMENT-PROPOSAL-v1");
  });
});
