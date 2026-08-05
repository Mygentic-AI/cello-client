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
    ack_version: 1,
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

  it("distinguishes one rejection reason from another", () => {
    expect(Buffer.from(buildDocumentAckTbs(rejection("a"))).toString("hex")).not.toBe(
      Buffer.from(buildDocumentAckTbs(rejection("b"))).toString("hex"),
    );
  });

  it("keeps the reason SLOT occupied whether or not there is a reason", () => {
    // The earlier version of this test was named for this rule and compared two rejections that
    // BOTH carried a reason — so it never exercised the absent case at all, and a builder that
    // omitted the slot would have kept it green.
    const admission = decodeCbor(
      buildDocumentAckTbs(ack(), { preHash: false }),
    ) as unknown[];
    const refusal = decodeCbor(
      buildDocumentAckTbs(rejection("x"), { preHash: false }),
    ) as unknown[];
    expect(admission).toHaveLength(refusal.length);
    expect(admission[6]).toBeNull();
    expect(refusal[6]).toBe("x");
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
      ack_version: a.ack_version,
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


describe("document ack — the FROZEN vector", () => {
  /**
   * The conformance artifact, matching the convention both sibling envelopes already follow. Every
   * other TBS test here is DIFFERENTIAL — "these two differ" — which structurally cannot catch a
   * reordering: swap two slots, or change the domain string, and the whole suite stays green while
   * every ack any deployed peer ever signed becomes unverifiable, surfacing as "bad signature" on a
   * frame that is fine.
   *
   * If this fails, the wire changed. Decide that deliberately and reissue the vector; never edit it
   * to match new output.
   */
  const FROZEN_ADMISSION: DocumentAck = {
    type: "document_ack",
    ack_version: 1,
    document_id: "00".repeat(31) + "01",
    envelope_hash: "00".repeat(31) + "02",
    acker_agent_id: "vector-acker",
    admitted: true,
    acked_at_ms: 1_700_000_000_000,
    signature: new Uint8Array(64).fill(0xef),
  };
  const FROZEN_REJECTION: DocumentAck = {
    ...FROZEN_ADMISSION,
    admitted: false,
    rejection_reason: "document_append_only_violation",
  };

  it("an ADMISSION preimage is byte-for-byte what it was the day it was frozen", () => {
    expect(Buffer.from(buildDocumentAckTbs(FROZEN_ADMISSION, { preHash: false })).toString("hex")).toBe(
      "887543454c4c4f2d444f43554d454e542d41434b2d7631017840303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030317840303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030326c766563746f722d61636b6572f5f61b0000018bcfe56800",
    );
  });

  it("a REJECTION preimage is byte-for-byte what it was the day it was frozen", () => {
    expect(Buffer.from(buildDocumentAckTbs(FROZEN_REJECTION, { preHash: false })).toString("hex")).toBe(
      "887543454c4c4f2d444f43554d454e542d41434b2d7631017840303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030317840303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030326c766563746f722d61636b6572f4781e646f63756d656e745f617070656e645f6f6e6c795f76696f6c6174696f6e1b0000018bcfe56800",
    );
  });

  it("the timestamp is a uint64, not an IEEE float64", () => {
    const hex = Buffer.from(buildDocumentAckTbs(FROZEN_ADMISSION, { preHash: false })).toString("hex");
    // cbor-x encodes a JS number past 0xffffffff as fb (float64). A millisecond timestamp is always
    // that large, so without the bigint coercion any RFC 8949-canonical implementation computes
    // different TBS bytes and rejects a GENUINE ack — which reads as forgery.
    expect(hex).toContain("1b0000018bcfe56800");
    expect(hex).not.toContain("fb4278bcfe56800000");
  });
});

describe("document ack — an honest peer's EMPTY-STRING reason is not a contradiction", () => {
  it("treats an empty rejection_reason on an admission as ABSENT", () => {
    const raw = encodeCbor({
      type: "document_ack",
      ack_version: 1,
      document_id: DOC,
      envelope_hash: ENV,
      acker_agent_id: "agent-b",
      admitted: true,
      rejection_reason: "",
      acked_at_ms: 1_700_000_000_000,
      signature: new Uint8Array(64),
    });
    // Go and Rust default a non-nullable string field to "". Refusing this as a contradiction it
    // never expressed meant the sender never settled, retried to the unacked ceiling, and the
    // document stalled — precisely the failure this frame exists to end.
    expect(() => decodeDocumentAck(raw)).not.toThrow();
    expect(decodeDocumentAck(raw).rejection_reason).toBeUndefined();
  });

  it("still refuses a rejection whose reason is empty", () => {
    const raw = encodeCbor({
      type: "document_ack",
      ack_version: 1,
      document_id: DOC,
      envelope_hash: ENV,
      acker_agent_id: "agent-b",
      admitted: false,
      rejection_reason: "",
      acked_at_ms: 1_700_000_000_000,
      signature: new Uint8Array(64),
    });
    expect(() => decodeDocumentAck(raw)).toThrow(/a rejection must carry its reason/);
  });
});

describe("document ack — a version skew is NAMED, not left to fail as a bad signature", () => {
  it("refuses a future ack version and says which side must upgrade", () => {
    const map = decodeCbor(encodeDocumentAck(ack())) as Record<string, unknown>;
    map.ack_version = 2;
    let caught = "";
    try {
      decodeDocumentAck(encodeCbor(map));
    } catch (e) {
      caught = (e as Error).message;
    }
    // Without a wire version the frame decoded cleanly and failed SIGNATURE verification, sending
    // an operator to key management for a version problem.
    expect(caught).toMatch(/document_ack_version/);
    expect(caught).toContain("upgrading");
  });
});

describe("document ack — the ENCODER applies the same cross-field rules as the decoder", () => {
  it("refuses to encode a contradictory ack locally, rather than shipping it", () => {
    // Otherwise the sender signs and ships it and it fails only on the remote decode: the sender
    // sees a silent stall, the peer sees the error, and the two never meet.
    expect(() => encodeDocumentAck(ack({ rejection_reason: "why" }))).toThrow(
      /must not carry a rejection reason/,
    );
  });

  it("refuses an over-long rejection reason", () => {
    expect(() =>
      encodeDocumentAck(ack({ admitted: false, rejection_reason: "x".repeat(500) })),
    ).toThrow(/at most/);
  });
});
