/**
 * DOD-DOC-TOOLS-1 — the proposal ack wire type.
 *
 * The frame that tells the proposer what was decided. Before it, `cello_doc_list` inferred consent
 * from "the peer has published into it", which conflates refused, never-received, and
 * accepted-but-untouched — two of which want the operator to act and one of which does not.
 */

import { describe, it, expect } from "vitest";
import {
  encodeDocumentProposalAck,
  decodeDocumentProposalAck,
  buildDocumentProposalAckTbs,
  assertDocumentProposalAckConsistent,
  DOCUMENT_PROPOSAL_ACK_DOMAIN,
  DOCUMENT_PROPOSAL_ACK_VERSION,
  MAX_PROPOSAL_REFUSAL_REASON_LENGTH,
  decodeCbor,
  encodeCbor,
  type DocumentProposalAck,
} from "../index.js";

const DOC = "cc".repeat(32);
const ACKER = "aa".repeat(32);
const NOW = 1_700_000_000_000;

function ack(over: Partial<DocumentProposalAck> = {}): DocumentProposalAck {
  return {
    type: "document_proposal_ack",
    ack_version: DOCUMENT_PROPOSAL_ACK_VERSION,
    document_id: DOC,
    acker_agent_id: ACKER,
    accepted: true,
    decided_at_ms: NOW,
    signature: new Uint8Array(64).fill(7),
    ...over,
  };
}

describe("document proposal ack — round trip", () => {
  it("survives encode/decode with every field intact", () => {
    const original = ack();
    expect(decodeDocumentProposalAck(encodeDocumentProposalAck(original))).toEqual(original);
  });

  it("carries a refusal and its reason", () => {
    const refused = ack({ accepted: false, refusal_reason: "not right now" });
    const back = decodeDocumentProposalAck(encodeDocumentProposalAck(refused));
    expect(back).toMatchObject({ accepted: false, refusal_reason: "not right now" });
  });

  it("normalises an EMPTY reason to absent rather than carrying a lie", () => {
    // "" is not a reason. Carried through, it would render as a refusal whose explanation is a
    // blank line, which reads as a bug in the sender rather than as silence.
    const back = decodeDocumentProposalAck(encodeDocumentProposalAck(ack({ refusal_reason: "" })));
    expect("refusal_reason" in back).toBe(false);
  });

  it("COPIES the signature out of the decode buffer", () => {
    const bytes = encodeDocumentProposalAck(ack());
    const back = decodeDocumentProposalAck(bytes);
    // cbor-x returns byte strings as VIEWS into the input. Retaining one pins the whole frame and
    // lets a later reuse of that buffer mutate a signature already verified.
    bytes.fill(0);
    expect(back.signature.every((b) => b === 7)).toBe(true);
  });
});

describe("the preimage is a fixed-order ARRAY with the domain in slot 0", () => {
  it("puts the domain first and the decision in its own slot", () => {
    const preimage = decodeCbor(buildDocumentProposalAckTbs(ack(), { preHash: false })) as unknown[];
    expect(preimage[0]).toBe(DOCUMENT_PROPOSAL_ACK_DOMAIN);
    expect(preimage[1]).toBe(DOCUMENT_PROPOSAL_ACK_VERSION);
    expect(preimage[2]).toBe(DOC);
    expect(preimage[3]).toBe(ACKER);
    expect(preimage[4]).toBe(true);
    // The absent reason OCCUPIES its slot, so no field's meaning depends on whether the one before
    // it was present.
    expect(preimage[5]).toBeNull();
    expect(preimage).toHaveLength(7);
  });

  it("encodes the timestamp as a BIGINT past 0xffffffff", () => {
    // cbor-x encodes a large JS number as IEEE float64 (`fb`), not uint64 (`1b`). A millisecond
    // timestamp is always that large, so an implementation encoding RFC 8949-canonically would
    // compute different TBS bytes and reject a GENUINE ack — surfacing as a signature failure,
    // which reads as forgery.
    const preimage = decodeCbor(buildDocumentProposalAckTbs(ack(), { preHash: false })) as unknown[];
    expect(typeof preimage[6]).toBe("bigint");
    expect(preimage[6]).toBe(BigInt(NOW));
  });

  it("a DIFFERENT DECISION is a different preimage", () => {
    // The signature covers the whole statement. If it did not cover `accepted`, a captured
    // acceptance could be flipped to a refusal and the proposer would tear down a live document.
    const yes = buildDocumentProposalAckTbs(ack());
    const no = buildDocumentProposalAckTbs(ack({ accepted: false, refusal_reason: "no" }));
    expect(Buffer.from(yes).equals(Buffer.from(no))).toBe(false);
  });

  it("a DIFFERENT DOCUMENT is a different preimage", () => {
    // Otherwise an ack could be lifted onto another proposal from the same peer.
    const a = buildDocumentProposalAckTbs(ack());
    const b = buildDocumentProposalAckTbs(ack({ document_id: "dd".repeat(32) }));
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });
});

describe("contradictions are refused where the object is BUILT, not only where it is read", () => {
  it("refuses a refusal with no reason", () => {
    // Without it the proposer cannot know what to change — the failure that makes people abandon a
    // protocol rather than adjust to it.
    expect(() => assertDocumentProposalAckConsistent(ack({ accepted: false }))).toThrow(
      /must carry its reason/,
    );
    expect(() => encodeDocumentProposalAck(ack({ accepted: false }))).toThrow();
  });

  it("refuses an acceptance carrying a refusal reason", () => {
    // Whichever field a reader trusts, the other is lying to them.
    expect(() => encodeDocumentProposalAck(ack({ accepted: true, refusal_reason: "why" }))).toThrow(
      /must not carry a refusal reason/,
    );
  });

  it("caps peer-controlled display text", () => {
    const long = "x".repeat(MAX_PROPOSAL_REFUSAL_REASON_LENGTH + 1);
    expect(() => encodeDocumentProposalAck(ack({ accepted: false, refusal_reason: long }))).toThrow(
      /at most 200/,
    );
  });

  it("checked on ENCODE, so a contradictory ack never leaves the machine", () => {
    // Otherwise it is signed and shipped and fails only at the remote decode: the acker sees
    // success, the proposer sees an error, and the two never meet.
    expect(() => buildDocumentProposalAckTbs(ack({ accepted: false }))).toThrow();
  });
});

describe("decode refuses rather than defaulting", () => {
  it("REFUSES a coerced `accepted`", () => {
    const bytes = encodeDocumentProposalAck(ack());
    const map = decodeCbor(bytes) as Record<string, unknown>;
    // A truthy string would record a REFUSED proposal as accepted: the proposer keeps the document,
    // keeps publishing, and keeps delivering to a peer who declined — every update refused at the
    // far end for a reason neither operator can see.
    expect(() => decodeDocumentProposalAck(encodeCbor({ ...map, accepted: "false" }))).toThrow(
      /must be a boolean/,
    );
  });

  it("names a VERSION mismatch as a version mismatch", () => {
    const map = decodeCbor(encodeDocumentProposalAck(ack())) as Record<string, unknown>;
    // Refused by value. Otherwise a future build's frame decodes cleanly and fails SIGNATURE
    // verification, sending whoever reads the error to key management for a skew bug.
    expect(() => decodeDocumentProposalAck(encodeCbor({ ...map, ack_version: 2 }))).toThrow(
      /newer CELLO/,
    );
  });

  it("refuses a missing field rather than substituting one", () => {
    const map = decodeCbor(encodeDocumentProposalAck(ack())) as Record<string, unknown>;
    for (const field of ["document_id", "acker_agent_id", "accepted", "decided_at_ms", "signature"]) {
      const without = { ...map };
      delete without[field];
      // A defaulted field is a claim the acker never made, and carrying their claim is the frame's
      // entire job.
      expect(() => decodeDocumentProposalAck(encodeCbor(without)), field).toThrow(/mandatory/);
    }
  });

  it("refuses a short signature", () => {
    const map = decodeCbor(encodeDocumentProposalAck(ack())) as Record<string, unknown>;
    expect(() => decodeDocumentProposalAck(encodeCbor({ ...map, signature: new Uint8Array(32) }))).toThrow(
      /64 bytes/,
    );
  });

  it("refuses a non-map frame", () => {
    expect(() => decodeDocumentProposalAck(encodeCbor([1, 2, 3]))).toThrow(/not a CBOR map/);
  });

  it("a DIFFERENT ACKER AGENT ID is a different preimage", () => {
    // The identity slot was UNPINNED: delete it from the TBS array and every other test in this
    // file still passed. Not exploitable today, because the verify key is derived from that same
    // field — but the binding is what makes that derivation safe, and a captured ack could
    // otherwise be re-signed by another party and presented as theirs.
    const mine = buildDocumentProposalAckTbs(ack());
    const theirs = buildDocumentProposalAckTbs(ack({ acker_agent_id: "ff".repeat(32) }));
    expect(Buffer.from(mine).equals(Buffer.from(theirs))).toBe(false);
  });
});
