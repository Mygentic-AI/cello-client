/**
 * DOD-DOC-TOOLS-1 — the document control frame (close / kill).
 *
 * The frame that tells the other party a document has ended. Without it, `notifyPeer` had nothing to
 * send: `withdraw`, `close` and `kill` all refused with `document_peer_notify_not_wired`, and a peer
 * never told keeps publishing into a document that will never answer.
 */

import { describe, it, expect } from "vitest";
import {
  encodeDocumentControl,
  decodeDocumentControl,
  buildDocumentControlTbs,
  DOCUMENT_CONTROL_DOMAIN,
  DOCUMENT_CONTROL_VERSION,
  DOCUMENT_CONTROL_VERBS,
  MAX_CONTROL_REASON_LENGTH,
  decodeCbor,
  encodeCbor,
  type DocumentControl,
} from "../index.js";

const DOC = "cc".repeat(32);
const SENDER = "aa".repeat(32);
const NOW = 1_700_000_000_000;

function control(over: Partial<DocumentControl> = {}): DocumentControl {
  return {
    type: "document_control",
    control_version: DOCUMENT_CONTROL_VERSION,
    document_id: DOC,
    sender_agent_id: SENDER,
    verb: "kill",
    sent_at_ms: NOW,
    signature: new Uint8Array(64).fill(3),
    ...over,
  };
}

describe("document control — round trip", () => {
  it("survives encode/decode for BOTH verbs", () => {
    for (const verb of DOCUMENT_CONTROL_VERBS) {
      const original = control({ verb });
      expect(decodeDocumentControl(encodeDocumentControl(original))).toEqual(original);
    }
  });

  it("carries an optional reason, and normalises an empty one to absent", () => {
    expect(decodeDocumentControl(encodeDocumentControl(control({ reason: "moving to a doc" })))).toMatchObject({
      reason: "moving to a doc",
    });
    // "" is not a reason; carried through it renders as an explanation that is a blank line.
    expect("reason" in decodeDocumentControl(encodeDocumentControl(control({ reason: "" })))).toBe(false);
  });

  it("COPIES the signature out of the decode buffer", () => {
    const bytes = encodeDocumentControl(control());
    const back = decodeDocumentControl(bytes);
    // cbor-x returns byte strings as VIEWS into the input; retaining one lets a later reuse of that
    // buffer mutate a signature already verified.
    bytes.fill(0);
    expect(back.signature.every((b) => b === 3)).toBe(true);
  });
});

describe("the preimage binds the VERB", () => {
  it("puts the domain first and the verb in its own slot", () => {
    const preimage = decodeCbor(buildDocumentControlTbs(control(), { preHash: false })) as unknown[];
    expect(preimage[0]).toBe(DOCUMENT_CONTROL_DOMAIN);
    expect(preimage[2]).toBe(DOC);
    expect(preimage[4]).toBe("kill");
    expect(preimage[5]).toBeNull();
    expect(preimage).toHaveLength(7);
  });

  it("close and kill are DIFFERENT preimages", () => {
    // Unsigned, a captured `close` could be replayed as a `kill` — the peer would end a
    // collaboration the sender only meant to wind down, with a valid signature on it.
    const close = buildDocumentControlTbs(control({ verb: "close" }));
    const kill = buildDocumentControlTbs(control({ verb: "kill" }));
    expect(Buffer.from(close).equals(Buffer.from(kill))).toBe(false);
  });

  it("a DIFFERENT DOCUMENT is a different preimage", () => {
    const a = buildDocumentControlTbs(control());
    const b = buildDocumentControlTbs(control({ document_id: "dd".repeat(32) }));
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it("encodes the timestamp as a BIGINT past 0xffffffff", () => {
    const preimage = decodeCbor(buildDocumentControlTbs(control(), { preHash: false })) as unknown[];
    expect(preimage[6]).toBe(BigInt(NOW));
  });
});

describe("decode refuses rather than defaulting", () => {
  it("REFUSES an unknown verb by VALUE", () => {
    const map = decodeCbor(encodeDocumentControl(control())) as Record<string, unknown>;
    // A third verb from a future build must not be admitted as one of these two. A `kill` read as a
    // `close` leaves a killed document waiting for a reciprocal close that is never coming.
    expect(() => decodeDocumentControl(encodeCbor({ ...map, verb: "archive" }))).toThrow(
      /newer CELLO/,
    );
  });

  it("names a VERSION mismatch as a version mismatch", () => {
    const map = decodeCbor(encodeDocumentControl(control())) as Record<string, unknown>;
    // Otherwise a future frame decodes cleanly and fails SIGNATURE verification, sending whoever
    // reads the error to key management for a skew bug.
    expect(() => decodeDocumentControl(encodeCbor({ ...map, control_version: 2 }))).toThrow(/newer CELLO/);
  });

  it("refuses a missing field rather than substituting one", () => {
    const map = decodeCbor(encodeDocumentControl(control())) as Record<string, unknown>;
    for (const field of ["document_id", "sender_agent_id", "verb", "sent_at_ms", "signature"]) {
      const without = { ...map };
      delete without[field];
      expect(() => decodeDocumentControl(encodeCbor(without)), field).toThrow(/mandatory/);
    }
  });

  it("refuses a short signature and a non-map frame", () => {
    const map = decodeCbor(encodeDocumentControl(control())) as Record<string, unknown>;
    expect(() => decodeDocumentControl(encodeCbor({ ...map, signature: new Uint8Array(10) }))).toThrow(/64 bytes/);
    expect(() => decodeDocumentControl(encodeCbor([1, 2]))).toThrow(/not a CBOR map/);
  });

  it("caps peer-controlled display text on ENCODE, so it never leaves the machine", () => {
    const long = "x".repeat(MAX_CONTROL_REASON_LENGTH + 1);
    expect(() => encodeDocumentControl(control({ reason: long }))).toThrow(/at most 200/);
  });
});
