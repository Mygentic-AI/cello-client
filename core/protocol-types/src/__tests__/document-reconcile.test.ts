/**
 * SYNC-P3 (R10–R16) — the reconcile frame: ONE wire shape for all three exchange steps.
 *
 * Step 1 carries positions + refusal sets; step 2 carries the same plus the entries the peer
 * lacks; step 3 carries entries alone. Because the shape is one, a lost reply degrades to a
 * fresh exchange — there is no half-open protocol state to wedge.
 *
 * The frame is NOT signed: it rides an authenticated session, and a position is advisory by
 * design (SYNC-R44 — no correctness decision reads it; a peer lying about its position earns
 * only wasted bytes, per the spec's §5 analysis). What IS load-bearing — the entries and
 * envelopes it carries — are each individually signed by their authors, and the receiver
 * verifies every one itself (SYNC-R2: forwarding confers no trust).
 */
import { describe, it, expect } from "vitest";
import { decodeCbor, encodeCbor } from "../cbor.js";
import {
  DOCUMENT_RECONCILE_EXCHANGE_VERSION,
  MAX_RECONCILE_DOCUMENTS,
  encodeDocumentReconcile,
  decodeDocumentReconcile,
  type DocumentReconcileFrame,
} from "../document-reconcile.js";

const DOC = "d".repeat(64);
const AUTHOR = "a".repeat(64);

function frame(over: Partial<DocumentReconcileFrame> = {}): DocumentReconcileFrame {
  return {
    type: "document_reconcile",
    exchange_version: DOCUMENT_RECONCILE_EXCHANGE_VERSION,
    documents: [
      {
        document_id: DOC,
        governance: [{ author: AUTHOR, seq: 3, head_hashes: ["ab".repeat(32)] }],
        content: [{ author: AUTHOR, count: 5, head_hash: "cd".repeat(32) }],
        refused: ["ef".repeat(32)],
        entries: [new Uint8Array([1, 2, 3])],
        envelopes: [new Uint8Array([4, 5, 6])],
      },
    ],
    ...over,
  };
}

describe("document_reconcile — one shape, three steps", () => {
  it("survives encode → decode with every field intact", () => {
    const f = frame();
    expect(decodeDocumentReconcile(encodeDocumentReconcile(f))).toEqual(f);
  });

  it("a bare position (step 1) round-trips with empty payloads — the payload arrays are always present, never optional keys", () => {
    const f = frame({
      documents: [
        {
          document_id: DOC,
          governance: [],
          content: [],
          refused: [],
          entries: [],
          envelopes: [],
        },
      ],
    });
    const decoded = decodeDocumentReconcile(encodeDocumentReconcile(f));
    expect(decoded.documents[0]!.entries).toEqual([]);
    expect(decoded.documents[0]!.envelopes).toEqual([]);
  });

  it("a governance watermark carries PLURAL heads — a forked author is visible on the wire, never silently collapsed", () => {
    const f = frame({
      documents: [
        {
          document_id: DOC,
          governance: [
            { author: AUTHOR, seq: 2, head_hashes: ["ab".repeat(32), "cd".repeat(32)] },
          ],
          content: [],
          refused: [],
          entries: [],
          envelopes: [],
        },
      ],
    });
    const decoded = decodeDocumentReconcile(encodeDocumentReconcile(f));
    expect(decoded.documents[0]!.governance[0]!.head_hashes).toHaveLength(2);
  });

  it.each([
    ["exchange_version", undefined, /document_reconcile_missing_field: exchange_version/],
    ["exchange_version", "1", /document_reconcile_field_type: exchange_version/],
    ["documents", undefined, /document_reconcile_missing_field: documents/],
  ] as const)("decode refuses %s = %j with the NAMED code", (field, value, expected) => {
    const wire = decodeCbor(encodeDocumentReconcile(frame())) as Record<string, unknown>;
    if (value === undefined) delete wire[field];
    else wire[field] = value;
    expect(() => decodeDocumentReconcile(encodeCbor(wire))).toThrow(expected);
  });

  it("decode refuses a malformed per-document block by name — no partial admission", () => {
    const wire = decodeCbor(encodeDocumentReconcile(frame())) as Record<string, unknown>;
    const docs = wire["documents"] as Array<Record<string, unknown>>;
    delete docs[0]!["governance"];
    expect(() => decodeDocumentReconcile(encodeCbor(wire))).toThrow(
      /document_reconcile_missing_field: governance/,
    );
  });

  it("decode refuses a document_id that is not 64-hex", () => {
    const wire = decodeCbor(encodeDocumentReconcile(frame())) as Record<string, unknown>;
    (wire["documents"] as Array<Record<string, unknown>>)[0]!["document_id"] = "nope";
    expect(() => decodeDocumentReconcile(encodeCbor(wire))).toThrow(
      /document_reconcile_field_type: document_id/,
    );
  });

  it("decode refuses more documents than the batching cap — one frame cannot be made unbounded", () => {
    const docs = Array.from({ length: MAX_RECONCILE_DOCUMENTS + 1 }, () => ({
      document_id: DOC,
      governance: [],
      content: [],
      refused: [],
      entries: [],
      envelopes: [],
    }));
    const f = frame({ documents: docs });
    expect(() => decodeDocumentReconcile(encodeDocumentReconcile(f))).toThrow(
      /document_reconcile_documents_cap/,
    );
  });

  it("copies byte payloads out of the wire rather than aliasing it", () => {
    const wire = encodeDocumentReconcile(frame());
    const decoded = decodeDocumentReconcile(wire);
    wire.fill(0);
    expect(decoded.documents[0]!.entries[0]).toEqual(new Uint8Array([1, 2, 3]));
  });

  it("the version is a number the far end can refuse BY NAME (R11) — pinned so a bump is a decision", () => {
    expect(DOCUMENT_RECONCILE_EXCHANGE_VERSION).toBe(1);
  });

  it("the genesis rides the frame for a peer who holds nothing — a joiner is just very far behind", () => {
    const f = frame({
      documents: [
        {
          document_id: DOC,
          governance: [],
          content: [],
          refused: [],
          entries: [],
          envelopes: [],
          genesis: new Uint8Array([7, 8, 9]),
        },
      ],
    });
    const decoded = decodeDocumentReconcile(encodeDocumentReconcile(f));
    expect(decoded.documents[0]!.genesis).toEqual(new Uint8Array([7, 8, 9]));
  });

  it("a refusal rides the SAME frame — no second carrier for 'no'", () => {
    const f = frame({
      documents: [],
      refusal: { reason: "document_reconcile_version: you speak 2, this holder speaks 1", terminal: false },
    });
    const decoded = decodeDocumentReconcile(encodeDocumentReconcile(f));
    expect(decoded.refusal).toEqual({
      reason: "document_reconcile_version: you speak 2, this holder speaks 1",
      terminal: false,
    });
    expect(decoded.documents).toEqual([]);
  });

  it("a malformed refusal is refused by name", () => {
    const wire = decodeCbor(
      encodeDocumentReconcile(frame({ documents: [], refusal: { reason: "x", terminal: true } })),
    ) as Record<string, unknown>;
    (wire["refusal"] as Record<string, unknown>)["terminal"] = "yes";
    expect(() => decodeDocumentReconcile(encodeCbor(wire))).toThrow(
      /document_reconcile_field_type: refusal/,
    );
  });
});
