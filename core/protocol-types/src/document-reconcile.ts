/**
 * SYNC-P3 (R10–R16) — the reconcile frame: ONE wire shape for all three exchange steps.
 *
 * | Step | Direction | Carries |
 * |------|-----------|---------|
 * | 1    | A → B     | per document: A's positions + A's refusal set (payload arrays empty) |
 * | 2    | B → A     | entries/envelopes A lacks, plus B's positions + refusal set |
 * | 3    | A → B     | entries/envelopes B lacks — sent only if B is behind |
 *
 * One shape means a lost reply degrades to a fresh exchange; there is no half-open protocol
 * state to wedge, and reconciling stays idempotent by construction (R15).
 *
 * POSITION IS THE R7 PRIMITIVE, both halves:
 * - governance: per author, the highest CONTIGUOUS entry seq held, with the head hash(es) at
 *   that seq — plural heads make a forked (equivocating) author visible on the wire instead of
 *   silently divergent (the Entry 48 §3 finding).
 * - content: per author, the length of that author's own envelope chain held, with its head —
 *   the store's chain-linkage invariant already guarantees every sender's links form one
 *   unbroken chain, so the primitive is the same shape. Refused envelopes occupy chain
 *   positions (they are bridged as payload-less stubs); the refusal set is what stops their
 *   payloads from being re-offered (R36).
 *
 * NOT SIGNED, deliberately: the frame rides an authenticated session, and a position is
 * advisory by design (R44 — no correctness decision reads it; a peer lying about its position
 * earns wasted bytes, spec §5). What is load-bearing — every entry and envelope carried — is
 * individually signed by its author, and the receiver verifies each itself (R2: forwarding
 * confers no trust).
 */

import { encodeCbor, decodeCbor } from "./cbor.js";

/** R11: a version mismatch is refused BY NAME at both ends, with both versions in the sentence. */
export const DOCUMENT_RECONCILE_EXCHANGE_VERSION = 1;

/** R16 batching ceiling — one frame cannot be made unbounded by naming every document at once. */
export const MAX_RECONCILE_DOCUMENTS = 32;

export interface GovernancePosition {
  author: string;
  /** Highest contiguous entry seq held from this author (R13: contiguous, never highest-received). */
  seq: number;
  /** Entry hash(es) at that seq. More than one = a fork, visible by design. */
  head_hashes: string[];
}

export interface ContentPosition {
  author: string;
  /** How many of this author's own-chain envelopes are held (refused stubs included). */
  count: number;
  /** The envelope hash at the head of this author's chain as held. */
  head_hash: string;
}

export interface DocumentReconcileBlock {
  document_id: string;
  governance: GovernancePosition[];
  content: ContentPosition[];
  /** Hashes this holder has refused (entries or envelopes) — never re-offer these (R36). */
  refused: string[];
  /** Governance entry wires the peer lacks. Empty on step 1. */
  entries: Uint8Array[];
  /** Content envelope wires the peer lacks. Empty on step 1. */
  envelopes: Uint8Array[];
  /**
   * SYNC-R35: this holder's OWN signed refusal records (document_rejection wires) for this
   * document — the refusal travels by the ordinary exchange like anything else, so a third
   * holder wedged behind a refused hash can learn its name and reason from any reply, not only
   * from the refuser's one-shot frame. Few by construction (each is a retry round); attached
   * whole and deduplicated by the receiver.
   */
  refusals?: Uint8Array[];
  /**
   * The signed genesis proposal, included when the peer's position shows them holding NOTHING —
   * a joiner is simply very far behind (spec §4), and the anchor everything derives from is the
   * one record that is not an entry. Harmless when they already hold it: the bootstrap is
   * idempotent, like everything else in the exchange.
   */
  genesis?: Uint8Array;
  /**
   * A PER-DOCUMENT refusal (P3 review F4): in a batched frame, one document's stranger or
   * removed ruling must not be silenced by another document's ordinary reply — refused-by-name
   * is per document, so the refusal rides the block. May coexist with entries: a removed
   * holder's block carries their own removal's closure AND the terminal ruling (R32 + R17).
   */
  refusal?: { reason: string; terminal: boolean };
}

export interface DocumentReconcileFrame {
  type: "document_reconcile";
  exchange_version: number;
  documents: DocumentReconcileBlock[];
  /**
   * R11: a refusal rides the SAME frame — a version mismatch (or an entitlement refusal) is
   * answered by name with a sentence, never by silence, and inventing a second frame kind for
   * "no" would be the second carrier this design exists to avoid. A refusal reply carries no
   * documents.
   */
  refusal?: { reason: string; terminal: boolean };
}

export function encodeDocumentReconcile(frame: DocumentReconcileFrame): Uint8Array {
  return encodeCbor({
    type: "document_reconcile",
    exchange_version: frame.exchange_version,
    ...(frame.refusal
      ? { refusal: { reason: frame.refusal.reason, terminal: frame.refusal.terminal } }
      : {}),
    documents: frame.documents.map((d) => ({
      document_id: d.document_id,
      governance: d.governance.map((g) => ({
        author: g.author,
        seq: g.seq,
        head_hashes: [...g.head_hashes],
      })),
      content: d.content.map((c) => ({
        author: c.author,
        count: c.count,
        head_hash: c.head_hash,
      })),
      refused: [...d.refused],
      entries: d.entries.map((e) => new Uint8Array(e)),
      envelopes: d.envelopes.map((e) => new Uint8Array(e)),
      ...(d.refusals && d.refusals.length > 0
        ? { refusals: d.refusals.map((e) => new Uint8Array(e)) }
        : {}),
      ...(d.genesis ? { genesis: new Uint8Array(d.genesis) } : {}),
      ...(d.refusal ? { refusal: { reason: d.refusal.reason, terminal: d.refusal.terminal } } : {}),
    })),
  });
}

function present(map: Record<string, unknown>, field: string): unknown {
  if (!(field in map)) {
    throw new Error(`document_reconcile_missing_field: ${field} is mandatory and was not present`);
  }
  return map[field];
}

function hex64(map: Record<string, unknown>, field: string): string {
  const v = present(map, field);
  if (typeof v !== "string" || !/^[0-9a-f]{64}$/.test(v)) {
    throw new Error(`document_reconcile_field_type: ${field} must be 64-hex`);
  }
  return v;
}

function nonNegativeInt(map: Record<string, unknown>, field: string): number {
  const v = present(map, field);
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0) {
    throw new Error(`document_reconcile_field_type: ${field} must be a non-negative integer`);
  }
  return v;
}

function arrayOf(map: Record<string, unknown>, field: string): unknown[] {
  const v = present(map, field);
  if (!Array.isArray(v)) {
    throw new Error(`document_reconcile_field_type: ${field} must be an array`);
  }
  return v;
}

function asMap(value: unknown, what: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`document_reconcile_field_type: ${what} must be a CBOR map`);
  }
  return value as Record<string, unknown>;
}

function hexList(map: Record<string, unknown>, field: string): string[] {
  const raw = arrayOf(map, field);
  return raw.map((h) => {
    if (typeof h !== "string" || !/^[0-9a-f]{64}$/.test(h)) {
      throw new Error(`document_reconcile_field_type: ${field} must hold 64-hex hashes`);
    }
    return h;
  });
}

function byteList(map: Record<string, unknown>, field: string): Uint8Array[] {
  const raw = arrayOf(map, field);
  return raw.map((b) => {
    if (!(b instanceof Uint8Array)) {
      throw new Error(`document_reconcile_field_type: ${field} must hold byte strings`);
    }
    // Copied — the caller may reuse or zero the wire buffer after decode returns.
    return new Uint8Array(b);
  });
}

export function decodeDocumentReconcile(input: Uint8Array): DocumentReconcileFrame {
  const decoded = decodeCbor(input);
  const map = asMap(decoded, "frame");
  const frameType = present(map, "type");
  if (frameType !== "document_reconcile") {
    throw new Error(`document_reconcile_type: expected document_reconcile, got ${String(frameType)}`);
  }
  const version = present(map, "exchange_version");
  if (typeof version !== "number" || !Number.isInteger(version) || version < 1) {
    throw new Error("document_reconcile_field_type: exchange_version must be a positive integer");
  }
  const rawDocs = arrayOf(map, "documents");
  if (rawDocs.length > MAX_RECONCILE_DOCUMENTS) {
    throw new Error(
      `document_reconcile_documents_cap: ${rawDocs.length} documents exceeds the batching ` +
        `ceiling of ${MAX_RECONCILE_DOCUMENTS} — split the exchange`,
    );
  }
  const documents = rawDocs.map((rawDoc) => {
    const d = asMap(rawDoc, "documents[]");
    const governance = arrayOf(d, "governance").map((rawG) => {
      const g = asMap(rawG, "governance[]");
      return {
        author: hex64(g, "author"),
        seq: nonNegativeInt(g, "seq"),
        head_hashes: hexList(g, "head_hashes"),
      };
    });
    const content = arrayOf(d, "content").map((rawC) => {
      const c = asMap(rawC, "content[]");
      return {
        author: hex64(c, "author"),
        count: nonNegativeInt(c, "count"),
        head_hash: hex64(c, "head_hash"),
      };
    });
    let genesis: Uint8Array | undefined;
    if ("genesis" in d) {
      const g = d["genesis"];
      if (!(g instanceof Uint8Array)) {
        throw new Error("document_reconcile_field_type: genesis must be a byte string");
      }
      genesis = new Uint8Array(g);
    }
    let blockRefusal: { reason: string; terminal: boolean } | undefined;
    if ("refusal" in d) {
      const r = asMap(d["refusal"], "documents[].refusal");
      const reason = present(r, "reason");
      const terminal = present(r, "terminal");
      if (typeof reason !== "string" || reason.length === 0 || typeof terminal !== "boolean") {
        throw new Error(
          "document_reconcile_field_type: a block refusal must carry a non-empty reason and a terminal flag",
        );
      }
      blockRefusal = { reason, terminal };
    }
    return {
      document_id: hex64(d, "document_id"),
      governance,
      content,
      refused: hexList(d, "refused"),
      entries: byteList(d, "entries"),
      envelopes: byteList(d, "envelopes"),
      ...("refusals" in d ? { refusals: byteList(d, "refusals") } : {}),
      ...(genesis ? { genesis } : {}),
      ...(blockRefusal ? { refusal: blockRefusal } : {}),
    };
  });
  let refusal: { reason: string; terminal: boolean } | undefined;
  if ("refusal" in map) {
    const r = asMap(map["refusal"], "refusal");
    const reason = present(r, "reason");
    const terminal = present(r, "terminal");
    if (typeof reason !== "string" || reason.length === 0 || typeof terminal !== "boolean") {
      throw new Error(
        "document_reconcile_field_type: refusal must carry a non-empty reason and a terminal flag",
      );
    }
    refusal = { reason, terminal };
  }
  return {
    type: "document_reconcile",
    exchange_version: version,
    documents,
    ...(refusal ? { refusal } : {}),
  };
}
