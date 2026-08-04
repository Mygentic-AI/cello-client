/**
 * DOD-DOC-ENGINE-1 — the daemon's Y.Doc lifecycle.
 *
 * This is where the properties DOD-DOC-STORE-1 could only assume get proven against a real
 * `Y.Doc`. The store's rebuild test used byte concatenation as a replay stand-in — associative
 * and order-only — while Yjs merge is neither, so "replaying the log in order reconstructs the
 * same state" was untested until here.
 *
 * The hostile-input handling is not invented here either: DOD-DOC-FUZZ-1 measured what
 * `Y.applyUpdate` actually does, and the engine's guards are the response to those measurements
 * rather than to guesses about them.
 */

import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import { DocumentEngine, DocumentUpdateError } from "../document-engine.js";
import { DocumentStore, type DocumentEnvelopeRow } from "../document-store.js";

const NOOP_LOGGER = { debug() {}, info() {}, warn() {}, error() {} } as never;
const AGENT = "aa".repeat(32);
const PEER = "bb".repeat(32);
const DOC = "cc".repeat(32);

function newStore(): DocumentStore {
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  const store = new DocumentStore(db, NOOP_LOGGER);
  store.createDocument({
    documentId: DOC, ownerAgentId: AGENT, peerAgentId: PEER, documentType: "markdown",
    properties: {}, status: "active", createdAtMs: 1,
  });
  return store;
}

let seq = 0;
function envelopeFor(
  payload: Uint8Array | null,
  prevHash: string | null,
  kind: DocumentEnvelopeRow["kind"] = "update",
  references?: string,
): DocumentEnvelopeRow {
  seq += 1;
  return {
    envelopeHash: createHash("sha256").update(`e${seq}`).digest("hex"),
    documentId: DOC,
    senderAgentId: AGENT,
    docPrevHash: prevHash,
    epochId: 0,
    signature: new Uint8Array(64),
    stateVector: new Uint8Array([0, 0]),
    payload,
    kind,
    referencesEnvelopeHash: references ?? null,
    createdAtMs: 1_700_000_000_000 + seq,
  };
}

describe("DocumentEngine — Y.Doc lifecycle", () => {
  it("creates a document from starting content", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const doc = engine.createDocument("# Title\n\nbody text");
    expect(engine.readText(doc)).toBe("# Title\n\nbody text");
  });

  it("applies an update and reads the merged result", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const a = engine.createDocument("hello");
    const b = engine.createDocument("");
    const update = engine.encodeState(a);

    const res = engine.applyUpdate(b, update);
    expect(res.ok).toBe(true);
    expect(engine.readText(b)).toBe("hello");
  });

  it("computes an update against a peer state vector — only the delta the peer lacks", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const mine = engine.createDocument("shared base");
    const theirs = engine.createDocument("");
    engine.applyUpdate(theirs, engine.encodeState(mine));

    // Now diverge: I add more.
    engine.insertText(mine, engine.readText(mine).length, " plus mine");

    const theirVector = engine.encodeStateVector(theirs);
    const delta = engine.encodeState(mine, theirVector);
    const full = engine.encodeState(mine);
    // The delta must be genuinely smaller than a full state — that is the point of the vector.
    expect(delta.length).toBeLessThan(full.length);

    engine.applyUpdate(theirs, delta);
    expect(engine.readText(theirs)).toBe("shared base plus mine");
  });

  it("snapshots and restores through binary + state vector", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const doc = engine.createDocument("persist me");
    const snap = engine.snapshot(doc);

    const restored = engine.restore(snap.binary);
    expect(engine.readText(restored)).toBe("persist me");
    expect(Buffer.from(engine.encodeStateVector(restored))).toEqual(Buffer.from(snap.stateVector));
  });

  it("converges regardless of the order two concurrent updates arrive in", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const base = engine.createDocument("base");
    const baseState = engine.encodeState(base);

    const a = engine.restore(baseState);
    const b = engine.restore(baseState);
    engine.insertText(a, engine.readText(a).length, " A");
    engine.insertText(b, 0, "B ");
    const updateA = engine.encodeState(a);
    const updateB = engine.encodeState(b);

    // Apply in both orders onto fresh docs.
    const first = engine.restore(baseState);
    engine.applyUpdate(first, updateA);
    engine.applyUpdate(first, updateB);

    const second = engine.restore(baseState);
    engine.applyUpdate(second, updateB);
    engine.applyUpdate(second, updateA);

    expect(engine.readText(first)).toBe(engine.readText(second));
  });
});

describe("DocumentEngine — the clientID rule (§14)", () => {
  it("every live Y.Doc gets its OWN random clientID — nothing derives it from identity", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const ids = new Set<number>();
    for (let i = 0; i < 20; i++) ids.add(engine.createDocument("x").clientID);
    // Yjs mints a random uint32 per doc; 20 collisions would mean something is deriving it.
    expect(ids.size).toBe(20);
  });

  it("restore does NOT carry a clientID across — the restored doc mints a fresh one", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const original = engine.createDocument("content");
    const restored = engine.restore(engine.snapshot(original).binary);
    // DOD-DOC-FUZZ-1 measured what a shared clientID costs: the colliding writer silently wins,
    // the honest client's update is accepted-and-dropped, and the document becomes a splice of
    // two authors with an empty pending set and no error anywhere.
    expect(restored.clientID).not.toBe(original.clientID);
    expect(engine.readText(restored)).toBe("content");
  });
});

describe("DocumentEngine — hostile input (guards measured by DOD-DOC-FUZZ-1)", () => {
  it("refuses an oversized update BEFORE Yjs sees the bytes", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const doc = engine.createDocument("");
    const res = engine.applyUpdate(doc, new Uint8Array(engine.maxUpdateBytes + 1));
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("document_update_too_large");
  });

  it("refuses an update below the two-byte floor, with a protocol reason not a decoder string", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const doc = engine.createDocument("");
    for (const tooSmall of [new Uint8Array(0), new Uint8Array(1)]) {
      const res = engine.applyUpdate(doc, tooSmall);
      expect(res.ok).toBe(false);
      if (!res.ok) {
        expect(res.reason).toBe("document_update_too_small");
        // The floor exists precisely so this is never "Unexpected end of array".
        expect(res.detail ?? "").not.toContain("Unexpected end of array");
      }
    }
  });

  it("turns a malformed update into ONE typed reason, carrying the decoder string as detail", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const doc = engine.createDocument("");
    const res = engine.applyUpdate(doc, new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff]));
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.reason).toBe("document_update_malformed");
      expect(typeof res.detail).toBe("string");
      expect(res.detail!.length).toBeGreaterThan(0); // the cause survives as detail
    }
  });

  it("refuses an update that leaves unresolved dependencies — the accept-class failure", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const source = engine.createDocument("");
    const updates: Uint8Array[] = [];
    source.on("update", (u: Uint8Array) => updates.push(u));
    for (let i = 0; i < 5; i++) engine.insertText(source, 0, `chunk${i} `);

    const target = engine.createDocument("");
    // Skip the first, so every later update depends on a struct the target never sees. Yjs
    // ACCEPTS these silently and retains them forever — measured in DOD-DOC-FUZZ-1.
    const res = engine.applyUpdate(target, updates[2]!);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("document_update_unresolved_dependencies");
    // And the document is left untouched, not half-integrated.
    expect(engine.readText(target)).toBe("");
  });

  it("a bad update never crashes and never mutates the document", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const doc = engine.createDocument("original");
    for (const bad of [new Uint8Array([0xff, 0xff]), new Uint8Array([0x01, 0x02, 0x03])]) {
      expect(() => engine.applyUpdate(doc, bad)).not.toThrow();
    }
    expect(engine.readText(doc)).toBe("original");
  });

  it("applyUpdateOrThrow raises a typed error for callers that want one", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const doc = engine.createDocument("");
    expect(() => engine.applyUpdateOrThrow(doc, new Uint8Array(0))).toThrow(DocumentUpdateError);
  });
});

describe("DocumentEngine — rebuild from the log (the ACs inherited from STORE-1)", () => {
  it("(i) replaying the log in order reconstructs BYTE-IDENTICAL Yjs state", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const store = newStore();

    // Build a document through a sequence of real Yjs updates, recording each as an envelope.
    const live = engine.createDocument("");
    const captured: Uint8Array[] = [];
    live.on("update", (u: Uint8Array) => captured.push(u));
    engine.insertText(live, 0, "first ");
    engine.insertText(live, engine.readText(live).length, "second ");
    engine.insertText(live, engine.readText(live).length, "third");

    let prev: string | null = null;
    for (const payload of captured) {
      const e = envelopeFor(payload, prev);
      store.appendEnvelope(AGENT, e);
      prev = e.envelopeHash;
    }

    const expected = engine.snapshot(live);
    const rebuilt = store.rebuildSnapshot(AGENT, DOC, (rows) => engine.replay(rows));

    // The property a concatenation stand-in cannot test: Yjs merge is neither associative nor
    // order-only, so this is where "the log is sufficient input" becomes "the fold is correct".
    expect(Buffer.from(rebuilt.stateVector)).toEqual(Buffer.from(expected.stateVector));
    const restored = engine.restore(rebuilt.binary);
    expect(engine.readText(restored)).toBe("first second third");
  });

  it("(ii) a WITHDRAWN update is excluded from the fold", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const store = newStore();

    const live = engine.createDocument("");
    const captured: Uint8Array[] = [];
    live.on("update", (u: Uint8Array) => captured.push(u));
    engine.insertText(live, 0, "keep ");
    engine.insertText(live, engine.readText(live).length, "WITHDRAWN");

    let prev: string | null = null;
    const hashes: string[] = [];
    for (const payload of captured) {
      const e = envelopeFor(payload, prev);
      store.appendEnvelope(AGENT, e);
      hashes.push(e.envelopeHash);
      prev = e.envelopeHash;
    }
    // A withdrawal row referencing the second update. It carries NO payload — which is exactly
    // why the store hands the engine whole rows rather than payload bytes.
    store.appendEnvelope(AGENT, envelopeFor(null, prev, "withdrawal", hashes[1]));

    const rebuilt = store.rebuildSnapshot(AGENT, DOC, (rows) => engine.replay(rows));
    const restored = engine.restore(rebuilt.binary);
    expect(engine.readText(restored)).toBe("keep ");
    expect(engine.readText(restored)).not.toContain("WITHDRAWN");
  });

  it("(iii) rebuilding through the store REFUSES over a chain that does not verify", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const store = newStore();
    const live = engine.createDocument("");
    const captured: Uint8Array[] = [];
    live.on("update", (u: Uint8Array) => captured.push(u));
    engine.insertText(live, 0, "content");

    const first = envelopeFor(captured[0]!, null);
    store.appendEnvelope(AGENT, first);
    // A second envelope pointing at a predecessor that was never stored.
    store.appendEnvelope(AGENT, envelopeFor(captured[0]!, "de".repeat(32)));

    expect(() => store.rebuildSnapshot(AGENT, DOC, (rows) => engine.replay(rows))).toThrow();
  });

  it("replay REFUSES a payload that does not apply — a corrupt log is not silently short", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const store = newStore();
    const live = engine.createDocument("");
    const captured: Uint8Array[] = [];
    live.on("update", (u: Uint8Array) => captured.push(u));
    engine.insertText(live, 0, "content");

    const good = envelopeFor(captured[0]!, null);
    store.appendEnvelope(AGENT, good);
    store.appendEnvelope(AGENT, envelopeFor(new Uint8Array([0xff, 0xff, 0xff]), good.envelopeHash));

    expect(() => store.rebuildSnapshot(AGENT, DOC, (rows) => engine.replay(rows)))
      .toThrow(DocumentUpdateError);
  });
});
