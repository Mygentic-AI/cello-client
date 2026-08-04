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
    expect(engine.readTextRoot(doc)).toBe("# Title\n\nbody text");
  });

  it("applies an update and reads the merged result", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const a = engine.createDocument("hello");
    const b = engine.createDocument("");
    const update = engine.encodeState(a);

    const res = engine.applyUpdate(b, update);
    expect(res.ok).toBe(true);
    expect(engine.readTextRoot(b)).toBe("hello");
  });

  it("computes an update against a peer state vector — only the delta the peer lacks", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const mine = engine.createDocument("shared base");
    const theirs = engine.createDocument("");
    engine.applyUpdate(theirs, engine.encodeState(mine));

    // Now diverge: I add more.
    engine.insertIntoTextRoot(mine, engine.readTextRoot(mine).length, " plus mine");

    const theirVector = engine.encodeStateVector(theirs);
    const delta = engine.encodeState(mine, theirVector);
    const full = engine.encodeState(mine);
    // The delta must be genuinely smaller than a full state — that is the point of the vector.
    expect(delta.length).toBeLessThan(full.length);

    engine.applyUpdate(theirs, delta);
    expect(engine.readTextRoot(theirs)).toBe("shared base plus mine");
  });

  it("snapshots and restores through binary + state vector", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const doc = engine.createDocument("persist me");
    const snap = engine.snapshot(doc);

    const restored = engine.restore(snap.binary);
    expect(engine.readTextRoot(restored)).toBe("persist me");
    expect(Buffer.from(engine.encodeStateVector(restored))).toEqual(Buffer.from(snap.stateVector));
  });

  it("converges regardless of the order two concurrent updates arrive in", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const base = engine.createDocument("base");
    const baseState = engine.encodeState(base);

    const a = engine.restore(baseState);
    const b = engine.restore(baseState);
    engine.insertIntoTextRoot(a, engine.readTextRoot(a).length, " A");
    engine.insertIntoTextRoot(b, 0, "B ");
    const updateA = engine.encodeState(a);
    const updateB = engine.encodeState(b);

    // Apply in both orders onto fresh docs.
    const first = engine.restore(baseState);
    engine.applyUpdate(first, updateA);
    engine.applyUpdate(first, updateB);

    const second = engine.restore(baseState);
    engine.applyUpdate(second, updateB);
    engine.applyUpdate(second, updateA);

    expect(engine.readTextRoot(first)).toBe(engine.readTextRoot(second));
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
    expect(engine.readTextRoot(restored)).toBe("content");
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
    for (let i = 0; i < 5; i++) engine.insertIntoTextRoot(source, 0, `chunk${i} `);

    const target = engine.createDocument("");
    // Skip the first, so every later update depends on a struct the target never sees. Yjs
    // ACCEPTS these silently and retains them forever — measured in DOD-DOC-FUZZ-1.
    const res = engine.applyUpdate(target, updates[2]!);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("document_update_unresolved_dependencies");
    // And the document is left untouched, not half-integrated.
    expect(engine.readTextRoot(target)).toBe("");
  });

  it("a bad update never crashes and never mutates the document", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const doc = engine.createDocument("original");
    for (const bad of [new Uint8Array([0xff, 0xff]), new Uint8Array([0x01, 0x02, 0x03])]) {
      expect(() => engine.applyUpdate(doc, bad)).not.toThrow();
    }
    expect(engine.readTextRoot(doc)).toBe("original");
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
    engine.insertIntoTextRoot(live, 0, "first ");
    engine.insertIntoTextRoot(live, engine.readTextRoot(live).length, "second ");
    engine.insertIntoTextRoot(live, engine.readTextRoot(live).length, "third");

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
    // BYTE-identical, which is what the AC says — a state vector is only clientID→clock, so
    // structurally different state with the same clocks would pass that alone.
    expect(Buffer.from(rebuilt.binary)).toEqual(Buffer.from(expected.binary));
    expect(Buffer.from(rebuilt.stateVector)).toEqual(Buffer.from(expected.stateVector));
    const restored = engine.restore(rebuilt.binary);
    expect(engine.readTextRoot(restored)).toBe("first second third");
  });

  it("(ii) a withdrawal record excludes NOTHING — the undo is an inverse update (§16.4)", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const store = newStore();

    const live = engine.createDocument("");
    const captured: Uint8Array[] = [];
    live.on("update", (u: Uint8Array) => captured.push(u));
    engine.insertIntoTextRoot(live, 0, "keep ");
    engine.insertIntoTextRoot(live, engine.readTextRoot(live).length, "WITHDRAWN");
    // The withdrawal's ACTUAL mechanism: a Yjs undo, which is itself an ordinary update.
    const withdrawnLength = "WITHDRAWN".length;
    live.getText("content").delete(engine.readTextRoot(live).length - withdrawnLength, withdrawnLength);

    let prev: string | null = null;
    const hashes: string[] = [];
    for (const payload of captured) {
      const e = envelopeFor(payload, prev);
      store.appendEnvelope(AGENT, e);
      hashes.push(e.envelopeHash);
      prev = e.envelopeHash;
    }
    // The audit record sits BESIDE the original — "marked withdrawn, never deleted, so the log
    // stays intact" (§16.4). It carries no payload and changes no content.
    store.appendEnvelope(AGENT, envelopeFor(null, prev, "withdrawal", hashes[1]));

    const rebuilt = store.rebuildSnapshot(AGENT, DOC, (rows) => engine.replay(rows));
    const restored = engine.restore(rebuilt.binary);
    expect(engine.readTextRoot(restored)).toBe("keep ");
    expect(engine.readTextRoot(restored)).not.toContain("WITHDRAWN");
  });

  // The case the previous implementation broke, and the previous test could not see because it
  // withdrew the LAST envelope — the one shape exclusion happened to survive.
  it("(ii) a withdrawal of a NON-LEAF envelope still rebuilds — exclusion would have broken it", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const store = newStore();

    const live = engine.createDocument("");
    const captured: Uint8Array[] = [];
    live.on("update", (u: Uint8Array) => captured.push(u));
    engine.insertIntoTextRoot(live, 0, "one ");
    engine.insertIntoTextRoot(live, engine.readTextRoot(live).length, "two ");
    engine.insertIntoTextRoot(live, engine.readTextRoot(live).length, "three");

    let prev: string | null = null;
    const hashes: string[] = [];
    for (const payload of captured) {
      const e = envelopeFor(payload, prev);
      store.appendEnvelope(AGENT, e);
      hashes.push(e.envelopeHash);
      prev = e.envelopeHash;
    }
    // Reference the FIRST envelope — Yjs operations are causally chained, so excluding it would
    // strand every later one on structs that never arrive.
    store.appendEnvelope(AGENT, envelopeFor(null, prev, "withdrawal", hashes[0]));

    const rebuilt = store.rebuildSnapshot(AGENT, DOC, (rows) => engine.replay(rows));
    expect(engine.readTextRoot(engine.restore(rebuilt.binary))).toBe("one two three");
  });

  it("(ii) a withdrawal referencing ANOTHER sender's envelope cannot erase it", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const store = newStore();

    const live = engine.createDocument("");
    const captured: Uint8Array[] = [];
    live.on("update", (u: Uint8Array) => captured.push(u));
    engine.insertIntoTextRoot(live, 0, "mine");

    const mine = envelopeFor(captured[0]!, null);
    store.appendEnvelope(AGENT, mine);
    // A hostile peer appends a payload-free withdrawal naming MY envelope. Nothing upstream
    // validates authorship of a reference, so if replay honoured it, a counterparty could erase
    // my contribution with a log that still verifies.
    store.appendEnvelope(AGENT, {
      ...envelopeFor(null, null, "withdrawal", mine.envelopeHash),
      senderAgentId: PEER,
    });

    const rebuilt = store.rebuildSnapshot(AGENT, DOC, (rows) => engine.replay(rows));
    expect(engine.readTextRoot(engine.restore(rebuilt.binary))).toBe("mine");
  });

  it("a PURGED update row REFUSES — a short document is never reported as a clean rebuild", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const store = newStore();
    const live = engine.createDocument("");
    const captured: Uint8Array[] = [];
    live.on("update", (u: Uint8Array) => captured.push(u));
    engine.insertIntoTextRoot(live, 0, "content");

    const first = envelopeFor(captured[0]!, null);
    store.appendEnvelope(AGENT, first);
    // kind "update" with no payload is a PURGED operation (V2), not an audit record. Folding
    // around it would silently drop an operation that was part of the document.
    store.appendEnvelope(AGENT, envelopeFor(null, first.envelopeHash, "update"));

    expect(() => store.rebuildSnapshot(AGENT, DOC, (rows) => engine.replay(rows)))
      .toThrow(/document_envelope_purged/);
  });

  it("(iii) rebuilding through the store REFUSES over a chain that does not verify", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const store = newStore();
    const live = engine.createDocument("");
    const captured: Uint8Array[] = [];
    live.on("update", (u: Uint8Array) => captured.push(u));
    engine.insertIntoTextRoot(live, 0, "content");

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
    engine.insertIntoTextRoot(live, 0, "content");

    const good = envelopeFor(captured[0]!, null);
    store.appendEnvelope(AGENT, good);
    store.appendEnvelope(AGENT, envelopeFor(new Uint8Array([0xff, 0xff, 0xff]), good.envelopeHash));

    expect(() => store.rebuildSnapshot(AGENT, DOC, (rows) => engine.replay(rows)))
      .toThrow(DocumentUpdateError);
  });
});

describe("DocumentEngine — restore is guarded like every other read", () => {
  it("a corrupt snapshot binary raises a TYPED reason, not a lib0 decoder string", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    let thrown: unknown;
    try {
      engine.restore(new Uint8Array([0xff, 0xff, 0xff, 0xff]));
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(DocumentUpdateError);
    const e = thrown as DocumentUpdateError;
    expect(e.reason).toBe("document_snapshot_malformed");
    // The decoder string survives as DETAIL — it is useful, it is just not the reason.
    expect(e.detail).toBeTruthy();
  });

  it("a snapshot that decodes but is INCOMPLETE refuses rather than restoring short", () => {
    const engine = new DocumentEngine(NOOP_LOGGER);
    const source = engine.createDocument("");
    const captured: Uint8Array[] = [];
    source.on("update", (u: Uint8Array) => captured.push(u));
    engine.insertIntoTextRoot(source, 0, "first ");
    engine.insertIntoTextRoot(source, engine.readTextRoot(source).length, "second");

    // Only the SECOND update — decodable, but depending on structs that are absent.
    expect(() => engine.restore(captured[1]!)).toThrow(DocumentUpdateError);
  });
});
