/**
 * DOD-DOC-STORE-1 — the document store's three tables.
 *
 * Two layers, not one (§14): the IMMUTABLE envelope log carries signatures, provenance and the
 * per-document chain that makes a seal verifiable; the Yjs SNAPSHOT is a materialization for
 * fast start. Storing only the merged binary would discard the chain. So the property this file
 * exists to prove is that the snapshot is **disposable** — delete it, rebuild from the log
 * alone, and get byte-identical state back.
 *
 * The store PERSISTS; it does not apply Yjs updates. Replay is injected, so the store owns what
 * to replay and in what order while the engine (DOD-DOC-ENGINE-1) owns how to apply.
 */

import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import { DocumentStore, DocumentChainError, type DocumentEnvelopeRow } from "../document-store.js";

const NOOP_LOGGER = { debug() {}, info() {}, warn() {}, error() {} } as never;

const AGENT = "aa".repeat(32);
const PEER = "bb".repeat(32);
const DOC = "cc".repeat(32);

function newStore(opts: { withDocument?: boolean } = { withDocument: true }): DocumentStore {
  // node:sqlite only as an in-memory TEST handle — production opens SQLCipher (see
  // sqlcipher-db.ts). The store itself never imports node:sqlite.
  const db = new DatabaseSync(":memory:");
  // Production sets this at open (sqlcipher-db.ts) and verifies it took effect. Without it here
  // the foreign keys would be decorative and the FK tests would pass vacuously.
  db.exec("PRAGMA foreign_keys = ON");
  const store = new DocumentStore(db, NOOP_LOGGER);
  if (opts.withDocument !== false) {
    store.createDocument({
      documentId: DOC, ownerAgentId: AGENT, peerAgentId: PEER, documentType: "markdown",
      properties: {}, status: "active", createdAtMs: 1,
    });
  }
  return store;
}

/** Chain-linked envelope: doc_prev_hash points at the sender's previous envelope. */
function envelope(
  seq: number,
  senderAgentId: string,
  prevHash: string | null,
  payload: Uint8Array | null,
): DocumentEnvelopeRow {
  const hash = createHash("sha256").update(`${senderAgentId}:${seq}`).digest("hex");
  return {
    envelopeHash: hash,
    documentId: DOC,
    senderAgentId,
    docPrevHash: prevHash,
    epochId: 0,
    signature: new Uint8Array(64).fill(seq),
    stateVector: new Uint8Array([seq, 0]),
    payload,
    kind: "update",
    createdAtMs: 1_700_000_000_000 + seq,
  };
}

/** A chain of `n` envelopes from one sender, each linked to the last. */
function chain(sender: string, n: number, from = 0): DocumentEnvelopeRow[] {
  const out: DocumentEnvelopeRow[] = [];
  let prev: string | null = null;
  for (let i = from; i < from + n; i++) {
    const e = envelope(i, sender, prev, new Uint8Array([i]));
    out.push(e);
    prev = e.envelopeHash;
  }
  return out;
}

describe("DocumentStore — documents table (DOD-DOC-STORE-1)", () => {
  it("round-trips a document keyed on document_id and peer agent_id", () => {
    const store = newStore({ withDocument: false });
    store.createDocument({
      documentId: DOC,
      ownerAgentId: AGENT,
      peerAgentId: PEER,
      documentType: "markdown",
      properties: { append_only: true, assurance_tier: "authenticated", schema_enforcement: false },
      status: "active",
      createdAtMs: 1_700_000_000_000,
    });

    const doc = store.getDocument(AGENT, DOC);
    expect(doc).not.toBeNull();
    expect(doc!.peerAgentId).toBe(PEER);
    expect(doc!.documentType).toBe("markdown");
    expect(doc!.status).toBe("active");
    expect(doc!.properties.append_only).toBe(true);
    // Seam fields survive the round trip (M14-PROCEDURE §5: serialization test in lieu of a
    // consumer — their consumer is M14B).
    expect(doc!.properties.assurance_tier).toBe("authenticated");
    expect(doc!.properties.schema_enforcement).toBe(false);
  });

  it("scopes by owner agent_id — another agent on the same daemon sees nothing", () => {
    const store = newStore();
    expect(store.getDocument("dd".repeat(32), DOC)).toBeNull();
    expect(store.listDocuments("dd".repeat(32))).toHaveLength(0);
    expect(store.listDocuments(AGENT)).toHaveLength(1);
  });

  it("status is mutable; identity is not", () => {
    const store = newStore();
    store.setDocumentStatus(AGENT, DOC, "stalled");
    expect(store.getDocument(AGENT, DOC)!.status).toBe("stalled");
  });
});

describe("DocumentStore — the append-only envelope log", () => {
  it("appends in order and reads back the chain with seam fields intact", () => {
    const store = newStore();
    for (const e of chain(AGENT, 3)) store.appendEnvelope(AGENT, e);

    const log = store.getEnvelopeLog(AGENT, DOC);
    expect(log).toHaveLength(3);
    expect(log[0]!.docPrevHash).toBeNull(); // genesis
    expect(log[1]!.docPrevHash).toBe(log[0]!.envelopeHash);
    expect(log[2]!.docPrevHash).toBe(log[1]!.envelopeHash);
    // epoch_id is CONSTANT 0 in V1 and must be stored, never omitted (§16.1 seam).
    expect(log.every((e) => e.epochId === 0)).toBe(true);
    expect(log[0]!.stateVector).toBeInstanceOf(Uint8Array);
  });

  it("is APPEND-ONLY — re-appending the same envelope hash is ignored, never an overwrite", () => {
    const store = newStore();
    const [first] = chain(AGENT, 1);
    expect(store.appendEnvelope(AGENT, first!)).toBe(true);

    // A re-delivery carrying different bytes under the same hash must NOT replace the original.
    const impostor: DocumentEnvelopeRow = { ...first!, payload: new Uint8Array([0xff]) };
    expect(store.appendEnvelope(AGENT, impostor)).toBe(false);

    const log = store.getEnvelopeLog(AGENT, DOC);
    expect(log).toHaveLength(1);
    expect(log[0]!.payload).toEqual(new Uint8Array([0]));
  });

  it("withdrawals and rejections are ROWS, never edits to the envelope they concern", () => {
    const store = newStore();
    const [original] = chain(AGENT, 1);
    store.appendEnvelope(AGENT, original!);

    store.appendEnvelope(AGENT, {
      ...envelope(99, AGENT, original!.envelopeHash, null),
      kind: "withdrawal",
      referencesEnvelopeHash: original!.envelopeHash,
    });

    const log = store.getEnvelopeLog(AGENT, DOC);
    expect(log).toHaveLength(2);
    // The original is untouched — its payload is still there.
    expect(log[0]!.payload).toEqual(new Uint8Array([0]));
    expect(log[0]!.kind).toBe("update");
    expect(log[1]!.kind).toBe("withdrawal");
    expect(log[1]!.referencesEnvelopeHash).toBe(original!.envelopeHash);
  });

  it("payload is NULLABLE — a purged envelope still proves it existed (§16.7-12)", () => {
    const store = newStore();
    const stripped = envelope(0, AGENT, null, null);
    store.appendEnvelope(AGENT, stripped);

    const log = store.getEnvelopeLog(AGENT, DOC);
    expect(log).toHaveLength(1);
    expect(log[0]!.payload).toBeNull();
    // The hash and signature survive, which is the whole point: the record proves an envelope
    // with this hash existed, and a 0x05 leaf referencing it is the explanation.
    expect(log[0]!.envelopeHash).toBe(stripped.envelopeHash);
    expect(log[0]!.signature).toHaveLength(64);
  });
});

describe("DocumentStore — per-sender chain verification on read", () => {
  it("verifies a well-formed chain from a single sender", () => {
    const store = newStore();
    for (const e of chain(AGENT, 4)) store.appendEnvelope(AGENT, e);
    expect(store.verifyChainLinkage(AGENT, DOC)).toEqual({ ok: true });
  });

  it("verifies TWO senders' chains independently — they interleave in the log", () => {
    const store = newStore();
    const mine = chain(AGENT, 3);
    const theirs = chain(PEER, 3);
    // Interleaved arrival, which is the normal case.
    for (let i = 0; i < 3; i++) {
      store.appendEnvelope(AGENT, mine[i]!);
      store.appendEnvelope(AGENT, theirs[i]!);
    }
    expect(store.verifyChainLinkage(AGENT, DOC)).toEqual({ ok: true });
  });

  it("REFUSES a broken link, naming the sender and the gap — never a silent skip", () => {
    const store = newStore();
    const good = chain(AGENT, 3);
    store.appendEnvelope(AGENT, good[0]!);
    // Third envelope points at a predecessor that was never stored.
    store.appendEnvelope(AGENT, { ...good[2]!, docPrevHash: "de".repeat(32) });

    const res = store.verifyChainLinkage(AGENT, DOC);
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.reason).toBe("document_chain_broken");
      expect(res.detail).toContain(AGENT.slice(0, 16)); // names the sender
      expect(res.detail).toContain("de".repeat(32).slice(0, 16)); // names the missing link
    }
  });

  it("REFUSES a second genesis from the same sender — a forked chain is not a chain", () => {
    const store = newStore();
    store.appendEnvelope(AGENT, envelope(0, AGENT, null, new Uint8Array([0])));
    store.appendEnvelope(AGENT, envelope(1, AGENT, null, new Uint8Array([1])));

    const res = store.verifyChainLinkage(AGENT, DOC);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("document_chain_forked");
  });
});

describe("DocumentStore — the snapshot is DISPOSABLE (the unit's headline property)", () => {
  it("deleting the snapshot and rebuilding from the log yields byte-identical state", () => {
    const store = newStore();
    const envelopes = chain(AGENT, 5);
    for (const e of envelopes) store.appendEnvelope(AGENT, e);

    // A replay function stands in for the engine: the store owns WHAT to replay and in what
    // order; the engine owns HOW to apply. Here, concatenating payloads is a faithful stand-in
    // for "fold the log into a state" without importing yjs into a P0 store.
    const replay = (rows: DocumentEnvelopeRow[]): { binary: Uint8Array; stateVector: Uint8Array } => {
      const payloads = rows.map((r) => r.payload!);
      const binary = new Uint8Array(payloads.reduce((n, p) => n + p.length, 0));
      let at = 0;
      for (const p of payloads) { binary.set(p, at); at += p.length; }
      return { binary, stateVector: new Uint8Array([payloads.length, 0]) };
    };

    const built = store.rebuildSnapshot(AGENT, DOC, replay);
    store.putSnapshot(AGENT, DOC, built);

    const original = store.getSnapshot(AGENT, DOC);
    expect(original).not.toBeNull();
    expect(original!.lastAppliedIndex).toBe(envelopes.length - 1);
    // CONTENT and ORDER pinned, not just self-consistency. Comparing rebuild-A to rebuild-B
    // passes for an implementation that never reads a payload at all — both would be empty and
    // equal. This is the assertion that makes the log demonstrably the INPUT to the rebuild.
    expect(Buffer.from(original!.binary)).toEqual(Buffer.from(Uint8Array.from([0, 1, 2, 3, 4])));

    // Throw it away.
    store.deleteSnapshot(AGENT, DOC);
    expect(store.getSnapshot(AGENT, DOC)).toBeNull();

    // Rebuild from the log ALONE.
    const rebuilt = store.rebuildSnapshot(AGENT, DOC, replay);
    store.putSnapshot(AGENT, DOC, rebuilt);
    const after = store.getSnapshot(AGENT, DOC);

    expect(after).not.toBeNull();
    expect(Buffer.from(after!.binary)).toEqual(Buffer.from(original!.binary));
    expect(Buffer.from(after!.stateVector)).toEqual(Buffer.from(original!.stateVector));
    expect(after!.lastAppliedIndex).toBe(original!.lastAppliedIndex);
  });

  it("rebuild SKIPS payload-stripped envelopes but still counts them in last_applied_index", () => {
    const store = newStore();
    const envelopes = chain(AGENT, 3);
    store.appendEnvelope(AGENT, envelopes[0]!);
    store.appendEnvelope(AGENT, { ...envelopes[1]!, payload: null }); // purged
    store.appendEnvelope(AGENT, envelopes[2]!);

    const seen: number[] = [];
    const replay = (rows: DocumentEnvelopeRow[]) => {
      for (const r of rows) seen.push(r.payload![0]!);
      return { binary: new Uint8Array(seen), stateVector: new Uint8Array([seen.length]) };
    };

    const built = store.rebuildSnapshot(AGENT, DOC, replay);
    // The stripped envelope contributes no payload...
    expect(seen).toEqual([0, 2]);
    // ...but the index still reflects the whole log, or the next rebuild would replay it again.
    expect(built.lastAppliedIndex).toBe(2);
  });

  it("a snapshot is per (agent, document) — never leaks across either axis", () => {
    const store = newStore();
    const snap = { binary: new Uint8Array([1, 2, 3]), stateVector: new Uint8Array([1]), lastAppliedIndex: 0 };
    store.putSnapshot(AGENT, DOC, snap);
    expect(store.getSnapshot("dd".repeat(32), DOC)).toBeNull();
    expect(store.getSnapshot(AGENT, "ee".repeat(32))).toBeNull();
    expect(store.getSnapshot(AGENT, DOC)).not.toBeNull();
  });

  it("putSnapshot REPLACES — a snapshot is a cache, not a log", () => {
    const store = newStore();
    store.putSnapshot(AGENT, DOC, { binary: new Uint8Array([1]), stateVector: new Uint8Array([1]), lastAppliedIndex: 0 });
    store.putSnapshot(AGENT, DOC, { binary: new Uint8Array([2, 2]), stateVector: new Uint8Array([2]), lastAppliedIndex: 1 });
    const s = store.getSnapshot(AGENT, DOC);
    expect(s!.binary).toEqual(new Uint8Array([2, 2]));
    expect(s!.lastAppliedIndex).toBe(1);
  });
});

describe("DocumentStore — schema discipline", () => {
  it("constructing twice over the same database is idempotent", () => {
    const db = new DatabaseSync(":memory:");
    db.exec("PRAGMA foreign_keys = ON");
    const a = new DocumentStore(db, NOOP_LOGGER);
    a.createDocument({
      documentId: DOC, ownerAgentId: AGENT, peerAgentId: PEER, documentType: "markdown",
      properties: {}, status: "active", createdAtMs: 1,
    });
    const b = new DocumentStore(db, NOOP_LOGGER); // must not throw, must not wipe
    expect(b.getDocument(AGENT, DOC)).not.toBeNull();
  });

  it("NO table this store creates carries an agent_name column — schema-driven, not a list", () => {
    const db = new DatabaseSync(":memory:");
    new DocumentStore(db, NOOP_LOGGER);
    // Enumerated from the schema so a table added later is covered automatically. A hand-kept
    // list gets shorter than the schema and silently stops checking the new one.
    const tables = (db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as Array<{ name: string }>)
      .map((t) => t.name)
      .filter((n) => !n.startsWith("sqlite_"));
    expect(tables).toEqual(expect.arrayContaining(["documents", "document_envelopes", "document_snapshots"]));
    for (const table of tables) {
      const cols = db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
      expect(cols.length, `${table} must exist`).toBeGreaterThan(0);
      expect(cols.map((c) => c.name), `${table} must not key on a mutable attribute`)
        .not.toContain("agent_name");
    }
  });
});

// ─── Review-pass additions: the refusals that were unwired or unreachable ────
describe("DocumentStore — refusals that must be reachable, not merely available", () => {
  it("rebuildSnapshot REFUSES over a broken chain — it never materializes a short document", () => {
    const store = newStore();
    const good = chain(AGENT, 3);
    store.appendEnvelope(AGENT, good[0]!);
    store.appendEnvelope(AGENT, { ...good[2]!, docPrevHash: "de".repeat(32) });

    // Verification is ON READ. Without this, a log with a missing predecessor folds into a state
    // quietly short of operations and putSnapshot persists it as authoritative.
    expect(() => store.rebuildSnapshot(AGENT, DOC, () => ({
      binary: new Uint8Array(), stateVector: new Uint8Array(),
    }))).toThrow(DocumentChainError);
    expect(store.getSnapshot(AGENT, DOC)).toBeNull();
  });

  it("REFUSES a detached cycle — every link resolves, and it is still not a chain", () => {
    const store = newStore();
    const a = envelope(0, AGENT, null, new Uint8Array([0]));
    const b = envelope(1, AGENT, a.envelopeHash, new Uint8Array([1]));
    // Close the loop: a points at b, b points at a. Zero genesis, nothing missing.
    store.appendEnvelope(AGENT, { ...a, docPrevHash: b.envelopeHash });
    store.appendEnvelope(AGENT, b);

    const res = store.verifyChainLinkage(AGENT, DOC);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("document_chain_forked");
  });

  it("REFUSES a mid-chain fork — two envelopes claiming the same predecessor", () => {
    const store = newStore();
    const root = envelope(0, AGENT, null, new Uint8Array([0]));
    store.appendEnvelope(AGENT, root);
    store.appendEnvelope(AGENT, envelope(1, AGENT, root.envelopeHash, new Uint8Array([1])));
    store.appendEnvelope(AGENT, envelope(2, AGENT, root.envelopeHash, new Uint8Array([2])));

    const res = store.verifyChainLinkage(AGENT, DOC);
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.reason).toBe("document_chain_forked");
      expect(res.detail).toContain("claiming predecessor");
    }
  });

  it("an envelope for a document that was never created is REFUSED by the database", () => {
    const store = newStore();
    const orphan = { ...envelope(0, AGENT, null, new Uint8Array([0])), documentId: "ff".repeat(32) };
    // The foreign key makes an unscoped row impossible to write, rather than discouraged by a
    // convention every future caller has to remember.
    expect(() => store.appendEnvelope(AGENT, orphan)).toThrow();
  });

  it("an empty log rebuilds to lastAppliedIndex -1, and the resume point is 0", () => {
    const store = newStore();
    const built = store.rebuildSnapshot(AGENT, DOC, () => ({
      binary: new Uint8Array(), stateVector: new Uint8Array(),
    }));
    expect(built.lastAppliedIndex).toBe(-1);
    // The sentinel and the resume convention are chosen to agree: `slice(-1 + 1)` is the whole log.
    expect(store.getEnvelopesSince(AGENT, DOC, built.lastAppliedIndex + 1)).toHaveLength(0);
  });

  it("getEnvelopesSince resumes at lastAppliedIndex + 1 — the lookup §14 asks for", () => {
    const store = newStore();
    for (const e of chain(AGENT, 5)) store.appendEnvelope(AGENT, e);
    const snapshotAt = 2;
    const tail = store.getEnvelopesSince(AGENT, DOC, snapshotAt + 1);
    expect(tail.map((e) => e.logIndex)).toEqual([3, 4]);
  });

  it("a status outside the lifecycle set is refused by the schema, not silently stored", () => {
    const store = newStore();
    expect(() => store.setDocumentStatus(AGENT, DOC, "nonsense" as never)).toThrow();
    expect(store.getDocument(AGENT, DOC)!.status).toBe("active");
  });
});
