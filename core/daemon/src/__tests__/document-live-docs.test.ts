/**
 * DOD-DOC-INBOUND-2 — the live Y.Doc cache.
 *
 * `node:sqlite` here is the test-file allowance; production is SQLCipher.
 */

import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import * as Y from "yjs";
import { createHash } from "node:crypto";
import { DocumentStore, type DocumentEnvelopeRow } from "../document-store.js";
import { DocumentEngine } from "../document-engine.js";
import { LiveDocuments, LIVE_DOC_CACHE_SIZE } from "../document-live-docs.js";
import type { Logger } from "../types.js";

const AGENT = "owner-agent";
const PEER = "peer-agent";
const NOW = 1_700_000_000_000;

function silentLogger(): Logger {
  const noop = () => {};
  const logger = { debug: noop, info: noop, warn: noop, error: noop, child: () => logger } as unknown as Logger;
  return logger;
}

let clientSeq = 1000;
function update(text: string): Uint8Array {
  clientSeq += 1;
  const d = new Y.Doc();
  d.clientID = clientSeq;
  d.getText("content").insert(0, text);
  return Y.encodeStateAsUpdate(d);
}

let seq = 0;
function envelope(documentId: string, payload: Uint8Array): DocumentEnvelopeRow {
  seq += 1;
  return {
    envelopeHash: createHash("sha256").update(`live${seq}`).digest("hex"),
    documentId,
    senderAgentId: AGENT,
    docPrevHash: null,
    epochId: 0,
    signature: new Uint8Array(64),
    stateVector: new Uint8Array([0]),
    payload,
    kind: "update",
    createdAtMs: NOW + seq,
  };
}

function newFixture() {
  const logger = silentLogger();
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  const store = new DocumentStore(db, logger);
  const engine = new DocumentEngine(logger);
  const live = new LiveDocuments(store, engine, logger);

  const makeDoc = (documentId: string, text: string) => {
    store.createDocument({
      documentId, ownerAgentId: AGENT, peerAgentId: PEER, documentType: "markdown",
      properties: {}, status: "active", createdAtMs: 1,
    });
    store.appendEnvelope(AGENT, envelope(documentId, update(text)));
  };
  return { store, engine, live, makeDoc };
}

const id = (n: number) => n.toString(16).padStart(2, "0").repeat(32);

describe("LiveDocuments — the SAME object, so updates accumulate", () => {
  it("returns the identical Y.Doc across calls", () => {
    const f = newFixture();
    f.makeDoc(id(1), "hello ");
    // A fresh doc per frame would land every update on an empty document and converge with nothing.
    expect(f.live.get(AGENT, id(1))).toBe(f.live.get(AGENT, id(1)));
  });

  it("keeps edits made through the cached handle", () => {
    const f = newFixture();
    f.makeDoc(id(1), "hello ");
    f.live.get(AGENT, id(1)).getText("content").insert(6, "world");
    expect(f.live.get(AGENT, id(1)).getText("content").toString()).toBe("hello world");
  });
});

describe("LiveDocuments — RESTORED from the log, not created empty", () => {
  it("materializes what the log holds on a first use", () => {
    const f = newFixture();
    f.makeDoc(id(2), "content from the log. ");
    // A cache that started blank would silently discard everything the operator and their peer have
    // written — the log is what makes a document survive a restart.
    expect(f.live.get(AGENT, id(2)).getText("content").toString()).toBe("content from the log. ");
  });

  it("REFUSES a document whose log cannot be rebuilt, rather than returning an empty one", () => {
    const f = newFixture();
    f.store.createDocument({
      documentId: id(3), ownerAgentId: AGENT, peerAgentId: PEER, documentType: "markdown",
      properties: {}, status: "active", createdAtMs: 1,
    });
    // Two genesis rows for one sender — a forked chain.
    f.store.appendEnvelope(AGENT, envelope(id(3), update("a")));
    f.store.appendEnvelope(AGENT, envelope(id(3), update("b")));

    // An empty doc here would be applied to, published from, and would converge the peer's real
    // content away — a whole-document loss originating in a cache miss.
    expect(() => f.live.get(AGENT, id(3))).toThrow();
  });
});

describe("LiveDocuments — BOUNDED, and eviction is not data loss", () => {
  it("holds at most the cache size", () => {
    const f = newFixture();
    for (let i = 1; i <= LIVE_DOC_CACHE_SIZE + 5; i++) {
      f.makeDoc(id(i), `doc ${i}. `);
      f.live.get(AGENT, id(i));
    }
    // A Y.Doc holds the whole document plus its history; unbounded, this is a leak whose symptom is
    // the daemon dying days later with no obvious cause.
    expect(f.live.size()).toBe(LIVE_DOC_CACHE_SIZE);
  });

  it("rebuilds an EVICTED document from the log rather than losing it", () => {
    const f = newFixture();
    f.makeDoc(id(1), "the first document. ");
    f.live.get(AGENT, id(1));
    for (let i = 2; i <= LIVE_DOC_CACHE_SIZE + 2; i++) {
      f.makeDoc(id(i), `doc ${i}. `);
      f.live.get(AGENT, id(i));
    }
    // Eviction is only safe because the log is the truth. Without log-backed restore it would be
    // exactly the silent loss it looks like.
    expect(f.live.get(AGENT, id(1)).getText("content").toString()).toBe("the first document. ");
  });

  it("evicts the LEAST RECENTLY USED, not the oldest inserted", () => {
    const f = newFixture();
    for (let i = 1; i <= LIVE_DOC_CACHE_SIZE; i++) {
      f.makeDoc(id(i), `doc ${i}. `);
      f.live.get(AGENT, id(i));
    }
    const first = f.live.get(AGENT, id(1)); // touch it — now the most recent
    f.makeDoc(id(LIVE_DOC_CACHE_SIZE + 1), "new. ");
    f.live.get(AGENT, id(LIVE_DOC_CACHE_SIZE + 1));

    // Insertion-order eviction would drop the document being actively edited — the one case where
    // a rebuild costs the most and is most likely to surprise.
    expect(f.live.get(AGENT, id(1))).toBe(first);
  });
});

describe("LiveDocuments — release", () => {
  it("drops a document and rebuilds it if asked again", () => {
    const f = newFixture();
    f.makeDoc(id(1), "text. ");
    const before = f.live.get(AGENT, id(1));
    f.live.release(AGENT, id(1));
    expect(f.live.size()).toBe(0);
    // Still recoverable — release is about residency, never about the document existing.
    expect(f.live.get(AGENT, id(1))).not.toBe(before);
    expect(f.live.get(AGENT, id(1)).getText("content").toString()).toBe("text. ");
  });

  it("releasing something not resident is a no-op, not a throw", () => {
    const f = newFixture();
    expect(() => f.live.release(AGENT, id(9))).not.toThrow();
  });
});
