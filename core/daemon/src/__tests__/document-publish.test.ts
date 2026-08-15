/**
 * DOD-DOC-DELIVERY-1 (outbound half) — publish.
 *
 * `node:sqlite` here is the test-file allowance; production is SQLCipher.
 */

import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import * as Y from "yjs";
import { decodeDocumentUpdateEnvelope, encodeDocumentUpdateEnvelope } from "@cello-protocol/protocol-types";
import { DocumentStore } from "../document-store.js";
import { DocumentEngine } from "../document-engine.js";
import { DocumentPublish } from "../document-publish.js";
import type { Logger } from "../types.js";

const AGENT = "owner-agent";
const SENDER = "aa".repeat(32); // M14-D5: an agent id IS its pubkey hex
const PEER = "bb".repeat(32);
const DOC = "cc".repeat(32);
const NOW = 1_700_000_000_000;

function silentLogger(): Logger {
  const noop = () => {};
  const logger = { debug: noop, info: noop, warn: noop, error: noop, child: () => logger } as unknown as Logger;
  return logger;
}

function newFixture(opts: { canPublish?: { ok: false; reason: string; detail: string } } = {}) {
  const logger = silentLogger();
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  const store = new DocumentStore(db, logger);
  store.createDocument({
    documentId: DOC, ownerAgentId: AGENT, peerAgentId: PEER, documentType: "markdown",
    properties: {}, status: "active", createdAtMs: 1,
  });
  const engine = new DocumentEngine(logger);
  const nudged: string[][] = [];
  const state = { publishHolders: [PEER] as string[] | null };
  const publish = new DocumentPublish({
    governanceFrontierFor: () => [],
    // Bilateral default: the sole holder is the genesis peer; tests may widen or null it.
    holdersFor: () => state.publishHolders,
    store,
    engine,
    logger,
    sign: async () => new Uint8Array(64).fill(5),
    senderIdFor: () => SENDER,
    canPublish: () => opts.canPublish ?? { ok: true },
    nudgeSeats: (_o, _d, seats) => { nudged.push([...seats]); },
  });
  const doc = new Y.Doc();
  doc.clientID = 7777;
  return {
    store, engine, publish, doc, db, nudged,
    get publishHolders() { return state.publishHolders; },
    set publishHolders(v: string[] | null) { state.publishHolders = v; },
  };
}

function raiseEpoch(db: DatabaseSync, owner: string, doc: string, epoch: number) {
  db.prepare(
    `INSERT INTO document_entries
       (owner_agent_id, document_id, entry_hash, author_agent_id, author_seq, epoch_id,
        received_bytes, recorded_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(owner, doc, "h".repeat(64), "a".repeat(64), epoch, epoch, Buffer.from([1]), 1);
}

describe("FANOUT-1 — publish SEEDS per-holder delivery rows through the production path", () => {
  it("one publish, two holders, two nudges — no genesis-peer-only fan-out anywhere", async () => {
    // The write that makes fan-out HAPPEN is now the nudge set. Nudge only the genesis peer and
    // a 3-party document converges with one holder only — the literal §7-1 divergence the DoD
    // line quotes, through the new machinery.
    const H2 = "ee".repeat(32);
    const f = newFixture();
    f.publishHolders = [PEER, H2];
    f.doc.getText("content").insert(0, "reaches both holders. ");
    const res = await f.publish.publish(AGENT, DOC, f.doc, NOW);
    expect(res.ok).toBe(true);
    expect(new Set(f.nudged.flat())).toEqual(new Set([PEER, H2]));
  });

  it("refuses when the chain does not derive — nothing appended, nothing invisible", async () => {
    const f = newFixture();
    f.publishHolders = null;
    f.doc.getText("content").insert(0, "never leaves. ");
    const res = await f.publish.publish(AGENT, DOC, f.doc, NOW);
    expect(res).toMatchObject({ ok: false, reason: "document_chain_invalid" });
    expect(f.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(0);
  });
});

describe("DocumentPublish — writes a signed, chained envelope and returns", () => {
  it("stamps the CURRENT epoch from the recorded amendment chain — never a constant", async () => {
    // REVERT-VISIBLE (AMEND-1 review T1): with the table non-empty, a producer reverted to the
    // old constant 0 fails here and nowhere else.
    const f = newFixture();
    raiseEpoch(f.db, AGENT, DOC, 1);
    f.doc.getText("content").insert(0, "post-amendment text. ");
    const res = await f.publish.publish(AGENT, DOC, f.doc, NOW);
    expect(res.ok).toBe(true);
    expect(f.store.getEnvelopeLog(AGENT, DOC)[0]!.epochId).toBe(1);
  });


  it("appends an update the peer can decode", async () => {
    const f = newFixture();
    f.doc.getText("content").insert(0, "first draft. ");

    const res = await f.publish.publish(AGENT, DOC, f.doc, NOW);
    expect(res.ok).toBe(true);

    const row = f.store.getEnvelopeLog(AGENT, DOC)[0]!;
    expect(row.senderAgentId).toBe(SENDER);
    expect(row.senderClientId).toBe(7777);
    // The payload is a real Yjs update the peer's decoder accepts — the round trip is what the whole
    // exchange rests on, so it is asserted rather than assumed.
    const doc2 = new Y.Doc();
    Y.applyUpdate(doc2, row.payload!);
    expect(doc2.getText("content").toString()).toBe("first draft. ");
  });

  it("CHAINS to our own previous envelope, read at publish time", async () => {
    const f = newFixture();
    f.doc.getText("content").insert(0, "one. ");
    const first = await f.publish.publish(AGENT, DOC, f.doc, NOW);
    f.doc.getText("content").insert(5, "two. ");
    const second = await f.publish.publish(AGENT, DOC, f.doc, NOW + 1);

    const log = f.store.getEnvelopeLog(AGENT, DOC);
    expect(log[0]!.docPrevHash).toBeNull();
    // Read, never cached: anything else appended since — a rejection, a withdrawal — moves this,
    // and a wrong link is refused by the peer and stops the document rebuilding locally.
    expect(log[1]!.docPrevHash).toBe((first as { envelopeHash: string }).envelopeHash);
    expect((second as { envelopeHash: string }).envelopeHash).toBe(log[1]!.envelopeHash);
    expect(f.store.verifyChainLinkage(AGENT, DOC)).toEqual({ ok: true });
  });

  it("the envelope round-trips through the WIRE encoding", async () => {
    const f = newFixture();
    f.doc.getText("content").insert(0, "wire. ");
    await f.publish.publish(AGENT, DOC, f.doc, NOW);
    const row = f.store.getEnvelopeLog(AGENT, DOC)[0]!;

    // Reconstructed the way the peer will see it. If the stored row and the wire type disagree
    // about a field, the peer refuses an envelope we believe we sent correctly.
    const wire = encodeDocumentUpdateEnvelope({
      type: "document_update",
      document_id: row.documentId,
      epoch_id: row.epochId,
      doc_prev_hash: row.docPrevHash,
      sender_agent_id: row.senderAgentId,
      sender_client_id: row.senderClientId!,
      update_encoding: "yjs-v1",
      governance_parents: row.governanceParents,
      state_vector: row.stateVector,
      update: row.payload!,
      signature: row.signature,
    });
    expect(() => decodeDocumentUpdateEnvelope(wire)).not.toThrow();
  });
});

describe("DocumentPublish — refuses rather than writing something useless", () => {
  it("says NOTHING TO PUBLISH when the peer already has everything", async () => {
    const f = newFixture();
    f.doc.getText("content").insert(0, "content. ");
    await f.publish.publish(AGENT, DOC, f.doc, NOW);
    // No new edits. Publishing an empty update would append a leaf, cost a delivery, and converge
    // nothing.
    const again = await f.publish.publish(AGENT, DOC, f.doc, NOW + 1);
    expect(again).toMatchObject({ ok: false, reason: "document_nothing_to_publish" });
    expect(f.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(1);
  });

  it("passes LIFECYCLE's refusal through with its own reason", async () => {
    const f = newFixture({
      canPublish: { ok: false, reason: "document_stalled", detail: "stopped after 3 rounds" },
    });
    f.doc.getText("content").insert(0, "text. ");
    const res = await f.publish.publish(AGENT, DOC, f.doc, NOW);
    // The reason the operator needs is the one LIFECYCLE composed, not a generic refusal from here.
    expect(res).toMatchObject({ ok: false, reason: "document_stalled" });
    expect(f.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(0);
  });

  it("refuses an unknown document", async () => {
    const f = newFixture();
    const res = await f.publish.publish(AGENT, "ff".repeat(32), f.doc, NOW);
    expect(res).toMatchObject({ ok: false, reason: "document_unknown" });
  });
});

describe("DocumentPublish — the publish NUDGES every other seat (SYNC-P4, R39's first trigger)", () => {
  it("nudges each holder except the sender, once, after the append", async () => {
    const f = newFixture();
    f.publishHolders = [SENDER, PEER, "cc".repeat(32)];
    f.doc.getText("content").insert(0, "deliver me. ");
    await f.publish.publish(AGENT, DOC, f.doc, NOW);
    // No ledger and no worker: the nudge — an initiated reconcile per seat — is how the envelope
    // travels, and the envelope itself is in the log for any later exchange to carry.
    expect(f.nudged).toEqual([[PEER, "cc".repeat(32)]]);
    expect(f.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(1);
  });

  it("a refused publish nudges nobody", async () => {
    const f = newFixture();
    f.publishHolders = null;
    f.doc.getText("content").insert(0, "never leaves. ");
    const res = await f.publish.publish(AGENT, DOC, f.doc, NOW);
    expect(res.ok).toBe(false);
    expect(f.nudged).toEqual([]);
  });
});
