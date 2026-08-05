/**
 * M14 — the round trip, on two independent daemons with real Ed25519.
 *
 * Every other document test exercises one side. This is the only one that answers the question the
 * milestone exists for: does an edit made by one operator arrive at the other and converge, through
 * the composed layer, with signatures that actually verify.
 *
 * It is NOT the live enforcer — there is no transport here, no session, no seal (DOD-DOC-E2E-CONV-1
 * owns that with two real daemons). What it does own is everything between publish and admission:
 * signing, the wire encoding, verification against the peer's real key, the gate, the chain, and
 * the materialized result. A bug in any of those is invisible to the per-unit tests, because each
 * of them stubs whatever it does not own.
 *
 * `node:sqlite` here is the test-file allowance; production is SQLCipher.
 */

import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { generateKeypair } from "@cello-protocol/crypto";
import { encodeDocumentUpdateEnvelope } from "@cello-protocol/protocol-types";
import { createDocumentLayer, agentPublicKeyFromId } from "../document-layer.js";
import { DocumentPublish } from "../document-publish.js";
import type { Logger } from "../types.js";

const DOC = "cc".repeat(32);
const NOW = 1_700_000_000_000;

function recordingLogger(): { logger: Logger; events: Array<{ event: string; fields: Record<string, unknown> }> } {
  const events: Array<{ event: string; fields: Record<string, unknown> }> = [];
  const push = (event: string, fields?: Record<string, unknown>) => {
    events.push({ event, fields: fields ?? {} });
  };
  const logger = { debug: push, info: push, warn: push, error: push, child: () => logger } as unknown as Logger;
  return { logger, events };
}

/** One party: its own database, its own key, its own layer. Nothing shared but the wire. */
async function makeParty(name: string, clientId: number) {
  const { logger, events } = recordingLogger();
  const keys = generateKeypair();
  const pubkey = await keys.getPublicKey();
  const id = Buffer.from(pubkey).toString("hex"); // M14-D5
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");

  const layer = createDocumentLayer({
    db,
    logger,
    publicKeyFor: agentPublicKeyFromId,
    notifyPeer: async () => ({ ok: true }),
    rollback: () => ({ ok: true }),
    sign: async (_owner, tbs) => keys.sign(tbs),
  });

  const publish = new DocumentPublish({
    store: layer.store,
    engine: layer.engine,
    logger,
    sign: async (_owner, tbs) => keys.sign(tbs),
    senderIdFor: () => id,
    canPublish: (owner, documentId) => layer.lifecycle.canPublish(owner, documentId),
  });

  // THE WORKING DOCUMENT IS THE LIVE DOCUMENT. There is exactly one Y.Doc per (agent, document),
  // and both editing and publishing use it. Publishing from a separate doc — which this test did
  // first — means an agent's own edits never reach its live document, so a peer's update is applied
  // to a copy missing everything the operator wrote. Both sides then "converge" on different text.
  const workingDoc = (owner: string) => {
    const d = layer.live.get(owner, DOC);
    d.clientID = clientId;
    return d;
  };
  return { name, id, layer, publish, workingDoc, events, logger };
}

async function openDocument(a: Awaited<ReturnType<typeof makeParty>>, b: Awaited<ReturnType<typeof makeParty>>) {
  for (const [self, peer] of [
    [a, b],
    [b, a],
  ] as const) {
    self.layer.store.createDocument({
      documentId: DOC,
      ownerAgentId: self.id,
      peerAgentId: peer.id,
      documentType: "markdown",
      properties: {},
      status: "active",
      createdAtMs: 1,
    });
  }
}

/** Publish everything `from` has pending and hand each frame to `to`, as the wire would. */
async function sync(
  from: Awaited<ReturnType<typeof makeParty>>,
  to: Awaited<ReturnType<typeof makeParty>>,
  nowMs: number,
): Promise<void> {
  for (const row of from.layer.store.pendingDeliveries(from.id, nowMs, from.id)) {
    const wire = encodeDocumentUpdateEnvelope({
      type: "document_update",
      document_id: row.documentId,
      epoch_id: row.epochId,
      doc_prev_hash: row.docPrevHash,
      sender_agent_id: row.senderAgentId,
      sender_client_id: row.senderClientId!,
      update_encoding: "yjs-v1",
      state_vector: row.stateVector,
      update: row.payload!,
      signature: row.signature,
    });
    await to.layer.router.route(to.id, wire, nowMs, "roundtrip");
    from.layer.store.markAcked(from.id, row.documentId, row.envelopeHash, nowMs);
  }
}

describe("M14 round trip — an edit reaches the other side and converges", () => {
  it("carries one operator's text to the other, verified", async () => {
    const a = await makeParty("A", 1001);
    const b = await makeParty("B", 1002);
    await openDocument(a, b);

    const docA = a.workingDoc(a.id);
    docA.getText("content").insert(0, "the agenda, from A. ");
    expect((await a.publish.publish(a.id, DOC, docA, NOW)).ok).toBe(true);
    await sync(a, b, NOW);

    // B's live document — materialized through the composed layer, from a signature verified
    // against A's real key.
    expect(b.layer.live.get(b.id, DOC).getText("content").toString()).toBe("the agenda, from A. ");
  });

  it("converges CONCURRENT edits from both sides", async () => {
    const a = await makeParty("A", 2001);
    const b = await makeParty("B", 2002);
    await openDocument(a, b);

    const docA = a.workingDoc(a.id);
    docA.getText("content").insert(0, "A writes first. ");
    await a.publish.publish(a.id, DOC, docA, NOW);
    await sync(a, b, NOW);

    // Both edit their own live document without having seen the other's next edit.
    const docB = b.workingDoc(b.id);
    docA.getText("content").insert(docA.getText("content").length, "A again. ");
    docB.getText("content").insert(docB.getText("content").length, "B replies. ");

    await a.publish.publish(a.id, DOC, docA, NOW + 1);
    await b.publish.publish(b.id, DOC, docB, NOW + 1);
    await sync(a, b, NOW + 2);
    await sync(b, a, NOW + 2);

    const onA = a.layer.live.get(a.id, DOC).getText("content").toString();
    const onB = b.layer.live.get(b.id, DOC).getText("content").toString();
    // The property the whole CRDT choice buys: both sides hold the same text, whichever order the
    // updates arrived in. Not "A wins" or "last write wins" — the same document.
    expect(onA).toBe(onB);
    expect(onA).toContain("A again.");
    expect(onA).toContain("B replies.");
  });

  it("REFUSES a tampered envelope, and the peer's document is untouched", async () => {
    const a = await makeParty("A", 3001);
    const b = await makeParty("B", 3002);
    await openDocument(a, b);

    const docA = a.workingDoc(a.id);
    docA.getText("content").insert(0, "genuine. ");
    await a.publish.publish(a.id, DOC, docA, NOW);

    const row = a.layer.store.pendingDeliveries(a.id, NOW, a.id)[0]!;
    const forged = new Uint8Array(row.payload!);
    forged[forged.length - 1] ^= 0xff; // the content, not the signature
    const wire = encodeDocumentUpdateEnvelope({
      type: "document_update",
      document_id: row.documentId,
      epoch_id: row.epochId,
      doc_prev_hash: row.docPrevHash,
      sender_agent_id: row.senderAgentId,
      sender_client_id: row.senderClientId!,
      update_encoding: "yjs-v1",
      state_vector: row.stateVector,
      update: forged,
      signature: row.signature,
    });

    const outcome = await b.layer.router.route(b.id, wire, NOW, "tamper");
    // The signature covers the update bytes, so altering the content invalidates it. Nothing is
    // logged, nothing is applied, and B's document does not exist yet at all.
    expect(outcome).toMatchObject({ consumed: true, ok: false, reason: "document_signature_invalid" });
    expect(b.layer.store.getEnvelopeLog(b.id, DOC)).toHaveLength(0);
  });

  it("REFUSES an envelope from a third party, whoever it claims to be", async () => {
    const a = await makeParty("A", 4001);
    const b = await makeParty("B", 4002);
    const stranger = await makeParty("C", 4003);
    await openDocument(a, b);
    stranger.layer.store.createDocument({
      documentId: DOC, ownerAgentId: stranger.id, peerAgentId: b.id, documentType: "markdown",
      properties: {}, status: "active", createdAtMs: 1,
    });

    const docC = stranger.workingDoc(stranger.id);
    docC.getText("content").insert(0, "text from nobody. ");
    await stranger.publish.publish(stranger.id, DOC, docC, NOW);
    const row = stranger.layer.store.pendingDeliveries(stranger.id, NOW, stranger.id)[0]!;
    const wire = encodeDocumentUpdateEnvelope({
      type: "document_update",
      document_id: row.documentId,
      epoch_id: row.epochId,
      doc_prev_hash: row.docPrevHash,
      sender_agent_id: row.senderAgentId,
      sender_client_id: row.senderClientId!,
      update_encoding: "yjs-v1",
      state_vector: row.stateVector,
      update: row.payload!,
      signature: row.signature,
    });

    // Perfectly signed — by the wrong party. A document is a pairwise agreement, so this is not a
    // rejection case; it does not belong here at all.
    const outcome = await b.layer.router.route(b.id, wire, NOW, "stranger");
    expect(outcome).toMatchObject({ consumed: true, ok: false, reason: "document_sender_not_peer" });
    expect(b.layer.store.getEnvelopeLog(b.id, DOC)).toHaveLength(0);
  });

  it("SURVIVES a restart on the receiving side", async () => {
    const a = await makeParty("A", 5001);
    const b = await makeParty("B", 5002);
    await openDocument(a, b);

    const docA = a.workingDoc(a.id);
    docA.getText("content").insert(0, "written before the restart. ");
    await a.publish.publish(a.id, DOC, docA, NOW);
    await sync(a, b, NOW);

    // Evict every live document — the restart, as far as the cache is concerned. The log is what
    // makes the document survivable, and this is the assertion that it does.
    b.layer.live.release(b.id, DOC);
    expect(b.layer.live.get(b.id, DOC).getText("content").toString()).toBe(
      "written before the restart. ",
    );
  });
});
