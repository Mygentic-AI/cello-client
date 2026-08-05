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
import { generateKeypair, verify as verifyEd25519 } from "@cello-protocol/crypto";
import {
  encodeDocumentUpdateEnvelope,
  encodeDocumentProposal,
  buildDocumentProposalTbs,
  documentIdFromProposal,
  DOCUMENT_FEATURE_VERSION,
  ASSURANCE_TIER_V1,
  TOPOLOGY_V1,
  type DocumentProposalEnvelope,
} from "@cello-protocol/protocol-types";
import { createDocumentLayer, agentPublicKeyFromId } from "../document-layer.js";
import { DocumentPublish } from "../document-publish.js";
import { createDocumentDeliveryTransport } from "../document-delivery-transport.js";
import { DocumentDelivery } from "../document-delivery.js";
import { DocumentHandshake } from "../document-handshake.js";
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
    ownerKeyFor: (agentName) => (agentName === name ? id : null),
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
  return { name, id, layer, publish, workingDoc, events, logger, db, sign: keys.sign.bind(keys) };
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

/**
 * Drive the REAL delivery worker, with only the wire stubbed.
 *
 * The hand-rolled loop below reads the log and hands frames over directly. This one goes through
 * `DocumentDelivery` and `createDocumentDeliveryTransport` — so the pending derivation, the
 * reachability check, session reuse, the ack accounting and the backoff are all the production code
 * paths, and the only thing replaced is the transport's bytes-on-a-socket.
 *
 * The peer's REAL verdict comes back as the ack, which is what closes the loop: `admitted` is
 * whatever their inbound path actually decided, not a stub's guess.
 */
function deliveryFor(
  from: Awaited<ReturnType<typeof makeParty>>,
  to: Awaited<ReturnType<typeof makeParty>>,
  opts: { reachable?: () => boolean; swallowAck?: boolean } = {},
) {
  const sent: string[] = [];
  const transport = createDocumentDeliveryTransport({
    agentName: from.id,
    logger: from.logger,
    lookupPeer: async () => ({
      kind: "result",
      state: (opts.reachable?.() ?? true) ? "online" : "offline",
      owningNodeIds: ["node-1"],
    }),
    // One long-lived session already open with this peer — the reuse path, which is what a real
    // daemon takes for every delivery after the first.
    activeSessionsWith: () => ["session-1"],
    openSession: async () => ({ ok: true, sessionId: "session-1" }),
    sealSession: async () => {},
    sendContent: async (_agent, _session, content) => {
      sent.push(Buffer.from(content).toString("hex").slice(0, 16));
      // THE WIRE. Everything either side of this is production code.
      const verdict = await to.layer.router.route(to.id, content, Date.now(), "wire");
      lastVerdict = verdict;
      return { ok: true, delivered: true };
    },
    encodeEnvelope: (envelope) => {
      const bytes = encodeDocumentUpdateEnvelope({
        type: "document_update",
        document_id: envelope.documentId,
        epoch_id: envelope.epochId,
        doc_prev_hash: envelope.docPrevHash,
        sender_agent_id: envelope.senderAgentId,
        sender_client_id: envelope.senderClientId!,
        update_encoding: "yjs-v1",
        state_vector: envelope.stateVector,
        update: envelope.payload!,
        signature: envelope.signature,
      });
      return { bytes, hash: new Uint8Array(32) };
    },
  });

  let lastVerdict: { consumed: boolean; ok?: boolean } = { consumed: false };
  // The peer answered synchronously in-process, so the ack is available by the time deliver
  // returns. A real transport waits for the ack frame; the SHAPE is the same three-valued outcome.
  const acking = {
    ...transport,
    deliver: async (input: Parameters<typeof transport.deliver>[0]) => {
      const res = await transport.deliver(input);
      if (!res.ok) return res;
      // `swallowAck` models the ordinary store-and-forward failure: the content left, and the
      // answer did not come back. `admitted: null` is SENT-not-acked.
      if (opts.swallowAck === true) return { ...res, admitted: null };
      return { ...res, admitted: lastVerdict.ok === true };
    },
  };
  return {
    worker: new DocumentDelivery(from.layer.store, acking, from.logger),
    sent,
    tick: (nowMs: number) =>
      new DocumentDelivery(from.layer.store, acking, from.logger).tick(
        from.id,
        () => to.id,
        nowMs,
        { senderAgentId: from.id },
      ),
  };
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


describe("M14 round trip — through the REAL delivery worker", () => {
  it("publishes, delivers, and the peer admits — with the ack settling the envelope", async () => {
    const a = await makeParty("A", 6001);
    const b = await makeParty("B", 6002);
    await openDocument(a, b);

    const docA = a.workingDoc(a.id);
    docA.getText("content").insert(0, "through the worker. ");
    await a.publish.publish(a.id, DOC, docA, NOW);

    const delivery = deliveryFor(a, b);
    const result = await delivery.tick(NOW);

    expect(result).toMatchObject({ attempted: 1, delivered: 1 });
    expect(b.layer.live.get(b.id, DOC).getText("content").toString()).toBe("through the worker. ");
    // The ack settled it: nothing is pending, so the worker will not re-send. That is the property
    // that makes delivery terminate rather than loop.
    expect(a.layer.store.pendingDeliveries(a.id, NOW + 10_000_000, a.id)).toHaveLength(0);
  });

  it("does not DIAL an unreachable peer, and delivers once it is back", async () => {
    const a = await makeParty("A", 7001);
    const b = await makeParty("B", 7002);
    await openDocument(a, b);

    const docA = a.workingDoc(a.id);
    docA.getText("content").insert(0, "written while they were away. ");
    await a.publish.publish(a.id, DOC, docA, NOW);

    let online = false;
    const delivery = deliveryFor(a, b, { reachable: () => online });
    const away = await delivery.tick(NOW);
    expect(away).toMatchObject({ attempted: 0, deferred: 1 });
    expect(delivery.sent).toEqual([]);

    // The peer comes back. The envelope is still pending because it was deferred, not dropped —
    // the log is the queue, so nothing was held in memory to lose.
    online = true;
    const back = await delivery.tick(NOW + 10_000_000);
    expect(back).toMatchObject({ delivered: 1 });
    expect(b.layer.live.get(b.id, DOC).getText("content").toString()).toBe(
      "written while they were away. ",
    );
  });

  it("a LOST ACK re-sends, and the peer treats the redelivery as a duplicate", async () => {
    const a = await makeParty("A", 8001);
    const b = await makeParty("B", 8002);
    await openDocument(a, b);

    const docA = a.workingDoc(a.id);
    docA.getText("content").insert(0, "once. ");
    await a.publish.publish(a.id, DOC, docA, NOW);

    // The ack never comes back — the transport reports SENT, not acked. This is the ordinary
    // failure a store-and-forward path produces, not an exotic one.
    const delivery = deliveryFor(a, b, { swallowAck: true });
    const first = await delivery.tick(NOW);
    expect(first).toMatchObject({ sent: 1, delivered: 0 });
    expect(delivery.sent).toHaveLength(1);
    // Still pending, because SENT is not ACKED — that distinction is the whole reason the outcome
    // is three-valued.
    expect(a.layer.store.pendingDeliveries(a.id, NOW + 10_000_000, a.id)).toHaveLength(1);

    const second = await delivery.tick(NOW + 10_000_000);
    expect(delivery.sent).toHaveLength(2);
    void second;

    // The peer received the SAME envelope twice and must hold it once. A second admission would
    // double the text; a refusal would strand a delivery that was correct.
    expect(b.layer.store.getEnvelopeLog(b.id, DOC)).toHaveLength(1);
    expect(b.layer.live.get(b.id, DOC).getText("content").toString()).toBe("once. ");
  });
});


describe("M14 round trip — through the REAL handshake", () => {
  it("proposes, consents, and both sides mint the SAME document", async () => {
    const a = await makeParty("A", 9001);
    const b = await makeParty("B", 9002);

    // Both sides verify a proposal against the proposer's real key. M14-D5 makes the id the key, so
    // there is no lookup to get wrong.
    const handshakeFor = (party: Awaited<ReturnType<typeof makeParty>>) =>
      new DocumentHandshake(party.db, party.logger, (proposerId, tbs, sig) => {
        const key = agentPublicKeyFromId(proposerId);
        return key !== null && verifyEd25519(key, tbs, sig);
      });
    const handshakeB = handshakeFor(b);

    const base: DocumentProposalEnvelope = {
      type: "document_proposal",
      feature_version: DOCUMENT_FEATURE_VERSION,
      proposer_agent_id: a.id,
      peer_agent_id: b.id,
      document_type: "markdown",
      properties: {
        assurance_tier: ASSURANCE_TIER_V1,
        schema_enforcement: false,
        topology: TOPOLOGY_V1,
        append_only: false,
      },
      starting_content: null,
      nonce: new Uint8Array([1, 2, 3, 4]),
      proposed_at_ms: NOW,
      signature: new Uint8Array(64),
    };
    const proposal = { ...base, signature: await a.sign(buildDocumentProposalTbs(base)) };
    const documentId = documentIdFromProposal(proposal);

    // B receives it, sees it pending, and accepts.
    const recorded = handshakeB.recordProposal(b.id, encodeDocumentProposal(proposal), NOW);
    expect(recorded).toMatchObject({ state: "pending", documentId });
    expect(handshakeB.pending(b.id)).toHaveLength(1);
    const accepted = handshakeB.accept(b.id, documentId, NOW + 1);
    expect(accepted.ok).toBe(true);

    // Both mint from the AGREED terms. The id is the hash of the proposal, so neither side chose
    // it and there was no coordination round — that is what makes it federated.
    for (const [self, peer] of [[a, b], [b, a]] as const) {
      self.layer.store.createDocument({
        documentId,
        ownerAgentId: self.id,
        peerAgentId: peer.id,
        documentType: proposal.document_type,
        properties: proposal.properties as unknown as Record<string, unknown>,
        status: "active",
        createdAtMs: NOW + 1,
      });
    }
    expect(a.layer.store.getDocument(a.id, documentId)).not.toBeNull();
    expect(b.layer.store.getDocument(b.id, documentId)).not.toBeNull();
    // Independently computed, never transmitted as a value.
    expect(documentIdFromProposal(handshakeB.get(b.id, documentId)!.envelope)).toBe(documentId);
  });

  it("REFUSES a proposal signed by someone other than its proposer", async () => {
    const a = await makeParty("A", 9101);
    const b = await makeParty("B", 9102);
    const impostor = await makeParty("C", 9103);

    const handshakeB = new DocumentHandshake(b.db, b.logger, (proposerId, tbs, sig) => {
      const key = agentPublicKeyFromId(proposerId);
      return key !== null && verifyEd25519(key, tbs, sig);
    });

    const base: DocumentProposalEnvelope = {
      type: "document_proposal",
      feature_version: DOCUMENT_FEATURE_VERSION,
      proposer_agent_id: a.id, // CLAIMS to be A
      peer_agent_id: b.id,
      document_type: "markdown",
      properties: {
        assurance_tier: ASSURANCE_TIER_V1,
        schema_enforcement: false,
        topology: TOPOLOGY_V1,
        append_only: false,
      },
      starting_content: null,
      nonce: new Uint8Array([9]),
      proposed_at_ms: NOW,
      signature: new Uint8Array(64),
    };
    // …but signed by C. Admitting this would put a consent decision in front of an operator for a
    // collaboration the named party never asked for, and ON CONFLICT DO NOTHING would make those
    // bytes the permanent record for that document_id.
    const forged = { ...base, signature: await impostor.sign(buildDocumentProposalTbs(base)) };

    expect(() => handshakeB.recordProposal(b.id, encodeDocumentProposal(forged), NOW)).toThrow(
      /document_proposal_signature_invalid/,
    );
    expect(handshakeB.pending(b.id)).toHaveLength(0);
  });
});
