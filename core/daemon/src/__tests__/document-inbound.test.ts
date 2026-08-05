/**
 * DOD-DOC-INBOUND-1 — the receiving half (§3.2, §14, §16.4).
 *
 * Every P2 unit built a piece of this: ENVELOPE-1 decodes and verifies the chain link, GATE-1
 * decides, REJECT-1 records a refusal, ENGINE-1 applies. Nothing owned assembling them, and the
 * ORDER they run in is the whole security property — a step done after admission is a step that
 * did not protect anything.
 *
 * `node:sqlite` here is the test-file allowance; production is SQLCipher.
 */

import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import * as Y from "yjs";
import {
  encodeDocumentUpdateEnvelope,
  documentEnvelopeHash,
  DOCUMENT_UPDATE_ENCODING_V1,
  DOCUMENT_EPOCH_V1,
  type DocumentUpdateEnvelope,
} from "@cello-protocol/protocol-types";
import { DocumentStore } from "../document-store.js";
import { DocumentEngine } from "../document-engine.js";
import { DocumentGate } from "../document-gate.js";
import { DocumentRejections } from "../document-rejection.js";
import { DocumentInbound } from "../document-inbound.js";
import type { Logger } from "../types.js";

const AGENT = "owner-agent";
const PEER = "peer-agent";
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

/** A real Yjs update from a pinned clientID, so sizes and order are not a coin flip. */
function update(clientId: number, text: string, base?: Uint8Array): Uint8Array {
  const d = new Y.Doc();
  d.clientID = clientId;
  if (base) Y.applyUpdate(d, base);
  d.getText("content").insert(d.getText("content").length, text);
  return base ? Y.diffUpdate(Y.encodeStateAsUpdate(d), Y.encodeStateVector(new Y.Doc())) : Y.encodeStateAsUpdate(d);
}

const PEER_CLIENT = 4242;

function envelope(over: Partial<DocumentUpdateEnvelope> = {}): DocumentUpdateEnvelope {
  return {
    type: "document_update",
    document_id: DOC,
    epoch_id: DOCUMENT_EPOCH_V1,
    doc_prev_hash: null,
    sender_agent_id: PEER,
    sender_client_id: PEER_CLIENT,
    update_encoding: DOCUMENT_UPDATE_ENCODING_V1,
    state_vector: new Uint8Array([0]),
    update: update(PEER_CLIENT, "peer text. "),
    signature: new Uint8Array(64).fill(3),
    ...over,
  };
}

function newFixture(opts: { verify?: () => boolean } = {}) {
  const { logger, events } = recordingLogger();
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  const store = new DocumentStore(db, logger);
  store.createDocument({
    documentId: DOC, ownerAgentId: AGENT, peerAgentId: PEER, documentType: "markdown",
    properties: {}, status: "active", createdAtMs: 1,
  });
  const engine = new DocumentEngine(logger);
  const gate = new DocumentGate(engine, {}, logger);
  const rejections = new DocumentRejections(store, logger);
  const live = new Y.Doc();
  live.clientID = 9999;

  const inbound = new DocumentInbound({
    store, engine, gate, rejections, logger,
    verifySignature: opts.verify ?? (() => true),
    liveDocFor: () => live,
    boundClientIds: () => [PEER_CLIENT],
    crypto: () => ({
      signature: new Uint8Array(64).fill(1),
      stateVector: new Uint8Array([0]),
      nonce: `n${Math.floor(NOW)}`,
    }),
  });
  return { inbound, store, engine, live, events, logger };
}

describe("DocumentInbound — an admitted envelope lands, and is acked", () => {
  it("appends it, applies it, and reports admitted", () => {
    const f = newFixture();
    const env = envelope();

    const res = f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(env), NOW);
    expect(res).toMatchObject({ ok: true, admitted: true });
    expect(f.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(1);
    expect(f.live.getText("content").toString()).toContain("peer text");
  });

  it("the ack names the envelope, so the sender can settle the right one", () => {
    const f = newFixture();
    const env = envelope();
    const res = f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(env), NOW);
    // An ack that does not identify what it acknowledges cannot settle anything — the sender has
    // a backlog, not a single outstanding envelope.
    expect((res as { envelopeHash: string }).envelopeHash).toBe(documentEnvelopeHash(env));
  });
});

describe("DocumentInbound — the ORDER is the security property", () => {
  it("REFUSES an envelope whose signature does not verify, and applies NOTHING", () => {
    const f = newFixture({ verify: () => false });
    const res = f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(envelope()), NOW);

    expect(res).toMatchObject({ ok: false, reason: "document_signature_invalid" });
    // Not admitted, not logged, not applied, and NOT rejected either: a rejection is a protocol
    // act that presumes an authenticated counterparty. An unsigned envelope has no counterparty.
    expect(f.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(0);
    expect(f.live.getText("content").toString()).toBe("");
    expect(f.store.listQuarantined(AGENT, DOC)).toHaveLength(0);
  });

  it("verifies the signature BEFORE the gate — an unsigned envelope never reaches the rules", () => {
    const order: string[] = [];
    const f = newFixture({
      verify: () => {
        order.push("verify");
        return false;
      },
    });
    f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(envelope()), NOW);
    // The gate runs pluggable rules over peer-controlled bytes. Running them first would mean the
    // rules — and eventually screening — process input from a party we have not authenticated.
    expect(order).toEqual(["verify"]);
  });

  it("refuses a malformed envelope by name, before anything else happens", () => {
    const f = newFixture();
    const res = f.inbound.receive(AGENT, new Uint8Array([1, 2, 3]), NOW);
    expect(res).toMatchObject({ ok: false });
    // Wrapped, not passed through raw: a lib0/CBOR decoder message names library internals and
    // reads as a crash, not a protocol refusal.
    expect((res as { reason: string }).reason).toBe("document_inbound_malformed");
    expect(f.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(0);
  });

  it("refuses an envelope for a document this agent does not have", () => {
    const f = newFixture();
    const res = f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(envelope({ document_id: "ab".repeat(32) })), NOW);
    expect(res).toMatchObject({ ok: false, reason: "document_unknown" });
  });

  it("refuses an envelope from someone who is not this document's peer", () => {
    const f = newFixture();
    const res = f.inbound.receive(
      AGENT,
      encodeDocumentUpdateEnvelope(envelope({ sender_agent_id: "a-stranger" })),
      NOW,
    );
    // The document is a pairwise agreement. A third party's envelope is not a rejection case —
    // there is no collaboration to supersede — it simply does not belong here.
    expect(res).toMatchObject({ ok: false, reason: "document_sender_not_peer" });
    expect(f.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(0);
  });
});

describe("DocumentInbound — a chain gap refuses; a REDELIVERY is benign", () => {
  it("acks a redelivered envelope without applying it twice", () => {
    const f = newFixture();
    const wire = encodeDocumentUpdateEnvelope(envelope());

    expect(f.inbound.receive(AGENT, wire, NOW)).toMatchObject({ ok: true, admitted: true });
    const second = f.inbound.receive(AGENT, wire, NOW + 1);

    // Delivery retries across restarts by design, so a redelivery is expected traffic. It must ack
    // — otherwise the sender never settles it — and it must not append or apply a second time.
    expect(second).toMatchObject({ ok: true, admitted: true, duplicate: true });
    expect(f.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(1);
  });

  it("REFUSES an envelope that chains to something we have never seen", () => {
    const f = newFixture();
    const res = f.inbound.receive(
      AGENT,
      encodeDocumentUpdateEnvelope(envelope({ doc_prev_hash: "ee".repeat(32) })),
      NOW,
    );
    expect(res).toMatchObject({ ok: false });
    expect((res as { reason: string }).reason).toBe("document_chain_broken");
    expect(f.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(0);
  });
});

describe("DocumentInbound — a gate refusal becomes a REJECTION, and the ack says so", () => {
  it("quarantines the bytes, writes the 0x05 leaf, and acks as NOT admitted", () => {
    const f = newFixture();
    // Seed an accepted base so the peer's update can delete from it.
    const base = envelope({ update: update(PEER_CLIENT, "original content. ") });
    f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(base), NOW);
    f.store.setDocumentProperties?.(AGENT, DOC, { append_only: true });

    const deleting = new Y.Doc();
    deleting.clientID = PEER_CLIENT;
    Y.applyUpdate(deleting, base.update);
    deleting.getText("content").delete(0, 8);
    const env = envelope({
      update: Y.encodeStateAsUpdate(deleting),
      doc_prev_hash: documentEnvelopeHash(base),
    });

    const res = f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(env), NOW + 1, {
      appendOnly: true,
    });
    // A rejection IS an ack for delivery purposes — the peer has decided, so the sender must stop
    // retrying and supersede instead.
    expect(res).toMatchObject({ ok: true, admitted: false });
    expect((res as { rejectionReason: string }).rejectionReason).toMatch(/append_only/);
    expect(f.store.listQuarantined(AGENT, DOC)).toHaveLength(1);
  });

  it("does NOT apply a refused update to the live document", () => {
    const f = newFixture();
    const base = envelope({ update: update(PEER_CLIENT, "original content. ") });
    f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(base), NOW);
    const before = f.live.getText("content").toString();

    const deleting = new Y.Doc();
    deleting.clientID = PEER_CLIENT;
    Y.applyUpdate(deleting, base.update);
    deleting.getText("content").delete(0, 8);
    f.inbound.receive(
      AGENT,
      encodeDocumentUpdateEnvelope(
        envelope({ update: Y.encodeStateAsUpdate(deleting), doc_prev_hash: documentEnvelopeHash(base) }),
      ),
      NOW + 1,
      { appendOnly: true },
    );

    // The whole point of the gate is that refused content never lands. Applying and then recording
    // a rejection would leave the refusal as an annotation on content the operator already has.
    expect(f.live.getText("content").toString()).toBe(before);
  });
});
