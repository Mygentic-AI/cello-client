/**
 * DOD-DOC-TOOLS-1 — the operator surface.
 *
 * This is the reachability proof for the whole document layer. Everything below it was built and
 * tested and none of it was reachable: nothing in production called `createDocument`, so no document
 * existed, so the delivery sweep swept nothing and the inbound path had nothing addressed to it. A
 * complete unreachable layer reads exactly like a working one, so what is pinned here is that each
 * verb REACHES the unit behind it — a real row, a real signed envelope, a real send.
 *
 * `node:sqlite` here is the test-file allowance; production is SQLCipher.
 */

import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { Buffer } from "node:buffer";
import * as Y from "yjs";
import { generateKeypair, verify } from "@cello-protocol/crypto";
import {
  decodeDocumentProposal,
  buildDocumentProposalTbs,
  encodeDocumentProposal,
  documentIdFromProposal,
  type DocumentProposalEnvelope,
} from "@cello-protocol/protocol-types";
import { registerDocumentHandlers } from "../document-handlers.js";
import { createDocumentLayer, agentPublicKeyFromId } from "../document-layer.js";
import { DocumentPublish } from "../document-publish.js";
import type { IpcHandler } from "../ipc-server.js";
import type { DocumentDeliveryTransport } from "../document-delivery.js";
import type { Logger } from "../types.js";

const AGENT = "owner-agent";
const CONN = "conn-1";
const NOW = 1_700_000_000_000;

function silentLogger(): Logger {
  const noop = () => {};
  const logger = { debug: noop, info: noop, warn: noop, error: noop, child: () => logger } as unknown as Logger;
  return logger;
}

async function newFixture(opts: { sendFails?: string } = {}) {
  /** Mutable so a test can fail the first send and succeed the retry — the real recovery sequence. */
  let sendFails = opts.sendFails;
  const keys = generateKeypair();
  const owner = Buffer.from(await keys.getPublicKey()).toString("hex");
  const peerKeys = generateKeypair();
  const peer = Buffer.from(await peerKeys.getPublicKey()).toString("hex");

  const logger = silentLogger();
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");

  const layer = createDocumentLayer({
    db,
    logger,
    publicKeyFor: agentPublicKeyFromId,
    ownerKeyFor: (agentName) => (agentName === AGENT ? owner : null),
    notifyPeer: async () => ({ ok: true }),
    rollback: () => ({ ok: true }),
    sign: async (_owner, tbs) => keys.sign(tbs),
  });

  /** Every byte the surface handed to the transport, so a "sent" claim can be checked. */
  const sent: Array<{ peerAgentId: string; bytes: Uint8Array }> = [];
  const transport = {
    isPeerReachable: async () => ({ reachable: true, unknownAgent: false }),
    sendBytes: async (input: { peerAgentId: string; bytes: Uint8Array }) => {
      sent.push({ peerAgentId: input.peerAgentId, bytes: input.bytes });
      if (sendFails) return { ok: false as const, reason: sendFails };
      return { ok: true as const, sessionId: "session-1", sessionOpened: true };
    },
    deliver: async () => ({ ok: true as const, sessionId: "s", sessionOpened: false, admitted: null }),
  } satisfies DocumentDeliveryTransport;

  const handlers = new Map<string, IpcHandler>();
  registerDocumentHandlers({
    handlers,
    logger,
    layer,
    publish: new DocumentPublish({
      store: layer.store,
      engine: layer.engine,
      logger,
      sign: async (_o, tbs) => keys.sign(tbs),
      senderIdFor: (o) => o,
      canPublish: (o, d) => layer.lifecycle.canPublish(o, d),
    }),
    transportFor: () => transport,
    resolveAgent: (_c, explicit) => explicit ?? AGENT,
    ownerKeyFor: (agentName) => (agentName === AGENT ? owner : null),
    sign: async (_agentName, tbs) => keys.sign(tbs),
    now: () => NOW,
  });

  const call = (verb: string, params: Record<string, unknown> = {}) =>
    handlers.get(verb)!(params, CONN) as Promise<Record<string, unknown>>;

  /** A proposal FROM the peer, correctly signed, as it would arrive on the wire. */
  const incomingProposal = async (over: Partial<DocumentProposalEnvelope> = {}) => {
    const base: DocumentProposalEnvelope = {
      type: "document_proposal",
      feature_version: 1,
      proposer_agent_id: peer,
      peer_agent_id: owner,
      document_type: "markdown",
      properties: {
        assurance_tier: "authenticated",
        schema_enforcement: false,
        topology: "hub-and-spoke",
        append_only: false,
      },
      starting_content: null,
      nonce: new Uint8Array([9, 9, 9]),
      proposed_at_ms: NOW,
      signature: new Uint8Array(64),
      ...over,
    };
    return { ...base, signature: await peerKeys.sign(buildDocumentProposalTbs(base)) };
  };

  return {
    call, layer, sent, owner, peer, incomingProposal,
    peerComesOnline: () => {
      sendFails = undefined;
    },
  };
}

describe("cello_doc_propose — a document exists and the offer leaves", () => {
  it("creates the local document AND sends a proposal the peer can verify", async () => {
    const f = await newFixture();
    const res = await f.call("cello_doc_propose", { peer_pubkey: f.peer, starting_content: "# Draft\n" });

    expect(res).toMatchObject({ ok: true, proposalSent: true });
    const documentId = res.documentId as string;

    // THE ROW. Before this handler existed nothing in production reached createDocument, so the
    // delivery sweep was a no-op by construction.
    expect(f.layer.store.getDocument(f.owner, documentId)).toMatchObject({ peerAgentId: f.peer });

    // THE WIRE. Decoded and verified the way the peer will, because "sent" is worth nothing if what
    // left cannot be authenticated — an unverifiable proposal is refused at the far end and the
    // operator waits forever for a consent decision nobody was asked to make.
    expect(f.sent).toHaveLength(1);
    const envelope = decodeDocumentProposal(f.sent[0]!.bytes);
    expect(
      await verify(agentPublicKeyFromId(f.owner)!, buildDocumentProposalTbs(envelope), envelope.signature),
    ).toBe(true);
    expect(documentIdFromProposal(envelope)).toBe(documentId);
    expect(envelope.peer_agent_id).toBe(f.peer);
  });

  it("puts the STARTING CONTENT on the wire as bytes both sides apply", async () => {
    const f = await newFixture();
    const res = await f.call("cello_doc_propose", { peer_pubkey: f.peer, starting_content: "shared start" });
    const envelope = decodeDocumentProposal(f.sent[0]!.bytes);

    // Not a string. Each side building its own doc from the same template produces two documents
    // that look identical and never converge — different client ids, different item ids.
    expect(envelope.starting_content).not.toBeNull();
    const theirs = new Y.Doc();
    Y.applyUpdate(theirs, envelope.starting_content!);
    expect(theirs.getText("content").toString()).toBe("shared start");
    // And OUR copy holds the same text, from the same bytes.
    expect(f.layer.live.get(f.owner, res.documentId as string).getText("content").toString()).toBe("shared start");
  });

  it("REPORTS BOTH FACTS when the peer is unreachable: the document exists, the offer did not land", async () => {
    const f = await newFixture({ sendFails: "peer_offline" });
    const res = await f.call("cello_doc_propose", { peer_pubkey: f.peer });

    // Reporting only the failure would hide a real local row; reporting only success would have the
    // operator wait for a decision the peer was never asked to make.
    expect(res).toMatchObject({ ok: true, proposalSent: false, reason: "peer_offline" });
    expect(f.layer.store.getDocument(f.owner, res.documentId as string)).not.toBeNull();
    // And the guidance names the recovery that actually exists, with the id needed to run it.
    expect(String(res.guidance)).toContain(res.documentId as string);
  });

  it("RE-SENDS the same offer rather than minting a second document", async () => {
    const f = await newFixture({ sendFails: "peer_offline" });
    const first = await f.call("cello_doc_propose", { peer_pubkey: f.peer, starting_content: "one" });
    const documentId = first.documentId as string;

    f.peerComesOnline();
    const retry = await f.call("cello_doc_propose", { document_id: documentId });
    // Same id, same bytes. A fresh proposal would carry a new nonce, hence a new document_id, hence
    // a second document — leaving the first an orphan the operator cannot explain or clear.
    expect(retry).toMatchObject({ documentId });
    expect(f.sent).toHaveLength(2);
    expect(Buffer.from(f.sent[1]!.bytes).equals(Buffer.from(f.sent[0]!.bytes))).toBe(true);
  });

  it("refuses to retry a proposal this agent did not author", async () => {
    const f = await newFixture();
    const env = await f.incomingProposal();
    f.layer.handshake.recordProposal(f.owner, encodeDocumentProposal(env), NOW);

    // Their offer to us is in the same table. Re-sending it would put OUR agent's name behind a
    // proposal the peer authored, addressed to ourselves.
    const res = await f.call("cello_doc_propose", { document_id: documentIdFromProposal(env) });
    expect(res).toMatchObject({ ok: false, reason: "document_proposal_not_ours" });
  });

  it("refuses a document with itself", async () => {
    const f = await newFixture();
    const res = await f.call("cello_doc_propose", { peer_pubkey: f.owner });
    // Every downstream unit would treat it as a real peer, including the delivery worker — which
    // would dial the daemon it is running in.
    expect(res).toMatchObject({ ok: false, reason: "document_peer_is_self" });
    expect(f.sent).toHaveLength(0);
  });
});

describe("cello_doc_accept — consent and the document are ONE act", () => {
  it("creates the document, so the peer's first update is not refused as unknown", async () => {
    const f = await newFixture();
    const env = await f.incomingProposal({ starting_content: null });
    const documentId = f.layer.handshake.recordProposal(f.owner, encodeDocumentProposal(env), NOW).documentId;

    expect(await f.call("cello_doc_inbox")).toMatchObject({
      proposals: [{ documentId, proposerAgentId: f.peer }],
    });

    const res = await f.call("cello_doc_accept", { document_id: documentId });
    expect(res).toMatchObject({ ok: true, peerAgentId: f.peer });
    // Without this row the operator has agreed to a document that does not exist, and the peer's
    // first update is refused as `document_unknown` — a refusal naming a real condition and
    // explaining nothing.
    expect(f.layer.store.getDocument(f.owner, documentId)).toMatchObject({ peerAgentId: f.peer });
  });

  it("a refused proposal creates nothing", async () => {
    const f = await newFixture();
    const env = await f.incomingProposal();
    const documentId = f.layer.handshake.recordProposal(f.owner, encodeDocumentProposal(env), NOW).documentId;

    expect(await f.call("cello_doc_refuse", { document_id: documentId, reason: "not now" })).toMatchObject({ ok: true });
    expect(f.layer.store.getDocument(f.owner, documentId)).toBeNull();
    // And the decision is made once.
    expect(await f.call("cello_doc_accept", { document_id: documentId })).toMatchObject({
      ok: false,
      reason: "document_proposal_not_pending",
    });
  });
});

describe("cello_doc_write — the edit is applied and published", () => {
  it("writes a signed envelope into the log the delivery worker reads", async () => {
    const f = await newFixture();
    const documentId = (await f.call("cello_doc_propose", { peer_pubkey: f.peer })).documentId as string;

    const res = await f.call("cello_doc_write", { document_id: documentId, content: "the whole document" });
    expect(res).toMatchObject({ ok: true, changed: true, published: true });
    expect(await f.call("cello_doc_read", { document_id: documentId })).toMatchObject({
      content: "the whole document",
    });
    // Pending delivery is derived FROM THE LOG, so this is the whole of publishing.
    expect(f.layer.store.pendingDeliveries(f.owner, NOW, f.owner)).toHaveLength(1);
  });

  it("an unchanged write publishes NOTHING", async () => {
    const f = await newFixture();
    const documentId = (await f.call("cello_doc_propose", { peer_pubkey: f.peer, starting_content: "same" })).documentId as string;

    const res = await f.call("cello_doc_write", { document_id: documentId, content: "same" });
    // Publishing anyway would append a leaf, cost a delivery, and converge nothing.
    expect(res).toMatchObject({ ok: true, changed: false, published: false });
    expect(f.layer.store.pendingDeliveries(f.owner, NOW, f.owner)).toHaveLength(0);
  });

  it("REFUSES a patch-shaped call rather than treating a fragment as the document", async () => {
    const f = await newFixture();
    const documentId = (await f.call("cello_doc_propose", { peer_pubkey: f.peer, starting_content: "keep me" })).documentId as string;

    const res = await f.call("cello_doc_write", { document_id: documentId, content: 42 });
    expect(res).toMatchObject({ ok: false, reason: "invalid_content" });
    // The document is untouched. A coerced non-string would have replaced the whole text with "42"
    // and published that as a legitimate signed edit.
    expect(await f.call("cello_doc_read", { document_id: documentId })).toMatchObject({ content: "keep me" });
  });

  it("reports an applied-but-unpublished edit as exactly that", async () => {
    const f = await newFixture();
    const documentId = (await f.call("cello_doc_propose", { peer_pubkey: f.peer })).documentId as string;
    f.layer.lifecycle.setPlatformPaused(f.owner, true, NOW);

    const res = await f.call("cello_doc_write", { document_id: documentId, content: "written while paused" });
    // NOT ok:false. An operator told the write failed would write it again, and the second write
    // would be a no-op diff against the text already applied — the change silently never leaving.
    expect(res).toMatchObject({ ok: true, changed: true, published: false });
    expect(String(res.reason)).toContain("paused");
  });
});

describe("the surface refuses when it cannot name an agent or a document", () => {
  it("refuses an unknown document rather than materializing an empty one", async () => {
    const f = await newFixture();
    // An empty document handed back here would be written over the peer's real content on the next
    // write, and both sides would converge on the loss.
    expect(await f.call("cello_doc_read", { document_id: "ff".repeat(32) })).toMatchObject({
      ok: false,
      reason: "document_unknown",
    });
  });

  it("refuses a malformed peer key before signing anything", async () => {
    const f = await newFixture();
    expect(await f.call("cello_doc_propose", { peer_pubkey: "not-a-key" })).toMatchObject({
      ok: false,
      reason: "invalid_peer_pubkey",
    });
    expect(f.sent).toHaveLength(0);
  });
});
