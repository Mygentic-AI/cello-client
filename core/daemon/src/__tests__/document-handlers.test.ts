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
  DOCUMENT_FEATURE_VERSION,
  decodeDocumentProposal,
  decodeDocumentProposalAck,
  buildDocumentProposalTbs,
  encodeDocumentProposal,
  documentIdFromProposal,
  documentAmendmentHash,
  buildDocumentMultisigTbs,
  encodeDocumentAmendment,
  type DocumentAmendmentBody,
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

async function newFixture(opts: { sendFails?: string } = {}) {
  /** Mutable so a test can fail the first send and succeed the retry — the real recovery sequence. */
  let sendFails = opts.sendFails;
  const keys = generateKeypair();
  const owner = Buffer.from(await keys.getPublicKey()).toString("hex");
  const peerKeys = generateKeypair();
  const peer = Buffer.from(await peerKeys.getPublicKey()).toString("hex");

  /** Event names captured, so operator-notice claims ("the warn IS the surface") are testable. */
  const events: string[] = [];
  const record = (event: string) => { events.push(event); };
  const logger = {
    debug: record, info: record, warn: record, error: record,
  } as unknown as Logger;

  /** Every byte the surface handed to the transport OR the layer, so "sent" can be checked. */
  const sent: Array<{ peerAgentId: string; bytes: Uint8Array }> = [];
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");

  const layer = createDocumentLayer({
    db,
    logger,
    // The layer's own send seam (auto-refusal acks, join answers) — captured in the SAME array
    // the transport writes to, so a test can assert what actually left by either route.
    sendFrame: async (_owner: string, peerAgentId: string, bytes: Uint8Array) => {
      sent.push({ peerAgentId, bytes });
      return { ok: true as const };
    },
    publicKeyFor: agentPublicKeyFromId,
    ownerKeyFor: (agentName) => (agentName === AGENT ? owner : null),
    notifyPeer: async () => ({ ok: true }),
    rollback: () => ({ ok: true }),
    sign: async (_owner, tbs) => keys.sign(tbs),
  });

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
      holdersFor: (o, d) => layer.holdersFor(o, d),
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
      feature_version: DOCUMENT_FEATURE_VERSION,
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
    call, layer, sent, owner, peer, events, db, incomingProposal,
    peerComesOnline: () => {
      sendFails = undefined;
    },
  };
}

/** Drain the router's per-owner async queue by polling the observable outcome. */
async function until(pred: () => boolean): Promise<void> {
  for (let i = 0; i < 100; i++) {
    if (pred()) return;
    await new Promise((r) => setTimeout(r, 10));
  }
  expect(pred()).toBe(true);
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
    // TOPOLOGY-1: the SENT proposal literally carries the mesh default.
    expect(envelope.properties.topology).toBe("mesh");
  });

  it("an ARRIVAL AUTO-REFUSAL answers the proposer — the sentence reaches a human, not just our DB", async () => {
    // TOPOLOGY-1 review F1: a seam/version refusal at arrival wrote its reason to OUR database
    // and answered with silence; the proposer waited forever and read it as a network fault.
    const f = await newFixture();
    const env = await f.incomingProposal({
      properties: {
        assurance_tier: "authenticated",
        schema_enforcement: false,
        topology: "star",
        append_only: false,
      },
    });
    f.layer.onDocumentFrame(AGENT, "session-1", encodeDocumentProposal(env), f.peer);
    await until(() => f.sent.some((s) => s.peerAgentId === f.peer));
    const answer = decodeDocumentProposalAck(f.sent.find((s) => s.peerAgentId === f.peer)!.bytes);
    expect(answer.accepted).toBe(false);
    expect(answer.refusal_reason).toMatch(/document_seam_topology/);
    expect(answer.refusal_reason).toContain("star");
  });

  it("writes the admin choice into the SIGNED proposal — the everyone default EXPLICITLY, never absent", async () => {
    // GOVERN-1: the invitee consents to a stated rule, not a convention. Omitted admins means
    // both parties govern, and that default is recorded in the signed bytes.
    const f = await newFixture();
    await f.call("cello_doc_propose", { peer_pubkey: f.peer });
    const everyone = decodeDocumentProposal(f.sent[0]!.bytes);
    expect(everyone.properties.admin_set).toEqual([f.owner, f.peer].sort());

    const f2 = await newFixture();
    await f2.call("cello_doc_propose", { peer_pubkey: f2.peer, admins: [f2.owner] });
    const solo = decodeDocumentProposal(f2.sent[0]!.bytes);
    expect(solo.properties.admin_set).toEqual([f2.owner]);
  });

  it("the DERIVED arrangement honours the declared admin set — not the everyone default", async () => {
    const f = await newFixture();
    const proposed = await f.call("cello_doc_propose", {
      peer_pubkey: f.peer,
      admins: [f.owner],
    });
    const documentId = proposed.documentId as string;
    const list = await f.call("cello_doc_list", {});
    const row = (list.documents as Array<Record<string, unknown>>).find(
      (d) => d.documentId === documentId,
    )!;
    expect(row.arrangementUnavailable).toBeUndefined();
    expect(row.admins).toEqual([f.owner]);
    expect((row.participants as string[]).sort()).toEqual([f.owner, f.peer].sort());
    // PROPERTIES is the third part of the arrangement G0 named — surfaced and asserted.
    expect((row.properties as Record<string, unknown>).topology).toBe("mesh");
    // And the admin set was DECLARED, not defaulted — the surface can tell them apart.
    expect(row.adminSetDefaulted).toBe(false);
  });

  it("a document whose chain cannot be read degrades ONE row, naming the fault — the list survives", async () => {
    // The blast-radius fix: chain() throws on bytes this build cannot read (a client downgrade
    // past an amendment kind is the reachable case). Uncontained, that took the WHOLE list down
    // and the operator asking "what documents do I have?" got nothing at all.
    const f = await newFixture();
    const healthy = await f.call("cello_doc_propose", { peer_pubkey: f.peer });
    const broken = await f.call("cello_doc_propose", {
      peer_pubkey: f.peer,
      starting_content: "second doc",
    });
    const brokenId = broken.documentId as string;
    f.db
      .prepare(
        `INSERT INTO document_amendments
           (owner_agent_id, document_id, epoch_id, amendment_hash, received_bytes, recorded_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(f.owner, brokenId, 1, "h".repeat(64), Buffer.from([0xff, 0xff, 0xff]), 1);

    const list = await f.call("cello_doc_list", {});
    const rows = list.documents as Array<Record<string, unknown>>;
    expect(rows).toHaveLength(2);
    const ok = rows.find((r) => r.documentId === healthy.documentId)!;
    expect(ok.arrangementUnavailable).toBeUndefined();
    expect((ok.participants as string[]).length).toBe(2);
    // The broken one says WHY, and its membership keys are null — never absent, which a caller
    // coerces to [] and reads as "nobody holds this".
    const bad = rows.find((r) => r.documentId === brokenId)!;
    expect(String(bad.arrangementUnavailable)).toContain("document_chain_undecodable");
    expect(bad.participants).toBeNull();
    expect(bad.admins).toBeNull();
  });

  it("refuses an admin who is not a party — admins are always holders, and nothing is created", async () => {
    const f = await newFixture();
    const res = await f.call("cello_doc_propose", {
      peer_pubkey: f.peer,
      admins: ["f".repeat(64)],
    });
    expect(res).toMatchObject({ ok: false, reason: "document_admins_invalid" });
    expect(f.sent).toHaveLength(0);
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

describe("JOIN-1 — the full join roundtrip, two daemons in process", () => {
  it("invite → offer → inbox → accept → materialized content → answer settled on the inviter", async () => {
    const fA = await newFixture(); // the inviter's daemon
    const fC = await newFixture(); // the invitee's daemon — its own DB, its own keys

    const proposed = await fA.call("cello_doc_propose", {
      peer_pubkey: fA.peer,
      starting_content: "hello from A. ",
    });
    expect(proposed.ok).toBe(true);
    const documentId = proposed.documentId as string;
    await fA.call("cello_doc_write", {
      document_id: documentId,
      content: "hello from A. plus an edit worth carrying. ",
    });

    const invited = await fA.call("cello_doc_invite", {
      document_id: documentId,
      invitee_pubkey: fC.owner,
    });
    expect(invited).toMatchObject({ ok: true, offerSent: true, epochId: 1 });

    // The offer crossed A's transport addressed to C; C receives it on the session channel and
    // the router queues the validation.
    const offerSend = fA.sent.find((s) => s.peerAgentId === fC.owner);
    expect(offerSend).toBeDefined();
    const routed = fC.layer.onDocumentFrame(AGENT, "session-1", offerSend!.bytes, fA.owner);
    expect(routed.consumed).toBe(true);
    await until(() => fC.layer.joins.pendingFor(fC.owner).length === 1);

    const inbox = await fC.call("cello_doc_inbox");
    expect((inbox.joins as Array<{ documentId: string }>)[0]?.documentId).toBe(documentId);

    // C consents BY DERIVING — the accept re-replays the carried bytes.
    const accepted = await fC.call("cello_doc_accept", { document_id: documentId });
    expect(accepted).toMatchObject({ ok: true, joined: true });
    expect(accepted.appliedEnvelopes as number).toBeGreaterThanOrEqual(1);

    // C's copy carries A's content, rebuilt from the snapshot, and both derive epoch 1.
    expect(fC.layer.live.get(fC.owner, documentId).getText("content").toString()).toContain(
      "hello from A",
    );
    expect(fC.layer.store.currentDocumentEpoch(fC.owner, documentId)).toBe(1);
    expect(fA.layer.store.currentDocumentEpoch(fA.owner, documentId)).toBe(1);

    // C's signed answer reaches A and settles the offer — consent recorded on both sides.
    const answerSend = fC.sent.find((s) => s.peerAgentId === fA.owner);
    expect(answerSend).toBeDefined();
    const back = fA.layer.onDocumentFrame(AGENT, "session-1", answerSend!.bytes, fC.owner);
    expect(back.consumed).toBe(true);
    await until(
      () => fA.layer.joins.get(fA.owner, invited.amendmentHash as string)?.state === "accepted",
    );
  });

  it("an arrived-but-unaccepted offer leaves the invitee holding NOTHING — neither alone admits anyone", async () => {
    const fA = await newFixture();
    const fC = await newFixture();
    const proposed = await fA.call("cello_doc_propose", {
      peer_pubkey: fA.peer, starting_content: "content C must not hold yet. ",
    });
    const documentId = proposed.documentId as string;
    await fA.call("cello_doc_invite", { document_id: documentId, invitee_pubkey: fC.owner });
    const offerSend = fA.sent.find((s) => s.peerAgentId === fC.owner)!;
    fC.layer.onDocumentFrame(AGENT, "session-1", offerSend.bytes, fA.owner);
    await until(() => fC.layer.joins.pendingFor(fC.owner).length === 1);
    // The AMENDMENT half is valid and delivered — and C holds NOTHING until C's own accept.
    expect(fC.layer.store.getDocument(fC.owner, documentId)).toBeNull();
    expect(fC.layer.store.currentDocumentEpoch(fC.owner, documentId)).toBe(0);
  });

  it("the inbox SHOWS THE RULES the invitee is consenting to — participants, admins, properties", async () => {
    const fA = await newFixture();
    const fC = await newFixture();
    const proposed = await fA.call("cello_doc_propose", {
      peer_pubkey: fA.peer, admins: [fA.owner], append_only: true,
    });
    const documentId = proposed.documentId as string;
    await fA.call("cello_doc_invite", { document_id: documentId, invitee_pubkey: fC.owner });
    const offerSend = fA.sent.find((s) => s.peerAgentId === fC.owner)!;
    fC.layer.onDocumentFrame(AGENT, "session-1", offerSend.bytes, fA.owner);
    await until(() => fC.layer.joins.pendingFor(fC.owner).length === 1);
    const inbox = await fC.call("cello_doc_inbox");
    const entry = (inbox.joins as Array<Record<string, unknown>>)[0]!;
    expect(entry.documentId).toBe(documentId);
    expect((entry.participants as string[]).sort()).toEqual([fA.owner, fA.peer, fC.owner].sort());
    expect(entry.admins).toEqual([fA.owner]);
    expect((entry.properties as Record<string, unknown>).append_only).toBe(true);
    expect(entry.assuranceTier).toBe("authenticated");
  });

  it("a REFUSED join settles on the inviter with the operator's reason — and C still holds nothing", async () => {
    const fA = await newFixture();
    const fC = await newFixture();
    const proposed = await fA.call("cello_doc_propose", { peer_pubkey: fA.peer });
    const documentId = proposed.documentId as string;
    const invited = await fA.call("cello_doc_invite", { document_id: documentId, invitee_pubkey: fC.owner });
    const offerSend = fA.sent.find((s) => s.peerAgentId === fC.owner)!;
    fC.layer.onDocumentFrame(AGENT, "session-1", offerSend.bytes, fA.owner);
    await until(() => fC.layer.joins.pendingFor(fC.owner).length === 1);
    const refused = await fC.call("cello_doc_refuse", {
      document_id: documentId, reason: "not this one thanks",
    });
    expect(refused).toMatchObject({ ok: true, joined: false });
    expect(fC.layer.store.getDocument(fC.owner, documentId)).toBeNull();
    const answerSend = fC.sent.find((s) => s.peerAgentId === fA.owner)!;
    fA.layer.onDocumentFrame(AGENT, "session-1", answerSend.bytes, fC.owner);
    await until(
      () => fA.layer.joins.get(fA.owner, invited.amendmentHash as string)?.state === "refused",
    );
    expect(fA.layer.joins.get(fA.owner, invited.amendmentHash as string)?.reason).toBe(
      "not this one thanks",
    );
    // And the inviter's list SURFACES the answer.
    const list = await fA.call("cello_doc_list");
    const offers = list.joinOffers as Array<Record<string, unknown>>;
    expect(offers.find((o) => o.documentId === documentId)).toMatchObject({ state: "refused" });
  });

  it("an existing holder VALIDATES an arriving amendment before appending — a forged one is refused", async () => {
    // The receive-side validate-before-append site, pinned revert-visibly (JOIN-1 review):
    // delete the replay in recordAmendment and the forged half of this test goes green-to-red.
    const fA = await newFixture();
    const fB = await newFixture();
    const fC = await newFixture();
    // A proposes TO B's real daemon; B accepts, so B holds the document.
    const proposed = await fA.call("cello_doc_propose", { peer_pubkey: fB.owner });
    const documentId = proposed.documentId as string;
    const proposalSend = fA.sent.find((s) => s.peerAgentId === fB.owner)!;
    const routedProposal = fB.layer.onDocumentFrame(AGENT, "session-1", proposalSend.bytes, fA.owner);
    expect(routedProposal).toMatchObject({ consumed: true, kind: "proposal" });
    await until(() => fB.layer.handshake.pending(fB.owner).length === 1);
    const bAccept = await fB.call("cello_doc_accept", { document_id: documentId });
    expect(bAccept.ok).toBe(true);

    // A invites C; the amendment fans out to B.
    const invited = await fA.call("cello_doc_invite", { document_id: documentId, invitee_pubkey: fC.owner });
    expect((invited.holdersNotified as Record<string, boolean>)[fB.owner]).toBe(true);
    const amendSend = fA.sent.filter((s) => s.peerAgentId === fB.owner).at(-1)!;
    const routedAmend = fB.layer.onDocumentFrame(AGENT, "session-1", amendSend.bytes, fA.owner);
    expect(routedAmend).toMatchObject({ consumed: true, kind: "amendment" });
    await until(() => fB.layer.store.currentDocumentEpoch(fB.owner, documentId) === 1);

    // The forged twin: a rogue key authors epoch 2 claiming itself as the required signer.
    const rogue = generateKeypair();
    const rogueId = Buffer.from(await rogue.getPublicKey()).toString("hex");
    const chain = fB.layer.amendments.chain(fB.owner, documentId);
    const body: DocumentAmendmentBody = {
      document_id: documentId,
      epoch_id: 2,
      prev_amendment_hash: Buffer.from(
        documentAmendmentHash(chain[chain.length - 1]!.body),
      ).toString("hex"),
      kind: "add_holder",
      subject_agent_id: "e".repeat(64),
      property_change: null,
      state_hash: null,
      authored_at_ms: NOW,
    };
    const hash = documentAmendmentHash(body);
    const tbs = buildDocumentMultisigTbs({
      document_id: documentId,
      subject_kind: "document_amendment",
      subject_hash: hash,
      required_signers: [rogueId],
    });
    const forged = encodeDocumentAmendment({
      body,
      collection: {
        document_id: documentId,
        subject_kind: "document_amendment",
        subject_hash: hash,
        required_signers: [rogueId],
        signatures: [{ signer_agent_id: rogueId, signature: await rogue.sign(tbs) }],
      },
    });
    const routed = fB.layer.onDocumentFrame(AGENT, "session-1", new Uint8Array(forged), rogueId);
    expect(routed.consumed).toBe(true);
    // The router contains the refusal; the epoch NEVER advances on a forged amendment.
    await new Promise((r) => setTimeout(r, 100));
    expect(fB.layer.store.currentDocumentEpoch(fB.owner, documentId)).toBe(1);
  });

  it("REMOVE-1: an admin removes the joined holder — forward-only on the removed daemon", async () => {
    const fA = await newFixture();
    const fC = await newFixture();
    const proposed = await fA.call("cello_doc_propose", {
      peer_pubkey: fA.peer, starting_content: "content C keeps forever. ",
    });
    const documentId = proposed.documentId as string;
    await fA.call("cello_doc_invite", { document_id: documentId, invitee_pubkey: fC.owner });
    const offerSend = fA.sent.find((s) => s.peerAgentId === fC.owner)!;
    fC.layer.onDocumentFrame(AGENT, "session-1", offerSend.bytes, fA.owner);
    await until(() => fC.layer.joins.pendingFor(fC.owner).length === 1);
    await fC.call("cello_doc_accept", { document_id: documentId });

    const removed = await fA.call("cello_doc_remove", {
      document_id: documentId, holder_pubkey: fC.owner,
    });
    expect(removed).toMatchObject({ ok: true, voluntary: false, epochId: 2 });
    expect((removed.holdersNotified as Record<string, boolean>)[fC.owner]).toBe(true);

    // C's daemon applies the removal: status flips, the event is the operator's notice —
    // and the COPY REMAINS, content readable, history intact.
    const removalSend = fA.sent.filter((s) => s.peerAgentId === fC.owner).at(-1)!;
    fC.layer.onDocumentFrame(AGENT, "session-1", removalSend.bytes, fA.owner);
    await until(
      () => fC.layer.store.removedFromArrangement(fC.owner, documentId).removed,
    );
    // The warn IS the operator's notice — the surfacing clause, pinned.
    expect(fC.events).toContain("document.removed_from");
    expect(fC.layer.live.get(fC.owner, documentId).getText("content").toString()).toContain(
      "content C keeps forever",
    );
    // Publishing refuses NAMING the condition — forward-only, not an error about transport.
    // (Asserted at the gate: the fixture has no file workspace, so the publish VERB refuses on
    // the missing file before it ever reaches this gate.)
    const gate = fC.layer.lifecycle.canPublish(fC.owner, documentId);
    expect(gate).toMatchObject({ ok: false, reason: "document_removed" });
    expect((gate as { detail: string }).detail).toContain("epoch 2");
    // And A's side refuses any post-removal envelope from C by membership (inbound-suite covers
    // the refusal shape; here we pin the derived arrangement dropped C).
    const chain = fA.layer.amendments.chain(fA.owner, documentId);
    expect(chain.at(-1)!.body.kind).toBe("remove_holder");
    expect(fA.layer.amendments.membershipOf(fA.owner, documentId, fC.owner).state).toBe("removed");
  });

  it("REMOVE-1: voluntary leave — a holder removes THEMSELVES on their own signature", async () => {
    const fA = await newFixture();
    const fC = await newFixture();
    const proposed = await fA.call("cello_doc_propose", { peer_pubkey: fA.peer });
    const documentId = proposed.documentId as string;
    await fA.call("cello_doc_invite", { document_id: documentId, invitee_pubkey: fC.owner });
    const offerSend = fA.sent.find((s) => s.peerAgentId === fC.owner)!;
    fC.layer.onDocumentFrame(AGENT, "session-1", offerSend.bytes, fA.owner);
    await until(() => fC.layer.joins.pendingFor(fC.owner).length === 1);
    await fC.call("cello_doc_accept", { document_id: documentId });

    // C is NOT an admin — leaving is still theirs (D3).
    const left = await fC.call("cello_doc_remove", {
      document_id: documentId, holder_pubkey: fC.owner,
    });
    expect(left).toMatchObject({ ok: true, voluntary: true });
    expect(fC.layer.store.removedFromArrangement(fC.owner, documentId).removed).toBe(true);
    expect(fC.layer.lifecycle.canPublish(fC.owner, documentId)).toMatchObject({
      ok: false,
      reason: "document_removed",
    });
    // The leave amendment reaches A and A's arrangement drops C.
    const leaveSend = fC.sent.filter((s) => s.peerAgentId === fA.owner).at(-1)!;
    fA.layer.onDocumentFrame(AGENT, "session-1", leaveSend.bytes, fC.owner);
    await until(
      () => fA.layer.amendments.membershipOf(fA.owner, documentId, fC.owner).state === "removed",
    );
  });

  it("REMOVE-1: a fellow ADMIN cannot be expelled through the holder door — the policy's sentence surfaces", async () => {
    const fA = await newFixture();
    const proposed = await fA.call("cello_doc_propose", { peer_pubkey: fA.peer });
    // Default admins = both parties; removing the peer (an admin) as a holder must refuse.
    const documentId = proposed.documentId as string;
    const res = await fA.call("cello_doc_remove", {
      document_id: documentId, holder_pubkey: fA.peer,
    });
    expect(res).toMatchObject({ ok: false, reason: "document_amendment_invalid" });
    expect(String(res.guidance)).toContain("governance_remove_admin_first");
  });

  it("an under-signed offer admits nobody — recorded refused on the invitee, named", async () => {
    const fA = await newFixture();
    const fC = await newFixture();
    const proposed = await fA.call("cello_doc_propose", {
      peer_pubkey: fA.peer,
      // A is deliberately NOT an admin: only the (absent) peer governs.
      admins: [fA.peer],
    });
    const documentId = proposed.documentId as string;
    const invited = await fA.call("cello_doc_invite", {
      document_id: documentId,
      invitee_pubkey: fC.owner,
    });
    // The inviter's own daemon refuses at authoring — a non-admin cannot even mint the offer.
    expect(invited).toMatchObject({ ok: false, reason: "document_not_admin" });
    expect(fA.sent.find((s) => s.peerAgentId === fC.owner)).toBeUndefined();
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

  it("FLUSHES that edit when the operator writes the same text again", async () => {
    // The case the test above stops one call short of, and the one that mattered. The edit is in
    // the live doc and in no log — and pending is derived from the log, so nothing will ever
    // deliver it. The operator's natural retry is to send the same text, which used to short-circuit
    // on `before === content` and answer `changed: false, published: false`: a cheerful no-op over a
    // permanent divergence, with the shipped skill telling the agent not to write it again.
    const f = await newFixture();
    const documentId = (await f.call("cello_doc_propose", { peer_pubkey: f.peer })).documentId as string;
    f.layer.lifecycle.setPlatformPaused(f.owner, true, NOW);
    await f.call("cello_doc_write", { document_id: documentId, content: "written while paused" });
    expect(f.layer.store.pendingDeliveries(f.owner, NOW, f.owner)).toHaveLength(0);

    f.layer.lifecycle.setPlatformPaused(f.owner, false, NOW);
    const retry = await f.call("cello_doc_write", { document_id: documentId, content: "written while paused" });

    expect(retry).toMatchObject({ ok: true, changed: false, published: true });
    // THE ASSERTION THAT MATTERS: it is now deliverable. Reporting `published: true` while the log
    // stayed empty would be the same lie one layer up.
    expect(
      f.layer.store.pendingDeliveries(f.owner, NOW, f.owner),
      "the stuck edit was reported as published but never entered the log",
    ).toHaveLength(1);
  });

  it("still refuses to publish while the edit remains unpublishable, and says why", async () => {
    const f = await newFixture();
    const documentId = (await f.call("cello_doc_propose", { peer_pubkey: f.peer })).documentId as string;
    f.layer.lifecycle.setPlatformPaused(f.owner, true, NOW);
    await f.call("cello_doc_write", { document_id: documentId, content: "stuck" });

    // Still paused. The retry must not claim success, and must not go silent either.
    const retry = await f.call("cello_doc_write", { document_id: documentId, content: "stuck" });
    expect(retry).toMatchObject({ ok: true, changed: false, published: false });
    expect(String(retry.guidance)).toContain("has not reached your peer");
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


describe("cello_doc_list distinguishes states that otherwise render identically", () => {
  it("says WHOSE offer it was, and whether the peer has actually shown up", async () => {
    const f = await newFixture();
    const documentId = (await f.call("cello_doc_propose", { peer_pubkey: f.peer })).documentId as string;

    const listed = ((await f.call("cello_doc_list")).documents as Array<Record<string, unknown>>)[0]!;
    expect(listed).toMatchObject({ documentId, proposedByUs: true, peerHasPublished: false });
    // Without these, a document the peer refused, one whose offer never arrived, and one being
    // actively co-edited all render the same — the only moving part is pendingUnsent, which also
    // moves for a peer who is merely offline. "They said no" and "they are asleep" want opposite
    // actions from the operator.
  });

  it("marks a document we ACCEPTED as not ours", async () => {
    const f = await newFixture();
    const env = await f.incomingProposal();
    const documentId = f.layer.handshake.recordProposal(f.owner, encodeDocumentProposal(env), NOW).documentId;
    await f.call("cello_doc_accept", { document_id: documentId });

    const listed = ((await f.call("cello_doc_list")).documents as Array<Record<string, unknown>>)[0]!;
    expect(listed).toMatchObject({ proposedByUs: false, consentState: "accepted" });
  });
});

describe("a document the peer REFUSED does not keep publishing", () => {
  it("refuses the write instead of authoring an envelope nobody will accept", async () => {
    const f = await newFixture();
    const documentId = (await f.call("cello_doc_propose", { peer_pubkey: f.peer })).documentId as string;

    // The peer's signed refusal, the way `recordProposalAck` records it.
    f.layer.handshake.recordPeerDecision(f.owner, documentId, f.peer, {
      accepted: false,
      reason: "not this one",
      decidedAtMs: NOW,
    });

    // Publishing anyway costs a signed leaf and a delivery that the peer refuses as
    // `document_unknown` — forever, because they have no such document. The operator meanwhile sees
    // `active` with a pending count that never clears, which is the shape of a document that has
    // silently stopped working.
    const res = await f.call("cello_doc_write", { document_id: documentId, content: "more text" });
    expect(res).toMatchObject({ ok: false, reason: "document_peer_refused" });
    // And the refusal names the peer's own words, so the operator knows what happened rather than
    // being told a generic no.
    expect(String(res.guidance)).toContain("not this one");
    expect(f.layer.store.pendingDeliveries(f.owner, NOW, f.owner)).toHaveLength(0);
  });

  it("still allows a write while the peer has NOT yet answered", async () => {
    const f = await newFixture();
    const documentId = (await f.call("cello_doc_propose", { peer_pubkey: f.peer })).documentId as string;
    // Unanswered is not refused. Publishing before the peer decides is normal — the update waits in
    // the log and delivers when they accept, which is what makes an offline proposal work at all.
    expect(await f.call("cello_doc_write", { document_id: documentId, content: "early text" }))
      .toMatchObject({ ok: true, published: true });
  });
});

describe("DOD-DOC-SCREEN-1 — the sender is told BEFORE the peer refuses", () => {
  it("refuses a bidi override at the write, naming the character and the offset", async () => {
    // §16.6 friction reduction. The receiver's gate refuses this and stays authoritative; catching
    // it here means the operator never spends a rejection round on a character they cannot see in
    // their own editor — and three rejected rounds stall the document.
    const f = await newFixture();
    const documentId = (await f.call("cello_doc_propose", { peer_pubkey: f.peer })).documentId as string;

    const res = await f.call("cello_doc_write", { document_id: documentId, content: "safe‮elbisiv" });
    expect(res).toMatchObject({ ok: false, reason: "document_content_refused" });
    expect(String(res.guidance)).toContain("U+202E");
    // Nothing was applied and nothing published — a refusal that half-applied would be worse than
    // the rejection round it saves.
    expect(f.layer.store.pendingDeliveries(f.owner, NOW, f.owner)).toHaveLength(0);
    expect(await f.call("cello_doc_read", { document_id: documentId })).not.toMatchObject({
      content: expect.stringContaining("‮"),
    });
  });

  it("refuses a chat-template marker, and ADMITS the text the sanitizer used to destroy", async () => {
    const f = await newFixture();
    const documentId = (await f.call("cello_doc_propose", { peer_pubkey: f.peer })).documentId as string;

    expect(await f.call("cello_doc_write", { document_id: documentId, content: "do <|im_start|>this" }))
      .toMatchObject({ ok: false, reason: "document_content_refused" });

    // The other half of the claim, and the one the audit was about: legitimate text in some
    // language must still go through. A sender-side check that refused these would be the
    // sanitizer's failure wearing a different name.
    for (const legit of ["कर्‍म", "👨‍👩‍👧", "Ｈｅｌｌｏ", "ﬁle is ½"]) {
      expect(
        await f.call("cello_doc_write", { document_id: documentId, content: legit }),
        `refused legitimate text: ${legit}`,
      ).toMatchObject({ ok: true });
    }
  });
});

describe("DOD-DOC-SCREEN-1 §16.7-16 — the sender ADOPTS the receiver's rule", () => {
  it("refuses a character this peer has already refused for this document", async () => {
    // Rules compose toward STRICT. Once they have said no, emitting it again spends a refusal round
    // on an answer we already have — and three rounds stall the document, so an avoidable one is
    // expensive. This is what the machine-readable refusal detail exists for: a refusal carrying
    // only prose can be read by an operator and adopted by nobody.
    const f = await newFixture();
    const documentId = (await f.call("cello_doc_propose", { peer_pubkey: f.peer })).documentId as string;

    // Their signed refusal, in the shape the screening rule actually emits.
    f.layer.rejections.recordIncomingRejection(f.owner, documentId, {
      rejectionEnvelopeHash: "11".repeat(32),
      rejectedEnvelopeHash: "22".repeat(32),
      reason: "document_content_refused",
      detail: JSON.stringify({ rule: "document_content_screen", codepoints: ["U+00E9"], count: 1, offsets: [3] }),
      fromAgentId: f.peer,
    });

    const res = await f.call("cello_doc_write", { document_id: documentId, content: "café time" });
    expect(res).toMatchObject({ ok: false, reason: "document_peer_rule_adopted" });
    expect(String(res.guidance)).toContain("U+00E9");
    // Nothing applied, nothing published — a refusal that half-applied is worse than the round it saves.
    expect(f.layer.store.pendingDeliveries(f.owner, NOW, f.owner)).toHaveLength(0);
  });

  it("admits text that does not contain what they refused", async () => {
    const f = await newFixture();
    const documentId = (await f.call("cello_doc_propose", { peer_pubkey: f.peer })).documentId as string;
    f.layer.rejections.recordIncomingRejection(f.owner, documentId, {
      rejectionEnvelopeHash: "11".repeat(32),
      rejectedEnvelopeHash: "22".repeat(32),
      reason: "document_content_refused",
      detail: JSON.stringify({ rule: "document_content_screen", codepoints: ["U+00E9"] }),
      fromAgentId: f.peer,
    });
    expect(await f.call("cello_doc_write", { document_id: documentId, content: "plain ascii" }))
      .toMatchObject({ ok: true, published: true });
  });

  it("adopts NOTHING from a refusal whose detail is prose", async () => {
    // Guessing a rule out of English is how a sender ends up refusing text nobody objected to. A
    // refusal with no structured codepoints carries no rule to adopt, and that is not an error.
    const f = await newFixture();
    const documentId = (await f.call("cello_doc_propose", { peer_pubkey: f.peer })).documentId as string;
    f.layer.rejections.recordIncomingRejection(f.owner, documentId, {
      rejectionEnvelopeHash: "11".repeat(32),
      rejectedEnvelopeHash: "22".repeat(32),
      reason: "document_content_refused",
      detail: "we would rather you did not use accented characters",
      fromAgentId: f.peer,
    });
    expect(await f.call("cello_doc_write", { document_id: documentId, content: "café time" }))
      .toMatchObject({ ok: true, published: true });
  });

  it("is scoped to THIS document — a rule adopted for one does not narrow another", async () => {
    // They refused it HERE, under the profile agreed HERE. Another peer, or another document with
    // the same peer, may accept it happily; silently narrowing what an operator can write
    // everywhere would be a rule nobody agreed to.
    const f = await newFixture();
    const docA = (await f.call("cello_doc_propose", { peer_pubkey: f.peer })).documentId as string;
    const docB = (await f.call("cello_doc_propose", { peer_pubkey: f.peer })).documentId as string;
    f.layer.rejections.recordIncomingRejection(f.owner, docA, {
      rejectionEnvelopeHash: "11".repeat(32),
      rejectedEnvelopeHash: "22".repeat(32),
      reason: "document_content_refused",
      detail: JSON.stringify({ rule: "document_content_screen", codepoints: ["U+00E9"] }),
      fromAgentId: f.peer,
    });
    expect(await f.call("cello_doc_write", { document_id: docA, content: "café" }))
      .toMatchObject({ ok: false, reason: "document_peer_rule_adopted" });
    expect(await f.call("cello_doc_write", { document_id: docB, content: "café" }))
      .toMatchObject({ ok: true, published: true });
  });
});
