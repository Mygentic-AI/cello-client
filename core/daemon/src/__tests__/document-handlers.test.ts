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
  encodeDocumentReconcile,
  DOCUMENT_RECONCILE_EXCHANGE_VERSION,
  encodeDocumentUpdateEnvelope,
  DOCUMENT_UPDATE_ENCODING_V1,
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

/**
 * Route every frame `from` has addressed to `to` into `to`'s daemon — redelivery-safe by design
 * (appends are idempotent, answers settle once), so calling it repeatedly is harmless. R21 made
 * accepting AUTHOR a consent entry, so after any accept the accepter owes frames the other
 * daemons must actually receive for their folds to show the accepter participating.
 */
type HandlerFixture = Awaited<ReturnType<typeof newFixture>>;
function routeAll(from: HandlerFixture, to: HandlerFixture) {
  for (const send of from.sent) {
    if (send.peerAgentId === to.owner) {
      to.layer.onDocumentFrame(AGENT, "session-1", send.bytes, from.owner);
    }
  }
}

/**
 * SYNC-P4 (D5 deleted): seat an invitee through the EXCHANGE. `cello_doc_invite` already put the
 * notice — a step-1 position frame — on the inviter's wire; bouncing the exchange lands the
 * genesis and the entry set on the invitee (empty hand → world → bootstrap). Bounded, and safe
 * to repeat: every frame in the exchange is idempotent on arrival.
 */
async function seatViaExchange(inviter: HandlerFixture, invitee: HandlerFixture, documentId: string) {
  for (let i = 0; i < 6 && invitee.layer.store.getDocument(invitee.owner, documentId) === null; i++) {
    routeAll(inviter, invitee);
    await new Promise((r) => setTimeout(r, 25));
    routeAll(invitee, inviter);
    await new Promise((r) => setTimeout(r, 25));
  }
  await until(() => invitee.layer.store.getDocument(invitee.owner, documentId) !== null);
}

async function newFixture(opts: { sendFails?: string } = {}) {
  /** Mutable so a test can fail the first send and succeed the retry — the real recovery sequence. */
  let sendFails = opts.sendFails;
  const keys = generateKeypair();
  const owner = Buffer.from(await keys.getPublicKey()).toString("hex");
  const peerKeys = generateKeypair();
  const peer = Buffer.from(await peerKeys.getPublicKey()).toString("hex");

  /** Event names captured, so operator-notice claims ("the warn IS the surface") are testable. */
  const events: string[] = [];
  const nudged: Array<{ documentId: string; seat: string }> = [];
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
      governanceFrontierFor: (o, d) => layer.governanceFrontierFor(o, d),
      holdersFor: (o, d) => layer.holdersFor(o, d),
      store: layer.store,
      engine: layer.engine,
      logger,
      sign: async (_o, tbs) => keys.sign(tbs),
      senderIdFor: (o) => o,
      canPublish: (o, d) => layer.lifecycle.canPublish(o, d),
      // Captured, not dropped: the publish-time nudge is a fact tests may assert on.
      nudgeSeats: (_o, documentId, seats) => {
        for (const seat of seats) nudged.push({ documentId, seat });
      },
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
    call, layer, sent, nudged, owner, peer, events, db, incomingProposal, keys,
    goOffline: () => {
      sendFails = "peer_offline";
    },
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
    // R22: the named peer has not consented yet — invited, not a participant.
    expect(row.participants).toEqual([f.owner]);
    expect(row.invited).toEqual([f.peer]);
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
        `INSERT INTO document_entries
           (owner_agent_id, document_id, entry_hash, author_agent_id, author_seq, epoch_id,
            received_bytes, recorded_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(f.owner, brokenId, "h".repeat(64), "a".repeat(64), 1, 1, Buffer.from([0xff, 0xff, 0xff]), 1);

    const list = await f.call("cello_doc_list", {});
    const rows = list.documents as Array<Record<string, unknown>>;
    expect(rows).toHaveLength(2);
    const ok = rows.find((r) => r.documentId === healthy.documentId)!;
    expect(ok.arrangementUnavailable).toBeUndefined();
    expect((ok.participants as string[]).length).toBe(1);
    expect((ok.invited as string[]).length).toBe(1);
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
  it("invite → notice → exchange bootstrap → inbox → accept — the consent entry seats the joiner on the inviter", async () => {
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
    expect(invited).toMatchObject({ ok: true, noticeSent: true, epochId: 1 });

    // The NOTICE crossed A's transport (a step-1 position frame — no offer, no carried history);
    // bouncing the exchange bootstraps C: empty hand, then the world with the genesis.
    await seatViaExchange(fA, fC, documentId);

    const inbox = await fC.call("cello_doc_inbox");
    expect((inbox.joins as Array<{ documentId: string }>)[0]?.documentId).toBe(documentId);

    // C consents BY DERIVING — their own daemon computed the rules from the signed record.
    const accepted = await fC.call("cello_doc_accept", { document_id: documentId });
    expect(accepted).toMatchObject({ ok: true, joined: true });

    // C's copy carries A's content, applied from the exchange. C's accept AUTHORED their
    // consent entry (R21), so C's chain holds the admission plus the consent.
    expect(fC.layer.live.get(fC.owner, documentId).getText("content").toString()).toContain(
      "hello from A",
    );
    expect(fC.layer.store.currentDocumentEpoch(fC.owner, documentId)).toBe(2);
    expect(fA.layer.store.currentDocumentEpoch(fA.owner, documentId)).toBe(1);

    // C's frames reach A — the CONSENT ENTRY is what turns C from invited into a participant
    // in A's own derivation. No answer frame exists to settle anything.
    routeAll(fC, fA);
    await until(() => fA.layer.store.currentDocumentEpoch(fA.owner, documentId) === 2);
    expect(fA.layer.holdersFor(fA.owner, documentId)).toContain(fC.owner);
  });

  it("an arrived-but-unaccepted offer leaves the invitee holding NOTHING — neither alone admits anyone", async () => {
    const fA = await newFixture();
    const fC = await newFixture();
    const proposed = await fA.call("cello_doc_propose", {
      peer_pubkey: fA.peer, starting_content: "content C must not hold yet. ",
    });
    const documentId = proposed.documentId as string;
    await fA.call("cello_doc_invite", { document_id: documentId, invitee_pubkey: fC.owner });
    await seatViaExchange(fA, fC, documentId);
    // The admission is delivered and C even HOLDS the record now — but no fold anywhere seats
    // C as a participant until C's OWN consent entry exists (R22): the admission alone admits
    // nobody, on either daemon.
    const cInbox = await fC.call("cello_doc_inbox");
    expect((cInbox.joins as Array<{ documentId: string }>)[0]?.documentId).toBe(documentId);
    // `holdersFor` is the FAN-OUT set and deliberately includes invited seats — the seat that
    // proves participation is the derived participants list on each surface.
    for (const f of [fA, fC]) {
      const list = await f.call("cello_doc_list", {});
      const row = (list.documents as Array<Record<string, unknown>>).find(
        (d) => d.documentId === documentId,
      )!;
      expect(row.participants).not.toContain(fC.owner);
    }
  });

  it("the inbox SHOWS THE RULES the invitee is consenting to — participants, admins, properties", async () => {
    const fA = await newFixture();
    const fC = await newFixture();
    const proposed = await fA.call("cello_doc_propose", {
      peer_pubkey: fA.peer, admins: [fA.owner], append_only: true,
    });
    const documentId = proposed.documentId as string;
    await fA.call("cello_doc_invite", { document_id: documentId, invitee_pubkey: fC.owner });
    await seatViaExchange(fA, fC, documentId);
    const inbox = await fC.call("cello_doc_inbox");
    const entry = (inbox.joins as Array<Record<string, unknown>>)[0]!;
    expect(entry.documentId).toBe(documentId);
    // R22: the proposer participates; the genesis peer and the invitee are invited seats until
    // their own consent entries exist.
    expect(entry.participants).toEqual([fA.owner]);
    expect((entry.invited as string[]).sort()).toEqual([fA.peer, fC.owner].sort());
    expect(entry.admins).toEqual([fA.owner]);
    expect((entry.properties as Record<string, unknown>).append_only).toBe(true);
    expect(entry.assuranceTier).toBe("authenticated");
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
    // B's consent entry reaches A — without it, A's fold shows B invited and fans out to nobody.
    routeAll(fB, fA);
    await until(() => fA.layer.store.currentDocumentEpoch(fA.owner, documentId) === 1);

    // A invites C; the amendment fans out to B.
    const invited = await fA.call("cello_doc_invite", { document_id: documentId, invitee_pubkey: fC.owner });
    expect((invited.holdersNotified as Record<string, boolean>)[fB.owner]).toBe(true);
    const amendSend = fA.sent.filter((s) => s.peerAgentId === fB.owner).at(-1)!;
    const routedAmend = fB.layer.onDocumentFrame(AGENT, "session-1", amendSend.bytes, fA.owner);
    expect(routedAmend).toMatchObject({ consumed: true, kind: "amendment" });
    await until(() => fB.layer.store.currentDocumentEpoch(fB.owner, documentId) === 2);

    // The forged twin: a rogue key authors the next epoch claiming itself as the required signer.
    const rogue = generateKeypair();
    const rogueId = Buffer.from(await rogue.getPublicKey()).toString("hex");
    const chain = fB.layer.amendments.chain(fB.owner, documentId);
    const chainLenBefore = chain.length;
    const body: DocumentAmendmentBody = {
      document_id: documentId,
      epoch_id: 3,
      prev_amendment_hash: Buffer.from(
        documentAmendmentHash(chain[chain.length - 1]!.body),
      ).toString("hex"),
      kind: "add_holder",
      subject_agent_id: "e".repeat(64),
      property_change: null,
      state_hash: null,
      authored_at_ms: NOW,
      author_agent_id: rogueId,
      author_seq: 1,
      parents: [],
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
    // The router contains the refusal; the epoch NEVER advances on a forged amendment — and the
    // stranger's entry is NOT STORED, not even as history (SYNC-R18: refused, never absorbed).
    await new Promise((r) => setTimeout(r, 100));
    expect(fB.layer.store.currentDocumentEpoch(fB.owner, documentId)).toBe(2);
    expect(fB.layer.amendments.chain(fB.owner, documentId)).toHaveLength(chainLenBefore);
  });

  it("a KNOWN author's semantically-void entry IS stored — history, not refusal (F4 of the fold)", async () => {
    // The other half of the stranger door: bouncing a known party's fold-void entry would leave
    // two holders holding different sets. B stores it; the fold rules it contributes nothing.
    const fA = await newFixture();
    const fB = await newFixture();
    const fC = await newFixture();
    const proposed = await fA.call("cello_doc_propose", { peer_pubkey: fB.owner });
    const documentId = proposed.documentId as string;
    const proposalSend = fA.sent.find((s) => s.peerAgentId === fB.owner)!;
    fB.layer.onDocumentFrame(AGENT, "session-1", proposalSend.bytes, fA.owner);
    await until(() => fB.layer.handshake.pending(fB.owner).length === 1);
    await fB.call("cello_doc_accept", { document_id: documentId });
    routeAll(fB, fA);
    await until(() => fA.layer.store.currentDocumentEpoch(fA.owner, documentId) === 1);
    await fA.call("cello_doc_invite", { document_id: documentId, invitee_pubkey: fC.owner });
    const amendSend = fA.sent.filter((s) => s.peerAgentId === fB.owner).at(-1)!;
    fB.layer.onDocumentFrame(AGENT, "session-1", amendSend.bytes, fA.owner);
    await until(() => fB.layer.store.currentDocumentEpoch(fB.owner, documentId) === 2);

    // A — a genesis party, fully signed — authors an admission for someone who ALREADY holds.
    const chain = fB.layer.amendments.chain(fB.owner, documentId);
    const invite = chain.find((e) => e.body.kind === "add_holder")!;
    const inviteHash = Buffer.from(documentAmendmentHash(invite.body)).toString("hex");
    const voidBody: DocumentAmendmentBody = {
      document_id: documentId,
      epoch_id: 3,
      prev_amendment_hash: inviteHash,
      kind: "add_holder",
      subject_agent_id: fB.owner, // already a holder — the fold voids this
      property_change: null,
      state_hash: null,
      authored_at_ms: NOW + 1,
      author_agent_id: fA.owner,
      author_seq: 2,
      parents: [inviteHash],
    };
    const voidHash = documentAmendmentHash(voidBody);
    const voidTbs = buildDocumentMultisigTbs({
      document_id: documentId,
      subject_kind: "document_amendment",
      subject_hash: voidHash,
      required_signers: [fA.owner],
    });
    const voidWire = encodeDocumentAmendment({
      body: voidBody,
      collection: {
        document_id: documentId,
        subject_kind: "document_amendment",
        subject_hash: voidHash,
        required_signers: [fA.owner],
        signatures: [{ signer_agent_id: fA.owner, signature: await fA.keys.sign(voidTbs) }],
      },
    });
    const routed = fB.layer.onDocumentFrame(AGENT, "session-1", new Uint8Array(voidWire), fA.owner);
    expect(routed.consumed).toBe(true);
    await until(() => fB.layer.amendments.chain(fB.owner, documentId).length === 3);
    // Stored as history; the derived seats are unchanged (C is invited, not yet consented —
    // and an invited seat counts in the who-is-seated set).
    const holders = fB.layer.holdersFor(fB.owner, documentId);
    expect(holders).not.toBeNull();
    expect([...holders!].sort()).toEqual([fA.owner, fB.owner, fC.owner].sort());
  });

  it("HELD-THEN-PROMOTED entries surface their notices — an out-of-order removal still tells its subject (review F2)", async () => {
    // The arrival order the pending table exists for: the removal lands BEFORE the amendment it
    // chains onto. On promotion, document.removed_from must fire and the lifecycle must run —
    // the early-return version dropped both, silently, forever.
    const fA = await newFixture();
    const fB = await newFixture();
    const fC = await newFixture();
    const proposed = await fA.call("cello_doc_propose", {
      peer_pubkey: fB.owner,
      admins: [fA.owner], // B must be a plain holder, or the holder door blocks the removal
    });
    const documentId = proposed.documentId as string;
    const proposalSend = fA.sent.find((s) => s.peerAgentId === fB.owner)!;
    fB.layer.onDocumentFrame(AGENT, "session-1", proposalSend.bytes, fA.owner);
    await until(() => fB.layer.handshake.pending(fB.owner).length === 1);
    await fB.call("cello_doc_accept", { document_id: documentId });
    // B's consent reaches A — B is now a participant A can remove.
    routeAll(fB, fA);
    await until(() => fA.layer.store.currentDocumentEpoch(fA.owner, documentId) === 1);

    // A authors the invite of C and the removal of B — B receives NEITHER yet.
    const sentToB = fA.sent.filter((s) => s.peerAgentId === fB.owner).length;
    await fA.call("cello_doc_invite", { document_id: documentId, invitee_pubkey: fC.owner });
    const removed = await fA.call("cello_doc_remove", {
      document_id: documentId,
      holder_pubkey: fB.owner,
    });
    expect(removed).toMatchObject({ ok: true, epochId: 3 });
    const [inviteToB, removalToB] = fA.sent
      .filter((s) => s.peerAgentId === fB.owner)
      .slice(sentToB);

    // The REMOVAL arrives first: held (its parent is missing), nothing applied, no notice.
    // B's chain holds exactly B's own consent entry at this point.
    fB.layer.onDocumentFrame(AGENT, "session-1", removalToB!.bytes, fA.owner);
    await until(() => fB.layer.amendments.pending(fB.owner, documentId).length === 1);
    expect(fB.layer.amendments.chain(fB.owner, documentId)).toHaveLength(1);
    expect(fB.events).not.toContain("document.removed_from");
    expect(fB.layer.store.removedFromArrangement(fB.owner, documentId).removed).toBe(false);

    // The parent arrives: the removal PROMOTES — and its notice fires with it.
    fB.layer.onDocumentFrame(AGENT, "session-1", inviteToB!.bytes, fA.owner);
    await until(() => fB.layer.amendments.chain(fB.owner, documentId).length === 3);
    expect(fB.layer.amendments.pending(fB.owner, documentId)).toHaveLength(0);
    expect(fB.events).toContain("document.removed_from");
    expect(fB.layer.store.removedFromArrangement(fB.owner, documentId).removed).toBe(true);
  });

  it("INVITED WINDOW: an invite while the peer's consent is in flight still reaches every seat (P2 review F4)", async () => {
    // A proposes to B; B accepts; A invites C BEFORE B's consent entry arrives. The admission
    // must be owed to B anyway — an invited seat is a seat — or B never learns C exists and
    // every later entry sits held on B behind a parent nobody ever sent.
    const fA = await newFixture();
    const fB = await newFixture();
    const fC = await newFixture();
    const proposed = await fA.call("cello_doc_propose", { peer_pubkey: fB.owner });
    const documentId = proposed.documentId as string;
    const proposalSend = fA.sent.find((send) => send.peerAgentId === fB.owner)!;
    fB.layer.onDocumentFrame(AGENT, "session-1", proposalSend.bytes, fA.owner);
    await until(() => fB.layer.handshake.pending(fB.owner).length === 1);
    await fB.call("cello_doc_accept", { document_id: documentId });
    // DELIBERATELY NOT ROUTED — the window is the point.

    const invited = await fA.call("cello_doc_invite", { document_id: documentId, invitee_pubkey: fC.owner });
    expect(invited.ok).toBe(true);
    expect((invited.holdersNotified as Record<string, boolean>)[fB.owner]).toBe(true);

    // B receives the admission, then B's consent finally lands at A — both sides converge on
    // the same two-entry set (the entries are CONCURRENT: each was authored blind to the other,
    // so both carry the same interim epoch stamp — the set, not the stamp, is the truth).
    const amendSend = fA.sent.filter((send) => send.peerAgentId === fB.owner).at(-1)!;
    fB.layer.onDocumentFrame(AGENT, "session-1", amendSend.bytes, fA.owner);
    routeAll(fB, fA);
    await until(() => fA.layer.amendments.chain(fA.owner, documentId).length === 2);
    await until(() => fB.layer.amendments.chain(fB.owner, documentId).length === 2);
    expect(fA.layer.holdersFor(fA.owner, documentId)!.sort()).toEqual(
      [fA.owner, fB.owner, fC.owner].sort(),
    );
  });

  it("HALF-CONSENTED CURE: re-running accept authors the missing consent entry (P2 review F2)", async () => {
    // The failure state: the earlier accept recorded the decision (both decision rows settle
    // once) but the consent entry never landed — the agent holds the document yet derives as
    // invited everywhere, and every other verb refuses. The guidance says "run accept again";
    // this pins that the retry actually cures instead of dead-ending in document_proposal_unknown.
    const fA = await newFixture();
    const fB = await newFixture();
    const proposed = await fA.call("cello_doc_propose", { peer_pubkey: fB.owner });
    const documentId = proposed.documentId as string;
    const proposalSend = fA.sent.find((send) => send.peerAgentId === fB.owner)!;
    fB.layer.onDocumentFrame(AGENT, "session-1", proposalSend.bytes, fA.owner);
    await until(() => fB.layer.handshake.pending(fB.owner).length === 1);
    const accepted = await fB.call("cello_doc_accept", { document_id: documentId });
    expect(accepted.ok).toBe(true);
    // Manufacture the half-state: strip B's own consent entry, as if authoring had failed after
    // the decision settled.
    fB.db
      .prepare(`DELETE FROM document_entries WHERE owner_agent_id = ? AND document_id = ?`)
      .run(fB.owner, documentId);
    expect(fB.layer.store.getDocument(fB.owner, documentId)).not.toBeNull();

    const retry = await fB.call("cello_doc_accept", { document_id: documentId });
    expect(retry.ok, JSON.stringify(retry)).toBe(true);
    expect(typeof retry.consentEntry).toBe("string");
    // And the cure took: B's own derivation shows B participating again.
    routeAll(fB, fA);
    await until(() => fA.layer.store.currentDocumentEpoch(fA.owner, documentId) >= 1);
  });

  it("CLOSE WAITS ON AN INVITED SEAT — one party alone is never the whole agreement (P2 review F5)", async () => {
    // During the consent-in-flight window the proposer must not be able to settle "closed by
    // agreement" alone while the accepted peer is editing, and the close frame must REACH the
    // invited seat.
    const fA = await newFixture();
    const fB = await newFixture();
    const proposed = await fA.call("cello_doc_propose", { peer_pubkey: fB.owner });
    const documentId = proposed.documentId as string;
    const proposalSend = fA.sent.find((send) => send.peerAgentId === fB.owner)!;
    fB.layer.onDocumentFrame(AGENT, "session-1", proposalSend.bytes, fA.owner);
    await until(() => fB.layer.handshake.pending(fB.owner).length === 1);
    await fB.call("cello_doc_accept", { document_id: documentId });
    // B's consent is NOT routed — A still sees an invited seat.

    const closed = await fA.call("cello_doc_close", { document_id: documentId });
    expect(closed.ok, JSON.stringify(closed)).toBe(true);
    // The close ENTRY is delivered to the invited seat like every other entry…
    expect((closed.closeDelivered as Record<string, boolean>)[fB.owner]).toBe(true);
    // …and NOT settled: the derivation waits on the seat that has not spoken.
    expect(closed.ended).toBeNull();
    expect(closed.waitingOn as string[]).toContain(fB.owner);
    expect(fA.layer.store.getDocument(fA.owner, documentId)!.status).not.toBe("closed");
  });

  it("RECONCILE (P3): two diverged holders converge through ONE exchange, and a repeat exchange moves nothing", async () => {
    // The pivot's core claim, in process: no delivery ledger ran here — both sides simply
    // compare positions and close the gap. A and B each write while the other never receives
    // it; one initiate → step-1 position → step-2 reply with B's missing content → step-3
    // catch-up with A's — then a second exchange finds no difference and sends NOTHING, which
    // is the termination rule (idempotence is the absence of a difference).
    // Governance divergence during content divergence still trips the interim per-envelope
    // epoch stamp — the exact coupling the P4 gate (SYNC-G1) exists to delete — so this pins
    // the content half; the governance half is pinned in the engine suite.
    const fA = await newFixture();
    const fB = await newFixture();
    const proposed = await fA.call("cello_doc_propose", { peer_pubkey: fB.owner });
    const documentId = proposed.documentId as string;
    const proposalSend = fA.sent.find((send) => send.peerAgentId === fB.owner)!;
    fB.layer.onDocumentFrame(AGENT, "session-1", proposalSend.bytes, fA.owner);
    await until(() => fB.layer.handshake.pending(fB.owner).length === 1);
    await fB.call("cello_doc_accept", { document_id: documentId });
    routeAll(fB, fA);
    await until(() => fA.layer.store.currentDocumentEpoch(fA.owner, documentId) === 1);

    // Diverge: each writes; NOTHING is routed.
    await fA.call("cello_doc_write", { document_id: documentId, content: "alpha from A. " });
    await fB.call("cello_doc_write", { document_id: documentId, content: "beta from B. " });
    expect(fA.layer.store.getEnvelopeLog(fA.owner, documentId)).toHaveLength(1);
    expect(fB.layer.store.getEnvelopeLog(fB.owner, documentId)).toHaveLength(1);

    // Step 1: A sends its position.
    const beforeInitiate = fA.sent.length;
    const initiated = await fA.layer.initiateReconcile(fA.owner, fB.owner, [documentId]);
    expect(initiated.ok).toBe(true);
    const step1 = fA.sent.slice(beforeInitiate).find((send) => send.peerAgentId === fB.owner)!;

    // Step 2: B answers with what A lacks + B's own position.
    const bBefore = fB.sent.length;
    fB.layer.onDocumentFrame(AGENT, "session-1", step1.bytes, fA.owner);
    await until(() => fB.sent.length > bBefore);
    const step2 = fB.sent.slice(bBefore).find((send) => send.peerAgentId === fA.owner)!;

    // Step 3: A applies B's content and, seeing B behind, sends the catch-up.
    const aBefore = fA.sent.length;
    fA.layer.onDocumentFrame(AGENT, "session-1", step2.bytes, fB.owner);
    await until(() => fA.sent.length > aBefore);
    const step3 = fA.sent.slice(aBefore).find((send) => send.peerAgentId === fB.owner)!;
    const b2Before = fB.sent.length;
    fB.layer.onDocumentFrame(AGENT, "session-1", step3.bytes, fA.owner);

    // CONVERGED: both hold both writes, unaided by any queue.
    await until(
      () =>
        String((fA.layer.live.get(fA.owner, documentId).getText("content") ?? "")).includes("beta from B") &&
        String((fB.layer.live.get(fB.owner, documentId).getText("content") ?? "")).includes("alpha from A"),
    );

    // IDEMPOTENCE: a fresh exchange over converged state moves nothing at all.
    await new Promise((r) => setTimeout(r, 50));
    const quietA = fA.sent.length;
    const quietB = Math.max(fB.sent.length, b2Before);
    await fA.layer.initiateReconcile(fA.owner, fB.owner, [documentId]);
    const secondStep1 = fA.sent.slice(quietA).find((send) => send.peerAgentId === fB.owner)!;
    fB.layer.onDocumentFrame(AGENT, "session-1", secondStep1.bytes, fA.owner);
    await new Promise((r) => setTimeout(r, 100));
    // B answered the converged position with SILENCE — no reply frame at all.
    expect(fB.sent.length).toBe(quietB);
  });

  it("FORWARDING is load-bearing (AC2 shape): the author is GONE, and their signed work reaches a third holder through someone else's exchange", async () => {
    // The standing ruling that unlocked the pivot: holders forward each other's signed entries,
    // and forwarding confers no trust — the receiver verifies the author's signature itself.
    // Here A authors content, A is never heard from again, and C ends up holding A's write
    // because B's exchange carried it. Without forwarding, three holders cannot converge when
    // an author goes offline; this is that claim, in process.
    const fA = await newFixture();
    const fB = await newFixture();
    const fC = await newFixture();
    const proposed = await fA.call("cello_doc_propose", { peer_pubkey: fB.owner });
    const documentId = proposed.documentId as string;
    const proposalSend = fA.sent.find((send) => send.peerAgentId === fB.owner)!;
    fB.layer.onDocumentFrame(AGENT, "session-1", proposalSend.bytes, fA.owner);
    await until(() => fB.layer.handshake.pending(fB.owner).length === 1);
    await fB.call("cello_doc_accept", { document_id: documentId });
    routeAll(fB, fA);
    await until(() => fA.layer.store.currentDocumentEpoch(fA.owner, documentId) === 1);

    // C joins FIRST (seated through the exchange), so C's copy predates what A writes next.
    await fA.call("cello_doc_invite", { document_id: documentId, invitee_pubkey: fC.owner });
    await seatViaExchange(fA, fC, documentId);
    await fC.call("cello_doc_accept", { document_id: documentId });
    // B must know C is seated before it will answer C's exchange: route C's consent AND the
    // admitting entry to B (in production the amendment carrier owes B both; here we route).
    const inviteToB = fA.sent.filter((send) => send.peerAgentId === fB.owner).at(-1)!;
    fB.layer.onDocumentFrame(AGENT, "session-1", inviteToB.bytes, fA.owner);
    routeAll(fC, fB);
    routeAll(fC, fA);
    await until(() => fB.layer.amendments.chain(fB.owner, documentId).length === 3);
    await until(() => fA.layer.amendments.chain(fA.owner, documentId).length === 3);

    // NOW A writes — after the offer, so C does not hold it — and B fetches it through the
    // exchange: the last answer A ever gives. (Everyone is at the same interim epoch stamp;
    // the stamp's coupling to content is the P4 gate's deletion target.)
    await fA.call("cello_doc_write", { document_id: documentId, content: "A's last words. " });
    const bInit = fB.sent.length;
    await fB.layer.initiateReconcile(fB.owner, fA.owner, [documentId]);
    const bStep1 = fB.sent.slice(bInit).find((send) => send.peerAgentId === fA.owner)!;
    const aBefore = fA.sent.length;
    fA.layer.onDocumentFrame(AGENT, "session-1", bStep1.bytes, fB.owner);
    await until(() => fA.sent.length > aBefore);
    const aStep2 = fA.sent.slice(aBefore).find((send) => send.peerAgentId === fB.owner)!;
    fB.layer.onDocumentFrame(AGENT, "session-1", aStep2.bytes, fA.owner);
    await until(() =>
      String(fB.layer.live.get(fB.owner, documentId).getText("content")).includes("A's last words"),
    );

    // C reconciles with B — NOT with A, who no longer exists. The offer carried the governance
    // history; A's CONTENT arrives only here, forwarded by B, and C verifies A's signature
    // itself on apply.
    const cBefore = fC.sent.length;
    await fC.layer.initiateReconcile(fC.owner, fB.owner, [documentId]);
    const step1 = fC.sent.slice(cBefore).find((send) => send.peerAgentId === fB.owner)!;
    const bBefore = fB.sent.length;
    fB.layer.onDocumentFrame(AGENT, "session-1", step1.bytes, fC.owner);
    await until(() => fB.sent.length > bBefore);
    const step2 = fB.sent.slice(bBefore).find((send) => send.peerAgentId === fC.owner)!;
    fC.layer.onDocumentFrame(AGENT, "session-1", step2.bytes, fB.owner);

    await until(() =>
      String(fC.layer.live.get(fC.owner, documentId).getText("content")).includes("A's last words"),
    );
    // And the envelope C holds is A's — the author's signed identity, not the forwarder's.
    const cLog = fC.layer.store.getEnvelopeLog(fC.owner, documentId);
    expect(cLog.some((row) => row.senderAgentId === fA.owner)).toBe(true);
  });

  it("JOIN VIA THE EXCHANGE: no offer frame anywhere — the invite's own step-1 is the notice, and the reply carries the world", async () => {
    // The D5 replacement, end to end: A invites C and simply initiates a reconcile toward
    // them. C, holding nothing, answers with an empty hand; A's reply carries the genesis,
    // every entry, and the content; C bootstraps, derives its OWN standing as invited, and
    // accepting is the ordinary consent-authoring accept — the same verb, the same cure
    // branch, no bespoke history-carrying offer and no answer frame in the flow at all.
    const fA = await newFixture();
    const fB = await newFixture();
    const fC = await newFixture();
    const proposed = await fA.call("cello_doc_propose", { peer_pubkey: fB.owner });
    const documentId = proposed.documentId as string;
    const proposalSend = fA.sent.find((send) => send.peerAgentId === fB.owner)!;
    fB.layer.onDocumentFrame(AGENT, "session-1", proposalSend.bytes, fA.owner);
    await until(() => fB.layer.handshake.pending(fB.owner).length === 1);
    await fB.call("cello_doc_accept", { document_id: documentId });
    routeAll(fB, fA);
    await until(() => fA.layer.store.currentDocumentEpoch(fA.owner, documentId) === 1);

    // A invites C (the entry lands in A's chain; the notice frame the invite itself sent is
    // deliberately not routed) and writes content afterwards, so the exchange must carry both.
    await fA.call("cello_doc_invite", { document_id: documentId, invitee_pubkey: fC.owner });
    await fA.call("cello_doc_write", { document_id: documentId, content: "history before C. " });

    // The notice IS a step-1 position frame.
    const aInit = fA.sent.length;
    await fA.layer.initiateReconcile(fA.owner, fC.owner, [documentId]);
    const step1 = fA.sent.slice(aInit).find((send) => send.peerAgentId === fC.owner)!;

    // C answers with an empty hand…
    const cBefore = fC.sent.length;
    fC.layer.onDocumentFrame(AGENT, "session-1", step1.bytes, fA.owner);
    await until(() => fC.sent.length > cBefore);
    const emptyHand = fC.sent.slice(cBefore).find((send) => send.peerAgentId === fA.owner)!;

    // …and A's reply carries the genesis, the entries, and the content.
    const aBefore = fA.sent.length;
    fA.layer.onDocumentFrame(AGENT, "session-1", emptyHand.bytes, fC.owner);
    await until(() => fA.sent.length > aBefore);
    const world = fA.sent.slice(aBefore).find((send) => send.peerAgentId === fC.owner)!;
    fC.layer.onDocumentFrame(AGENT, "session-1", world.bytes, fA.owner);

    // C bootstrapped: the document exists, the content is there, and C's OWN derivation says
    // invited — the surface shows an invitation without any join-store row behind it.
    await until(() => fC.layer.store.getDocument(fC.owner, documentId) !== null);
    await until(() =>
      String(fC.layer.live.get(fC.owner, documentId).getText("content")).includes("history before C"),
    );

    // Accepting is the ORDINARY accept — the consent-authoring cure branch, same verb.
    const accepted = await fC.call("cello_doc_accept", { document_id: documentId });
    expect(accepted.ok, JSON.stringify(accepted)).toBe(true);
    expect(typeof accepted.consentEntry).toBe("string");

    // C's consent reaches A, and A's own derivation seats C as a participant.
    routeAll(fC, fA);
    await until(() => fA.layer.amendments.chain(fA.owner, documentId).length === 3);
    await until(() => fA.layer.holdersFor(fA.owner, documentId)!.includes(fC.owner));
    // The inviter's invitation surface settled FROM THE ENTRY — C is a participant, so no
    // pending-invitation row survives anywhere.
    {
      const settledList = await fA.call("cello_doc_list", {});
      const rows = (settledList.joinOffers as Array<Record<string, unknown>> | undefined) ?? [];
      expect(rows.find((r) => r.inviteeAgentId === fC.owner)).toBeUndefined();
    }
    const list = await fA.call("cello_doc_list", {});
    const row = (list.documents as Array<Record<string, unknown>>).find(
      (d) => d.documentId === documentId,
    )!;
    expect(row.participants).toContain(fC.owner);
  });

  it("A FORGED OR STRANGER-ADDRESSED GENESIS IS REFUSED, NOT STORED (review F2) — no session peer can spawn documents on this daemon", async () => {
    // Two adversarial bootstraps, both through the real router: (a) a genesis whose signature
    // does not verify against its named proposer; (b) a perfectly signed genesis for a document
    // that names this holder NOWHERE. Both must leave the store untouched — the old code
    // recorded both, handing any session peer an unlimited license to grow the store with
    // fabricated documents attributed to proposers who never signed them.
    const fA = await newFixture();
    const fC = await newFixture();

    // (a) Forged: a real proposal from A to C, signature stripped.
    const honest = await fA.call("cello_doc_propose", { peer_pubkey: fC.owner });
    const honestId = honest.documentId as string;
    const proposalToC = fA.sent.find((send) => send.peerAgentId === fC.owner)!;
    const forgedGenesis = decodeDocumentProposal(proposalToC.bytes);
    forgedGenesis.signature = new Uint8Array(64);
    const forgedWire = encodeDocumentReconcile({
      type: "document_reconcile",
      exchange_version: DOCUMENT_RECONCILE_EXCHANGE_VERSION,
      documents: [{
        document_id: honestId,
        governance: [], content: [], refused: [], entries: [], envelopes: [],
        genesis: new Uint8Array(encodeDocumentProposal(forgedGenesis)),
      }],
    });
    fC.layer.onDocumentFrame(AGENT, "session-1", new Uint8Array(forgedWire), fA.owner);
    await new Promise((r) => setTimeout(r, 100));
    expect(fC.layer.store.getDocument(fC.owner, honestId)).toBeNull();
    expect(fC.events).toContain("document.reconcile.genesis_refused");

    // (b) Signed but a stranger's: A proposes to A's own bare-key peer — C is named nowhere.
    const strangerDoc = await fA.call("cello_doc_propose", { peer_pubkey: fA.peer });
    const strangerId = strangerDoc.documentId as string;
    const strangerGenesis = fA.layer.handshake.get(fA.owner, strangerId)!.envelope;
    const strangerWire = encodeDocumentReconcile({
      type: "document_reconcile",
      exchange_version: DOCUMENT_RECONCILE_EXCHANGE_VERSION,
      documents: [{
        document_id: strangerId,
        governance: [], content: [], refused: [], entries: [], envelopes: [],
        genesis: new Uint8Array(encodeDocumentProposal(strangerGenesis)),
      }],
    });
    fC.layer.onDocumentFrame(AGENT, "session-1", new Uint8Array(strangerWire), fA.owner);
    await new Promise((r) => setTimeout(r, 100));
    expect(fC.layer.store.getDocument(fC.owner, strangerId)).toBeNull();
  });

  it("A FORWARDED ENVELOPE WITH A CORRUPTED SIGNATURE IS REFUSED — forwarding confers no trust, verified not asserted (R2)", async () => {
    // The AC2 test proves delivery; this proves VERIFICATION: B forwards A's envelope with the
    // signature corrupted, and C's gate refuses it — the forwarder cannot vouch for content.
    const fA = await newFixture();
    const fB = await newFixture();
    const proposed = await fA.call("cello_doc_propose", { peer_pubkey: fB.owner });
    const documentId = proposed.documentId as string;
    const proposalSend = fA.sent.find((send) => send.peerAgentId === fB.owner)!;
    fB.layer.onDocumentFrame(AGENT, "session-1", proposalSend.bytes, fA.owner);
    await until(() => fB.layer.handshake.pending(fB.owner).length === 1);
    await fB.call("cello_doc_accept", { document_id: documentId });
    routeAll(fB, fA);
    await until(() => fA.layer.store.currentDocumentEpoch(fA.owner, documentId) === 1);
    await fA.call("cello_doc_write", { document_id: documentId, content: "signed by A. " });

    // A "forwards" its own envelope to B with the signature corrupted — as a hostile forwarder
    // would after tampering.
    const row = fA.layer.store.getEnvelopeLog(fA.owner, documentId)[0]!;
    const tampered = encodeDocumentUpdateEnvelope({
      type: "document_update",
      document_id: row.documentId,
      epoch_id: row.epochId,
      doc_prev_hash: row.docPrevHash,
      sender_agent_id: row.senderAgentId,
      sender_client_id: 0,
      update_encoding: DOCUMENT_UPDATE_ENCODING_V1,
      governance_parents: [],
      state_vector: row.stateVector,
      update: row.payload!,
      signature: new Uint8Array(64),
    });
    const wire = encodeDocumentReconcile({
      type: "document_reconcile",
      exchange_version: DOCUMENT_RECONCILE_EXCHANGE_VERSION,
      documents: [{
        document_id: documentId,
        governance: [], content: [], refused: [], entries: [], envelopes: [new Uint8Array(tampered)],
      }],
    });
    fB.layer.onDocumentFrame(AGENT, "session-1", new Uint8Array(wire), fA.owner);
    await new Promise((r) => setTimeout(r, 100));
    // The tampered envelope was NOT applied.
    expect(
      String(fB.layer.live.get(fB.owner, documentId).getText("content")),
    ).not.toContain("signed by A");
  });

  it("REFUSAL VIA THE EXCHANGE: the invitee's signed no settles the inviter's surface, and an unanswered invitation can be RETRACTED", async () => {
    // Both halves of ending an invitation under the new model: the invitee declines by
    // authoring their own refuse_join entry (no answer frame anywhere), and separately, an
    // admin takes back an offer nobody answered with the same removal verb every seat answers
    // to — a consent racing the retraction loses under removal dominance.
    const fA = await newFixture();
    const fB = await newFixture();
    const fC = await newFixture();
    const proposed = await fA.call("cello_doc_propose", { peer_pubkey: fB.owner });
    const documentId = proposed.documentId as string;
    const proposalSend = fA.sent.find((send) => send.peerAgentId === fB.owner)!;
    fB.layer.onDocumentFrame(AGENT, "session-1", proposalSend.bytes, fA.owner);
    await until(() => fB.layer.handshake.pending(fB.owner).length === 1);
    await fB.call("cello_doc_accept", { document_id: documentId });
    routeAll(fB, fA);
    await until(() => fA.layer.store.currentDocumentEpoch(fA.owner, documentId) === 1);
    await fA.call("cello_doc_invite", { document_id: documentId, invitee_pubkey: fC.owner });

    // Bootstrap C through the exchange (the join test's flow, condensed).
    const aInit = fA.sent.length;
    await fA.layer.initiateReconcile(fA.owner, fC.owner, [documentId]);
    const step1 = fA.sent.slice(aInit).find((send) => send.peerAgentId === fC.owner)!;
    const cBefore = fC.sent.length;
    fC.layer.onDocumentFrame(AGENT, "session-1", step1.bytes, fA.owner);
    await until(() => fC.sent.length > cBefore);
    const emptyHand = fC.sent.slice(cBefore).find((send) => send.peerAgentId === fA.owner)!;
    const aBefore = fA.sent.length;
    fA.layer.onDocumentFrame(AGENT, "session-1", emptyHand.bytes, fC.owner);
    await until(() => fA.sent.length > aBefore);
    const world = fA.sent.slice(aBefore).find((send) => send.peerAgentId === fC.owner)!;
    fC.layer.onDocumentFrame(AGENT, "session-1", world.bytes, fA.owner);
    await until(() => fC.layer.store.getDocument(fC.owner, documentId) !== null);

    // C DECLINES — their own signed entry, authored and fanned like everything else.
    const refused = await fC.call("cello_doc_refuse", { document_id: documentId });
    expect(refused.ok, JSON.stringify(refused)).toBe(true);
    expect(typeof refused.refusalEntry).toBe("string");
    routeAll(fC, fA);
    await until(() =>
      fA.layer.amendments
        .chain(fA.owner, documentId)
        .some((e) => e.body.kind === "refuse_join" && e.body.subject_agent_id === fC.owner),
    );
    // The inviter's surface shows the refusal — derived from the entry, no answer frame anywhere.
    const refusedList = await fA.call("cello_doc_list", {});
    expect(
      ((refusedList.joinOffers as Array<Record<string, unknown>> | undefined) ?? []).find(
        (r) => r.inviteeAgentId === fC.owner,
      ),
    ).toMatchObject({ state: "refused" });
    // C is no longer a seat anywhere.
    expect(fA.layer.holdersFor(fA.owner, documentId)).not.toContain(fC.owner);

    // RETRACTION: invite a fourth key that never answers, then take the offer back.
    const ghost = "9".repeat(64);
    await fA.call("cello_doc_invite", { document_id: documentId, invitee_pubkey: ghost });
    expect(fA.layer.holdersFor(fA.owner, documentId)).toContain(ghost);
    const retracted = await fA.call("cello_doc_remove", {
      document_id: documentId, holder_pubkey: ghost,
    });
    expect(retracted.ok, JSON.stringify(retracted)).toBe(true);
    expect(fA.layer.holdersFor(fA.owner, documentId)).not.toContain(ghost);
  });

  it("REMOVE-1: an admin removes the joined holder — forward-only on the removed daemon", async () => {
    const fA = await newFixture();
    const fC = await newFixture();
    const proposed = await fA.call("cello_doc_propose", {
      peer_pubkey: fA.peer, starting_content: "content C keeps forever. ",
    });
    const documentId = proposed.documentId as string;
    await fA.call("cello_doc_invite", { document_id: documentId, invitee_pubkey: fC.owner });
    await seatViaExchange(fA, fC, documentId);
    await fC.call("cello_doc_accept", { document_id: documentId });
    // C's consent entry reaches A — C is a participant A can remove (an invited seat cannot be
    // removed through the holder door; it has not sat down yet).
    routeAll(fC, fA);
    await until(() => fA.layer.store.currentDocumentEpoch(fA.owner, documentId) === 2);

    const removed = await fA.call("cello_doc_remove", {
      document_id: documentId, holder_pubkey: fC.owner,
    });
    expect(removed).toMatchObject({ ok: true, voluntary: false, epochId: 3 });
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
    expect((gate as { detail: string }).detail).toContain("epoch 3");
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
    await seatViaExchange(fA, fC, documentId);
    await fC.call("cello_doc_accept", { document_id: documentId });
    // A learns of C's consent before C leaves — otherwise the leave entry (which chains onto the
    // consent) sits held on A awaiting a parent A never got.
    routeAll(fC, fA);
    await until(() => fA.layer.store.currentDocumentEpoch(fA.owner, documentId) === 2);

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
    routeAll(fC, fA);
    await until(
      () => fA.layer.amendments.membershipOf(fA.owner, documentId, fC.owner).state === "removed",
    );
  });

  it("REMOVE-1: a fellow ADMIN cannot be expelled through the holder door — the policy's sentence surfaces", async () => {
    const fA = await newFixture();
    const fB = await newFixture();
    // Default admins = both parties; B consents, so B is a PARTICIPATING admin — and removing
    // an admin as a holder must refuse with the policy's own sentence.
    const proposed = await fA.call("cello_doc_propose", { peer_pubkey: fB.owner });
    const documentId = proposed.documentId as string;
    const proposalSend = fA.sent.find((send) => send.peerAgentId === fB.owner)!;
    fB.layer.onDocumentFrame(AGENT, "session-1", proposalSend.bytes, fA.owner);
    await until(() => fB.layer.handshake.pending(fB.owner).length === 1);
    await fB.call("cello_doc_accept", { document_id: documentId });
    routeAll(fB, fA);
    await until(() => fA.layer.store.currentDocumentEpoch(fA.owner, documentId) === 1);
    const res = await fA.call("cello_doc_remove", {
      document_id: documentId, holder_pubkey: fB.owner,
    });
    expect(res).toMatchObject({ ok: false, reason: "document_amendment_invalid" });
    expect(String(res.guidance)).toContain("governance_remove_admin_first");
  });

  it("a non-admin cannot invite — refused at authoring, and no notice leaves", async () => {
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
    // The inviter's own daemon refuses at authoring — a non-admin cannot even mint the entry.
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
    // The LOG is the whole record now (D1): one envelope authored, carried by the exchange.
    expect(f.layer.store.getEnvelopeLog(f.owner, documentId)).toHaveLength(1);
  });

  it("an unchanged write publishes NOTHING", async () => {
    const f = await newFixture();
    const documentId = (await f.call("cello_doc_propose", { peer_pubkey: f.peer, starting_content: "same" })).documentId as string;

    const res = await f.call("cello_doc_write", { document_id: documentId, content: "same" });
    // Publishing anyway would append a leaf, cost a delivery, and converge nothing.
    expect(res).toMatchObject({ ok: true, changed: false, published: false });
    expect(f.layer.store.getEnvelopeLog(f.owner, documentId)).toHaveLength(0);
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
    expect(f.layer.store.getEnvelopeLog(f.owner, documentId)).toHaveLength(0);

    f.layer.lifecycle.setPlatformPaused(f.owner, false, NOW);
    const retry = await f.call("cello_doc_write", { document_id: documentId, content: "written while paused" });

    expect(retry).toMatchObject({ ok: true, changed: false, published: true });
    // THE ASSERTION THAT MATTERS: it is now deliverable. Reporting `published: true` while the log
    // stayed empty would be the same lie one layer up.
    expect(
      f.layer.store.getEnvelopeLog(f.owner, documentId),
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
    expect(f.layer.store.getEnvelopeLog(f.owner, documentId)).toHaveLength(0);
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
    expect(f.layer.store.getEnvelopeLog(f.owner, documentId)).toHaveLength(0);
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
    expect(f.layer.store.getEnvelopeLog(f.owner, documentId)).toHaveLength(0);
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

describe("ENDINGS AS ENTRIES — close and kill travel like everything else and settle by derivation", () => {
  async function threeSeated() {
    // The threeHolders shape, local to this describe after the control-frame path's retirement.
    const fA = await newFixture();
    const fB = await newFixture();
    const fC = await newFixture();
    const proposed = await fA.call("cello_doc_propose", {
      peer_pubkey: fB.owner, starting_content: "shared base. ", admins: [fA.owner],
    });
    const documentId = proposed.documentId as string;
    const proposalSend = fA.sent.find((send) => send.peerAgentId === fB.owner)!;
    fB.layer.onDocumentFrame(AGENT, "session-1", proposalSend.bytes, fA.owner);
    await until(() => fB.layer.handshake.pending(fB.owner).length === 1);
    await fB.call("cello_doc_accept", { document_id: documentId });
    routeAll(fB, fA);
    await until(() => fA.layer.store.currentDocumentEpoch(fA.owner, documentId) === 1);
    await fA.call("cello_doc_invite", { document_id: documentId, invitee_pubkey: fC.owner });
    await seatViaExchange(fA, fC, documentId);
    await fC.call("cello_doc_accept", { document_id: documentId });
    routeAll(fC, fA);
    await until(() => fA.layer.amendments.chain(fA.owner, documentId).length === 3);
    // B learns of C too, so every fold agrees who is seated.
    const inviteToB = fA.sent.filter((send) => send.peerAgentId === fB.owner).at(-1)!;
    fB.layer.onDocumentFrame(AGENT, "session-1", inviteToB.bytes, fA.owner);
    routeAll(fC, fB);
    await until(() => fB.layer.amendments.chain(fB.owner, documentId).length === 3);
    return { fA, fB, fC, documentId };
  }

  it("one close does NOT settle; every seat's own close does — derived on every daemon, no settlement bookkeeping anywhere", async () => {
    const { fA, fB, fC, documentId } = await threeSeated();
    const aClosed = await fA.call("cello_doc_close", { document_id: documentId });
    expect(aClosed.ok, JSON.stringify(aClosed)).toBe(true);
    expect(aClosed.ended).toBeNull();
    expect((aClosed.waitingOn as string[]).sort()).toEqual([fB.owner, fC.owner].sort());
    // The close ENTRY reached both seats over the ordinary carrier.
    routeAll(fA, fB);
    routeAll(fA, fC);
    await until(() => fB.layer.amendments.chain(fB.owner, documentId).length === 4);
    expect(fB.layer.store.getDocument(fB.owner, documentId)!.status).not.toBe("closed");

    // B and C close too; entries spread; EVERY daemon derives closed and projects it.
    await fB.call("cello_doc_close", { document_id: documentId });
    await fC.call("cello_doc_close", { document_id: documentId });
    routeAll(fB, fA); routeAll(fC, fA); routeAll(fB, fC); routeAll(fC, fB);
    await until(() => fA.layer.store.getDocument(fA.owner, documentId)!.status === "closed");
    await until(() => fB.layer.store.getDocument(fB.owner, documentId)!.status === "closed");
    await until(() => fC.layer.store.getDocument(fC.owner, documentId)!.status === "closed");
  });

  it("REMOVING the holder who never closed COMPLETES the agreement — by derivation, with no code acting on it", async () => {
    const { fA, fB, fC, documentId } = await threeSeated();
    await fA.call("cello_doc_close", { document_id: documentId });
    await fB.call("cello_doc_close", { document_id: documentId });
    routeAll(fB, fA);
    await until(() => fA.layer.amendments.chain(fA.owner, documentId).length === 5);
    expect(fA.layer.store.getDocument(fA.owner, documentId)!.status).not.toBe("closed");
    const removed = await fA.call("cello_doc_remove", {
      document_id: documentId, holder_pubkey: fC.owner,
    });
    expect(removed.ok, JSON.stringify(removed)).toBe(true);
    await until(() => fA.layer.store.getDocument(fA.owner, documentId)!.status === "closed");
  });

  it("a KILL is one admin's entry — immediate locally, and the entry stops the other daemons when it lands", async () => {
    const { fA, fB, documentId } = await threeSeated();
    const killed = await fA.call("cello_doc_kill", { document_id: documentId });
    expect(killed.ok, JSON.stringify(killed)).toBe(true);
    expect(killed.ended).toBe("killed");
    expect(fA.layer.store.getDocument(fA.owner, documentId)!.status).toBe("killed");
    routeAll(fA, fB);
    await until(() => fB.layer.store.getDocument(fB.owner, documentId)!.status === "killed");
  });

  it("a kill SUCCEEDS with every peer unreachable — the entry is recorded and owed; nothing about ending waits on the network", async () => {
    const { fA, documentId } = await threeSeated();
    fA.goOffline();
    const killed = await fA.call("cello_doc_kill", { document_id: documentId });
    expect(killed.ok, JSON.stringify(killed)).toBe(true);
    expect(fA.layer.store.getDocument(fA.owner, documentId)!.status).toBe("killed");
    // The ENTRY is the durable debt (D2: no ledger): it is in the chain, every delivery honestly
    // reported failed, and any later exchange with any seat carries it.
    expect((killed.killDelivered as Record<string, boolean>)).not.toEqual({});
    expect(Object.values(killed.killDelivered as Record<string, boolean>).every((v) => v === false)).toBe(true);
    expect(
      fA.layer.amendments.chain(fA.owner, documentId).some((e) => e.body.kind === "kill"),
    ).toBe(true);
  });

  it("a chain that will not derive REFUSES to close rather than guessing", async () => {
    const { fA, documentId } = await threeSeated();
    fA.layer.store.rawDb
      .prepare(`UPDATE document_entries SET received_bytes = ? WHERE document_id = ?`)
      .run(new Uint8Array([0xff, 0xff, 0xff]), documentId);
    const res = await fA.call("cello_doc_close", { document_id: documentId });
    expect(res).toMatchObject({ ok: false, reason: "document_close_unrecorded" });
  });

  it("a LEGACY document with no genesis record refuses to close by agreement — named, not guessed (the control-frame fallback is retired)", async () => {
    const fA = await newFixture();
    const proposed = await fA.call("cello_doc_propose", { peer_pubkey: fA.peer });
    const documentId = proposed.documentId as string;
    fA.layer.store.rawDb
      .prepare(`DELETE FROM document_proposals WHERE document_id = ?`)
      .run(documentId);
    const res = await fA.call("cello_doc_close", { document_id: documentId });
    expect(res.ok).toBe(false);
    expect(String(res.reason)).toBe("document_close_unrecorded");
  });
});


describe("the admission SURVIVES an unreachable holder — through the exchange, not a ledger (SYNC-P4)", () => {
  it("a holder unreachable at invite time learns of the admission at the next exchange", async () => {
    const fA = await newFixture({ sendFails: "session_sealed" });
    const fB = await newFixture();
    const fC = await newFixture();
    const proposed = await fA.call("cello_doc_propose", {
      peer_pubkey: fB.owner,
      starting_content: "a document with a second holder who is about to go dark. ",
    });
    const documentId = proposed.documentId as string;
    // B consented while reachable (frames route directly; only A's TRANSPORT is dark).
    const proposalSend = fA.sent.find((send) => send.peerAgentId === fB.owner)!;
    fB.layer.onDocumentFrame(AGENT, "session-1", proposalSend.bytes, fA.owner);
    await until(() => fB.layer.handshake.pending(fB.owner).length === 1);
    await fB.call("cello_doc_accept", { document_id: documentId });
    routeAll(fB, fA);
    await until(() => fA.layer.store.currentDocumentEpoch(fA.owner, documentId) === 1);

    const invited = await fA.call("cello_doc_invite", {
      document_id: documentId,
      invitee_pubkey: fC.owner,
    });
    expect(invited.ok).toBe(true);
    // The fan-out ran and reported the truth per holder — B was NOT told.
    expect((invited.holdersNotified as Record<string, boolean>)[fB.owner]).toBe(false);
    expect(fB.layer.amendments.chain(fB.owner, documentId)).toHaveLength(1);

    // No ledger anywhere (D2) — the admission's durability IS the chain. When A's transport
    // comes back, ONE exchange closes the difference: B's position lacks the admit entry, so
    // A's answer carries it.
    fA.peerComesOnline();
    const before = fA.sent.length;
    await fA.layer.initiateReconcile(fA.owner, fB.owner, [documentId]);
    const step1 = fA.sent.slice(before).find((send) => send.peerAgentId === fB.owner)!;
    fB.layer.onDocumentFrame(AGENT, "session-1", step1.bytes, fA.owner);
    await until(() => fB.sent.length > 0);
    routeAll(fB, fA);
    await new Promise((r) => setTimeout(r, 50));
    routeAll(fA, fB);
    await until(() =>
      fB.layer.amendments
        .chain(fB.owner, documentId)
        .some((e) => e.body.kind === "add_holder" && e.body.subject_agent_id === fC.owner),
    );
  });

  it("the INVITER and the INVITEE are not in the fan-out — only the existing holders", async () => {
    const fA = await newFixture();
    const fB = await newFixture();
    const fC = await newFixture();
    const proposed = await fA.call("cello_doc_propose", {
      peer_pubkey: fB.owner, starting_content: "who is told what. ",
    });
    const documentId = proposed.documentId as string;
    const proposalSend = fA.sent.find((send) => send.peerAgentId === fB.owner)!;
    fB.layer.onDocumentFrame(AGENT, "session-1", proposalSend.bytes, fA.owner);
    await until(() => fB.layer.handshake.pending(fB.owner).length === 1);
    await fB.call("cello_doc_accept", { document_id: documentId });
    routeAll(fB, fA);
    await until(() => fA.layer.store.currentDocumentEpoch(fA.owner, documentId) === 1);
    const invited = await fA.call("cello_doc_invite", { document_id: documentId, invitee_pubkey: fC.owner });
    // The invitee gets the NOTICE (their bootstrap carries the chain), and a daemon does not fan
    // governance to itself — the per-holder report names exactly the existing other holders.
    expect(Object.keys(invited.holdersNotified as Record<string, boolean>)).toEqual([fB.owner]);
  });
});

/**
 * DOD-MP-REMOVE-FEEDBACK-1 — the removed holder's OWN view.
 *
 * The write refusal already names the removal. `cello_doc_list` did not mention it at all: the
 * document simply stopped listing them among the participants, which renders identically to a
 * document they are still part of and haven't looked at closely. So the one surface an operator
 * checks to answer "what is going on with my documents" was silent about the single fact that
 * changes what they can do with this one.
 *
 * FORWARD-ONLY-REMOVAL is the constraint on the wording: nothing here may imply the copy was taken
 * back, because it was not and cannot be.
 */
describe("DOD-MP-REMOVE-FEEDBACK-1 — a holder who is out is told, on the surface they check", () => {
  const rowFor = async (f: Awaited<ReturnType<typeof newFixture>>, documentId: string) => {
    const list = await f.call("cello_doc_list");
    return (list.documents as Array<Record<string, unknown>>).find(
      (d) => d["documentId"] === documentId,
    )!;
  };

  it("the row says they are out, at which epoch, and that the copy is theirs", async () => {
    const fA = await newFixture();
    const fB = await newFixture();
    const proposed = await fA.call("cello_doc_propose", {
      peer_pubkey: fB.owner, starting_content: "shared for a while. ",
    });
    const documentId = proposed.documentId as string;
    // B consents first — a solo proposer leaving would orphan the document (zero admins), and
    // the derivation refuses that by the admin floor.
    const proposalSend = fA.sent.find((send) => send.peerAgentId === fB.owner)!;
    fB.layer.onDocumentFrame(AGENT, "session-1", proposalSend.bytes, fA.owner);
    await until(() => fB.layer.handshake.pending(fB.owner).length === 1);
    await fB.call("cello_doc_accept", { document_id: documentId });
    routeAll(fB, fA);
    await until(() => fA.layer.store.currentDocumentEpoch(fA.owner, documentId) === 1);
    const left = await fA.call("cello_doc_remove", {
      document_id: documentId, holder_pubkey: fA.owner,
    });
    expect(left).toMatchObject({ ok: true, voluntary: true });

    const row = await rowFor(fA, documentId);
    // The row has carried `removed: true` since REMOVE-1. What was missing is that a bare flag is
    // not feedback — it says nothing about when, about the copy, or about what actually stopped.
    expect(row["removed"]).toBe(true);
    expect(row["yourStanding"]).toBe("removed");
    expect(typeof row["removedAtEpoch"]).toBe("number");
    const sentence = String(row["standingGuidance"] ?? "");
    expect(sentence.length, "a flag with no sentence is not feedback").toBeGreaterThan(40);
    expect(sentence).toMatch(/no longer a holder|removed/i);
    expect(sentence).toContain("remain yours");
    expect(sentence).toMatch(/no longer publish|do not publish|stop publishing/i);
    // FORWARD-ONLY-REMOVAL: nothing may read as though the copy was taken.
    expect(sentence).not.toMatch(/revoked|deleted|taken|lost access to your copy/i);
  });

  it("REMOVING SOMEONE ELSE leaves your OWN row saying holder", async () => {
    // The bypass the review proved: an implementation that reports removal whenever the chain
    // contains ANY remove_holder — subject filter ignored — passed the whole suite, because the
    // only negative case was a document with an EMPTY chain. That cannot tell "I am still a
    // holder" from "nothing has happened here yet". This one has a real removal in the chain.
    const fA = await newFixture();
    const fC = await newFixture();
    const proposed = await fA.call("cello_doc_propose", { peer_pubkey: fA.peer });
    const documentId = proposed.documentId as string;
    await fA.call("cello_doc_invite", { document_id: documentId, invitee_pubkey: fC.owner });
    // C consents — seated through the exchange, then the ordinary consent-authoring accept.
    await seatViaExchange(fA, fC, documentId);
    await fC.call("cello_doc_accept", { document_id: documentId });
    routeAll(fC, fA);
    await until(() => fA.layer.store.currentDocumentEpoch(fA.owner, documentId) === 2);
    const removed = await fA.call("cello_doc_remove", {
      document_id: documentId, holder_pubkey: fC.owner,
    });
    expect(removed).toMatchObject({ ok: true });

    const row = await rowFor(fA, documentId);
    // The ADMIN who removed somebody else must not be told they are out of their own document.
    expect(row["yourStanding"], "the subject of the removal was someone else").toBe("holder");
    expect(row["removed"]).toBeUndefined();
    expect(row["standingGuidance"]).toBeUndefined();
  });

  it("INVITING someone leaves your own row saying holder", async () => {
    // The sibling bypass: an implementation keyed on `state !== "untouched"` would mislabel every
    // party to a chain that has any amendment at all, including the inviter.
    const fA = await newFixture();
    const fC = await newFixture();
    const proposed = await fA.call("cello_doc_propose", { peer_pubkey: fA.peer });
    const documentId = proposed.documentId as string;
    await fA.call("cello_doc_invite", { document_id: documentId, invitee_pubkey: fC.owner });
    const row = await rowFor(fA, documentId);
    expect(row["yourStanding"]).toBe("holder");
  });

  it("a chain this build cannot read says UNKNOWN, never 'holder'", async () => {
    const fA = await newFixture();
    const proposed = await fA.call("cello_doc_propose", { peer_pubkey: fA.peer });
    const documentId = proposed.documentId as string;
    // A chain that will not decode. The membership walk honestly cannot answer here, and it
    // reports not-removed — so a key that is merely ABSENT renders a removed holder as fine.
    fA.db.prepare(
      `INSERT INTO document_entries
         (owner_agent_id, document_id, entry_hash, author_agent_id, author_seq, epoch_id,
          received_bytes, recorded_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(fA.owner, documentId, "ff".repeat(32), "a".repeat(64), 1, 1, Buffer.from([0xff, 0xff, 0xff]), 1);

    const row = await rowFor(fA, documentId);
    expect(row["arrangementUnavailable"]).toBeDefined();
    // ALWAYS PRESENT, exactly as `participants` is null rather than absent on the same failure.
    expect(row["yourStanding"], "silence here reads as 'you are fine'").toBe("unknown");
    expect(String(row["standingGuidance"])).toContain("cannot tell");
  });
});

describe("DOD-MP-REMOVE-FEEDBACK-1 — a write REFUSES on an unreadable chain, never throws", () => {
  it("the operator gets a named reason, not a CBOR library message", async () => {
    const fA = await newFixture();
    const proposed = await fA.call("cello_doc_propose", {
      peer_pubkey: fA.peer, starting_content: "before the chain went bad. ",
    });
    const documentId = proposed.documentId as string;
    fA.db.prepare(
      `INSERT INTO document_entries
         (owner_agent_id, document_id, entry_hash, author_agent_id, author_seq, epoch_id,
          received_bytes, recorded_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(fA.owner, documentId, "ff".repeat(32), "a".repeat(64), 1, 1, Buffer.from([0xff, 0xff, 0xff]), 1);

    // `holdersFor` is contracted to return null when it cannot derive, and the publish path is
    // already holding a named refusal for that. The chain decode threw straight past both, so the
    // operator got `Data read, but end of buffer not reached` — where it surfaced, not what is
    // wrong — on one of the three surfaces this DoD line names.
    const res = await fA.call("cello_doc_write", { document_id: documentId, content: "an edit. " });

    // It does not THROW, which is the whole finding. The shape it returns is the documented one for
    // this case — the edit is applied to the local copy and NOT published — and the reason names
    // the chain rather than the CBOR reader.
    expect(res.published).toBe(false);
    // The refusal moved EARLIER and got more precise: the frontier cannot be derived from an
    // unreadable chain, and publish refuses before building anything.
    expect(String(res.reason)).toBe("document_frontier_underivable");
    const said = `${String(res.guidance ?? "")} ${String(res.detail ?? "")}`;
    expect(said).not.toMatch(/end of buffer/i);
    expect(said).toMatch(/governance could not be derived|does not derive from its recorded chain/i);
  });
});
