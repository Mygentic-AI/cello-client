/**
 * DOD-DOC-TOOLS-1 — two parties, through the operator surface, with the wire connected.
 *
 * Every other document test exercises one unit with the other side stubbed. This one wires two
 * complete layers to each other: two databases, two real Ed25519 keypairs, two frame routers, and
 * nothing shared but bytes. A party's `sendBytes` hands its output to the OTHER party's
 * `onDocumentFrame` — the same entry point the session content path calls in production.
 *
 * That is the difference that matters. The two defects that made the shipped delivery wiring a
 * no-op — the inbound half scoped by agent NAME while the outbound half queried by pubkey hex, and
 * a session opener called with a field name nothing reads — were both invisible to single-unit
 * tests, because a stub on the far side agrees with whatever the near side does. A connected wire
 * does not.
 *
 * What this does NOT cover, deliberately: real sessions, the relay, the seal, and the delivery
 * worker's scheduling. Those are the live enforcers' job (DOD-DOC-E2E-*). This covers the surface
 * contract — that the seven verbs, composed the way an operator composes them, converge two
 * documents.
 *
 * `node:sqlite` here is the test-file allowance; production is SQLCipher.
 */

import { describe, it, expect, vi } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { Buffer } from "node:buffer";
import { generateKeypair } from "@cello-protocol/crypto";
import { encodeDocumentUpdateEnvelope, DOCUMENT_UPDATE_ENCODING_V1 } from "@cello-protocol/protocol-types";
import { registerDocumentHandlers } from "../document-handlers.js";
import { createDocumentLayer, agentPublicKeyFromId } from "../document-layer.js";
import { DocumentPublish } from "../document-publish.js";
import { DocumentDelivery } from "../document-delivery.js";
import type { DocumentDeliveryTransport } from "../document-delivery.js";
import type { IpcHandler } from "../ipc-server.js";
import type { Logger } from "../types.js";

const NOW = 1_700_000_000_000;

function silentLogger(): Logger {
  const noop = () => {};
  const logger = { debug: noop, info: noop, warn: noop, error: noop, child: () => logger } as unknown as Logger;
  return logger;
}

/** Delivers bytes to whichever party is wired in as the counterparty, or refuses if none is. */
interface Wire {
  deliverToPeer: ((bytes: Uint8Array) => void) | null;
  online: boolean;
}

async function makeParty(agentName: string) {
  const keys = generateKeypair();
  const owner = Buffer.from(await keys.getPublicKey()).toString("hex");
  const logger = silentLogger();
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");

  const wire: Wire = { deliverToPeer: null, online: true };

  const layer = createDocumentLayer({
    db,
    logger,
    publicKeyFor: agentPublicKeyFromId,
    // The NAME→KEY map, exactly as the daemon does it. Both halves resolve through this one
    // function; when they did not, every row landed where the other half never looked.
    ownerKeyFor: (n) => (n === agentName ? owner : null),
    notifyPeer: async () => ({ ok: true }),
    rollback: () => ({ ok: true }),
    sign: async (_o, tbs) => keys.sign(tbs),
  });

  const transport = {
    isPeerReachable: async () => ({ reachable: wire.online, unknownAgent: false }),
    sendBytes: async (input: { bytes: Uint8Array }) => {
      if (!wire.online || !wire.deliverToPeer) return { ok: false as const, reason: "peer_offline" };
      wire.deliverToPeer(input.bytes);
      return { ok: true as const, sessionId: "session-1", sessionOpened: true };
    },
    deliver: async (input: { envelope: { payload: Uint8Array | null } }) => {
      if (!wire.online || !wire.deliverToPeer) return { ok: false as const, reason: "peer_offline" };
      // The worker hands the transport a LOG ROW; production re-encodes it into the wire envelope.
      // Reproduced here rather than shortcut, because encoding is where the two halves can disagree
      // about a field and the peer refuses something we believe we sent correctly.
      wire.deliverToPeer(encodeFromRow(input.envelope));
      return { ok: true as const, sessionId: "session-1", sessionOpened: false, admitted: null };
    },
  } as unknown as DocumentDeliveryTransport;

  const publish = new DocumentPublish({
    store: layer.store,
    engine: layer.engine,
    logger,
    sign: async (_o, tbs) => keys.sign(tbs),
    senderIdFor: (o) => o,
    canPublish: (o, d) => layer.lifecycle.canPublish(o, d),
  });

  const handlers = new Map<string, IpcHandler>();
  registerDocumentHandlers({
    handlers,
    logger,
    layer,
    publish,
    transportFor: () => transport,
    resolveAgent: () => agentName,
    ownerKeyFor: (n) => (n === agentName ? owner : null),
    sign: async (_n, tbs) => keys.sign(tbs),
    now: () => NOW,
  });

  const worker = new DocumentDelivery(layer.store, transport, logger);

  return {
    agentName,
    owner,
    layer,
    wire,
    worker,
    call: (verb: string, params: Record<string, unknown> = {}) =>
      handlers.get(verb)!(params, "conn") as Promise<Record<string, unknown>>,
    /** The production entry point: whatever arrives on the session content path. */
    receive: (bytes: Uint8Array) => layer.onDocumentFrame(agentName, "session-1", bytes, "pk", "wire"),
    /** Run one delivery pass, the way the daemon's sweep does. */
    sweep: () =>
      worker.tick(
        owner,
        (documentId) => layer.store.getDocument(owner, documentId)?.peerAgentId ?? null,
        NOW,
        { senderAgentId: owner },
      ),
    text: (documentId: string) => layer.live.get(owner, documentId).getText("content").toString(),
  };
}

/** Re-encode a stored envelope row the way the daemon's composition root does. */
function encodeFromRow(row: unknown): Uint8Array {
  const r = row as {
    documentId: string; epochId: string; docPrevHash: string | null; senderAgentId: string;
    senderClientId: number | null; stateVector: Uint8Array; payload: Uint8Array | null; signature: Uint8Array;
  };
  // The SHIPPED encoder, not a hand-built object: encoding is where the two halves can disagree
  // about a field, and the peer then refuses something we believe we sent correctly.
  return encodeDocumentUpdateEnvelope({
    type: "document_update",
    document_id: r.documentId,
    epoch_id: r.epochId,
    doc_prev_hash: r.docPrevHash,
    sender_agent_id: r.senderAgentId,
    sender_client_id: r.senderClientId ?? 0,
    update_encoding: DOCUMENT_UPDATE_ENCODING_V1,
    state_vector: r.stateVector,
    update: r.payload ?? new Uint8Array(0),
    signature: r.signature,
  });
}

/** Connect two parties' wires to each other's inbound path. */
function connect(a: Awaited<ReturnType<typeof makeParty>>, b: Awaited<ReturnType<typeof makeParty>>) {
  a.wire.deliverToPeer = (bytes) => b.receive(bytes);
  b.wire.deliverToPeer = (bytes) => a.receive(bytes);
}

describe("two parties converge through the operator surface", () => {
  it("propose → accept → write → deliver → converge", async () => {
    const a = await makeParty("alice");
    const b = await makeParty("bob");
    connect(a, b);

    // 1. Alice offers. The proposal reaches Bob's inbound path as bytes.
    const proposed = await a.call("cello_doc_propose", {
      peer_pubkey: b.owner,
      starting_content: "# Plan\n",
    });
    expect(proposed).toMatchObject({ ok: true, proposalSent: true });
    const documentId = proposed.documentId as string;

    // 2. It is Bob's decision, and it is in his inbox because Alice's signature verified against
    //    the agent she named.
    await vi.waitFor(async () =>
      expect(await b.call("cello_doc_inbox")).toMatchObject({ proposals: [{ documentId }] }),
    );
    expect(await b.call("cello_doc_accept", { document_id: documentId })).toMatchObject({ ok: true });
    // Epoch zero from the SAME bytes on both sides — the reason starting_content is an update and
    // not a string.
    expect(b.text(documentId)).toBe("# Plan\n");

    // 3. Alice writes. Publishing does not wait for Bob.
    expect(await a.call("cello_doc_write", { document_id: documentId, content: "# Plan\n- ship it\n" }))
      .toMatchObject({ ok: true, published: true });

    // 4. The worker delivers, and Bob's copy converges without Bob doing anything.
    const swept = await a.sweep();
    // `sent`, not `delivered`: the envelope LEFT and no ack has come back yet. `delivered` would be
    // the peer's daemon confirming admission, which is a separate frame — counting a send as an ack
    // is exactly the lie the transport's `admitted: null` exists to refuse.
    expect(swept).toMatchObject({ attempted: 1, sent: 1, failed: 0 });
    await vi.waitFor(() => expect(b.text(documentId)).toBe("# Plan\n- ship it\n"));

    // 5. And it goes the other way, which is the property that makes it a shared document rather
    //    than a feed.
    expect(await b.call("cello_doc_write", { document_id: documentId, content: "# Plan\n- ship it\n- and tell Alice\n" }))
      .toMatchObject({ ok: true, published: true });
    await b.sweep();
    await vi.waitFor(() => expect(a.text(documentId)).toBe("# Plan\n- ship it\n- and tell Alice\n"));

    // 6. Both READ the same thing through the surface. Convergence is the product claim, so it is
    //    asserted where the operator would see it, not only in the live cache.
    expect(await a.call("cello_doc_read", { document_id: documentId })).toMatchObject({
      content: "# Plan\n- ship it\n- and tell Alice\n",
    });
    expect(await b.call("cello_doc_read", { document_id: documentId })).toMatchObject({
      content: "# Plan\n- ship it\n- and tell Alice\n",
    });
  });

  it("a REFUSED proposal converges nothing, and Alice's writes go nowhere", async () => {
    const a = await makeParty("alice");
    const b = await makeParty("bob");
    connect(a, b);

    const documentId = (await a.call("cello_doc_propose", { peer_pubkey: b.owner })).documentId as string;
    await vi.waitFor(async () =>
      expect(await b.call("cello_doc_inbox")).toMatchObject({ proposals: [{ documentId }] }),
    );
    await b.call("cello_doc_refuse", { document_id: documentId, reason: "not this one" });

    await a.call("cello_doc_write", { document_id: documentId, content: "content Bob never agreed to" });
    await a.sweep();

    // Refusing is not a no-op that leaves a half-open door. Bob has no document, so the update is
    // refused as unknown rather than materializing one — which is the whole point of consent.
    await vi.waitFor(() => expect(b.layer.store.getDocument(b.owner, documentId)).toBeNull());
    // Asserted where the OPERATOR sees it. The live cache would hand back an empty document for an
    // id it has never heard of — harmless only because the surface refuses before reaching it, which
    // is precisely why the surface is what gets asserted.
    expect(await b.call("cello_doc_read", { document_id: documentId })).toMatchObject({
      ok: false,
      reason: "document_unknown",
    });
  });

  it("an OFFLINE peer does not lose the change — it delivers when they return", async () => {
    const a = await makeParty("alice");
    const b = await makeParty("bob");
    connect(a, b);

    const documentId = (await a.call("cello_doc_propose", { peer_pubkey: b.owner })).documentId as string;
    await vi.waitFor(async () =>
      expect(await b.call("cello_doc_inbox")).toMatchObject({ proposals: [{ documentId }] }),
    );
    await b.call("cello_doc_accept", { document_id: documentId });

    b.wire.online = false;
    a.wire.online = false;
    expect(await a.call("cello_doc_write", { document_id: documentId, content: "written while away" }))
      .toMatchObject({ ok: true, published: true });
    // The sweep tries and gets nowhere. The change is NOT lost — pending is derived from the log,
    // which is what makes it survivable.
    await a.sweep();
    expect(b.text(documentId)).toBe("");
    // Still pending, and deliberately checked PAST the backoff window: a failed attempt schedules
    // the next one, so asking at the same instant would report nothing pending for a reason that has
    // nothing to do with whether the change survived.
    expect(a.layer.store.pendingDeliveries(a.owner, NOW + 3_600_000, a.owner)).toHaveLength(1);

    a.wire.online = true;
    b.wire.online = true;
    await a.worker.tick(
      a.owner,
      (documentId2) => a.layer.store.getDocument(a.owner, documentId2)?.peerAgentId ?? null,
      NOW + 3_600_000,
      { senderAgentId: a.owner },
    );
    await vi.waitFor(() => expect(b.text(documentId)).toBe("written while away"));
  });

  it("a THIRD party's document is not reachable from this pair's surface", async () => {
    const a = await makeParty("alice");
    const b = await makeParty("bob");
    const c = await makeParty("carol");
    connect(a, b);

    const documentId = (await a.call("cello_doc_propose", { peer_pubkey: b.owner })).documentId as string;
    // Carol never saw the proposal, so she holds nothing under that id — and her surface says so
    // rather than materializing an empty document she could then write over.
    expect(await c.call("cello_doc_read", { document_id: documentId })).toMatchObject({
      ok: false,
      reason: "document_unknown",
    });
  });
});

describe("concurrent writes MERGE — they do not concatenate the two documents", () => {
  /**
   * MEASURED, not assumed. `delete(0,len); insert(0,content)` can only delete the items this side
   * has seen, so a peer's concurrently-inserted items survive the delete and splice into the new
   * text. Both sides full-replacing "original" converged on "AAABBB" — two whole documents
   * concatenated, signed and published by both parties.
   *
   * That is the same class of permanent, silently-converged corruption the whole-text contract was
   * chosen to PREVENT. The fix is line hunks: touch only what changed.
   */
  it("a peer's edit to an untouched line SURVIVES our write of a different line", async () => {
    const a = await makeParty("alice");
    const b = await makeParty("bob");
    connect(a, b);

    const documentId = (await a.call("cello_doc_propose", {
      peer_pubkey: b.owner,
      starting_content: "line one\nline two\nline three\n",
    })).documentId as string;
    await vi.waitFor(async () =>
      expect(await b.call("cello_doc_inbox")).toMatchObject({ proposals: [{ documentId }] }),
    );
    await b.call("cello_doc_accept", { document_id: documentId });

    // Both edit the SAME document at the SAME time, each sending back the complete text they saw —
    // exactly what the API's contract asks for, and exactly what a whole-text replace destroys.
    await a.call("cello_doc_write", { document_id: documentId, content: "line one EDITED BY A\nline two\nline three\n" });
    await b.call("cello_doc_write", { document_id: documentId, content: "line one\nline two\nline three EDITED BY B\n" });

    await a.sweep();
    await b.sweep();

    await vi.waitFor(() => {
      const text = a.text(documentId);
      // BOTH edits present, each on its own line, and the untouched middle line intact and single.
      expect(text).toContain("line one EDITED BY A");
      expect(text).toContain("line three EDITED BY B");
      expect(text.match(/line two/g)).toHaveLength(1);
    });
    // And both sides agree, which is the property that makes any of it worth having.
    expect(b.text(documentId)).toBe(a.text(documentId));
  });

  it("an untouched document is not rewritten by a write that changes one line", async () => {
    const a = await makeParty("alice");
    const documentId = (await a.call("cello_doc_propose", {
      peer_pubkey: "cc".repeat(32),
      starting_content: "keep\nchange me\nkeep too\n",
    })).documentId as string;

    await a.call("cello_doc_write", { document_id: documentId, content: "keep\nCHANGED\nkeep too\n" });
    expect(a.text(documentId)).toBe("keep\nCHANGED\nkeep too\n");
    // The published update carries the hunk, not the whole document. A whole-document update on
    // every keystroke-batch is what makes a peer's concurrent edit collide with an unchanged line.
    const row = a.layer.store.getEnvelopeLog(a.owner, documentId).at(-1)!;
    expect(row.payload!.length).toBeLessThan(200);
  });
});

describe("the proposer is TOLD the decision — not left to infer it", () => {
  it("an ACCEPT comes back as the peer's own signed answer", async () => {
    const a = await makeParty("alice");
    const b = await makeParty("bob");
    connect(a, b);

    const documentId = (await a.call("cello_doc_propose", { peer_pubkey: b.owner })).documentId as string;
    await vi.waitFor(async () =>
      expect(await b.call("cello_doc_inbox")).toMatchObject({ proposals: [{ documentId }] }),
    );

    // Before the answer: unanswered, and the surface says so rather than guessing.
    const before = ((await a.call("cello_doc_list")).documents as Array<Record<string, unknown>>)[0]!;
    expect(before.peerAccepted).toBeNull();

    expect(await b.call("cello_doc_accept", { document_id: documentId })).toMatchObject({
      ok: true,
      proposerNotified: true,
    });

    await vi.waitFor(async () => {
      const after = ((await a.call("cello_doc_list")).documents as Array<Record<string, unknown>>)[0]!;
      // A FACT now, from Bob's signature — not "he has published into it", which cannot tell
      // refused from unreceived from accepted-but-untouched.
      expect(after.peerAccepted).toBe(true);
      expect(after.peerHasPublished).toBe(false);
    });
  });

  it("a REFUSAL comes back WITH its reason", async () => {
    const a = await makeParty("alice");
    const b = await makeParty("bob");
    connect(a, b);

    const documentId = (await a.call("cello_doc_propose", { peer_pubkey: b.owner })).documentId as string;
    await vi.waitFor(async () =>
      expect(await b.call("cello_doc_inbox")).toMatchObject({ proposals: [{ documentId }] }),
    );
    await b.call("cello_doc_refuse", { document_id: documentId, reason: "wrong document type" });

    await vi.waitFor(async () => {
      const after = ((await a.call("cello_doc_list")).documents as Array<Record<string, unknown>>)[0]!;
      // Distinguishable from "not yet answered", which is the whole point: those two want opposite
      // actions from the operator, and a refusal with no reason leaves them unable to propose
      // anything better.
      expect(after.peerAccepted).toBe(false);
    });
    expect(a.layer.handshake.peerDecision(a.owner, documentId)).toBe(false);
  });

  it("a decision made while the proposer is OFFLINE still stands locally", async () => {
    const a = await makeParty("alice");
    const b = await makeParty("bob");
    connect(a, b);

    const documentId = (await a.call("cello_doc_propose", { peer_pubkey: b.owner })).documentId as string;
    await vi.waitFor(async () =>
      expect(await b.call("cello_doc_inbox")).toMatchObject({ proposals: [{ documentId }] }),
    );

    b.wire.online = false;
    // Consent is LOCAL and final the moment the operator makes it. Refusing to accept because the
    // counterparty is momentarily unreachable would hand any network blip a veto over the
    // operator's own choice.
    expect(await b.call("cello_doc_accept", { document_id: documentId })).toMatchObject({
      ok: true,
      proposerNotified: false,
    });
    expect(b.layer.store.getDocument(b.owner, documentId)).not.toBeNull();
    // Alice is still waiting, and the surface reports waiting — never a refusal.
    const alice = ((await a.call("cello_doc_list")).documents as Array<Record<string, unknown>>)[0]!;
    expect(alice.peerAccepted).toBeNull();
  });

  it("a CONTRADICTING second answer is refused, not applied", async () => {
    const a = await makeParty("alice");
    const b = await makeParty("bob");
    connect(a, b);

    const documentId = (await a.call("cello_doc_propose", { peer_pubkey: b.owner })).documentId as string;
    await vi.waitFor(async () =>
      expect(await b.call("cello_doc_inbox")).toMatchObject({ proposals: [{ documentId }] }),
    );
    await b.call("cello_doc_accept", { document_id: documentId });
    await vi.waitFor(() => expect(a.layer.handshake.peerDecision(a.owner, documentId)).toBe(true));

    // Settle once. A peer that accepted must not be able to later claim it refused, or the proposer
    // tears down a document the peer is still editing.
    const flip = a.layer.handshake.recordPeerDecision(a.owner, documentId, {
      accepted: false,
      reason: "changed my mind",
      decidedAtMs: NOW + 1,
    });
    expect(flip).toMatchObject({ ok: false, reason: "document_proposal_ack_contradicts" });
    expect(a.layer.handshake.peerDecision(a.owner, documentId)).toBe(true);
  });
});

describe("cello_doc_diff — reviewing what arrived before building on it", () => {
  it("shows the peer's change against what THIS agent last read", async () => {
    const a = await makeParty("alice");
    const b = await makeParty("bob");
    connect(a, b);

    const documentId = (await a.call("cello_doc_propose", {
      peer_pubkey: b.owner,
      starting_content: "one\ntwo\nthree\n",
    })).documentId as string;
    await vi.waitFor(async () =>
      expect(await b.call("cello_doc_inbox")).toMatchObject({ proposals: [{ documentId }] }),
    );
    await b.call("cello_doc_accept", { document_id: documentId });

    // Alice looks. THIS is the bookmark — not the accept, not an arriving update.
    await a.call("cello_doc_read", { document_id: documentId });

    await b.call("cello_doc_write", { document_id: documentId, content: "one\ntwo CHANGED BY BOB\nthree\n" });
    await b.sweep();
    await vi.waitFor(() => expect(a.text(documentId)).toContain("CHANGED BY BOB"));

    const diff = await a.call("cello_doc_diff", { document_id: documentId });
    expect(diff).toMatchObject({ ok: true, unchanged: false });
    expect(String(diff.diff)).toContain("CHANGED BY BOB");
    expect(diff.stats).toMatchObject({ linesAdded: 1, linesRemoved: 1 });
  });

  it("REFUSES rather than diffing against nothing when the document was never read", async () => {
    const a = await makeParty("alice");
    const documentId = (await a.call("cello_doc_propose", {
      peer_pubkey: "cc".repeat(32),
      starting_content: "a long document\nwith several lines\n",
    })).documentId as string;

    const diff = await a.call("cello_doc_diff", { document_id: documentId });
    // Diffing against "" would render a FIRST look at a long document as an enormous change, which
    // an agent then treats as "what just arrived" and acts on. Never-read is a different fact from
    // nothing-changed and is said as one.
    expect(diff).toMatchObject({ ok: false, reason: "document_never_read" });
  });

  it("reports UNCHANGED when nothing moved since the read", async () => {
    const a = await makeParty("alice");
    const documentId = (await a.call("cello_doc_propose", {
      peer_pubkey: "cc".repeat(32),
      starting_content: "steady\n",
    })).documentId as string;
    await a.call("cello_doc_read", { document_id: documentId });

    expect(await a.call("cello_doc_diff", { document_id: documentId })).toMatchObject({
      ok: true,
      unchanged: true,
    });
  });

  it("a second READ moves the bookmark, so the same change is not shown twice", async () => {
    const a = await makeParty("alice");
    const b = await makeParty("bob");
    connect(a, b);
    const documentId = (await a.call("cello_doc_propose", {
      peer_pubkey: b.owner,
      starting_content: "base\n",
    })).documentId as string;
    await vi.waitFor(async () =>
      expect(await b.call("cello_doc_inbox")).toMatchObject({ proposals: [{ documentId }] }),
    );
    await b.call("cello_doc_accept", { document_id: documentId });
    await a.call("cello_doc_read", { document_id: documentId });

    await b.call("cello_doc_write", { document_id: documentId, content: "base\nbob was here\n" });
    await b.sweep();
    await vi.waitFor(() => expect(a.text(documentId)).toContain("bob was here"));

    expect(await a.call("cello_doc_diff", { document_id: documentId })).toMatchObject({ unchanged: false });
    await a.call("cello_doc_read", { document_id: documentId });
    // An agent that re-reviews the same change on every turn will keep re-reacting to it.
    expect(await a.call("cello_doc_diff", { document_id: documentId })).toMatchObject({ unchanged: true });
  });
});
