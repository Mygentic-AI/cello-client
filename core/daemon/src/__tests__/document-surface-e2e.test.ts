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
  // DOD-DOC-WATCH-1 — every nudge this party received. The seam the daemon fills with the doorbell
  // dispatcher; collected here so the test asserts on what the operator's agent would actually be
  // woken by rather than on the store.
  const nudges: Array<{ documentId: string; paths: string[] }> = [];

  // Declared before the layer because the notifier needs the store, and the store is inside the
  // layer. Assigned immediately after; the notifier is only ever called from lifecycle, long after
  // construction.

  const layer = createDocumentLayer({
    db,
    logger,
    publicKeyFor: agentPublicKeyFromId,
    nudge: (_owner, documentId, paths) => {
      nudges.push({ documentId, paths: [...paths] });
    },
    // The NAME→KEY map, exactly as the daemon does it. Both halves resolve through this one
    // function; when they did not, every row landed where the other half never looked.
    ownerKeyFor: (n) => (n === agentName ? owner : null),
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
    governanceFrontierFor: (o, d) => layer.governanceFrontierFor(o, d),
    holdersFor: (o, d) => layer.holdersFor(o, d),
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
    /** DOD-DOC-WATCH-1 — the doorbells this party was rung with, in order. */
    nudges,
    // Exposed so a test can author an update the way a HOSTILE PEER would — below the operator
    // surface, whose authoring screen a patched client simply would not run. Reaching the
    // receiver's gate is the whole point of the screening case, and going through cello_doc_write
    // now stops the frame on the sender's own machine before it can get there.
    publish,
    call: (verb: string, params: Record<string, unknown> = {}) =>
      handlers.get(verb)!(params, "conn") as Promise<Record<string, unknown>>,
    /** The production entry point: whatever arrives on the session content path. */
    receive: (bytes: Uint8Array) => layer.onDocumentFrame(agentName, "session-1", bytes, "pk", "wire"),
    /** Run one delivery pass, the way the daemon's sweep does. */
    sweep: () =>
      worker.tick(
        owner,
        (documentId) => {
          const doc = layer.store.getDocument(owner, documentId);
          return doc ? [doc.peerAgentId] : null;
        },
        NOW,
        { senderAgentId: owner },
      ),
    text: (documentId: string) => layer.live.get(owner, documentId).getText("content").toString(),
    /** The map root as JSON — a `text` read is empty for a JSON document, whose content is the map. */
    json: (documentId: string) => layer.live.get(owner, documentId).getMap("data").toJSON() as Record<string, unknown>,
  };
}

/** Re-encode a stored envelope row the way the daemon's composition root does. */
function encodeFromRow(row: unknown): Uint8Array {
  const r = row as {
    documentId: string; epochId: string; docPrevHash: string | null; senderAgentId: string;
    senderClientId: number | null; stateVector: Uint8Array; payload: Uint8Array | null;
    governanceParents: string[]; signature: Uint8Array;
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
    // The ROW's real parents — an empty list here would re-encode bytes the signature never
    // covered, and the peer would refuse an envelope we believe we sent correctly.
    governance_parents: r.governanceParents ?? [],
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

  it("DOD-DOC-TYPES-1: a JSON document converges, and two agents editing DIFFERENT KEYS both survive", async () => {
    // The use case JSON exists for: two agents working a shared structured goal, each owning
    // different fields. On a text root their concurrent edits are overlapping rewrites of the same
    // lines and the CRDT interleaves them into broken JSON. On the map root they are edits to
    // different keys, and both hold.
    const a = await makeParty("alice");
    const b = await makeParty("bob");
    connect(a, b);

    const proposed = await a.call("cello_doc_propose", {
      peer_pubkey: b.owner,
      document_type: "json",
      starting_content: JSON.stringify({ status: "open" }),
    });
    expect(proposed, "json is still refused at the door").toMatchObject({ ok: true, proposalSent: true });
    const documentId = proposed.documentId as string;

    await vi.waitFor(async () =>
      expect(await b.call("cello_doc_inbox")).toMatchObject({ proposals: [{ documentId }] }),
    );
    expect(await b.call("cello_doc_accept", { document_id: documentId })).toMatchObject({ ok: true });

    // Both READ it as canonical JSON — the same bytes on both sides, which is what makes a paste of
    // it something the other party can confirm.
    const readA = await a.call("cello_doc_read", { document_id: documentId });
    const readB = await b.call("cello_doc_read", { document_id: documentId });
    expect(readA.content).toBe(readB.content);
    expect(JSON.parse(readA.content as string)).toEqual({ status: "open" });

    // Alice sets `owner`. Bob CONCURRENTLY sets `due` — neither has seen the other's write.
    expect(
      await a.call("cello_doc_write", {
        document_id: documentId,
        content: JSON.stringify({ status: "open", owner: "alice" }, null, 2) + "\n",
      }),
    ).toMatchObject({ ok: true, published: true });
    expect(
      await b.call("cello_doc_write", {
        document_id: documentId,
        content: JSON.stringify({ status: "open", due: "friday" }, null, 2) + "\n",
      }),
    ).toMatchObject({ ok: true, published: true });

    await a.sweep();
    await b.sweep();

    // BOTH keys survive on BOTH sides. A line merge would have lost one or produced invalid JSON.
    const expected = { status: "open", owner: "alice", due: "friday" };
    await vi.waitFor(async () => {
      const fromA = await a.call("cello_doc_read", { document_id: documentId });
      const fromB = await b.call("cello_doc_read", { document_id: documentId });
      expect(JSON.parse(fromA.content as string)).toEqual(expected);
      expect(JSON.parse(fromB.content as string)).toEqual(expected);
      // And BYTE-identical, not merely equal as objects — the two arrived at these keys in opposite
      // orders, so this is the determinism the file diff and paste-and-agree both depend on.
      expect(fromA.content).toBe(fromB.content);
    });
  });

  it("DOD-DOC-TYPES-1: a write that is not valid JSON is refused, and changes nothing", async () => {
    const a = await makeParty("alice");
    const b = await makeParty("bob");
    connect(a, b);
    const documentId = (
      await a.call("cello_doc_propose", {
        peer_pubkey: b.owner,
        document_type: "json",
        starting_content: JSON.stringify({ a: 1 }),
      })
    ).documentId as string;
    await vi.waitFor(async () =>
      expect(await b.call("cello_doc_inbox")).toMatchObject({ proposals: [{ documentId }] }),
    );
    await b.call("cello_doc_accept", { document_id: documentId });

    const bad = await a.call("cello_doc_write", { document_id: documentId, content: '{ "a": 1' });
    expect(bad.ok, "a truncated write was accepted into a structured document").toBe(false);
    expect(bad.reason).toBe("document_content_unparseable");
    // Unchanged — a half-parsed write must not partially apply.
    expect(JSON.parse((await a.call("cello_doc_read", { document_id: documentId })).content as string))
      .toEqual({ a: 1 });
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
      (documentId2) => {
        const doc = a.layer.store.getDocument(a.owner, documentId2);
        return doc ? [doc.peerAgentId] : null;
      },
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
  it("DOD-DOC-WATCH-1: a watched field wakes you; an unwatched one does not", async () => {
    // The wiring, not the matcher. A watch feature whose store and matcher are both correct and whose
    // inbound hook is never called is exactly the shape this milestone keeps finding.
    const a = await makeParty("alice");
    const b = await makeParty("bob");
    connect(a, b);

    const documentId = (await a.call("cello_doc_propose", {
      peer_pubkey: b.owner,
      document_type: "json",
      starting_content: JSON.stringify({ blocking_flags: { funds: false }, note: "x" }),
    })).documentId as string;
    await vi.waitFor(async () =>
      expect(await b.call("cello_doc_inbox")).toMatchObject({ proposals: [{ documentId }] }),
    );
    await b.call("cello_doc_accept", { document_id: documentId });

    // Alice watches the flags, and READS — the read is what establishes the baseline a nudge is
    // measured against.
    expect(await a.call("cello_doc_watch", { document_id: documentId, paths: ["blocking_flags"] }))
      .toMatchObject({ ok: true, paths: ["blocking_flags"] });
    await a.call("cello_doc_read", { document_id: documentId });

    // Bob changes something she is NOT watching.
    await b.call("cello_doc_write", {
      document_id: documentId,
      content: JSON.stringify({ blocking_flags: { funds: false }, note: "y" }, null, 2) + "\n",
    });
    await b.sweep();
    await vi.waitFor(() => expect(a.json(documentId).note).toBe("y"));
    expect(a.nudges, "an unwatched field woke her — the nudge is not selective").toEqual([]);

    // Now he changes the flag she IS watching.
    await b.call("cello_doc_write", {
      document_id: documentId,
      content: JSON.stringify({ blocking_flags: { funds: true }, note: "y" }, null, 2) + "\n",
    });
    await b.sweep();
    await vi.waitFor(() => expect(a.nudges.length).toBeGreaterThan(0));
    // THE WATCH PATTERN, not the changed path. A changed path can carry a key the peer named, and a
    // doorbell body is unscreened — see `matchingWatches`.
    expect(a.nudges[0]).toMatchObject({ documentId, paths: ["blocking_flags"] });

    // RINGS ONCE. A peer editing for ten minutes must produce one nudge, not forty.
    await b.call("cello_doc_write", {
      document_id: documentId,
      content: JSON.stringify({ blocking_flags: { funds: true, other: true }, note: "y" }, null, 2) + "\n",
    });
    await b.sweep();
    await vi.waitFor(() => expect((a.json(documentId).blocking_flags as Record<string, unknown>).other).toBe(true));
    expect(a.nudges.length, "it rang again without her having read").toBe(1);

    // Reading re-arms it — otherwise a document nudges once in its life and then goes quiet, which
    // is worse than never nudging because the operator would trust the silence.
    await a.call("cello_doc_read", { document_id: documentId });
    await b.call("cello_doc_write", {
      document_id: documentId,
      content: JSON.stringify({ blocking_flags: { funds: false, other: true }, note: "y" }, null, 2) + "\n",
    });
    await b.sweep();
    await vi.waitFor(() => expect(a.nudges.length).toBe(2));
  });

  it("DOD-DOC-STALE-WRITE-1: a write does NOT delete a peer edit that arrived after your read", async () => {
    // The 226ms incident, end to end. Alice reads, Bob's paragraph is admitted, Alice writes the
    // text she read — which no longer contains it. Before the guard this published a deletion,
    // returned ok/published, and both copies converged on it with nobody told.
    const a = await makeParty("alice");
    const b = await makeParty("bob");
    connect(a, b);

    const documentId = (await a.call("cello_doc_propose", {
      peer_pubkey: b.owner,
      starting_content: "line one\nline two\n",
    })).documentId as string;
    await vi.waitFor(async () =>
      expect(await b.call("cello_doc_inbox")).toMatchObject({ proposals: [{ documentId }] }),
    );
    await b.call("cello_doc_accept", { document_id: documentId });

    // Alice LOOKS. This is the baseline the guard measures against.
    const seen = (await a.call("cello_doc_read", { document_id: documentId })).content as string;
    expect(seen).toBe("line one\nline two\n");

    // Bob writes and it reaches Alice — she has not looked since.
    await b.call("cello_doc_write", { document_id: documentId, content: "line one\nline two\nBOB WAS HERE\n" });
    await b.sweep();
    await vi.waitFor(() => expect(a.text(documentId)).toContain("BOB WAS HERE"));

    // Alice writes the text she read, plus her own line. Bob's line is absent from it.
    const refused = await a.call("cello_doc_write", {
      document_id: documentId,
      content: "line one\nline two\nALICE WAS HERE\n",
    });

    expect(refused.ok, "the write was accepted and Bob's line is gone").toBe(false);
    expect(refused.reason).toBe("document_write_would_delete_unseen");
    expect(refused.unseenRemovals).toEqual(["BOB WAS HERE"]);
    // The diff travels WITH the refusal — this is the moment Alice can still act.
    expect(refused.currentContent).toContain("BOB WAS HERE");
    // And NOTHING was changed. A refusal that half-applied would be worse than the bug.
    expect(a.text(documentId)).toBe("line one\nline two\nBOB WAS HERE\n");
    expect(a.text(documentId)).not.toContain("ALICE WAS HERE");
  });

  it("DOD-DOC-STALE-WRITE-1: after READING it, the same removal is allowed as deliberate", async () => {
    // The second refusal. Alice reads Bob's line and still leaves it out — that is an editorial act,
    // and the system must let her perform it rather than trapping her in a refusal loop.
    const a = await makeParty("alice");
    const b = await makeParty("bob");
    connect(a, b);

    const documentId = (await a.call("cello_doc_propose", {
      peer_pubkey: b.owner,
      starting_content: "line one\n",
    })).documentId as string;
    await vi.waitFor(async () =>
      expect(await b.call("cello_doc_inbox")).toMatchObject({ proposals: [{ documentId }] }),
    );
    await b.call("cello_doc_accept", { document_id: documentId });

    await b.call("cello_doc_write", { document_id: documentId, content: "line one\nBOB WAS HERE\n" });
    await b.sweep();
    await vi.waitFor(() => expect(a.text(documentId)).toContain("BOB WAS HERE"));

    // She looks at it — which is exactly what the refusal told her to do.
    await a.call("cello_doc_read", { document_id: documentId });

    const accepted = await a.call("cello_doc_write", { document_id: documentId, content: "line one\n" });
    expect(accepted, "a removal the author has READ must not be refused").toMatchObject({
      ok: true,
      changed: true,
    });
    expect(a.text(documentId)).toBe("line one\n");
  });

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
      // actions from the operator.
      expect(after.peerAccepted).toBe(false);
      // AND THE REASON. This assertion did not exist, and could not have: the reason was verified,
      // stored, and read by nothing. That defeats why it is mandatory on the wire — a refusal whose
      // reason the proposer cannot see leaves them unable to propose anything better. Without this
      // line, replacing every reason with the constant "declined" keeps the suite green forever.
      expect(after.peerRefusalReason).toBe("wrong document type");
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
    // Bob's own key — the acker check must be satisfied so the SETTLE-ONCE rule is what refuses,
    // not the authorization one. Passing anyone else here would test the wrong guard.
    const flip = a.layer.handshake.recordPeerDecision(a.owner, documentId, b.owner, {
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

describe("ending a document — the peer is TOLD, over the wire", () => {
  it("a KILL reaches the peer and stops their document too", async () => {
    const a = await makeParty("alice");
    const b = await makeParty("bob");
    connect(a, b);

    const documentId = (await a.call("cello_doc_propose", { peer_pubkey: b.owner })).documentId as string;
    await vi.waitFor(async () =>
      expect(await b.call("cello_doc_inbox")).toMatchObject({ proposals: [{ documentId }] }),
    );
    await b.call("cello_doc_accept", { document_id: documentId });

    // SYNC-P4: a kill is a signed ENTRY now — the result names the entry, reports per-holder
    // delivery of it, and the ended verdict is DERIVED (any admin's kill suffices, immediately).
    const killedRes = await a.call("cello_doc_kill", { document_id: documentId });
    expect(killedRes).toMatchObject({ ok: true, ended: "killed" });
    expect((killedRes.killDelivered as Record<string, boolean>)[b.owner]).toBe(true);

    // Bob's copy is terminal too — the kill ENTRY travels the ordinary carrier, and Bob's daemon
    // derives the ending on arrival. Before endings were entries, a lost one-shot frame left Bob
    // publishing into a document that would never answer, with nothing on his screen explaining why.
    await vi.waitFor(() => expect(b.layer.store.getDocument(b.owner, documentId)?.status).toBe("killed"));
    const write = await b.call("cello_doc_write", { document_id: documentId, content: "still typing" });
    // REFUSED OUTRIGHT, and this assertion changed deliberately (DOD-DOC-TOOLS-1 review, finding 6).
    // It used to accept `{published: false}` with `ok: true` — the old behaviour applied the edit to
    // Bob's local copy, failed to publish it, and remembered it as a stuck edit that no flush could
    // ever clear, because the document is terminal. Bob's next read then showed text that exists in
    // no envelope log and no peer's copy, and that vanishes on the next daemon restart when the live
    // document is rebuilt from the log. Reporting `ok: true` for that is the fabricated-success
    // shape: nothing was saved anywhere it can survive.
    expect(write).toMatchObject({ ok: false, reason: "document_killed" });
    // And the local copy is untouched, which is the half that made the old answer harmful.
    expect(String((await b.call("cello_doc_read", { document_id: documentId }))["content"] ?? "")).not.toContain(
      "still typing",
    );
  });

  it("a kill SUCCEEDS locally when the peer cannot be reached, and says the peer was not told", async () => {
    const a = await makeParty("alice");
    const b = await makeParty("bob");
    connect(a, b);
    const documentId = (await a.call("cello_doc_propose", { peer_pubkey: b.owner })).documentId as string;
    await vi.waitFor(async () =>
      expect(await b.call("cello_doc_inbox")).toMatchObject({ proposals: [{ documentId }] }),
    );
    await b.call("cello_doc_accept", { document_id: documentId });

    a.wire.online = false;
    const killed = await a.call("cello_doc_kill", { document_id: documentId });
    // A decision to stop that depends on the other party being online is not a decision to stop.
    // But the operator is TOLD they were not told, because otherwise they will not understand why
    // the peer keeps writing.
    expect(killed).toMatchObject({ ok: true, ended: "killed" });
    // The entry did NOT reach the peer — the per-holder delivery map says so, and the difference
    // is owed: the next reconcile exchange with bob carries the kill entry.
    expect((killed.killDelivered as Record<string, boolean>)[b.owner]).not.toBe(true);
    expect(a.layer.store.getDocument(a.owner, documentId)?.status).toBe("killed");
  });

  it("a CLOSE is bilateral — one side saying it does not end the document", async () => {
    const a = await makeParty("alice");
    const b = await makeParty("bob");
    connect(a, b);
    const documentId = (await a.call("cello_doc_propose", { peer_pubkey: b.owner })).documentId as string;
    await vi.waitFor(async () =>
      expect(await b.call("cello_doc_inbox")).toMatchObject({ proposals: [{ documentId }] }),
    );
    await b.call("cello_doc_accept", { document_id: documentId });

    await a.call("cello_doc_close", { document_id: documentId });
    // Still active on BOTH sides. Reporting "closed" here would tell an operator the collaboration
    // is over while the counterparty is still editing.
    expect(a.layer.store.getDocument(a.owner, documentId)?.status).toBe("active");
    await vi.waitFor(() => expect(b.layer.store.getDocument(b.owner, documentId)).not.toBeNull());

    await b.call("cello_doc_close", { document_id: documentId });
    await vi.waitFor(() => expect(a.layer.store.getDocument(a.owner, documentId)?.status).toBe("closed"));
  });

  it("a THIRD party cannot end this pair's document", async () => {
    const a = await makeParty("alice");
    const b = await makeParty("bob");
    const c = await makeParty("carol");
    connect(a, b);
    const documentId = (await a.call("cello_doc_propose", { peer_pubkey: b.owner })).documentId as string;
    await vi.waitFor(async () =>
      expect(await b.call("cello_doc_inbox")).toMatchObject({ proposals: [{ documentId }] }),
    );
    await b.call("cello_doc_accept", { document_id: documentId });

    // Carol signs a real, well-formed kill for a document she is not part of and delivers it
    // straight to Bob's inbound path. Without the sender check, any string plus a valid signature
    // ends someone else's document.
    c.wire.deliverToPeer = (bytes) => b.receive(bytes);
    c.layer.store.createDocument({
      documentId, ownerAgentId: c.owner, peerAgentId: b.owner, documentType: "markdown",
      properties: {}, status: "active", createdAtMs: 1,
    });
    await c.call("cello_doc_kill", { document_id: documentId });

    // Bob's document is untouched: Carol is not its peer.
    expect(b.layer.store.getDocument(b.owner, documentId)?.status).toBe("active");
  });
});

describe("an ack is VERIFIED and also AUTHORIZED", () => {
  it("a THIRD party cannot answer a proposal that was never addressed to them", async () => {
    const a = await makeParty("alice");
    const b = await makeParty("bob");
    const c = await makeParty("carol");
    connect(a, b);

    const documentId = (await a.call("cello_doc_propose", { peer_pubkey: b.owner })).documentId as string;
    await vi.waitFor(async () =>
      expect(await b.call("cello_doc_inbox")).toMatchObject({ proposals: [{ documentId }] }),
    );

    // Carol signs a REAL, well-formed ack for a document she is not part of and delivers it to
    // Alice's inbound path. The signature verifies — against Carol, who is exactly who she says she
    // is — and that says nothing about whether she was entitled to answer.
    //
    // Recorded, this is permanent: Alice's surface reports "they said no" for a peer who never saw
    // it, and settle-once is by VALUE, so Bob's genuine later answer contradicts and is discarded.
    c.wire.deliverToPeer = (bytes) => a.receive(bytes);
    const poisoned = c.layer.handshake.recordPeerDecision(a.owner, documentId, c.owner, {
      accepted: false,
      reason: "no thanks",
      decidedAtMs: NOW,
    });
    void poisoned;
    const direct = a.layer.handshake.recordPeerDecision(a.owner, documentId, c.owner, {
      accepted: false,
      reason: "no thanks",
      decidedAtMs: NOW,
    });
    expect(direct).toMatchObject({ ok: false, reason: "document_proposal_ack_not_peer" });
    expect(a.layer.handshake.peerDecision(a.owner, documentId)).toBeNull();

    // And Bob's real answer still lands, which is the half that matters: the poisoning attempt must
    // not have consumed the one decision slot.
    await b.call("cello_doc_accept", { document_id: documentId });
    await vi.waitFor(() => expect(a.layer.handshake.peerDecision(a.owner, documentId)).toBe(true));
  });
});

describe("a KILL arriving after a settled CLOSE does not rewrite it", () => {
  it("ignores a late or redelivered kill on a closed document", async () => {
    const a = await makeParty("alice");
    const b = await makeParty("bob");
    connect(a, b);
    const documentId = (await a.call("cello_doc_propose", { peer_pubkey: b.owner })).documentId as string;
    await vi.waitFor(async () =>
      expect(await b.call("cello_doc_inbox")).toMatchObject({ proposals: [{ documentId }] }),
    );
    await b.call("cello_doc_accept", { document_id: documentId });

    await a.call("cello_doc_close", { document_id: documentId });
    await b.call("cello_doc_close", { document_id: documentId });
    await vi.waitFor(() => expect(a.layer.store.getDocument(a.owner, documentId)?.status).toBe("closed"));

    // A late kill must not rewrite a settled agreement as a unilateral end. In the entry model
    // that is enforced at AUTHORING time: the killer's own daemon derives the world already ended
    // and refuses to mint the entry at all — and had it somehow been minted, every receiver's
    // causal gate refuses an entry authored after an ending in its closure (R30). Both operators
    // keep "closed by agreement", which is the fact they chose.
    const late = await b.call("cello_doc_kill", { document_id: documentId });
    expect(late).toMatchObject({ ok: false });
    expect(a.layer.store.getDocument(a.owner, documentId)?.status).toBe("closed");
    expect(b.layer.store.getDocument(b.owner, documentId)?.status).toBe("closed");
  });
});

describe("cello_doc_diff reports OVERLAP as a computed answer", () => {
  it("flags a peer edit landing on a line WE also changed", async () => {
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

    await a.call("cello_doc_read", { document_id: documentId });
    // Alice edits line two; Bob edits line two.
    await a.call("cello_doc_write", { document_id: documentId, content: "one\ntwo ALICE\nthree\n" });
    await b.call("cello_doc_write", { document_id: documentId, content: "one\ntwo BOB\nthree\n" });
    await b.sweep();

    await vi.waitFor(async () => {
      const diff = (await a.call("cello_doc_diff", { document_id: documentId })) as {
        stats?: { overlap?: boolean | null };
      };
      // `null` here is the reassuring answer three instruction sheets told agents to trust while it
      // was hardcoded — and null is falsy, so every one of them read it as "no conflict".
      expect(diff.stats?.overlap).toBe(true);
    });
  });

  it("reports NOT COMPUTED, never false, when we have not written since the read", async () => {
    const a = await makeParty("alice");
    const b = await makeParty("bob");
    connect(a, b);
    const documentId = (await a.call("cello_doc_propose", {
      peer_pubkey: b.owner,
      starting_content: "one\ntwo\n",
    })).documentId as string;
    await vi.waitFor(async () =>
      expect(await b.call("cello_doc_inbox")).toMatchObject({ proposals: [{ documentId }] }),
    );
    await b.call("cello_doc_accept", { document_id: documentId });
    await a.call("cello_doc_read", { document_id: documentId });
    await b.call("cello_doc_write", { document_id: documentId, content: "one\ntwo BOB\n" });
    await b.sweep();

    await vi.waitFor(async () => {
      const diff = (await a.call("cello_doc_diff", { document_id: documentId })) as {
        unchanged?: boolean;
        stats?: { overlap?: boolean | null };
      };
      expect(diff.unchanged).toBe(false);
      // Alice made no edit, so there is nothing to overlap WITH — that is "not computed", and it
      // must stay distinguishable from "checked, and there is no conflict".
      expect(diff.stats?.overlap).toBeNull();
    });
  });
});

describe("DOD-DOC-SCREEN-1 — the content gate is REACHED, and it refuses rather than rewrites", () => {
  it("refuses a peer's update carrying a bidi override, and the operator's copy is untouched", async () => {
    const a = await makeParty("alice");
    const b = await makeParty("bob");
    connect(a, b);

    const documentId = (await a.call("cello_doc_propose", {
      peer_pubkey: b.owner,
      starting_content: "agreed text\n",
    })).documentId as string;
    await vi.waitFor(async () =>
      expect(await b.call("cello_doc_inbox")).toMatchObject({ proposals: [{ documentId }] }),
    );
    await b.call("cello_doc_accept", { document_id: documentId });

    // U+202E renders the text that follows it in reverse, so what an operator READS and what the
    // document SAYS differ. In a shared document that is a signature on content the signer did not
    // see — which is why it is refused rather than stripped.
    //
    // AUTHORED BELOW THE HANDLER, and that is the point of this test rather than an inconvenience.
    // `cello_doc_write` now runs the same screen at authoring time (§16.6), so writing this through
    // it would be refused on B's own machine and the RECEIVER'S gate — the thing under test — would
    // never be reached. A hostile peer has a patched client and does not consult our authoring
    // check either, so going around it is the faithful simulation, not a shortcut.
    //
    // This is exactly why the sender-side scan is friction reduction and never a boundary: it can
    // be removed by whoever is sending, so the receiver's gate has to stand alone. Proving that is
    // what this case is for.
    b.layer.live.get(b.owner, documentId).getText("content").insert(11, "\nsafe\u202Eelbisiv");
    await b.publish.publish(b.owner, documentId, b.layer.live.get(b.owner, documentId), Date.now());
    await b.sweep();

    // REFUSED, and A's copy is byte-identical to what it held before. Not "sanitized" — the whole
    // finding behind this line is that rewriting one party's replica is permanent divergence that
    // both sides converge on and neither can see.
    await vi.waitFor(() =>
      expect(a.layer.store.listQuarantined(a.owner, documentId).length, "A never quarantined it").toBeGreaterThan(0),
    );
    expect(a.text(documentId)).toBe("agreed text\n");
    expect(a.text(documentId)).not.toContain("\u202E");
  });

  it("ADMITS legitimate non-Latin text the message sanitizer would have rewritten", async () => {
    const a = await makeParty("alice");
    const b = await makeParty("bob");
    connect(a, b);

    const documentId = (await a.call("cello_doc_propose", {
      peer_pubkey: b.owner,
      starting_content: "notes\n",
    })).documentId as string;
    await vi.waitFor(async () =>
      expect(await b.call("cello_doc_inbox")).toMatchObject({ proposals: [{ documentId }] }),
    );
    await b.call("cello_doc_accept", { document_id: documentId });

    // Every one of these was silently altered in the audit. Admitting them is as much the claim as
    // refusing the override above: a rule that refused these would make CELLO unusable for exactly
    // the operators most likely to need it.
    const real = "notes\nकर्‍म 👨‍👩‍👧 Ｈｅｌｌｏ ﬁle is ½ it…\n";
    await b.call("cello_doc_write", { document_id: documentId, content: real });
    await b.sweep();

    await vi.waitFor(() => expect(a.text(documentId)).toBe(real));
    // BYTE-IDENTICAL, which is the property the whole line exists for.
    expect(a.text(documentId)).toBe(b.text(documentId));
  });
});

describe("a gate refusal leaves the sender's chain FOLLOWABLE (DOD-DOC-REJECT-1)", () => {
  it("the refused envelope becomes the head and is known, so a supersession can link to it", async () => {
    const a = await makeParty("alice");
    const b = await makeParty("bob");
    connect(a, b);

    const documentId = (await a.call("cello_doc_propose", {
      peer_pubkey: b.owner,
      starting_content: "one\ntwo\nthree\n",
      append_only: true,
    })).documentId as string;
    await vi.waitFor(async () =>
      expect(await b.call("cello_doc_inbox")).toMatchObject({ proposals: [{ documentId }] }),
    );
    await b.call("cello_doc_accept", { document_id: documentId });

    // B deletes — A's gate must refuse it.
    await b.call("cello_doc_write", { document_id: documentId, content: "one\n" });
    await b.sweep();

    await vi.waitFor(() =>
      expect(a.layer.store.listQuarantined(a.owner, documentId).length).toBeGreaterThan(0),
    );

    // THE THREE VALUES THE SPINE RUN COULD ONLY GUESS AT. Read straight from A's store instead of
    // inferred from a log tail three minutes at a time.
    // THE THREE VALUES THE PROTOCOL DEPENDS ON AFTER A REFUSAL, read straight from the store rather
    // than inferred from a log tail. A refused envelope is deliberately never written to
    // `document_envelopes`, so without these the sender's next envelope — their supersession —
    // links to a hash that is nowhere, and the document dies after one refusal.
    const q = a.layer.store.listQuarantined(a.owner, documentId);
    expect(q).toHaveLength(1);
    // Scoped to the REFUSED envelope's own author, so one peer's quarantine can never make another
    // peer's broken chain resolve.
    expect(q[0]!.rejectedSenderAgentId).toBe(b.owner);

    const known = a.layer.store.knownEnvelopeHashesBySender(a.owner, documentId, b.owner);
    const head = a.layer.store.lastEnvelopeHashBySender(a.owner, documentId, b.owner);
    // KNOWN answers "have I seen this" (duplicate detection); HEAD is what a forward link is
    // checked against. Bridging only the first looks right and changes nothing — that was one of
    // the wrong turns on this path, and both are asserted here so neither can regress alone.
    expect(known.size).toBe(1);
    expect(head, "the head did not advance across the refused envelope").toBe(q[0]!.rejectedEnvelopeHash);
  });
});
