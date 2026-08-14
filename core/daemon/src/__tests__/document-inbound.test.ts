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
  documentAmendmentHash,
  encodeDocumentAmendment,
  DOCUMENT_UPDATE_ENCODING_V1,
  DOCUMENT_EPOCH_V1,
  type DocumentUpdateEnvelope,
} from "@cello-protocol/protocol-types";
import { DocumentStore } from "../document-store.js";
import { DocumentEngine } from "../document-engine.js";
import { DocumentGate } from "../document-gate.js";
import { DocumentRejections } from "../document-rejection.js";
import { DocumentInbound } from "../document-inbound.js";
import { DocumentAmendmentStore } from "../document-amendment-store.js";
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

function newFixture(
  opts: {
    verify?: () => boolean;
    currentHolders?: () => string[] | null;
    order?: string[];
    appendOnly?: boolean;
    /** Omit the document entirely — the peer-refused-the-proposal case, which holds no row. */
    noDocument?: boolean;
    status?: "active" | "killed" | "closed" | "stalled";
  } = {},
) {
  const { logger, events } = recordingLogger();
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  const store = new DocumentStore(db, logger);
  if (!opts.noDocument) {
    store.createDocument({
      documentId: DOC, ownerAgentId: AGENT, peerAgentId: PEER, documentType: "markdown",
      properties: opts.appendOnly ? { append_only: true } : {},
      status: opts.status ?? "active", createdAtMs: 1,
    });
  }
  const engine = new DocumentEngine(logger);
  const realGate = new DocumentGate(engine, {}, logger);
  // INSTRUMENTED. The ordering test needs to observe that the gate is REACHED, not merely that
  // verify was called — and a real gate with no instrumentation cannot report that.
  const gate = {
    validate: (...args: Parameters<DocumentGate["validate"]>) => {
      opts.order?.push("gate");
      return realGate.validate(...args);
    },
  } as unknown as DocumentGate;
  const rejections = new DocumentRejections(store, logger);
  const amendmentStore = new DocumentAmendmentStore(db, logger);
  const live = new Y.Doc();
  live.clientID = 9999;

  const inbound = new DocumentInbound({
    store, engine, gate, rejections, logger,
    // Null = bilateral legacy (the row's peer column is the gate) — the pre-fan-out semantics
    // every older test in this file was written against.
    currentHolders: opts.currentHolders ?? (() => null),
    verifySignature: opts.verify ?? (() => true),
    liveDocFor: () => live,
    membershipOf: (o, d, a) => amendmentStore.membershipOf(o, d, a),
    sign: async () => new Uint8Array(64).fill(1),
  });
  return { inbound, store, engine, live, events, logger, db };
}

describe("DocumentInbound — an admitted envelope lands, and is acked", () => {
  it("appends it, applies it, and reports admitted", async () => {
    const f = newFixture();
    const env = envelope();

    const res = await f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(env), NOW);
    expect(res).toMatchObject({ ok: true, admitted: true });
    expect(f.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(1);
    expect(f.live.getText("content").toString()).toContain("peer text");
  });

  it("the ack names the envelope, so the sender can settle the right one", async () => {
    const f = newFixture();
    const env = envelope();
    const res = await f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(env), NOW);
    // An ack that does not identify what it acknowledges cannot settle anything — the sender has
    // a backlog, not a single outstanding envelope.
    expect((res as { envelopeHash: string }).envelopeHash).toBe(documentEnvelopeHash(env));
  });
});

/** Module-level twin of the epoch describe's planter — a DECODABLE amendment row. */
function plantAmendment2(
  db: DatabaseSync,
  epoch: number,
  kind: "add_holder" | "remove_holder",
  subject: string,
) {
  const body = {
    document_id: DOC,
    epoch_id: epoch,
    prev_amendment_hash: null,
    kind,
    subject_agent_id: subject,
    property_change: null,
    state_hash: null,
    authored_at_ms: 1,
    author_agent_id: "a".repeat(64),
    author_seq: epoch,
    parents: [],
  } as const;
  const hash = documentAmendmentHash(body);
  const bytes = encodeDocumentAmendment({
    body,
    collection: {
      document_id: DOC,
      subject_kind: "document_amendment",
      subject_hash: hash,
      required_signers: ["a".repeat(64)],
      signatures: [{ signer_agent_id: "a".repeat(64), signature: new Uint8Array(64) }],
    },
  });
  db.prepare(
    `INSERT INTO document_entries
       (owner_agent_id, document_id, entry_hash, author_agent_id, author_seq, epoch_id,
        received_bytes, recorded_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(AGENT, DOC, Buffer.from(hash).toString("hex"), "a".repeat(64), epoch, epoch, Buffer.from(bytes), 1);
}

describe("DOD-MP-INBOUND-N-1 — the sender gate follows the DERIVED arrangement", () => {
  const JOINED = "0".repeat(63) + "2";

  it("a JOINED non-genesis holder's envelope ADMITS — the row's peer column is not the gate", async () => {
    const f = newFixture({ currentHolders: () => [PEER, JOINED] });
    const res = await f.inbound.receive(
      AGENT,
      encodeDocumentUpdateEnvelope(envelope({ sender_agent_id: JOINED, sender_client_id: 4242 })),
      NOW,
    );
    expect(res).toMatchObject({ ok: true, admitted: true });
    expect(f.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(1);
  });

  it("N senders chain INDEPENDENTLY — each first envelope anchors its own per-sender chain", async () => {
    const f = newFixture({ currentHolders: () => [PEER, JOINED] });
    const fromPeer = await f.inbound.receive(
      AGENT, encodeDocumentUpdateEnvelope(envelope()), NOW,
    );
    // JOINED's first envelope also carries prev null — a GLOBAL chain would refuse it as a fork
    // of PEER's head; the per-sender chain admits it on its own anchor.
    const fromJoined = await f.inbound.receive(
      AGENT,
      encodeDocumentUpdateEnvelope(envelope({ sender_agent_id: JOINED, sender_client_id: 4242 })),
      NOW,
    );
    expect(fromPeer).toMatchObject({ ok: true, admitted: true });
    expect(fromJoined).toMatchObject({ ok: true, admitted: true });
    expect(f.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(2);
  });

  it("an UNKNOWN epoch-ahead sender is LOGGED as amendment lag, not as a stranger probe", async () => {
    // F1: the honest new holder's first envelope — their add_holder amendment still in flight
    // to us — is wire-silent (disclosure stands) but the LOG names the lag signature: unknown
    // sender + epoch ahead of ours. Revert the discriminator and this reads as a stranger.
    const f = newFixture({ currentHolders: () => [PEER] });
    const res = await f.inbound.receive(
      AGENT,
      encodeDocumentUpdateEnvelope(
        envelope({ sender_agent_id: "0".repeat(63) + "4", sender_client_id: 7, epoch_id: 1 }),
      ),
      NOW,
    );
    expect(res).toMatchObject({ ok: false, reason: "document_sender_not_peer" });
    expect(f.events.some((e) => e.event === "document.inbound.sender_unknown_epoch_ahead")).toBe(true);
    expect(f.events.some((e) => e.event === "document.inbound.not_peer")).toBe(false);
  });

  it("a STRANGER stays silently refused even when the chain derives — membership discloses nothing to non-parties", async () => {
    const f = newFixture({ currentHolders: () => [PEER, JOINED] });
    const res = await f.inbound.receive(
      AGENT,
      encodeDocumentUpdateEnvelope(envelope({ sender_agent_id: "0".repeat(63) + "3" })),
      NOW,
    );
    expect(res).toMatchObject({ ok: false, reason: "document_sender_not_peer" });
    expect((res as { terminal?: boolean }).terminal).toBeUndefined();
  });

  it("a REMOVED genesis peer's envelope refuses BY NAME when the chain derives — not admitted via the row", async () => {
    const f = newFixture({ currentHolders: () => [JOINED] });
    plantAmendment2(f.db, 1, "add_holder", JOINED);
    plantAmendment2(f.db, 2, "remove_holder", PEER);
    const res = await f.inbound.receive(
      AGENT,
      encodeDocumentUpdateEnvelope(envelope({ epoch_id: 2 })),
      NOW,
    );
    expect(res).toMatchObject({ ok: false, reason: "document_sender_removed", terminal: true });
  });
});

describe("DocumentInbound — the EPOCH ruling (M14B / DOD-MP-AMEND-1)", () => {
  /**
   * Raise the document's current epoch by planting a DECODABLE amendment-chain row — the
   * membership walk (DOD-MP-REMOVE-1) decodes every stored row, so a garbage blob here is a
   * state no real daemon can hold (validate-before-append) and would only test the test.
   */
  function plantAmendment(
    db: DatabaseSync,
    epoch: number,
    kind: "add_holder" | "remove_holder" = "add_holder",
    subject: string = "f".repeat(64),
  ) {
    const body = {
      document_id: DOC,
      epoch_id: epoch,
      prev_amendment_hash: null,
      kind,
      subject_agent_id: subject,
      property_change: null,
      state_hash: null,
      authored_at_ms: 1,
      author_agent_id: "a".repeat(64),
      author_seq: epoch,
      parents: [],
    } as const;
    const hash = documentAmendmentHash(body);
    const bytes = encodeDocumentAmendment({
      body,
      collection: {
        document_id: DOC,
        subject_kind: "document_amendment",
        subject_hash: hash,
        required_signers: ["a".repeat(64)],
        signatures: [{ signer_agent_id: "a".repeat(64), signature: new Uint8Array(64) }],
      },
    });
    db.prepare(
      `INSERT INTO document_entries
         (owner_agent_id, document_id, entry_hash, author_agent_id, author_seq, epoch_id,
          received_bytes, recorded_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(AGENT, DOC, Buffer.from(hash).toString("hex"), "a".repeat(64), epoch, epoch, Buffer.from(bytes), 1);
  }
  const raiseEpoch = (db: DatabaseSync, epoch: number) => plantAmendment(db, epoch);

  it("the MISSED-AMENDMENT removed publisher gets the REMOVAL answer, not the epoch answer", async () => {
    // REMOVE-1 review F2 — the honest case: a removed holder who never received the removal
    // amendment publishes at the OLD epoch. "Republish under the current epoch" is an
    // instruction they cannot follow; the membership fact is the diagnosis.
    const f = newFixture();
    plantAmendment(f.db, 1, "remove_holder", PEER);
    const res = await f.inbound.receive(
      AGENT,
      encodeDocumentUpdateEnvelope(envelope({ epoch_id: 0 })),
      NOW,
    );
    expect(res).toMatchObject({ ok: false, reason: "document_sender_removed", terminal: true });
    expect((res as { detail: string }).detail).toContain("epoch 1");
  });

  it("a daemon that knows ITSELF removed stops applying — terminal, so the sender settles", async () => {
    const f = newFixture();
    plantAmendment(f.db, 1, "remove_holder", AGENT);
    const res = await f.inbound.receive(
      AGENT,
      encodeDocumentUpdateEnvelope(envelope({ epoch_id: 0 })),
      NOW,
    );
    expect(res).toMatchObject({ ok: false, reason: "document_recipient_removed", terminal: true });
    expect(f.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(0);
    expect(f.events.some((e) => e.event === "document.inbound.recipient_removed")).toBe(true);
  });

  it("a removed FORMER holder who is not the genesis peer refuses NAMED and terminal — never the silent stranger path", async () => {
    // REMOVE-1 review F4: the silent not_peer refusal left a removed joined holder redelivering
    // forever. They hold the removal fact already — the named terminal answer discloses nothing.
    const f = newFixture();
    const other = "0".repeat(63) + "1";
    plantAmendment(f.db, 1, "add_holder", other);
    plantAmendment(f.db, 2, "remove_holder", other);
    const res = await f.inbound.receive(
      AGENT,
      encodeDocumentUpdateEnvelope(envelope({ sender_agent_id: other, epoch_id: 2 })),
      NOW,
    );
    expect(res).toMatchObject({ ok: false, reason: "document_sender_removed", terminal: true });
    expect((res as { detail: string }).detail).toContain("epoch 2");
  });

  it("a REMOVED sender's envelope is TERMINAL, naming the removal epoch — never a silent drop", async () => {
    const f = newFixture();
    plantAmendment(f.db, 1, "remove_holder", PEER);
    const res = await f.inbound.receive(
      AGENT,
      encodeDocumentUpdateEnvelope(envelope({ epoch_id: 1 })),
      NOW,
    );
    expect(res).toMatchObject({ ok: false, reason: "document_sender_removed", terminal: true });
    expect((res as { detail: string }).detail).toContain("epoch 1");
    expect(f.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(0);
  });

  it("an envelope BEHIND the current epoch is TERMINAL — its TBS binds the old epoch forever", async () => {
    const f = newFixture();
    raiseEpoch(f.db, 1);
    const res = await f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(envelope()), NOW);
    expect(res).toMatchObject({ ok: false, reason: "document_epoch_stale", terminal: true });
    expect(f.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(0);
  });

  it("an envelope AHEAD of us refuses NON-terminally — the amendment is still in flight here", async () => {
    const f = newFixture();
    const res = await f.inbound.receive(
      AGENT,
      encodeDocumentUpdateEnvelope(envelope({ epoch_id: 2 })),
      NOW,
    );
    expect(res).toMatchObject({ ok: false, reason: "document_epoch_ahead" });
    expect((res as { terminal?: boolean }).terminal).toBeUndefined();
    expect(f.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(0);
  });

  it("an envelope AT the current post-amendment epoch admits normally", async () => {
    const f = newFixture();
    raiseEpoch(f.db, 1);
    const res = await f.inbound.receive(
      AGENT,
      encodeDocumentUpdateEnvelope(envelope({ epoch_id: 1 })),
      NOW,
    );
    expect(res).toMatchObject({ ok: true, admitted: true });
  });
});

describe("DocumentInbound — the ORDER is the security property", () => {
  it("REFUSES an envelope whose signature does not verify, and applies NOTHING", async () => {
    const f = newFixture({ verify: () => false });
    const res = await f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(envelope()), NOW);

    expect(res).toMatchObject({ ok: false, reason: "document_signature_invalid" });
    // Not admitted, not logged, not applied, and NOT rejected either: a rejection is a protocol
    // act that presumes an authenticated counterparty. An unsigned envelope has no counterparty.
    expect(f.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(0);
    expect(f.live.getText("content").toString()).toBe("");
    expect(f.store.listQuarantined(AGENT, DOC)).toHaveLength(0);
  });

  it("verifies the signature BEFORE the gate — an unsigned envelope never REACHES the rules", async () => {
    const order: string[] = [];
    const f = newFixture({
      order,
      verify: () => {
        order.push("verify");
        return false;
      },
    });
    await f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(envelope()), NOW);
    // The gate is INSTRUMENTED, so this asserts it was never reached. The earlier version only ever
    // pushed from the verify callback, so `["verify"]` was satisfied by any implementation calling
    // verify once — including one that ran the gate first. It was the headline test and it pinned
    // nothing; my commit message claimed it pinned the ordering.
    expect(order).toEqual(["verify"]);
  });

  it("reaches the gate ONLY after a signature that verifies", async () => {
    const order: string[] = [];
    const f = newFixture({
      order,
      verify: () => {
        order.push("verify");
        return true;
      },
    });
    await f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(envelope()), NOW);
    // The positive half. Swap the two steps and this becomes ["gate", "verify"].
    expect(order).toEqual(["verify", "gate"]);
  });

  it("does not disclose the peer's identity to an unauthenticated sender", async () => {
    const f = newFixture();
    const res = await f.inbound.receive(
      AGENT,
      encodeDocumentUpdateEnvelope(envelope({ sender_agent_id: "a-stranger" })),
      NOW,
    );
    // Anyone reaching the channel with a guessed or leaked document_id would otherwise learn who
    // the owner collaborates with. The full detail belongs in the daemon log, not the reply.
    expect((res as { detail: string }).detail).not.toContain(PEER);
  });

  it("refuses a malformed envelope by name, before anything else happens", async () => {
    const f = newFixture();
    const res = await f.inbound.receive(AGENT, new Uint8Array([1, 2, 3]), NOW);
    expect(res).toMatchObject({ ok: false });
    // Wrapped, not passed through raw: a lib0/CBOR decoder message names library internals and
    // reads as a crash, not a protocol refusal.
    expect((res as { reason: string }).reason).toBe("document_inbound_malformed");
    expect(f.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(0);
  });

  it("refuses an envelope for a document this agent does not have", async () => {
    const f = newFixture();
    const res = await f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(envelope({ document_id: "ab".repeat(32) })), NOW);
    expect(res).toMatchObject({ ok: false, reason: "document_unknown" });
  });

  it("refuses an envelope from someone who is not this document's peer", async () => {
    const f = newFixture();
    const res = await f.inbound.receive(
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
  it("acks a redelivered envelope without applying it twice", async () => {
    const f = newFixture();
    const wire = encodeDocumentUpdateEnvelope(envelope());

    expect(await f.inbound.receive(AGENT, wire, NOW)).toMatchObject({ ok: true, admitted: true });
    const second = await f.inbound.receive(AGENT, wire, NOW + 1);

    // Delivery retries across restarts by design, so a redelivery is expected traffic. It must ack
    // — otherwise the sender never settles it — and it must not append or apply a second time.
    expect(second).toMatchObject({ ok: true, admitted: true, duplicate: true });
    expect(f.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(1);
  });

  it("REFUSES an envelope that chains to something we have never seen", async () => {
    const f = newFixture();
    const res = await f.inbound.receive(
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
  it("quarantines the bytes, writes the 0x05 leaf, and acks as NOT admitted", async () => {
    const f = newFixture({ appendOnly: true });
    // Seed an accepted base so the peer's update can delete from it.
    const base = envelope({ update: update(PEER_CLIENT, "original content. ") });
    await f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(base), NOW);

    const deleting = new Y.Doc();
    deleting.clientID = PEER_CLIENT;
    Y.applyUpdate(deleting, base.update);
    deleting.getText("content").delete(0, 8);
    const env = envelope({
      update: Y.encodeStateAsUpdate(deleting),
      doc_prev_hash: documentEnvelopeHash(base),
    });

    const res = await f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(env), NOW + 1);
    // A rejection IS an ack for delivery purposes — the peer has decided, so the sender must stop
    // retrying and supersede instead.
    expect(res).toMatchObject({ ok: true, admitted: false });
    expect((res as { rejectionReason: string }).rejectionReason).toMatch(/append_only/);
    expect(f.store.listQuarantined(AGENT, DOC)).toHaveLength(1);
  });

  it("does NOT apply a refused update to the live document", async () => {
    const f = newFixture({ appendOnly: true });
    const base = envelope({ update: update(PEER_CLIENT, "original content. ") });
    await f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(base), NOW);
    const before = f.live.getText("content").toString();

    const deleting = new Y.Doc();
    deleting.clientID = PEER_CLIENT;
    Y.applyUpdate(deleting, base.update);
    deleting.getText("content").delete(0, 8);
    await f.inbound.receive(
      AGENT,
      encodeDocumentUpdateEnvelope(
        envelope({ update: Y.encodeStateAsUpdate(deleting), doc_prev_hash: documentEnvelopeHash(base) }),
      ),
      NOW + 1,
    );

    // The whole point of the gate is that refused content never lands. Applying and then recording
    // a rejection would leave the refusal as an annotation on content the operator already has.
    expect(f.live.getText("content").toString()).toBe(before);
  });
});


describe("DocumentInbound — a document that has STOPPED accepting does not admit", () => {
  for (const status of ["killed", "closed", "stalled"] as const) {
    it(`refuses while ${status}, naming that as the cause`, async () => {
      const f = newFixture();
      f.store.setDocumentStatus(AGENT, DOC, status);

      const res = await f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(envelope()), NOW);
      expect(res.ok).toBe(false);
      // Reporting this envelope's own gate verdict instead would send an operator to the
      // append-only rule for a document that has been frozen for days.
      expect((res as { reason: string }).reason).toBe(`document_${status}`);
      expect(f.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(0);
    });
  }
});

describe("DocumentInbound — a REJECTED envelope redelivered does not advance the round", () => {
  it("re-answers with the recorded reason instead of rejecting again", async () => {
    const f = newFixture({ appendOnly: true });
    const base = envelope({ update: update(PEER_CLIENT, "original content. ") });
    await f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(base), NOW);

    const deleting = new Y.Doc();
    deleting.clientID = PEER_CLIENT;
    Y.applyUpdate(deleting, base.update);
    deleting.getText("content").delete(0, 8);
    const wire = encodeDocumentUpdateEnvelope(
      envelope({ update: Y.encodeStateAsUpdate(deleting), doc_prev_hash: documentEnvelopeHash(base) }),
    );

    const first = await f.inbound.receive(AGENT, wire, NOW + 1);
    expect(first).toMatchObject({ ok: true, admitted: false });

    // A rejected envelope's hash is never written to the log, so a redelivery is NOT a duplicate.
    // Re-running the gate minted a fresh nonce and advanced the retry round — so a peer whose acks
    // were being lost, which is delivery's ordinary retry behaviour, permanently stalled the shared
    // document in three attempts with no hostility required.
    for (let i = 0; i < 5; i++) await f.inbound.receive(AGENT, wire, NOW + 2 + i);

    expect(f.store.getDocument(AGENT, DOC)!.status).toBe("active");
    expect(f.store.listQuarantined(AGENT, DOC)).toHaveLength(1);
  });
});

describe("DocumentInbound — append_only comes from the AGREED property", () => {
  it("enforces it with no caller option, because the property is where it was agreed", async () => {
    const f = newFixture({ appendOnly: true });
    const base = envelope({ update: update(PEER_CLIENT, "original content. ") });
    await f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(base), NOW);

    const deleting = new Y.Doc();
    deleting.clientID = PEER_CLIENT;
    Y.applyUpdate(deleting, base.update);
    deleting.getText("content").delete(0, 8);

    // Taken from a caller option defaulting to OFF, a document configured append-only was
    // unprotected unless every future call site remembered the flag — and the gate's own header
    // says append_only is the only thing standing between a bound peer and erasure.
    const res = await f.inbound.receive(
      AGENT,
      encodeDocumentUpdateEnvelope(
        envelope({ update: Y.encodeStateAsUpdate(deleting), doc_prev_hash: documentEnvelopeHash(base) }),
      ),
      NOW + 1,
    );
    expect(res).toMatchObject({ ok: true, admitted: false });
  });

  it("does NOT enforce it when the document did not agree to it", async () => {
    const f = newFixture({ appendOnly: false });
    const base = envelope({ update: update(PEER_CLIENT, "original content. ") });
    await f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(base), NOW);

    const deleting = new Y.Doc();
    deleting.clientID = PEER_CLIENT;
    Y.applyUpdate(deleting, base.update);
    deleting.getText("content").delete(0, 8);
    const res = await f.inbound.receive(
      AGENT,
      encodeDocumentUpdateEnvelope(
        envelope({ update: Y.encodeStateAsUpdate(deleting), doc_prev_hash: documentEnvelopeHash(base) }),
      ),
      NOW + 1,
    );
    expect(res).toMatchObject({ ok: true, admitted: true });
  });
});

/**
 * DOD-DOC-INBOUND-TERMINAL-1 — a refusal the sender can never fix must SETTLE their delivery.
 *
 * Found on the live daemon, not by a test. Miss_Chelly proposed document `662743b1…`, CELLO_Coder_1
 * refused the proposal, and Miss_Chelly wrote into it anyway. That envelope has sat at
 * `pendingSent: 1` ever since: the peer holds no such document, answers `document_unknown`, and
 * because that is an `ok: false` result the router never sends an ack — so nothing ever settles it
 * and the delivery worker redelivers it forever.
 *
 * The router's own comment names this exact failure ("an inbound path with no ack producer leaves
 * the peer retrying until their document stalls at the unacked ceiling") and then produces an ack
 * only on the `ok: true` path. The refusals below are the ones that path never covers.
 *
 * WHICH REFUSALS QUALIFY, and why the list is short. Two conditions, both required:
 *   - TERMINAL — redelivering cannot change the answer. A stalled document is deliberately NOT on
 *     this list: the stall is resolved by operator action, after which the very same redelivery
 *     succeeds, so retrying there is the recovery mechanism rather than a leak.
 *   - AUTHENTICATED — we verified the sender's own signature. An ack is a signed statement to a
 *     named party; producing one for an unverified sender answers whoever reached the channel.
 */
describe("a TERMINAL refusal settles the sender's delivery instead of leaving it to retry forever", () => {
  it("document_unknown is terminal, and names the envelope so an ack can settle it", async () => {
    const f = newFixture({ noDocument: true });
    const env = envelope();

    const res = await f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(env), NOW);

    expect(res).toMatchObject({ ok: false, reason: "document_unknown", terminal: true });
    // The envelope hash is what makes the ack settle THIS delivery rather than the sender's whole
    // backlog. A terminal refusal that cannot name what it refused settles nothing.
    expect((res as { envelopeHash?: string }).envelopeHash).toBe(documentEnvelopeHash(env));
  });

  it("a KILLED and a CLOSED document are terminal too — they will never accept this envelope", async () => {
    for (const status of ["killed", "closed"] as const) {
      const f = newFixture({ status });
      const env = envelope();
      const res = await f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(env), NOW);
      // THE HASH, not just the flag. Asserting `terminal` alone let an implementation drop
      // `envelopeHash` here and still pass — and the router only acks when it has BOTH, so the
      // defect came straight back with every gate green. Caught in review, not by the gate.
      expect(res, status).toMatchObject({ terminal: true, envelopeHash: documentEnvelopeHash(env) });
    }
  });

  it("a NON-PARTY is answered with SILENCE even when the document is killed", async () => {
    // THE ORDERING BUG THIS PINS. The peer check used to run AFTER the killed/closed branch, so a
    // stranger naming an existing killed document got back a signed ack — `sendAck` addresses the
    // ENVELOPE's sender, so it really reached them — confirming both that the document exists and
    // what state it is in. Precisely the disclosure the silent refusal exists to withhold.
    const f = newFixture({ status: "killed" });
    const res = await f.inbound.receive(
      AGENT,
      encodeDocumentUpdateEnvelope(envelope({ sender_agent_id: "someone-else" })),
      NOW,
    );
    expect(res).toMatchObject({ ok: false, reason: "document_sender_not_peer" });
    expect((res as { terminal?: boolean }).terminal).toBeUndefined();
  });

  it("a chain FORK is terminal; a chain GAP is not", async () => {
    // The distinction the envelope module created, applied to delivery. A gap means the predecessor
    // has not arrived YET — redelivery IS the recovery. A fork chains onto something that never was
    // our head, and an append-only log has no repair for that.
    const f = newFixture();
    // Establish a head, then send a SECOND genesis envelope — two roots for one sender, which the
    // envelope module calls a fork and for which it states plainly "there is no repair".
    await f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(envelope()), NOW);
    const forked = envelope({ update: update(PEER_CLIENT, "a different root. ") });
    const res = await f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(forked), NOW);
    expect(res).toMatchObject({ ok: false, reason: "document_chain_forked", terminal: true });
    expect((res as { envelopeHash?: string }).envelopeHash).toBe(documentEnvelopeHash(forked));

    // THE GAP, for contrast: a predecessor we have never seen may still arrive, so the sender must
    // keep retrying and must NOT be settled.
    const g = newFixture();
    const gap = envelope({ doc_prev_hash: "ff".repeat(32) });
    const gapRes = await g.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(gap), NOW);
    expect(gapRes).toMatchObject({ ok: false, reason: "document_chain_broken" });
    expect((gapRes as { terminal?: boolean }).terminal).toBeUndefined();
  });

  it("VERIFIES BEFORE the document lookup — an unsigned envelope for an unknown document is not terminal", async () => {
    // The ordering IS the property. If the lookup ran first, a party we never authenticated would
    // get back a signed ack naming a document — so the bad signature must win over the missing
    // document, not the other way round.
    const f = newFixture({ noDocument: true, verify: () => false });
    const res = await f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(envelope()), NOW);

    expect(res).toMatchObject({ ok: false, reason: "document_signature_invalid" });
    expect((res as { terminal?: boolean }).terminal).toBeUndefined();
  });

  it("a NON-PARTY sender is refused but NOT settled — an ack would confirm the document exists", async () => {
    // This one is terminal in the plain sense (a third party will never be a party to this
    // document) and still must not be acked: the refusal deliberately withholds the peer's
    // identity for exactly this reason, and a signed ack naming the document_id gives back the
    // existence answer the refusal was written to hide.
    const f = newFixture();
    const res = await f.inbound.receive(
      AGENT,
      encodeDocumentUpdateEnvelope(envelope({ sender_agent_id: "someone-else" })),
      NOW,
    );
    expect(res).toMatchObject({ ok: false, reason: "document_sender_not_peer" });
    expect((res as { terminal?: boolean }).terminal).toBeUndefined();
  });

  it("a STALLED document is NOT terminal — the retry is how it recovers once the operator acts", async () => {
    // The distinction this whole list turns on. `killed` and `closed` are decisions; `stalled` is a
    // condition, and clearing it makes the very same redelivery land. Settling the sender's
    // delivery here would throw away the update that the operator is about to unblock.
    const f = newFixture({ status: "stalled" });
    const res = await f.inbound.receive(AGENT, encodeDocumentUpdateEnvelope(envelope()), NOW);

    expect(res).toMatchObject({ ok: false, reason: "document_stalled" });
    expect((res as { terminal?: boolean }).terminal).toBeUndefined();
  });
});
