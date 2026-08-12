/**
 * DOD-DOC-INBOUND-2 — consuming an arriving ACK, which is what closes DELIVERY-2's loop.
 *
 * An ack settles an envelope permanently: it stops being redelivered, and a rejection makes the
 * sender roll back local work. Every refusal below exists because the alternative is one of those
 * two consequences happening on a claim nobody made.
 *
 * `node:sqlite` here is the test-file allowance; production is SQLCipher.
 */

import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import { encodeDocumentAck, type DocumentAck } from "@cello-protocol/protocol-types";
import { DocumentStore, type DocumentEnvelopeRow } from "../document-store.js";
import { DocumentRejections } from "../document-rejection.js";
import { DocumentAckInbound } from "../document-ack-inbound.js";
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

let seq = 0;
function envelope(sender = AGENT): DocumentEnvelopeRow {
  seq += 1;
  return {
    envelopeHash: createHash("sha256").update(`ack${seq}`).digest("hex"),
    documentId: DOC,
    senderAgentId: sender,
    docPrevHash: null,
    epochId: 0,
    signature: new Uint8Array(64),
    stateVector: new Uint8Array([0]),
    payload: new Uint8Array([1, 2, 3]),
    kind: "update",
    createdAtMs: NOW,
  };
}

function ack(over: Partial<DocumentAck> = {}): DocumentAck {
  return {
    type: "document_ack",
    document_id: DOC,
    envelope_hash: "bb".repeat(32),
    ack_version: 1,
    acker_agent_id: PEER,
    admitted: true,
    acked_at_ms: NOW,
    signature: new Uint8Array(64).fill(4),
    ...over,
  };
}

function newFixture(opts: {
  verify?: () => boolean;
  onSettled?: (owner: string, hash: string) => void;
  /** Derived holders; null = bilateral legacy (the genesis-peer gate stands alone). */
  currentHolders?: () => string[] | null;
} = {}) {
  const { logger, events } = recordingLogger();
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  const store = new DocumentStore(db, logger);
  store.createDocument({
    documentId: DOC, ownerAgentId: AGENT, peerAgentId: PEER, documentType: "markdown",
    properties: {}, status: "active", createdAtMs: 1,
  });
  const rejections = new DocumentRejections(store, logger);
  const inbound = new DocumentAckInbound({
    store, rejections, logger,
    // Null = the bilateral-legacy gate (genesis peer only) — the pre-fan-out semantics.
    currentHolders: opts.currentHolders ?? (() => null),
    verifySignature: opts.verify ?? (() => true),
    ...(opts.onSettled ? { onSettled: opts.onSettled } : {}),
  });
  return { inbound, store, events, rejections };
}

describe("FANOUT-1 — the ack gate follows the DERIVED arrangement, not the genesis column", () => {
  it("a JOINED non-genesis holder's ack passes the gate and settles THEIR row", async () => {
    const JOINED = "ff".repeat(32);
    const f = newFixture({ currentHolders: () => [PEER, JOINED] });
    const e = envelope();
    f.store.appendEnvelope(AGENT, e);
    f.store.seedDeliveries(AGENT, DOC, e.envelopeHash, [PEER, JOINED], NOW);
    const res = await f.inbound.receive(
      AGENT,
      encodeDocumentAck(ack({ envelope_hash: e.envelopeHash, acker_agent_id: JOINED })),
      NOW,
    );
    expect(res).toMatchObject({ ok: true, admitted: true });
    expect(f.store.holderHasPending(AGENT, DOC, JOINED)).toBe(false);
    expect(f.store.holderHasPending(AGENT, DOC, PEER)).toBe(true);
    // Not all-confirmed while the genesis peer is owed.
    expect(f.store.getEnvelopeLog(AGENT, DOC)[0]!.ackedAtMs).toBeNull();
  });

  it("a REMOVED genesis peer's ack refuses when the chain derives — the genesis column is not a permanent credential", async () => {
    // Review H2: doc.peerAgentId outlives the arrangement; a removed (hostile) genesis peer
    // could otherwise keep settling rows forever.
    const JOINED = "ff".repeat(32);
    const f = newFixture({ currentHolders: () => [JOINED] });
    const e = envelope();
    f.store.appendEnvelope(AGENT, e);
    f.store.seedDeliveries(AGENT, DOC, e.envelopeHash, [JOINED], NOW);
    const res = await f.inbound.receive(
      AGENT,
      encodeDocumentAck(ack({ envelope_hash: e.envelopeHash, acker_agent_id: PEER })),
      NOW,
    );
    expect(res).toMatchObject({ ok: false, reason: "document_ack_not_peer" });
    expect(f.store.holderHasPending(AGENT, DOC, JOINED)).toBe(true);
  });

  it("H1: one holder's ack cannot settle another's row — each settles exactly their own", async () => {
    const JOINED = "ff".repeat(32);
    const f = newFixture({ currentHolders: () => [PEER, JOINED] });
    const e = envelope();
    f.store.appendEnvelope(AGENT, e);
    f.store.seedDeliveries(AGENT, DOC, e.envelopeHash, [PEER, JOINED], NOW);
    await f.inbound.receive(
      AGENT,
      encodeDocumentAck(ack({ envelope_hash: e.envelopeHash, acker_agent_id: PEER })),
      NOW,
    );
    expect(f.store.holderHasPending(AGENT, DOC, PEER)).toBe(false);
    expect(f.store.holderHasPending(AGENT, DOC, JOINED)).toBe(true);
  });
});

describe("DocumentAckInbound — an admission settles the envelope", () => {
  it("marks it acked, so the worker stops redelivering", () => {
    const f = newFixture();
    const e = envelope();
    f.store.appendEnvelope(AGENT, e);

    const res = f.inbound.receive(AGENT, encodeDocumentAck(ack({ envelope_hash: e.envelopeHash })), NOW);
    expect(res).toMatchObject({ ok: true, admitted: true });
    expect(f.store.pendingDeliveries(AGENT, NOW + 10_000_000)).toHaveLength(0);
  });

  it("a REDELIVERED ack does not move the recorded time", () => {
    const f = newFixture();
    const e = envelope();
    f.store.appendEnvelope(AGENT, e);
    const wire = encodeDocumentAck(ack({ envelope_hash: e.envelopeHash }));

    f.inbound.receive(AGENT, wire, NOW);
    f.inbound.receive(AGENT, wire, NOW + 5_000);
    // The ack records WHEN the peer answered. A redelivery moving it would make the delivery record
    // say the peer confirmed at a time it did not.
    expect(f.store.getEnvelopeLog(AGENT, DOC)[0]!.ackedAtMs).toBe(NOW);
  });
});

describe("DocumentAckInbound — a rejection settles it too, and says why", () => {
  it("acks the envelope AND records the peer's refusal", () => {
    const f = newFixture();
    const e = envelope();
    f.store.appendEnvelope(AGENT, e);

    const res = f.inbound.receive(
      AGENT,
      encodeDocumentAck(
        ack({
          envelope_hash: e.envelopeHash,
          admitted: false,
          rejection_reason: "document_append_only_violation",
        }),
      ),
      NOW,
    );

    expect(res).toMatchObject({ ok: true, admitted: false });
    // Settled: the peer has DECIDED, so retrying would re-trigger their gate and their retry
    // counter until the document stalls for reasons the operator cannot see.
    expect(f.store.pendingDeliveries(AGENT, NOW + 10_000_000)).toHaveLength(0);
    // And durable, on the publishing side — the operator needs to know why their work was refused
    // after a restart, not just that it was.
    expect(f.store.countRejectionsReceived(AGENT, DOC)).toBe(1);
    expect(f.store.latestRejectionReceived(AGENT, DOC)!.reason).toBe(
      "document_append_only_violation",
    );
  });
});

describe("DocumentAckInbound — the ORDER of the checks is the security property", () => {
  it("REFUSES an ack whose signature does not verify, and settles nothing", () => {
    const f = newFixture({ verify: () => false });
    const e = envelope();
    f.store.appendEnvelope(AGENT, e);

    const res = f.inbound.receive(AGENT, encodeDocumentAck(ack({ envelope_hash: e.envelopeHash })), NOW);
    expect(res).toMatchObject({ ok: false, reason: "document_ack_signature_invalid" });
    // Unsigned, anyone who can reach the channel silences a delivery: the content drops out of the
    // pending set and neither operator ever learns it was never applied.
    expect(f.store.pendingDeliveries(AGENT, NOW + 10_000_000)).toHaveLength(1);
  });

  it("refuses an ack from someone who is not this document's peer", () => {
    const f = newFixture();
    const e = envelope();
    f.store.appendEnvelope(AGENT, e);

    const res = f.inbound.receive(
      AGENT,
      encodeDocumentAck(ack({ envelope_hash: e.envelopeHash, acker_agent_id: "a-stranger" })),
      NOW,
    );
    expect(res).toMatchObject({ ok: false, reason: "document_ack_not_peer" });
    expect(f.store.pendingDeliveries(AGENT, NOW + 10_000_000)).toHaveLength(1);
  });

  it("refuses an ack for an envelope this agent never authored", () => {
    const f = newFixture();
    // The PEER's envelope. Acking it would settle a delivery that was never ours to make.
    const e = envelope(PEER);
    f.store.appendEnvelope(AGENT, e);

    const res = f.inbound.receive(AGENT, encodeDocumentAck(ack({ envelope_hash: e.envelopeHash })), NOW);
    expect(res).toMatchObject({ ok: false, reason: "document_ack_not_author" });
  });

  it("refuses an ack for an envelope that is not in the log at all", () => {
    const f = newFixture();
    const res = f.inbound.receive(AGENT, encodeDocumentAck(ack()), NOW);
    // An ack for an unknown envelope is either a bug or a probe. Recording it would put a claim
    // about a nonexistent delivery into the publishing side's permanent record.
    expect(res).toMatchObject({ ok: false, reason: "document_ack_envelope_unknown" });
  });

  it("refuses an ack for a document this agent does not have", () => {
    const f = newFixture();
    const res = f.inbound.receive(
      AGENT,
      encodeDocumentAck(ack({ document_id: "ff".repeat(32) })),
      NOW,
    );
    expect(res).toMatchObject({ ok: false, reason: "document_unknown" });
  });

  it("refuses a malformed ack by name", () => {
    const f = newFixture();
    const res = f.inbound.receive(AGENT, new Uint8Array([1, 2, 3]), NOW);
    expect(res).toMatchObject({ ok: false, reason: "document_ack_malformed" });
  });
});


describe("DocumentAckInbound — an envelope is SETTLED ONCE", () => {
  it("REFUSES a contradicting second ack, and keeps the first verdict", () => {
    const f = newFixture();
    const e = envelope();
    f.store.appendEnvelope(AGENT, e);

    expect(
      f.inbound.receive(AGENT, encodeDocumentAck(ack({ envelope_hash: e.envelopeHash })), NOW),
    ).toMatchObject({ ok: true, admitted: true });

    const contradiction = f.inbound.receive(
      AGENT,
      encodeDocumentAck(
        ack({
          envelope_hash: e.envelopeHash,
          admitted: false,
          rejection_reason: "changed_my_mind",
          acked_at_ms: NOW + 1,
        }),
      ),
      NOW + 1,
    );

    // Nothing binds an ack to the acker's chain, so one acker CAN produce both. Applying the later
    // one would let a peer that admitted an envelope later claim it refused it — and the sender
    // would roll back work the peer already holds.
    expect(contradiction).toMatchObject({ ok: false, reason: "document_ack_contradiction" });
    expect(f.store.countRejectionsReceived(AGENT, DOC)).toBe(0);
    expect(f.events.some((ev) => ev.event === "document.ack.contradiction")).toBe(true);
  });

  it("does NOT read another envelope's rejection as this one's", () => {
    const f = newFixture();
    const refused = envelope();
    const fine = envelope();
    f.store.appendEnvelope(AGENT, refused);
    f.store.appendEnvelope(AGENT, fine);

    f.inbound.receive(
      AGENT,
      encodeDocumentAck(
        ack({ envelope_hash: refused.envelopeHash, admitted: false, rejection_reason: "nope" }),
      ),
      NOW,
    );
    const wire = encodeDocumentAck(ack({ envelope_hash: fine.envelopeHash }));
    f.inbound.receive(AGENT, wire, NOW + 1);

    // Document-scoped, this redelivered ADMISSION would be refused as a contradiction simply
    // because something else in the document had been refused.
    expect(f.inbound.receive(AGENT, wire, NOW + 2)).toMatchObject({ ok: true, admitted: true });
  });

  it("accepts an IDENTICAL redelivery without complaint", () => {
    const f = newFixture();
    const e = envelope();
    f.store.appendEnvelope(AGENT, e);
    const wire = encodeDocumentAck(ack({ envelope_hash: e.envelopeHash }));

    f.inbound.receive(AGENT, wire, NOW);
    // Delivery retries by design; a redelivered ack is expected traffic, not a fault.
    expect(f.inbound.receive(AGENT, wire, NOW + 1)).toMatchObject({ ok: true, admitted: true });
    expect(f.events.some((ev) => ev.event === "document.ack.contradiction")).toBe(false);
  });
});

describe("a settled envelope ANNOUNCES itself, so the sender can stop holding a session open", () => {
  for (const admitted of [true, false]) {
    it(`fires onSettled for ${admitted ? "an ADMISSION" : "a REJECTION"} — both end the delivery`, () => {
      // Both outcomes settle. A waiter that only heard about admissions would hold the session open
      // through every rejection, which is the case where the sender most needs to act.
      const settled: Array<[string, string]> = [];
      const f = newFixture({ onSettled: (owner, hash) => settled.push([owner, hash]) });
      const e = envelope();
      f.store.appendEnvelope(AGENT, e);
      // The wire type requires a rejection to name its reason, and enforces it at encode.
      const answer = admitted
        ? ack({ envelope_hash: e.envelopeHash, admitted: true })
        : ack({ envelope_hash: e.envelopeHash, admitted: false, rejection_reason: "gate_refused" });
      f.inbound.receive(AGENT, encodeDocumentAck(answer), NOW);
      expect(settled).toEqual([[AGENT, e.envelopeHash]]);
    });
  }

  it("does NOT fire for an ack whose signature did not verify", () => {
    // Nothing was settled, so releasing a waiter here would end a delivery on the word of a party
    // we could not authenticate.
    const settled: string[] = [];
    const f = newFixture({ onSettled: (_owner, hash) => settled.push(hash), verify: () => false });
    const e = envelope();
    f.store.appendEnvelope(AGENT, e);
    f.inbound.receive(AGENT, encodeDocumentAck(ack({ envelope_hash: e.envelopeHash })), NOW);
    expect(settled).toEqual([]);
  });
});
