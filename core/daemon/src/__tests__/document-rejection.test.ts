/**
 * DOD-DOC-REJECT-1 — rejection and supersession (§3.2, §16.7-2).
 *
 * The naive protocol — receiver discards, sender undoes, both "return to the pre-update state" —
 * leaves a PERMANENT CAUSAL GAP. Yjs undo adds inverses; it does not erase. So the rejected
 * operations stay in the sender's document, every later update computed against the receiver's
 * state vector re-transmits them, and the receiver can never integrate the legitimate work stacked
 * on top of operations it refuses to hold. That is why rejection resolves by SUPERSESSION rather
 * than by rollback on both sides.
 *
 * Scope (from the DoD): this proves the protocol against STORE-1's local envelope log. The CBOR
 * wire encoding is ENVELOPE-1's and the cross-daemon proof is E2E-REJECT-1's.
 */

import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import * as Y from "yjs";
import { DocumentEngine } from "../document-engine.js";
import { DocumentStore, type DocumentEnvelopeRow } from "../document-store.js";
import { DocumentRejections, REJECTION_RETRY_LIMIT } from "../document-rejection.js";

const AGENT = "aa".repeat(32);
const PEER = "bb".repeat(32);
const DOC = "cc".repeat(32);

function recordingLogger(): { logger: never; events: Array<{ event: string; fields: Record<string, unknown> }> } {
  const events: Array<{ event: string; fields: Record<string, unknown> }> = [];
  const capture = (event: string, fields: Record<string, unknown> = {}) => void events.push({ event, fields });
  return { logger: { debug: capture, info: capture, warn: capture, error: capture } as never, events };
}

function newFixture() {
  const { logger, events } = recordingLogger();
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  const store = new DocumentStore(db, logger);
  store.createDocument({
    documentId: DOC, ownerAgentId: AGENT, peerAgentId: PEER, documentType: "markdown",
    properties: {}, status: "active", createdAtMs: 1,
  });
  const engine = new DocumentEngine(logger);
  return { store, engine, rejections: new DocumentRejections(store, logger), events };
}

let seq = 0;
function envelope(payload: Uint8Array | null, prev: string | null): DocumentEnvelopeRow {
  seq += 1;
  return {
    envelopeHash: createHash("sha256").update(`rej${seq}`).digest("hex"),
    documentId: DOC,
    senderAgentId: PEER,
    docPrevHash: prev,
    epochId: 0,
    signature: new Uint8Array(64),
    stateVector: new Uint8Array([0, 0]),
    payload,
    kind: "update",
    createdAtMs: 1_700_000_000_000 + seq,
  };
}

describe("DocumentRejections — a rejection is a record, not a discard", () => {
  it("persists the quarantined bytes as a 0x05-kind row REFERENCING the rejected envelope", () => {
    const { store, rejections } = newFixture();
    const rejected = envelope(new Uint8Array([1, 2, 3]), null);
    store.appendEnvelope(AGENT, rejected);

    rejections.reject(AGENT, DOC, {
      rejectedEnvelopeHash: rejected.envelopeHash,
      quarantined: new Uint8Array([1, 2, 3]),
      reason: "document_append_only_violation",
      detail: "removes existing content",
      senderAgentId: PEER,
    });

    const log = store.getEnvelopeLog(AGENT, DOC);
    const record = log.find((e) => e.kind === "rejection");
    expect(record).toBeDefined();
    // §9: the 0x05 leaf references the rejected update's envelope hash — that reference is what
    // makes the record self-describing for replay ("an update leaf is effective iff no rejection
    // leaf references it").
    expect(record!.referencesEnvelopeHash).toBe(rejected.envelopeHash);
    // And the ORIGINAL is untouched: a rejection is a new row, never an edit.
    expect(log.find((e) => e.envelopeHash === rejected.envelopeHash)!.payload).toEqual(
      new Uint8Array([1, 2, 3]),
    );
  });

  it("HOLDS the quarantined bytes — never admitted, never discarded", () => {
    const { rejections } = newFixture();
    const bytes = new Uint8Array([9, 9, 9]);
    rejections.reject(AGENT, DOC, {
      rejectedEnvelopeHash: "ab".repeat(32),
      quarantined: bytes,
      reason: "document_update_malformed",
      senderAgentId: PEER,
    });

    const held = rejections.quarantined(AGENT, DOC);
    expect(held).toHaveLength(1);
    expect(Buffer.from(held[0]!.quarantined)).toEqual(Buffer.from(bytes));
  });

  it("writes a policy record carrying the REASON, so both operators can see why", () => {
    const { rejections, events } = newFixture();
    rejections.reject(AGENT, DOC, {
      rejectedEnvelopeHash: "ab".repeat(32),
      quarantined: new Uint8Array([1, 1]),
      reason: "document_append_only_violation",
      detail: "the update deletes 12 existing range(s)",
      senderAgentId: PEER,
    });

    const emitted = events.find((e) => e.event === "document.rejection.sent");
    expect(emitted).toBeDefined();
    expect(emitted!.fields.reason).toBe("document_append_only_violation");
    expect(emitted!.fields.documentId).toBe(DOC);
    expect(emitted!.fields.senderAgentId).toBe(PEER);
  });
});

describe("DocumentRejections — supersession, not rollback on both sides (§3.2)", () => {
  it("the superseding update NETS TO ZERO for the rejected content, and converges", () => {
    const { engine, rejections } = newFixture();

    // The receiver holds an accepted base. The sender writes something that will be refused.
    const base = new Y.Doc();
    base.clientID = 1_000;
    base.getText("content").insert(0, "agreed base. ");
    const receiver = new Y.Doc();
    receiver.clientID = 2_000;
    Y.applyUpdate(receiver, Y.encodeStateAsUpdate(base));

    const sender = new Y.Doc();
    sender.clientID = 3_000;
    Y.applyUpdate(sender, Y.encodeStateAsUpdate(base));

    const tracked = rejections.trackLocalEdits(sender);
    sender.getText("content").insert(13, "REFUSED CONTENT. ");

    // The receiver refuses THAT update. The sender rolls back — Yjs undo, inverses not erasure —
    // BEFORE making further local edits, which is the protocol's ordering (§3.2 steps 2-3) and
    // the precondition `rollback` documents.
    rejections.rollback(tracked);

    // Then legitimate work, stacked causally on top of operations the receiver refuses to hold.
    // That stacking is the whole reason the naive "both sides roll back" protocol cannot work.
    sender.getText("content").insert(sender.getText("content").length, "legitimate work.");

    // And publishes a superseding update computed against the RECEIVER's state vector, which
    // necessarily carries the rejected ops PLUS their inverses plus the new work.
    const superseding = engine.encodeState(sender, Y.encodeStateVector(receiver));
    expect(engine.applyUpdate(receiver, superseding).ok).toBe(true);

    // The rejected content nets to zero on the receiver, the legitimate work survives, and both
    // sides genuinely converge — the rejected bytes remaining only as inert tombstones.
    expect(receiver.getText("content").toString()).not.toContain("REFUSED CONTENT");
    expect(receiver.getText("content").toString()).toContain("legitimate work.");
    expect(receiver.getText("content").toString()).toBe(sender.getText("content").toString());
  });

  it("the rollback ADDS INVERSES rather than erasing — the audit trail survives", () => {
    const { rejections } = newFixture();
    const doc = new Y.Doc();
    doc.clientID = 3_000;
    doc.getText("content").insert(0, "base");

    const tracked = rejections.trackLocalEdits(doc);
    doc.getText("content").insert(4, " REFUSED");
    const afterWrite = Y.encodeStateAsUpdate(doc).length;

    rejections.rollback(tracked);
    const afterUndo = Y.encodeStateAsUpdate(doc).length;

    // History GREW. "Wrote X, was rejected, undid X" is auditable, and it is also what keeps
    // causality intact for everything stacked on top.
    expect(afterUndo).toBeGreaterThan(afterWrite);
    expect(doc.getText("content").toString()).toBe("base");
  });

  it("clears the quarantine when the supersession is admitted", () => {
    const { rejections } = newFixture();
    rejections.reject(AGENT, DOC, {
      rejectedEnvelopeHash: "ab".repeat(32),
      quarantined: new Uint8Array([1, 1]),
      reason: "document_append_only_violation",
      senderAgentId: PEER,
    });
    expect(rejections.quarantined(AGENT, DOC)).toHaveLength(1);

    rejections.clearQuarantine(AGENT, DOC, "ab".repeat(32));
    expect(rejections.quarantined(AGENT, DOC)).toHaveLength(0);
  });
});

describe("DocumentRejections — one retry, then stalled (§16.7-2)", () => {
  it("allows exactly one more round, then flips the document to stalled", () => {
    const { store, rejections } = newFixture();
    const reject = () =>
      rejections.reject(AGENT, DOC, {
        rejectedEnvelopeHash: "ab".repeat(32),
        quarantined: new Uint8Array([1, 1]),
        reason: "document_append_only_violation",
        senderAgentId: PEER,
      });

    expect(reject().stalled).toBe(false); // the original rejection
    expect(reject().stalled).toBe(false); // the superseding update rejected — one more round
    expect(reject().stalled).toBe(true); // and that is the limit
    expect(REJECTION_RETRY_LIMIT).toBe(1);

    expect(store.getDocument(AGENT, DOC)!.status).toBe("stalled");
  });

  it("a stalled document STOPS accepting updates, and says why", () => {
    const { store, rejections } = newFixture();
    for (let i = 0; i < 3; i++) {
      rejections.reject(AGENT, DOC, {
        rejectedEnvelopeHash: "ab".repeat(32),
        quarantined: new Uint8Array([1, 1]),
        reason: "document_append_only_violation",
        senderAgentId: PEER,
      });
    }

    const accepting = rejections.acceptsUpdates(AGENT, DOC);
    expect(accepting.ok).toBe(false);
    if (!accepting.ok) {
      // Both operators surface the reason — a document that silently stops converging is the
      // failure this exists to prevent.
      expect(accepting.reason).toBe("document_stalled");
      expect(accepting.detail).toContain("document_append_only_violation");
    }
    expect(store.getDocument(AGENT, DOC)!.status).toBe("stalled");
  });

  it("emits document.stalled once, not on every subsequent refusal", () => {
    const { rejections, events } = newFixture();
    for (let i = 0; i < 5; i++) {
      rejections.reject(AGENT, DOC, {
        rejectedEnvelopeHash: "ab".repeat(32),
        quarantined: new Uint8Array([1, 1]),
        reason: "document_append_only_violation",
        senderAgentId: PEER,
      });
    }
    expect(events.filter((e) => e.event === "document.stalled")).toHaveLength(1);
  });
});

describe("DocumentRejections — mutual concurrent rejections are independent", () => {
  it("each direction has its own quarantine and its own retry count", () => {
    const { store, rejections } = newFixture();
    const other = "dd".repeat(32);
    store.createDocument({
      documentId: other, ownerAgentId: AGENT, peerAgentId: PEER, documentType: "markdown",
      properties: {}, status: "active", createdAtMs: 1,
    });

    // Two documents standing in for the two directions of a mutual rejection: each carries its
    // own quarantine and counter, so neither can stall the other and state vectors keep them
    // from deadlocking.
    rejections.reject(AGENT, DOC, {
      rejectedEnvelopeHash: "11".repeat(32), quarantined: new Uint8Array([1]),
      reason: "document_append_only_violation", senderAgentId: PEER,
    });
    for (let i = 0; i < 3; i++) {
      rejections.reject(AGENT, other, {
        rejectedEnvelopeHash: "22".repeat(32), quarantined: new Uint8Array([2]),
        reason: "document_update_malformed", senderAgentId: PEER,
      });
    }

    expect(store.getDocument(AGENT, DOC)!.status).toBe("active");
    expect(store.getDocument(AGENT, other)!.status).toBe("stalled");
    expect(rejections.quarantined(AGENT, DOC)).toHaveLength(1);
  });
});

describe("DocumentRejections — erasure by a BOUND peer (the question GATE-1 handed over)", () => {
  it("a bound peer's deletion is REJECTABLE, because the gate cannot see it", () => {
    const { rejections } = newFixture();
    // GATE-1's rule (h) binds insertions only: a Yjs delete set carries no clientID and advances
    // no clock, so a bound peer deleting the owner's content passes the gate silently. That is
    // legitimate CRDT behaviour, not a forgery — but it must be REPORTABLE, or the only defence
    // is append_only, which defaults off.
    const outcome = rejections.reject(AGENT, DOC, {
      rejectedEnvelopeHash: "ab".repeat(32),
      quarantined: new Uint8Array([1, 1]),
      reason: "document_bound_peer_erasure",
      detail: "the update deletes content this agent authored",
      senderAgentId: PEER,
    });
    expect(outcome.stalled).toBe(false);
    expect(rejections.quarantined(AGENT, DOC)).toHaveLength(1);
  });
});
