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
import { DocumentRejections, MAX_REJECTED_ROUNDS } from "../document-rejection.js";

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
  return { store, engine, logger, rejections: new DocumentRejections(store, logger), events };
}

/**
 * Signature, state vector and nonce are REQUIRED inputs — the unit refuses to fabricate crypto,
 * because an all-zero placeholder in an immutable log is indistinguishable from a real signature
 * that fails to verify. ENVELOPE-1 produces the real ones.
 */
let nonceCounter = 0;
function crypto(): { sign: (tbs: Uint8Array) => Promise<Uint8Array>; nowMs: number } {
  nonceCounter += 1;
  return {
    sign: async () => new Uint8Array(64).fill(7),
    nowMs: 1_700_000_000_000 + nonceCounter,
    // The refused envelope's own chain link. Required, so the bridge can never fabricate a
    // genesis for a refused envelope it does not actually know the predecessor of.
    rejectedDocPrevHash: null as string | null,
  };
}

/** A real Yjs base update, so a rebuild has something to materialize. clientID pinned per the rule. */
function baseUpdate(): Uint8Array {
  const d = new Y.Doc();
  d.clientID = 1000;
  d.getText("content").insert(0, "agreed base. ");
  return Y.encodeStateAsUpdate(d);
}

/** The bytes the gate refuses — never written to the log, only quarantined. */
function refusedUpdate(): Uint8Array {
  const d = new Y.Doc();
  d.clientID = 1001;
  d.getText("content").insert(0, "REFUSED CONTENT. ");
  return Y.encodeStateAsUpdate(d);
}

/** A clean supersession, causally independent of the refused bytes for fixture purposes. */
function cleanSupersession(): Uint8Array {
  const d = new Y.Doc();
  d.clientID = 1002;
  d.getText("content").insert(0, "clean text. ");
  return Y.encodeStateAsUpdate(d);
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
  it("writes a 0x05 row REFERENCING the refused envelope, and never the refused payload", async () => {
    const { store, engine, rejections } = newFixture();
    const base = envelope(baseUpdate(), null);
    store.appendEnvelope(AGENT, base);
    const refusedHash = "ab".repeat(32);

    await rejections.reject(AGENT, DOC, {
      rejectedEnvelopeHash: refusedHash,
      quarantined: refusedUpdate(),
      reason: "document_append_only_violation",
      detail: "removes existing content",
      senderAgentId: PEER,
      ...crypto(),
      // The refused envelope chains onto the base, as the peer authored it. The bridge needs this:
      // the log will never hold the refused envelope, so this is the only record of where it sat.
      rejectedDocPrevHash: base.envelopeHash,
    });

    const log = store.getEnvelopeLog(AGENT, DOC);
    const record = log.find((e) => e.kind === "rejection");
    expect(record).toBeDefined();
    expect(record!.referencesEnvelopeHash).toBe(refusedHash);

    // THE REFUSAL HAS TO SURVIVE A REBUILD, which is the assertion the previous version of this
    // test stopped one line short of. §9 phrases effectiveness as a replay-time set property
    // ("effective iff no rejection leaf references it"), but implemented literally that is unsound
    // — a supersession is causally stacked on the refused operations, so skipping them at replay
    // leaves everything later permanently pending and the document silently loses the legitimate
    // work. What makes the refusal real is that the payload is NEVER WRITTEN: there is nothing to
    // subtract because nothing was added.
    expect(log.some((e) => e.envelopeHash === refusedHash)).toBe(false);
    const rebuilt = store.rebuildSnapshot(AGENT, DOC, (rows) => engine.replay(rows));
    const doc = new Y.Doc();
    Y.applyUpdate(doc, rebuilt.binary);
    expect(doc.getText("content").toString()).toBe("agreed base. ");
    expect(doc.getText("content").toString()).not.toContain("REFUSED");
  });

  it("HOLDS the quarantined bytes — never admitted, never discarded", async () => {
    const { rejections } = newFixture();
    const bytes = new Uint8Array([9, 9, 9]);
    await rejections.reject(AGENT, DOC, {
      rejectedEnvelopeHash: "ab".repeat(32),
      quarantined: bytes,
      reason: "document_update_malformed",
      senderAgentId: PEER,
      ...crypto(),
    });

    const held = rejections.quarantined(AGENT, DOC);
    expect(held).toHaveLength(1);
    expect(Buffer.from(held[0]!.quarantined)).toEqual(Buffer.from(bytes));
  });

  it("writes a policy record carrying the REASON, so both operators can see why", async () => {
    const { rejections, events } = newFixture();
    await rejections.reject(AGENT, DOC, {
      rejectedEnvelopeHash: "ab".repeat(32),
      quarantined: new Uint8Array([1, 1]),
      reason: "document_append_only_violation",
      detail: "the update deletes 12 existing range(s)",
      senderAgentId: PEER,
      ...crypto(),
    });

    const emitted = events.find((e) => e.event === "document.rejection.sent");
    expect(emitted).toBeDefined();
    expect(emitted!.fields.reason).toBe("document_append_only_violation");
    expect(emitted!.fields.documentId).toBe(DOC);
    expect(emitted!.fields.senderAgentId).toBe(PEER);
  });
});

describe("DocumentRejections — supersession, not rollback on both sides (§3.2)", () => {
  it("the superseding update NETS TO ZERO for the rejected content, and converges", async () => {
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

  it("the rollback ADDS INVERSES rather than erasing — the audit trail survives", async () => {
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

  it("clears the quarantine when the supersession is admitted", async () => {
    const { rejections } = newFixture();
    await rejections.reject(AGENT, DOC, {
      rejectedEnvelopeHash: "ab".repeat(32),
      quarantined: new Uint8Array([1, 1]),
      reason: "document_append_only_violation",
      senderAgentId: PEER,
      ...crypto(),
    });
    expect(rejections.quarantined(AGENT, DOC)).toHaveLength(1);

    rejections.clearQuarantine(AGENT, DOC, "ab".repeat(32));
    expect(rejections.quarantined(AGENT, DOC)).toHaveLength(0);
  });
});

describe("DocumentRejections — one retry, then stalled (§16.7-2)", () => {
  it("allows exactly one more round, then flips the document to stalled", async () => {
    const { store, rejections } = newFixture();
    // DISTINCT envelopes per round, which is what the protocol produces — the original update,
    // then the supersession, then its supersession. Re-rejecting one hash collapsed to a single
    // log row and is what hid the chain fork.
    let n = 0;
    const reject = async () =>
      rejections.reject(AGENT, DOC, {
        rejectedEnvelopeHash: `${(n += 1)}`.padStart(64, "e"),
        quarantined: new Uint8Array([1, 1]),
        reason: "document_append_only_violation",
        senderAgentId: PEER,
        ...crypto(),
      });

    expect((await reject()).stalled).toBe(false); // the original rejection
    expect((await reject()).stalled).toBe(false); // the superseding update rejected — one more round
    expect((await reject()).stalled).toBe(true); // and that is the limit

    expect(store.getDocument(AGENT, DOC)!.status).toBe("stalled");
  });

  it("a stalled document STOPS accepting updates, and says why", async () => {
    const { store, rejections } = newFixture();
    for (let i = 0; i < 3; i++) {
      await rejections.reject(AGENT, DOC, {
        rejectedEnvelopeHash: `${i}`.padStart(64, "e"),
        quarantined: new Uint8Array([1, 1]),
        reason: "document_append_only_violation",
        senderAgentId: PEER,
        ...crypto(),
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

  it("emits document.stalled once, not on every subsequent refusal", async () => {
    const { rejections, events } = newFixture();
    for (let i = 0; i < 5; i++) {
      await rejections.reject(AGENT, DOC, {
        rejectedEnvelopeHash: `${i}`.padStart(64, "f"),
        quarantined: new Uint8Array([1, 1]),
        reason: "document_append_only_violation",
        senderAgentId: PEER,
        ...crypto(),
      });
    }
    expect(events.filter((e) => e.event === "document.stalled")).toHaveLength(1);
  });
});

describe("DocumentRejections — mutual concurrent rejections are independent", () => {
  it("each direction has its own quarantine and its own retry count", async () => {
    const { store, rejections } = newFixture();
    const other = "dd".repeat(32);
    store.createDocument({
      documentId: other, ownerAgentId: AGENT, peerAgentId: PEER, documentType: "markdown",
      properties: {}, status: "active", createdAtMs: 1,
    });

    // Two documents standing in for the two directions of a mutual rejection: each carries its
    // own quarantine and counter, so neither can stall the other and state vectors keep them
    // from deadlocking.
    await rejections.reject(AGENT, DOC, {
      rejectedEnvelopeHash: "11".repeat(32), quarantined: new Uint8Array([1]),
      reason: "document_append_only_violation", senderAgentId: PEER, ...crypto(),
    });
    for (let i = 0; i < 3; i++) {
      await rejections.reject(AGENT, other, {
        rejectedEnvelopeHash: `${i}`.padStart(64, "2"), quarantined: new Uint8Array([2]),
        reason: "document_update_malformed", senderAgentId: PEER, ...crypto(),
      });
    }

    expect(store.getDocument(AGENT, DOC)!.status).toBe("active");
    expect(store.getDocument(AGENT, other)!.status).toBe("stalled");
    expect(rejections.quarantined(AGENT, DOC)).toHaveLength(1);
  });
});

describe("DocumentRejections — erasure by a BOUND peer (the question GATE-1 handed over)", () => {
  it("records the DECISION that erasure is rejectable — detection is owed to the gate", async () => {
    const { rejections } = newFixture();
    // GATE-1's rule (h) binds insertions only: a Yjs delete set carries no clientID and advances
    // no clock, so a bound peer deleting the owner's content passes the gate silently. That is
    // legitimate CRDT behaviour, not a forgery — but it must be REPORTABLE, or the only defence
    // is append_only, which defaults off.
    const outcome = await rejections.reject(AGENT, DOC, {
      rejectedEnvelopeHash: "ab".repeat(32),
      quarantined: new Uint8Array([1, 1]),
      reason: "document_bound_peer_erasure",
      detail: "the update deletes content this agent authored",
      senderAgentId: PEER,
      ...crypto(),
    });
    expect(outcome.stalled).toBe(false);
    expect(rejections.quarantined(AGENT, DOC)).toHaveLength(1);
  });
});

// ─── Pass-one: the cases the original tests could not see ───────────────────

describe("DocumentRejections — the quarantine SURVIVES a restart", () => {
  it("a new instance over the same store still holds the bytes, the round, and the stall", async () => {
    const { store, rejections, logger } = newFixture();
    for (let i = 0; i < 3; i++) {
      await rejections.reject(AGENT, DOC, {
        rejectedEnvelopeHash: `${i}`.padStart(64, "a"),
        quarantined: new Uint8Array([i, i]),
        reason: "document_append_only_violation",
        senderAgentId: PEER,
        ...crypto(),
      });
    }
    expect(store.getDocument(AGENT, DOC)!.status).toBe("stalled");

    // A fresh instance stands in for a daemon restart. Holding this in memory meant the document
    // row said `stalled` while the daemon happily accepted updates on it, the held bytes were
    // gone, and the retry counter restarted — the system reporting two contradictory states.
    const restarted = new DocumentRejections(store, logger);
    expect(restarted.acceptsUpdates(AGENT, DOC).ok).toBe(false);
    expect(restarted.quarantined(AGENT, DOC)).toHaveLength(3);
  });

  it("the held bytes are recovered from the STORE, not from the caller's array", async () => {
    const { store, rejections, logger } = newFixture();
    await rejections.reject(AGENT, DOC, {
      rejectedEnvelopeHash: "ab".repeat(32),
      quarantined: new Uint8Array([4, 5, 6]),
      reason: "document_update_malformed",
      senderAgentId: PEER,
      ...crypto(),
    });

    const recovered = new DocumentRejections(store, logger).quarantined(AGENT, DOC);
    expect(Buffer.from(recovered[0]!.quarantined)).toEqual(Buffer.from([4, 5, 6]));
  });

  it("the bytes are COPIED — a caller reusing its buffer cannot change what was refused", async () => {
    const { rejections } = newFixture();
    const buffer = new Uint8Array([7, 7, 7]);
    await rejections.reject(AGENT, DOC, {
      rejectedEnvelopeHash: "cd".repeat(32),
      quarantined: buffer,
      reason: "document_update_malformed",
      senderAgentId: PEER,
      ...crypto(),
    });
    buffer.fill(0); // a pooled network read buffer is reused

    expect(Buffer.from(rejections.quarantined(AGENT, DOC)[0]!.quarantined)).toEqual(
      Buffer.from([7, 7, 7]),
    );
  });
});

describe("DocumentRejections — rejections do not fork the chain", () => {
  it("three rejections leave the chain VERIFIABLE and the document rebuildable", async () => {
    const { store, engine, rejections } = newFixture();
    // Three SUCCESSIVE envelopes from the peer, each refused. This is the protocol's own shape:
    // the original, its supersession, and that supersession's — a chain, not three roots. An
    // earlier version of this test rejected the same hash three times, which collapsed to one row
    // and hid the fork it was written to catch.
    let prev: string | null = null;
    for (let i = 0; i < 3; i++) {
      const hash = `${i}`.padStart(64, "b");
      await rejections.reject(AGENT, DOC, {
        rejectedEnvelopeHash: hash,
        quarantined: new Uint8Array([i]),
        reason: "document_append_only_violation",
        senderAgentId: PEER,
        ...crypto(),
        rejectedDocPrevHash: prev,
      });
      prev = hash;
    }

    // Writing docPrevHash: null made every rejection a second GENESIS row, so two rejections
    // forked the chain — and the retry protocol guarantees at least two before a stall. The
    // document then rebuilt until the next daemon start and was permanently unopenable after it.
    expect(store.verifyChainLinkage(AGENT, DOC)).toEqual({ ok: true });
    expect(() => store.rebuildSnapshot(AGENT, DOC, (rows) => engine.replay(rows))).not.toThrow();
  });
});

describe("DocumentRejections — rollback refuses rather than undoing the wrong work", () => {
  it("REFUSES when local edits are stacked since tracking began", async () => {
    const { rejections } = newFixture();
    const doc = new Y.Doc();
    doc.clientID = 3_000;
    doc.getText("content").insert(0, "base");

    const tracked = rejections.trackLocalEdits(doc);
    doc.getText("content").insert(4, " REFUSED");
    doc.getText("content").insert(doc.getText("content").length, " legitimate");

    // Unguarded, this undid the LEGITIMATE work and KEPT the refused content — so the supersession
    // re-ships the refused bytes, is rejected again, and the document stalls with a reason
    // pointing at the peer while the operator's writing is gone.
    expect(() => rejections.rollback(tracked)).toThrow(/document_rollback_out_of_order/);
    expect(doc.getText("content").toString()).toBe("base REFUSED legitimate");
  });

  it("REFUSES when nothing was tracked at all, rather than reporting success", async () => {
    const { rejections } = newFixture();
    const doc = new Y.Doc();
    doc.clientID = 3_000;
    const tracked = rejections.trackLocalEdits(doc);
    expect(() => rejections.rollback(tracked)).toThrow(/document_rollback/);
  });
});

describe("DocumentRejections — a duplicate rejection does not advance the round", () => {
  it("re-rejecting the same envelope for the same reason writes one leaf and one round", async () => {
    const { store, rejections } = newFixture();
    const input = {
      rejectedEnvelopeHash: "ef".repeat(32),
      quarantined: new Uint8Array([1]),
      reason: "document_update_malformed",
      senderAgentId: PEER,
      sign: async () => new Uint8Array(64).fill(7),
      nowMs: 1_700_000_000_000,
      rejectedDocPrevHash: null,
    };
    expect((await rejections.reject(AGENT, DOC, input)).round).toBe(1);
    // A duplicate must not advance the counter, or a document reaches `stalled` with fewer
    // rejection leaves than rounds and an auditor replaying the log cannot see why.
    expect((await rejections.reject(AGENT, DOC, input)).round).toBe(1);
    expect(store.getEnvelopeLog(AGENT, DOC).filter((e) => e.kind === "rejection")).toHaveLength(1);
  });
});

describe("DocumentRejections — the policy record lands on BOTH sides (§3.2)", () => {
  it("the sender's side records a rejection ARRIVING, with the reason intact", async () => {
    const { rejections, events } = newFixture();
    rejections.recordIncomingRejection(AGENT, DOC, {
      rejectionEnvelopeHash: "f1".repeat(32),
      rejectedEnvelopeHash: "ab".repeat(32),
      reason: "document_append_only_violation",
      detail: "the update deletes 12 existing range(s)",
      fromAgentId: PEER,
    });

    const received = events.find((e) => e.event === "document.rejection.received");
    expect(received).toBeDefined();
    // Both operators need the reason, not just the one who refused — a rejection an operator
    // cannot see the cause of is indistinguishable from the document silently not converging.
    expect(received!.fields.reason).toBe("document_append_only_violation");
    expect(received!.fields.fromAgentId).toBe(PEER);
    expect(received!.fields.detail).toContain("deletes 12");
  });

  it("the two halves are DISTINCT events — a log reader can tell who refused whom", async () => {
    const { rejections, events } = newFixture();
    await rejections.reject(AGENT, DOC, {
      rejectedEnvelopeHash: "11".repeat(32),
      quarantined: new Uint8Array([1]),
      reason: "document_update_malformed",
      senderAgentId: PEER,
      ...crypto(),
    });
    rejections.recordIncomingRejection(AGENT, DOC, {
      rejectionEnvelopeHash: "f2".repeat(32),
      rejectedEnvelopeHash: "22".repeat(32),
      reason: "document_update_malformed",
      fromAgentId: PEER,
    });

    expect(events.filter((e) => e.event === "document.rejection.sent")).toHaveLength(1);
    expect(events.filter((e) => e.event === "document.rejection.received")).toHaveLength(1);
  });
});


describe("DocumentRejections — the chain BRIDGES a refused envelope (§3.2 + §16.7-5)", () => {
  it("the peer's supersession still links, even though the refused envelope is not in the log", async () => {
    const { store, engine, rejections } = newFixture();
    const base = envelope(baseUpdate(), null);
    store.appendEnvelope(AGENT, base);
    const refusedHash = "ab".repeat(32);

    await rejections.reject(AGENT, DOC, {
      rejectedEnvelopeHash: refusedHash,
      quarantined: refusedUpdate(),
      reason: "document_append_only_violation",
      senderAgentId: PEER,
      ...crypto(),
      rejectedDocPrevHash: base.envelopeHash,
    });

    // The peer does not know its envelope was refused when it authors the supersession, so the
    // supersession chains onto the REFUSED envelope — a hash our log deliberately never holds.
    // Without the bridge this reads as document_chain_broken and the document refuses to rebuild,
    // sending an operator to debug the chain layer for a rejection-protocol event.
    const supersession = envelope(cleanSupersession(), refusedHash);
    store.appendEnvelope(AGENT, supersession);

    expect(store.verifyChainLinkage(AGENT, DOC)).toEqual({ ok: true });
    const rebuilt = store.rebuildSnapshot(AGENT, DOC, (rows) => engine.replay(rows));
    const doc = new Y.Doc();
    Y.applyUpdate(doc, rebuilt.binary);
    expect(doc.getText("content").toString()).toContain("clean text");
    expect(doc.getText("content").toString()).not.toContain("REFUSED");
  });

  it("a link to something that is NEITHER logged nor refused still refuses, and says which", async () => {
    const { store } = newFixture();
    store.appendEnvelope(AGENT, envelope(baseUpdate(), null));
    store.appendEnvelope(AGENT, envelope(new Uint8Array([0]), "de".repeat(32)));

    const verdict = store.verifyChainLinkage(AGENT, DOC);
    expect(verdict.ok).toBe(false);
    // The operator has to be able to tell a rejection from a genuine gap. Saying only "absent from
    // the log" describes both, and one of them is not a chain problem at all.
    expect((verdict as { detail: string }).detail).toContain("not among this document's refused");
  });
});

describe("DocumentRejections — a refused envelope re-refused keeps EVERY round's facts", () => {
  it("three rounds on one envelope hold three sets of bytes, reasons, rules and limits", async () => {
    const { rejections } = newFixture();
    const refusedHash = "ab".repeat(32);
    for (const [i, reason] of ["reason_ONE", "reason_TWO", "reason_THREE"].entries()) {
      await rejections.reject(AGENT, DOC, {
        rejectedEnvelopeHash: refusedHash,
        quarantined: new Uint8Array([i]),
        reason,
        rule: `rule_${i}`,
        limit: { name: "bytes", limit: 100, actual: 100 + i },
        senderAgentId: PEER,
        ...crypto(),
      });
    }

    // Keyed on the REFUSED envelope, ON CONFLICT DO NOTHING dropped rounds two and three with no
    // log line — and the stall message then said "the most recent reason was" and printed the
    // OLDEST. "Held, never discarded" (§3.2) has to hold for every round, not just the first.
    const held = rejections.quarantined(AGENT, DOC);
    expect(held.map((h) => h.reason)).toEqual(["reason_ONE", "reason_TWO", "reason_THREE"]);
    expect(held.map((h) => h.rule)).toEqual(["rule_0", "rule_1", "rule_2"]);
    expect(held.map((h) => h.limitActual)).toEqual([100, 101, 102]);
    expect(held.map((h) => Array.from(h.quarantined))).toEqual([[0], [1], [2]]);
  });

  it("the stall detail names the LATEST reason, not the first", async () => {
    const { rejections } = newFixture();
    for (const reason of ["reason_ONE", "reason_TWO", "reason_THREE"]) {
      await rejections.reject(AGENT, DOC, {
        rejectedEnvelopeHash: "ab".repeat(32),
        quarantined: new Uint8Array([1]),
        reason,
        senderAgentId: PEER,
        ...crypto(),
      });
    }
    const verdict = rejections.acceptsUpdates(AGENT, DOC);
    expect(verdict.ok).toBe(false);
    expect((verdict as { detail: string }).detail).toContain("reason_THREE");
    expect((verdict as { detail: string }).detail).not.toContain("reason_ONE");
  });
});

describe("DocumentRejections — TWO PEERS, one document, two independent counters", () => {
  it("each side reaches its own stall, and neither advances the other's round", async () => {
    // Two stores, because two peers are two daemons. The previous version of this test used two
    // DOCUMENTS owned by one agent, which any implementation passes — it asserted that a composite
    // primary key distinguishes two different keys.
    const a = newFixture();
    const b = newFixture();

    for (let i = 0; i < 2; i++) {
      await a.rejections.reject(AGENT, DOC, {
        rejectedEnvelopeHash: `${i}`.padStart(64, "b"),
        quarantined: new Uint8Array([i]),
        reason: "a_refuses_b",
        senderAgentId: PEER,
        ...crypto(),
      });
      await b.rejections.reject(AGENT, DOC, {
        rejectedEnvelopeHash: `${i}`.padStart(64, "c"),
        quarantined: new Uint8Array([i]),
        reason: "b_refuses_a",
        senderAgentId: PEER,
        ...crypto(),
      });
    }

    // Two rounds each, not four. Counting rejection rows across senders conflated the directions,
    // so the moment both peers refused something the document stalled at half the intended rounds.
    expect(a.rejections.acceptsUpdates(AGENT, DOC).ok).toBe(true);
    expect(b.rejections.acceptsUpdates(AGENT, DOC).ok).toBe(true);

    const third = async (f: typeof a, reason: string, fill: string): Promise<boolean> =>
      (
        await f.rejections.reject(AGENT, DOC, {
          rejectedEnvelopeHash: "9".padStart(64, fill),
          quarantined: new Uint8Array([9]),
          reason,
          senderAgentId: PEER,
          ...crypto(),
        })
      ).stalled;

    expect(await third(a, "a_refuses_b", "b")).toBe(true);
    expect(b.rejections.acceptsUpdates(AGENT, DOC).ok).toBe(true); // A stalling did not stall B
  });
});

describe("DocumentRejections — the RECEIVING half is durable and counts (§3.2 both sides)", () => {
  const incoming = (n: number) => ({
    rejectionEnvelopeHash: `${n}`.padStart(64, "f"),
    rejectedEnvelopeHash: `${n}`.padStart(64, "e"),
    reason: "document_append_only_violation",
    fromAgentId: PEER,
  });

  it("counts the rejections RECEIVED, not the ones this agent authored", async () => {
    const { rejections } = newFixture();
    // On a pure publisher the authored count is zero forever, so the round read 0 for the first,
    // second and third rejection alike — the one number an operator uses to see how close the
    // document is to stalling.
    expect(rejections.recordIncomingRejection(AGENT, DOC, incoming(1)).round).toBe(1);
    expect(rejections.recordIncomingRejection(AGENT, DOC, incoming(2)).round).toBe(2);
  });

  it("stalls the PUBLISHER on the same threshold the receiver stops accepting on", async () => {
    const { rejections } = newFixture();
    rejections.recordIncomingRejection(AGENT, DOC, incoming(1));
    rejections.recordIncomingRejection(AGENT, DOC, incoming(2));
    const third = rejections.recordIncomingRejection(AGENT, DOC, incoming(3));

    // Without this the receiver freezes and the sender keeps superseding into a document that will
    // never take it — the hot loop the retry bound exists to stop, on the only side that loops.
    expect(third.stalled).toBe(true);
    expect(rejections.acceptsUpdates(AGENT, DOC).ok).toBe(false);
    expect(MAX_REJECTED_ROUNDS).toBe(3);
  });

  it("SURVIVES a restart — the publisher's operator still knows why and how many", async () => {
    const f = newFixture();
    f.rejections.recordIncomingRejection(AGENT, DOC, incoming(1));
    f.rejections.recordIncomingRejection(AGENT, DOC, incoming(2));

    const restarted = new DocumentRejections(f.store, f.logger);
    expect(restarted.recordIncomingRejection(AGENT, DOC, incoming(3)).round).toBe(3);
  });

  it("a REDELIVERED rejection does not advance the round", async () => {
    const { rejections, events } = newFixture();
    expect(rejections.recordIncomingRejection(AGENT, DOC, incoming(1)).round).toBe(1);
    expect(rejections.recordIncomingRejection(AGENT, DOC, incoming(1)).round).toBe(1);
    expect(events.filter((e) => e.event === "document.rejection.received")).toHaveLength(1);
  });
});

describe("DocumentRejections — clearQuarantine only announces a real admission", () => {
  it("stays silent for a hash that was never quarantined", async () => {
    const { rejections, events } = newFixture();
    rejections.clearQuarantine(AGENT, DOC, "ff".repeat(32));
    // An event that fires on a no-op is a signal on the wrong case: an operator watching for
    // supersessions would see one that never happened.
    expect(events.filter((e) => e.event === "document.supersession.admitted")).toHaveLength(0);
  });

  it("announces once when the entry existed", async () => {
    const { rejections, events } = newFixture();
    await rejections.reject(AGENT, DOC, {
      rejectedEnvelopeHash: "ab".repeat(32),
      quarantined: new Uint8Array([1]),
      reason: "document_update_malformed",
      senderAgentId: PEER,
      ...crypto(),
    });
    rejections.clearQuarantine(AGENT, DOC, "ab".repeat(32));
    rejections.clearQuarantine(AGENT, DOC, "ab".repeat(32));
    expect(events.filter((e) => e.event === "document.supersession.admitted")).toHaveLength(1);
  });
});
