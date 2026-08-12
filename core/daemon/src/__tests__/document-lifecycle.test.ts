/**
 * DOD-DOC-LIFECYCLE-1 — the verbs (§3.5 + §16.4): list, close, kill, withdraw.
 *
 * The three ending verbs are deliberately different, and conflating any two of them is the failure
 * this unit exists to prevent:
 *
 *   close     BILATERAL. Both sides ack; the document is complete by agreement.
 *   kill      UNILATERAL. Stop accepting and publishing, notify the peer, and KEEP the local copy
 *             and the log. The peer keeps what it holds — stated plainly, because a "kill" that an
 *             operator believes retracts their content is a promise the protocol cannot make.
 *   withdraw  ONE UNDELIVERED UPDATE. A local rollback plus a withdrawal record BESIDE the
 *             original envelope — marked, never deleted.
 *
 * `node:sqlite` here is the test-file allowance; production is SQLCipher.
 */

import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import * as Y from "yjs";
import {
  documentAmendmentHash,
  encodeDocumentAmendment,
} from "@cello-protocol/protocol-types";
import { DocumentStore, type DocumentEnvelopeRow } from "../document-store.js";
import { DocumentEngine } from "../document-engine.js";
import { DocumentLifecycle } from "../document-lifecycle.js";
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
function envelope(sender: string, prev: string | null, payload: Uint8Array | null = null): DocumentEnvelopeRow {
  seq += 1;
  return {
    envelopeHash: createHash("sha256").update(`life${seq}`).digest("hex"),
    documentId: DOC,
    senderAgentId: sender,
    docPrevHash: prev,
    epochId: 0,
    signature: new Uint8Array(64),
    stateVector: new Uint8Array([0]),
    payload: payload ?? update("some text. "),
    kind: "update",
    createdAtMs: NOW + seq,
  };
}

/** A real Yjs update. clientID pinned per the project rule. */
let clientSeq = 1000;
function update(text: string): Uint8Array {
  clientSeq += 1;
  const d = new Y.Doc();
  d.clientID = clientSeq;
  d.getText("content").insert(0, text);
  return Y.encodeStateAsUpdate(d);
}

function newFixture() {
  const { logger, events } = recordingLogger();
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  const store = new DocumentStore(db, logger);
  store.createDocument({
    documentId: DOC, ownerAgentId: AGENT, peerAgentId: PEER, documentType: "markdown",
    properties: { append_only: false }, status: "active", createdAtMs: 1,
  });
  const engine = new DocumentEngine(logger);
  const notified: Array<{ documentId: string; verb: string }> = [];
  const rolledBack: string[] = [];
  const lifecycle = new DocumentLifecycle(
    store,
    logger,
    {
      notifyPeer: async (documentId, verb) => {
        notified.push({ documentId, verb });
        return { ok: true };
      },
    },
    (_a, _d, envelopeHash) => {
      rolledBack.push(envelopeHash);
      return { ok: true };
    },
  );
  return { store, engine, lifecycle, events, notified, rolledBack, db };
}

describe("DocumentLifecycle — list", () => {
  it("shows the peer, type, tier, epoch, status and the pending-delivery state", () => {
    const f = newFixture();
    f.store.appendEnvelope(AGENT, envelope(AGENT, null));

    const [row] = f.lifecycle.list(AGENT, NOW);
    expect(row).toMatchObject({
      documentId: DOC,
      peerAgentId: PEER,
      documentType: "markdown",
      status: "active",
      pendingDeliveries: 1,
    });
    // Tier is constant in V1; epoch is DERIVED since M14B / AMEND-1 — 0 here because this
    // document has no amendments, not because anything is hardcoded.
    expect(row!.assuranceTier).toBe("authenticated");
    expect(row!.epochId).toBe(0);
  });

  it("reports the CURRENT epoch once the document has amendments — not a constant", () => {
    // A DECODABLE row — the list's removal overlay and the membership walk decode every stored
    // amendment, and a garbage blob is a state no real daemon can hold (validate-before-append).
    const f = newFixture();
    const body = {
      document_id: DOC,
      epoch_id: 2,
      prev_amendment_hash: null,
      kind: "add_holder",
      subject_agent_id: "f".repeat(64),
      property_change: null,
      state_hash: null,
      authored_at_ms: 1,
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
    f.db.prepare(
      `INSERT INTO document_amendments
         (owner_agent_id, document_id, epoch_id, amendment_hash, received_bytes, recorded_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(AGENT, DOC, 2, Buffer.from(hash).toString("hex"), Buffer.from(bytes), 1);
    const row = f.lifecycle.list(AGENT, NOW).find((r) => r.documentId === DOC);
    expect(row!.epochId).toBe(2);
  });

  it("counts only what is actually pending, not the whole log", () => {
    const f = newFixture();
    const a = envelope(AGENT, null);
    f.store.appendEnvelope(AGENT, a);
    f.store.appendEnvelope(AGENT, envelope(PEER, null));
    f.store.markAcked(AGENT, DOC, a.envelopeHash, NOW);

    // The peer's envelope is not ours to deliver, and ours was acked. "1 update pending" when
    // nothing is pending is the kind of number an operator stops trusting.
    expect(f.lifecycle.list(AGENT, NOW)[0]!.pendingDeliveries).toBe(0);
  });
});

describe("DocumentLifecycle — close is BILATERAL", () => {
  it("stays open until BOTH sides have closed", async () => {
    const f = newFixture();
    await f.lifecycle.close(AGENT, DOC, NOW);

    // One side's close is a request, not a conclusion. Marking it closed here would tell this
    // operator the collaboration ended while the peer is still writing into it.
    expect(f.store.getDocument(AGENT, DOC)!.status).toBe("active");
    expect(f.lifecycle.list(AGENT, NOW)[0]!.closePending).toBe(true);
  });

  it("closes once the peer's close arrives too", async () => {
    const f = newFixture();
    await f.lifecycle.close(AGENT, DOC, NOW);
    expect(f.lifecycle.recordPeerClose(AGENT, DOC, PEER, NOW + 1).ok).toBe(true);

    expect(f.store.getDocument(AGENT, DOC)!.status).toBe("closed");
  });

  it("closes when the PEER asks first and we then agree", async () => {
    const f = newFixture();
    f.lifecycle.recordPeerClose(AGENT, DOC, PEER, NOW);
    expect(f.store.getDocument(AGENT, DOC)!.status).toBe("active");

    await f.lifecycle.close(AGENT, DOC, NOW + 1);
    expect(f.store.getDocument(AGENT, DOC)!.status).toBe("closed");
  });

  it("a repeated close from one side does not stand in for the other's", async () => {
    const f = newFixture();
    await f.lifecycle.close(AGENT, DOC, NOW);
    await f.lifecycle.close(AGENT, DOC, NOW + 1);
    // Counting closes rather than distinguishing WHO closed would let one party close a document
    // unilaterally by asking twice.
    expect(f.store.getDocument(AGENT, DOC)!.status).toBe("active");
  });

  it("refuses publishing into a closed document, saying so", async () => {
    const f = newFixture();
    await f.lifecycle.close(AGENT, DOC, NOW);
    f.lifecycle.recordPeerClose(AGENT, DOC, PEER, NOW + 1);

    const verdict = f.lifecycle.canPublish(AGENT, DOC);
    expect(verdict.ok).toBe(false);
    expect((verdict as { reason: string }).reason).toBe("document_closed");
  });
});

describe("DocumentLifecycle — kill is UNILATERAL, and honest about what it cannot do", () => {
  it("stops accepting and publishing, notifies the peer, and KEEPS the local copy and log", async () => {
    const f = newFixture();
    const e = envelope(AGENT, null);
    f.store.appendEnvelope(AGENT, e);

    const res = await f.lifecycle.kill(AGENT, DOC, NOW);
    expect(res.ok).toBe(true);
    expect(f.store.getDocument(AGENT, DOC)!.status).toBe("killed");
    expect(f.lifecycle.canPublish(AGENT, DOC).ok).toBe(false);
    expect(f.lifecycle.canAdmit(AGENT, DOC).ok).toBe(false);
    // Retained, not deleted. The log is the evidence of what was exchanged, and a kill that
    // destroys it destroys the operator's own record along with it.
    expect(f.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(1);
    expect(f.notified).toEqual([{ documentId: DOC, verb: "kill" }]);
  });

  it("states plainly that the peer keeps what it holds", async () => {
    const f = newFixture();
    const res = await f.lifecycle.kill(AGENT, DOC, NOW);
    // The one thing an operator is most likely to assume a kill does is the one thing it cannot
    // do. Leaving that unsaid is a promise the protocol does not keep.
    expect((res as { note: string }).note).toContain("keeps what it holds");
  });

  it("still kills when the peer cannot be notified — the local decision does not depend on them", async () => {
    const { logger, events } = recordingLogger();
    const db = new DatabaseSync(":memory:");
    const store = new DocumentStore(db, logger);
    store.createDocument({
      documentId: DOC, ownerAgentId: AGENT, peerAgentId: PEER, documentType: "markdown",
      properties: {}, status: "active", createdAtMs: 1,
    });
    const lifecycle = new DocumentLifecycle(
      store,
      logger,
      { notifyPeer: async () => ({ ok: false, reason: "peer_offline" }) },
      () => ({ ok: true }),
    );

    const res = await lifecycle.kill(AGENT, DOC, NOW);
    expect(res.ok).toBe(true);
    expect(store.getDocument(AGENT, DOC)!.status).toBe("killed");
    // But it is REPORTED — a kill the peer never heard about leaves them publishing into a
    // document that will never answer, and the operator should know that happened.
    expect((res as { peerNotified: boolean }).peerNotified).toBe(false);
    expect(events.some((e) => e.event === "document.kill.peer_not_notified")).toBe(true);
  });
});

describe("DocumentLifecycle — withdraw touches ONE UNDELIVERED update", () => {
  it("writes a withdrawal record BESIDE the original, which is marked and never deleted", () => {
    const f = newFixture();
    const e = envelope(AGENT, null);
    f.store.appendEnvelope(AGENT, e);

    const res = f.lifecycle.withdraw(AGENT, DOC, e.envelopeHash, NOW);
    expect(res.ok).toBe(true);

    const log = f.store.getEnvelopeLog(AGENT, DOC);
    // The original is still there with its payload. "Marked, never deleted" is what keeps the log
    // verifiable — a hole in an append-only log is indistinguishable from tampering.
    expect(log.find((r) => r.envelopeHash === e.envelopeHash)!.payload).not.toBeNull();
    // And the record is NOT an envelope. As one it advanced our per-sender chain over a node the
    // peer will never hold — a withdrawal is never delivered — so our next update chained onto
    // something they had never seen and they refused it as document_chain_broken, sending an
    // operator to the chain layer for a withdrawal-scoping bug.
    expect(log.filter((r) => r.kind === "withdrawal")).toHaveLength(0);
    expect(f.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(1);
  });

  it("ROLLS BACK locally — the operator's own document no longer contains it", () => {
    const f = newFixture();
    const e = envelope(AGENT, null);
    f.store.appendEnvelope(AGENT, e);

    expect(f.lifecycle.withdraw(AGENT, DOC, e.envelopeHash, NOW).ok).toBe(true);
    // The clause is "local rollback + a withdrawal record". Only the record shipped, so the
    // operator was told their update was withdrawn while their own file still contained it —
    // replay applies every update payload in order, so it came back on every rebuild forever.
    expect(f.rolledBack).toEqual([e.envelopeHash]);
  });

  it("REFUSES rather than reporting success when the rollback did not happen", () => {
    const { logger } = recordingLogger();
    const db = new DatabaseSync(":memory:");
    db.exec("PRAGMA foreign_keys = ON");
    const store = new DocumentStore(db, logger);
    store.createDocument({
      documentId: DOC, ownerAgentId: AGENT, peerAgentId: PEER, documentType: "markdown",
      properties: {}, status: "active", createdAtMs: 1,
    });
    const lifecycle = new DocumentLifecycle(
      store, logger,
      { notifyPeer: async () => ({ ok: true }) },
      () => ({ ok: false, reason: "nothing_tracked" }),
    );
    const e = envelope(AGENT, null);
    store.appendEnvelope(AGENT, e);

    const res = lifecycle.withdraw(AGENT, DOC, e.envelopeHash, NOW);
    expect(res.ok).toBe(false);
    expect((res as { reason: string }).reason).toBe("document_withdraw_rollback_failed");
  });

  it("refuses a SECOND withdrawal of the same envelope instead of reporting success", () => {
    const f = newFixture();
    const e = envelope(AGENT, null);
    f.store.appendEnvelope(AGENT, e);
    expect(f.lifecycle.withdraw(AGENT, DOC, e.envelopeHash, NOW).ok).toBe(true);
    const second = f.lifecycle.withdraw(AGENT, DOC, e.envelopeHash, NOW);
    expect(second.ok).toBe(false);
    expect((second as { reason: string }).reason).toBe("document_already_withdrawn");
  });

  it("REFUSES to withdraw an update the peer already has", () => {
    const f = newFixture();
    const e = envelope(AGENT, null);
    f.store.appendEnvelope(AGENT, e);
    f.store.markAcked(AGENT, DOC, e.envelopeHash, NOW);

    const res = f.lifecycle.withdraw(AGENT, DOC, e.envelopeHash, NOW);
    // Withdrawing a delivered update would tell the operator their content was retracted when the
    // peer is holding it. That is the promise a protocol cannot make, and saying so is the feature.
    expect(res.ok).toBe(false);
    expect((res as { reason: string }).reason).toBe("document_already_delivered");
  });

  it("refuses to withdraw someone else's envelope", () => {
    const f = newFixture();
    const e = envelope(PEER, null);
    f.store.appendEnvelope(AGENT, e);
    const res = f.lifecycle.withdraw(AGENT, DOC, e.envelopeHash, NOW);
    expect(res.ok).toBe(false);
    expect((res as { reason: string }).reason).toBe("document_not_author");
  });

  it("refuses to withdraw an envelope that is not there, rather than writing a dangling record", () => {
    const f = newFixture();
    const res = f.lifecycle.withdraw(AGENT, DOC, "ff".repeat(32), NOW);
    expect(res.ok).toBe(false);
    expect((res as { reason: string }).reason).toBe("document_envelope_unknown");
  });

  it("the withdrawn update no longer counts as pending delivery", () => {
    const f = newFixture();
    const e = envelope(AGENT, null);
    f.store.appendEnvelope(AGENT, e);
    f.lifecycle.withdraw(AGENT, DOC, e.envelopeHash, NOW);
    // Otherwise the delivery worker ships the very update that was just withdrawn.
    expect(f.store.pendingDeliveries(AGENT, NOW + 1_000_000)).toHaveLength(0);
  });
});

describe("DocumentLifecycle — the kill switch (§16.7-11)", () => {
  it("a paused agent refuses outbound publishes LOUDLY", () => {
    const f = newFixture();
    f.lifecycle.setPlatformPaused(AGENT, true, NOW);

    const verdict = f.lifecycle.canPublish(AGENT, DOC);
    expect(verdict.ok).toBe(false);
    expect((verdict as { reason: string }).reason).toBe("agent_platform_paused");
    // Loudly: a silent no-op would leave the operator writing into a document that is going
    // nowhere, with their work accumulating locally and no sign anything is wrong.
    expect((verdict as { detail: string }).detail).toMatch(/paused/);
  });

  it("a paused agent STILL admits incoming updates, mechanically", () => {
    const f = newFixture();
    f.lifecycle.setPlatformPaused(AGENT, true, NOW);
    // Refusing inbound would make the pause visible to the peer as a protocol fault and would
    // force a rejection round for something that is not the peer's doing.
    expect(f.lifecycle.canAdmit(AGENT, DOC).ok).toBe(true);
  });

  it("a paused agent suppresses notifications", () => {
    const f = newFixture();
    f.lifecycle.setPlatformPaused(AGENT, true, NOW);
    expect(f.lifecycle.shouldNotify(AGENT)).toBe(false);
  });

  it("unpausing resumes all three", () => {
    const f = newFixture();
    f.lifecycle.setPlatformPaused(AGENT, true, NOW);
    f.lifecycle.setPlatformPaused(AGENT, false, NOW + 1);

    expect(f.lifecycle.canPublish(AGENT, DOC).ok).toBe(true);
    expect(f.lifecycle.canAdmit(AGENT, DOC).ok).toBe(true);
    expect(f.lifecycle.shouldNotify(AGENT)).toBe(true);
  });

  it("the pause is per-agent, not global", () => {
    const f = newFixture();
    f.lifecycle.setPlatformPaused(AGENT, true, NOW);
    // A daemon can attend several agents; pausing one because another was paused would take a
    // platform action against an agent it was never aimed at.
    expect(f.lifecycle.shouldNotify("another-agent")).toBe(true);
  });
});


describe("DocumentLifecycle — a close only counts from the document's ACTUAL peer", () => {
  it("refuses a close from anyone else, and the document stays open", async () => {
    const f = newFixture();
    await f.lifecycle.close(AGENT, DOC, NOW);

    const res = f.lifecycle.recordPeerClose(AGENT, DOC, "someone-else", NOW + 1);
    expect(res.ok).toBe(false);
    expect((res as { reason: string }).reason).toBe("document_close_not_peer");
    // The closer id was written as `closed_by` and settled against ITSELF, so any second distinct
    // string plus our own close flipped the document closed — the bilateral guarantee the whole
    // table exists to protect, bypassed by passing a different string twice.
    expect(f.store.getDocument(AGENT, DOC)!.status).toBe("active");
  });

  it("refuses a close for a document that does not exist", () => {
    const f = newFixture();
    const res = f.lifecycle.recordPeerClose(AGENT, "ff".repeat(32), PEER, NOW);
    expect(res.ok).toBe(false);
    // There is no foreign key on this table, and setDocumentStatus on a missing row updates zero
    // rows and returns silently — so an unchecked write leaves an orphan and no signal.
    expect((res as { reason: string }).reason).toBe("document_unknown");
  });
});

describe("DocumentLifecycle — a close does not overwrite an ending the operator chose", () => {
  it("a peer close arriving after a KILL leaves the document killed", async () => {
    const f = newFixture();
    await f.lifecycle.close(AGENT, DOC, NOW);
    await f.lifecycle.kill(AGENT, DOC, NOW + 1);
    f.lifecycle.recordPeerClose(AGENT, DOC, PEER, NOW + 2);

    // "Closed by agreement" is a different fact from "I ended this", and it is the one the
    // operator did not choose.
    expect(f.store.getDocument(AGENT, DOC)!.status).toBe("killed");
  });
});

describe("DocumentLifecycle — a STALLED document is terminal too", () => {
  it("refuses publish and admit, naming the stall", () => {
    const f = newFixture();
    f.store.setDocumentStatus(AGENT, DOC, "stalled");

    for (const verdict of [f.lifecycle.canPublish(AGENT, DOC), f.lifecycle.canAdmit(AGENT, DOC)]) {
      expect(verdict.ok).toBe(false);
      // REJECT-1 stalls a document after its retry rounds. Two partial gates that each know half
      // the terminal states is how a caller ends up wrong about the other half.
      expect((verdict as { reason: string }).reason).toBe("document_stalled");
    }
  });
});

describe("DocumentLifecycle — the pause records WHEN", () => {
  it("writes the timestamp it was given, not 1970", () => {
    const f = newFixture();
    f.lifecycle.setPlatformPaused(AGENT, true, NOW);
    const row = f.db
      .prepare("SELECT updated_at FROM agent_platform_pause WHERE agent_id = ?")
      .get(AGENT) as { updated_at: number };
    // On the kill switch, "when was this agent paused by the platform" is the audit fact of the
    // whole feature.
    expect(row.updated_at).toBe(NOW);
  });
});
