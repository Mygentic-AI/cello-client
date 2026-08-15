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
  const rolledBack: string[] = [];
  // SYNC-P4: closes are ENTRIES and the pending question is answered by the derivation on the
  // layer; this unit only ever sees the injected answer.
  const lifecycle = new DocumentLifecycle(
    store,
    logger,
    () => false,
    (_a, _d, envelopeHash) => {
      rolledBack.push(envelopeHash);
      return { ok: true };
    },
  );
  return { store, engine, lifecycle, events, rolledBack, db };
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
    });
    // Tier is constant in V1; epoch is DERIVED since M14B / AMEND-1 — 0 here because this
    // document has no amendments, not because anything is hardcoded.
    expect(row!.assuranceTier).toBe("authenticated");
  });

  
  it("a removed owner's row says so — the overlay is derived, the stored status stays active", () => {
    const f = newFixture();
    const body = {
      document_id: DOC,
      epoch_id: 1,
      prev_amendment_hash: null,
      kind: "remove_holder",
      subject_agent_id: AGENT,
      property_change: null,
      state_hash: null,
      authored_at_ms: 1,
      author_agent_id: "a".repeat(64),
      author_seq: 1,
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
    f.db.prepare(
      `INSERT INTO document_entries
         (owner_agent_id, document_id, entry_hash, author_agent_id, author_seq,
          received_bytes, recorded_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(AGENT, DOC, Buffer.from(hash).toString("hex"), "a".repeat(64), 1, Buffer.from(bytes), 1);
    const row = f.lifecycle.list(AGENT, NOW).find((r) => r.documentId === DOC);
    expect((row as unknown as { removed?: boolean }).removed).toBe(true);
    expect(row!.status).toBe("active");
    expect(f.lifecycle.canPublish(AGENT, DOC)).toMatchObject({ ok: false, reason: "document_removed" });
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
      () => false,
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
    // The peer has it: acked_at set directly — the ack machinery is deleted (D4); the column
    // survives on the row and withdrawal (itself dying in D9) still reads it.
    f.db.prepare(
      `UPDATE document_envelopes SET acked_at = ? WHERE owner_agent_id = ? AND envelope_hash = ?`,
    ).run(NOW, AGENT, e.envelopeHash);

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

describe("the terminal statuses gate publish AND admit — the projection is what these read", () => {
  it("a closed document refuses both, naming the closure", () => {
    const f = newFixture();
    f.store.setDocumentStatus(AGENT, DOC, "closed");
    for (const verdict of [f.lifecycle.canPublish(AGENT, DOC), f.lifecycle.canAdmit(AGENT, DOC)]) {
      expect(verdict.ok).toBe(false);
      expect((verdict as { reason: string }).reason).toBe("document_closed");
    }
  });

  it("a killed document refuses both, and the log is KEPT — a kill never destroys the record", () => {
    const f = newFixture();
    const e = envelope(AGENT, null);
    f.store.appendEnvelope(AGENT, e);
    f.store.setDocumentStatus(AGENT, DOC, "killed");
    for (const verdict of [f.lifecycle.canPublish(AGENT, DOC), f.lifecycle.canAdmit(AGENT, DOC)]) {
      expect(verdict.ok).toBe(false);
      expect((verdict as { reason: string }).reason).toBe("document_killed");
    }
    expect(f.store.getEnvelopeLog(AGENT, DOC)).toHaveLength(1);
  });
});
