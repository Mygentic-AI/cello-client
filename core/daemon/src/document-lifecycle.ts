/**
 * DOD-DOC-LIFECYCLE-1 — the verbs (§3.5 + §16.4).
 *
 * Three ways a document can end, and they are not interchangeable. Conflating any two of them
 * makes a promise the protocol cannot keep:
 *
 *   close     BILATERAL. Both sides ack and the document is complete by agreement. One side's
 *             close is a REQUEST — treating it as a conclusion would tell this operator the
 *             collaboration ended while the peer is still writing into it.
 *   kill      UNILATERAL. Stop accepting and publishing, notify the peer, and KEEP the local copy
 *             and the log. The peer keeps what it holds, and that is said out loud: it is the one
 *             thing an operator is most likely to assume a kill undoes, and the one thing it
 *             cannot.
 *   withdraw  ONE UNDELIVERED update. A local rollback plus a withdrawal record BESIDE the
 *             original — marked, never deleted, because a hole in an append-only log is
 *             indistinguishable from tampering. Once the peer has it, withdrawal is refused rather
 *             than faked.
 *
 * ── THE KILL SWITCH (§16.7-11) ────────────────────────────────────────────────────────────────
 *
 * A platform-paused agent refuses OUTBOUND publishes loudly, still admits INBOUND mechanically,
 * and suppresses notifications. The asymmetry is deliberate. Refusing inbound would surface the
 * pause to the peer as a protocol fault and force a rejection round for something that is not
 * their doing; refusing outbound silently would leave the operator writing into a document that is
 * going nowhere, with their work piling up locally and no sign anything is wrong.
 */

import { createHash } from "node:crypto";
import type { DocumentStore } from "./document-store.js";
import type { Logger } from "./types.js";

/** How the peer is told about a unilateral end. Injected — the transport is not this unit's. */
export interface LifecycleNotifier {
  notifyPeer(
    documentId: string,
    verb: "kill" | "close",
  ): Promise<{ ok: true } | { ok: false; reason: string }>;
}

const CREATE_LIFECYCLE_SQL = `
  CREATE TABLE IF NOT EXISTS document_closes (
    owner_agent_id TEXT    NOT NULL,
    document_id    TEXT    NOT NULL,
    -- WHO closed, not how many closes there were. Counting would let one party close a document
    -- unilaterally by asking twice, which is precisely the bilateral guarantee gone.
    closed_by      TEXT    NOT NULL,
    created_at     INTEGER NOT NULL,
    PRIMARY KEY (owner_agent_id, document_id, closed_by)
  );

  CREATE TABLE IF NOT EXISTS agent_platform_pause (
    agent_id   TEXT    NOT NULL PRIMARY KEY,
    paused     INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
`;

export interface DocumentListRow {
  documentId: string;
  peerAgentId: string;
  documentType: string;
  /** Constant in V1, shown because it is seam surface — a field nobody sees cannot be noticed. */
  assuranceTier: string;
  epochId: number;
  status: string;
  pendingDeliveries: number;
  /** We have closed and the peer has not. */
  closePending: boolean;
}

export type Verdict = { ok: true } | { ok: false; reason: string; detail: string };

export class DocumentLifecycle {
  readonly #store: DocumentStore;
  readonly #logger: Logger;
  readonly #notifier: LifecycleNotifier;

  constructor(store: DocumentStore, logger: Logger, notifier: LifecycleNotifier) {
    this.#store = store;
    this.#logger = logger;
    this.#notifier = notifier;
    this.#store.rawDb.exec(CREATE_LIFECYCLE_SQL);
  }

  list(ownerAgentId: string, nowMs: number): DocumentListRow[] {
    // Every pending envelope regardless of schedule: the operator is asking "what has not reached
    // my peer", not "what is due for a retry in the next few seconds".
    const pending = this.#store.pendingDeliveries(ownerAgentId, Number.MAX_SAFE_INTEGER);
    const pendingByDocument = new Map<string, number>();
    for (const e of pending) {
      pendingByDocument.set(e.documentId, (pendingByDocument.get(e.documentId) ?? 0) + 1);
    }
    void nowMs;

    return this.#store.listDocuments(ownerAgentId).map((d) => ({
      documentId: d.documentId,
      peerAgentId: d.peerAgentId,
      documentType: d.documentType,
      assuranceTier: "authenticated",
      epochId: 0,
      status: d.status,
      pendingDeliveries: pendingByDocument.get(d.documentId) ?? 0,
      closePending:
        this.#hasClosed(ownerAgentId, d.documentId, ownerAgentId) &&
        !this.#hasClosed(ownerAgentId, d.documentId, d.peerAgentId),
    }));
  }

  /** Our half of a bilateral close. Completes only when the peer's half is also on record. */
  async close(ownerAgentId: string, documentId: string, nowMs: number): Promise<Verdict> {
    const doc = this.#store.getDocument(ownerAgentId, documentId);
    if (!doc) {
      return { ok: false, reason: "document_unknown", detail: `no document ${documentId.slice(0, 16)}…` };
    }
    this.#recordClose(ownerAgentId, documentId, ownerAgentId, nowMs);
    const notified = await this.#notifier.notifyPeer(documentId, "close");
    if (!notified.ok) {
      this.#logger.warn("document.close.peer_not_notified", { documentId, reason: notified.reason });
    }
    this.#settleClose(ownerAgentId, documentId, doc.peerAgentId);
    this.#logger.info("document.close.requested", { documentId });
    return { ok: true };
  }

  /** The peer's half, arriving over the session. */
  recordPeerClose(ownerAgentId: string, documentId: string, peerAgentId: string, nowMs: number): void {
    this.#recordClose(ownerAgentId, documentId, peerAgentId, nowMs);
    this.#settleClose(ownerAgentId, documentId, peerAgentId);
    this.#logger.info("document.close.peer_requested", { documentId, peerAgentId });
  }

  /**
   * Unilateral end. Local, and deliberately not contingent on the peer hearing about it — a
   * decision to stop that depends on the other party being online is not a decision to stop.
   */
  async kill(
    ownerAgentId: string,
    documentId: string,
    nowMs: number,
  ): Promise<
    | { ok: true; peerNotified: boolean; note: string }
    | { ok: false; reason: string; detail: string }
  > {
    const doc = this.#store.getDocument(ownerAgentId, documentId);
    if (!doc) {
      return { ok: false, reason: "document_unknown", detail: `no document ${documentId.slice(0, 16)}…` };
    }
    void nowMs;

    this.#store.setDocumentStatus(ownerAgentId, documentId, "killed");
    const notified = await this.#notifier.notifyPeer(documentId, "kill");
    if (!notified.ok) {
      // Reported, not swallowed: a kill the peer never heard about leaves them publishing into a
      // document that will never answer, and the operator is the one who needs to know that.
      this.#logger.error("document.kill.peer_not_notified", {
        documentId,
        peerAgentId: doc.peerAgentId,
        reason: notified.reason,
      });
    }
    this.#logger.info("document.killed", { documentId, peerNotified: notified.ok });

    return {
      ok: true,
      peerNotified: notified.ok,
      note:
        "this document no longer accepts or publishes updates, and your local copy and log are " +
        "retained. Your peer keeps what it holds — a kill stops the collaboration, it does not " +
        "retract content they already have.",
    };
  }

  /**
   * Withdraw ONE undelivered update: a withdrawal record beside the original.
   *
   * Every refusal here is the same shape — say no rather than produce a record that claims
   * something untrue about the log.
   */
  withdraw(
    ownerAgentId: string,
    documentId: string,
    envelopeHash: string,
    nowMs: number,
  ): Verdict {
    const log = this.#store.getEnvelopeLog(ownerAgentId, documentId);
    const original = log.find((e) => e.envelopeHash === envelopeHash);
    if (!original) {
      // A withdrawal record pointing at nothing is worse than a refusal: it is a permanent claim
      // in an append-only log about an envelope that never existed.
      return {
        ok: false,
        reason: "document_envelope_unknown",
        detail: `no envelope ${envelopeHash.slice(0, 16)}… in this document's log`,
      };
    }
    if (original.senderAgentId !== ownerAgentId) {
      return {
        ok: false,
        reason: "document_not_author",
        detail: `envelope ${envelopeHash.slice(0, 16)}… was authored by ${original.senderAgentId}, not by you`,
      };
    }
    if (original.ackedAtMs != null) {
      // The honest refusal. Withdrawing a delivered update would tell the operator their content
      // was retracted while the peer is holding it — the promise this whole module refuses to make.
      return {
        ok: false,
        reason: "document_already_delivered",
        detail:
          `envelope ${envelopeHash.slice(0, 16)}… has already been delivered and acknowledged — ` +
          `your peer holds it, so it cannot be withdrawn. Publish a superseding update instead.`,
      };
    }

    this.#store.appendEnvelope(ownerAgentId, {
      envelopeHash: withdrawalHash(envelopeHash, nowMs),
      documentId,
      senderAgentId: ownerAgentId,
      docPrevHash: this.#store.lastEnvelopeHashBySender(ownerAgentId, documentId, ownerAgentId),
      epochId: 0,
      signature: original.signature,
      stateVector: original.stateVector,
      payload: null,
      kind: "withdrawal",
      referencesEnvelopeHash: envelopeHash,
      createdAtMs: nowMs,
    });
    this.#logger.info("document.withdrawn", { documentId, envelopeHash });
    return { ok: true };
  }

  // ─── the kill switch (§16.7-11) ───────────────────────────────────────────

  setPlatformPaused(agentId: string, paused: boolean): void {
    this.#store.rawDb
      .prepare(
        `INSERT INTO agent_platform_pause (agent_id, paused, updated_at) VALUES (?, ?, ?)
         ON CONFLICT (agent_id) DO UPDATE SET paused = excluded.paused, updated_at = excluded.updated_at`,
      )
      .run(agentId, paused ? 1 : 0, 0);
    this.#logger.warn("agent.platform_pause.changed", { agentId, paused });
  }

  isPlatformPaused(agentId: string): boolean {
    const r = this.#store.rawDb
      .prepare("SELECT paused FROM agent_platform_pause WHERE agent_id = ?")
      .get(agentId) as { paused?: number } | undefined;
    return (r?.paused ?? 0) === 1;
  }

  /** Outbound. Refused loudly while paused, and while the document has ended. */
  canPublish(ownerAgentId: string, documentId: string): Verdict {
    if (this.isPlatformPaused(ownerAgentId)) {
      return {
        ok: false,
        reason: "agent_platform_paused",
        detail:
          `this agent is paused by the platform, so nothing can be published. Your work is kept ` +
          `locally and will publish once the agent is unpaused.`,
      };
    }
    const doc = this.#store.getDocument(ownerAgentId, documentId);
    if (!doc) {
      return { ok: false, reason: "document_unknown", detail: `no document ${documentId.slice(0, 16)}…` };
    }
    if (doc.status === "closed") {
      return { ok: false, reason: "document_closed", detail: "this document was closed by agreement" };
    }
    if (doc.status === "killed") {
      return { ok: false, reason: "document_killed", detail: "this document was ended locally" };
    }
    return { ok: true };
  }

  /** Inbound. A pause does NOT refuse it — see the header. */
  canAdmit(ownerAgentId: string, documentId: string): Verdict {
    const doc = this.#store.getDocument(ownerAgentId, documentId);
    if (!doc) {
      return { ok: false, reason: "document_unknown", detail: `no document ${documentId.slice(0, 16)}…` };
    }
    if (doc.status === "killed") {
      return { ok: false, reason: "document_killed", detail: "this document was ended locally" };
    }
    if (doc.status === "closed") {
      return { ok: false, reason: "document_closed", detail: "this document was closed by agreement" };
    }
    return { ok: true };
  }

  shouldNotify(agentId: string): boolean {
    return !this.isPlatformPaused(agentId);
  }

  // ─── internals ────────────────────────────────────────────────────────────

  #recordClose(ownerAgentId: string, documentId: string, closedBy: string, nowMs: number): void {
    this.#store.rawDb
      .prepare(
        `INSERT INTO document_closes (owner_agent_id, document_id, closed_by, created_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT (owner_agent_id, document_id, closed_by) DO NOTHING`,
      )
      .run(ownerAgentId, documentId, closedBy, nowMs);
  }

  #hasClosed(ownerAgentId: string, documentId: string, who: string): boolean {
    const r = this.#store.rawDb
      .prepare(
        `SELECT 1 AS present FROM document_closes
          WHERE owner_agent_id = ? AND document_id = ? AND closed_by = ?`,
      )
      .get(ownerAgentId, documentId, who) as { present?: number } | undefined;
    return r?.present === 1;
  }

  #settleClose(ownerAgentId: string, documentId: string, peerAgentId: string): void {
    if (
      this.#hasClosed(ownerAgentId, documentId, ownerAgentId) &&
      this.#hasClosed(ownerAgentId, documentId, peerAgentId)
    ) {
      this.#store.setDocumentStatus(ownerAgentId, documentId, "closed");
      this.#logger.info("document.closed", { documentId });
    }
  }
}

function withdrawalHash(envelopeHash: string, nowMs: number): string {
  return createHash("sha256").update(`withdrawal:${envelopeHash}:${nowMs}`).digest("hex");
}
