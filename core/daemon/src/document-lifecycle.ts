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
 * ── THE KILL SWITCH (§16.7-11) ────────────────────────────────────────────────────────────────
 *
 * A platform-paused agent refuses OUTBOUND publishes loudly, still admits INBOUND mechanically,
 * and suppresses notifications. The asymmetry is deliberate. Refusing inbound would surface the
 * pause to the peer as a protocol fault and force a rejection round for something that is not
 * their doing; refusing outbound silently would leave the operator writing into a document that is
 * going nowhere, with their work piling up locally and no sign anything is wrong.
 */

import type { DocumentStore } from "./document-store.js";
import type { Logger } from "./types.js";

const CREATE_LIFECYCLE_SQL = `
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
  status: string;
  /** We have closed and at least one current holder has not. */
  closePending: boolean;
}

export type Verdict = { ok: true } | { ok: false; reason: string; detail: string };

export class DocumentLifecycle {
  readonly #store: DocumentStore;
  readonly #logger: Logger;
  readonly #closePendingFor: (ownerAgentId: string, documentId: string) => boolean;
  readonly #removedFor: (ownerAgentId: string, documentId: string) => boolean;

  constructor(
    store: DocumentStore,
    logger: Logger,
    /**
     * "I have closed and the derivation is still waiting on someone" — the list row's question,
     * answered from the entry set (SYNC-P4). Injected because the derivation lives on the layer;
     * this unit keeps only the platform gates and the delivery-facing surfaces.
     */
    closePendingFor: (ownerAgentId: string, documentId: string) => boolean,
    /** SYNC-D8 — "was this owner written out?", answered by the layer's one fold derivation. */
    removedFor: (ownerAgentId: string, documentId: string) => boolean,
  ) {
    this.#store = store;
    this.#logger = logger;
    this.#closePendingFor = closePendingFor;
    this.#removedFor = removedFor;
    this.#store.rawDb.exec(CREATE_LIFECYCLE_SQL);
  }

  list(ownerAgentId: string, nowMs: number): DocumentListRow[] {
    // SYNC-P4 (D1/D2/D4): there is no delivery ledger to count "pending" from anymore — what a
    // peer holds is computed at each exchange from positions, not tracked per envelope (R8/R9).
    void nowMs;

    return this.#store.listDocuments(ownerAgentId).map((d) => ({
      documentId: d.documentId,
      peerAgentId: d.peerAgentId,
      documentType: d.documentType,
      // DOD-MP-REMOVE-1 — display overlay, derived: a removed holder's row still says active in
      // the table (removal is a chain fact, not a stored flag), and a list that said "active"
      // would be the surface claiming more than forward-only allows.
      // DOD-MP-REMOVE-FEEDBACK-1 — the epoch travels with the flag, from the SAME walk. Deriving
      // it separately in the surface layer would be a second walk of one chain, which
      // `walkMembership`'s own header forbids: two walks disagreeing about whether someone was
      // removed is two daemons disagreeing about the arrangement.
      ...(this.#removedFor(ownerAgentId, d.documentId) ? { removed: true } : {}),
      assuranceTier: "authenticated",
      status: d.status,
      // "I have closed and the derivation is still waiting on someone" — derived from the entry
      // set, ALL current seats (SYNC-P4; the DOD-MP-CLOSE-N-1 rule, now the fold's).
      closePending: this.#closePendingFor(ownerAgentId, d.documentId),
    }));
  }

  setPlatformPaused(agentId: string, paused: boolean, nowMs: number): void {
    this.#store.rawDb
      .prepare(
        `INSERT INTO agent_platform_pause (agent_id, paused, updated_at) VALUES (?, ?, ?)
         ON CONFLICT (agent_id) DO UPDATE SET paused = excluded.paused, updated_at = excluded.updated_at`,
      )
      // Hard-wired to 0 before, so every row read 1970 — on the KILL SWITCH, where "when was this
      // agent paused by the platform" is the audit fact of the whole feature. The tell was that it
      // was the only method in the class taking no clock.
      .run(agentId, paused ? 1 : 0, nowMs);
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
    // DOD-MP-REMOVE-1, forward-only — DERIVED from the amendment chain, never a stored flag:
    // the copy is theirs (reading, the file, the history all remain), but publishing into an
    // arrangement that no longer includes them would only be refused by every holder, so it is
    // refused here first, naming the actual condition and the epoch it happened at.
    if (this.#removedFor(ownerAgentId, documentId)) {
      return {
        ok: false,
        reason: "document_removed",
        detail:
          `you were removed from this document's arrangement — your copy and its history remain ` +
          `yours, but new edits no longer publish to the other holders`,
      };
    }
    if (doc.status === "stalled") {
      // REJECT-1 stalls a document after its retry rounds. A stalled document has stopped
      // converging, so publishing into it is the same lie as publishing into a killed one — and
      // two partial gates that each know half the terminal states is how a caller ends up wrong
      // about the other half.
      return {
        ok: false,
        reason: "document_stalled",
        // NAMES BOTH CAUSES, because `stalled` has two and this text asserted one of them.
        //
        // It is set by REJECT-1 after the peer's gate refuses repeatedly, AND by the delivery
        // worker's unacked ceiling — where the peer's daemon never answered at all. Those are
        // opposite subsystems. An operator hitting the second was told to go and read rejection
        // reasons, which do not exist for it, and the shipped skill sent them to a `cello_doc_list`
        // field that does not exist either.
        detail:
          "this document stopped accepting updates. Two things set that state and they need " +
          "different actions: the peer's gate REFUSED your updates repeatedly (look for " +
          "document.rejection.received), or their daemon never CONFIRMED them at all (look for " +
          "document.delivery.unacked_limit — that one may be a local fault, not theirs)",
      };
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
    if (doc.status === "stalled") {
      return {
        ok: false,
        reason: "document_stalled",
        // NAMES BOTH CAUSES, because `stalled` has two and this text asserted one of them.
        //
        // It is set by REJECT-1 after the peer's gate refuses repeatedly, AND by the delivery
        // worker's unacked ceiling — where the peer's daemon never answered at all. Those are
        // opposite subsystems. An operator hitting the second was told to go and read rejection
        // reasons, which do not exist for it, and the shipped skill sent them to a `cello_doc_list`
        // field that does not exist either.
        detail:
          "this document stopped accepting updates. Two things set that state and they need " +
          "different actions: the peer's gate REFUSED your updates repeatedly (look for " +
          "document.rejection.received), or their daemon never CONFIRMED them at all (look for " +
          "document.delivery.unacked_limit — that one may be a local fault, not theirs)",
      };
    }
    return { ok: true };
  }

  shouldNotify(agentId: string): boolean {
    return !this.isPlatformPaused(agentId);
  }

}
