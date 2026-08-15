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

export type Verdict = { ok: true } | { ok: false; reason: string; detail: string };

export class DocumentLifecycle {
  readonly #store: DocumentStore;
  readonly #logger: Logger;
  readonly #removedFor: (ownerAgentId: string, documentId: string) => boolean;
  readonly #endedFor: (
    ownerAgentId: string,
    documentId: string,
  ) => { derived: boolean; ended: "closed" | "killed" | null };

  constructor(
    store: DocumentStore,
    logger: Logger,
    /** SYNC-D8 — "was this owner written out?", answered by the layer's one fold derivation. */
    removedFor: (ownerAgentId: string, documentId: string) => boolean,
    /**
     * SYNC-P4 review F2 — "is this document ended?", answered by the fold, never the status
     * column. `derived: false` means the chain does not derive (legacy bilateral, undecodable
     * bytes); ONLY there does the stored column stand in, because for a pre-pivot document the
     * column IS the record of its ending.
     */
    endedFor: (
      ownerAgentId: string,
      documentId: string,
    ) => { derived: boolean; ended: "closed" | "killed" | null },
  ) {
    this.#store = store;
    this.#logger = logger;
    this.#removedFor = removedFor;
    this.#endedFor = endedFor;
    this.#store.rawDb.exec(CREATE_LIFECYCLE_SQL);
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
    // THE FOLD RULES ENDINGS (review F2): the status column is a display projection that can lag
    // the derivation (a concurrently-arriving admission re-opens a closure). Only a document whose
    // chain does not derive — the pre-pivot bilateral record — is judged by its column.
    const ending = this.#endedFor(ownerAgentId, documentId);
    const ended = ending.derived
      ? ending.ended
      : doc.status === "closed" || doc.status === "killed"
        ? (doc.status as "closed" | "killed")
        : null;
    if (ended === "closed") {
      return { ok: false, reason: "document_closed", detail: "this document was closed by agreement" };
    }
    if (ended === "killed") {
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


  shouldNotify(agentId: string): boolean {
    return !this.isPlatformPaused(agentId);
  }

}
