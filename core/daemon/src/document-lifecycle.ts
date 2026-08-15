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

import type { DocumentStore } from "./document-store.js";
import type { Logger } from "./types.js";

const CREATE_LIFECYCLE_SQL = `
  -- WITHDRAWALS live here, NOT in document_envelopes, and that placement is the fix for three
  -- separate defects rather than a filing preference.
  --
  -- 1. CHAIN. A withdrawal is local-only by design: it is never delivered (the update it concerns
  --    was never delivered, so the peer has nothing to act on). As an envelope it still advanced
  --    our per-sender chain, so our NEXT update chained onto a node the peer will never hold and
  --    the peer refused it with document_chain_broken — sending an operator to the chain layer for
  --    a withdrawal-scoping bug, and leaving the document unopenable after their next restart.
  --    Chaining it to the last DELIVERABLE envelope instead would fork our chain, since the next
  --    update claims the same predecessor. It cannot be a node in that chain at all.
  -- 2. CRYPTO. As an envelope it needed a signature and a state vector, and it had neither of its
  --    own — the first version copied the ORIGINAL's, putting a real Ed25519 signature made over a
  --    different record onto a permanent append-only row. document-rejection.ts states the rule
  --    this violated in writing: required, never fabricated.
  -- 3. REPLAY. An envelope row is something rebuildSnapshot must reason about; an audit row is not.
  --
  -- Same shape as document_quarantine, for the same reason: audit that must survive, must not be
  -- replayed, and must not be chained.
  CREATE TABLE IF NOT EXISTS document_withdrawals (
    owner_agent_id TEXT    NOT NULL,
    document_id    TEXT    NOT NULL,
    envelope_hash  TEXT    NOT NULL,
    created_at     INTEGER NOT NULL,
    PRIMARY KEY (owner_agent_id, document_id, envelope_hash)
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
  /** We have closed and at least one current holder has not. */
  closePending: boolean;
}

export type Verdict = { ok: true } | { ok: false; reason: string; detail: string };

export class DocumentLifecycle {
  readonly #store: DocumentStore;
  readonly #logger: Logger;
  readonly #closePendingFor: (ownerAgentId: string, documentId: string) => boolean;
  readonly #rollback: (
    ownerAgentId: string,
    documentId: string,
    envelopeHash: string,
  ) => { ok: true } | { ok: false; reason: string };

  constructor(
    store: DocumentStore,
    logger: Logger,
    /**
     * "I have closed and the derivation is still waiting on someone" — the list row's question,
     * answered from the entry set (SYNC-P4). Injected because the derivation lives on the layer;
     * this unit keeps only the platform gates and the delivery-facing surfaces.
     */
    closePendingFor: (ownerAgentId: string, documentId: string) => boolean,
    /**
     * Undo one envelope's operations on the LIVE document, as inverses. Injected because the live
     * `Y.Doc` and its UndoManager belong to the engine, not here — and REQUIRED, because a default
     * that quietly did nothing would restore exactly the defect this argument exists to fix.
     */
    rollback: (ownerAgentId: string, documentId: string, envelopeHash: string) =>
      { ok: true } | { ok: false; reason: string },
  ) {
    this.#store = store;
    this.#logger = logger;
    this.#closePendingFor = closePendingFor;
    this.#rollback = rollback;
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
      ...(() => {
        const standing = this.#store.removedFromArrangement(ownerAgentId, d.documentId);
        return standing.removed
          ? { removed: true, ...(standing.epochId === null ? {} : { removedAtEpoch: standing.epochId }) }
          : {};
      })(),
      assuranceTier: "authenticated",
      epochId: this.#store.currentDocumentEpoch(ownerAgentId, d.documentId),
      status: d.status,
      // "I have closed and the derivation is still waiting on someone" — derived from the entry
      // set, ALL current seats (SYNC-P4; the DOD-MP-CLOSE-N-1 rule, now the fold's).
      closePending: this.#closePendingFor(ownerAgentId, d.documentId),
    }));
  }

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
      // in an append-only store about an envelope that never existed.
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
      // was retracted while the peer is holding it — the promise this module refuses to make.
      return {
        ok: false,
        reason: "document_already_delivered",
        detail:
          `envelope ${envelopeHash.slice(0, 16)}… has already been delivered and acknowledged — ` +
          `your peer holds it, so it cannot be withdrawn. Publish a superseding update instead.`,
      };
    }

    // THE LOCAL ROLLBACK — the half that was missing. Writing only the record left the original in
    // the log WITH its payload, and replay applies every update payload in order, so the withdrawn
    // text stayed in the operator's own document and came back on every rebuild. The operator was
    // told their update was withdrawn while their file still contained it.
    //
    // Rolled back as INVERSES through the same undo path a rejection uses, never by dropping the
    // payload: our own later work may be causally stacked on these operations, and REJECT-1
    // measured what removing them costs — everything after stays pending forever and the document
    // silently loses the legitimate work. The inverse enters the log on the next ordinary publish,
    // computed from the live document, which is also why neither the original nor the inverse is
    // ever delivered: the peer holds neither, and the next publish carries the net effect.
    const rolledBack = this.#rollback(ownerAgentId, documentId, envelopeHash);
    if (!rolledBack.ok) {
      return {
        ok: false,
        reason: "document_withdraw_rollback_failed",
        detail:
          `the local rollback did not happen (${rolledBack.reason}), so nothing was withdrawn — ` +
          `reporting success here would tell you your update was retracted while your file still ` +
          `contains it`,
      };
    }

    const info = this.#store.rawDb
      .prepare(
        `INSERT INTO document_withdrawals (owner_agent_id, document_id, envelope_hash, created_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT (owner_agent_id, document_id, envelope_hash) DO NOTHING`,
      )
      .run(ownerAgentId, documentId, envelopeHash, nowMs);
    if (Number(info.changes) === 0) {
      // Already withdrawn. Reported rather than inferred — the earlier version ignored the write's
      // outcome and returned success for a no-op.
      return {
        ok: false,
        reason: "document_already_withdrawn",
        detail: `envelope ${envelopeHash.slice(0, 16)}… was already withdrawn`,
      };
    }

    this.#logger.info("document.withdrawn", { documentId, envelopeHash });
    return { ok: true };
  }

  // ─── the kill switch (§16.7-11) ───────────────────────────────────────────

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
    const membership = this.#store.removedFromArrangement(ownerAgentId, documentId);
    if (membership.removed) {
      return {
        ok: false,
        reason: "document_removed",
        detail:
          `you were removed from this document's arrangement at epoch ${membership.epochId} — ` +
          `your copy and its history remain yours, but new edits no longer publish to the ` +
          `other holders`,
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
