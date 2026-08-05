/**
 * DOD-DOC-REJECT-1 — rejection and supersession (§3.2, §16.7-2).
 *
 * ── WHY SUPERSESSION, AND NOT "BOTH SIDES ROLL BACK" ──────────────────────────────────────────
 *
 * The naive protocol is: the receiver discards, the sender undoes locally, and both return to the
 * pre-update state. It does not work, and the reason is a property of CRDTs rather than a bug.
 *
 * **Yjs undo adds INVERSES; it does not erase.** The rejected operations stay in the sender's
 * document. So every later update the sender computes against the receiver's state vector
 * re-transmits them, and the receiver — which refuses to hold them — can never integrate the
 * legitimate work stacked causally on top, because Yjs will not apply operations whose
 * predecessors are missing. A permanent causal gap, from a protocol that looked symmetric.
 *
 * The protocol that works (§3.2):
 *   1. The receiver rejects with a REASON — a protocol message and its own `0x05` leaf, never a
 *      silent drop. The update goes to quarantine, held rather than discarded.
 *   2. The sender rolls back locally, which emits inverses into its own log and leaves an
 *      auditable "wrote X, was rejected, undid X" trail.
 *   3. The sender publishes a SUPERSEDING update against the receiver's state vector, which
 *      necessarily carries the rejected operations PLUS their inverses plus any new work.
 *   4. The receiver validates the now-clean projected diff — the rejected content nets to zero —
 *      admits it, and clears the quarantine. Causality intact, both parties converge, and the
 *      rejected content survives only as inert tombstones.
 *
 * ── SCOPE ─────────────────────────────────────────────────────────────────────────────────────
 *
 * This proves the protocol against STORE-1's local envelope log. The CBOR wire encoding is
 * DOD-DOC-ENVELOPE-1's job and the cross-daemon proof is DOD-DOC-E2E-REJECT-1's.
 */

import { createHash } from "node:crypto";
import * as Y from "yjs";
import type { DocumentStore } from "./document-store.js";
import type { Logger } from "./types.js";

/**
 * One more round after the first rejection, then the document stalls (§16.7-2).
 *
 * Bounded because an unbounded retry loop between two daemons that disagree is not convergence,
 * it is a hot loop neither operator can see. Stalling is the visible failure.
 */
export const REJECTION_RETRY_LIMIT = 1;

export interface RejectionInput {
  /** The envelope being rejected — the `0x05` leaf references this hash (§9). */
  rejectedEnvelopeHash: string;
  /** The bytes, held rather than discarded (§3.2). Supplied by the gate's quarantine verdict. */
  quarantined: Uint8Array;
  reason: string;
  detail?: string;
  senderAgentId: string;
}

export interface RejectionOutcome {
  /** The document has exhausted its retries and stopped accepting updates. */
  stalled: boolean;
  /** How many rejections this document has seen, including this one. */
  round: number;
}

export interface QuarantineEntry {
  rejectedEnvelopeHash: string;
  quarantined: Uint8Array;
  reason: string;
  detail?: string;
}

/** A handle over the sender's local edits, so a rejection can be rolled back as inverses. */
export interface TrackedEdits {
  readonly doc: Y.Doc;
  readonly undoManager: Y.UndoManager;
}

export class DocumentRejections {
  readonly #store: DocumentStore;
  readonly #logger: Logger;
  /** (agent, document) → quarantined entries, keyed by the rejected envelope hash. */
  readonly #quarantine = new Map<string, Map<string, QuarantineEntry>>();
  /** (agent, document) → rejection rounds so far. */
  readonly #rounds = new Map<string, number>();
  /** (agent, document) → the reason it stalled, for both operators to see. */
  readonly #stalledReason = new Map<string, string>();

  constructor(store: DocumentStore, logger: Logger) {
    this.#store = store;
    this.#logger = logger;
  }

  /**
   * Record a rejection: a `0x05` row referencing the rejected envelope, the quarantined bytes
   * held, and a policy record carrying the reason.
   *
   * The envelope log is append-only, so this is a NEW ROW — the rejected envelope is never edited
   * or removed. §9 makes the record self-describing for replay: an update leaf is effective iff
   * no rejection leaf references it.
   */
  reject(agentId: string, documentId: string, input: RejectionInput): RejectionOutcome {
    const key = this.#key(agentId, documentId);

    this.#store.appendEnvelope(agentId, {
      envelopeHash: rejectionHash(input.rejectedEnvelopeHash, input.reason),
      documentId,
      senderAgentId: agentId, // WE authored the rejection, whoever authored the update
      docPrevHash: null,
      epochId: 0,
      signature: new Uint8Array(64),
      stateVector: new Uint8Array([0, 0]),
      payload: null, // an audit record carries no content
      kind: "rejection",
      referencesEnvelopeHash: input.rejectedEnvelopeHash,
      createdAtMs: Date.now(),
    });

    const held = this.#quarantine.get(key) ?? new Map<string, QuarantineEntry>();
    held.set(input.rejectedEnvelopeHash, {
      rejectedEnvelopeHash: input.rejectedEnvelopeHash,
      // COPY: the caller's buffer may be a pooled network read, and a 0x05 leaf must reference
      // the bytes that were actually refused.
      quarantined: new Uint8Array(input.quarantined),
      reason: input.reason,
      detail: input.detail,
    });
    this.#quarantine.set(key, held);

    const round = (this.#rounds.get(key) ?? 0) + 1;
    this.#rounds.set(key, round);

    // The policy record — on BOTH sides, per §3.2. This is the sending half; the receiving half
    // is written when a rejection arrives.
    this.#logger.warn("document.rejection.sent", {
      documentId,
      senderAgentId: input.senderAgentId,
      reason: input.reason,
      detail: input.detail,
      round,
    });

    // One retry, then stalled: the original rejection, one superseding attempt, and no more.
    const stalled = round > REJECTION_RETRY_LIMIT + 1;
    if (stalled && !this.#stalledReason.has(key)) {
      this.#stalledReason.set(key, input.reason);
      this.#store.setDocumentStatus(agentId, documentId, "stalled");
      // Once, not on every subsequent refusal — a stalled document that keeps shouting is noise
      // an operator learns to filter.
      this.#logger.error("document.stalled", {
        documentId,
        reason: input.reason,
        detail: input.detail,
        rounds: round,
      });
    }
    return { stalled, round };
  }

  /** Entries held for this document — never admitted, never discarded (§3.2). */
  quarantined(agentId: string, documentId: string): QuarantineEntry[] {
    return [...(this.#quarantine.get(this.#key(agentId, documentId))?.values() ?? [])];
  }

  /** Clear one entry once its superseding update has been admitted (§3.2 step 4). */
  clearQuarantine(agentId: string, documentId: string, rejectedEnvelopeHash: string): void {
    const key = this.#key(agentId, documentId);
    this.#quarantine.get(key)?.delete(rejectedEnvelopeHash);
    this.#logger.info("document.supersession.admitted", { documentId, rejectedEnvelopeHash });
  }

  /**
   * Whether this document still accepts updates.
   *
   * A stalled document REFUSES, naming the reason it stalled — both operators need to see why,
   * because a document that silently stops converging is the failure this exists to prevent.
   */
  acceptsUpdates(
    agentId: string,
    documentId: string,
  ): { ok: true } | { ok: false; reason: string; detail: string } {
    const stalledReason = this.#stalledReason.get(this.#key(agentId, documentId));
    if (stalledReason !== undefined) {
      return {
        ok: false,
        reason: "document_stalled",
        detail: `this document stopped accepting updates after ${REJECTION_RETRY_LIMIT + 1} ` +
          `rejected rounds; the last reason was ${stalledReason}`,
      };
    }
    return { ok: true };
  }

  /**
   * Start tracking local edits so a rejection can be rolled back.
   *
   * Yjs's own UndoManager, deliberately: rolling back by hand would mean computing inverses, and
   * the inverse of a CRDT operation is not something to hand-roll — the whole reason supersession
   * works is that Yjs's undo produces operations that compose correctly with everything stacked
   * on top of them.
   */
  trackLocalEdits(doc: Y.Doc): TrackedEdits {
    return {
      doc,
      undoManager: new Y.UndoManager([doc.getText("content"), doc.getMap("data")], {
        captureTimeout: 0,
      }),
    };
  }

  /**
   * Roll back the last tracked edit, as INVERSES.
   *
   * The sender's history grows rather than shrinking. That is not a limitation to work around: it
   * is what leaves an auditable "wrote X, was rejected, undid X" trail, and what lets the
   * superseding update carry the rejected operations plus their inverses so causality survives.
   *
   * **PRECONDITION: roll back before making further local edits.** Yjs's UndoManager undoes the
   * most recent stack item, and it cannot undo one out of order — so a sender that keeps editing
   * after a rejection arrives and then rolls back would undo the WRONG transaction. §3.2's
   * ordering is steps 2 then 3 for exactly this reason: roll back, THEN do new work, THEN
   * publish the supersession that carries all three. A caller that needs to interleave has a
   * genuine design question, not a call-order detail, and it belongs in the unit that wires
   * publish to the receive path.
   */
  rollback(tracked: TrackedEdits): void {
    tracked.undoManager.undo();
  }

  #key(agentId: string, documentId: string): string {
    return `${agentId}:${documentId}`;
  }
}

/** A rejection's own envelope hash — distinct per rejected envelope and reason. */
function rejectionHash(rejectedEnvelopeHash: string, reason: string): string {
  return createHash("sha256").update(`rejection:${rejectedEnvelopeHash}:${reason}`, "utf8").digest("hex");
}
