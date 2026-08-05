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
  /** Which pluggable rule refused, when one did (from the gate's verdict). */
  rule?: string;
  /** The limit breached, when one was (from the gate's verdict). */
  limit?: { name: string; limit: number; actual: number };
  /**
   * The rejection's own signature and state vector.
   *
   * REQUIRED rather than fabricated. An all-zero placeholder written into an immutable log is
   * indistinguishable from a real signature that fails to verify, so a later verifier would send
   * an operator to the crypto layer for a value nobody ever signed. Producing these is
   * DOD-DOC-ENVELOPE-1's job; this unit refuses to invent them.
   */
  signature: Uint8Array;
  stateVector: Uint8Array;
  /** Distinguishes repeat rejections of the same envelope for the same reason. */
  nonce: string;
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
  /** Stack depth when tracking began, so `rollback` can prove it is undoing the right item. */
  readonly depthAtTracking: number;
}

export class DocumentRejections {
  readonly #store: DocumentStore;
  readonly #logger: Logger;

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

    // CHAIN IT. Writing `docPrevHash: null` made every rejection a second GENESIS row for this
    // agent, so two rejections forked the chain — and the retry protocol guarantees at least two
    // before a stall. `verifyChainLinkage` then refuses, and since `rebuildSnapshot` is how a
    // document survives a restart, the document rebuilt until the next daemon start and was
    // permanently unopenable after it. Measured. A rejection is this agent's own authored act, so
    // it belongs in this agent's own chain.
    const appended = this.#store.appendEnvelope(agentId, {
      envelopeHash: rejectionHash(input.rejectedEnvelopeHash, input.reason, input.nonce),
      documentId,
      senderAgentId: agentId, // WE authored the rejection, whoever authored the update
      docPrevHash: this.#store.lastEnvelopeHashBySender(agentId, documentId, agentId),
      epochId: 0,
      signature: input.signature,
      stateVector: input.stateVector,
      payload: null, // an audit record carries no content
      kind: "rejection",
      referencesEnvelopeHash: input.rejectedEnvelopeHash,
      createdAtMs: Date.now(),
    });
    if (!appended) {
      // The store tells callers whether a row was written precisely so this is not inferred. A
      // duplicate must not advance the retry round, or a document reaches `stalled` with fewer
      // rejection leaves than rounds and an auditor replaying the log cannot see why.
      this.#logger.warn("document.rejection.duplicate", {
        documentId,
        rejectedEnvelopeHash: input.rejectedEnvelopeHash,
        reason: input.reason,
      });
      return { stalled: this.#isStalled(agentId, documentId), round: this.#round(agentId, documentId) };
    }

    // PERSISTED, not remembered. The 0x05 leaf references these bytes; holding them in a Map
    // meant the reference outlived the thing it referenced across a restart.
    this.#store.holdQuarantined(agentId, {
      documentId,
      rejectedEnvelopeHash: input.rejectedEnvelopeHash,
      // COPY: the caller's buffer may be a pooled network read, and a 0x05 leaf must reference
      // the bytes that were actually refused.
      payload: new Uint8Array(input.quarantined),
      reason: input.reason,
      detail: input.detail,
      // The gate produces these deliberately; dropping them leaves an operator unable to see
      // WHICH rule refused or WHAT number was exceeded.
      rule: input.rule,
      limitName: input.limit?.name,
      limitValue: input.limit?.limit,
      limitActual: input.limit?.actual,
      createdAtMs: Date.now(),
    });

    const round = this.#round(agentId, documentId);

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
    const alreadyStalled = this.#store.getDocument(agentId, documentId)?.status === "stalled";
    if (stalled && !alreadyStalled) {
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

  /**
   * Record a rejection ARRIVING from the peer — the receiving half of §3.2's "both sides".
   *
   * ── THE ROUTING DECISION (the DoD requires it resolved in-unit) ─────────────────────────────
   *
   * A document rejection is written **daemon-side**, into this document's own log and quarantine,
   * NOT through the gateway record store's `source` discriminator.
   *
   * The gateway's record store exists for SCREENING verdicts, and most V1 rejection reasons are
   * not screening at all — `append_only`, the receiver-local limits, malformed updates, unresolved
   * dependencies. Routing every document rejection through a screening store would file structural
   * protocol events as policy verdicts, and it would couple this unit to a schema owned by a
   * component that is not involved. DOD-DOC-SCREEN-1 is parked, so that coupling would also have
   * to be built speculatively and unwound if screening lands differently.
   *
   * When SCREEN-1 does land, a rejection whose reason came from the screening rule can ADDITIONALLY
   * write a gateway record — the discriminator exists for exactly that, and adding it later costs
   * nothing, whereas removing a premature coupling costs a migration.
   */
  recordIncomingRejection(
    agentId: string,
    documentId: string,
    input: { rejectedEnvelopeHash: string; reason: string; detail?: string; fromAgentId: string },
  ): void {
    this.#logger.warn("document.rejection.received", {
      documentId,
      fromAgentId: input.fromAgentId,
      rejectedEnvelopeHash: input.rejectedEnvelopeHash,
      reason: input.reason,
      detail: input.detail,
      round: this.#round(agentId, documentId),
    });
  }

  /** Entries held for this document — never admitted, never discarded (§3.2). From the store. */
  quarantined(agentId: string, documentId: string): QuarantineEntry[] {
    return this.#store.listQuarantined(agentId, documentId).map((r) => ({
      rejectedEnvelopeHash: r.rejectedEnvelopeHash,
      quarantined: r.payload,
      reason: r.reason,
      detail: r.detail,
    }));
  }

  /** Clear one entry once its superseding update has been admitted (§3.2 step 4). */
  clearQuarantine(agentId: string, documentId: string, rejectedEnvelopeHash: string): void {
    // Only announce an admission that actually happened — an event that fires on a no-op is a
    // signal on the wrong case.
    if (this.#store.releaseQuarantined(agentId, documentId, rejectedEnvelopeHash)) {
      this.#logger.info("document.supersession.admitted", { documentId, rejectedEnvelopeHash });
    }
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
    // Read the STORE, not memory. The status was persisted while the flag that gated this check
    // was not, so after a restart the document row said `stalled` while the daemon happily
    // accepted updates on it — the system reporting two contradictory states at once.
    if (this.#isStalled(agentId, documentId)) {
      const held = this.#store.listQuarantined(agentId, documentId);
      const last = held[held.length - 1];
      return {
        ok: false,
        reason: "document_stalled",
        detail: `this document stopped accepting updates after ` +
          `${this.#round(agentId, documentId)} rejected rounds` +
          (last ? `; the most recent reason was ${last.reason}` : ""),
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
    // The two roots this codebase's write path projects from, taken through their TYPED getters.
    //
    // Not the `doc.share` placeholders: `doc.get(name)` hands back the untyped AbstractType, and
    // the typed getter later instantiates a DIFFERENT object — so the UndoManager would watch a
    // root nobody edits and `undo()` would silently do nothing. Caught by the out-of-order guard
    // below, which is the guard earning its keep on its first outing.
    //
    // Instantiating these two as Text and Map is not the guessed-type hazard GATE-1 measured:
    // the write path DEFINES them as Text and Map. A document that puts content under any other
    // root is not tracked here, and that is a real gap — recorded rather than papered over,
    // because it belongs with whichever unit lets a document declare its own roots.
    const undoManager = new Y.UndoManager([doc.getText("content"), doc.getMap("data")], {
      captureTimeout: 0,
    });
    return { doc, undoManager, depthAtTracking: undoManager.undoStack.length };
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
    // REFUSE rather than undo the wrong thing. Measured, the unguarded version had three failure
    // modes that all reported success: nothing tracked (silent no-op), an untracked root (silent
    // no-op), and — the damaging one — a sender that kept editing after the rejection arrived,
    // where undo removed the agent's LEGITIMATE later work and KEPT the refused content. The
    // supersession then re-ships the refused bytes, is rejected again, and the document stalls
    // with a reason pointing at the peer while the operator's writing is gone.
    const depth = tracked.undoManager.undoStack.length;
    if (depth !== tracked.depthAtTracking + 1) {
      throw new Error(
        `document_rollback_out_of_order: ${depth - tracked.depthAtTracking} local edit(s) are ` +
          `stacked since tracking began, and Yjs can only undo the most recent — rolling back now ` +
          `would discard the wrong work. Roll back before making further local edits (§3.2 step 2).`,
      );
    }
    if (tracked.undoManager.undo() === null) {
      throw new Error(
        "document_rollback_nothing_tracked: no tracked edit to roll back — the rejected update " +
          "was not produced through this tracker",
      );
    }
  }

  /** Derived from the log, not remembered — so it survives a restart. */
  #round(agentId: string, documentId: string): number {
    return this.#store.countRejections(agentId, documentId);
  }

  #isStalled(agentId: string, documentId: string): boolean {
    return this.#store.getDocument(agentId, documentId)?.status === "stalled";
  }
}

/** A rejection's own envelope hash — distinct per rejected envelope and reason. */
function rejectionHash(rejectedEnvelopeHash: string, reason: string, nonce: string): string {
  // The nonce is what stops two rejections of the same envelope for the same reason collapsing
  // into one row — which would let a document reach `stalled` with fewer leaves than rounds.
  // ENVELOPE-1 replaces this with a real content hash over the signed envelope.
  return createHash("sha256")
    .update(`rejection:${rejectedEnvelopeHash}:${reason}:${nonce}`, "utf8")
    .digest("hex");
}
