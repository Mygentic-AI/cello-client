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

/**
 * "Did every holder hear it?" — and NO on an empty map.
 *
 * `[].every(…)` is `true`, so folding an empty fan-out with `every` alone reports that everybody
 * was notified precisely when nobody was. The notifier refuses a holder-less document by name, so
 * this is the second line rather than the first, but the vacuous-truth reading is the one that
 * would surface to an operator as a clean close that told no one.
 */
function everyHolderNotified(ok: boolean, holders: Record<string, boolean>): boolean {
  const told = Object.values(holders ?? {});
  return ok && told.length > 0 && told.every((v) => v);
}

/**
 * Who currently holds this document, derived from the chain — the INBOUND authorization gate.
 *
 * DOD-MP-CONTROL-N-1 fixed the outbound half first and that was only half the defect: the
 * receiving side still authorized a `close`/`kill` by `sender === doc.peerAgentId`, the same
 * genesis column. Two ordinary-command consequences, no rewritten daemon required:
 *
 *  - **A REMOVED holder could still end the creator's document.** A created with B, invited C,
 *    removed B. A's `peerAgentId` is still B, so B's kill was accepted by A and refused by C —
 *    the two operators left in different states by a party who holds no rights at all.
 *  - **A JOINER's end reached nobody.** With {A, B, C}, C's close is now correctly addressed to
 *    both, and BOTH refused it, because C is neither one's `peerAgentId`. The sender was told
 *    everyone heard them while nothing was recorded anywhere.
 *
 * Returns null when the chain cannot answer, which is NOT an empty list: "nobody holds this" and
 * "this cannot be answered" are different facts. On null the row's peer column stands in, exactly
 * as `document-inbound.ts` does for update envelopes — that is the bilateral-legacy path, not a
 * fallback for convenience.
 */
export type CurrentHolders = (ownerAgentId: string, documentId: string) => readonly string[] | null;

/** How the peer is told about a unilateral end. Injected — the transport is not this unit's. */
export interface LifecycleNotifier {
  notifyPeer(
    documentId: string,
    verb: "kill" | "close",
    // `detail` carries the underlying description when the failure is LOCAL — a key that could not
    // be loaded reads nothing like a peer who is offline, and one guidance string for both sent
    // operators to wait for someone who was already there.
    // `holdersNotified` is per-holder because a control frame goes to EVERY current holder
    // (DOD-MP-CONTROL-N-1). With N holders a partial fan-out is the ordinary failure, and the one
    // boolean this used to return could not tell "all three heard you" from "one of three did".
  ): Promise<
    | { ok: true; holdersNotified: Record<string, boolean> }
    | { ok: false; reason: string; detail?: string }
  >;
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
  pendingDeliveries: number;
  /** Of those, how many have LEFT and are awaiting the peer's confirmation. */
  pendingSent: number;
  /** Of those, how many have not left this machine at all. */
  pendingUnsent: number;
  /**
   * Updates WE GAVE UP ON — the unacked ceiling fired and they will never be retried.
   *
   * Without this the surface lies by omission. An abandoned envelope drops out of all three pending
   * counters, so the operator's view goes from `pendingUnsent: 1` to `pendingDeliveries: 0`, which
   * reads as delivered. The only other signal was `status: "stalled"`, and nothing said an update
   * had been permanently dropped. The database keeps the distinction (`abandoned_at` is our
   * decision, not evidence about the peer) and the surface threw it away.
   */
  abandonedDeliveries: number;
  /** We have closed and the peer has not. */
  closePending: boolean;
}

export type Verdict = { ok: true } | { ok: false; reason: string; detail: string };

export class DocumentLifecycle {
  readonly #store: DocumentStore;
  readonly #logger: Logger;
  readonly #notifier: LifecycleNotifier;
  /**
   * Our own wire sender id for an agent. M14-D5 makes it the pubkey hex, which is NOT the local
   * owner key this store is otherwise keyed by — and passing the wrong one here reports every
   * pending update as delivered.
   */
  readonly #senderAgentId: (ownerAgentId: string) => string;
  readonly #rollback: (
    ownerAgentId: string,
    documentId: string,
    envelopeHash: string,
  ) => { ok: true } | { ok: false; reason: string };
  readonly #currentHolders: CurrentHolders;

  /**
   * May this sender end this document? Derived membership is the WHOLE gate when the chain
   * derives — a joined third holder's close is as admissible as the genesis peer's, and a removed
   * holder's is not admissible at all. The peer column stands in only when the chain cannot
   * answer. Mirrors `document-inbound.ts`'s sender gate deliberately; two different answers to
   * "is this agent a party to this document" is how the two paths drift apart.
   */
  #senderMayEnd(ownerAgentId: string, documentId: string, senderAgentId: string, peerAgentId: string): boolean {
    const holders = this.#currentHolders(ownerAgentId, documentId);
    return holders === null ? senderAgentId === peerAgentId : holders.includes(senderAgentId);
  }

  constructor(
    store: DocumentStore,
    logger: Logger,
    notifier: LifecycleNotifier,
    /**
     * Undo one envelope's operations on the LIVE document, as inverses. Injected because the live
     * `Y.Doc` and its UndoManager belong to the engine, not here — and REQUIRED, because a default
     * that quietly did nothing would restore exactly the defect this argument exists to fix.
     */
    rollback: (ownerAgentId: string, documentId: string, envelopeHash: string) =>
      { ok: true } | { ok: false; reason: string },
    senderAgentId: (ownerAgentId: string) => string = (id) => id,
    /**
     * The inbound authorization gate (DOD-MP-CONTROL-N-1). Defaults to "cannot answer", which
     * routes to the `peerAgentId` check — the pre-multiplayer behaviour — so a caller that has not
     * been wired yet is bilateral-correct rather than open. It is NOT defaulted to a permissive
     * answer: a membership gate whose default admits everyone is worse than no gate, because it
     * reads as one.
     */
    currentHolders: CurrentHolders = () => null,
  ) {
    this.#store = store;
    this.#logger = logger;
    this.#notifier = notifier;
    this.#rollback = rollback;
    this.#senderAgentId = senderAgentId;
    this.#currentHolders = currentHolders;
    this.#store.rawDb.exec(CREATE_LIFECYCLE_SQL);
  }

  list(ownerAgentId: string, nowMs: number): DocumentListRow[] {
    // Every pending envelope regardless of schedule: the operator is asking "what has not reached
    // my peer", not "what is due for a retry in the next few seconds".
    const pending = this.#store.pendingDeliveries(
      ownerAgentId,
      Number.MAX_SAFE_INTEGER,
      this.#senderAgentId(ownerAgentId),
    );
    const pendingByDocument = new Map<string, { total: number; sent: number }>();
    for (const e of pending) {
      const c = pendingByDocument.get(e.documentId) ?? { total: 0, sent: 0 };
      c.total += 1;
      // SPLIT, because "sent, awaiting confirmation" and "never left this machine" are different
      // things to tell an operator asking why their work has not landed. FANOUT-1: the fact
      // moved to the per-holder rows — "sent" means it reached AT LEAST ONE holder's wire.
      if (e.deliveredAtMs != null || this.#store.envelopeEverSent(ownerAgentId, e.envelopeHash)) c.sent += 1;
      pendingByDocument.set(e.documentId, c);
    }
    void nowMs;

    return this.#store.listDocuments(ownerAgentId).map((d) => ({
      documentId: d.documentId,
      peerAgentId: d.peerAgentId,
      documentType: d.documentType,
      // DOD-MP-REMOVE-1 — display overlay, derived: a removed holder's row still says active in
      // the table (removal is a chain fact, not a stored flag), and a list that said "active"
      // would be the surface claiming more than forward-only allows.
      ...(this.#store.removedFromArrangement(ownerAgentId, d.documentId).removed
        ? { removed: true }
        : {}),
      assuranceTier: "authenticated",
      epochId: this.#store.currentDocumentEpoch(ownerAgentId, d.documentId),
      status: d.status,
      pendingDeliveries: pendingByDocument.get(d.documentId)?.total ?? 0,
      pendingSent: pendingByDocument.get(d.documentId)?.sent ?? 0,
      pendingUnsent:
        (pendingByDocument.get(d.documentId)?.total ?? 0) -
        (pendingByDocument.get(d.documentId)?.sent ?? 0),
      abandonedDeliveries: this.#store.abandonedCount(ownerAgentId, d.documentId),
      closePending:
        this.#hasClosed(ownerAgentId, d.documentId, ownerAgentId) &&
        !this.#hasClosed(ownerAgentId, d.documentId, d.peerAgentId),
    }));
  }

  /** Our half of a bilateral close. Completes only when the peer's half is also on record. */
  async close(
    ownerAgentId: string,
    documentId: string,
    nowMs: number,
  ): Promise<
    | (Verdict & {
        ok: true;
        peerNotified: boolean;
        holdersNotified: Record<string, boolean>;
        notifyReason?: string;
        notifyDetail?: string;
      })
    | (Verdict & { ok: false })
  > {
    const doc = this.#store.getDocument(ownerAgentId, documentId);
    if (!doc) {
      return { ok: false, reason: "document_unknown", detail: `no document ${documentId.slice(0, 16)}…` };
    }
    this.#recordClose(ownerAgentId, documentId, ownerAgentId, nowMs);
    const notified = await this.#notifier.notifyPeer(documentId, "close");
    if (!notified.ok) {
      // RAISED to error, and RETURNED, matching `kill`. This was a warn whose outcome went nowhere:
      // the caller answered `{ok: true, status: "active"}`, which is indistinguishable from "sent
      // fine, they have not answered yet". Control frames are fire-once — not in the log, never
      // swept — so a close the peer never received means the document can never settle, and neither
      // operator has anything to look at.
      this.#logger.error("document.close.peer_not_notified", {
        documentId,
        reason: notified.reason,
        detail: notified.detail ?? "",
      });
    }
    this.#settleClose(ownerAgentId, documentId, doc.peerAgentId);
    const holdersNotified = notified.ok ? notified.holdersNotified : {};
    // EVERY current holder, not "the send returned ok" — with N holders a partial fan-out is the
    // normal failure and one boolean cannot describe it. The map is the precise answer; this stays
    // as the summary a caller can branch on.
    const allNotified = everyHolderNotified(notified.ok, holdersNotified);
    this.#logger.info("document.close.requested", { documentId, peerNotified: allNotified, holdersNotified });
    // THE REASON TRAVELS. It used to stop here, so one guidance string covered a transport failure,
    // a missing signing key and a wiring fault — and it told the operator to wait for their peer,
    // which only helps for the first of the three.
    return {
      ok: true,
      peerNotified: allNotified,
      holdersNotified,
      ...(notified.ok ? {} : { notifyReason: notified.reason, notifyDetail: notified.detail }),
    };
  }

  /** The peer's half, arriving over the session. */
  recordPeerClose(
    ownerAgentId: string,
    documentId: string,
    peerAgentId: string,
    nowMs: number,
  ): Verdict {
    const doc = this.#store.getDocument(ownerAgentId, documentId);
    if (!doc) {
      // Without this the row is written for a document that does not exist — there is no foreign
      // key on this table — and `setDocumentStatus` updates zero rows and returns silently.
      return {
        ok: false,
        reason: "document_unknown",
        detail: `no document ${documentId.slice(0, 16)}… for this agent`,
      };
    }
    if (!this.#senderMayEnd(ownerAgentId, documentId, peerAgentId, doc.peerAgentId)) {
      // THE PARTY GUARANTEE. The closer id came from the caller and was written as `closed_by`
      // and settled against ITSELF, so any second distinct string — a stale contact id, a
      // pubkey-vs-name mismatch, a hostile session — plus our own close flipped the document to
      // closed. The whole point of recording WHO closed is defeated if who is never checked.
      //
      // The check is now MEMBERSHIP, not identity-with-one-peer: a joiner is a party and their
      // close must count, a removed holder is not and theirs must not.
      this.#logger.warn("document.close.not_holder", {
        documentId,
        claimedBy: peerAgentId,
        peerAgentId: doc.peerAgentId,
      });
      return {
        ok: false,
        reason: "document_close_not_peer",
        detail:
          `${peerAgentId} does not currently hold this document, so their close is not one of the ` +
          `halves that can settle it`,
      };
    }
    // RECORDED AGAINST THE SENDER, not against `doc.peerAgentId`. Writing the peer column here
    // credited a joiner's close to the genesis peer — the wrong name on the record, and with two
    // joiners closing it would settle twice against one identity.
    this.#recordClose(ownerAgentId, documentId, peerAgentId, nowMs);
    this.#settleClose(ownerAgentId, documentId, peerAgentId);
    this.#logger.info("document.close.peer_requested", { documentId, peerAgentId });
    return { ok: true };
  }

  /**
   * The peer KILLED the document. Their half of the unilateral end.
   *
   * Terminal immediately, and there is no reciprocal step: a kill is one-sided by definition, which
   * is what separates it from a close. Continuing to publish afterwards would send updates to a
   * party who has stopped listening — refused at their end forever, with nothing on this screen
   * explaining why.
   *
   * The SENDER IS CHECKED against the document's peer for the same reason `recordPeerClose` checks
   * it: without that, any string plus a valid-looking frame ends someone else's document.
   */
  recordPeerKill(
    ownerAgentId: string,
    documentId: string,
    peerAgentId: string,
    nowMs: number,
  ): Verdict {
    const doc = this.#store.getDocument(ownerAgentId, documentId);
    if (!doc) {
      return {
        ok: false,
        reason: "document_unknown",
        detail: `no document ${documentId.slice(0, 16)}… for this agent`,
      };
    }
    if (!this.#senderMayEnd(ownerAgentId, documentId, peerAgentId, doc.peerAgentId)) {
      this.#logger.warn("document.kill.not_holder", {
        documentId,
        claimedBy: peerAgentId,
        peerAgentId: doc.peerAgentId,
      });
      return {
        ok: false,
        reason: "document_kill_not_peer",
        detail: `${peerAgentId} does not currently hold this document, so their kill is not theirs to make`,
      };
    }
    void nowMs;
    if (doc.status !== "active" && doc.status !== "stalled") {
      // ONLY FROM ACTIVE, the same guard `#settleClose` carries and for the mirror reason. The
      // transport WILL redeliver, and nothing bounds a control frame's freshness — `sent_at_ms` is
      // signed and never checked. Unconditional, a kill arriving after a bilateral close rewrote a
      // settled agreement as a unilateral end.
      this.#logger.info("document.kill.peer_requested.ignored", {
        documentId,
        status: doc.status,
      });
      return { ok: true };
    }
    this.#store.setDocumentStatus(ownerAgentId, documentId, "killed");
    this.#logger.info("document.kill.peer_requested", { documentId, peerAgentId: doc.peerAgentId });
    return { ok: true };
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
    | {
        ok: true;
        peerNotified: boolean;
        holdersNotified: Record<string, boolean>;
        note: string;
        notifyReason?: string;
        notifyDetail?: string;
      }
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
        detail: notified.detail ?? "",
      });
    }
    const holdersNotified = notified.ok ? notified.holdersNotified : {};
    const allNotified = everyHolderNotified(notified.ok, holdersNotified);
    this.#logger.info("document.killed", { documentId, peerNotified: allNotified, holdersNotified });

    return {
      ok: true,
      peerNotified: allNotified,
      holdersNotified,
      note:
        "this document no longer accepts or publishes updates, and your local copy and log are " +
        "retained. Your peer keeps what it holds — a kill stops the collaboration, it does not " +
        "retract content they already have.",
      // Same reason `close` carries it: a local signing fault and an absent peer are opposite
      // problems and only one of them is fixed by waiting.
      ...(notified.ok ? {} : { notifyReason: notified.reason, notifyDetail: notified.detail }),
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
    // ONLY FROM ACTIVE. Unconditional, a peer close arriving after a unilateral kill overwrote
    // `killed` with `closed` — the operator's own decision replaced by "closed by agreement", which
    // is a different fact and the one they did not choose. Same for `stalled`.
    if (this.#store.getDocument(ownerAgentId, documentId)?.status !== "active") return;
    if (
      this.#hasClosed(ownerAgentId, documentId, ownerAgentId) &&
      this.#hasClosed(ownerAgentId, documentId, peerAgentId)
    ) {
      this.#store.setDocumentStatus(ownerAgentId, documentId, "closed");
      this.#logger.info("document.closed", { documentId });
    }
  }
}
