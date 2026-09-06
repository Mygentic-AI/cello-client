/**
 * CELLO Daemon — CONTENT WE HAVE BUT CANNOT SHOW YET
 *
 * Split out of `session-node-manager.ts` by 037-SESSIONCORE. A message that arrives out of order is
 * verified and kept, not delivered: showing it would put the conversation in the wrong sequence, and
 * dropping it would lose a message the sender believes landed. It is HELD until the gap ahead of it
 * closes, then released down the path it came from.
 *
 * Moved verbatim, comments included.
 *
 * ⚠️ `origin` DECIDES THE RELEASE PATH, AND GETTING IT WRONG IS NOT COSMETIC. A held frame of OUR OWN
 * must be released down the SENT path — appended and transcribed as sent. Releasing it down the
 * received path would put our own words in the counterparty's mouth in the sealed record, and hand
 * them back to our own agent through `cello_receive` as though they had just arrived.
 */
import type { Logger } from "./types.js";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { SessionQueries } from "./session-queries.js";
import type { SessionRecords } from "./session-records.js";
import type { SessionTree, WritableSessionTreeLeafKind } from "./session-tree.js";
import type { SentAuthorship } from "./session-node-types.js";

/** One piece of content held behind an ordering gap. */
type HeldEntry = {
  content: Uint8Array; originalContent?: Uint8Array; contentHashHex: string; correlationId?: string;
  screenedOut?: boolean; origin?: "sent"; kind?: WritableSessionTreeLeafKind; authorship?: SentAuthorship;
  restoredAcrossRestart?: boolean;
};

/** What held content needs from the manager. */
export interface HeldContentContext {
  readonly logger: Logger;
  readonly queries: SessionQueries;
  readonly records: SessionRecords;
  /** A function: the manager opens its database after construction. Re-exposed below as `#db`. */
  db(): DaemonDatabase | null;
  sessionKey(agentName: string, sessionId: string): string;
  requireAgentId(agentName: string): string;
  /**
   * ⚠️ THE HELD MAP ITSELF, shared by reference rather than owned here — `ingestReceivedContent`,
   * `placeOwnLeaf`, `sealReadiness` and `getUndeliverableSeqs` all read it and all stayed behind.
   * Splitting the map would have meant two sources of truth for "what are we holding", which is
   * worse than sharing one. It is only ever ASSIGNED once, at construction, so there is one Map
   * object and no two-writer divergence.
   */
  readonly heldContent: Map<string, Map<number, HeldEntry>>;
  readonly witnessedSeq: Map<string, Map<string, number>>;
  getSessionTree(agentName: string, sessionId: string): SessionTree;
  appendSessionLeaf(
    agentName: string,
    sessionId: string,
    kind: WritableSessionTreeLeafKind,
    leafHashHex: string,
    correlationId?: string,
  ): { leafIndex: number; newRootHex: string };
  appendVerifiedContent(
    agentName: string,
    sessionId: string,
    content: Uint8Array,
    contentHashHex: string,
    senderPubkey: string,
    correlationId?: string,
    originalContent?: Uint8Array,
    verifiedAuthorship?: { senderPubkey: Uint8Array; senderSig: Uint8Array },
  ): { leafIndex: number };
}

export class HeldContent {
  readonly #ctx: HeldContentContext;

  constructor(ctx: HeldContentContext) {
    this.#ctx = ctx;
  }

  /** A getter so the moved queries still read `this.#db` and narrow exactly as they did. */
  get #db(): DaemonDatabase | null {
    return this.#ctx.db();
  }

  #heldRestored = new Set<string>();
  #heldReleased = new Set<string>();
  /** M8C-ABUSE-1 (reviewer HIGH fix, D18): bytes currently sitting in the out-of-order hold
   *  buffer for this session — NOT yet committed leaves, but real bytes in memory that would
   *  otherwise let multiple held chunks each individually pass the size gate while cumulatively
   *  exceeding it once #releaseHeld drains them. */
  getHeldBytesTotal(agentName: string, sessionId: string): number {
    // DOD-M12B-STRAND-1: hydrate first. Reading the Map before the durable holds are back
    // under-counts, and this gate exists to stop several held chunks each passing the size cap
    // individually while cumulatively exceeding it — an under-count is the bypass.
    this.ensureHeldRestored(agentName, sessionId);
    const held = this.#ctx.heldContent.get(this.#ctx.sessionKey(agentName, sessionId));
    if (!held) return 0;
    let total = 0;
    for (const entry of held.values()) total += entry.content.length;
    return total;
  }
  /**
   * DOD-M12B-STRAND-1 — restore this session's held frames into memory.
   *
   * Called when a session node is (re)created, which is the moment the session becomes able to
   * append again. Loading at daemon boot instead would be wrong for the same reason the old code
   * was wrong: a frame is only releasable against a tree, and the tree is loaded per session.
   *
   * A frame whose content the tree ALREADY HOLDS at that position is dropped — re-appending it
   * would change the root a seal signs over. That test is `hashAt`, not `canonical_seq < frontier`:
   * the two counters are different spaces and this file documents them drifting, so the index
   * comparison alone would destroy a frame the tree never held. See the drift branch below.
   */
  ensureHeldRestored(agentName: string, sessionId: string, opts?: { release?: boolean }): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    if (!this.#heldRestored.has(key)) {
      // Set BEFORE restoring, so the #ensureHeldRestored inside #releaseHeld below returns straight
      // away instead of recursing.
      this.#heldRestored.add(key);
      this.restoreHeldContent(agentName, sessionId);
    }
    // A RESTORED FRAME MAY ALREADY BE IN ORDER, and nothing else would ever notice.
    //
    // #releaseHeld has one caller: the tail of a successful inbound ingest. Every other way the tree
    // grows — an outbound send leaf, a queued or rejected leaf — advances the frontier without
    // draining. While holds died with the session node that cost seconds; now the hold is durable,
    // so the stall is durable too: the counterparty's message sits on disk at exactly the next slot,
    // is never delivered, and `sealReadiness` counts it, so the session cannot close either.
    // Undeliverable AND unsealable, forever, from one restart.
    //
    // TRACKED SEPARATELY FROM THE HYDRATION. A read-only caller (the status surface) hydrates and
    // must NOT release — otherwise `cello status` appends leaves, advances the session root, writes
    // transcript rows and rings the doorbell, which makes a diagnostic command the thing that
    // delivers messages. One shared flag would also let that read CONSUME the release the next real
    // ingest was going to perform, which is the stall above, reintroduced.
    if (opts?.release === false) return;
    if (this.#heldReleased.has(key)) return;
    this.#heldReleased.add(key);
    if (this.#ctx.heldContent.get(key)?.size) {
      const counterparty = this.#ctx.queries.getSessionRecord(agentName, sessionId)?.counterparty_pubkey;
      if (counterparty) this.releaseHeld(agentName, sessionId, counterparty);
    }
  }
  restoreHeldContent(agentName: string, sessionId: string): void {
    if (!this.#db) return;
    let rows: Array<{ canonical_seq: number; content_blob: Buffer; original_blob: Buffer | null; content_hash_hex: string; screened_out: number; correlation_id: string | null; origin: string; leaf_kind: string }>;
    try {
      rows = this.#db.prepare(
        `SELECT canonical_seq, content_blob, original_blob, content_hash_hex, screened_out, correlation_id, origin, leaf_kind
           FROM held_content WHERE agent_id = ? AND session_id = ? ORDER BY canonical_seq ASC`,
      ).all(this.#ctx.requireAgentId(agentName), sessionId) as never;
    } catch (err: unknown) {
      this.#ctx.logger.error("session.content.held.restore.failed", {
        agentName, sessionId,
        impact: "verified content held before the restart is not in memory and cannot be released",
        error: err instanceof Error ? err.message : String(err),
      });
      return;
    }
    if (rows.length === 0) return;
    const key = this.#ctx.sessionKey(agentName, sessionId);
    let held = this.#ctx.heldContent.get(key);
    if (!held) { held = new Map(); this.#ctx.heldContent.set(key, held); }
    const tree = this.#ctx.getSessionTree(agentName, sessionId);
    const frontier = tree.size();
    let restored = 0;
    let superseded = 0;
    let drifted = 0;
    for (const row of rows) {
      // ASK THE TREE WHAT IS AT THAT POSITION — do not infer it from the index.
      //
      // `canonical_seq` is the RELAY's sequence space; `frontier` is this tree's msg-leaf count.
      // The two drift, on purpose and by documented cases: the relay counts CTRL leaves the tree
      // never appends, and a first message whose relay submit failed leaves the tree one ahead.
      // Under drift `canonical_seq < frontier` is TRUE for a frame the tree has never held, and
      // deleting on that comparison destroys verified content while reporting it as tidy-up —
      // the exact failure this unit exists to end, reintroduced on the recovery path.
      const occupant = tree.hashAt(row.canonical_seq);
      if (occupant === row.content_hash_hex) {
        this.#ctx.queries.deleteHeldContent(agentName, sessionId, row.canonical_seq);
        superseded++;
        continue;
      }
      if (row.canonical_seq < frontier) {
        // The position is taken by DIFFERENT content. The frame cannot be appended (that would
        // rewrite a committed leaf) and must not be deleted (it is verified content nobody else
        // holds), so it goes to the annex that exists for exactly this — content that arrived for
        // a chain that can no longer carry it — and only then does the row go.
        const annexed = this.#ctx.queries.recordSealedAnnex(
          agentName, sessionId, row.content_hash_hex, new Uint8Array(row.content_blob),
          // DOD-M12B-INDEX-1: our own held send is attributed to US, never to the counterparty.
          row.origin === "sent"
            ? this.#ctx.queries.ownPubkeyHex(agentName)
            : this.#ctx.queries.getSessionRecord(agentName, sessionId)?.counterparty_pubkey ?? null,
        );
        this.#ctx.logger.error("session.content.held.position_drifted", {
          agentName, sessionId, canonicalSeq: row.canonical_seq, frontier,
          contentHash: row.content_hash_hex, occupant, annexed,
          correlationId: row.correlation_id ?? undefined,
          impact: annexed
            ? "the relay's position for this frame is occupied by different content — it cannot join the chain and is readable only from the annex"
            : "the relay's position for this frame is occupied by different content AND the annex write failed — the durable row is kept rather than destroyed",
        });
        if (annexed) this.#ctx.queries.deleteHeldContent(agentName, sessionId, row.canonical_seq);
        drifted++;
        continue;
      }
      held.set(row.canonical_seq, {
        content: new Uint8Array(row.content_blob),
        ...(row.original_blob ? { originalContent: new Uint8Array(row.original_blob) } : {}),
        contentHashHex: row.content_hash_hex,
        ...(row.correlation_id ? { correlationId: row.correlation_id } : {}),
        ...(row.screened_out ? { screenedOut: true } : {}),
        ...(row.origin === "sent" ? { origin: "sent" as const } : {}),
        ...(row.leaf_kind === "doc" ? { kind: "doc" as const } : {}),
        /**
         * ⚠️ `restoredAcrossRestart` EXISTS TO NAME A LOSS, NOT TO CHANGE BEHAVIOUR — review pass 2, H1.
         *
         * `held_content` has no authorship columns, so a SENT message held behind a gap and released
         * after a daemon restart comes back with **no signature** — its transcript row records
         * `self_authored` with no proof, indistinguishable from an unwitnessed send. That is the
         * defect bullet 5 exists to end, reappearing on the recovery path, and it was silent.
         *
         * The proof cannot be reconstructed here: it was made over Structure-1 bytes this process no
         * longer holds. **So the honest move is to say so, not to fabricate one** — a proof that
         * cannot be checked, presented as one that can, is worse than the absence.
         *
         * Two BLOB columns would close it properly (this table already carries two `ALTER TABLE …
         * ADD COLUMN` migrations, so the pattern exists). Under a frozen gate a log is additive and
         * tightenable where a schema change is neither, so this announces the loss now and
         * `DOD-M15-HELD-AUTHORSHIP-1` carries the column.
         */
        restoredAcrossRestart: true,
      });
      restored++;
    }
    if (held.size === 0) this.#ctx.heldContent.delete(key);
    this.#ctx.logger.info("session.content.held.restored", {
      agentName, sessionId, restored, superseded, drifted, frontier,
      canonicalSeqs: [...held.keys()].sort((a, b) => a - b),
      // The flow ids of the frames that came back, so a restored message ties to the
      // `session.content.held` that opened its flow before the restart.
      correlationIds: rows.map((r) => r.correlation_id).filter((c): c is string => c !== null),
    });
  }
  /**
   * DOD-MSG-4: drain held out-of-order content in canonical order. After a leaf is appended, any
   * held entry whose canonical sequence equals the new next-expected index is now in order — append
   * it, then check again (a single fill can release a run of consecutive held messages).
   */
  releaseHeld(agentName: string, sessionId: string, senderPubkey: string): number {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    // DOD-M12B-STRAND-1: hydrate before scanning. Restoring eagerly at session-node creation put
    // it behind writes that can fail — one failed `sessions` row upsert and the frames stayed on
    // disk, invisible, which is the same outcome as losing them.
    this.ensureHeldRestored(agentName, sessionId);
    const held = this.#ctx.heldContent.get(key);
    if (!held) return 0;
    let released = 0;
    for (;;) {
      const nextExpected = this.#ctx.getSessionTree(agentName, sessionId).size();
      const entry = held.get(nextExpected);
      if (!entry) break;
      held.delete(nextExpected);
      // DOD-M12B-STRAND-1: released content leaves the durable store in the same breath. A row
      // that outlives its release would re-append the same content on the next boot — growing the
      // tree and changing a root that has already been signed.
      this.#ctx.queries.deleteHeldContent(agentName, sessionId, nextExpected);
      // DOD-M12B-INDEX-1: OUR OWN held message. It leafs at its canonical index and is transcribed
      // as SENT — never routed down the received path, which would attribute our words to the
      // counterparty in the sealed record and hand them back to our own agent as inbound.
      if (entry.origin === "sent") {
        // The KIND the leaf was placed with, not a hardcoded "msg" — a document leaf that had to
        // wait for its position must come back as a document leaf, or the two sides disagree about
        // what the chain contains.
        this.#ctx.appendSessionLeaf(agentName, sessionId, entry.kind ?? "msg", entry.contentHashHex, entry.correlationId);
        // A DOCUMENT frame takes a leaf and NO transcript row — matching what the immediate-append
        // path does for one. Writing one would put raw CBOR into the operator's transcript as
        // something they said, which is the same attribution failure as releasing it inbound.
        if (entry.kind === "doc") {
          released++;
          this.#ctx.logger.info("session.content.released", {
            sessionId, sequenceNumber: nextExpected, leafKind: "doc", correlationId: entry.correlationId,
          });
          if (held.size === 0) { this.#ctx.heldContent.delete(key); break; }
          continue;
        }
        // OBSERVED, not assumed — the received path already does this. The leaf commits either way,
        // so a dropped transcript write means the operator's OWN message is missing from their own
        // transcript with the chain saying it is there, and nothing anywhere said so.
        // bullet 5: the proof was captured at submit time and rides the held entry — see #heldContent.
        /**
         * THE RESTART LOSS, ANNOUNCED — review pass 2, H1. Only for an entry that actually crossed a
         * restart: an in-memory held entry carries its proof, and an unwitnessed send legitimately
         * has none, so warning on every absent proof would fire on a designed benign state and bury
         * the one occurrence that means something.
         */
        if (entry.restoredAcrossRestart === true && entry.authorship === undefined) {
          this.#ctx.logger.warn("session.content.released.authorship.lost", {
            agentName, sessionId, sequenceNumber: nextExpected, correlationId: entry.correlationId,
            impact:
              "this message was held behind a gap, survived a daemon restart, and is now committed with " +
              "attribution 'self_authored' and NO signature. Its transcript row asserts its author rather " +
              "than proving one, and is indistinguishable from a send the relay never witnessed.",
            guidance:
              "Not recoverable after the fact — the signature covered Structure-1 bytes this process no longer " +
              "holds, and fabricating one would be worse than the absence. Tracked as DOD-M15-HELD-AUTHORSHIP-1: " +
              "held_content needs the two proof columns so a restart carries them.",
          });
        }
        if (!this.#ctx.records.recordTranscriptMessage(agentName, sessionId, nextExpected, "sent", entry.content, entry.correlationId, entry.authorship)) {
          this.#ctx.logger.error("session.content.released.transcript.failed", {
            agentName, sessionId, sequenceNumber: nextExpected, correlationId: entry.correlationId,
            impact: "this side's own message is committed to the chain but missing from its transcript",
          });
        }
      } else if (entry.screenedOut) {
        this.#ctx.appendSessionLeaf(agentName, sessionId, "msg", entry.contentHashHex, entry.correlationId);
        // The SAME witness leak as the immediate-append terminal-block branch (see the block comment
        // at the `if (terminalBlock)` append in `ingestReceivedContent`), on the held path. This
        // branch also bypasses `#appendVerifiedContent`, where the drop lives — so a blocked message
        // that arrived out of order left `missingLeaves` stuck at 1 and the session unsealable.
        this.#ctx.witnessedSeq.get(key)?.delete(entry.contentHashHex);
      } else {
        this.#ctx.appendVerifiedContent(agentName, sessionId, entry.content, entry.contentHashHex, senderPubkey, entry.correlationId, entry.originalContent);
      }
      released++;
      this.#ctx.logger.info("session.content.released", {
        sessionId,
        sequenceNumber: nextExpected,
        screenedOut: entry.screenedOut === true,
        correlationId: entry.correlationId,
      });
      if (held.size === 0) { this.#ctx.heldContent.delete(key); break; }
    }
    return released;
  }
  /**
   * Test seam: put an own leaf in the HELD state instead of the tree — 033-ACKEMIT.
   *
   * The state `placeOwnLeaf` produces when the relay assigns a position ahead of our tail: the leaf
   * exists on this side and is not in the tree, while the counterparty already has it from the relay
   * and can acknowledge it. Reproducing it through the real hold map rather than by asserting the
   * tree is short is what makes the acknowledgement test measure the case instead of a neighbour of
   * it.
   */
  holdOwnLeafForTest(agentName: string, sessionId: string, canonicalSeq: number, contentHashHex: string): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    let held = this.#ctx.heldContent.get(key);
    if (!held) { held = new Map(); this.#ctx.heldContent.set(key, held); }
    held.set(canonicalSeq, { content: new Uint8Array(), contentHashHex, origin: "sent", kind: "msg" });
  }
  /** @returns true iff the UPDATE was executed without error (a failed write is logged, never thrown). */
  /**
   * DOD-M12B-STRAND-1 — move a terminal session's held frames to the annex.
   *
   * A held frame is content this agent RECEIVED and VERIFIED. When its session ends it can never
   * join that chain (appending behind a committed root is not an option, and ingest refuses a
   * terminal session outright), but it is still the operator's mail and no other copy exists —
   * the sender was never acknowledged for it. `sealed_session_annex` is where M12-P17 already puts
   * content that arrives for an ended session; this is the same content arriving slightly earlier.
   *
   * ANNEX FIRST, DELETE SECOND, per row. A crash between them costs a duplicate the annex's
   * INSERT OR IGNORE absorbs; the other order costs the message. A row whose annex write fails is
   * KEPT — the retention sweep will find it again, and a leftover row is cheaper than a lost one.
   */
  annexHeldContentOnTerminal(agentName: string, sessionId: string, status: "sealed" | "abandoned"): void {
    if (!this.#db) return;
    let rows: Array<{ canonical_seq: number; content_blob: Buffer; content_hash_hex: string; held_at: number; origin: string }>;
    try {
      rows = this.#db.prepare(
        `SELECT canonical_seq, content_blob, content_hash_hex, held_at, origin
           FROM held_content WHERE agent_id = ? AND session_id = ? ORDER BY canonical_seq ASC`,
      ).all(this.#ctx.requireAgentId(agentName), sessionId) as never;
    } catch (err: unknown) {
      this.#ctx.logger.error("session.content.held.annex.scan.failed", {
        agentName, sessionId, status,
        impact: "held frames for a terminal session were not moved to the annex and remain unreadable",
        error: err instanceof Error ? err.message : String(err),
      });
      return;
    }
    if (rows.length === 0) return;
    const counterparty = this.#ctx.queries.getSessionRecord(agentName, sessionId)?.counterparty_pubkey ?? null;
    let annexed = 0;
    let kept = 0;
    for (const row of rows) {
      // DOD-M12B-INDEX-1: ATTRIBUTION. A `sent` row is our own message. Stamping the counterparty's
      // pubkey on it would put our words in their mouth in the one record that survives the
      // session — the same failure the release path was changed to avoid, on the drain it did not
      // touch. `#ownPubkeyHex` is null only when the identity cannot be resolved, and a null sender
      // reads as "unattributed", which is true, rather than as a false attribution.
      const sender = row.origin === "sent" ? this.#ctx.queries.ownPubkeyHex(agentName) : counterparty;
      if (this.#ctx.queries.recordSealedAnnex(agentName, sessionId, row.content_hash_hex, new Uint8Array(row.content_blob), sender)) {
        this.#ctx.queries.deleteHeldContent(agentName, sessionId, row.canonical_seq);
        // AND OUT OF THE IN-MEMORY MAP. Measured live 2026-08-17 on daemon 0.0.170: this frame is
        // now safe in the annex and its durable row is gone — but teardown still found it in the
        // map, counted `held_content` for the session, got 0, and fired
        // `session.content.held.lost`: "verified content was destroyed". Ten frames were annexed
        // and the same ten were reported destroyed, in the same second. A false alarm on the most
        // serious event in the system is worse than no alarm, because the next investigation goes
        // looking for content that was never lost.
        this.#ctx.heldContent.get(this.#ctx.sessionKey(agentName, sessionId))?.delete(row.canonical_seq);
        annexed++;
      } else {
        kept++;
      }
    }
    this.#ctx.logger.warn("session.content.held.annexed", {
      agentName, sessionId, status, annexed, kept,
      // The consumer of `held_at`: how long the oldest frame waited before its session ended.
      oldestHeldMs: Date.now() - Math.min(...rows.map((r) => r.held_at)),
      impact: "these messages arrived and verified but never joined the chain — they are readable from the annex, not the transcript",
    });
  }

  /**
   * Forget the restore/release bookkeeping for a torn-down session.
   *
   * The held CONTENT itself is not dropped here — the map is shared and the manager's eviction still
   * owns that line. What goes is this module's memory of whether a session was already hydrated from
   * disk and already released, which must not survive a teardown: a revived session has to re-read
   * from durable state rather than trust a flag about a process that is gone.
   */
  evictSession(agentName: string, sessionId: string): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    this.#heldRestored.delete(key);
    this.#heldReleased.delete(key);
  }
}
