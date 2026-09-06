/**
 * CELLO Daemon — HOLDING WHAT WAS REFUSED, AND WHERE A MESSAGE SITS IN THE ORDER
 *
 * Split out of `session-node-manager.ts` by 036-GODFILE, Parts 3 and 4. Everything that happens to
 * an inbound message this daemon will NOT deliver: quarantining the bytes so the operator has an
 * artifact to show, triaging one that belongs to no session, saying why authorship could not be
 * proven, remembering a terminal refusal, and recording the relay position a frame claims.
 *
 * Moved verbatim, comments included. Much of the prose here records a defect that came back once
 * already, and several of the bounds exist because the map they guard is fed by a remote party.
 *
 * ⚠️ THIS CLASS OWNS THE FIVE PER-SESSION CONTAINERS IT MAINTAINS, which is what made it a seam.
 * THREE of them are capped per session because a remote peer feeds them (`#terminallyRefused`,
 * `#unreadableAlgSeen`, `#refusedOnDirectPath`); the other two — `#terminalRefusalsLoaded`, a SET
 * rather than a map, and `#terminalRefusalsReadFailedAt` — carry no cap and grow one entry per
 * session, so `evictSession` is the only thing that releases them. Said precisely because "each is
 * bounded" reads as a safety property and only three of the five have it.
 *
 * They used to be cleared field-by-field from the manager's cache eviction; that is now one
 * `evictSession` call, which is the point — a caller that had to know five field names in order to
 * forget a session knew too much.
 */
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";
import type { RefusalKind } from "./refusal-reasons.js";
import { REFUSAL_KINDS } from "./refusal-reasons.js";
import { TIER, normalizeTier } from "./contacts-tier-migration.js";
import { extractErrorMessage } from "./error-message.js";
import { normalizeContactPubkey } from "./contact-pubkey-case.js";
import type { OrphanEvidence } from "./orphan-triage.js";
import { decodeStructure1 } from "@cello-protocol/protocol-types";
import { decode } from "cbor-x";
import {
  type AuthorshipVerdict,
  type AckHashReason,
  TERMINAL_REFUSAL_REASONS,
  TERMINAL_REFUSAL_READ_RETRY_MS,
  MAX_TERMINAL_REFUSALS_PER_SESSION,
  MAX_UNREADABLE_ALG_FRAMES,
  ACK_HASH_REASONS,
  AUTHORSHIP_SELF_CHAIN_MISMATCH,
  AUTHORSHIP_ACK_HASH_MISMATCH,
  AUTHORSHIP_ACK_HASH_UNKNOWN,
  AUTHORSHIP_CONTENT_HASH_MISMATCH,
  AUTHORSHIP_SESSION_MISMATCH,
  REFUSAL_MAY_STILL_ARRIVE,
  REFUSAL_NO_OTHER_ROUTE,
} from "./session-node-types.js";

/**
 * Everything this module needs from the manager, stated explicitly rather than handed `this`.
 *
 * `db()` is a FUNCTION, not a value: the manager opens its database after construction, so a
 * snapshot taken at wiring time would be null forever.
 */
export interface RefusalContext {
  readonly logger: Logger;
  /**
   * ⚠️ A FUNCTION, because the manager opens its database AFTER construction — a value snapshotted
   * at wiring time would be null for the life of the process. The class re-exposes it as a private
   * getter (`#db`) so the moved code keeps saying `this.#db`, exactly as it did in the manager.
   */
  db(): DaemonDatabase | null;
  sessionKey(agentName: string, sessionId: string): string;
  requireAgentId(agentName: string): string;
  /** Cancels a pending leaf fetch. The timers stay the manager's — this side only says "stop". */
  cancelLeafFetch(sessionKey: string, contentHashHex: string): void;

  /**
   * The operator-facing refusal surface. Every refusal in this module reaches a READER through one
   * of these — a refusal whose only consumer is the log is not a control (M15 Invariant 2).
   */
  noteContentRefusal(
    agentName: string,
    sessionId: string,
    reason: string,
    detail: { kind: RefusalKind; impact: string; guidance: string },
  ): void;
  recordTranscriptMessage(
    agentName: string,
    sessionId: string,
    sequence: number,
    direction: "sent" | "received" | "quarantined",
    plaintext: Uint8Array,
    correlationId?: string,
    authorship?: { senderPubkey: Uint8Array; senderSig: Uint8Array },
    quarantineReason?: string,
    senderPubkeyHexOverride?: string | null,
  ): boolean;
  recordWitnessedSequence(agentName: string, sessionId: string, contentHashHex: string, sequenceNumber: number): void;
  getTier(agentName: string, pubkey: string): number;
  resolveTierBound(agentName: string, tier: number, field: "max_sessions" | "max_bytes"): number;
  /** Is there a relay mailbox this refusal could still arrive by? It changes what the operator is told. */
  mailboxRouteAvailable(agentName: string): boolean;
  receivedBytesTotal(agentName: string, sessionId: string): number;
  /**
   * Part 1's verifier. Ordering asks the same question of the RELAY's copy of the signature that the
   * content frame asks of the one carried beside the bytes — both must hold, and if they disagree
   * one of them was altered in flight.
   */
  verifyAuthorshipClaim(
    agentName: string,
    sessionId: string,
    structure1Cbor: Uint8Array,
    senderSignature: Uint8Array,
    contentHash: Uint8Array,
  ): AuthorshipVerdict;
}

export class InboundRefusals {
  readonly #ctx: RefusalContext;

  constructor(ctx: RefusalContext) {
    this.#ctx = ctx;
  }

  /**
   * ⚠️ A GETTER SO THE MOVED CODE IS UNCHANGED. Every query below still reads `this.#db` and still
   * narrows through `if (!this.#db) throw ...`, exactly as it did inside the manager. Rewriting
   * those to a call would have been a diff on every database access in this file for no behavioural
   * reason, and the narrowing would have had to become a null assertion — turning checked accesses
   * into unchecked ones at precisely the sites that do the checking.
   */
  get #db(): DaemonDatabase | null {
    return this.#ctx.db();
  }

  /**
   * Frames refused because they named a content-hash algorithm this build cannot read, keyed by
   * session → the refused frame's content hash → the name it used. Review F2, corrected by F-D.
   *
   * ⚠️ KEYED BY THE FRAME, NOT THE SESSION, and the first version was keyed by the session. That
   * made it fire on the NORMAL case: after one junk-alg frame, every subsequent park recovery on
   * that session logged a WARN forever, for entirely unrelated messages — and the text asserted the
   * two events were "the same message arriving twice by different routes", which nothing had
   * established. A warning that fires on the benign steady state is not a signal.
   *
   * Hash-keyed, the claim becomes a fact and the event fires exactly once per affected message: the
   * entry is removed the moment it is reconciled.
   */
  #unreadableAlgSeen = new Map<string, Map<string, string>>();

  /**
   * `DOD-M15-AUTHORSHIP-ABSENT-1` review H1, widened by `029c` review F4 — the content hashes this
   * side refused ON THE DIRECT PATH, for any reason, so the park path can say so when the same
   * message arrives the other way.
   *
   * One map rather than one per refusal: what the park path needs to know is "did we turn this
   * content away and tell somebody so", and the reason is already on the notice.
   *
   * **The silence this closes.** A direct-path refusal sends no delivery ACK, so the sender's TTF
   * backstop parks the message and it arrives through the relay mailbox seconds later — where the
   * ENVELOPE's signature is what authenticates it, and recovery correctly accepts it. So the
   * message is delivered, with no per-message proof, moments after the operator was told it was
   * refused. Nothing tied the two events together, which is the same shape the algorithm refusal
   * above already had and the same remedy.
   *
   * Same bounded shape and the same reason: it is fed entirely by a remote party, so losing an
   * entry costs one reconciliation line and an unbounded map would be a leak with a peer's hand on
   * the tap.
   */
  #refusedOnDirectPath = new Map<string, Set<string>>();

  /**
   * DOD-M15-REFUSALTERMINAL-1: content hashes refused for a reason no retry can get past — a READ
   * CACHE over `terminal_content_refusals`, never the record itself.
   *
   * ⚠️ **NOT the same fact as `#resolvedContent`, and collapsing them is the trap.** "Resolved"
   * means we HAVE the content. Terminally refused means we have it and are never accepting it.
   * Filing one under the other tells the next reader that refused content was delivered.
   */
  #terminallyRefused = new Map<string, Set<string>>();

  /** DOD-M15-REFUSALTERMINAL-1 review F3: when the load above last FAILED, per session. Bounds the
   *  retry and the ERROR to once a minute instead of once per witnessed leaf. */
  #terminalRefusalsReadFailedAt = new Map<string, number>();

  /** Sessions whose terminal-refusal rows have been read from the database into the map above.
   *  Nothing ever un-marks content, so a loaded set only grows and can never go stale. */
  #terminalRefusalsLoaded = new Set<string>();

  /**
   * DOD-M15-REFUSEDEVIDENCE-1 — RETAIN a message that was refused. Retention is universal; DELIVERY
   * is what is withheld.
   *
   * Every refusal path that can store calls this. It writes the plaintext, the sender's key, the
   * sender's signature and the refusal reason into the transcript, flagged `'quarantined'` so it is
   * excluded by construction from delivery and from unread counts.
   *
   * ⚠️ STORING HOSTILE CONTENT IS SAFE; INTERPOLATING IT IS NOT. The blob is a bound parameter and
   * the database never parses it — SQL injection is not the risk here and must not be defended
   * against. The risk is on the way OUT, so nothing below puts `content` into a log line, an error
   * message or a path. The log carries the length and the hash.
   *
   * Returns the sequence it was stored at, or `null` when it was not stored — which happens only for
   * a reason the caller is expected to log.
   */
  quarantineRefusedContent(
    agentName: string,
    sessionId: string,
    reason: string,
    content: Uint8Array,
    contentHashHex: string,
    opts: {
      senderPubkeyHex?: string | null;
      authorship?: { senderPubkey: Uint8Array; senderSig: Uint8Array };
      canonicalSeq?: number;
      correlationId?: string;
    },
  ): number | null {
    const sequence = this.retainRefusedContent(agentName, sessionId, reason, content, contentHashHex, opts);
    /**
     * DOD-M15-REFUSALTERMINAL-1 — **THE FUNNEL, and the reason it lives here.**
     *
     * Every refusal that retains evidence passes through this method carrying its reason and its
     * content hash, so this is the one place where "which reasons stop the work" can be a LIST
     * rather than a decision copied into seven branches. `TERMINAL_REFUSAL_REASONS` decides; the
     * six other reasons that reach here — a hash mismatch, an unreadable algorithm, a missing salt,
     * an unresolved sender, an orphaned session, a terminal screen block — all keep retrying, and
     * each of them can succeed on a later attempt.
     *
     * AFTER the retention, deliberately: the evidence has to exist before anything stops going to
     * look for the message.
     */
    this.considerTerminalRefusal(agentName, sessionId, contentHashHex, reason);
    return sequence;
  }

  /** DOD-M15-REFUSEDEVIDENCE-1: the retention itself. Reached only through the funnel above. */
  retainRefusedContent(
    agentName: string,
    sessionId: string,
    reason: string,
    content: Uint8Array,
    contentHashHex: string,
    opts: {
      /** The sender's key when this side resolved one. `null` is itself evidence. */
      senderPubkeyHex?: string | null;
      /** The VERIFIED authorship proof, when the frame carried one that checked out. */
      authorship?: { senderPubkey: Uint8Array; senderSig: Uint8Array };
      /** The relay-assigned position, for a refusal that DOES occupy one (a screener block). */
      canonicalSeq?: number;
      correlationId?: string;
    },
  ): number | null {
    if (!this.#db) return null;
    try {
      const agentId = this.#ctx.requireAgentId(agentName);
      /**
       * ⚠️ **DEDUP FIRST — review F1, and without it retention KILLS THE CONVERSATION IT PROTECTS.**
       *
       * Six of the seven retaining exits refuse WITHOUT ACKNOWLEDGING, which is exactly what makes
       * the sender's daemon redeliver. Each redelivery re-enters here, above the leaf dedup, and
       * would take a fresh negative sequence — another full copy of the same bytes. The park drain's
       * own comment measures that loop at *"~120 repeats per message, forever"*.
       *
       * **And retained bytes spend the delivery budget** (`#getReceivedBytesTotal` counts them, which
       * is what makes the bound honest). So a counterparty on a newer build sends ONE message, the
       * version skew refuses it un-acked, and twenty-five drains later the conversation's 25 MB is
       * gone — permanently, because the cap does not reset. Honest traffic then hits
       * `session_size_limit_exceeded` and the daemon tells the operator to start a new conversation.
       *
       * The counterbalance, stated properly this time: **evidence and delivery share one monotonic
       * budget, and when evidence wins the conversation stops working.** Entry 69 claimed there was
       * nothing to trade off, and this is what that claim was hiding.
       *
       * Keyed on (session, reason, bytes) rather than a hash column: SQLite compares BLOBs directly
       * and short-circuits on length, the candidate set is one session's refusals, and it needs no
       * schema change. Same bytes refused the same way is ONE piece of evidence — how many times it
       * arrived is already counted by the refusal notice. The same bytes refused for a DIFFERENT
       * reason is a different fact and keeps its own row.
       */
      const already = this.#db
        .prepare(
          `SELECT sequence FROM transcript
           WHERE agent_id = ? AND session_id = ? AND direction = 'quarantined'
             AND quarantine_reason = ? AND blob = ?`,
        )
        .get(agentId, sessionId, reason, Buffer.from(content)) as { sequence: number } | undefined;
      if (already) {
        this.#ctx.logger.debug("session.content.quarantine.duplicate", {
          agentName, sessionId, reason, sequence: already.sequence,
          contentHash: contentHashHex, correlationId: opts.correlationId,
        });
        return already.sequence;
      }
      /**
       * THE BOUND. A session at its byte cap retains no more.
       *
       * `senderPubkeyHex` is absent exactly when there is no session row or no counterparty
       * (`session_orphaned`, `sender_unresolved`), so there is no contact to look a tier up on. Those
       * take the UNKNOWN tier — the tightest bound, and the right one for a sender we cannot name.
       */
      const tier = opts.senderPubkeyHex ? this.#ctx.getTier(agentName, opts.senderPubkeyHex) : TIER.UNKNOWN;
      const cap = this.#ctx.resolveTierBound(agentName, tier, "max_bytes");
      const prior = this.#ctx.receivedBytesTotal(agentName, sessionId);
      if (prior + content.length > cap) {
        this.#ctx.logger.warn("session.content.quarantine.skipped", {
          agentName, sessionId, reason, contentHash: contentHashHex,
          bytes: content.length, prior, cap, tier,
          correlationId: opts.correlationId,
          skipped: "byte_budget_exhausted",
          impact: "this refused message was NOT retained: the conversation has already spent its storage budget, so there is no evidence of it beyond this line and the refusal notice.",
        });
        return null;
      }
      /**
       * WHERE IT SITS.
       *
       * A screener block already leafed at its canonical position, and the quarantine row takes that
       * same sequence so the leaf and the evidence describe one event — DoD 7's leaf index is
       * untouched by this unit.
       *
       * A refusal with NO leaf takes the next NEGATIVE sequence for the session. A leaf position is
       * never negative, so the two spaces cannot collide, and descending from −1 means two refusals
       * cannot overwrite each other. This is what lets `session_orphaned` — a session id with no
       * `sessions` row at all — live in the same table as everything else, which is the whole point
       * of one store rather than two.
       */
      let sequence = opts.canonicalSeq;
      if (sequence === undefined || sequence < 0) {
        const low = this.#db
          .prepare("SELECT MIN(sequence) AS lo FROM transcript WHERE agent_id = ? AND session_id = ? AND direction = 'quarantined'")
          .get(agentId, sessionId) as { lo: number | null };
        sequence = Math.min(low.lo ?? 0, 0) - 1;
      }
      const stored = this.#ctx.recordTranscriptMessage(
        agentName, sessionId, sequence, "quarantined", content, opts.correlationId,
        opts.authorship, reason, opts.senderPubkeyHex ?? null,
      );
      if (!stored) return null;
      this.#ctx.logger.info("session.content.quarantined", {
        agentName, sessionId, reason, sequence,
        contentHash: contentHashHex, bytes: content.length,
        signature: opts.authorship ? "verified" : "none",
        correlationId: opts.correlationId,
      });
      return sequence;
    } catch (err: unknown) {
      this.#ctx.logger.error("session.content.quarantine.failed", {
        agentName, sessionId, reason, contentHash: contentHashHex,
        error: extractErrorMessage(err),
        impact: "a refused message could not be retained, so nothing holds a copy of it — it cannot be shown to anyone or reported.",
      });
      return null;
    }
  }

  /**
   * DOD-M15-REFUSALTERMINAL-1 — the funnel. A refusal stops the work ONLY if its reason is in
   * `TERMINAL_REFUSAL_REASONS`; every other reason keeps retrying, which is what makes a transient
   * screener block or a version skew recoverable.
   *
   * One place decides, so "is this reason terminal?" is answerable from the set rather than from
   * thirteen call sites.
   */
  considerTerminalRefusal(agentName: string, sessionId: string, contentHashHex: string, reason: string): void {
    if (!TERMINAL_REFUSAL_REASONS.has(reason)) return;
    this.markContentTerminallyRefused(agentName, sessionId, contentHashHex, reason);
  }

  /**
   * DOD-M15-REFUSALTERMINAL-1: this content can NEVER be accepted on this session — cancel the
   * pending fetch and make sure no future one is scheduled, across restarts.
   *
   * The durable write comes FIRST and the in-memory cache second, so a process that dies between
   * them wakes up with the stop still in force. A failed write is announced at ERROR and the
   * in-memory mark is still taken: the loop stops for the life of THIS process, and the log says
   * plainly that it will resume after a restart. That is a degraded stop, not a silent one.
   */
  markContentTerminallyRefused(agentName: string, sessionId: string, contentHashHex: string, reason: string): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    /**
     * Read BEFORE the write, so the announcement below fires on the TRANSITION rather than on every
     * re-refusal. The same message can be refused again by a drain triggered for another reason, and
     * an INFO line per repeat is a smaller version of the noise this unit exists to remove.
     *
     * The durable write is still ATTEMPTED every time, deliberately: `INSERT OR IGNORE` costs
     * nothing when the row is already there, and skipping it would mean a write that failed once —
     * the branch that logs the error below — never got another chance to succeed.
     */
    const alreadyKnown = this.isTerminallyRefused(agentName, sessionId, contentHashHex);
    try {
      if (!this.#db) throw new Error("database is not open");
      const agentId = this.#ctx.requireAgentId(agentName);
      this.#db
        .prepare(
          `INSERT OR IGNORE INTO terminal_content_refusals
             (agent_id, session_id, content_hash, reason, marked_at)
           VALUES (?, ?, ?, ?, ?)`,
        )
        .run(agentId, sessionId, contentHashHex, reason, Date.now());
      /**
       * ⚠️ **BOUNDED, because the counterparty chooses how many rows exist — review F7.**
       *
       * One row per distinct content hash aimed at a closed conversation, and the funnel that calls
       * this runs even when the byte cap has already stopped RETENTION. So a peer who has exhausted
       * the session's storage budget can still write rows here, indefinitely, on a table nothing
       * else deletes. Every sibling store in this file is bounded (`MAX_UNREADABLE_ALG_FRAMES`, the
       * tier byte cap, `MAX_REFUSAL_READERS`); this one was not.
       *
       * Oldest-dropped, so the newest refusals keep their stop and the loop stays closed for what
       * is arriving now. A dropped row costs at most one extra fetch for content nobody is sending
       * any more — the pre-fix behaviour for that one hash, and nothing worse.
       */
      const dropped = this.#db
        .prepare(
          `DELETE FROM terminal_content_refusals
            WHERE agent_id = ? AND session_id = ? AND content_hash NOT IN (
              SELECT content_hash FROM terminal_content_refusals
               WHERE agent_id = ? AND session_id = ?
               ORDER BY marked_at DESC LIMIT ${MAX_TERMINAL_REFUSALS_PER_SESSION}
            )`,
        )
        .run(agentId, sessionId, agentId, sessionId);
      if (Number(dropped.changes) > 0) {
        // Loud, because it means a counterparty has aimed more than the cap's worth of distinct
        // messages at one closed conversation — which is abuse, not ordinary traffic.
        this.#ctx.logger.warn("session.content.terminal_refusal.evicted", {
          agentName, sessionId, dropped: Number(dropped.changes),
          cap: MAX_TERMINAL_REFUSALS_PER_SESSION,
          impact:
            "more distinct messages have been refused on this closed conversation than the cap keeps a record of, so the oldest stops were dropped. If one of those arrives again it costs one wasted fetch; nothing is delivered and nothing is lost.",
        });
      }
    } catch (err: unknown) {
      this.#ctx.logger.error("session.content.terminal_refusal.persist.failed", {
        agentName, sessionId, reason,
        contentHash: contentHashHex,
        error: extractErrorMessage(err),
        impact:
          "this message can never be accepted on this conversation, and that fact could not be written down. Fetching for it stops while this daemon runs, and RESUMES after the next restart — which is the loop that filled a log with a quarter of a million refusals for one message.",
        guidance:
          "This is a fault on THIS machine, not with the counterparty. Check free disk space and the permissions on ~/.cello; session.refusal.persist.failed in this log usually appears alongside it with the underlying error.",
      });
    }
    let set = this.#terminallyRefused.get(key);
    if (!set) { set = new Set(); this.#terminallyRefused.set(key, set); }
    set.add(contentHashHex);
    // The same cancellation `#markContentResolved` performs, for the opposite fact: an already-armed
    // grace timer must not fire for content we have just decided never to accept.
    this.#ctx.cancelLeafFetch(key, contentHashHex);
    if (!alreadyKnown) {
      this.#ctx.logger.info("session.content.terminal_refusal", {
        agentName, sessionId, reason,
        contentHash: contentHashHex,
        impact:
          "no further attempt will be made to fetch this message. The conversation it was sent to is closed and signed, so no retry could ever have succeeded.",
      });
    }
  }

  /**
   * DOD-M15-REFUSALTERMINAL-1: has this content already been refused terminally?
   *
   * Reads the durable rows for a session ONCE and caches them, so the hot path — a witnessed leaf
   * on a healthy session — costs one `Set` lookup rather than a query per message. A read failure
   * returns `false`: the cost is the loop continuing, which is the pre-fix behaviour, and it is
   * announced rather than swallowed. Answering `true` on a failed read would be the dangerous
   * direction, because it silently stops fetching content that was never refused.
   */
  isTerminallyRefused(agentName: string, sessionId: string, contentHashHex: string): boolean {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    /**
     * ⚠️ **A FAILING READ MUST NOT BE RETRIED PER MESSAGE — review F3.**
     *
     * The loaded flag is set only on success, so a database that throws (a full disk, a corrupt
     * page) sent this method back to SQLite on EVERY witnessed leaf, logged an ERROR each time, and
     * — because nothing was ever cached — made `alreadyKnown` false forever, so the mark's INFO
     * fired on every refusal too. That is the ~2/s log growth this unit exists to end, reproduced
     * by its own fix in the failure mode.
     *
     * Backed off instead: one attempt per session per minute, so the read still recovers when the
     * disk does, and the ERROR is bounded rather than proportional to traffic.
     */
    const failedAt = this.#terminalRefusalsReadFailedAt.get(key);
    const backedOff = failedAt !== undefined && Date.now() - failedAt < TERMINAL_REFUSAL_READ_RETRY_MS;
    if (!this.#terminalRefusalsLoaded.has(key) && !backedOff && this.#db) {
      try {
        const rows = this.#db
          .prepare("SELECT content_hash FROM terminal_content_refusals WHERE agent_id = ? AND session_id = ?")
          .all(this.#ctx.requireAgentId(agentName), sessionId) as Array<{ content_hash: string }>;
        let set = this.#terminallyRefused.get(key);
        if (!set) { set = new Set(); this.#terminallyRefused.set(key, set); }
        for (const r of rows) set.add(r.content_hash);
        this.#terminalRefusalsLoaded.add(key);
        this.#terminalRefusalsReadFailedAt.delete(key);
      } catch (err: unknown) {
        this.#terminalRefusalsReadFailedAt.set(key, Date.now());
        this.#ctx.logger.error("session.content.terminal_refusal.read.failed", {
          agentName, sessionId,
          error: extractErrorMessage(err),
          retryInMs: TERMINAL_REFUSAL_READ_RETRY_MS,
          impact:
            "the record of messages this conversation can never accept could not be read, so this daemon may keep fetching one of them. Nothing is lost; the cost is repeated work and log noise. The read is retried once a minute rather than on every message, so this line is bounded — its absence for a while does NOT mean the fault cleared.",
          guidance:
            "This is a fault on THIS machine, not with any counterparty. Check free disk space and the permissions on ~/.cello; the error above carries SQLite's own message.",
        });
      }
    }
    return this.#terminallyRefused.get(key)?.has(contentHashHex) === true;
  }

  /**
   * 024-ORPHANTRIAGE — the three signals, read from evidence this side owns.
   *
   * ⚠️ **THE SEQUENCE NUMBER ON THE FRAME IS NOT ONE OF THEM.** "Was there an ongoing conversation
   * up to this point" is tempting to answer from the position the sender wrote, and that answer is
   * worthless: the sender picks the number, so anyone wanting the reach-out branch writes a large
   * one. It is answered from OUR transcript rows instead — a partial local record of that
   * conversation is something an attacker cannot put there from the wire.
   *
   * ⚠️ **"KNOWN" IS A TIER, NOT A ROW — review F1/F2, and reading it as a row inverted the unit.**
   * `contacts` rows are written from the WIRE with no operator action: `inbound-sessions.ts` calls
   * `addContact(..., "signal_presentation")` at `TIER.UNKNOWN` for any inbound offer inside the
   * acceptance bound, because the trust-signal foreign key needs a row to point at. And BLOCKING a
   * contact is an UPDATE to `TIER.BLOCKED`, so the row survives that too. A `SELECT … WHERE pubkey`
   * therefore answers "yes, known" for a stranger who merely dialled, AND for a key the operator
   * deliberately blocked — handing both the reach-out branch, which is the exact population this
   * unit exists to refuse. `DOD-TIER-4` had already settled this and retired `isContact` for it:
   * *"An UNKNOWN-tier contact (a mere row) is NOT known."* The tier is read from the row already
   * being fetched, so the case-insensitivity below survives (`getTier` compares case-sensitively).
   *
   * ⚠️ **HEX CASE IS NOT A DIFFERENCE IN IDENTITY.** This unit originally worked around that with its
   * own `lower(pubkey)` lookup, because `contacts.pubkey` was stored verbatim from the IPC parameter
   * and an exact match would report a contact the operator can SEE in `cello_contacts` as an unknown
   * stranger. The workaround is gone: `contact-pubkey-case.ts` now normalizes every contacts
   * accessor and folds the rows already on disk, so there is one spelling and one rule.
   */
  orphanEvidence(
    agentName: string,
    sessionId: string,
    verifiedSignerUnmatched: Uint8Array | undefined,
  ): OrphanEvidence {
    const signerPubkeyHex = verifiedSignerUnmatched === undefined
      ? null
      : Buffer.from(verifiedSignerUnmatched).toString("hex");
    /**
     * ⚠️ `"not_checked"` IS NOT A COSMETIC THIRD STATE — review F6.
     *
     * These two were `false` on every path that did not look, and the log event then reported them
     * as readings. An investigator filtering `session.content.orphaned` days later would read
     * `ongoingConversation: false` and conclude there was no local trace, when nothing had been
     * asked. Clause 1 says the branch RECORDS these; a default wearing the shape of a measurement
     * is not a record, and it is the cheapest possible way to mislead the one person who comes
     * looking.
     */
    const notChecked: OrphanEvidence = {
      signerPubkeyHex, knownContact: "not_checked", contactMoniker: null, ongoingConversation: "not_checked",
    };
    // With no verifiable signature the other two signals mean nothing — a claimed key is a string
    // anyone can type — so they are not looked up at all rather than looked up and ignored.
    if (signerPubkeyHex === null) return notChecked;
    try {
      /**
       * ⚠️ NO `!this.#db` SHORT-CIRCUIT — review F7, and it was the silent half of this guard.
       *
       * The catch below logs ERROR for exactly this outcome; a bare `if (!this.#db) return` did not,
       * and the state is reachable while the operator still gets a notice — `noteContentRefusal`
       * keeps its own in-memory fallback when the write fails, so a daemon with an unusable store
       * still surfaces a refusal saying "that key is not in your address book" about a key that may
       * well be in it, with nothing anywhere recording that the address book was never opened.
       * Throwing into the catch is also what this file's other contact reads do (`getTier`,
       * `addContact`), and for the same reason: a read that decides how to treat a sender must not
       * degrade to "unclassified" in silence.
       */
      if (!this.#db) throw new Error("database is not open");
      const agentId = this.#ctx.requireAgentId(agentName);
      const contact = this.#db
        .prepare("SELECT moniker, tier FROM contacts WHERE agent_id = ? AND pubkey = ?")
        .get(agentId, normalizeContactPubkey(signerPubkeyHex)) as { moniker: string | null; tier: number | null } | undefined;
      /**
       * ⚠️ **QUARANTINED ROWS ARE NOT A LOCAL TRACE, AND WITHOUT THIS CLAUSE THE PROBE WRITES ITS
       * OWN EVIDENCE.** Found where `023-REFUSEDEVIDENCE` met `024-ORPHANTRIAGE`.
       *
       * This signal answers *"does this machine hold any part of a conversation under the id the
       * message names?"*, and a `true` is one of the two conditions that flips the triage from
       * REPORT-ONLY to offering the operator a reach-out. Since 023, a refused message is RETAINED
       * as a transcript row — so an unfiltered `SELECT 1 FROM transcript` sees the row this very
       * refusal just wrote.
       *
       * From the operator's chair, unfiltered: a stranger with a vouched key probes an id nobody
       * opened; the first probe is refused and retained; the second probe finds the first one's row,
       * reads as an ongoing conversation, and the operator is invited to reach out. **The attacker
       * manufactures the signal by sending twice** — which is precisely the outcome 024 exists to
       * prevent, reintroduced by the unit that made evidence durable.
       *
       * `direction != 'quarantined'` is the same exclusion every delivery reader uses, and it is the
       * right one: what is asked here is whether anything was ever DELIVERED under this id.
       */
      const trace = this.#db
        .prepare("SELECT 1 AS present FROM transcript WHERE agent_id = ? AND session_id = ? AND direction != 'quarantined' LIMIT 1")
        .get(agentId, sessionId) as { present: number } | undefined;
      return {
        signerPubkeyHex,
        knownContact: contact !== undefined && normalizeTier(contact.tier) >= TIER.KNOWN,
        contactMoniker: contact?.moniker ?? null,
        ongoingConversation: trace !== undefined,
      };
    } catch (err: unknown) {
      /**
       * NOT A SILENT FALLBACK. Both signals come back `"not_checked"`, which the triage treats
       * exactly as it treats a stranger — REPORT, the action that is safe when nothing is known — and
       * which the log distinguishes from a measured `false`. A read failure here must never invent
       * the reach-out branch, and it must never be invisible.
       */
      this.#ctx.logger.error("session.content.orphaned.evidence.failed", {
        agentName, sessionId,
        error: extractErrorMessage(err),
        impact: "the address book and transcript could not be read, so a message whose signature DID verify is being reported to the operator as coming from a key nothing is known about. The advice is the safe one; it may be more cautious than the evidence warrants.",
      });
      return notChecked;
    }
  }

  /**
   * `DOD-M15-AUTHORSHIP-ABSENT-1` — the refusal an inbound frame gets when its authorship cannot be
   * established. NOT a freeze: see `AuthorshipVerdict` for why those are different facts.
   *
   * Both surfaces, always. The ERROR is the durable forensic record an investigation reads days
   * later; the notice is the CONTROL — the thing that actually reaches the operator, who otherwise
   * watches a conversation go quiet and concludes the other person stopped replying.
   */
  refuseUnprovenAuthorship(
    agentName: string,
    sessionId: string,
    reason: "authorship_proof_absent" | "authorship_proof_unusable" | "authorship_wrong_conversation"
      | typeof AUTHORSHIP_SELF_CHAIN_MISMATCH | AckHashReason,
    contentHash: Uint8Array,
    detail: Record<string, unknown>,
    correlationId?: string,
  ): void {
    /**
     * ⚠️ **THREE REASONS, THREE SENTENCES — AND THE THIRD USED TO BORROW THE SECOND'S** (review of
     * `029b`, and it is the operator half of the same finding as the check order).
     *
     * A replayed claim is the one branch on this path that is potentially ADVERSARIAL: a real,
     * valid, correctly-signed line of your counterparty's, presented in a conversation it was not
     * written for. It was reaching the operator under the `unusable` wording, which says the proof
     * was "unreadable, or signed over different content" — neither is true — and under guidance
     * telling them to go and ask their counterparty to upgrade. A version number is not the
     * question, and sending someone to chase one spends their attention on the wrong thing.
     */
    const impact =
      reason === "authorship_proof_absent"
        ? "a message arrived carrying no proof of who wrote it, so it was NOT ingested, NOT shown and NOT attributed to anyone. Every message in this conversation has to be provable to whoever reads its receipt later, and this one could not be."
        : reason === "authorship_wrong_conversation"
          ? "a message arrived carrying a VALID signature by this conversation's counterparty — made for a DIFFERENT conversation. The same message, or an old one of theirs, was presented here. It was NOT ingested, NOT shown and NOT added to this conversation's record."
          /**
           * 033-ACKEMIT. Says what was OBSERVED — the two records disagree about what was said —
           * and stops there. It does NOT say the counterparty is lying: the same signal is what a
           * genuine fault on their side looks like, and naming a conclusion the code did not reach
           * is the error-fidelity defect this milestone was opened for.
           */
          /**
           * ⚠️ THREE CAUSES, THREE SENTENCES — review F5. They shared one, and it described none of
           * them properly: an ABSENT acknowledgement has no part that "does not match", because it
           * has no part at all.
           *
           * All three say what was OBSERVED and stop there. None says the counterparty is lying:
           * the same signal is what a genuine fault on their side looks like, and naming a
           * conclusion the code did not reach is the error-fidelity defect this milestone exists
           * for.
           */
          /**
           * `DOD-M15-SELFCHAIN-1` — THE ORDER, NOT THE CONTENT, AND IT NEEDS ITS OWN WORDS.
           *
           * This reached the operator under the generic `authorship_proof_unusable` sentence, which
           * says the proof was "unreadable, or signed over different content". Neither is true: the
           * proof is perfect and it is about this conversation. What is in dispute is WHERE this
           * message sits — and telling someone their decoder failed sends them to audit the wrong
           * subsystem entirely. The reason's own comment claimed it was "named apart from the
           * acknowledgement reasons"; the surface collapsed it back, which is error substitution on
           * the strongest evidence this protocol can produce.
           */
          : reason === AUTHORSHIP_SELF_CHAIN_MISMATCH
            ? "a message arrived that is genuinely from your counterparty, about this conversation, and correctly signed — and it names a message of THEIR OWN that they never sent you. Each message says which of their own came before it, and that is what fixes the ORDER of the conversation. This one points somewhere your record has never been. It was NOT ingested and NOT shown."
          : reason === AUTHORSHIP_ACK_HASH_MISMATCH
            ? "a message arrived that is genuinely from your counterparty — and it names a DIFFERENT message of yours in the position where your own record holds one. Both sides agree the message exists; you disagree about which one sits there. It was NOT ingested and NOT shown."
          : reason === AUTHORSHIP_ACK_HASH_UNKNOWN
            ? "a message arrived that is genuinely from your counterparty — and it says they received something from you that this side has no record of ever holding. It was NOT ingested and NOT shown. This is the check that stops someone quietly rewriting what was said before the receipt is made."
            : "a message arrived whose proof of authorship could not be checked against it — it was unreadable, or it was signed over different content. It was NOT ingested, NOT shown and NOT attributed to anyone.";
    /**
     * ⚠️ THE VERB IS THE COUNTERPARTY'S, AND THE GUIDANCE SAYS SO. The reader is the RECEIVING
     * operator, and there is nothing on their machine to change — the missing signature is produced
     * on the sender's. Telling them to do something local would be an affordance that resolves to
     * nothing. So it names the one move that works (tell them to upgrade) and the one that settles
     * the other explanation (confirm out of band), and it stops at two.
     *
     * ⚠️ **IT USED TO OPEN "Nothing was shown and nothing was stored." THAT SENTENCE WAS FALSE** —
     * review H1, and it is kept here rather than deleted because it is the exact shape this
     * milestone exists to catch: a refusal that announces a stronger outcome than it delivers.
     *
     * Refusing sends no delivery ACK, so the sender's TTF backstop parks the message and it arrives
     * through the relay mailbox seconds later, where the ENVELOPE's signature authenticates it and
     * recovery accepts it — correctly, and with no per-message proof. So the message may well be
     * delivered, moments after the operator was told it was not. The reconciliation is logged
     * (`content.recover.refusal_reconciled`) and the sentence below now says what is
     * actually true of this path: nothing was shown YET, and this refusal does not stop the copy
     * coming the other way.
     */
    const guidance = reason === "authorship_wrong_conversation"
      ? "STOPPED ON PURPOSE, and this one is NOT a version problem — do not go and ask them about " +
        "their build. The signature is real and it is theirs; what is wrong is that it was made for " +
        "another conversation, so something replayed it into this one. That is either software on " +
        "one of your machines re-sending an old message into the wrong session, or someone in " +
        "between doing it deliberately. ONE thing to do: ask your counterparty OUT OF BAND (a " +
        "channel that is not this one) whether they meant to send this, before you continue here."
      /**
       * ⚠️ **THIS BRANCH SHIPPED AS `NaNcopy in the relay mailbox…` AND NOTHING NOTICED** — review
       * F1, and it is worth more than the one-line fix.
       *
       * Splitting the guidance in two dropped the opening literal and left behind the `+` that had
       * joined it, which is not a concatenation with nothing on its left — it is a UNARY PLUS on the
       * next string. `+"REACH YOU BY…"` is `NaN`, and `NaN + "copy in the relay mailbox…"` is a
       * perfectly good string. So the flagship refusal of this whole milestone reached the operator
       * beginning mid-word with `NaN`, with its "STOPPED ON PURPOSE" framing and its reason gone.
       *
       * **The test was green because it asked the wrong question.** The only assertion on this
       * string was `.toMatch(/upgrade/i)`, and "tell them to upgrade" survives at the tail. A
       * substring match on a sentence cannot see that the sentence lost its head — so the assertion
       * below pins what it OPENS with, which a truncation cannot survive.
       */
      /**
       * 033-ACKEMIT — TWO PATHS, AND THE FIRST IS THE ONE THAT ACTUALLY HAPPENS.
       *
       * Capped at two (Invariant 4): an affordance list that enumerates everything is a menu. The
       * verb is the counterparty's in both cases — there is nothing to change on this machine — so
       * it names the one move that fixes the likely cause and the one that settles the other.
       */
      /**
       * ⚠️ AND THREE REMEDIES, because the shared one was WRONG for two of the three. It told the
       * reader their counterparty's build was probably old — which is impossible for a claim that
       * carries an acknowledgement, since only a newer build sends one — and then told them to
       * abandon the conversation. Two is the cap on each (Invariant 4); the verb is the
       * counterparty's in every case, because there is nothing to change on this machine.
       */
      : reason === AUTHORSHIP_SELF_CHAIN_MISMATCH
      ? "STOPPED ON PURPOSE, and this is the most serious of these refusals. " +
        (this.#ctx.mailboxRouteAvailable(agentName) ? REFUSAL_MAY_STILL_ARRIVE : REFUSAL_NO_OTHER_ROUTE) +
        " Their signature is real and it is about this conversation. What does not hold is the " +
        "ORDER: this message names one of their own as the one before it, and that message was " +
        "never sent to you. Either something between you is rearranging what they say, or their " +
        "agent's record of what it has said went out of step. THIS SESSION IS NOW FROZEN — no " +
        "further message on it will be accepted, because carrying on writes a disputed order into " +
        "the receipt. Reach them OUT OF BAND — a channel that is not this one — and ask them to " +
        "read back the last few things they sent you. If it matches what you have, open a NEW " +
        "session; if it does not, do not."
      /**
       * ⚠️ THESE TWO SHARED ONE SENTENCE, AND THE TEST THAT WAS MEANT TO CATCH THAT COULD NOT SEE
       * IT — `DOD-M15-SELFCHAIN-1`.
       *
       * The file's thesis is "three causes, three sentences", and it compared ABSENT against
       * MISMATCH and stopped. Mismatch and unknown-content shared a remedy the whole time; the pair
       * was never compared, so the defect the test existed for was live inside it.
       *
       * They are not the same situation. A MISMATCH means you both agree a message sits at that
       * position and disagree about which one — a record that has drifted. UNKNOWN CONTENT means
       * they are acknowledging something this side never held at all, which is the shape of content
       * being attributed to you that you did not send. The second is the more serious reading and
       * the operator's next move differs, so it gets its own sentence.
       */
      : reason === AUTHORSHIP_ACK_HASH_MISMATCH
      ? "STOPPED ON PURPOSE, and this is NOT about their signature or their version — both are " +
        "fine. " +
        (this.#ctx.mailboxRouteAvailable(agentName) ? REFUSAL_MAY_STILL_ARRIVE : REFUSAL_NO_OTHER_ROUTE) +
        " Your record of this conversation and theirs have stopped agreeing about what you sent " +
        "them. Confirm with them OUT OF BAND what they actually received from you. If it matches " +
        "what you sent, this was a fault and a new session will clear it; if it does not, do not " +
        "carry on in this one."
      : reason === AUTHORSHIP_ACK_HASH_UNKNOWN
      ? "STOPPED ON PURPOSE, and this one is more serious than a record that has drifted. " +
        (this.#ctx.mailboxRouteAvailable(agentName) ? REFUSAL_MAY_STILL_ARRIVE : REFUSAL_NO_OTHER_ROUTE) +
        " They are acknowledging a message from you that this side has NEVER held — not at that " +
        "position, not anywhere. Either their record contains something you did not send, or " +
        "yours is missing something you did. Ask them OUT OF BAND to read you back what they " +
        "believe you sent. Do not continue this conversation until you know which of the two it " +
        "is: carrying on writes their version into the receipt."
      : "STOPPED ON PURPOSE. This copy was refused and the message itself was not kept. " +
      // Review F2: chosen from what THIS machine can do, not asserted. An agent with no identity
      // key cannot open a mailbox copy either, and telling them to wait for one would be the same
      // false promise on a different refusal.
      (this.#ctx.mailboxRouteAvailable(agentName) ? REFUSAL_MAY_STILL_ARRIVE : REFUSAL_NO_OTHER_ROUTE) +
      " Almost always their CELLO build is older than this one: a build from before message signing " +
      "does not attach a signature at all. Ask which version they are running, and tell them to " +
      "upgrade — this will keep happening until they do, and only they can fix it. If they are on " +
      "the SAME version as you, that explanation does not hold: confirm with them OUT OF BAND " +
      "before opening another session.";
    this.#ctx.logger.error("session.content.refused", {
      agentName, sessionId, correlationId, reason, ...detail, impact, guidance,
    });
    this.#ctx.noteContentRefusal(agentName, sessionId, reason, { kind: REFUSAL_KINDS.REFUSED, impact, guidance });
    // Armed AFTER the refusal is filed, so the memo can never claim a refusal that did not happen.
    this.noteRefusedOnDirectPath(agentName, sessionId, contentHash);
  }

  recordFrameOrdering(
    agentName: string,
    sessionId: string,
    structure1Cbor: Uint8Array,
    structure2Cbor: Uint8Array,
    contentHash: Uint8Array,
    correlationId?: string,
    source: string = "content_frame",
    // DOD-FRONTIER-STRAND-1 AC1: RETURNS the verified canonical position so the caller hands it
    // straight to ingest. It was void, and the position was only stashed in the hash-keyed
    // #witnessedSeq map — which cannot hold two positions for one hash, so two identical
    // messages collapsed there before dedup ran. Returning it is what makes per-message dedup
    // possible at all.
    //
    // DOD-M15-FRAME-1: `null` no longer says enough. It meant "no position" for six different
    // reasons, two of which are PROOF THAT THE SIGNER IS NOT WHO THIS SESSION IS WITH — and the
    // caller treated all six alike and ingested the content regardless. The check ran, answered
    // correctly, and its answer was thrown away.
    //
    // `fatal` separates the two questions Invariant 2 keeps apart: sequence POSITION may stay soft
    // (a missing ordering record is the documented relay-degraded path and refusing it would make
    // the relay a precondition for reading mail), while IDENTITY may never be. A bad signature, or
    // a signature by a key that is not this session's counterparty, is an identity failure that the
    // sender supplied and that we verified — not an absence we could not resolve.
    // `DOD-M15-AUTHORSHIP-ABSENT-1` — THE AUTHORSHIP FIELDS ARE GONE FROM THIS RETURN, and their
    // absence is the point rather than a tidy-up. This method used to be the only place that
    // verified a signer, so the content frame had to take its proof from here; the proof now
    // arrives on the frame beside the bytes it signs and is verified before this is ever called.
    // Returning a second copy would give the caller two answers to one question, and the day they
    // disagreed the caller would have picked whichever it read first.
  ): {
    seq: number | null;
    fatal?: { reason: string };
  } {
    try {
      const s2 = decode(structure2Cbor) as unknown[];
      const seq = typeof s2?.[0] === "number" ? s2[0] : -1;
      const s2Sig = s2?.[3];
      if (!(s2Sig instanceof Uint8Array) || seq < 1) {
        // SOFT: we could not read the record, so we learned nothing about the signer either way.
        // Position falls back to the witness stream, exactly as an absent record does.
        // The Structure 1 reason is carried so an unreadable RECORD and an unnamed LAYOUT are
        // distinguishable in the log — they arrive at the same soft outcome by different routes.
        const s1Layout = decodeStructure1(structure1Cbor);
        this.#ctx.logger.warn("session.content.ordering.malformed", {
          sessionId,
          correlationId,
          ...(s1Layout.ok ? {} : { structure1Reason: s1Layout.reason }),
        });
        return { seq: null };
      }
      /**
       * `DOD-M15-AUTHORSHIP-ABSENT-1` — the same verifier the content frame uses, handed the
       * signature the RELAY committed (`structure2_cbor` index 3) instead of the one the frame
       * carries. Two claims about the same message, and both must hold: if the relay's copy of the
       * sender's signature does not verify against the bytes on the frame, one of them has been
       * altered in flight.
       *
       * The verdicts map to this path's own severities, which are NOT the content frame's:
       * an `unusable` record leaves POSITION unknown and is soft here, because position may always
       * fall back to the witness stream. Identity is the half that may never be soft, and it is
       * established before this is called.
       */
      const auth = this.#ctx.verifyAuthorshipClaim(agentName, sessionId, structure1Cbor, s2Sig, contentHash);
      if (auth.verdict === "unusable") {
        /**
         * ⚠️ **THE ACK CAUSES REACH THIS PATH TOO, AND THEY ARE NOT A DECODER PROBLEM** — review F7.
         *
         * `#verifyAuthorshipClaim` has two callers. This one is reached from park RECOVERY, where
         * it is the only authorship check that runs — so 033-ACKEMIT's acknowledgement causes
         * started arriving here and fell into the generic `else` below, which logs
         * `…ordering.malformed` and buries the cause in `structure1Reason`. That event name sends
         * the next reader to audit a decoder for a record that decoded perfectly.
         *
         * SOFT, like every other `unusable` on this path, and deliberately: position may always
         * fall back to the witness stream, and a recovered parked message is authenticated by the
         * ENVELOPE's own signature rather than by this. What changes is that the log says which
         * thing disagreed.
         */
        if (ACK_HASH_REASONS.has(auth.reason)) {
          this.#ctx.logger.warn("session.content.ordering.ack_hash_unverified", {
            sessionId, correlationId, reason: auth.reason,
            impact:
              "a recovered message's acknowledgement of what its sender had received does not " +
              "reconcile with this side's record, so no canonical POSITION was taken from it. The " +
              "message itself is authenticated by its park envelope and is not refused here.",
          });
        } else if (auth.reason === AUTHORSHIP_CONTENT_HASH_MISMATCH) {
          // SOFT: the record does not describe this content. Nothing is proven about the signer's
          // identity — only that this record and these bytes do not belong together.
          this.#ctx.logger.warn("session.content.ordering.hash_mismatch", { sessionId, correlationId });
        } else if (auth.reason === AUTHORSHIP_SESSION_MISMATCH) {
          // Its own name, because `…malformed` points a reader at a decoder and this record decoded
          // perfectly — it belongs to another conversation. Unreachable in practice on this path:
          // `authenticateParkedEntry` binds `session_id` in the park TBS before anything is
          // unsealed, so a mismatched record cannot get this far. Named anyway, because an event
          // that lies about its cause is worse the day it does fire.
          this.#ctx.logger.warn("session.content.ordering.session_mismatch", { sessionId, correlationId });
        } else {
          this.#ctx.logger.warn("session.content.ordering.malformed", {
            sessionId, correlationId, structure1Reason: auth.reason,
          });
        }
        return { seq: null };
      }
      if (auth.verdict === "refuted" && auth.reason === "bad_signature") {
        // FATAL. The sender supplied a signature and it does not verify against the key inside its
        // own record. That is not an absence we could not resolve — it is a proof that failed.
        this.#ctx.logger.warn("session.content.ordering.bad_signature", { sessionId, correlationId });
        return { seq: null, fatal: { reason: "bad_signature" } };
      }
      // Sovereign-node cross-check: the signer MUST be THIS session's counterparty, not an unrelated
      // key. FAIL CLOSED (review L) — if the counterparty pubkey is unknown we cannot prove the signer,
      // so we do NOT trust the framed ordering record (fall back to the witness stream / arrival). The
      // "B does not trust the counterparty for ordering" invariant is non-negotiable; never fail open.
      if (auth.verdict !== "verified") {
        /**
         * FATAL when the counterparty is KNOWN and the signer is someone else (`refuted`). SOFT when
         * we simply do not know who the counterparty is (`verified_unmatched`) — the reasoning for
         * both, and the MITM substitution this catches, lives on `#verifyAuthorshipClaim`.
         *
         * The soft half is the one that matters HERE: `counterparty_unknown` means we cannot prove
         * the signer either way, so we decline to take a POSITION from a record we cannot attribute,
         * and the caller falls back to the witness stream. Nothing about the message is refused on
         * this path — that decision was already made, on the frame's own proof.
         */
        const reason = auth.verdict === "refuted" ? auth.reason : "counterparty_unknown";
        this.#ctx.logger.warn("session.content.ordering.wrong_signer", { sessionId, reason, correlationId });
        return auth.verdict === "refuted" ? { seq: null, fatal: { reason } } : { seq: null };
      }
      // Verified — record the relay-assigned canonical sequence (1-based → 0-based leaf index) for the gate.
      this.#ctx.recordWitnessedSequence(agentName, sessionId, Buffer.from(contentHash).toString("hex"), seq - 1);
      this.#ctx.logger.info("session.content.ordering.recorded", {
        sessionId,
        canonicalSeq: seq - 1,
        source,
        correlationId,
      });
      /**
       * THE POSITION, AND ONLY THE POSITION — `DOD-M15-AUTHORSHIP-ABSENT-1`.
       *
       * `DOD-M15-SEALWIRE-1` bullet 5 had this return the verified proof as well, because this was
       * the only place a signer was ever checked and the transcript row needed it from somewhere.
       * The frame now carries the sender's signature beside the bytes it signs and the caller
       * verifies it before calling this at all, so the proof reaches the transcript from there. What
       * this answers is the question it is named for: WHERE the relay says this message sits.
       */
      return { seq: seq - 1 };
    } catch (err: unknown) {
      this.#ctx.logger.warn("session.content.ordering.decode_failed", {
        sessionId,
        error: err instanceof Error ? err.message : String(err),
        correlationId,
      });
    }
    // No verified position — the caller falls back to the announced hash-dedup path. SOFT: a decode
    // throw tells us nothing about the signer, so it is the absent case, not the refuted one.
    return { seq: null };
  }

  /**
   * DAEMON-004: cross-check received content against its hash, append the
   * verified leaf to the daemon-owned tree, and buffer it for cello_receive.
   * A hash MISMATCH is genuine tamper — rejected without append or buffer.
   *
   * SCOPE / finding #5 — what this cross-check proves BY ITSELF, and what proves the rest:
   * `contentHash` here is carried in the SAME content_frame as `content`, so this comparison on its
   * own catches wire corruption of a single frame and nothing more. It is not what establishes that
   * the sender committed to these bytes. That proof arrives separately and is checked BEFORE any
   * caller reaches this method.
   *
   * ⚠️ **THE RULE THIS PARAGRAPH EXISTS TO ENFORCE: a comment that says a protection is missing
   * must be re-read whenever the protection lands, because in a PUBLIC repository it keeps handing
   * a reader a hole that is already closed.** This one said: *"Full tamper-evidence (EARS behavior
   * #2) requires cross-checking against the K_local-signed content_hash leaf the sender submits to
   * the RELAY on a separate channel; that relay hash-submit path is MSG-001's scope and **does not
   * exist yet**. Until MSG-001 lands, a malicious sender that sends matching (content, hash) in one
   * frame is not detected here — only the relay-relayed signed leaf closes that gap."* True when
   * written; the quote stays because its last clause predicts the wrong closure, as below.
   *
   * What closes it today — and note it is NOT only the route the old sentence predicted:
   *   - The relay hash-submit path EXISTS (`relay-node.ts` `#processHashSubmit`), so the separate
   *     channel the paragraph was waiting for is built.
   *   - `DOD-M15-AUTHORSHIP-ABSENT-1` then made the relay unnecessary for this question: the
   *     sender's signature over their own Structure 1 travels on the content frame beside the bytes
   *     it signs. `#verifyAuthorshipClaim` verifies it against the pubkey inside those signed bytes
   *     and matches the signer to this session's counterparty; a frame carrying nothing checkable is
   *     refused by name (`authorship_proof_absent`), so omitting the proof is not the softer option
   *     it once was. That verdict reaches this method as `verifiedAuthorship`.
   *   - The PARK-RECOVERY caller deliberately passes no `verifiedAuthorship`, and is not an
   *     exception to the above: recovered mail is authenticated by its park ENVELOPE's own
   *     signature (`authenticateParkedEntry`) before any of it is ingested — note the order is
   *     unseal THEN authenticate, so the envelope signature gates the append, not the decrypt.
   *     Two routes, both cryptographic, and the transcript row records which one attested the
   *     message rather than implying a proof it does not have.
   *
   * @returns the appended leaf index (as sequenceNumber) on success.
   */
  /**
   * Mark this session's content unverifiable — review F1, and every path that fails the cross-check
   * must come through here.
   *
   * It gates `getSealUpgradeReadiness().tampered` and the auto-acknowledge check, i.e. whether this
   * agent's key signs anything covering content it could not check. Three refusal paths reach it and
   * they carry different labels, because what the operator is told must differ; **what the gate does
   * must not.**
   *
   * TAMPERED NEVER DOWNGRADES. A session that has already seen a hash mismatch stays `tampered` even
   * if a later frame merely names an unreadable algorithm — otherwise a sender that had been caught
   * could clear its own alarm by sending one more frame with a junk algorithm name, and the seal
   * would auto-complete.
   */
  /**
   * Remember that THIS frame was refused for naming an unreadable algorithm, so the park path can
   * say so if the same message comes back the other way (review F2/F-D).
   *
   * BOUNDED, and it has to be: a peer that keeps sending unreadable frames would otherwise grow this
   * without limit, and it is fed entirely by a remote party. The cap is per session and it drops the
   * OLDEST entry — losing one only costs a missing reconciliation line, whereas an unbounded map fed
   * by a counterparty is the leak class this codebase has already caught twice.
   */
  noteUnreadableAlgFrame(agentName: string, sessionId: string, contentHash: Uint8Array, declaredAlg: string): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    let byHash = this.#unreadableAlgSeen.get(key);
    if (!byHash) { byHash = new Map(); this.#unreadableAlgSeen.set(key, byHash); }
    if (byHash.size >= MAX_UNREADABLE_ALG_FRAMES) {
      const oldest = byHash.keys().next();
      if (!oldest.done) byHash.delete(oldest.value);
    }
    byHash.set(Buffer.from(contentHash).toString("hex"), declaredAlg);
  }

  /**
   * Remember that THIS frame was refused for carrying no usable proof of who wrote it, so the park
   * path can say so when the same content arrives through the relay mailbox — review H1.
   *
   * Bounded for the same reason and by the same cap as `#noteUnreadableAlgFrame`: a peer sending
   * unprovable frames feeds this map, so it drops the oldest rather than growing.
   */
  noteRefusedOnDirectPath(agentName: string, sessionId: string, contentHash: Uint8Array): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    let hashes = this.#refusedOnDirectPath.get(key);
    if (!hashes) { hashes = new Set(); this.#refusedOnDirectPath.set(key, hashes); }
    if (hashes.size >= MAX_UNREADABLE_ALG_FRAMES) {
      const oldest = hashes.values().next();
      if (!oldest.done) hashes.delete(oldest.value);
    }
    hashes.add(Buffer.from(contentHash).toString("hex"));
  }

  /**
   * What algorithm did we refuse this content for naming, on the DIRECT path?
   *
   * Read by park recovery so it can tell the operator the message arrived by the other route after
   * all. Returns `undefined` when there was no such refusal.
   */
  priorUnreadableAlg(agentName: string, sessionId: string, contentHashHex: string): string | undefined {
    return this.#unreadableAlgSeen.get(this.#ctx.sessionKey(agentName, sessionId))?.get(contentHashHex);
  }

  /**
   * Forget one direct-path algorithm refusal, because the same content arrived by the mailbox.
   *
   * ⚠️ CLEARED ONLY ON A REAL RECONCILIATION. Clearing on the LOOKUP forgets the refusal even when
   * the recovery then fails, and the next genuine reconciliation says nothing — that was the defect,
   * and separating the read from the clear is what fixed it. Both halves stay separate here.
   */
  clearUnreadableAlg(agentName: string, sessionId: string, contentHashHex: string): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    const byHash = this.#unreadableAlgSeen.get(key);
    byHash?.delete(contentHashHex);
    if (byHash && byHash.size === 0) this.#unreadableAlgSeen.delete(key);
  }

  /** Was this content refused on the direct path for carrying no usable proof of who wrote it? */
  wasRefusedOnDirectPath(agentName: string, sessionId: string, contentHashHex: string): boolean {
    return this.#refusedOnDirectPath.get(this.#ctx.sessionKey(agentName, sessionId))?.has(contentHashHex) === true;
  }

  /** Forget one direct-path authorship refusal — same reconciliation rule as the algorithm memo. */
  clearRefusedOnDirectPath(agentName: string, sessionId: string, contentHashHex: string): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    const hashes = this.#refusedOnDirectPath.get(key);
    hashes?.delete(contentHashHex);
    if (hashes && hashes.size === 0) this.#refusedOnDirectPath.delete(key);
  }

  /**
   * Forget everything this module holds for one session.
   *
   * ⚠️ THIS EXISTS SO NO CALLER HAS TO KNOW THE FIELD NAMES. The manager's cache eviction used to
   * clear these five maps by hand, which made adding a sixth a silent bug waiting to happen — the
   * kind that leaves a bounded, remote-fed map growing for the life of the process. One call now,
   * and the list of what to forget lives beside the code that fills them.
   */
  evictSession(agentName: string, sessionId: string): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    this.#terminallyRefused.delete(key);
    this.#terminalRefusalsLoaded.delete(key);
    this.#terminalRefusalsReadFailedAt.delete(key);
    this.#unreadableAlgSeen.delete(key);
    this.#refusedOnDirectPath.delete(key);
  }
}
