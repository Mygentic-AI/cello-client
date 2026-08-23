/**
 * CELLO Daemon — RetryQueue
 *
 * Per-session FIFO queue of messages awaiting delivery. When a send over a
 * session node stream fails, the message envelope is added to the queue. When
 * the peer reconnects, the daemon drains the queue in FIFO order.
 *
 * Persistence: SQLCipher table `retry_queue`.
 * Cap: 1,000 messages per session. On overflow the OLDEST is evicted.
 *
 * FIFO invariant: a drain HALTS on the first failure. M3 must never arrive before M2.
 */

import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

/** Per-session cap. On overflow the OLDEST entry is evicted. */
export const RETRY_QUEUE_CAP = 1000;

export interface RetryQueueEntry {
  sessionId: string;
  nonceHex: string;
  contentBlob: Uint8Array;
  queuedAt: number;
  attempts: number;
  position: number;
}

/** Result of a resend attempt during drain. */
export type ResendResult = { delivered: true } | { delivered: false; error: string };

export type ResendFn = (contentBlob: Uint8Array) => Promise<ResendResult>;

/**
 * An un-acked content entry awaiting a `persisted` delivery ACK. Stored in the SAME retry_queue
 * table (awaiting_ack = 1) — no second table. Drains to the relay store-and-forward queue (park
 * target) instead of direct-P2P resend.
 */
export interface AwaitingContentEntry {
  /** The OWNING agent — the original sender. Two of the operator's agents can hold awaiting content
   *  for the SAME session_id on one daemon (loopback), so the entry is keyed by (agentId, sessionId),
   *  not sessionId alone.
   *  This is the STABLE agent_id, never the mutable agent_name — a retire frees the name for reuse,
   *  and awaiting content must never be handed to the keypair that inherited it. */
  agentId: string;
  sessionId: string;
  contentHashHex: string;
  contentBlob: Uint8Array;
  /** M12-P12 (review F2): the relay's signed ordering record, carried so a RE-park is self-ordering
   *  exactly like the live park. Without it `recoverParkedFromRelay` falls back to the in-memory
   *  #witnessedSeq map, which is empty after a receiver restart — the content then appends at its
   *  ARRIVAL index instead of its witnessed sequence, and the session tree diverges at seal.
   *  Nullable: rows written before this column existed, and the agent-less direct-retry rows,
   *  legitimately have none. */
  /**
   * `DOD-M15-SEALWIRE-1` part B2b — WHICH content-hash algorithm `contentHashHex` was produced
   * under, so a RE-park names the same one the original frame did.
   *
   * The crash-backstop producer has no other source: it runs at the next boot, the frame is long
   * gone, and re-deriving it from the session's current row would be a fact about what THIS side
   * holds now, not about how this message was actually hashed.
   *
   * Nullable, and `undefined` is meaningful rather than a gap — it is what `resolveContentHashAlg`
   * reads as "predates the field", the only value meaning legacy. Never defaulted to `"sha256"`.
   */
  contentHashAlg?: string;
  structure1Cbor?: Uint8Array;
  structure2Cbor?: Uint8Array;
  queuedAt: number;
  position: number;
}

/** Result of a park attempt during the awaiting-ACK drain. */
export type ParkResult = { parked: true } | { parked: false; error: string };
export type ParkFn = (entry: AwaitingContentEntry) => Promise<ParkResult>;

/**
 * Park failures from which the entry can NEVER recover, so keeping it only re-attempts it at every
 * boot forever. An ALLOWLIST, and deliberately a short one: everything not named here is kept,
 * because the cost of keeping a deliverable row is one WARN per boot while the cost of dropping one
 * is a message the sender believes was delivered.
 *
 * `owning_agent_not_found` qualifies on evidence, not judgement: it means `agentNameForId` found no
 * `agents` row for the entry's agent_id, and `remove-agent` is permanent and frees the name. The
 * owner cannot come back, so no future boot can park this.
 *
 * The other four are all recoverable on a later boot and MUST NOT be added:
 *   no_persisted_relay_endpoint  — the endpoint is learned when the session next reconnects
 *   no_counterparty              — the sessions row can still gain one
 *   standing_receiver_unavailable— the receiver is rebuilt on the next agent start
 *   signing_key_unavailable      — the key provider may simply not be loaded yet
 */
const PERMANENT_PARK_FAILURES: ReadonlySet<string> = new Set(["owning_agent_not_found"]);

export class RetryQueue {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;
  /** Per-session FIFO arrays of DIRECT-resend entries, ordered by position ascending. */
  #queues = new Map<string, RetryQueueEntry[]>();
  /** Per-session position counter for monotonic increment. */
  #positionCounters = new Map<string, number>();
  /** Per-(agent,session) FIFO arrays of awaiting-ACK content (park target). */
  #awaiting = new Map<string, AwaitingContentEntry[]>();

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;

    // Create table + index if not exists (inline migration — not Flyway).
    // ORDERING CONSTRAINT: migrateSessionTablesToAgentId (run by SessionNodeManager.initialize) MUST
    // execute BEFORE this constructor, so the table here either does not exist (fresh DB, created
    // below) or already carries agent_id. Do not reorder.
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS retry_queue (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id      TEXT    NOT NULL,
        agent_id        TEXT,
        nonce_hex       TEXT    NOT NULL,
        content_blob    BLOB    NOT NULL,
        queued_at       INTEGER NOT NULL,
        attempts        INTEGER NOT NULL DEFAULT 1,
        position        INTEGER NOT NULL,
        awaiting_ack    INTEGER NOT NULL DEFAULT 0,
        content_hash_hex TEXT,
        structure1_cbor BLOB,
        structure2_cbor BLOB,
        content_hash_alg TEXT
      )
    `);
    // Idempotent add for databases created before M12-P12. SQLite has no ADD COLUMN IF NOT EXISTS,
    // so the duplicate-column error is the expected no-op on an already-migrated DB; any OTHER
    // error is a real failure and must not be swallowed.
    /**
     * 🚨 A COLUMN ADDED HERE NEEDS A SECOND ENTRY, in `agent-id-migration.ts`'s `retry_queue`
     * `createSql`. That rebuild copies the INTERSECTION of the old and new column lists, so a column
     * this loop adds and that DDL omits is DROPPED on the one boot where a legacy database migrates
     * — and then re-added EMPTY by this very loop, which is what makes it silent.
     *
     * It has happened: `structure1_cbor` and `structure2_cbor` were missing from that DDL from the
     * day they were added until `DOD-M15-SEALWIRE-1` part B2b found it.
     */
    for (const col of [
      { name: "structure1_cbor", type: "BLOB" },
      { name: "structure2_cbor", type: "BLOB" },
      // DOD-M15-SEALWIRE-1 part B2b: which content-hash algorithm this queued message was hashed
      // under. The crash-backstop park producer has no other source for it — the frame is gone by
      // the time it runs — and re-parking under the wrong one gets the message refused.
      { name: "content_hash_alg", type: "TEXT" },
    ]) {
      try {
        this.#db.exec(`ALTER TABLE retry_queue ADD COLUMN ${col.name} ${col.type}`);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        if (!/duplicate column name/i.test(msg)) throw err;
      }
    }
    this.#db.exec(`
      CREATE INDEX IF NOT EXISTS retry_queue_by_session_position
        ON retry_queue(session_id, position ASC)
    `);
    // Uniqueness MUST include the agent. For an awaiting row nonce_hex IS the content hash, so
    // without the agent in the key two local agents parking identical content in one session collide.
    //
    // It is expressed over COALESCE(agent_id, '') rather than as a bare UNIQUE(agent_id, ...) because
    // SQLite treats NULLs as DISTINCT in a UNIQUE constraint, which would silently REMOVE the
    // (session_id, nonce_hex) dedup that agent-less direct-retry rows (agent_id NULL) rely on.
    // COALESCE folds every agent-less row into one bucket while giving each agent its own.
    this.#db.exec(`
      CREATE UNIQUE INDEX IF NOT EXISTS retry_queue_agent_session_nonce
        ON retry_queue(COALESCE(agent_id, ''), session_id, nonce_hex)
    `);
  }

  /** Composite key for the awaiting-ACK map — (agentId, sessionId). */
  #ak(agentId: string, sessionId: string): string {
    return `${agentId}\x1f${sessionId}`;
  }

  /**
   * Load all retry queue entries from SQLCipher into memory.
   * Must complete BEFORE the IPC socket opens.
   */
  loadFromDb(): void {
    const rows = this.#db
      .prepare("SELECT session_id, agent_id, nonce_hex, content_blob, queued_at, attempts, position, awaiting_ack, content_hash_hex, structure1_cbor, structure2_cbor, content_hash_alg FROM retry_queue ORDER BY session_id, position ASC")
      .all() as unknown as Array<{
        session_id: string;
        agent_id: string | null;
        nonce_hex: string;
        content_blob: Buffer;
        queued_at: number;
        attempts: number;
        position: number;
        awaiting_ack: number;
        content_hash_hex: string | null;
        content_hash_alg: string | null;
        structure1_cbor: Buffer | null;
        structure2_cbor: Buffer | null;
      }>;

    this.#queues.clear();
    this.#positionCounters.clear();
    this.#awaiting.clear();

    for (const row of rows) {
      if (row.awaiting_ack === 1) {
        // Un-acked content to re-park at startup, keyed by the OWNING agent. An awaiting row ALWAYS
        // carries an agent_id (enqueueAwaitingContent requires one); an agent-less row here is a
        // corrupt row, not a single-agent default, so it is reported and skipped rather than silently
        // re-parked under an empty-string agent — which would merge two agents' content into one queue.
        if (row.agent_id === null) {
          this.#logger.error("message.retry.awaiting.orphaned", {
            sessionId: row.session_id,
            nonce: row.content_hash_hex ?? row.nonce_hex,
            impact: "awaiting-ACK row has no owning agent_id; not re-parked",
          });
          continue;
        }
        const entry: AwaitingContentEntry = {
          agentId: row.agent_id,
          sessionId: row.session_id,
          contentHashHex: row.content_hash_hex ?? row.nonce_hex,
          contentBlob: this.#openBlob(Uint8Array.from(row.content_blob)),
          // M12-P12 (F2): the ordering record is NOT sealed — it is the relay's own signed record,
          // already public to the relay, and it must be readable to re-seal the park envelope.
          contentHashAlg: row.content_hash_alg ?? undefined,
          structure1Cbor: row.structure1_cbor ? Uint8Array.from(row.structure1_cbor) : undefined,
          structure2Cbor: row.structure2_cbor ? Uint8Array.from(row.structure2_cbor) : undefined,
          queuedAt: row.queued_at,
          position: row.position,
        };
        const ak = this.#ak(row.agent_id, entry.sessionId);
        // The awaiting position counter MUST be keyed by (agentId, sessionId) — the same key
        // enqueueAwaitingContent uses. Bumping it under the bare session_id here restarts every
        // awaiting position at 1 after a reload, colliding with the rows just loaded.
        const awaitingMax = this.#positionCounters.get(ak) ?? 0;
        if (row.position > awaitingMax) this.#positionCounters.set(ak, row.position);
        let q = this.#awaiting.get(ak);
        if (!q) { q = []; this.#awaiting.set(ak, q); }
        q.push(entry);
        continue;
      }

      // Direct-retry entries are session-scoped (no owning agent), so their counter is too.
      const currentMax = this.#positionCounters.get(row.session_id) ?? 0;
      if (row.position > currentMax) this.#positionCounters.set(row.session_id, row.position);

      const entry: RetryQueueEntry = {
        sessionId: row.session_id,
        nonceHex: row.nonce_hex,
        contentBlob: this.#openBlob(Uint8Array.from(row.content_blob)),
        queuedAt: row.queued_at,
        attempts: row.attempts,
        position: row.position,
      };

      let sessionQueue = this.#queues.get(entry.sessionId);
      if (!sessionQueue) {
        sessionQueue = [];
        this.#queues.set(entry.sessionId, sessionQueue);
      }
      sessionQueue.push(entry);
    }
  }

  /**
   * Enqueue a failed message for later retry.
   * Evicts the oldest entry if cap is reached.
   */
  /**
   * The content blob is stored as plaintext bytes — the whole DB is SQLCipher-encrypted at rest, so
   * there is no per-column cipher. These pass-throughs keep the call sites stable.
   */
  #sealBlob(b: Uint8Array): Uint8Array {
    return b;
  }

  #openBlob(b: Uint8Array): Uint8Array {
    return b;
  }

  enqueue(sessionId: string, nonce: Uint8Array, contentBlob: Uint8Array): void {
    const nonceHex = Buffer.from(nonce).toString("hex");

    let sessionQueue = this.#queues.get(sessionId);
    if (!sessionQueue) {
      sessionQueue = [];
      this.#queues.set(sessionId, sessionQueue);
    }

    // Cap enforcement: evict oldest if at limit
    if (sessionQueue.length >= RETRY_QUEUE_CAP) {
      const oldest = sessionQueue[0];
      // Delete from DB
      try {
        this.#db
          .prepare("DELETE FROM retry_queue WHERE session_id = ? AND position = ?")
          .run(sessionId, oldest.position);
      } catch (err: unknown) {
        this.#logger.error("message.retry.persist.failed", {
          sessionId,
          nonce: oldest.nonceHex,
          error: err instanceof Error ? err.message : String(err),
        });
      }
      // Log eviction BEFORE the new entry is logged.
      this.#logger.warn("message.retry.evicted", {
        sessionId,
        nonce: oldest.nonceHex,
        queueDepth: RETRY_QUEUE_CAP,
      });
      // Remove from in-memory
      sessionQueue.shift();
    }

    // Compute next position
    const currentMax = this.#positionCounters.get(sessionId) ?? 0;
    const nextPosition = currentMax + 1;
    this.#positionCounters.set(sessionId, nextPosition);

    const queuedAt = Date.now();
    const entry: RetryQueueEntry = {
      sessionId,
      nonceHex,
      contentBlob,
      queuedAt,
      attempts: 1,
      position: nextPosition,
    };

    // Persist to SQLCipher
    try {
      this.#db
        .prepare(
          `INSERT INTO retry_queue (session_id, nonce_hex, content_blob, queued_at, attempts, position)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .run(sessionId, nonceHex, Buffer.from(this.#sealBlob(contentBlob)), queuedAt, 1, nextPosition);
    } catch (err: unknown) {
      this.#logger.error("message.retry.persist.failed", {
        sessionId,
        nonce: nonceHex,
        error: err instanceof Error ? err.message : String(err),
      });
      // Message stays in memory only — it is not durable across a restart.
    }

    sessionQueue.push(entry);

    this.#logger.info("message.retry.queued", {
      sessionId,
      nonce: nonceHex,
      queueDepth: sessionQueue.length,
    });
  }

  /**
   * Drain the session's retry queue in FIFO order.
   * Halts immediately on first failure (FIFO invariant: no out-of-order delivery).
   * Returns the number of successfully delivered messages.
   */
  async drainSession(sessionId: string, sendFn: ResendFn): Promise<number> {
    const sessionQueue = this.#queues.get(sessionId);
    if (!sessionQueue || sessionQueue.length === 0) {
      return 0;
    }

    let delivered = 0;

    // Drain in FIFO order (array is already sorted by position ascending)
    while (sessionQueue.length > 0) {
      const entry = sessionQueue[0];
      const result = await sendFn(entry.contentBlob);

      if (!result.delivered) {
        // Increment attempts on failure so attemptsTotal reflects actual tries
        entry.attempts++;
        try {
          this.#db
            .prepare("UPDATE retry_queue SET attempts = ? WHERE session_id = ? AND nonce_hex = ?")
            .run(entry.attempts, sessionId, entry.nonceHex);
        } catch (err: unknown) {
          this.#logger.error("message.retry.persist.failed", {
            sessionId,
            nonce: entry.nonceHex,
            error: err instanceof Error ? err.message : String(err),
          });
        }
        // Halt immediately — FIFO invariant: no out-of-order delivery.
        break;
      }

      // Success: delete from DB
      try {
        this.#db
          .prepare("DELETE FROM retry_queue WHERE session_id = ? AND nonce_hex = ?")
          .run(sessionId, entry.nonceHex);
      } catch (err: unknown) {
        this.#logger.error("message.retry.persist.failed", {
          sessionId,
          nonce: entry.nonceHex,
          error: err instanceof Error ? err.message : String(err),
        });
      }

      // Remove from memory
      sessionQueue.shift();

      // Increment attempts for logging
      const attemptsTotal = entry.attempts + 1;

      this.#logger.info("message.retry.delivered", {
        sessionId,
        nonce: entry.nonceHex,
        attemptsTotal,
      });

      delivered++;
    }

    // Clean up empty queue entry
    if (sessionQueue.length === 0) {
      this.#queues.delete(sessionId);
    }

    return delivered;
  }

  /**
   * Remove the DIRECT-resend entries (awaiting_ack = 0) of a session that can never drain again.
   *
   * Removal is authorised by ONE thing: the session reached a status from which no resend can
   * succeed. Never by age — "old" is not "undeliverable", and an age sweep discards live content
   * on a slow link (the DOD-SESSION-REAP-1 rule).
   *
   * Awaiting-ACK rows are deliberately left alone. They drain through `drainAwaitingToPark`, which
   * the startup flush really calls, so they are not stranded; their terminal disposition is a
   * separate concern. Deleting them here would discard content that path still owes delivery on.
   *
   * @returns how many entries were removed — 0 is the normal case and is silent.
   */
  reapTerminalSession(sessionId: string, terminalStatus: "sealed" | "abandoned"): number {
    // The in-memory queue is NOT the authority, and must not be the source for either half of this.
    // A row written by an earlier daemon exists only in the DB until loadFromDb runs — the live
    // strand was exactly that shape — so the rows to announce are read from the DB, and the same
    // set is then deleted. Announcing from memory while deleting from disk would silently discard
    // any row the map does not happen to hold, which is the precise failure AC3 names as the worse
    // one.
    let doomed: Array<{ nonce_hex: string }>;
    try {
      doomed = this.#db
        .prepare("SELECT nonce_hex FROM retry_queue WHERE session_id = ? AND awaiting_ack = 0")
        .all(sessionId) as unknown as Array<{ nonce_hex: string }>;
    } catch (err: unknown) {
      this.#logger.error("message.retry.persist.failed", {
        sessionId,
        operation: "terminal_reap_select",
        error: err instanceof Error ? err.message : String(err),
        impact: "could not read the rows to reap; nothing was deleted and retryQueueDepth stays pinned",
      });
      return 0;
    }

    if (doomed.length === 0) {
      // Still drop any memory-only residue so depth cannot disagree with the DB, then stay silent:
      // the overwhelming majority of terminal sessions have nothing queued, and an event on every
      // one of them buries the occurrence that means content was actually lost.
      this.#queues.delete(sessionId);
      this.#positionCounters.delete(sessionId);
      return 0;
    }

    let removed: number;
    try {
      const result = this.#db
        .prepare("DELETE FROM retry_queue WHERE session_id = ? AND awaiting_ack = 0")
        .run(sessionId) as unknown as { changes?: number | bigint };
      // Both drivers in use (node:sqlite in tests, SQLCipher in production) report `changes`. Its
      // absence is a driver contract violation, not a case to paper over with a memory count — the
      // whole point of this method is that memory is not authoritative.
      if (result?.changes === undefined) {
        this.#logger.error("message.retry.persist.failed", {
          sessionId,
          operation: "terminal_reap_delete",
          error: "driver returned no `changes` from DELETE",
          impact: "rows may or may not have been removed; the reported count cannot be trusted",
        });
      }
      removed = Number(result?.changes ?? doomed.length);
    } catch (err: unknown) {
      // A failed DELETE must not leave memory claiming the rows are gone — the next loadFromDb
      // would resurrect them and the depth would silently disagree with the DB.
      this.#logger.error("message.retry.persist.failed", {
        sessionId,
        operation: "terminal_reap_delete",
        error: err instanceof Error ? err.message : String(err),
        impact: "terminal-session reap did not remove the rows; retryQueueDepth stays pinned",
      });
      return 0;
    }

    // Each dropped entry is content the sender believes it sent. Say so per entry, with the nonce,
    // so the loss is nameable rather than a bare count.
    for (const row of doomed) {
      this.#logger.warn("session.retryqueue.content.dropped", {
        sessionId,
        nonce: row.nonce_hex,
        reason: terminalStatus,
        impact: "queued content was never delivered and is now discarded — the session can no longer drain",
      });
    }

    this.#queues.delete(sessionId);
    this.#positionCounters.delete(sessionId);

    this.#logger.info("session.retryqueue.reaped", {
      sessionId,
      entryCount: removed,
      reason: terminalStatus,
    });

    return removed;
  }

  /**
   * DOD-RETRYQ-STRAND-1: reconcile at startup. The terminal-transition hook only covers sessions
   * that go terminal while THIS daemon is running. A session that was already sealed/abandoned
   * before boot never transitions again — `cello_close_session` returns `already_abandoned`
   * without reaching `abandonSession` — so its rows would strand forever with no path that could
   * ever clear them. That is the shape of the row found on the live daemon.
   *
   * Still evidence-gated: the session's terminal status is the evidence, read from the DB. Nothing
   * here consults age.
   *
   * @returns total entries reaped across all already-terminal sessions.
   */
  reapAlreadyTerminalSessions(): number {
    let rows: Array<{ session_id: string; status: string }>;
    try {
      rows = this.#db
        .prepare(
          `SELECT DISTINCT rq.session_id AS session_id, s.status AS status
             FROM retry_queue rq
             JOIN sessions s ON s.session_id = rq.session_id
            WHERE rq.awaiting_ack = 0
              AND s.status IN ('sealed', 'abandoned')`,
        )
        .all() as unknown as Array<{ session_id: string; status: string }>;
    } catch (err: unknown) {
      this.#logger.error("message.retry.persist.failed", {
        operation: "startup_terminal_reconcile",
        error: err instanceof Error ? err.message : String(err),
        impact: "already-terminal sessions were not reconciled; retryQueueDepth may stay pinned",
      });
      return 0;
    }

    let total = 0;
    for (const row of rows) {
      total += this.reapTerminalSession(
        row.session_id,
        row.status === "sealed" ? "sealed" : "abandoned",
      );
    }
    if (total > 0) {
      this.#logger.info("session.retryqueue.startup.reconciled", {
        sessionCount: rows.length,
        entryCount: total,
      });
    }
    return total;
  }

  /** Total retry queue depth across all sessions. */
  getTotalDepth(): number {
    let total = 0;
    for (const queue of this.#queues.values()) {
      total += queue.length;
    }
    return total;
  }

  /** Retry queue depth for a specific session. */
  getSessionDepth(sessionId: string): number {
    return this.#queues.get(sessionId)?.length ?? 0;
  }

  /** Get all entries for a session (FIFO ordered, defensive copy). Used by drain_session IPC. */
  getSessionEntries(sessionId: string): RetryQueueEntry[] {
    const queue = this.#queues.get(sessionId);
    return queue ? [...queue] : [];
  }

  // ─── Awaiting-ACK content (park target) ──

  /**
   * Record un-acked content awaiting a `persisted` delivery ACK. Persisted to the SAME
   * retry_queue table (awaiting_ack = 1) so a crash before the relay park confirms is
   * recoverable at startup. Idempotent on (agentId, sessionId, contentHash).
   */
  /**
   * Returns TRUE only when this copy is actually queued. M12-P13 (review HIGH-1): the dedupe branch
   * below DROPS the content, and the caller now commits a hash-chain leaf on the strength of this
   * answer — so "I dropped it" must be reportable, not merely logged. A void return made the drop
   * indistinguishable from a successful enqueue at the call site, which is how a leaf could be
   * committed for content that no longer existed anywhere.
   */
  /**
   * `contentHashAlg` — `DOD-M15-SEALWIRE-1` part B2b. WHICH algorithm `contentHash` was produced
   * under, carried because the crash-backstop park producer has NO OTHER SOURCE for it: it runs at
   * the next boot, long after the frame is gone, and re-parking under the wrong algorithm gets the
   * message refused by the recipient and re-pulled forever.
   *
   * Optional and stored as NULL when absent, never defaulted to the literal `"sha256"` — absent is
   * what `resolveContentHashAlg` reads as "predates the field", and that distinction is the one B1
   * and B2a each had to restore after it was collapsed.
   */
  enqueueAwaitingContent(agentId: string, sessionId: string, contentHash: Uint8Array, contentBlob: Uint8Array, structure1Cbor?: Uint8Array, structure2Cbor?: Uint8Array, contentHashAlg?: string): boolean {
    if (!agentId) throw new Error("enqueueAwaitingContent: an owning agentId is required");
    const contentHashHex = Buffer.from(contentHash).toString("hex");
    const ak = this.#ak(agentId, sessionId);
    let q = this.#awaiting.get(ak);
    if (!q) { q = []; this.#awaiting.set(ak, q); }
    if (q.some((e) => e.contentHashHex === contentHashHex)) {
      // M12-P12 (review F7): the key is SHA-256(0x00 ‖ content) — content-derived, with no sequence
      // and no nonce. Two identical messages in one session ("ok" at seq 3 and seq 7) collide, and
      // the second is DROPPED here. Silently, until now: the drop looked like a successful enqueue
      // and reproduced the very symptom this class of fix exists to remove. Logged so it is at
      // least visible; keying on (sessionId, canonicalSeq, contentHash) is the real fix.
      this.#logger.warn("message.retry.enqueue.deduped", {
        agentId, sessionId, contentHash: contentHashHex,
        impact: "identical content already queued for this session — this copy is NOT separately queued",
      });
      return false;
    }

    const currentMax = this.#positionCounters.get(ak) ?? 0;
    const position = currentMax + 1;
    const queuedAt = Date.now();

    // FAILS LOUD: a failed persist of awaiting content is DATA LOSS and MUST throw. Do not "recover"
    // by pushing to memory anyway — the content would vanish at the next restart while the caller was
    // told it was parked. Nothing is added to memory, the position counter is not advanced, and the
    // caller learns its content is not durable. Reaching this branch means a real DB failure (disk
    // full, corruption, SQLITE_LOCKED); the agent-scoped unique index rules out a benign collision.
    try {
      this.#db
        .prepare(
          `INSERT INTO retry_queue (session_id, agent_id, nonce_hex, content_blob, queued_at, attempts, position, awaiting_ack, content_hash_hex, structure1_cbor, structure2_cbor, content_hash_alg)
           VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)`,
        )
        .run(sessionId, agentId, contentHashHex, Buffer.from(this.#sealBlob(contentBlob)), queuedAt, 1, position, contentHashHex,
             structure1Cbor ? Buffer.from(structure1Cbor) : null,
             structure2Cbor ? Buffer.from(structure2Cbor) : null,
             contentHashAlg ?? null);
    } catch (err: unknown) {
      const reason = err instanceof Error ? err.message : String(err);
      this.#logger.error("message.retry.persist.failed", {
        agentId,
        sessionId,
        nonce: contentHashHex,
        error: reason,
        impact: "awaiting-ACK content NOT durable — it will be lost if the daemon restarts",
      });
      throw new Error(`awaiting_content_persist_failed: ${reason}`);
    }

    this.#positionCounters.set(ak, position);
    q.push({ agentId, sessionId, contentHashHex, contentBlob, structure1Cbor, structure2Cbor, contentHashAlg, queuedAt, position });
    return true;
  }

  /** Remove an awaiting-ACK entry once its `persisted` ACK arrives. */
  markContentAcked(agentId: string, sessionId: string, contentHash: Uint8Array): void {
    const contentHashHex = Buffer.from(contentHash).toString("hex");
    const ak = this.#ak(agentId, sessionId);
    const q = this.#awaiting.get(ak);
    if (q) {
      const idx = q.findIndex((e) => e.contentHashHex === contentHashHex);
      if (idx !== -1) q.splice(idx, 1);
      if (q.length === 0) this.#awaiting.delete(ak);
    }
    try {
      this.#db
        .prepare("DELETE FROM retry_queue WHERE agent_id = ? AND session_id = ? AND content_hash_hex = ? AND awaiting_ack = 1")
        .run(agentId, sessionId, contentHashHex);
    } catch (err: unknown) {
      this.#logger.error("message.retry.persist.failed", {
        sessionId, nonce: contentHashHex, error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  /** Awaiting-ACK depth for a session (un-acked content count). */
  getAwaitingDepth(agentId: string, sessionId: string): number {
    return this.#awaiting.get(this.#ak(agentId, sessionId))?.length ?? 0;
  }

  /** All (agent, session) pairs that currently hold awaiting-ACK content (for the startup flush). */
  getAwaitingSessions(): Array<{ agentId: string; sessionId: string }> {
    const out: Array<{ agentId: string; sessionId: string }> = [];
    for (const q of this.#awaiting.values()) {
      if (q.length > 0) out.push({ agentId: q[0].agentId, sessionId: q[0].sessionId });
    }
    return out;
  }

  /**
   * Drain a session's awaiting-ACK content to the relay park target. Each item is
   * independent — unlike the direct FIFO resend, a park failure does NOT halt the rest;
   * the failed item stays queued for the next reconnect / startup flush. Returns the
   * number of entries successfully parked.
   */
  async drainAwaitingToPark(agentId: string, sessionId: string, parkFn: ParkFn): Promise<number> {
    const ak = this.#ak(agentId, sessionId);
    const q = this.#awaiting.get(ak);
    if (!q || q.length === 0) return 0;
    let parked = 0;
    for (const entry of [...q]) {
      let result: ParkResult;
      try {
        result = await parkFn(entry);
      } catch (err: unknown) {
        result = { parked: false, error: err instanceof Error ? err.message : String(err) };
      }
      if (!result.parked) {
        // `result.error` MUST be logged. Every failure branch of the park target
        // (owning_agent_not_found, no_persisted_relay_endpoint, no_counterparty,
        // standing_receiver_unavailable, signing_key_unavailable) is otherwise invisible — the only
        // trace would be `parkedCount: 0`, a number with no reason. The entry is still KEPT for the
        // next flush.
        if (PERMANENT_PARK_FAILURES.has(result.error)) {
          // Nothing a later boot can change, so keeping it just re-attempts it forever. ERROR, not
          // WARN: this is the terminal loss of content the sender believes it delivered, and it is
          // the one occurrence in this path that an operator must actually see.
          this.#logger.error("content.park.abandoned", {
            agentId,
            sessionId,
            contentHash: entry.contentHashHex,
            error: result.error,
            impact: "the owning agent no longer exists, so this content can never be parked or delivered; it is discarded rather than retried at every boot",
          });
          const gone = q.indexOf(entry);
          if (gone !== -1) q.splice(gone, 1);
          try {
            this.#db
              .prepare("DELETE FROM retry_queue WHERE agent_id = ? AND session_id = ? AND content_hash_hex = ? AND awaiting_ack = 1")
              .run(agentId, sessionId, entry.contentHashHex);
          } catch (err: unknown) {
            this.#logger.error("message.retry.persist.failed", {
              agentId, sessionId, nonce: entry.contentHashHex, operation: "park_abandon_delete",
              error: err instanceof Error ? err.message : String(err),
              impact: "the unparkable row was not removed and will be re-attempted at every boot",
            });
          }
          continue;
        }
        this.#logger.warn("content.park.failed", {
          agentId,
          sessionId,
          contentHash: entry.contentHashHex,
          error: result.error,
        });
        continue; // keep for next reconnect / startup flush
      }
      const idx = q.indexOf(entry);
      if (idx !== -1) q.splice(idx, 1);
      try {
        this.#db
          .prepare("DELETE FROM retry_queue WHERE agent_id = ? AND session_id = ? AND content_hash_hex = ? AND awaiting_ack = 1")
          .run(agentId, sessionId, entry.contentHashHex);
      } catch (err: unknown) {
        this.#logger.error("message.retry.persist.failed", {
          sessionId, nonce: entry.contentHashHex, error: err instanceof Error ? err.message : String(err),
        });
      }
      parked += 1;
    }
    if (q.length === 0) this.#awaiting.delete(ak);
    return parked;
  }
}
