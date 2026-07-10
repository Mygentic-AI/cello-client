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
 * Pseudocode (SPARC Phase P):
 *
 * 1. constructor(db, logger):
 *    - Store db handle and logger reference
 *    - Initialize empty per-session Map<sessionId, RetryQueueEntry[]>
 *    - Create retry_queue table IF NOT EXISTS
 *    - Create index on (session_id, position ASC)
 *
 * 2. loadFromDb():
 *    - SELECT all rows from retry_queue ordered by session_id, position ASC
 *    - Group into per-session arrays of RetryQueueEntry
 *    - Store in in-memory Map
 *    - Track per-session position counters (MAX position per session)
 *
 * 3. enqueue(sessionId, nonce: Uint8Array, contentBlob: Uint8Array):
 *    - Convert nonce to hex via Buffer.from(nonce).toString('hex')
 *    - If session queue size >= 1000: evict oldest (lowest position)
 *      - DELETE from retry_queue WHERE session_id AND position = min
 *      - Log message.retry.evicted WARN with evicted nonce hex
 *      - Remove from in-memory array
 *    - Compute next position: max(existing positions) + 1
 *    - INSERT into retry_queue (session_id, nonce_hex, content_blob, queued_at, attempts, position)
 *    - Add to in-memory array
 *    - Log message.retry.queued INFO
 *    - Return queueDepth
 *
 * 4. drainSession(sessionId, sendFn):
 *    - Get entries for session in FIFO order (ascending position)
 *    - For each entry:
 *      a. Call sendFn(entry.contentBlob) → await result
 *      b. If success: DELETE from retry_queue, remove from memory,
 *         log message.retry.delivered INFO with attemptsTotal
 *      c. If failure: HALT immediately. Do not attempt remaining entries.
 *         FIFO invariant: M3 must not arrive before M2.
 *    - Return count of successfully delivered messages
 *
 * 5. getTotalDepth():
 *    - Sum sizes of all per-session arrays
 *    - Return integer >= 0
 *
 * 6. getSessionDepth(sessionId):
 *    - Return length of session's array (0 if absent)
 */

import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

/** Cap per outline.md Resource Caps. */
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
 * CELLO-M7-MSG-001: an un-acked content entry awaiting a `persisted` delivery ACK.
 * Stored in the SAME retry_queue table (awaiting_ack = 1) — no new table. Drains to
 * the relay store-and-forward queue (park target) instead of direct-P2P resend.
 */
export interface AwaitingContentEntry {
  /** DOD-LOOP-1: the OWNING agent — the original sender. Two of the operator's agents can hold
   *  awaiting content for the SAME session_id on one daemon (loopback), so the entry is keyed by
   *  (agentId, sessionId), not sessionId alone.
   *  DOD-AGENT-ID-JOINKEY-1: the STABLE agent_id, never the mutable agent_name — a retire frees the
   *  name for reuse, and awaiting content must never be handed to the keypair that inherited it. */
  agentId: string;
  sessionId: string;
  contentHashHex: string;
  contentBlob: Uint8Array;
  queuedAt: number;
  position: number;
}

/** Result of a park attempt during the awaiting-ACK drain. */
export type ParkResult = { parked: true } | { parked: false; error: string };
export type ParkFn = (entry: AwaitingContentEntry) => Promise<ParkResult>;

export class RetryQueue {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;
  /** Per-session FIFO arrays of DIRECT-resend entries, ordered by position ascending. */
  #queues = new Map<string, RetryQueueEntry[]>();
  /** Per-session position counter for monotonic increment. */
  #positionCounters = new Map<string, number>();
  /** CELLO-M7-MSG-001: per-session FIFO arrays of awaiting-ACK content (park target). */
  #awaiting = new Map<string, AwaitingContentEntry[]>();

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;

    // Create table + index if not exists (inline migration — not Flyway)
    // DOD-AGENT-ID-JOINKEY-1: this table is created in its RE-KEYED shape. An EXISTING database is
    // rebuilt to this exact shape by migrateSessionTablesToAgentId, which SessionNodeManager.initialize
    // runs BEFORE this constructor — so by the time we get here the table either does not exist (fresh
    // DB, created below) or already carries agent_id.
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
        content_hash_hex TEXT
      )
    `);
    this.#db.exec(`
      CREATE INDEX IF NOT EXISTS retry_queue_by_session_position
        ON retry_queue(session_id, position ASC)
    `);
    // DOD-AGENT-ID-JOINKEY-1: the uniqueness constraint DOD-LOOP-1 should have written. It added
    // agent_name so "two of the operator's agents can hold awaiting content for the SAME session_id
    // without colliding" — and then left the agent OUT of UNIQUE(session_id, nonce_hex). For an
    // awaiting row nonce_hex IS the content hash, so two local agents parking identical content in one
    // session collided, and the collision was swallowed (see enqueueAwaitingContent) and lost on the
    // next restart.
    //
    // Expressed over COALESCE(agent_id, '') rather than as a bare UNIQUE(agent_id, ...): SQLite treats
    // NULLs as DISTINCT in a UNIQUE constraint, which would silently REMOVE the (session_id, nonce_hex)
    // dedup that agent-less direct-retry rows (agent_id NULL) have always relied on. COALESCE folds
    // every agent-less row into one bucket — old semantics preserved — while giving each agent its own.
    this.#db.exec(`
      CREATE UNIQUE INDEX IF NOT EXISTS retry_queue_agent_session_nonce
        ON retry_queue(COALESCE(agent_id, ''), session_id, nonce_hex)
    `);
  }

  /** DOD-LOOP-1: composite key for the awaiting-ACK map — (agentId, sessionId). */
  #ak(agentId: string, sessionId: string): string {
    return `${agentId}\x1f${sessionId}`;
  }

  /**
   * Load all retry queue entries from SQLCipher into memory.
   * Must complete BEFORE the IPC socket opens (AC-007).
   */
  loadFromDb(): void {
    const rows = this.#db
      .prepare("SELECT session_id, agent_id, nonce_hex, content_blob, queued_at, attempts, position, awaiting_ack, content_hash_hex FROM retry_queue ORDER BY session_id, position ASC")
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
      }>;

    this.#queues.clear();
    this.#positionCounters.clear();
    this.#awaiting.clear();

    for (const row of rows) {
      if (row.awaiting_ack === 1) {
        // CELLO-M7-MSG-001 (AC-004): un-acked content to re-park at startup. DOD-LOOP-1: keyed by
        // the OWNING agent. An awaiting row ALWAYS carries an agent_id (enqueueAwaitingContent
        // requires one); a legacy agent-less row here is a corrupt row, not a single-agent default,
        // so it is reported and skipped rather than silently re-parked under an empty-string agent —
        // which would merge two agents' content into one queue.
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
          queuedAt: row.queued_at,
          position: row.position,
        };
        const ak = this.#ak(row.agent_id, entry.sessionId);
        // The awaiting position counter is keyed by (agentId, sessionId) — the same key
        // enqueueAwaitingContent uses. It was previously bumped under the bare session_id here, so
        // after a restart every awaiting position restarted at 1 and collided with the loaded rows.
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
   * PERSIST-002 (AC-010): the content blob is stored as plaintext bytes — the whole DB is
   * SQLCipher-encrypted at rest, so the per-column cipher is gone. These pass-throughs keep the
   * call sites stable.
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
      // Log eviction BEFORE the new entry is logged (per story spec)
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
      // Message stays in memory only (DB-001 fallback)
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
        // Halt immediately — FIFO invariant (AC-015)
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

  // ─── CELLO-M7-MSG-001 (AC-004/AC-005/AC-019): awaiting-ACK content (park target) ──

  /**
   * Record un-acked content awaiting a `persisted` delivery ACK (TTF-trigger path,
   * AC-005). Persisted to the SAME retry_queue table (awaiting_ack = 1) so a crash
   * before the relay park confirms is recoverable at startup (AC-004). Idempotent on
   * (sessionId, contentHash).
   */
  enqueueAwaitingContent(agentId: string, sessionId: string, contentHash: Uint8Array, contentBlob: Uint8Array): void {
    if (!agentId) throw new Error("enqueueAwaitingContent: an owning agentId is required");
    const contentHashHex = Buffer.from(contentHash).toString("hex");
    const ak = this.#ak(agentId, sessionId);
    let q = this.#awaiting.get(ak);
    if (!q) { q = []; this.#awaiting.set(ak, q); }
    if (q.some((e) => e.contentHashHex === contentHashHex)) return; // idempotent

    const currentMax = this.#positionCounters.get(ak) ?? 0;
    const position = currentMax + 1;
    const queuedAt = Date.now();

    // DOD-AGENT-ID-JOINKEY-1: a failed persist of awaiting content is DATA LOSS, and it must say so.
    // This catch used to log and fall through to an in-memory push commented "still re-parkable this
    // run" — a guarantee the schema denied. The content vanished at the next restart while the caller
    // was told it was parked. Now: nothing is added to memory, the position counter is not advanced,
    // and the caller learns its content is not durable. (The collision that used to land here cannot
    // occur any more — retry_queue_agent_session_nonce scopes uniqueness by agent — so reaching this
    // branch now means a real DB failure: disk full, corruption, SQLITE_LOCKED.)
    try {
      this.#db
        .prepare(
          `INSERT INTO retry_queue (session_id, agent_id, nonce_hex, content_blob, queued_at, attempts, position, awaiting_ack, content_hash_hex)
           VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)`,
        )
        .run(sessionId, agentId, contentHashHex, Buffer.from(this.#sealBlob(contentBlob)), queuedAt, 1, position, contentHashHex);
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
    q.push({ agentId, sessionId, contentHashHex, contentBlob, queuedAt, position });
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
   * Drain a session's awaiting-ACK content to the relay park target (AC-005). Each item
   * is independent — unlike the direct FIFO resend, a park failure does NOT halt the
   * rest; the failed item stays queued for the next reconnect / startup flush (DB-001,
   * AC-019). Returns the number of entries successfully parked.
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
      if (!result.parked) continue; // keep for next reconnect / startup flush (AC-019)
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
