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

import type { DatabaseSync } from "node:sqlite";
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

export class RetryQueue {
  readonly #db: DatabaseSync;
  readonly #logger: Logger;
  /** Per-session FIFO arrays, ordered by position ascending. */
  #queues = new Map<string, RetryQueueEntry[]>();
  /** Per-session position counter for monotonic increment. */
  #positionCounters = new Map<string, number>();

  constructor(db: DatabaseSync, logger: Logger) {
    this.#db = db;
    this.#logger = logger;

    // Create table + index if not exists (inline migration — not Flyway)
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS retry_queue (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id      TEXT    NOT NULL,
        nonce_hex       TEXT    NOT NULL,
        content_blob    BLOB    NOT NULL,
        queued_at       INTEGER NOT NULL,
        attempts        INTEGER NOT NULL DEFAULT 1,
        position        INTEGER NOT NULL,
        UNIQUE(session_id, nonce_hex)
      )
    `);
    this.#db.exec(`
      CREATE INDEX IF NOT EXISTS retry_queue_by_session_position
        ON retry_queue(session_id, position ASC)
    `);
  }

  /**
   * Load all retry queue entries from SQLCipher into memory.
   * Must complete BEFORE the IPC socket opens (AC-007).
   */
  loadFromDb(): void {
    const rows = this.#db
      .prepare("SELECT session_id, nonce_hex, content_blob, queued_at, attempts, position FROM retry_queue ORDER BY session_id, position ASC")
      .all() as unknown as Array<{
        session_id: string;
        nonce_hex: string;
        content_blob: Buffer;
        queued_at: number;
        attempts: number;
        position: number;
      }>;

    this.#queues.clear();
    this.#positionCounters.clear();

    for (const row of rows) {
      const entry: RetryQueueEntry = {
        sessionId: row.session_id,
        nonceHex: row.nonce_hex,
        contentBlob: Uint8Array.from(row.content_blob),
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

      // Track max position per session
      const currentMax = this.#positionCounters.get(entry.sessionId) ?? 0;
      if (entry.position > currentMax) {
        this.#positionCounters.set(entry.sessionId, entry.position);
      }
    }
  }

  /**
   * Enqueue a failed message for later retry.
   * Evicts the oldest entry if cap is reached.
   */
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
        .run(sessionId, nonceHex, Buffer.from(contentBlob), queuedAt, 1, nextPosition);
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
}
