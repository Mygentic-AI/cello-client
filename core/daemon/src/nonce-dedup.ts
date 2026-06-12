/**
 * CELLO Daemon — NonceDedupStore
 *
 * Per-session LRU set of already-seen incoming nonces. When an incoming message
 * arrives, the daemon checks its nonce here BEFORE delivering to cello_receive.
 * Duplicates are silently discarded.
 *
 * Persistence: SQLCipher table `session_seen_nonces`.
 * Cap: 10,000 nonces per session (LRU eviction).
 *
 * Pseudocode (SPARC Phase P):
 *
 * 1. constructor(db, logger):
 *    - Store db handle and logger reference
 *    - Initialize empty per-session Map<sessionId, Map<nonceHex, seenAt>>
 *    - Create session_seen_nonces table IF NOT EXISTS
 *    - Create index on (session_id, seen_at ASC) for LRU eviction
 *
 * 2. loadFromDb():
 *    - SELECT all rows from session_seen_nonces ORDER BY session_id, seen_at ASC
 *    - Group into per-session Maps of nonceHex → seenAt
 *    - This populates the in-memory LRU for duplicate checks
 *
 * 3. has(sessionId, nonce: Uint8Array):
 *    - Convert nonce to hex: Buffer.from(nonce).toString('hex')
 *    - Return whether the session's set contains this nonceHex
 *
 * 4. add(sessionId, nonce: Uint8Array, senderPubkey: Uint8Array):
 *    - Convert to hex strings
 *    - If already present: log message.nonce.duplicate DEBUG, return true (is duplicate)
 *    - If session set size >= 10,000: LRU evict oldest (lowest seen_at)
 *      - DELETE from session_seen_nonces WHERE session_id AND nonce_hex = oldest
 *      - Remove from in-memory map
 *    - INSERT into session_seen_nonces
 *    - Add to in-memory map
 *    - Return false (not a duplicate)
 *
 * 5. checkAndAdd(sessionId, nonce: Uint8Array, senderPubkey: Uint8Array):
 *    - If has(sessionId, nonce): log duplicate, return true (duplicate)
 *    - Otherwise: add, return false (new)
 *    - Combined check-and-add for atomic dedup logic
 */

import type { DatabaseSync } from "node:sqlite";
import type { Logger } from "./types.js";

/** LRU cap per outline.md Resource Caps. */
export const NONCE_DEDUP_CAP = 10_000;

interface NonceEntry {
  nonceHex: string;
  senderPubkey: string;
  seenAt: number;
}

export class NonceDedupStore {
  readonly #db: DatabaseSync;
  readonly #logger: Logger;
  /**
   * Per-session ordered map: nonceHex → NonceEntry.
   * Insertion order approximates LRU (oldest first in iteration).
   * For exact LRU we track seenAt and find the minimum.
   */
  #sessions = new Map<string, Map<string, NonceEntry>>();

  constructor(db: DatabaseSync, logger: Logger) {
    this.#db = db;
    this.#logger = logger;

    // Create table + index if not exists (inline migration — not Flyway)
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS session_seen_nonces (
        session_id      TEXT    NOT NULL,
        nonce_hex       TEXT    NOT NULL,
        sender_pubkey   TEXT    NOT NULL,
        seen_at         INTEGER NOT NULL,
        PRIMARY KEY (session_id, nonce_hex)
      )
    `);
    this.#db.exec(`
      CREATE INDEX IF NOT EXISTS seen_nonces_by_session_seen_at
        ON session_seen_nonces(session_id, seen_at ASC)
    `);
  }

  /**
   * Load all nonce entries from SQLCipher into memory.
   * Must complete BEFORE the IPC socket opens (AC-007).
   */
  loadFromDb(): void {
    const rows = this.#db
      .prepare("SELECT session_id, nonce_hex, sender_pubkey, seen_at FROM session_seen_nonces ORDER BY session_id, seen_at ASC")
      .all() as unknown as Array<{
        session_id: string;
        nonce_hex: string;
        sender_pubkey: string;
        seen_at: number;
      }>;

    this.#sessions.clear();

    for (const row of rows) {
      let sessionMap = this.#sessions.get(row.session_id);
      if (!sessionMap) {
        sessionMap = new Map();
        this.#sessions.set(row.session_id, sessionMap);
      }
      sessionMap.set(row.nonce_hex, {
        nonceHex: row.nonce_hex,
        senderPubkey: row.sender_pubkey,
        seenAt: row.seen_at,
      });
    }
  }

  /**
   * Check if a nonce has been seen for a session.
   */
  has(sessionId: string, nonce: Uint8Array): boolean {
    const nonceHex = Buffer.from(nonce).toString("hex");
    const sessionMap = this.#sessions.get(sessionId);
    if (!sessionMap) return false;
    return sessionMap.has(nonceHex);
  }

  /**
   * Check if nonce is a duplicate; if not, add it to the store.
   * Returns true if the nonce is a DUPLICATE (should be discarded).
   * Returns false if the nonce is NEW (should be delivered).
   *
   * This is the combined check-and-add for the daemon's inbound message path.
   */
  checkAndAdd(sessionId: string, nonce: Uint8Array, senderPubkey: Uint8Array): boolean {
    const nonceHex = Buffer.from(nonce).toString("hex");
    const senderPubkeyHex = Buffer.from(senderPubkey).toString("hex");

    let sessionMap = this.#sessions.get(sessionId);
    if (!sessionMap) {
      sessionMap = new Map();
      this.#sessions.set(sessionId, sessionMap);
    }

    // Check for duplicate
    if (sessionMap.has(nonceHex)) {
      this.#logger.info("message.nonce.duplicate", {
        sessionId,
        nonce: nonceHex,
        senderPubkey: senderPubkeyHex,
      });
      return true; // duplicate — discard
    }

    // LRU eviction if at cap
    if (sessionMap.size >= NONCE_DEDUP_CAP) {
      this.#evictOldest(sessionId, sessionMap);
    }

    // Add new nonce
    const seenAt = Date.now();
    const entry: NonceEntry = { nonceHex, senderPubkey: senderPubkeyHex, seenAt };
    sessionMap.set(nonceHex, entry);

    // Persist to SQLCipher
    try {
      this.#db
        .prepare(
          `INSERT INTO session_seen_nonces (session_id, nonce_hex, sender_pubkey, seen_at)
           VALUES (?, ?, ?, ?)`,
        )
        .run(sessionId, nonceHex, senderPubkeyHex, seenAt);
    } catch (err: unknown) {
      this.#logger.error("message.nonce.persist.failed", {
        sessionId,
        nonce: nonceHex,
        error: err instanceof Error ? err.message : String(err),
      });
    }

    return false; // new — deliver
  }

  /**
   * Evict the oldest entry (lowest seen_at) for a session.
   */
  #evictOldest(sessionId: string, sessionMap: Map<string, NonceEntry>): void {
    // Find entry with lowest seen_at
    let oldest: NonceEntry | null = null;
    for (const entry of sessionMap.values()) {
      if (!oldest || entry.seenAt < oldest.seenAt) {
        oldest = entry;
      }
    }

    if (!oldest) return;

    // Delete from DB
    try {
      this.#db
        .prepare("DELETE FROM session_seen_nonces WHERE session_id = ? AND nonce_hex = ?")
        .run(sessionId, oldest.nonceHex);
    } catch (err: unknown) {
      this.#logger.error("message.nonce.persist.failed", {
        sessionId,
        nonce: oldest.nonceHex,
        error: err instanceof Error ? err.message : String(err),
      });
    }

    // Remove from memory
    sessionMap.delete(oldest.nonceHex);
  }
}
