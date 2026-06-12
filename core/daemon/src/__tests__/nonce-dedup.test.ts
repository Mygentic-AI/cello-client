/**
 * CELLO-M7-DAEMON-003 — NonceDedupStore unit tests
 *
 * ACs covered:
 * - AC-004: duplicate nonce discarded, message.nonce.duplicate logged at DEBUG
 * - AC-011: LRU eviction at cap 10,000 (oldest evicted, new accepted)
 * - AC-005: persistence across restart (loadFromDb restores nonces)
 * - AC-006: typed serializer (nonce Uint8Array survives hex round-trip)
 *
 * AC interpretations:
 * - AC-004: "logged at DEBUG" — per the Logger interface we have info/warn/error.
 *   The story says DEBUG level, but our Logger interface only has info/warn/error.
 *   We'll use logger.info for message.nonce.duplicate (it's a known-nonce event,
 *   not an error). The story's DEBUG intent is that it should NOT pollute important
 *   log streams. In production the Logger implementation can filter by event name.
 *   UPDATE: Re-reading the story, it says "logged at DEBUG with sessionId, nonce (hex),
 *   and senderPubkey (hex)". Since our Logger has no .debug method, we use .info
 *   and note this is a deliberate interpretation. The production Logger adapter will
 *   route message.nonce.duplicate to DEBUG level based on the event name.
 * - AC-011: We pre-seed exactly 10,000 entries and verify the oldest is evicted
 *   when entry 10,001 is added.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { randomBytes } from "node:crypto";
import { NonceDedupStore, NONCE_DEDUP_CAP } from "../nonce-dedup.js";
import type { Logger } from "../types.js";

describe("NonceDedupStore", () => {
  let db: DatabaseSync;
  let logEvents: Array<{ level: string; event: string; context: Record<string, unknown> }>;
  let logger: Logger;
  let store: NonceDedupStore;

  beforeEach(() => {
    db = new DatabaseSync(":memory:");
    logEvents = [];
    logger = {
      info(event, context) { logEvents.push({ level: "info", event, context }); },
      warn(event, context) { logEvents.push({ level: "warn", event, context }); },
      error(event, context) { logEvents.push({ level: "error", event, context }); },
    };
    store = new NonceDedupStore(db, logger);
  });

  afterEach(() => {
    db.close();
  });

  describe("AC-004: duplicate nonce detection and discard", () => {
    it("returns false (not duplicate) for a new nonce", () => {
      const sessionId = "session-new";
      const nonce = randomBytes(32);
      const sender = randomBytes(32);

      const isDuplicate = store.checkAndAdd(sessionId, nonce, sender);
      expect(isDuplicate).toBe(false);
    });

    it("returns true (duplicate) for a previously seen nonce", () => {
      const sessionId = "session-dup";
      const nonce = randomBytes(32);
      const sender = randomBytes(32);

      // First time — new
      store.checkAndAdd(sessionId, nonce, sender);

      // Second time — duplicate
      const isDuplicate = store.checkAndAdd(sessionId, nonce, sender);
      expect(isDuplicate).toBe(true);
    });

    it("logs message.nonce.duplicate with correct context fields", () => {
      const sessionId = "session-dup-log";
      const nonce = randomBytes(32);
      const sender = randomBytes(32);

      store.checkAndAdd(sessionId, nonce, sender);
      logEvents.length = 0;

      store.checkAndAdd(sessionId, nonce, sender);

      const dupEvent = logEvents.find((e) => e.event === "message.nonce.duplicate");
      expect(dupEvent).toBeDefined();
      expect(dupEvent!.context.sessionId).toBe(sessionId);
      expect(dupEvent!.context.nonce).toBe(Buffer.from(nonce).toString("hex"));
      expect(dupEvent!.context.senderPubkey).toBe(Buffer.from(sender).toString("hex"));
    });

    it("same nonce in different sessions is NOT a duplicate", () => {
      const nonce = randomBytes(32);
      const sender = randomBytes(32);

      store.checkAndAdd("session-A", nonce, sender);
      const isDuplicate = store.checkAndAdd("session-B", nonce, sender);
      expect(isDuplicate).toBe(false);
    });
  });

  describe("AC-011: LRU eviction at cap 10,000", () => {
    it("evicts oldest nonce when at cap and accepts the new one", () => {
      const sessionId = "session-lru";
      const sender = randomBytes(32);

      // Pre-seed with 10,000 nonces using direct DB inserts for speed
      const insertStmt = db.prepare(
        "INSERT INTO session_seen_nonces (session_id, nonce_hex, sender_pubkey, seen_at) VALUES (?, ?, ?, ?)",
      );

      const oldestNonce = randomBytes(32);
      const oldestNonceHex = Buffer.from(oldestNonce).toString("hex");
      insertStmt.run(sessionId, oldestNonceHex, Buffer.from(sender).toString("hex"), 1);

      for (let i = 1; i < NONCE_DEDUP_CAP; i++) {
        const n = randomBytes(32);
        insertStmt.run(sessionId, Buffer.from(n).toString("hex"), Buffer.from(sender).toString("hex"), i + 1);
      }

      // Load from DB to populate in-memory state
      store.loadFromDb();

      // Verify oldest is present before eviction
      expect(store.has(sessionId, oldestNonce)).toBe(true);

      // Add one more — triggers LRU eviction of the oldest
      const newNonce = randomBytes(32);
      const isDuplicate = store.checkAndAdd(sessionId, newNonce, sender);
      expect(isDuplicate).toBe(false);

      // (a) Set size remains at 10,000
      const count = (db.prepare("SELECT COUNT(*) as cnt FROM session_seen_nonces WHERE session_id = ?").get(sessionId) as unknown as { cnt: number }).cnt;
      expect(count).toBe(NONCE_DEDUP_CAP);

      // (b) Oldest nonce is absent
      expect(store.has(sessionId, oldestNonce)).toBe(false);

      // (c) New nonce is present
      expect(store.has(sessionId, newNonce)).toBe(true);

      // (d) has(evictedNonce) returns false
      expect(store.has(sessionId, oldestNonce)).toBe(false);

      // (e) has(newNonce) returns true
      expect(store.has(sessionId, newNonce)).toBe(true);
    });

    it("evicted nonce is not recognized as a duplicate after eviction", () => {
      const sessionId = "session-evict-replay";
      const sender = randomBytes(32);

      // Insert exactly NONCE_DEDUP_CAP nonces via DB for speed
      const insertStmt = db.prepare(
        "INSERT INTO session_seen_nonces (session_id, nonce_hex, sender_pubkey, seen_at) VALUES (?, ?, ?, ?)",
      );

      const oldestNonce = randomBytes(32);
      insertStmt.run(sessionId, Buffer.from(oldestNonce).toString("hex"), Buffer.from(sender).toString("hex"), 1);

      for (let i = 1; i < NONCE_DEDUP_CAP; i++) {
        insertStmt.run(sessionId, Buffer.from(randomBytes(32)).toString("hex"), Buffer.from(sender).toString("hex"), i + 1);
      }

      store.loadFromDb();

      // Trigger eviction
      store.checkAndAdd(sessionId, randomBytes(32), sender);

      // The evicted nonce should NOT be recognized as duplicate
      // (this proves the acceptable tradeoff per Q6)
      const isDuplicate = store.checkAndAdd(sessionId, oldestNonce, sender);
      expect(isDuplicate).toBe(false);
    });
  });

  describe("AC-005: persistence across restart", () => {
    it("nonces survive daemon restart (loadFromDb populates in-memory LRU)", () => {
      const sessionId = "session-restart";
      const nonce = randomBytes(32);
      const sender = randomBytes(32);

      // First "daemon lifetime" — add a nonce
      store.checkAndAdd(sessionId, nonce, sender);

      // Simulate restart: create new store from same DB
      const store2 = new NonceDedupStore(db, logger);
      store2.loadFromDb();

      // The nonce must be recognized as a duplicate after restart
      const isDuplicate = store2.checkAndAdd(sessionId, nonce, sender);
      expect(isDuplicate).toBe(true);
    });

    it("multiple sessions with nonces all survive restart", () => {
      const nonceA = randomBytes(32);
      const nonceB = randomBytes(32);
      const sender = randomBytes(32);

      store.checkAndAdd("session-1", nonceA, sender);
      store.checkAndAdd("session-2", nonceB, sender);

      // Restart
      const store2 = new NonceDedupStore(db, logger);
      store2.loadFromDb();

      expect(store2.has("session-1", nonceA)).toBe(true);
      expect(store2.has("session-2", nonceB)).toBe(true);
    });
  });

  describe("AC-006: typed serializer — Uint8Array type integrity", () => {
    it("has() works with the same Uint8Array bytes (not object reference)", () => {
      const sessionId = "session-type";
      const nonceBytes = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]);
      const sender = randomBytes(32);

      store.checkAndAdd(sessionId, nonceBytes, sender);

      // Restart and check with a freshly-constructed Uint8Array with same bytes
      const store2 = new NonceDedupStore(db, logger);
      store2.loadFromDb();

      const sameBytesNewArray = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]);
      expect(store2.has(sessionId, sameBytesNewArray)).toBe(true);
    });

    it("hex conversion preserves all byte values 0-255", () => {
      const sessionId = "session-allbytes";
      // A nonce containing boundary values that would break with JSON.stringify
      const nonce = new Uint8Array(32);
      nonce[0] = 0;
      nonce[1] = 255;
      nonce[2] = 128;
      nonce[31] = 127;
      const sender = randomBytes(32);

      store.checkAndAdd(sessionId, nonce, sender);

      const store2 = new NonceDedupStore(db, logger);
      store2.loadFromDb();

      expect(store2.has(sessionId, nonce)).toBe(true);
    });
  });

  describe("has() without checkAndAdd", () => {
    it("returns false for unknown session", () => {
      expect(store.has("nonexistent", randomBytes(32))).toBe(false);
    });

    it("returns false for unknown nonce in known session", () => {
      const sender = randomBytes(32);
      store.checkAndAdd("known-session", randomBytes(32), sender);
      expect(store.has("known-session", randomBytes(32))).toBe(false);
    });
  });
});
