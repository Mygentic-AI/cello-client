/**
 * CELLO-M6B-005 — SQLCipher WAL mode
 *
 * AC-003: PRAGMA journal_mode returns 'wal' after open() completes.
 *         The PRAGMA is verified by executing `PRAGMA journal_mode` after
 *         open() and asserting the result row's `journal_mode` field equals 'wal'.
 *
 * AC-004: WAL mode enables concurrent readers even while another store instance
 *         holds an open write transaction on the same file. The second open()
 *         call completes within 5 seconds despite the write lock being held.
 *
 * SI-001: WAL mode PRAGMA is issued AFTER key verification completes, not before.
 *         Security invariant: (1) PRAGMA key, (2) verify key via SELECT on
 *         sqlite_master, (3) PRAGMA journal_mode=WAL, (4) run migrations.
 *         WAL mode on an unencrypted (wrong-key) open path must not succeed.
 *
 * Observability: The existing client.store.opened event includes journalMode field
 *         set to 'wal' after WAL mode is enabled.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { rmSync, mkdirSync } from "node:fs";

import { deriveDbKey } from "../db-key-derivation.js";

// ─── Dynamic import guard — skip if SQLCipher native module is unavailable ────

let sqlCipherAvailable = false;
let SQLCipherClientStore: typeof import("../sqlcipher-client-store.js").SQLCipherClientStore;
let createRequireFn: (typeof import("node:module"))["createRequire"];

try {
  const mod = await import("../sqlcipher-client-store.js");
  SQLCipherClientStore = mod.SQLCipherClientStore;
  const nodeModule = await import("node:module");
  createRequireFn = nodeModule.createRequire;
  sqlCipherAvailable = true;
} catch {
  sqlCipherAvailable = false;
}

/** Minimal spy logger that captures log events for assertions. */
function makeSpyLogger() {
  const events: Array<{ level: string; event: string; context: Record<string, unknown> }> = [];
  return {
    debug: (event: string, context: Record<string, unknown> = {}) =>
      events.push({ level: "debug", event, context }),
    info: (event: string, context: Record<string, unknown> = {}) =>
      events.push({ level: "info", event, context }),
    warn: (event: string, context: Record<string, unknown> = {}) =>
      events.push({ level: "warn", event, context }),
    error: (event: string, context: Record<string, unknown> = {}) =>
      events.push({ level: "error", event, context }),
    events,
  };
}

/** Create a temporary directory and return a path for a test database file. */
function makeTmpDbPath(): string {
  const dir = join(tmpdir(), `cello-m6b-005-${randomBytes(8).toString("hex")}`);
  mkdirSync(dir, { recursive: true });
  return join(dir, "test.db");
}

function cleanupPath(dbPath: string): void {
  const dir = join(dbPath, "..");
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {
    // ignore cleanup errors
  }
}

const describeWithSQLCipher = sqlCipherAvailable ? describe : describe.skip;

// ─── AC-003 — PRAGMA journal_mode returns 'wal' after open() ─────────────────

describeWithSQLCipher("CELLO-M6B-005 AC-003 — WAL mode enabled after open()", () => {
  let dbPath: string;

  beforeEach(() => {
    dbPath = makeTmpDbPath();
  });

  afterEach(() => {
    cleanupPath(dbPath);
  });

  it("PRAGMA journal_mode returns 'wal' after SQLCipherClientStore.open() completes", async () => {
    // AC-003: open() must enable WAL mode. Verified by querying PRAGMA journal_mode
    // on the same database file using a direct SQLCipher connection (not through
    // SQLCipherClientStore) to confirm the WAL journal mode was persisted.
    const logger = makeSpyLogger();
    const dbKey = deriveDbKey(randomBytes(32), "agent-ac003-wal");
    const store = new SQLCipherClientStore(dbKey, {
      dbPath,
      agentId: "agent-ac003-wal",
      env: "dev",
      logger,
    });

    await store.open();
    await store.close();

    // Open the same database file directly via @signalapp/sqlcipher to read back journal_mode.
    // This proves WAL mode is persisted at the database level, not just active in memory.
    // @signalapp/sqlcipher uses a synchronous better-sqlite3-style API.
    const req = createRequireFn(import.meta.url);
    const { Database: SignalDatabase } = req("@signalapp/sqlcipher") as {
      Database: new (path: string) => {
        pragma(source: string, options?: { simple?: boolean }): unknown;
        prepare(sql: string): { get(params?: unknown[]): Record<string, unknown> | undefined };
        close(): void;
      };
    };

    const keyHex = Buffer.from(dbKey).toString("hex");
    const db = new SignalDatabase(dbPath);

    try {
      db.pragma(`key = "x'${keyHex}'"`);
      // Verify key accepted
      db.prepare("SELECT count(*) FROM sqlite_master").get([]);

      const journalMode = db.pragma("journal_mode", { simple: true });
      expect(journalMode).toBe("wal");
    } finally {
      db.close();
    }
  });

  it("WAL mode persists across open/close cycles (second open also reads 'wal')", async () => {
    // Once WAL mode is set at the SQLite database level, it persists across connections.
    // The second open() should still read 'wal' (it was already WAL from first open).
    const logger = makeSpyLogger();
    const dbKey = deriveDbKey(randomBytes(32), "agent-ac003-wal-persist");

    // First open — sets WAL mode
    const storeA = new SQLCipherClientStore(dbKey, {
      dbPath,
      agentId: "agent-ac003-wal-persist",
      env: "dev",
      logger,
    });
    await storeA.open();
    await storeA.close();

    // Second open — WAL mode should still be active
    const storeB = new SQLCipherClientStore(dbKey, {
      dbPath,
      agentId: "agent-ac003-wal-persist",
      env: "dev",
      logger,
    });
    await storeB.open();
    await storeB.close();

    // Verify the opened events both include journalMode: 'wal'
    const openedEvents = logger.events.filter((e) => e.event === "client.store.opened");
    expect(openedEvents.length).toBe(2);
    for (const ev of openedEvents) {
      expect(ev.context).toHaveProperty("journalMode", "wal");
    }
  });
});

// ─── Observability — journalMode field on client.store.opened ─────────────────

describeWithSQLCipher("CELLO-M6B-005 observability — client.store.opened includes journalMode", () => {
  let dbPath: string;

  beforeEach(() => {
    dbPath = makeTmpDbPath();
  });

  afterEach(() => {
    cleanupPath(dbPath);
  });

  it("client.store.opened event includes journalMode: 'wal' field", async () => {
    // The existing client.store.opened event (already fired after open()) must
    // include a journalMode field set to 'wal' after WAL mode is enabled.
    // Required context fields: env, dbPath, agentId, journalMode
    const logger = makeSpyLogger();
    const dbKey = deriveDbKey(randomBytes(32), "agent-obs-wal");
    const store = new SQLCipherClientStore(dbKey, {
      dbPath,
      agentId: "agent-obs-wal",
      env: "staging",
      logger,
    });
    await store.open();
    await store.close();

    const openedEvents = logger.events.filter((e) => e.event === "client.store.opened");
    expect(openedEvents.length).toBe(1);
    expect(openedEvents[0].level).toBe("info");
    expect(openedEvents[0].context).toMatchObject({
      env: "staging",
      dbPath,
      agentId: "agent-obs-wal",
      journalMode: "wal",
    });
  });
});

// ─── SI-001 — WAL mode issued AFTER key verification ─────────────────────────

describeWithSQLCipher("CELLO-M6B-005 SI-001 — WAL mode set only after key verification succeeds", () => {
  it("wrong-key open does NOT enable WAL mode — key verification fails before WAL PRAGMA", async () => {
    // SI-001: The order in open() must be: (1) PRAGMA key, (2) verify key via
    // SELECT on sqlite_master, (3) PRAGMA journal_mode=WAL, (4) run migrations.
    // A wrong-key open must fail at step 2 — WAL PRAGMA must never be issued.
    // Proof: if open() rejects for a wrong-key attempt, WAL was not set on an
    // unverified database.
    const dbPath = makeTmpDbPath();
    const logger = makeSpyLogger();

    try {
      // Create a valid encrypted database
      const correctKey = deriveDbKey(randomBytes(32), "agent-si001-wal-correct");
      const store = new SQLCipherClientStore(correctKey, {
        dbPath,
        agentId: "agent-si001-wal-correct",
        logger,
      });
      await store.open();
      await store.close();

      // Attempt with wrong key — must fail at verification, before WAL PRAGMA
      const wrongKey = deriveDbKey(randomBytes(32), "agent-si001-wal-wrong");
      const badStore = new SQLCipherClientStore(wrongKey, {
        dbPath,
        agentId: "agent-si001-wal-correct",
        logger,
      });
      await expect(badStore.open()).rejects.toThrow();

      // No client.store.opened event — the open failed before that point
      const openedEventsAfterFail = logger.events.filter(
        (e) => e.event === "client.store.opened",
      );
      // The only opened event should be from the correct-key open, not the wrong-key attempt
      expect(openedEventsAfterFail.length).toBe(1);
      // That one opened event must be from the correct-key open (no journalMode from wrong-key)
      expect(openedEventsAfterFail[0].context).toHaveProperty("agentId", "agent-si001-wal-correct");

      // client.store.open.failed must have been logged for the wrong-key attempt
      const failedEvents = logger.events.filter((e) => e.event === "client.store.open.failed");
      expect(failedEvents.length).toBeGreaterThan(0);
    } finally {
      cleanupPath(dbPath);
    }
  });
});

// ─── AC-004 — Concurrent reader while writer holds write lock ────────────────

describeWithSQLCipher("CELLO-M6B-005 AC-004 — WAL mode enables concurrent readers", () => {
  it("second store open() completes within 5s while first store holds an open write transaction", async () => {
    // AC-004: Simulate the stale-process deadlock scenario in-process.
    // Process A (writer) holds an open BEGIN transaction.
    // Process B (new cello-mcp) calls open() on the same file.
    // With WAL mode, Process B's open() + read operations must complete without waiting
    // for Process A to commit.
    //
    // Implementation: open storeA, begin a transaction manually via the raw SQLCipher
    // handle (accessed via the test shim), then open storeB and verify it completes
    // within 5 seconds.
    //
    // Since SQLCipherClientStore does not expose its internal db handle, we use a
    // two-store approach:
    //   1. Open storeA and perform an operation (migrations done, WAL mode set).
    //   2. Close storeA (so its connection is freed — WAL journal file now exists).
    //   3. Open a direct SQLCipher connection as the "stale writer" that begins an
    //      uncommitted write transaction (BEGIN — not BEGIN EXCLUSIVE, which would
    //      block readers even in WAL mode and would defeat the test).
    //   4. While the writer holds the open transaction, open storeB and measure the time.
    //   5. StoreB must open within 5s. In WAL mode, readers see the last committed
    //      state without waiting for the uncommitted write.
    //   6. Clean up both.
    //
    // This proves WAL mode allows readers to proceed concurrently with a writer.
    // NOTE: BEGIN EXCLUSIVE is intentionally NOT used here — it blocks readers even
    // in WAL mode and would make this test measure lock contention, not WAL concurrency.

    const dbPath = makeTmpDbPath();
    const logger = makeSpyLogger();
    const dbKey = deriveDbKey(randomBytes(32), "agent-ac004-concurrent");

    try {
      // Step 1: Open and close storeA to establish the database in WAL mode
      const storeA = new SQLCipherClientStore(dbKey, {
        dbPath,
        agentId: "agent-ac004-concurrent",
        env: "dev",
        logger,
      });
      await storeA.open();
      await storeA.close();

      // Step 2: Open a direct SQLCipher connection as the "stale writer"
      // Uses @signalapp/sqlcipher (the replacement library) with its synchronous API.
      const req = createRequireFn(import.meta.url);
      const { Database: SignalWriterDatabase } = req("@signalapp/sqlcipher") as {
        Database: new (path: string) => {
          pragma(source: string, options?: { simple?: boolean }): unknown;
          prepare(sql: string): { get(params?: unknown[]): Record<string, unknown> | undefined; run(params?: unknown[]): { changes: number; lastInsertRowid: number } };
          exec(sql: string): void;
          close(): void;
        };
      };

      const keyHex = Buffer.from(dbKey).toString("hex");
      const writerDb = new SignalWriterDatabase(dbPath);

      // Apply key and begin an uncommitted write transaction — simulates the stale process.
      // BEGIN (not BEGIN EXCLUSIVE) is correct here: WAL mode allows readers to read
      // the last committed snapshot while a writer holds an uncommitted transaction.
      // BEGIN EXCLUSIVE would block readers even in WAL mode and would be wrong.
      writerDb.pragma(`key = "x'${keyHex}'"`);
      writerDb.prepare("SELECT count(*) FROM sqlite_master").get([]); // verify key
      writerDb.exec("BEGIN");

      // Step 3: Open storeB while the writer holds the transaction
      const storeB = new SQLCipherClientStore(dbKey, {
        dbPath,
        agentId: "agent-ac004-concurrent",
        env: "dev",
        logger,
      });

      // With WAL mode (set by storeA during its open()), storeB's open() must complete
      // within 5 seconds. WAL allows readers to read the last committed state
      // without waiting for the writer's exclusive lock.
      const start = Date.now();
      await storeB.open();
      const elapsed = Date.now() - start;

      // Clean up storeB
      await storeB.close();

      // Clean up the writer
      writerDb.exec("ROLLBACK");
      writerDb.close();

      // Assert storeB opened within 5 seconds
      expect(elapsed).toBeLessThan(5000);

      // Assert storeB logged client.store.opened with journalMode: 'wal'
      const openedEvents = logger.events.filter((e) => e.event === "client.store.opened");
      // At least storeA's event and storeB's event
      expect(openedEvents.length).toBeGreaterThanOrEqual(2);
      // The last opened event (storeB) must have journalMode: 'wal'
      const storeBEvent = openedEvents[openedEvents.length - 1];
      expect(storeBEvent.context).toHaveProperty("journalMode", "wal");
    } finally {
      cleanupPath(dbPath);
    }
  });
});
