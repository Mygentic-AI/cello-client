/**
 * CELLO-M6B-013 — SQLCipher Replacement: Cross-Library Compatibility Test
 *
 * AC-002: An existing ~/.cello/client.db created with @journeyapps/sqlcipher
 *   (kept as devDependency for this test only) opens correctly with the
 *   replacement library (@signalapp/sqlcipher).
 *
 *   Test procedure (per AC-002 specification):
 *     1. Create a database using the OLD library (@journeyapps/sqlcipher).
 *     2. Write a row with a known signing_share Uint8Array (BLOB column).
 *     3. Open the SAME .db file with the REPLACEMENT library (@signalapp/sqlcipher).
 *     4. Read the row back and assert:
 *        (a) Buffer.isBuffer(row.signing_share) || row.signing_share instanceof Uint8Array
 *        (b) Byte equality: the bytes read back match the bytes written.
 *
 *   Byte equality alone is NOT sufficient — a plain object could satisfy bytes
 *   matching while breaking downstream crypto (e.g., frost_key_share deserialization).
 *
 * AC-005: WAL mode still works with the replacement library.
 *
 * SI-001: The db_key (derived encryption key) NEVER appears in any log event,
 *   error message, or return value.
 *
 * SI-002: The replacement library must not use a weaker cipher than AES-256-CBC.
 *   Verified by auditing the initialization code for cipher_* PRAGMAs and
 *   confirming kdf_iter = 256000 (SQLCipher 4 default).
 *
 * IMPORTANT: This test requires both @journeyapps/sqlcipher (devDependency) and
 * @signalapp/sqlcipher (production dependency) to be installed. If either is
 * unavailable (e.g., CELLO_ENV=local without devDependencies), the tests skip.
 */

import { describe, it, expect } from "vitest";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { rmSync, mkdirSync } from "node:fs";
import { createRequire } from "node:module";

import { deriveDbKey } from "../db-key-derivation.js";

// ─── Module availability guard ────────────────────────────────────────────────

// Both libraries must be available to run the cross-compatibility test.
// @journeyapps/sqlcipher is a devDependency (for this test only).
// @signalapp/sqlcipher is the production replacement library.

const req = createRequire(import.meta.url);

let journeyAvailable = false;
let signalAvailable = false;

// Type shim for @journeyapps/sqlcipher (callback-based async API)
interface JourneyRawDb {
  run: (sql: string, params: unknown[], cb: (this: { lastID: number; changes: number }, err: Error | null) => void) => void;
  get: (sql: string, params: unknown[], cb: (err: Error | null, row?: Record<string, unknown>) => void) => void;
  close: (cb: (err: Error | null) => void) => void;
  serialize: (fn: () => void) => void;
}
interface JourneyModule {
  Database: new (f: string, m: number, cb: (e: Error | null) => void) => JourneyRawDb;
  OPEN_READWRITE: number;
  OPEN_CREATE: number;
}

// Type shim for @signalapp/sqlcipher (synchronous API)
interface SignalRawStatement<T = Record<string, unknown>> {
  run(params?: unknown[]): { changes: number; lastInsertRowid: number };
  get(params?: unknown[]): T | undefined;
  all(params?: unknown[]): T[];
}
interface SignalRawDb {
  pragma(source: string, options?: { simple?: boolean }): unknown;
  prepare<T = Record<string, unknown>>(sql: string): SignalRawStatement<T>;
  exec(sql: string): void;
  close(): void;
}
interface SignalModule {
  Database: new (path: string) => SignalRawDb;
}

let journeyMod: JourneyModule | null = null;
let signalMod: SignalModule | null = null;

try {
  journeyMod = req("@journeyapps/sqlcipher") as JourneyModule;
  journeyAvailable = true;
} catch {
  // @journeyapps/sqlcipher not available (production install without devDependencies)
}

try {
  signalMod = req("@signalapp/sqlcipher") as SignalModule;
  signalAvailable = true;
} catch {
  // @signalapp/sqlcipher not available
}

const describeCompat = journeyAvailable && signalAvailable ? describe : describe.skip;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeTmpDbPath(): string {
  const dir = join(tmpdir(), `cello-m6b-013-${randomBytes(8).toString("hex")}`);
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

/**
 * Open a database with @journeyapps/sqlcipher and apply the encryption key.
 * Returns a promisified helper object for test use only.
 */
async function openWithJourney(journey: JourneyModule, dbPath: string, keyHex: string): Promise<{
  run(sql: string): Promise<void>;
  get(sql: string): Promise<Record<string, unknown> | undefined>;
  close(): Promise<void>;
}> {
  const mode = journey.OPEN_READWRITE | journey.OPEN_CREATE;
  const db = await new Promise<JourneyRawDb>((resolve, reject) => {
    const d = new journey.Database(dbPath, mode, (err) => {
      if (err) reject(err);
      else resolve(d);
    });
  });

  const run = (sql: string): Promise<void> =>
    new Promise<void>((res, rej) =>
      db.run(sql, [], function (err) {
        if (err) rej(err);
        else res();
      }),
    );

  const get = (sql: string): Promise<Record<string, unknown> | undefined> =>
    new Promise<Record<string, unknown> | undefined>((res, rej) =>
      db.get(sql, [], (err, row) => {
        if (err) rej(err);
        else res(row);
      }),
    );

  const close = (): Promise<void> =>
    new Promise<void>((res, rej) =>
      db.close((err) => {
        if (err) rej(err);
        else res();
      }),
    );

  await run(`PRAGMA key = "x'${keyHex}'"`);
  // Verify key accepted
  await get("SELECT count(*) FROM sqlite_master");

  return { run, get, close };
}

// ─── AC-002: Cross-library compatibility ────────────────────────────────────

describeCompat("CELLO-M6B-013 AC-002 — Cross-library SQLCipher database compatibility", () => {
  it("AC-002: database created with @journeyapps/sqlcipher opens with @signalapp/sqlcipher — BLOB fields preserved as Buffer/Uint8Array with byte equality", async () => {
    // CRITICAL AC: verifies that existing ~/.cello/client.db files created by
    // @journeyapps/sqlcipher are readable by the replacement library.
    // If this test fails, the migration is NOT feasible without a re-encryption step
    // that would break existing user databases.

    const dbPath = makeTmpDbPath();
    const identityKey = randomBytes(32);
    const dbKey = deriveDbKey(identityKey, "m6b-013-compat-agent");
    const keyHex = Buffer.from(dbKey).toString("hex");

    // Known test data — the signing_share is a raw binary blob (simulates FROST key share)
    const knownSigningShare = new Uint8Array([
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
      0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    ]);

    try {
      // Step 1-2: Create DB with @journeyapps/sqlcipher and write BLOB data
      const journey = openWithJourney(journeyMod!, dbPath, keyHex);
      const journeyDb = await journey;

      await journeyDb.run(
        `CREATE TABLE frost_key_shares (
          id TEXT PRIMARY KEY,
          signing_share BLOB NOT NULL
        )`,
      );
      await journeyDb.run(
        `INSERT INTO frost_key_shares (id, signing_share) VALUES ('share-1', x'${Buffer.from(knownSigningShare).toString("hex")}')`,
      );
      await journeyDb.close();

      // Step 3: Open the SAME file with @signalapp/sqlcipher (replacement library)
      const signalDb = new signalMod!.Database(dbPath);
      signalDb.pragma(`key = "x'${keyHex}'"`);
      // Verify key accepted (also proves database format is compatible)
      signalDb.prepare("SELECT count(*) as c FROM sqlite_master").get([]);

      // Step 4a+4b: Read the BLOB row and assert type + byte equality
      const row = signalDb.prepare<{ id: string; signing_share: Buffer }>(
        "SELECT id, signing_share FROM frost_key_shares WHERE id = 'share-1'",
      ).get([]);

      signalDb.close();

      // 4a: The returned value must be a Buffer or Uint8Array — not a plain object
      expect(row).toBeDefined();
      expect(row!.signing_share).toBeDefined();
      expect(
        Buffer.isBuffer(row!.signing_share) || row!.signing_share instanceof Uint8Array,
        `signing_share must be Buffer or Uint8Array, got: ${typeof row!.signing_share} (${Object.prototype.toString.call(row!.signing_share)})`,
      ).toBe(true);

      // 4b: Byte equality — the bytes read back must match the bytes written
      const readBack = Buffer.isBuffer(row!.signing_share)
        ? row!.signing_share
        : Buffer.from(row!.signing_share);
      const expected = Buffer.from(knownSigningShare);
      expect(readBack.length).toBe(expected.length);
      expect(readBack.equals(expected)).toBe(true);
    } finally {
      cleanupPath(dbPath);
    }
  });

  it("AC-002: PRAGMA key = \"x'<hexkey>'\" format is honored — database opened with same key format as @journeyapps/sqlcipher", async () => {
    // Verifies that @signalapp/sqlcipher accepts the exact PRAGMA key format used
    // by the existing production code: PRAGMA key = "x'<32-byte-hex>'"
    const dbPath = makeTmpDbPath();
    const identityKey = randomBytes(32);
    const dbKey = deriveDbKey(identityKey, "m6b-013-pragma-format");
    const keyHex = Buffer.from(dbKey).toString("hex");

    try {
      // Create with journey
      const journeyDb = await openWithJourney(journeyMod!, dbPath, keyHex);
      await journeyDb.run("CREATE TABLE t (x INTEGER)");
      await journeyDb.run("INSERT INTO t VALUES (42)");
      await journeyDb.close();

      // Open with signal using the same PRAGMA format
      const signalDb = new signalMod!.Database(dbPath);
      // This must not throw — proves format compatibility
      expect(() => signalDb.pragma(`key = "x'${keyHex}'"`)).not.toThrow();
      const row = signalDb.prepare<{ x: number }>("SELECT x FROM t").get([]);
      signalDb.close();

      expect(row?.x).toBe(42);
    } finally {
      cleanupPath(dbPath);
    }
  });
});

// ─── AC-005: WAL mode works with replacement library ─────────────────────────

describeCompat("CELLO-M6B-013 AC-005 — WAL mode supported by replacement library", () => {
  it("AC-005: PRAGMA journal_mode=WAL returns 'wal' with @signalapp/sqlcipher", () => {
    // Verifies that the replacement library supports PRAGMA journal_mode=WAL,
    // which is required by PREP-002 (M6B-005). The existing WAL test suite covers
    // this through SQLCipherClientStore, but this test verifies it at the library level.
    const dbPath = makeTmpDbPath();
    const dbKey = deriveDbKey(randomBytes(32), "m6b-013-wal-test");
    const keyHex = Buffer.from(dbKey).toString("hex");

    try {
      const db = new signalMod!.Database(dbPath);
      db.pragma(`key = "x'${keyHex}'"`);
      db.prepare("SELECT count(*) FROM sqlite_master").get([]);

      const walResult = db.pragma("journal_mode=WAL", { simple: true });
      db.close();

      expect(walResult).toBe("wal");
    } finally {
      cleanupPath(dbPath);
    }
  });
});

// ─── SI-001: db_key never in error messages ──────────────────────────────────

describeCompat("CELLO-M6B-013 SI-001 — db_key never in error messages from replacement library", () => {
  it("SI-001: wrong-key error from @signalapp/sqlcipher does not include the key hex in the message", () => {
    // Adversarial condition: if the replacement library throws an error on incorrect key,
    // the error message must not include the key bytes (per SI-001 in the story).
    const dbPath = makeTmpDbPath();
    const goodKey = deriveDbKey(randomBytes(32), "m6b-013-si001-good");
    const goodKeyHex = Buffer.from(goodKey).toString("hex");
    const badKey = deriveDbKey(randomBytes(32), "m6b-013-si001-bad");
    const badKeyHex = Buffer.from(badKey).toString("hex");

    try {
      // Create a database with the good key
      const db = new signalMod!.Database(dbPath);
      db.pragma(`key = "x'${goodKeyHex}'"`);
      db.prepare("SELECT count(*) FROM sqlite_master").get([]);
      db.exec("CREATE TABLE t (x INTEGER)");
      db.close();

      // Attempt to open with the wrong key — must throw
      let caughtError: Error | null = null;
      try {
        const badDb = new signalMod!.Database(dbPath);
        badDb.pragma(`key = "x'${badKeyHex}'"`);
        // This should throw when we try to query
        badDb.prepare("SELECT count(*) FROM sqlite_master").get([]);
        badDb.close();
      } catch (err: unknown) {
        caughtError = err instanceof Error ? err : new Error(String(err));
      }

      expect(caughtError).not.toBeNull();
      if (caughtError !== null) {
        // The error message must NOT contain the bad key hex
        expect(caughtError.message.toLowerCase()).not.toMatch(/[0-9a-f]{64}/i);
        // Confirm error is about invalid key/file, not something else
        expect(caughtError.message.length).toBeGreaterThan(0);
      }
    } finally {
      cleanupPath(dbPath);
    }
  });
});

// ─── SI-002: No weaker cipher than AES-256-CBC ───────────────────────────────

describeCompat("CELLO-M6B-013 SI-002 — Replacement library uses AES-256-CBC with SQLCipher 4 defaults", () => {
  it("SI-002: @signalapp/sqlcipher uses kdf_iter=256000 and cipher=aes-256-cbc (SQLCipher 4 defaults)", () => {
    // Verifies that the replacement library does NOT reduce cipher strength.
    // Audits initialization code by checking PRAGMA kdf_iter and PRAGMA cipher.
    const dbPath = makeTmpDbPath();
    const dbKey = deriveDbKey(randomBytes(32), "m6b-013-si002-cipher");
    const keyHex = Buffer.from(dbKey).toString("hex");

    try {
      const db = new signalMod!.Database(dbPath);
      db.pragma(`key = "x'${keyHex}'"`);
      db.prepare("SELECT count(*) FROM sqlite_master").get([]);

      // SQLCipher 4 defaults: 256000 iterations, AES-256-CBC
      const kdfIter = db.pragma("kdf_iter", { simple: true });
      const cipherName = db.pragma("cipher", { simple: true });
      db.close();

      expect(Number(kdfIter)).toBe(256000);
      expect(cipherName).toBe("aes-256-cbc");
    } finally {
      cleanupPath(dbPath);
    }
  });
});
