/**
 * CELLO-M7-PERSIST-002 — the daemon's single encrypted store (DEC-1).
 *
 * The daemon DB is a SQLCipher database (whole-file AES-256 at rest). This module is the ONE
 * engine site: it loads @signalapp/sqlcipher (prebuilt — DEC-1; no compile), opens the DB with a
 * PRAGMA key, verifies the key, enables WAL, and presents a thin `DaemonDatabase` adapter so the
 * rest of the daemon (SessionNodeManager, RetryQueue, NonceDedupStore) keeps its node:sqlite-style
 * varargs call sites unchanged.
 *
 * Why an adapter: node:sqlite's `DatabaseSync` uses varargs (`stmt.run(a, b, c)`); @signalapp's
 * better-sqlite3-style API takes an array (`stmt.run([a, b, c])`). The `DaemonDatabase` /
 * `DaemonStatement` interfaces expose the varargs surface — node:sqlite's `DatabaseSync` structurally
 * satisfies them too (used for in-memory test handles and for reading a legacy plaintext DB during
 * migration), and `SqlcipherDatabase` implements them by forwarding varargs as an array.
 *
 * Key custody (DEC-2/DEC-4): the SQLCipher key is a standalone random 32-byte 0600 key file beside
 * the DB. It is NOT derived from K_local (chicken-and-egg — K_local now lives inside the DB). It is
 * the single plaintext key file and replaces the old `sessions.db.transcript-key`.
 *
 * Fail closed (SI-002/AC-011): there is no plaintext fallback anywhere. A wrong/missing key on an
 * existing DB throws `db_encryption_key_mismatch`; the daemon never opens, creates, or migrates to a
 * plaintext store as a fallback.
 *
 * Security invariants:
 *   SI-001: the db key is NEVER logged, serialized, or placed in an error message — only the raw
 *           `PRAGMA key` string uses the hex, and that string is never logged.
 *   SI-003 (M6B-005 parity): WAL mode is enabled only AFTER key verification, so WAL files are
 *           encrypted at rest.
 */

import { createRequire } from "node:module";
import {
  existsSync,
  readFileSync,
  readSync,
  openSync,
  writeSync,
  fsyncSync,
  closeSync,
  renameSync,
  mkdirSync,
  unlinkSync,
} from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";

const DB_KEY_BYTES = 32; // AES-256

// ─── The minimal DB surface the daemon uses (node:sqlite-compatible varargs) ────

export interface DaemonStatement {
  run(...params: unknown[]): { changes: number | bigint; lastInsertRowid: number | bigint };
  get(...params: unknown[]): unknown;
  all(...params: unknown[]): unknown[];
}

export interface DaemonDatabase {
  exec(sql: string): void;
  prepare(sql: string): DaemonStatement;
  close(): void;
  /**
   * Optional — present on the SQLCipher adapter, absent on node:sqlite's `DatabaseSync` (which uses
   * `exec("PRAGMA ...")`). Optional so a plain `DatabaseSync` (in-memory test handles) still
   * structurally satisfies this interface. Used to read cipher metadata (e.g. cipher_version).
   */
  pragma?(source: string, options?: { simple?: boolean }): unknown;
}

// ─── Tagged error (AC-012 distinct codes) ───────────────────────────────────────

export type DbErrorCode = "db_encryption_key_mismatch" | "db_sqlcipher_unavailable" | "db_open_failed";

export class DbEncryptionError extends Error {
  readonly code: DbErrorCode;
  /** Actionable next step surfaced to the operator (never contains key material). */
  readonly guidance: string;
  constructor(code: DbErrorCode, message: string, guidance: string) {
    super(message);
    this.name = "DbEncryptionError";
    this.code = code;
    this.guidance = guidance;
  }
}

// ─── @signalapp/sqlcipher type shim (it ships its own .d.ts but may not load in all envs) ──

interface SignalRunResult {
  changes: number;
  lastInsertRowid: number;
}
interface SignalStatement {
  run(params?: unknown[] | Record<string, unknown>): SignalRunResult;
  get(params?: unknown[] | Record<string, unknown>): unknown;
  all(params?: unknown[] | Record<string, unknown>): unknown[];
}
export interface SignalDatabase {
  exec(sql: string): void;
  prepare(sql: string): SignalStatement;
  pragma(source: string, options?: { simple?: boolean }): unknown;
  close(): void;
}
interface SignalModule {
  default: new (path: string) => SignalDatabase;
  Database: new (path: string) => SignalDatabase;
}

// ─── The varargs→array adapter ──────────────────────────────────────────────────

class SqlcipherStatement implements DaemonStatement {
  readonly #inner: SignalStatement;
  constructor(inner: SignalStatement) {
    this.#inner = inner;
  }
  run(...params: unknown[]): { changes: number | bigint; lastInsertRowid: number | bigint } {
    return this.#inner.run(params);
  }
  get(...params: unknown[]): unknown {
    return this.#inner.get(params);
  }
  all(...params: unknown[]): unknown[] {
    return this.#inner.all(params);
  }
}

class SqlcipherDatabase implements DaemonDatabase {
  readonly #inner: SignalDatabase;
  constructor(inner: SignalDatabase) {
    this.#inner = inner;
  }
  exec(sql: string): void {
    this.#inner.exec(sql);
  }
  prepare(sql: string): DaemonStatement {
    return new SqlcipherStatement(this.#inner.prepare(sql));
  }
  pragma(source: string, options?: { simple?: boolean }): unknown {
    return this.#inner.pragma(source, options);
  }
  close(): void {
    this.#inner.close();
  }
}

// ─── The raw SQLite magic — used to distinguish a plaintext DB from an encrypted one ──
// A plaintext SQLite file begins with "SQLite format 3\0". A SQLCipher database encrypts the
// header too, so its first bytes are ciphertext and never match. The migration path (PERSIST-002
// Unit 6) uses this to detect a pre-story plaintext DB that must be migrated.
const SQLITE_MAGIC = Buffer.concat([Buffer.from("SQLite format 3", "latin1"), Buffer.from([0x00])]);

/** True when the file at `dbPath` exists and is an UNENCRYPTED node:sqlite database. */
export function isPlaintextSqliteFile(dbPath: string): boolean {
  if (!existsSync(dbPath)) return false;
  const head = Buffer.alloc(SQLITE_MAGIC.length);
  try {
    const fd = openSync(dbPath, "r");
    try {
      // Read exactly the header bytes — never slurp the whole (possibly very large) DB into RAM.
      const bytesRead = readSync(fd, head, 0, SQLITE_MAGIC.length, 0);
      if (bytesRead < SQLITE_MAGIC.length) return false;
    } finally {
      closeSync(fd);
    }
  } catch {
    return false;
  }
  return head.equals(SQLITE_MAGIC);
}

// ─── Key custody (DEC-2/DEC-4) ───────────────────────────────────────────────────

/**
 * Resolve the SQLCipher key, generating it on a genuinely fresh install only.
 *
 * Fail-closed matrix (SI-002/AC-011):
 *   key present                      → load it (must be 32 bytes).
 *   key absent + DB absent           → generate + persist (0600), proceed (fresh install).
 *   key absent + DB present          → THROW db_encryption_key_mismatch (never overwrite an
 *                                      existing DB with a new key — that would be data loss; and
 *                                      a pre-story PLAINTEXT DB must be migrated first, not opened).
 */
export function resolveDbKey(dbPath: string, keyPath: string): Uint8Array {
  if (existsSync(keyPath)) {
    const key = readFileSync(keyPath);
    if (key.length !== DB_KEY_BYTES) {
      throw new DbEncryptionError(
        "db_encryption_key_mismatch",
        `SQLCipher key file is ${key.length} bytes, expected ${DB_KEY_BYTES}`,
        `The key file at ${keyPath} is malformed. Restore it from backup or remove it only if the database is also gone.`,
      );
    }
    return new Uint8Array(key);
  }

  if (existsSync(dbPath)) {
    throw new DbEncryptionError(
      "db_encryption_key_mismatch",
      `database exists at ${dbPath} but its SQLCipher key file is missing`,
      `The encrypted database cannot be opened without its key file (${keyPath}). Restore the key file from backup. The daemon will not create a new plaintext store.`,
    );
  }

  // Fresh install: generate and persist the key atomically with 0600.
  const key = randomBytes(DB_KEY_BYTES);
  const keyDir = dirname(keyPath);
  mkdirSync(keyDir, { recursive: true, mode: 0o700 });
  const tmp = join(keyDir, `.cello-dbkey-tmp-${process.pid}-${randomBytes(6).toString("hex")}`);
  const fd = openSync(tmp, "wx", 0o600);
  try {
    writeSync(fd, key);
    fsyncSync(fd);
  } catch (err) {
    // Never leave a stray plaintext key fragment on disk if the write/fsync failed partway
    // (SI-001: the only plaintext key on disk is the one sanctioned key file).
    closeSync(fd);
    try {
      unlinkSync(tmp);
    } catch {
      /* ignore */
    }
    throw err;
  }
  closeSync(fd);
  try {
    renameSync(tmp, keyPath);
  } catch (err) {
    try {
      unlinkSync(tmp);
    } catch {
      /* ignore */
    }
    throw err;
  }
  // Durability of the rename itself (parent-dir fsync) so a crash right after a fresh install can't
  // lose the key while the encrypted DB exists. Best-effort — some platforms reject dir fsync.
  try {
    const dfd = openSync(keyDir, "r");
    try {
      fsyncSync(dfd);
    } finally {
      closeSync(dfd);
    }
  } catch {
    /* directory fsync is best-effort */
  }
  return new Uint8Array(key);
}

// ─── Open ────────────────────────────────────────────────────────────────────────

/**
 * Load the SQLCipher native module. Exported because the daemon's singleton lock
 * (DOD-SINGLE-DAEMON-1) needs the same engine for its kernel-level file lock — one place that knows
 * how to load the prebuilt, and one error when it will not load.
 */
export function loadSignalModule(): SignalModule {
  const require = createRequire(import.meta.url);
  try {
    return require("@signalapp/sqlcipher") as SignalModule;
  } catch (err: unknown) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new DbEncryptionError(
      "db_sqlcipher_unavailable",
      `SQLCipher native module unavailable: ${reason}`,
      "The @signalapp/sqlcipher prebuilt binary failed to load for this platform. Reinstall the CELLO client.",
    );
  }
}

/**
 * Open `dbPath` as a SQLCipher database keyed by `dbKey`. Verifies the key (reads sqlite_master)
 * and enables WAL after verification. Throws DbEncryptionError on any failure — never returns a
 * plaintext handle (SI-002).
 */
export function openEncryptedDatabase(
  dbPath: string,
  dbKey: Uint8Array,
  logger?: { warn(event: string, context?: Record<string, unknown>): void },
): DaemonDatabase {
  const mod = loadSignalModule();
  const Ctor = mod.Database ?? mod.default;

  let inner: SignalDatabase;
  try {
    inner = new Ctor(dbPath);
  } catch (err: unknown) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new DbEncryptionError("db_open_failed", reason, `Could not open the database file at ${dbPath}.`);
  }

  // SI-001: set the key OUTSIDE the message-bearing try below, so the key hex can never reach a
  // thrown/logged error string even if a future SQLCipher build echoed the pragma source on error.
  // A well-formed `key` pragma does not throw; a wrong key surfaces at the verify read instead.
  const keyHex = Buffer.from(dbKey).toString("hex");
  inner.pragma(`key = "x'${keyHex}'"`);

  try {
    // Verify: reading sqlite_master decrypts the header. Wrong key / plaintext file → throws.
    inner.prepare("SELECT count(*) AS c FROM sqlite_master").get([]);
  } catch (err: unknown) {
    try {
      inner.close();
    } catch {
      /* ignore */
    }
    // Deliberately do NOT echo the underlying SQLITE message into guidance verbatim — but DO log
    // nothing here (the caller logs). SI-001: no key material in the message.
    const reason = err instanceof Error ? err.message : String(err);
    throw new DbEncryptionError(
      "db_encryption_key_mismatch",
      `database did not decrypt with the supplied key (${reason})`,
      "The SQLCipher key does not match this database. Restore the correct key file; the daemon will not fall back to a plaintext store.",
    );
  }

  // SI-003 (M6B-005 parity): WAL only AFTER key verification, so WAL/SHM files are encrypted.
  try {
    const mode = inner.pragma("journal_mode=WAL", { simple: true });
    if (mode !== "wal") {
      // Not fatal — SQLCipher encrypts the rollback journal too, so at-rest integrity holds — but
      // surface it so a permanent non-WAL degradation (e.g. a network filesystem) is not silent.
      logger?.warn("persist.db.wal.unavailable", { mode: String(mode) });
    }
  } catch (err: unknown) {
    logger?.warn("persist.db.wal.unavailable", { error: err instanceof Error ? err.message : String(err) });
  }

  return new SqlcipherDatabase(inner);
}

/**
 * Convenience used by tests and tooling: resolve the key file beside `dbPath` and open. Throws if
 * the key file is absent (it does NOT generate one) — callers inspecting an existing DB always have
 * the key.
 */
export function openEncryptedDatabaseAtPath(dbPath: string, keyPath?: string): DaemonDatabase {
  const kp = keyPath ?? `${dbPath}.key`;
  if (!existsSync(kp)) {
    throw new DbEncryptionError(
      "db_encryption_key_mismatch",
      `SQLCipher key file not found at ${kp}`,
      "Provide the key file path that was generated beside the database.",
    );
  }
  const key = readFileSync(kp);
  return openEncryptedDatabase(dbPath, new Uint8Array(key));
}

/** The key file path the daemon uses for a given DB path (DEC-2: one plaintext key file). */
export function dbKeyPathFor(dbPath: string): string {
  return `${dbPath}.key`;
}
