/**
 * The gateway's encrypted store engine (DOD-M9C-STORE-1, INV-4 as amended).
 *
 * One SQLCipher file holds BOTH gateway stores (config versions + security records — M9C-D9),
 * keyed by the daemon's key: the caller hands over the KEY FILE PATH (M9C-D8 — never key bytes in
 * env or argv), and this module reads the same raw 32-byte key file the daemon uses for its own
 * database. Same key, same backup set — that is policy D-3's "one key, covered by backup".
 *
 * FAILS CLOSED. A missing key file, a malformed key, or a key that does not decrypt the file each
 * refuse with a distinct code. There is no plaintext fallback and no plaintext read path: no
 * production plaintext gateway store has ever existed (M9C-D7), so nothing here consults one.
 *
 * This deliberately does NOT import from core/daemon (the dependency points the other way); the
 * ~50 lines shared with the daemon's opener are the price of the package boundary. WAL is enabled
 * only AFTER key verification so WAL/SHM files are encrypted; busy_timeout + the stores' own
 * BEGIN IMMEDIATE transactions carry the two-process access (gateway writes records, the daemon
 * writes config and reads records).
 */
import { createRequire } from "node:module";
import { readFileSync, existsSync, openSync, readSync, closeSync } from "node:fs";

const STORE_KEY_BYTES = 32; // AES-256 — the daemon's key size

/**
 * A plaintext SQLite file begins with these bytes; a SQLCipher file encrypts its header, so its
 * first bytes are ciphertext and never match. Used to tell "someone left a plaintext store here"
 * apart from "wrong key" — two very different operator actions.
 */
const SQLITE_PLAINTEXT_MAGIC = Buffer.concat([Buffer.from("SQLite format 3", "latin1"), Buffer.from([0x00])]);

function isPlaintextSqliteFile(dbPath: string): boolean {
  if (!existsSync(dbPath)) return false;
  const head = Buffer.alloc(SQLITE_PLAINTEXT_MAGIC.length);
  try {
    const fd = openSync(dbPath, "r");
    try {
      if (readSync(fd, head, 0, head.length, 0) < head.length) return false;
    } finally {
      closeSync(fd);
    }
  } catch {
    return false;
  }
  return head.equals(SQLITE_PLAINTEXT_MAGIC);
}

export type GatewayStoreErrorCode =
  | "store_key_unavailable"
  | "store_key_mismatch"
  | "store_plaintext_file"
  | "store_locked"
  | "store_engine_unavailable"
  | "store_open_failed";

export class GatewayStoreError extends Error {
  readonly code: GatewayStoreErrorCode;
  /** Actionable next step for the operator — never contains key material. */
  readonly guidance: string;
  constructor(code: GatewayStoreErrorCode, message: string, guidance: string) {
    super(message);
    this.name = "GatewayStoreError";
    this.code = code;
    this.guidance = guidance;
  }
}

// ─── @signalapp/sqlcipher shim (better-sqlite3-style: array params) ─────────────

interface SignalRunResult {
  changes: number;
  lastInsertRowid: number;
}
interface SignalStatement {
  run(params?: unknown[]): SignalRunResult;
  get(params?: unknown[]): unknown;
  all(params?: unknown[]): unknown[];
}
interface SignalDatabase {
  exec(sql: string): void;
  prepare(sql: string): SignalStatement;
  pragma(source: string, options?: { simple?: boolean }): unknown;
  close(): void;
}
interface SignalModule {
  default: new (path: string) => SignalDatabase;
  Database: new (path: string) => SignalDatabase;
}

// ─── The varargs surface the stores use (node:sqlite-shaped) ────────────────────

export interface StoreStatement {
  run(...params: unknown[]): { changes: number | bigint; lastInsertRowid: number | bigint };
  get(...params: unknown[]): unknown;
  all(...params: unknown[]): unknown[];
}

export interface StoreDb {
  exec(sql: string): void;
  prepare(sql: string): StoreStatement;
  close(): void;
}

class AdaptedStatement implements StoreStatement {
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

class AdaptedDb implements StoreDb {
  readonly #inner: SignalDatabase;
  constructor(inner: SignalDatabase) {
    this.#inner = inner;
  }
  exec(sql: string): void {
    this.#inner.exec(sql);
  }
  prepare(sql: string): StoreStatement {
    return new AdaptedStatement(this.#inner.prepare(sql));
  }
  close(): void {
    this.#inner.close();
  }
}

/**
 * One structured line on stderr. This module has no injected logger — it is loaded by the gateway
 * bin, a composition root whose stdout is reserved for the READY handshake `spawnGatewaySidecar`
 * parses. stderr is drained and surfaced by the spawner, so these lines reach the operator.
 */
function emit(fields: Record<string, unknown>): void {
  process.stderr.write(`${JSON.stringify({ level: "info", ...fields })}\n`);
}

function loadEngine(): SignalModule {
  const require = createRequire(import.meta.url);
  try {
    return require("@signalapp/sqlcipher") as SignalModule;
  } catch (err: unknown) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new GatewayStoreError(
      "store_engine_unavailable",
      `SQLCipher native module unavailable: ${reason}`,
      "The @signalapp/sqlcipher prebuilt failed to load for this platform. Reinstall the CELLO client.",
    );
  }
}

function readStoreKey(keyFilePath: string): Uint8Array {
  let key: Buffer;
  try {
    key = readFileSync(keyFilePath);
  } catch {
    throw new GatewayStoreError(
      "store_key_unavailable",
      `gateway store key file not found at ${keyFilePath}`,
      "The gateway store is encrypted with the daemon's database key and will not open without it. " +
        "Restore the key file from backup; the gateway never falls back to a plaintext store.",
    );
  }
  if (key.length !== STORE_KEY_BYTES) {
    throw new GatewayStoreError(
      "store_key_unavailable",
      `gateway store key file is ${key.length} bytes, expected ${STORE_KEY_BYTES}`,
      `The key file at ${keyFilePath} is malformed. Restore it from backup.`,
    );
  }
  return new Uint8Array(key);
}

/**
 * Open (creating if absent) the gateway's encrypted store file, keyed by the raw 32-byte key in
 * `keyFilePath`. Verifies the key by reading sqlite_master; enables WAL only after verification.
 * Throws GatewayStoreError on every failure path — never returns a plaintext handle.
 */
export function openEncryptedStoreDb(dbPath: string, keyFilePath: string): StoreDb {
  const key = readStoreKey(keyFilePath);

  // Distinguish "a plaintext store was left here" from "wrong key" BEFORE trying to decrypt.
  // Both surface as an unreadable header, and they call for opposite operator actions: one is
  // "delete this stale file", the other is "restore your key from backup" — advice that destroys
  // data if given for the wrong cause.
  if (isPlaintextSqliteFile(dbPath)) {
    throw new GatewayStoreError(
      "store_plaintext_file",
      `the file at ${dbPath} is an UNENCRYPTED SQLite database`,
      "The gateway store must be encrypted. This is a leftover plaintext store from before the " +
        "store was encrypted; it is not migrated and not read. Move or delete it and restart — a " +
        "fresh encrypted store is created automatically.",
    );
  }

  const mod = loadEngine();
  const Ctor = mod.Database ?? mod.default;

  let inner: SignalDatabase;
  try {
    inner = new Ctor(dbPath);
  } catch (err: unknown) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new GatewayStoreError("store_open_failed", reason, `Could not open the gateway store at ${dbPath}.`);
  }

  // Key set outside the message-bearing try: key hex must never reach an error string.
  const keyHex = Buffer.from(key).toString("hex");
  inner.pragma(`key = "x'${keyHex}'"`);

  // busy_timeout FIRST — before the verify read and before the WAL pragma, both of which take
  // locks. This file is shared with the daemon (M9C-D9), so a contended startup is ordinary, and
  // with the SQLite default timeout of 0 the very first contended open returns SQLITE_BUSY
  // instantly — which the verify-read catch below would then report as a wrong key. Setting it
  // last (as this did) turns lock contention into "your key is wrong. Restore it from backup."
  inner.pragma("busy_timeout = 3000");

  try {
    inner.prepare("SELECT count(*) AS c FROM sqlite_master").get([]);
  } catch (err: unknown) {
    try {
      inner.close();
    } catch {
      /* ignore */
    }
    // The upstream reason MUST survive. A wrong key, a locked file, a truncated file and an I/O
    // error all surface here, and a label that names only the exit point sends the operator to
    // the wrong subsystem. No key material can appear in this string — the key is only ever in
    // the pragma above, which is not part of the thrown error. (The daemon's opener does the
    // same at sqlcipher-db.ts; this copy dropped it, which is the defect being fixed.)
    const reason = err instanceof Error ? err.message : String(err);
    const locked = /SQLITE_BUSY|database is locked/i.test(reason);
    if (locked) {
      throw new GatewayStoreError(
        "store_locked",
        `gateway store is locked by another process (${reason})`,
        "Another process holds the gateway store's write lock — usually an orphaned gateway from " +
          "a previous daemon. Stop it and restart the daemon. The key is not the problem.",
      );
    }
    throw new GatewayStoreError(
      "store_key_mismatch",
      `gateway store did not decrypt with the supplied key (${reason})`,
      "The daemon's key does not match this gateway store file. Restore the matching key file; " +
        "the gateway will not fall back to a plaintext store.",
    );
  }

  // WAL after verification so WAL/SHM are ciphertext. CHECK the result rather than assuming it:
  // the file is shared with the daemon, and a silent fall back to rollback-journal mode means a
  // daemon write blocks gateway reads, which surfaces to the user as messages fail-closed with a
  // generic screen error. Not fatal — SQLCipher encrypts the rollback journal too, so custody
  // holds either way — but never silent.
  try {
    const mode = inner.pragma("journal_mode=WAL", { simple: true });
    if (mode !== "wal") emit({ event: "gateway.store.wal_unavailable", mode: String(mode) });
  } catch (err: unknown) {
    emit({ event: "gateway.store.wal_unavailable", error: err instanceof Error ? err.message : String(err) });
  }

  // The store is open and encrypted. Structured, on stderr: stdout carries the READY handshake the
  // parent parses, so nothing else may go there. Never the key, and never the key file's contents.
  emit({ event: "gateway.store.opened", encrypted: true, path: dbPath });

  return new AdaptedDb(inner);
}
