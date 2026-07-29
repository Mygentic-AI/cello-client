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
import { readFileSync } from "node:fs";

const STORE_KEY_BYTES = 32; // AES-256 — the daemon's key size

export type GatewayStoreErrorCode =
  | "store_key_unavailable"
  | "store_key_mismatch"
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

  try {
    inner.prepare("SELECT count(*) AS c FROM sqlite_master").get([]);
  } catch {
    try {
      inner.close();
    } catch {
      /* ignore */
    }
    throw new GatewayStoreError(
      "store_key_mismatch",
      "gateway store did not decrypt with the supplied key",
      "The daemon's key does not match this gateway store file. Restore the matching key file; " +
        "the gateway will not fall back to a plaintext store.",
    );
  }

  // WAL after verification so WAL/SHM are ciphertext; busy_timeout tolerates the daemon's own
  // connection to the same file (SURFACE-1 config writes, AUDIT-1 record reads).
  try {
    inner.pragma("journal_mode=WAL", { simple: true });
  } catch {
    /* non-WAL degrades performance, not custody — SQLCipher encrypts the rollback journal too */
  }
  inner.pragma("busy_timeout = 3000");

  return new AdaptedDb(inner);
}
