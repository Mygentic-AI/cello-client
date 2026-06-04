/**
 * SQLCipherClientStore — SQLCipher-encrypted ClientStore for CELLO_ENV=dev+.
 *
 * PERSIST-009: Implements the ClientStore interface backed by SQLCipher-encrypted SQLite.
 * Used only by the composition root. Never exported from packages/client/src/index.ts.
 *
 * CELLO-M6B-013: Replaced @journeyapps/sqlcipher (always compiles from source, 20-40s)
 * with @signalapp/sqlcipher (ships prebuilt binaries for darwin-arm64, darwin-x64,
 * linux-arm64, linux-x64, win32-arm64, win32-x64). The prebuilt binaries are bundled
 * inside the npm tarball — no node-gyp invocation occurs on install.
 *
 * @signalapp/sqlcipher is a SQLCipher 4 binding with the same AES-256-CBC defaults
 * as @journeyapps/sqlcipher. Databases created by @journeyapps/sqlcipher are readable
 * by @signalapp/sqlcipher using the same PRAGMA key = "x'<hexkey>'" format. Verified
 * by the cross-library compatibility test in m6b-013-sqlcipher-compat.test.ts (AC-002).
 *
 * API: @signalapp/sqlcipher uses a synchronous better-sqlite3-style API:
 *   db.prepare(sql).run([params]) / .get([params]) / .all([params])
 *   db.exec(sql)
 *   db.pragma(source, { simple: true })
 *   db.transaction(fn)
 *
 * Security invariants (PERSIST-009):
 *   SI-001: db_key is NEVER logged, serialized, or included in any error message.
 *   SI-002: Constructor takes db_key (Uint8Array), NOT identity_key. The caller
 *           must derive db_key via deriveDbKey() before constructing this store.
 *   SI-003: No PRAGMA cipher_* commands that would weaken AES-256-CBC defaults.
 *
 * Security invariants (CELLO-M6B-005):
 *   SI-001 (M6B-005): WAL mode PRAGMA is issued only AFTER key verification.
 *           Order: (1) PRAGMA key, (2) verify key, (3) PRAGMA journal_mode=WAL,
 *           (4) migrations. Ensures WAL files are encrypted at rest.
 *
 * Degraded behavior (DB-001):
 *   On corrupt file or wrong key, logs client.store.open.failed and throws.
 *   Never creates a new empty database over a corrupt file.
 */

import { createRequire } from "node:module";
import { readFileSync, readdirSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { ClientStore, Logger } from "@cello-protocol/interfaces";

// ─── Type shim for @signalapp/sqlcipher ─────────────────────────────────────

// @signalapp/sqlcipher ships its own .d.ts in dist/lib/index.d.ts.
// We use a local type alias to keep this file self-contained and avoid
// importing the full type at module level (the module may not load in local env).

interface SignalRunResult {
  changes: number;
  lastInsertRowid: number;
}

interface SignalStatement {
  run(params?: unknown[] | Record<string, unknown>): SignalRunResult;
  get<T = Record<string, unknown>>(params?: unknown[] | Record<string, unknown>): T | undefined;
  all<T = Record<string, unknown>>(params?: unknown[] | Record<string, unknown>): T[];
  close(): void;
}

interface SignalDatabase {
  exec(sql: string): void;
  prepare(sql: string): SignalStatement;
  pragma(source: string, options?: { simple?: boolean }): unknown;
  transaction<T>(fn: () => T): () => T;
  close(): void;
}

interface SignalModule {
  default: new (path: string) => SignalDatabase;
  Database: new (path: string) => SignalDatabase;
}

// ─── Constructor options ──────────────────────────────────────────────────────

export interface SQLCipherClientStoreOptions {
  /** Absolute path to the SQLite database file. */
  dbPath: string;
  /** Stable agent identifier — included in log events. */
  agentId: string;
  /** CELLO_ENV value — included in client.store.opened log event. */
  env?: string;
  /**
   * @internal test seam — defaults to packages/client/db/migrations/
   */
  migrationsPath?: string;
  /** Structured logger injected at the composition root. */
  logger: Logger;
}

// ─── SQLCipherClientStore ────────────────────────────────────────────────────

/**
 * ClientStore backed by a SQLCipher-encrypted SQLite database.
 *
 * Lifecycle: construct → open() → (use) → close().
 *
 * IMPORTANT: only import this from the composition root. The ESLint
 * no-restricted-imports rule enforces this at compile time.
 */
export class SQLCipherClientStore implements ClientStore {
  readonly #dbKey: Uint8Array;
  readonly #dbPath: string;
  readonly #agentId: string;
  readonly #env: string;
  readonly #migrationsPath: string;
  readonly #logger: Logger;

  // Mutable state set during open()
  #db: SignalDatabase | null = null;

  /**
   * @param dbKey   - 32-byte database encryption key derived from identity_key via HKDF.
   *                  NEVER pass identity_key here — only the derived db_key (SI-002).
   * @param options - Store configuration including dbPath, agentId, and logger.
   */
  constructor(dbKey: Uint8Array, options: SQLCipherClientStoreOptions) {
    this.#dbKey = dbKey;
    this.#dbPath = options.dbPath;
    this.#agentId = options.agentId;
    this.#env = options.env ?? "unknown";
    this.#logger = options.logger;

    if (options.migrationsPath !== undefined) {
      this.#migrationsPath = options.migrationsPath;
    } else {
      // Resolve default migrations path relative to this module file.
      // Works for both the TypeScript source (packages/client/src/) and
      // the compiled output (packages/client/dist/), since db/ is a sibling of both.
      const moduleDir = dirname(fileURLToPath(import.meta.url));
      this.#migrationsPath = resolve(moduleDir, "../db/migrations");
    }
  }

  /**
   * Open the encrypted database, verify the key, and apply pending migrations.
   * Must be called before any read/write operations.
   *
   * Throws on:
   *   - corrupt file (file exists but is not a valid SQLCipher database)
   *   - wrong key (PRAGMA key does not decrypt the file)
   *   - migration failure
   *
   * On any throw, logs client.store.open.failed and does NOT create a new empty
   * database over the corrupt file (DB-001).
   */
  async open(): Promise<void> {
    // Load the native module. Using createRequire because @signalapp/sqlcipher
    // is a CJS module and this file is ESM.
    const require = createRequire(import.meta.url);
    let signalModule: SignalModule;
    try {
      signalModule = require("@signalapp/sqlcipher") as SignalModule;
    } catch (loadErr: unknown) {
      const reason = loadErr instanceof Error ? loadErr.message : String(loadErr);
      this.#logger.error("client.store.open.failed", { reason: `SQLCipher native module unavailable: ${reason}`, agentId: this.#agentId });
      throw new Error(`SQLCipher native module unavailable: ${reason}`);
    }

    // @signalapp/sqlcipher exports { default: Database, Database, setLogger }
    // The Database constructor takes a file path.
    const DatabaseCtor = signalModule.Database ?? signalModule.default;
    let db: SignalDatabase;
    try {
      db = new DatabaseCtor(this.#dbPath);
    } catch (openErr: unknown) {
      const reason = openErr instanceof Error ? openErr.message : String(openErr);
      this.#logger.error("client.store.open.failed", { reason, agentId: this.#agentId });
      throw openErr;
    }

    // NOTE: do not assign this.#db yet — #applyKey and #verifyKey must succeed first.
    try {
      // Apply PRAGMA key (SI-003: only the key PRAGMA — no weakening cipher settings)
      this.#applyKey(db);

      // Verify the key is correct by reading the sqlite_master table.
      // If the key is wrong or the file is corrupt, this will throw.
      this.#verifyKey(db);

      // SI-001 (M6B-005): WAL mode is set AFTER key verification and BEFORE migrations.
      // Order: (1) PRAGMA key, (2) verify key, (3) PRAGMA journal_mode=WAL, (4) migrations.
      // WAL mode is issued on a key-verified database — attackers with filesystem access
      // see encrypted WAL files, not plaintext.
      const journalMode = this.#setWalMode(db);

      // Key is verified — safe to make the database accessible to other methods.
      this.#db = db;

      // Run migration runner — applies pending V{n}__*.sql files
      this.#runMigrations(db);

      this.#logger.info("client.store.opened", {
        env: this.#env,
        dbPath: this.#dbPath,
        agentId: this.#agentId,
        journalMode,
      });
    } catch (err: unknown) {
      const reason = err instanceof Error ? err.message : String(err);
      // SI-001: never include key material in the error log
      this.#logger.error("client.store.open.failed", {
        reason,
        agentId: this.#agentId,
      });
      // Close the DB to release the file handle
      try { db.close(); } catch { /* ignore close error */ }
      this.#db = null;
      throw err;
    }
  }

  /** Close the database. Idempotent — safe to call multiple times. */
  async close(): Promise<void> {
    if (this.#db === null) return;
    const db = this.#db;
    this.#db = null;
    db.close();
  }

  // ─── ClientStore interface ─────────────────────────────────────────────────

  async set(_key: string, _value: Uint8Array): Promise<void> {
    throw new Error("client_store has been removed by V2 migration — use ClientStatePersistence instead");
  }

  async get(_key: string): Promise<Uint8Array | undefined> {
    throw new Error("client_store has been removed by V2 migration — use ClientStatePersistence instead");
  }

  async delete(_key: string): Promise<void> {
    throw new Error("client_store has been removed by V2 migration — use ClientStatePersistence instead");
  }

  async has(_key: string): Promise<boolean> {
    throw new Error("client_store has been removed by V2 migration — use ClientStatePersistence instead");
  }

  // ─── Private helpers ───────────────────────────────────────────────────────

  #assertOpen(): void {
    if (this.#db === null) {
      throw new Error("SQLCipherClientStore: database is not open. Call open() first.");
    }
  }

  /**
   * Apply the SQLCipher PRAGMA key using the raw hex format.
   * The key is passed as x'<hex>' which is the SQLCipher raw key format.
   * SI-001: The key hex is used only in the PRAGMA string and never logged.
   * SI-003: Only the `key` PRAGMA is set — no cipher_* weakening PRAGMAs.
   *
   * @signalapp/sqlcipher's synchronous pragma() throws on error — no callback needed.
   */
  #applyKey(db: SignalDatabase): void {
    const keyHex = Buffer.from(this.#dbKey).toString("hex");
    const pragmaSource = `key = "x'${keyHex}'"`;
    // SI-001: keyHex is used only in the PRAGMA string and is never logged.
    // SI-003: only the `key` PRAGMA is issued — no cipher_* weakening PRAGMAs.
    db.pragma(pragmaSource);
  }

  /**
   * Verify the PRAGMA key is correct by executing a test query.
   * If the key is wrong or the file is corrupt, this will throw with
   * an error like "SQLITE_NOTADB: file is not a database".
   *
   * DB-001: We do NOT catch and recover here — the error propagates to open()
   * which logs client.store.open.failed and throws, halting the client.
   */
  #verifyKey(db: SignalDatabase): void {
    db.prepare(`SELECT count(*) as c FROM sqlite_master`).get([]);
  }

  /**
   * Enable WAL (Write-Ahead Log) journal mode on the database.
   *
   * @signalapp/sqlcipher's synchronous pragma() with { simple: true } returns
   * the first column of the first result row directly.
   *
   * Implements SI-001 (M6B-005): Must only be called AFTER #verifyKey() succeeds.
   * WAL mode on an unverified database would operate on plaintext; by calling this after
   * key verification, we guarantee WAL files are encrypted at rest.
   *
   * Returns the active journal mode string (normally 'wal').
   */
  #setWalMode(db: SignalDatabase): string {
    const mode = db.pragma("journal_mode=WAL", { simple: true }) as string;
    if (mode !== "wal") {
      throw new Error(`WAL mode failed: expected 'wal', got '${mode}'. This may occur on network filesystems (NFS, SMB). Move your CELLO_DB_PATH to a local filesystem.`);
    }
    return mode;
  }

  /**
   * Run the custom migration runner.
   *
   * Algorithm:
   *   1. Ensure schema_migrations table exists.
   *   2. Read migration files from migrationsPath matching V{n}__*.sql.
   *   3. Sort by version number.
   *   4. For each file not yet in schema_migrations, run it in a transaction.
   *   5. Record the version in schema_migrations.
   *   6. Log client.store.migration.applied for each applied migration.
   */
  #runMigrations(db: SignalDatabase): void {
    // Bootstrap the migrations table before any migration runs — this is not a migration
    // itself and must not be inside a migration transaction.
    // Step 1: bootstrap the schema_migrations table itself
    db.exec(
      `CREATE TABLE IF NOT EXISTS schema_migrations (
         version    TEXT PRIMARY KEY,
         applied_at TEXT NOT NULL DEFAULT (datetime('now'))
       )`,
    );

    // Step 2: read migration files
    const migrationFiles = this.#readMigrationFiles();

    // Step 3: find already-applied migrations
    const appliedVersions = this.#queryAppliedVersions(db);

    // Step 4-6: apply pending migrations in order
    let v2Applied = false;
    const v2StartTime = Date.now();
    for (const { filename, version, description } of migrationFiles) {
      if (appliedVersions.has(version)) continue;

      const sql = readFileSync(filename, "utf-8");
      const startTime = Date.now();

      try {
        this.#applyMigration(db, sql, version);
        const executionTime = Date.now() - startTime;
        this.#logger.info("client.store.migration.applied", {
          version,
          description,
          executionTime,
        });
        if (version === "V2__client_schema_structured") {
          v2Applied = true;
        }
      } catch (err: unknown) {
        const reason = err instanceof Error ? err.message : String(err);
        this.#logger.error("client.store.migration.failed", {
          version,
          description,
          reason,
          agentPubkey: this.#agentId,
        });
        throw err;
      }
    }

    // PERSIST-024: Emit batch-level V2 summary event
    if (v2Applied) {
      const executionTimeMs = Date.now() - v2StartTime;
      // MED-2: tableCount must match the number of CREATE TABLE statements in
      // V2__client_schema_structured.sql. If that migration is modified, update this number.
      this.#logger.info("client.db.v2.migration.applied", {
        agentPubkey: this.#agentId,
        tableCount: 18, // must equal CREATE TABLE count in V2__client_schema_structured.sql
        executionTimeMs,
      });
    } else if (appliedVersions.has("V2__client_schema_structured")) {
      this.#logger.info("client.db.v2.migration.skipped", {
        agentPubkey: this.#agentId,
        currentVersion: "V2__client_schema_structured",
      });
    }
  }

  /** Read and sort migration files from the migrations directory. */
  #readMigrationFiles(): Array<{ filename: string; version: string; description: string }> {
    let files: string[];
    try {
      files = readdirSync(this.#migrationsPath);
    } catch (err: unknown) {
      const reason = err instanceof Error ? err.message : String(err);
      throw new Error(`Cannot read migrations directory '${this.#migrationsPath}': ${reason}`);
    }

    const migrations = files
      .filter((f) => /^V\d+__.*\.sql$/.test(f))
      .map((f) => {
        const match = /^(V(\d+)__(.+))\.sql$/.exec(f);
        if (!match) throw new Error(`Unexpected migration filename: ${f}`);
        return {
          filename: resolve(this.#migrationsPath, f),
          version: match[1],          // e.g. "V1__client_schema"
          versionNum: parseInt(match[2], 10),
          description: match[3].replaceAll("_", " "), // e.g. "client schema"
        };
      })
      .sort((a, b) => a.versionNum - b.versionNum);

    return migrations;
  }

  /** Query the schema_migrations table and return the set of applied version strings. */
  #queryAppliedVersions(db: SignalDatabase): Set<string> {
    const rows = db.prepare(`SELECT version FROM schema_migrations`).all<{ version: string }>([]);
    return new Set(rows.map((r) => r.version));
  }

  /**
   * Apply a single migration SQL within a transaction and record it in schema_migrations.
   *
   * @signalapp/sqlcipher's synchronous db.transaction(fn) wraps fn in a BEGIN/COMMIT pair.
   * If fn throws, the transaction is automatically rolled back.
   */
  #applyMigration(db: SignalDatabase, sql: string, version: string): void {
    const applyFn = db.transaction(() => {
      db.exec(sql);
      db.prepare(
        `INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, datetime('now'))`,
      ).run([version]);
    });
    (applyFn as () => void)();
  }

  // ─── Structured DB access (PERSIST-024) ───────────────────────────────────────

  /**
   * Execute a parameterized SQL statement (INSERT, UPDATE, DELETE).
   * Returns { lastID, changes }.
   */
  async run(sql: string, params: unknown[] = []): Promise<{ lastID: number; changes: number }> {
    this.#assertOpen();
    const result = this.#db!.prepare(sql).run(params);
    return { lastID: result.lastInsertRowid, changes: result.changes };
  }

  /**
   * Execute a parameterized query returning a single row (or undefined).
   */
  async getRow<T = Record<string, unknown>>(sql: string, params: unknown[] = []): Promise<T | undefined> {
    this.#assertOpen();
    return this.#db!.prepare(sql).get<T>(params);
  }

  /**
   * Execute a parameterized query returning all matching rows.
   */
  async allRows<T = Record<string, unknown>>(sql: string, params: unknown[] = []): Promise<T[]> {
    this.#assertOpen();
    return this.#db!.prepare(sql).all<T>(params);
  }

  /**
   * Execute raw SQL without parameters (for multi-statement DDL or pragmas).
   */
  async exec(sql: string): Promise<void> {
    this.#assertOpen();
    this.#db!.exec(sql);
  }

  /**
   * Check if the database is open.
   */
  isOpen(): boolean {
    return this.#db !== null;
  }
}
