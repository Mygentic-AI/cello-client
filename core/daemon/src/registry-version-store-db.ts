/**
 * DOD-REGISTRY-1 — DB-backed registry version store (anti-rollback).
 *
 * Same shape as DbManifestVersionStore — a singleton row in the encrypted daemon DB
 * holding the last-seen registry version. A registry fetch whose version is <= the
 * persisted version is refused (monotonicity across restarts prevents rollback attacks
 * where a compromised directory serves an older registry to un-classify a new type).
 */

import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

export interface IRegistryVersionStore {
  getLastSeenVersion(): number | null;
  persistVersion(version: number): void;
}

export function ensureRegistrySchema(db: DaemonDatabase): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS registry_state (
      id                INTEGER PRIMARY KEY CHECK (id = 1),
      last_seen_version INTEGER,
      updated_at        INTEGER NOT NULL
    )
  `);
}

export class DbRegistryVersionStore implements IRegistryVersionStore {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
    ensureRegistrySchema(db);
  }

  getLastSeenVersion(): number | null {
    const row = this.#db
      .prepare("SELECT last_seen_version FROM registry_state WHERE id = 1")
      .get() as { last_seen_version: number | null } | undefined;
    return row && row.last_seen_version != null ? Number(row.last_seen_version) : null;
  }

  persistVersion(version: number): void {
    try {
      this.#db
        .prepare(
          `INSERT INTO registry_state (id, last_seen_version, updated_at)
           VALUES (1, ?, ?)
           ON CONFLICT(id) DO UPDATE SET last_seen_version = excluded.last_seen_version, updated_at = excluded.updated_at`,
        )
        .run(version, Date.now());
    } catch (err: unknown) {
      this.#logger.error("registry.version.persist.failed", { version, error: err instanceof Error ? err.message : String(err) });
      const e = new Error(`registry_persist_failed: ${err instanceof Error ? err.message : String(err)}`);
      (e as Error & { code?: string }).code = "registry_persist_failed";
      throw e;
    }
    this.#logger.info("registry.version.persisted", { version });
  }
}
