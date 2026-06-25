/**
 * CELLO-M7-PERSIST-002 (AC-008): DB-backed IManifestVersionStore.
 *
 * The last-seen manifest version (which backs the anti-rollback monotonicity invariant across daemon
 * restarts) lives in the `manifest_state` singleton row of the SQLCipher-encrypted daemon DB — not a
 * plaintext `manifest-version.json` file. Same interface as the old FileManifestVersionStore, so the
 * SignalingManager that consumes it is unchanged.
 *
 * Crypto reference: RFC 8032 context — the version number is not itself cryptographic, but its
 * correct, durable persistence is load-bearing for anti-rollback security (a reset enables a manifest
 * downgrade attack). Whole-DB SQLCipher now protects it at rest along with all other client state.
 */

import type { IManifestVersionStore } from "@cello-protocol/transport";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

/** Idempotent schema for the singleton manifest-version row. */
export function ensureManifestSchema(db: DaemonDatabase): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS manifest_state (
      id                INTEGER PRIMARY KEY CHECK (id = 1),
      last_seen_version INTEGER,
      updated_at        INTEGER NOT NULL
    )
  `);
}

export class DbManifestVersionStore implements IManifestVersionStore {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
    ensureManifestSchema(db);
  }

  async getLastSeenVersion(): Promise<number | null> {
    const row = this.#db
      .prepare("SELECT last_seen_version FROM manifest_state WHERE id = 1")
      .get() as { last_seen_version: number | null } | undefined;
    return row && row.last_seen_version != null ? Number(row.last_seen_version) : null;
  }

  async persistVersion(version: number): Promise<void> {
    // Upsert the singleton row. Atomic within the encrypted DB — no temp-file rename dance.
    try {
      this.#db
        .prepare(
          `INSERT INTO manifest_state (id, last_seen_version, updated_at)
           VALUES (1, ?, ?)
           ON CONFLICT(id) DO UPDATE SET last_seen_version = excluded.last_seen_version, updated_at = excluded.updated_at`,
        )
        .run(version, Date.now());
    } catch (err: unknown) {
      // AC-012: a distinct, actionable failure — never a silent no-op (a lost anti-rollback version
      // would re-open a manifest-downgrade window).
      this.#logger.error("persist.manifest.persist.failed", { version, error: err instanceof Error ? err.message : String(err) });
      const e = new Error(`manifest_persist_failed: ${err instanceof Error ? err.message : String(err)}`);
      (e as Error & { code?: string }).code = "manifest_persist_failed";
      throw e;
    }
    this.#logger.info("persist.manifest.version.persisted", { version });
  }
}
