/**
 * CELLO-M7-PERSIST-002 — test helper: open the daemon's SQLCipher DB by path.
 *
 * The daemon DB is now whole-file SQLCipher-encrypted, so tests can no longer open `sessions.db`
 * with a plain `new DatabaseSync(dbPath)`. This helper resolves the key file beside the DB
 * (generating it if the DB is being seeded before a SessionNodeManager opens it) and returns the
 * same `DaemonDatabase` varargs surface the production code uses — a drop-in for the old direct open.
 */

import {
  resolveDbKey,
  openEncryptedDatabase,
  dbKeyPathFor,
  type DaemonDatabase,
} from "../../sqlcipher-db.js";

/**
 * Open (or create) the encrypted daemon DB at `dbPath`. Works for both:
 *   - post-inspect: a SessionNodeManager already initialized it → the key file exists → load + open.
 *   - pre-seed: the DB does not exist yet → generate the key file + create the encrypted DB, so a
 *     later SessionNodeManager.initialize() opens the SAME encrypted DB with the SAME key.
 */
export function openTestDb(dbPath: string): DaemonDatabase {
  const key = resolveDbKey(dbPath, dbKeyPathFor(dbPath));
  return openEncryptedDatabase(dbPath, key);
}
