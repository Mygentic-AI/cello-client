/**
 * CELLO-M7-PERSIST-002 — Unit 4/6: one-time migration of pre-story flat-file state and a plaintext
 * node:sqlite DB into the single SQLCipher-encrypted daemon DB (AC-006, DB-002).
 *
 * Before this story the daemon kept:
 *   - identity as plaintext flat files: `agents/<name>/key` (37-byte CELLO seed), `frost-share.json`,
 *     `ml-dsa-keypair.json`, `registration-state.json`, `agent-user-link.json`, and the legacy
 *     single-file `~/.cello/key` (loaded as agent "default");
 *   - sessions/transcript/etc. in a PLAINTEXT `sessions.db` (node:sqlite), with two columns
 *     (transcript.blob, retry_queue.content_blob) envelope-encrypted by a sibling
 *     `sessions.db.transcript-key`.
 *
 * This migration runs at daemon startup BEFORE the encrypted DB is opened. If it detects either a
 * plaintext DB or any flat-file identity, it builds a fresh SQLCipher DB (at `<dbPath>.migrating`),
 * imports every row of the old DB (decrypting the two column-ciphered blobs to plaintext) AND every
 * flat-file identity item into `agents` rows, verifies, then atomically swaps it into place — backing
 * up the old plaintext DB to `<dbPath>.pre-sqlcipher.bak` and deleting the flat files. It is
 * idempotent: once the DB is encrypted and the flat files are gone, it is a no-op.
 *
 * Fail-closed (SI-002/DB-002): on ANY error it aborts cleanly — the original flat files / plaintext
 * DB are left in place, the partial `.migrating` DB is discarded, and the caller surfaces
 * `identity_migration_failed`. No identity is lost and no plaintext is left half-migrated.
 */

import {
  existsSync,
  readFileSync,
  readdirSync,
  statSync,
  renameSync,
  unlinkSync,
} from "node:fs";
import { join, dirname } from "node:path";
import { createDecipheriv, randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { InMemoryKeyProvider, decodeKeyFileSeed } from "@cello-protocol/crypto";
import {
  openEncryptedDatabase,
  isPlaintextSqliteFile,
  resolveDbKey,
  dbKeyPathFor,
  type DaemonDatabase,
} from "./sqlcipher-db.js";
import { ensureIdentitySchema } from "./db-identity-store.js";
import { ensureManifestSchema } from "./manifest-version-store-db.js";
import type { Logger } from "./types.js";

export interface MigrationResult {
  migrated: boolean;
  agentsMigrated: number;
  rowsMigrated: number;
}

export class IdentityMigrationError extends Error {
  readonly code = "identity_migration_failed" as const;
  readonly guidance: string;
  constructor(message: string, guidance: string) {
    super(message);
    this.name = "IdentityMigrationError";
    this.guidance = guidance;
  }
}

const REG_FILES = {
  frost: "frost-share.json",
  mlDsa: "ml-dsa-keypair.json",
  reg: "registration-state.json",
  link: "agent-user-link.json",
} as const;

const hexToBytes = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "hex"));

/** Decrypt a legacy column blob (iv(12)||ct||tag(16)) with the old transcript key; null on failure. */
function decryptColumnBlob(blob: Uint8Array, key: Buffer): Uint8Array | null {
  if (blob.length < 12 + 16) return null;
  const buf = Buffer.from(blob);
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(buf.length - 16);
  const ct = buf.subarray(12, buf.length - 16);
  try {
    const d = createDecipheriv("aes-256-gcm", key, iv);
    d.setAuthTag(tag);
    return Uint8Array.from(Buffer.concat([d.update(ct), d.final()]));
  } catch {
    return null;
  }
}

/** Read + parse a flat JSON identity file, or null if absent. */
function readJson(path: string): Record<string, unknown> | null {
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
}

/** Enumerate pre-story agent directories that hold a `key` file. */
function discoverFlatAgents(celloDir: string): Array<{ name: string; dir: string; keyPath: string }> {
  const out: Array<{ name: string; dir: string; keyPath: string }> = [];
  const agentsDir = join(celloDir, "agents");
  if (existsSync(agentsDir) && statSync(agentsDir).isDirectory()) {
    for (const entry of readdirSync(agentsDir, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const dir = join(agentsDir, entry.name);
      const keyPath = join(dir, "key");
      if (existsSync(keyPath)) out.push({ name: entry.name, dir, keyPath });
    }
  }
  // Legacy single-file ~/.cello/key → agent "default" (only when there's no agents/default already).
  const legacyKey = join(celloDir, "key");
  if (existsSync(legacyKey) && !out.some((a) => a.name === "default")) {
    out.push({ name: "default", dir: celloDir, keyPath: legacyKey });
  }
  return out;
}

/** True if there is any pre-story flat-file identity to migrate. */
function hasFlatIdentity(celloDir: string): boolean {
  return discoverFlatAgents(celloDir).length > 0;
}

const MANIFEST_FILE = "manifest-version.json";

/**
 * Carry the legacy anti-rollback floor (`manifest-version.json`) into the encrypted `manifest_state`
 * table. CRITICAL (fallback-finder HIGH): without this, an upgraded operator's last-seen manifest
 * version resets to null on first start, re-opening a manifest-DOWNGRADE window for one cycle. The
 * upsert keeps the MAX of any existing floor, so it can never LOWER the floor. Returns true if a
 * value was imported.
 */
function importManifestVersion(celloDir: string, db: DaemonDatabase, logger: Logger): boolean {
  const obj = readJson(join(celloDir, MANIFEST_FILE));
  if (!obj || typeof obj["lastSeenVersion"] !== "number") return false;
  ensureManifestSchema(db);
  db.prepare(
    `INSERT INTO manifest_state (id, last_seen_version, updated_at) VALUES (1, ?, ?)
     ON CONFLICT(id) DO UPDATE SET last_seen_version = MAX(last_seen_version, excluded.last_seen_version), updated_at = excluded.updated_at`,
  ).run(obj["lastSeenVersion"], Date.now());
  logger.info("persist.manifest.version.migrated", { version: obj["lastSeenVersion"] });
  return true;
}

/**
 * Run the one-time migration if needed. Returns { migrated:false } when there is nothing to do
 * (fresh install or an already-encrypted DB with no flat files).
 */
export function migrateToEncryptedIfNeeded(dbPath: string, logger: Logger): MigrationResult {
  const celloDir = dirname(dbPath);
  const keyPath = dbKeyPathFor(dbPath);
  const migratingPath = `${dbPath}.migrating`;

  // Resume a crash in the tiny window between the backup-rename and the swap-rename: a COMPLETED
  // `.migrating` exists but `dbPath` is gone. Promote it (instead of the in-place branch rebuilding a
  // fresh EMPTY DB and orphaning the migrated session/transcript history — code-review M1). Only if it
  // decrypts with the key; otherwise discard the partial and let the originals drive a fresh attempt.
  if (!existsSync(dbPath) && existsSync(migratingPath) && existsSync(keyPath)) {
    try {
      const k = new Uint8Array(readFileSync(keyPath));
      openEncryptedDatabase(migratingPath, k, logger).close(); // probe: decrypts?
      renameSync(migratingPath, dbPath);
      for (const ext of ["-wal", "-shm"]) {
        if (existsSync(`${migratingPath}${ext}`)) renameSync(`${migratingPath}${ext}`, `${dbPath}${ext}`);
      }
      logger.warn("persist.identity.migrate.resumed", {});
    } catch {
      for (const p of [migratingPath, `${migratingPath}-wal`, `${migratingPath}-shm`]) {
        if (existsSync(p)) { try { unlinkSync(p); } catch { /* ignore */ } }
      }
    }
  }

  const plaintextDb = isPlaintextSqliteFile(dbPath);
  const flatIdentity = hasFlatIdentity(celloDir);
  // The legacy anti-rollback floor file ALSO requires a migration pass even when there is no flat
  // identity / plaintext DB (an already-encrypted DB whose manifest floor still sits in a file).
  const manifestFile = existsSync(join(celloDir, MANIFEST_FILE));

  if (!plaintextDb && !flatIdentity && !manifestFile) {
    return { migrated: false, agentsMigrated: 0, rowsMigrated: 0 };
  }

  // ── In-place flat-identity import: the DB is ALREADY encrypted (or absent) and only flat-file
  // identity remains to be imported. There is NO plaintext DB to re-encrypt, so we must NOT build a
  // fresh DB and swap it over the existing one (that would destroy the existing encrypted data —
  // sessions, transcript, hash chain). Open the existing/created encrypted DB and import in place. ──
  if (!plaintextDb) {
    let key: Uint8Array;
    try {
      key = resolveDbKey(dbPath, keyPath); // loads the existing key, or generates one if the DB is absent
    } catch (err) {
      throw new IdentityMigrationError(
        `could not open the encrypted DB for in-place identity import: ${err instanceof Error ? err.message : String(err)}`,
        "Restore the SQLCipher key file, then restart.",
      );
    }
    let db: DaemonDatabase | null = null;
    let agentsMigrated = 0;
    try {
      db = openEncryptedDatabase(dbPath, key, logger);
      ensureIdentitySchema(db);
      agentsMigrated = importFlatIdentity(celloDir, db, logger);
      importManifestVersion(celloDir, db, logger); // carry the anti-rollback floor (HIGH)
      db.close();
      db = null;
    } catch (err) {
      if (db) { try { db.close(); } catch { /* ignore */ } }
      if (err instanceof IdentityMigrationError) throw err;
      throw new IdentityMigrationError(
        `in-place identity import failed: ${err instanceof Error ? err.message : String(err)}`,
        "The original flat files are untouched. Resolve the error and restart to retry.",
      );
    }
    deleteFlatIdentity(celloDir, logger);
    logger.info("persist.identity.migrated", { agentsMigrated, rowsMigrated: 0 });
    return { migrated: true, agentsMigrated, rowsMigrated: 0 };
  }

  // ── Re-encrypt path: a PLAINTEXT DB exists. Build a fresh encrypted DB at `<dbPath>.migrating`
  // (copying every row + importing flat identity), verify, then atomically swap it into place with a
  // backup of the plaintext original. ──
  // Clean any stale partial from a previously-interrupted attempt.
  for (const p of [migratingPath, `${migratingPath}-wal`, `${migratingPath}-shm`]) {
    if (existsSync(p)) unlinkSync(p);
  }

  // The SQLCipher key for the NEW encrypted DB. Reuse the key file if a prior attempt already wrote
  // one; otherwise generate it via resolveDbKey on the migrating path (which has no DB yet → fresh).
  let dbKey: Uint8Array;
  try {
    dbKey = existsSync(keyPath)
      ? new Uint8Array(readFileSync(keyPath))
      : resolveDbKey(migratingPath, keyPath); // generates + writes keyPath (migrating DB absent → fresh)
  } catch (err) {
    throw new IdentityMigrationError(
      `could not establish a SQLCipher key for migration: ${err instanceof Error ? err.message : String(err)}`,
      "Ensure the CELLO directory is writable, then restart.",
    );
  }

  let encDb: DaemonDatabase | null = null;
  let agentsMigrated = 0;
  let rowsMigrated = 0;
  try {
    encDb = openEncryptedDatabase(migratingPath, dbKey, logger);
    ensureIdentitySchema(encDb);

    // (1) Copy the old plaintext DB's schema + rows, decrypting the two column-ciphered blobs.
    if (plaintextDb) {
      rowsMigrated = copyPlaintextDb(dbPath, encDb, celloDir, logger);
    }

    // (2) Import flat-file identity into `agents` rows + the anti-rollback floor into manifest_state.
    agentsMigrated = importFlatIdentity(celloDir, encDb, logger);
    importManifestVersion(celloDir, encDb, logger);

    encDb.close();
    encDb = null;
  } catch (err) {
    if (encDb) {
      try { encDb.close(); } catch { /* ignore */ }
    }
    for (const p of [migratingPath, `${migratingPath}-wal`, `${migratingPath}-shm`]) {
      if (existsSync(p)) { try { unlinkSync(p); } catch { /* ignore */ } }
    }
    if (err instanceof IdentityMigrationError) throw err;
    throw new IdentityMigrationError(
      `migration failed before commit: ${err instanceof Error ? err.message : String(err)}`,
      "The original data is untouched. Resolve the error (e.g. disk space) and restart to retry.",
    );
  }

  // ── Commit: back up + swap the DB, then delete the flat files. Past this point identity is in the
  // encrypted DB; deleting the now-redundant plaintext originals completes the move. ──
  try {
    if (plaintextDb) {
      renameSync(dbPath, `${dbPath}.pre-sqlcipher.bak`);
      // The old WAL/SHM + the column-cipher key are superseded — remove them.
      for (const p of [`${dbPath}-wal`, `${dbPath}-shm`, `${dbPath}.transcript-key`]) {
        if (existsSync(p)) { try { unlinkSync(p); } catch { /* ignore */ } }
      }
    }
    renameSync(migratingPath, dbPath);
    for (const p of [`${migratingPath}-wal`, `${migratingPath}-shm`]) {
      if (existsSync(p)) renameSync(p, p.replace(`${dbPath}.migrating`, dbPath));
    }
    deleteFlatIdentity(celloDir, logger);
  } catch (err) {
    throw new IdentityMigrationError(
      `migration failed during commit/cleanup: ${err instanceof Error ? err.message : String(err)}`,
      "Inspect the CELLO directory: a .pre-sqlcipher.bak backup of the original DB is retained.",
    );
  }

  logger.info("persist.identity.migrated", { agentsMigrated, rowsMigrated });
  return { migrated: true, agentsMigrated, rowsMigrated };
}

/**
 * Copy every table + row from the old plaintext DB into the encrypted DB, decrypting the two
 * column-ciphered blobs to plaintext. A row whose transcript/retry blob CANNOT be decrypted (the old
 * transcript-key is missing or the blob fails GCM) is SKIPPED with a loud error — it is NEVER stored
 * as ciphertext-masquerading-as-plaintext (which the rest of the daemon would TextDecode into garbage;
 * fallback-finder HIGH). After each table, the copied count is VERIFIED against (old count − skipped);
 * a mismatch means INSERT OR IGNORE silently dropped a row → abort (the docstring's "verify" is real).
 */
function copyPlaintextDb(dbPath: string, encDb: DaemonDatabase, _celloDir: string, logger: Logger): number {
  const old = new DatabaseSync(dbPath);
  try {
    const transcriptKeyPath = `${dbPath}.transcript-key`;
    const transcriptKey = existsSync(transcriptKeyPath) ? readFileSync(transcriptKeyPath) : null;

    const tables = (
      old
        .prepare("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .all() as Array<{ name: string; sql: string }>
    ).filter((t) => t.sql);

    let totalCopied = 0;
    for (const t of tables) {
      // Recreate the table in the encrypted DB (the old CREATE statement, made idempotent).
      encDb.exec(t.sql.replace(/^CREATE TABLE/i, "CREATE TABLE IF NOT EXISTS"));
      const cols = (old.prepare(`PRAGMA table_info(${t.name})`).all() as Array<{ name: string }>).map((c) => c.name);
      if (cols.length === 0) continue;
      const allRows = old.prepare(`SELECT * FROM ${t.name}`).all() as Array<Record<string, unknown>>;
      if (allRows.length === 0) continue;
      const placeholders = cols.map(() => "?").join(", ");
      const insert = encDb.prepare(`INSERT OR IGNORE INTO ${t.name} (${cols.join(", ")}) VALUES (${placeholders})`);
      let copied = 0;
      let skipped = 0;
      for (const r of allRows) {
        let undecryptable = false;
        const values = cols.map((c) => {
          let v = r[c];
          if (v instanceof Uint8Array && ((t.name === "transcript" && c === "blob") || (t.name === "retry_queue" && c === "content_blob"))) {
            const pt = transcriptKey ? decryptColumnBlob(v, transcriptKey) : null;
            if (pt !== null) v = Buffer.from(pt);
            else undecryptable = true;
          }
          return v as unknown;
        });
        if (undecryptable) {
          // Drop the row rather than store ciphertext-as-plaintext (silent corruption). The session's
          // authoritative hash chain (session_tree_leaves) is unaffected; only this readable copy is lost.
          logger.error("persist.identity.migrate.blob.undecryptable", { table: t.name });
          skipped++;
          continue;
        }
        insert.run(...values);
        copied++;
      }
      // Verify: every old row was either copied or deliberately skipped — none silently dropped by IGNORE.
      const newCount = Number((encDb.prepare(`SELECT COUNT(*) AS c FROM ${t.name}`).get() as { c: number }).c);
      if (newCount !== copied) {
        throw new IdentityMigrationError(
          `row-count mismatch migrating table '${t.name}': expected ${copied}, found ${newCount}`,
          "A row was unexpectedly dropped during migration. The original DB is untouched; restart to retry.",
        );
      }
      if (skipped > 0) logger.warn("persist.identity.migrate.table.partial", { table: t.name, copied, skipped });
      totalCopied += copied;
    }
    return totalCopied;
  } finally {
    old.close();
  }
}

/** Quarantine an agent's flat files (key + sibling secrets) to `*.corrupt`. */
function quarantineFlatAgent(a: { name: string; dir: string; keyPath: string }, logger: Logger): void {
  for (const f of [a.keyPath, ...Object.values(REG_FILES).map((n) => join(a.dir, n))]) {
    if (existsSync(f)) {
      try { renameSync(f, `${f}.corrupt`); } catch { /* ignore */ }
    }
  }
  logger.warn("persist.identity.migrate.agent.quarantined", { agentName: a.name });
}

/** Import each pre-story agent's flat files into one `agents` row. Returns the count imported. */
function importFlatIdentity(celloDir: string, encDb: DaemonDatabase, logger: Logger): number {
  const agents = discoverFlatAgents(celloDir);
  let count = 0;
  for (const a of agents) {
    // Skip an agent whose name is held by an ACTIVE row in the encrypted DB (e.g. a prior in-place run
    // imported it but a cleanup unlink failed) — never overwrite live DB identity with stale flat-file
    // values (fallback-finder / code-review LOW). REMOVE-001: a RETIRED tombstone does NOT occupy the
    // name (it was freed for reuse), so qualify active-only — matching hasActiveAgent everywhere else —
    // otherwise a genuinely different flat identity restored under a freed name would be silently
    // skipped and then deleted. deleteFlatIdentity will remove the redundant files.
    const exists = encDb
      .prepare("SELECT 1 AS one FROM agents WHERE agent_name = ? AND state != 'retired'")
      .get(a.name) as { one: number } | undefined;
    if (exists) continue;

    // K_local seed from the 37-byte CELLO key file. A corrupt key SKIPS the WHOLE agent — its key AND
    // its sibling plaintext secrets (frost-share/ml-dsa/link) are quarantined to `*.corrupt` so no
    // plaintext secret is left on disk (code-review HIGH). One unreadable agent must not down the
    // daemon (availability); its identity is unrecoverable anyway, so the daemon starts without it.
    let seed: Uint8Array;
    try {
      seed = decodeKeyFileSeed(new Uint8Array(readFileSync(a.keyPath)));
    } catch (err) {
      logger.error("persist.identity.migrate.key.corrupt", {
        agentName: a.name,
        error: (err as { message?: string })?.message ?? String(err),
      });
      quarantineFlatAgent(a, logger);
      continue;
    }
    const pubkeyHex = Buffer.from(deriverPubkey(seed)).toString("hex");

    const reg = readJson(join(a.dir, REG_FILES.reg));
    const mlDsa = readJson(join(a.dir, REG_FILES.mlDsa));
    const frost = readJson(join(a.dir, REG_FILES.frost));
    const link = readJson(join(a.dir, REG_FILES.link));
    const state = reg ? "registered" : "created";
    const now = Date.now();

    // REMOVE-001: the store is keyed by a stable agent_id — mint one for each imported flat agent.
    encDb
      .prepare(
        `INSERT OR IGNORE INTO agents (agent_id, agent_name, k_local_seed, k_local_pubkey, state, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(randomUUID(), a.name, Buffer.from(seed), pubkeyHex, state, now, now);

    if (mlDsa) {
      encDb
        .prepare("UPDATE agents SET ml_dsa_pubkey = ?, ml_dsa_secret = ?, ml_dsa_algorithm = ? WHERE agent_name = ?")
        .run(String(mlDsa["mlDsaPubkey"]), Buffer.from(hexToBytes(String(mlDsa["secretKeyBlob"]))), String(mlDsa["algorithm"] ?? "ML-DSA-44"), a.name);
    }
    if (frost) {
      encDb
        .prepare(
          `UPDATE agents SET frost_epoch_id=?, frost_primary_pubkey=?, frost_identifier=?, frost_signing_share=?,
             frost_threshold=?, frost_participants=?, frost_commitments=?, frost_verifying_shares=?, frost_dkg_method=?
           WHERE agent_name=?`,
        )
        .run(
          String(frost["epochId"]),
          String(frost["primaryPubkey"]),
          String(frost["identifier"]),
          Buffer.from(hexToBytes(String(frost["signingShare"]))),
          Number(frost["threshold"]),
          Number(frost["participants"]),
          Buffer.from(hexToBytes(String(frost["commitmentsCbor"]))),
          Buffer.from(hexToBytes(String(frost["verifyingSharesCbor"]))),
          String(frost["dkgMethod"]),
          a.name,
        );
    }
    if (reg) {
      encDb
        .prepare("UPDATE agents SET reg_agent_id=?, reg_primary_pubkey=?, reg_ml_dsa_pubkey=?, reg_registered_at=?, reg_status=? WHERE agent_name=?")
        .run(String(reg["agentId"]), String(reg["primaryPubkey"]), String(reg["mlDsaPubkey"]), Number(reg["registeredAt"]), String(reg["status"] ?? "active"), a.name);
    }
    if (link) {
      encDb
        .prepare("UPDATE agents SET link_agent_id=?, link_pre_auth_token=?, link_linked_at=? WHERE agent_name=?")
        .run(String(link["agentId"]), String(link["preAuthToken"]), Number(link["linkedAt"]), a.name);
    }
    // SI-001: never log the seed/share/secret — only the agent name + count.
    logger.info("persist.identity.migrated.agent", { agentName: a.name, registered: reg != null });
    count++;
  }
  return count;
}

/** Delete every flat-file identity artifact after a successful import. */
function deleteFlatIdentity(celloDir: string, logger: Logger): void {
  for (const a of discoverFlatAgents(celloDir)) {
    for (const f of [a.keyPath, ...Object.values(REG_FILES).map((n) => join(a.dir, n))]) {
      if (existsSync(f)) { try { unlinkSync(f); } catch (err) { logger.warn("persist.identity.migrate.cleanup.failed", { file: f, error: String(err) }); } }
    }
  }
  // The legacy anti-rollback floor file — its value now lives in manifest_state (importManifestVersion).
  const manifestPath = join(celloDir, MANIFEST_FILE);
  if (existsSync(manifestPath)) {
    try { unlinkSync(manifestPath); } catch (err) { logger.warn("persist.identity.migrate.cleanup.failed", { file: manifestPath, error: String(err) }); }
  }
}

/** Derive the Ed25519 public key for a seed (migration helper). */
function deriverPubkey(seed: Uint8Array): Uint8Array {
  // InMemoryKeyProvider computes the pubkey in its constructor; getPublicKey is async, but the value
  // is synchronous. We re-derive via a throwaway provider's toJSON (which exposes the hex) to avoid
  // an async hop in this sync migration.
  const provider = new InMemoryKeyProvider(seed);
  const hex = (provider.toJSON() as { publicKey: string }).publicKey;
  return new Uint8Array(Buffer.from(hex, "hex"));
}
