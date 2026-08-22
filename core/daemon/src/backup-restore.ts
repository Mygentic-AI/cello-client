/**
 * DOD-M15-BACKUP-1 — export an agent's identity, and put it back on another machine.
 *
 * ─── What a backup has to contain, and why the obvious answer is wrong ─────────────────────────
 *
 * The DoD line says *"Backup = exporting the SQLCipher database for transport."* Exporting the
 * database alone produces a file nobody can ever open.
 *
 * The database is encrypted and its key is a separate 32-byte file at `<db>.key` — `sqlcipher-db.ts`
 * calls it "the ONE plaintext key file on disk". A fresh daemon on a new machine mints its own key,
 * which cannot open a database encrypted under a different one. An operator restoring a
 * database-only archive would be told it worked, and find out on the day they needed it that the
 * contents are unreadable forever.
 *
 * So the archive carries BOTH, and the round-trip test restores into a directory holding a
 * different key precisely to prove it.
 *
 * ─── The consequence of that, which the tool must say out loud ─────────────────────────────────
 *
 * A file containing that key IS the agent. Whoever holds it can sign as them, read every
 * transcript, and use their identity. Nothing about the word "backup" suggests a file this
 * dangerous, so the response says it at the moment one is written. `DOD-M15-CLAIM-SCREEN-1`'s rule
 * applies to affordances as much as claims: silence is not an option.
 *
 * ─── Why `VACUUM INTO` rather than copying the file ────────────────────────────────────────────
 *
 * The daemon holds the database open with a write lock. Copying the file byte-for-byte while it is
 * open can capture a torn page or miss a WAL frame, producing an archive that restores into a
 * corrupt database — the worst outcome available here, because it looks like a successful backup.
 * `VACUUM INTO` asks SQLite for a consistent snapshot, and on SQLCipher the target inherits the
 * source's cipher settings, so the snapshot is encrypted under the same key.
 *
 * ─── Restore is validated in full BEFORE anything is touched ───────────────────────────────────
 *
 * Restore OVERWRITES. A truncated or wrong file that is accepted destroys the working agent the
 * operator still had — the backup tool becomes the thing that loses the identity. So the container
 * is parsed, its checksum verified and its payloads decompressed entirely in memory first; only
 * then does anything reach the disk.
 *
 * ─── V1 scope, per the DoD ─────────────────────────────────────────────────────────────────────
 *
 * Export plus overwrite-restore. MERGE — restoring onto a device that has its own live state — is
 * explicitly deferred, and this module does not pretend otherwise: restore replaces, and says so.
 */

import { createHash, randomBytes } from "node:crypto";
import { gzipSync, gunzipSync } from "node:zlib";
import { readFile, writeFile, rm, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { openEncryptedDatabase, dbKeyPathFor } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

/** Magic + version, so a wrong file is refused by shape before anything else is attempted. */
const MAGIC = "CELLO-BACKUP-v1";

interface BackupEnvelope {
  magic: string;
  version: 1;
  created_at: number;
  /** SHA-256 over the raw database snapshot bytes — an interrupted copy fails this. */
  db_sha256: string;
  db_b64: string;
  key_b64: string;
}

export type BackupResult =
  | { ok: true; path: string; bytes: number; guidance: string }
  | { ok: false; reason: string; guidance: string };

export type RestoreResult =
  | { ok: true; dbPath: string; guidance: string }
  | { ok: false; reason: string; guidance: string };

/**
 * THE SENSITIVITY NOTICE. One string, used by every path that writes an archive, so a second call
 * site cannot ship a quieter version of it.
 */
const SENSITIVITY =
  "TREAT THIS FILE LIKE A PRIVATE KEY. It contains your agent's encrypted database AND the key that " +
  "opens it, because a backup without the key restores to something nobody can read. Anyone who has " +
  "this file can sign as your agent and read every transcript in it. Store it where you would store " +
  "a private key — not a shared drive, not a chat message.";

/**
 * Take a consistent snapshot of the live database and write a portable archive.
 *
 * `dbPath` is the live database. It may be open in this process; `VACUUM INTO` is safe against that
 * and is why the snapshot goes through SQLite rather than a file copy.
 */
export async function createBackup(opts: {
  dbPath: string;
  outPath: string;
  logger: Logger;
  keyPath?: string;
  /** A backup is not a scratch file: replacing one is deliberate, never incidental. */
  overwrite?: boolean;
}): Promise<BackupResult> {
  const keyPath = opts.keyPath ?? dbKeyPathFor(opts.dbPath);

  if (!existsSync(opts.dbPath)) {
    return {
      ok: false,
      reason: "database_not_found",
      guidance: `No database at ${opts.dbPath}. Start the daemon at least once before taking a backup — there is no identity to export yet.`,
    };
  }
  if (!existsSync(keyPath)) {
    // Refused rather than exported-without-key: an archive that cannot be opened is worse than no
    // archive, because the operator stops worrying about it.
    return {
      ok: false,
      reason: "key_file_not_found",
      guidance: `The database at ${opts.dbPath} has no key file at ${keyPath}. Exporting the database without it would produce a backup nobody can ever open, so nothing was written.`,
    };
  }
  if (existsSync(opts.outPath) && opts.overwrite !== true) {
    return {
      ok: false,
      reason: "archive_exists",
      guidance: `${opts.outPath} already exists. Replacing a backup silently is a way to lose an identity while believing you hold two copies of it — pass overwrite to replace it deliberately, or choose another path.`,
    };
  }

  // A snapshot beside the real database, then read and discard it. `VACUUM INTO` refuses to write
  // to an existing path, so the name is fresh per call.
  const snapshot = join(tmpdir(), `cello-backup-${randomBytes(8).toString("hex")}.db`);
  try {
    const key = await readFile(keyPath);
    const db = openEncryptedDatabase(opts.dbPath, new Uint8Array(key));
    try {
      db.exec(`VACUUM INTO '${snapshot.replace(/'/g, "''")}'`);
    } finally {
      db.close();
    }

    const dbBytes = await readFile(snapshot);
    const envelope: BackupEnvelope = {
      magic: MAGIC,
      version: 1,
      created_at: Date.now(),
      db_sha256: createHash("sha256").update(dbBytes).digest("hex"),
      db_b64: dbBytes.toString("base64"),
      key_b64: key.toString("base64"),
    };

    await mkdir(dirname(opts.outPath), { recursive: true });
    const packed = gzipSync(Buffer.from(JSON.stringify(envelope), "utf8"));
    // 0600: the file carries a signing key, so it is not world-readable even for a moment.
    await writeFile(opts.outPath, packed, { mode: 0o600 });

    opts.logger.info("agent.backup.written", {
      path: opts.outPath,
      bytes: packed.length,
      impact: "the agent's identity, key shares, contacts, transcripts and seals are now exportable to another machine",
      guidance: SENSITIVITY,
    });

    return { ok: true, path: opts.outPath, bytes: packed.length, guidance: SENSITIVITY };
  } catch (err: unknown) {
    const reason = err instanceof Error ? err.message : String(err);
    opts.logger.error("agent.backup.failed", { path: opts.outPath, reason });
    return {
      ok: false,
      reason: "backup_failed",
      guidance: `The backup could not be written: ${reason}. Nothing was changed on this machine.`,
    };
  } finally {
    await rm(snapshot, { force: true }).catch(() => { /* best effort */ });
  }
}

/** Read an archive's metadata without restoring it. */
export async function inspectBackup(
  archivePath: string,
): Promise<{ ok: true; createdAt: number; hasKey: boolean; dbBytes: number } | { ok: false; reason: string }> {
  const parsed = await parseArchive(archivePath);
  if (!parsed.ok) return { ok: false, reason: parsed.reason };
  return {
    ok: true,
    createdAt: parsed.envelope.created_at,
    hasKey: parsed.envelope.key_b64.length > 0,
    dbBytes: parsed.dbBytes.length,
  };
}

/**
 * Parse and FULLY VALIDATE an archive in memory.
 *
 * Everything that can fail happens here, before `restoreBackup` touches the disk. That ordering is
 * the whole safety property: a restore that fails must leave the machine exactly as it was.
 */
async function parseArchive(
  archivePath: string,
): Promise<{ ok: true; envelope: BackupEnvelope; dbBytes: Buffer; keyBytes: Buffer } | { ok: false; reason: string }> {
  if (!existsSync(archivePath)) return { ok: false, reason: "archive_not_found" };

  let raw: Buffer;
  try {
    raw = await readFile(archivePath);
  } catch (err: unknown) {
    return { ok: false, reason: `archive_unreadable: ${err instanceof Error ? err.message : String(err)}` };
  }

  let json: string;
  try {
    json = gunzipSync(raw).toString("utf8");
  } catch {
    // A truncated file usually dies here — gzip carries its own length and CRC, which is why the
    // container is compressed rather than raw JSON.
    return { ok: false, reason: "archive_corrupt_or_not_a_cello_backup" };
  }

  let envelope: BackupEnvelope;
  try {
    envelope = JSON.parse(json) as BackupEnvelope;
  } catch {
    return { ok: false, reason: "archive_corrupt_or_not_a_cello_backup" };
  }

  if (envelope.magic !== MAGIC || envelope.version !== 1) {
    return { ok: false, reason: "archive_wrong_format_or_version" };
  }
  if (typeof envelope.db_b64 !== "string" || typeof envelope.key_b64 !== "string") {
    return { ok: false, reason: "archive_missing_payload" };
  }

  const dbBytes = Buffer.from(envelope.db_b64, "base64");
  const keyBytes = Buffer.from(envelope.key_b64, "base64");
  if (dbBytes.length === 0) return { ok: false, reason: "archive_missing_database" };
  if (keyBytes.length !== 32) {
    // Without a well-formed key the restored database is unopenable — the exact failure this unit
    // exists to prevent, so it is refused rather than restored hopefully.
    return { ok: false, reason: "archive_missing_or_malformed_key" };
  }

  const actual = createHash("sha256").update(dbBytes).digest("hex");
  if (actual !== envelope.db_sha256) return { ok: false, reason: "archive_checksum_mismatch" };

  return { ok: true, envelope, dbBytes, keyBytes };
}

/**
 * Replace this machine's database and key with the archive's.
 *
 * OVERWRITE, not merge — merge is explicitly deferred, and pretending otherwise would silently pick
 * a winner between two divergent histories. The caller is responsible for the daemon not holding
 * the database open; the handler enforces that.
 */
export async function restoreBackup(opts: {
  archivePath: string;
  dbPath: string;
  logger: Logger;
  keyPath?: string;
}): Promise<RestoreResult> {
  const keyPath = opts.keyPath ?? dbKeyPathFor(opts.dbPath);

  const parsed = await parseArchive(opts.archivePath);
  if (!parsed.ok) {
    opts.logger.error("agent.restore.refused", {
      archivePath: opts.archivePath,
      reason: parsed.reason,
      impact: "nothing was written — the agent currently on this machine is untouched",
    });
    return {
      ok: false,
      reason: parsed.reason,
      guidance:
        `That file was not restored: ${parsed.reason}. NOTHING on this machine was changed — the ` +
        `archive is validated completely before anything is written, because a restore overwrites ` +
        `and a bad archive must never be able to destroy the agent you still have.`,
    };
  }

  try {
    await mkdir(dirname(opts.dbPath), { recursive: true });
    // Key first: a database present without its key is the unopenable state, and if the process
    // dies between the two writes that is the one to avoid being left in.
    await writeFile(keyPath, parsed.keyBytes, { mode: 0o600 });
    await writeFile(opts.dbPath, parsed.dbBytes, { mode: 0o600 });
    // SQLite sidecars belong to the database that was here before; leaving them would let stale WAL
    // frames replay over the restored file.
    await rm(`${opts.dbPath}-wal`, { force: true }).catch(() => {});
    await rm(`${opts.dbPath}-shm`, { force: true }).catch(() => {});
  } catch (err: unknown) {
    const reason = err instanceof Error ? err.message : String(err);
    opts.logger.error("agent.restore.failed", { archivePath: opts.archivePath, reason });
    return {
      ok: false,
      reason: "restore_write_failed",
      guidance: `The restore could not complete: ${reason}. The database may be in a partial state — restore again from the same archive before starting the daemon.`,
    };
  }

  // Prove it opens, here, rather than letting the daemon discover it at next boot.
  try {
    const db = openEncryptedDatabase(opts.dbPath, new Uint8Array(parsed.keyBytes));
    db.close();
  } catch (err: unknown) {
    const reason = err instanceof Error ? err.message : String(err);
    opts.logger.error("agent.restore.unopenable", { dbPath: opts.dbPath, reason });
    return {
      ok: false,
      reason: "restored_database_unopenable",
      guidance: `The archive was written but the restored database could not be opened: ${reason}. This should not happen — the archive carries its own key. Keep the archive and report it.`,
    };
  }

  const createdAt = new Date(parsed.envelope.created_at).toISOString();
  opts.logger.info("agent.restore.completed", {
    dbPath: opts.dbPath,
    backupCreatedAt: createdAt,
    impact: "this machine's agent database and key were REPLACED by the archive's",
  });

  return {
    ok: true,
    dbPath: opts.dbPath,
    guidance:
      `Restored from a backup taken ${createdAt}. This machine's previous agent database was ` +
      `REPLACED, not merged — anything that happened here since that backup is gone. Restart the ` +
      `daemon (cello logout && cello login) so it opens the restored database.`,
  };
}
