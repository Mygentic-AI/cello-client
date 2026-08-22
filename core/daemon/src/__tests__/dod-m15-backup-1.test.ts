/**
 * DOD-M15-BACKUP-1 — an identity can be exported and restored.
 *
 * ─── What is at stake ──────────────────────────────────────────────────────────────────────────
 *
 * `cello_backup` and `cello_restore` are registered tools that return `not_implemented`. A lost
 * machine loses the agent permanently: the key shares, the pinned counterparty identities, the
 * transcripts and the seals are all in one SQLCipher database on that disk, and nothing exports it.
 *
 * ─── The trap this unit exists to avoid, and the DoD's own wording walks into it ───────────────
 *
 * The line says *"Backup = exporting the SQLCipher database for transport."* Exporting the database
 * ALONE produces a brick.
 *
 * The database is encrypted, and its key is a standalone 32-byte file at `<db>.key` — "the ONE
 * plaintext key file on disk". Restore it onto a fresh machine and the daemon mints a NEW key,
 * which cannot open the restored database. The operator would be told the backup succeeded, keep it
 * for a year, and discover on the day they need it that it can never be opened.
 *
 * So a backup carries the key with the database, and the round-trip test below is run against a
 * DIFFERENT key file to prove it — restoring into a directory whose key does not match the archive
 * is exactly the lost-machine case, and it is the one that must work.
 *
 * ─── And the opposite failure, which is worse ──────────────────────────────────────────────────
 *
 * A file containing that key IS the agent. Anyone holding it can sign as them. The archive is
 * therefore as sensitive as a private key, and the tool has to say so at the moment it writes one —
 * an operator who drops it in a shared folder has handed over their identity, and nothing about a
 * file called "backup" suggests that.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { openTestDb } from "./helpers/encrypted-db.js";
import { createBackup, restoreBackup } from "../backup-restore.js";
import type { Logger } from "../types.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

describe("DOD-M15-BACKUP-1: an agent survives the loss of its machine", () => {
  let dir: string;

  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), "m15-backup-")); });
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

  /** A live encrypted database with something identifying in it. */
  function seedDb(dbPath: string, marker: string): void {
    const db = openTestDb(dbPath);
    db.exec("CREATE TABLE IF NOT EXISTS backup_probe (id INTEGER PRIMARY KEY, marker TEXT)");
    db.prepare("INSERT INTO backup_probe (marker) VALUES (?)").run(marker);
    db.close();
  }

  it("ROUND TRIP onto a machine that never had this agent — the lost-laptop case", async () => {
    /**
     * ★ THE PROPERTY. The restore target is a DIFFERENT directory with its OWN key file, which is
     * what a new machine looks like. If the archive did not carry the key, the restored database
     * would be unopenable here — and that is the failure an operator would only discover on the day
     * they needed the backup.
     */
    const srcDb = join(dir, "src", "sessions.db");
    await rm(join(dir, "src"), { recursive: true, force: true });
    const { mkdir } = await import("node:fs/promises");
    await mkdir(join(dir, "src"), { recursive: true });
    seedDb(srcDb, "the-original-agent");

    const archive = join(dir, "agent.cello-backup");
    const made = await createBackup({ dbPath: srcDb, outPath: archive, logger: silent });
    expect(made.ok, `backup failed: ${JSON.stringify(made)}`).toBe(true);
    expect(existsSync(archive), "the archive must actually exist on disk").toBe(true);

    // A fresh machine: its own directory, its own (different) key file, no database.
    const dstDir = join(dir, "dst");
    await mkdir(dstDir, { recursive: true });
    const dstDb = join(dstDir, "sessions.db");
    await writeFile(`${dstDb}.key`, randomBytes(32), { mode: 0o600 });

    const restored = await restoreBackup({ archivePath: archive, dbPath: dstDb, logger: silent });
    expect(restored.ok, `restore failed: ${JSON.stringify(restored)}`).toBe(true);

    const db = openTestDb(dstDb);
    const row = db.prepare("SELECT marker FROM backup_probe LIMIT 1").get() as { marker: string } | undefined;
    db.close();
    expect(
      row?.marker,
      "the restored database could not be read on the new machine — the archive did not carry its key",
    ).toBe("the-original-agent");
  });

  it("the archive carries the KEY, not just the database", async () => {
    // Stated separately from the round trip so a failure says WHICH half is missing.
    const dbPath = join(dir, "sessions.db");
    seedDb(dbPath, "x");
    const archive = join(dir, "a.cello-backup");
    await createBackup({ dbPath, outPath: archive, logger: silent });

    const inspected = await readFile(archive);
    // The container is compressed, so assert through the reader rather than on raw bytes.
    const { inspectBackup } = await import("../backup-restore.js");
    const meta = await inspectBackup(archive);
    expect(meta.ok).toBe(true);
    expect(meta.ok && meta.hasKey, "an archive without the key restores to an unopenable database").toBe(true);
    expect(inspected.length).toBeGreaterThan(0);
  });

  it("REFUSES to restore a corrupt archive rather than destroying the database it would replace", async () => {
    /**
     * Restore OVERWRITES. If a truncated or wrong file is accepted, the operator loses the working
     * agent they still had — the backup tool becomes the thing that destroys the identity. So the
     * archive is validated in full BEFORE anything on disk is touched.
     */
    const dbPath = join(dir, "sessions.db");
    seedDb(dbPath, "still-here");
    const archive = join(dir, "broken.cello-backup");
    await writeFile(archive, Buffer.from("this is not a cello backup"));

    const res = await restoreBackup({ archivePath: archive, dbPath, logger: silent });
    expect(res.ok).toBe(false);
    expect(res.ok === false && typeof res.guidance).toBe("string");

    // The existing agent must be untouched.
    const db = openTestDb(dbPath);
    const row = db.prepare("SELECT marker FROM backup_probe LIMIT 1").get() as { marker: string } | undefined;
    db.close();
    expect(row?.marker, "a failed restore destroyed the database it was replacing").toBe("still-here");
  });

  it("a TRUNCATED archive is refused too — length is checked, not just the header", async () => {
    // The plausible real corruption: an interrupted copy. A header-only check would accept it and
    // then write a half database over a working one.
    const dbPath = join(dir, "sessions.db");
    seedDb(dbPath, "intact");
    const good = join(dir, "good.cello-backup");
    await createBackup({ dbPath, outPath: good, logger: silent });

    const bytes = await readFile(good);
    const truncated = join(dir, "truncated.cello-backup");
    await writeFile(truncated, bytes.subarray(0, Math.floor(bytes.length / 2)));

    const res = await restoreBackup({ archivePath: truncated, dbPath, logger: silent });
    expect(res.ok).toBe(false);

    const db = openTestDb(dbPath);
    expect((db.prepare("SELECT marker FROM backup_probe LIMIT 1").get() as { marker: string }).marker).toBe("intact");
    db.close();
  });

  it("the backup response SAYS the file is as sensitive as a private key", async () => {
    /**
     * Invariant 5 (affordances), and the reason it matters here more than usual: the archive
     * contains the plaintext SQLCipher key, so possession of the file IS possession of the agent.
     * Nothing about the word "backup" suggests that, and an operator who puts it in a shared drive
     * has handed someone the ability to sign as them.
     */
    const dbPath = join(dir, "sessions.db");
    seedDb(dbPath, "x");
    const res = await createBackup({ dbPath, outPath: join(dir, "b.cello-backup"), logger: silent });
    expect(res.ok).toBe(true);
    const warning = res.ok ? `${res.guidance}` : "";
    expect(warning).toMatch(/private key|anyone who has|sign as/i);
  });

  it("refuses to overwrite an existing archive unless told to — a backup is not a scratch file", async () => {
    // Silently replacing yesterday's good archive with today's broken one is a way to lose an
    // identity while believing you have two copies of it.
    const dbPath = join(dir, "sessions.db");
    seedDb(dbPath, "x");
    const archive = join(dir, "once.cello-backup");
    expect((await createBackup({ dbPath, outPath: archive, logger: silent })).ok).toBe(true);

    const second = await createBackup({ dbPath, outPath: archive, logger: silent });
    expect(second.ok).toBe(false);

    const forced = await createBackup({ dbPath, outPath: archive, logger: silent, overwrite: true });
    expect(forced.ok).toBe(true);
  });
});
