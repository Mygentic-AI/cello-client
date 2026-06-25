/**
 * CELLO-M7-PERSIST-002 — Unit 1: SQLCipher engine swap + key custody + fail-closed.
 *
 * Specification (SPARC Phase S):
 *   AC-001  The daemon DB is opened via @signalapp/sqlcipher with a PRAGMA key; the raw file yields
 *           NO readable data — table contents, indexes, SQLite structure are all ciphertext. Opening
 *           without the key fails to yield plaintext; the daemon with the key reads every table.
 *   AC-010  The whole-DB SQLCipher supersedes the per-column transcript cipher; the transcript read
 *           surface still works (round-trip), but there is no separate column cipher / transcript-key.
 *   AC-011  Missing key on a fresh DB → generate (0600) and proceed. Present-but-wrong key on an
 *           existing DB → fail closed with 'db_encryption_key_mismatch'; never a plaintext fallback.
 *   SI-002  Fail closed on encryption — no plaintext store/fallback anywhere.
 *
 * These assertions are RED on the pre-story daemon (plain node:sqlite — session-row metadata sits in
 * cleartext in the file) and GREEN once the engine is SQLCipher.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { DatabaseSync } from "node:sqlite";
import { SessionNodeManager } from "../session-node-manager.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Logger } from "../types.js";
import {
  openEncryptedDatabase,
  openEncryptedDatabaseAtPath,
  resolveDbKey,
  dbKeyPathFor,
  DbEncryptionError,
  isPlaintextSqliteFile,
} from "../sqlcipher-db.js";

function makeLogger(): Logger {
  return {
    debug() {},
    info() {},
    warn() {},
    error() {},
  };
}

/** Minimal factory — never invoked by these DB-only tests. */
class StubNodeFactory implements ISessionNodeFactory {
  async createNode(_config: SessionNodeConfig): Promise<CelloNode> {
    throw new Error("not used in DB-only tests");
  }
}

const SQLITE_MAGIC = "SQLite format 3";

let tempDir = "";
beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "persist002-"));
});
afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

async function initManager(dbPath: string): Promise<SessionNodeManager> {
  const mgr = new SessionNodeManager({ factory: new StubNodeFactory(), logger: makeLogger(), dbPath });
  await mgr.initialize();
  return mgr;
}

function insertSessionRow(mgr: SessionNodeManager, counterparty: string): void {
  const now = Date.now();
  mgr
    .getDb()
    .prepare(
      `INSERT INTO sessions (session_id, agent_name, counterparty_pubkey, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .run("sess-needle-id", "alice", counterparty, "active", now, now);
}

describe("PERSIST-002 Unit 1 — SQLCipher engine (AC-001/AC-010/AC-011, SI-002)", () => {
  it("AC-001: session-row metadata and transcript are ciphertext in the raw DB file", async () => {
    const dbPath = join(tempDir, "sessions.db");
    const COUNTERPARTY_NEEDLE = "deadbeefcounterparty00000000000000000000000000000000000000000001";
    const TRANSCRIPT_NEEDLE = "TOP-SECRET-PLAINTEXT-NEEDLE-9f3a";

    const mgr = await initManager(dbPath);
    insertSessionRow(mgr, COUNTERPARTY_NEEDLE);
    mgr.recordTranscriptMessage("alice", "sess-needle-id", 0, "sent", new TextEncoder().encode(TRANSCRIPT_NEEDLE));

    // The raw on-disk bytes must contain NO plaintext — not the metadata, not the message, not even
    // the SQLite header magic (a SQLCipher DB encrypts the header).
    const raw = await readFile(dbPath);
    expect(raw.includes(Buffer.from(COUNTERPARTY_NEEDLE, "latin1"))).toBe(false);
    expect(raw.includes(Buffer.from(TRANSCRIPT_NEEDLE, "latin1"))).toBe(false);
    expect(raw.subarray(0, SQLITE_MAGIC.length).toString("latin1")).not.toBe(SQLITE_MAGIC);
    expect(isPlaintextSqliteFile(dbPath)).toBe(false);
  });

  it("AC-001: plain node:sqlite cannot read the encrypted file; the keyed handle can", async () => {
    const dbPath = join(tempDir, "sessions.db");
    const mgr = await initManager(dbPath);
    insertSessionRow(mgr, "cphex");

    // Plain node:sqlite open of the encrypted file must NOT yield the row (it should throw or read
    // nothing) — never plaintext.
    let plaintextLeak = false;
    try {
      const plain = new DatabaseSync(dbPath);
      const rows = plain.prepare("SELECT counterparty_pubkey FROM sessions").all() as Array<{ counterparty_pubkey: string }>;
      plaintextLeak = rows.some((r) => r.counterparty_pubkey === "cphex");
      plain.close();
    } catch {
      plaintextLeak = false;
    }
    expect(plaintextLeak).toBe(false);

    // The keyed handle reads the row back.
    const keyed = openEncryptedDatabaseAtPath(dbPath);
    const got = keyed.prepare("SELECT counterparty_pubkey FROM sessions WHERE session_id = ?").get("sess-needle-id") as
      | { counterparty_pubkey: string }
      | undefined;
    keyed.close();
    expect(got?.counterparty_pubkey).toBe("cphex");
  });

  it("AC-010: the transcript read surface still round-trips (whole-DB SQLCipher, no column cipher)", async () => {
    const dbPath = join(tempDir, "sessions.db");
    const mgr = await initManager(dbPath);
    insertSessionRow(mgr, "cphex");
    mgr.recordTranscriptMessage("alice", "sess-needle-id", 0, "sent", new TextEncoder().encode("hello"));
    mgr.recordTranscriptMessage("alice", "sess-needle-id", 1, "received", new TextEncoder().encode("world"));

    const out = mgr.readTranscript("alice", "sess-needle-id");
    expect(out.messages.map((m) => m.text)).toEqual(["hello", "world"]);
    expect(out.undecryptable).toBe(0);
    // No separate transcript-key file is created (the column cipher is gone).
    await expect(stat(`${dbPath}.transcript-key`)).rejects.toThrow();
  });

  it("AC-011/DEC-2: a 0600 32-byte key file is created beside a fresh DB", async () => {
    const dbPath = join(tempDir, "sessions.db");
    await initManager(dbPath);
    const keyPath = dbKeyPathFor(dbPath);
    const st = await stat(keyPath);
    expect(st.size).toBe(32);
    expect(st.mode & 0o777).toBe(0o600);
  });

  it("AC-011/SI-002: a wrong key on an existing DB fails closed with db_encryption_key_mismatch", async () => {
    const dbPath = join(tempDir, "sessions.db");
    await initManager(dbPath);

    const wrongKey = new Uint8Array(32).fill(7);
    try {
      openEncryptedDatabase(dbPath, wrongKey);
      throw new Error("expected open with wrong key to throw");
    } catch (err) {
      expect(err).toBeInstanceOf(DbEncryptionError);
      expect((err as DbEncryptionError).code).toBe("db_encryption_key_mismatch");
    }
  });

  it("AC-011/SI-002: resolveDbKey fails closed when the DB exists but the key file is gone", async () => {
    const dbPath = join(tempDir, "sessions.db");
    await initManager(dbPath);
    // Remove the key file → an existing encrypted DB with no key must NOT be silently replaced.
    await rm(dbKeyPathFor(dbPath));
    expect(() => resolveDbKey(dbPath, dbKeyPathFor(dbPath))).toThrowError(/key file is missing/i);
  });

  it("AC-011: resolveDbKey generates a fresh key only when both DB and key are absent", () => {
    const dbPath = join(tempDir, "fresh.db");
    const keyPath = dbKeyPathFor(dbPath);
    const key = resolveDbKey(dbPath, keyPath);
    expect(key.length).toBe(32);
    // Idempotent: a second resolve loads the same key.
    const again = resolveDbKey(dbPath, keyPath);
    expect(Buffer.from(again).equals(Buffer.from(key))).toBe(true);
  });
});
