/**
 * CELLO-M7-PERSIST-002 — Unit 1: SQLCipher engine swap + key custody + fail-closed.
 *
 * Specification (SPARC Phase S):
 *   AC-001  The daemon DB is opened via @signalapp/sqlcipher with a PRAGMA key; the raw file (and its
 *           WAL) yield NO readable data — table contents, indexes, AND SQLite structure (schema
 *           identifiers) are all ciphertext. It is genuinely SQLCipher (cipher_version present, high
 *           entropy), not a reversible scramble. Opening without the key yields no plaintext; the
 *           keyed handle reads every table.
 *   AC-010  The whole-DB SQLCipher supersedes the per-column transcript cipher; the transcript read
 *           surface still round-trips; no separate transcript-key file.
 *   AC-011  Missing key on a fresh DB → generate (0600) and proceed. Present-but-wrong key on an
 *           EXISTING DB (driven through the real SessionNodeManager.initialize() path) → fail closed
 *           with db_encryption_key_mismatch, and the operator's DB is left BYTE-IDENTICAL — never
 *           recreated, truncated, or replaced with a plaintext store.
 *   SI-002  Fail closed on encryption — no plaintext store/fallback anywhere.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile, writeFile, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { DatabaseSync } from "node:sqlite";
import { PassthroughGatewayClient } from "@cello-protocol/gateway";
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
import { seedAgents } from "./helpers/seed-agents.js";

function makeLogger(): Logger {
  return { debug() {}, info() {}, warn() {}, error() {} };
}

/** Minimal factory — never invoked by these DB-only tests. */
class StubNodeFactory implements ISessionNodeFactory {
  async createNode(_config: SessionNodeConfig): Promise<CelloNode> {
    throw new Error("not used in DB-only tests");
  }
}

/** Shannon entropy in bits/byte (0..8). AES ciphertext ≈ 7.9+; an XOR/plaintext SQLite file is low. */
function entropyBitsPerByte(buf: Buffer): number {
  if (buf.length === 0) return 0;
  const counts = new Array<number>(256).fill(0);
  for (const b of buf) counts[b]++;
  let h = 0;
  for (const c of counts) {
    if (c === 0) continue;
    const p = c / buf.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** All on-disk bytes for a DB path: the main file plus its WAL (where fresh writes may sit). */
async function allDbBytes(dbPath: string): Promise<Buffer> {
  const parts: Buffer[] = [await readFile(dbPath)];
  if (existsSync(`${dbPath}-wal`)) parts.push(await readFile(`${dbPath}-wal`));
  return Buffer.concat(parts);
}

let tempDir = "";
beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "persist002-"));
});
afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

async function initManager(dbPath: string): Promise<SessionNodeManager> {
  const mgr = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new StubNodeFactory(), logger: makeLogger(), dbPath });
  await mgr.initialize();
  return mgr;
}

/**
 * DOD-AGENT-ID-JOINKEY-1: `sessions` is keyed by the stable agent_id, never agent_name. Production
 * always has an `agents` row before a session exists, so seed one here (idempotent) and insert
 * against its resolved id — never a bare, never-created name.
 */
async function insertSessionRow(mgr: SessionNodeManager, counterparty: string): Promise<void> {
  const now = Date.now();
  const ids = await seedAgents(mgr.getDb(), ["alice"]);
  mgr
    .getDb()
    .prepare(
      `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .run("sess-needle-id", ids.get("alice")!, counterparty, "active", now, now);
}

describe("PERSIST-002 Unit 1 — SQLCipher engine (AC-001/AC-010/AC-011, SI-002)", () => {
  it("AC-001: the raw DB+WAL is genuinely-encrypted ciphertext — no metadata, no message, no SCHEMA, high entropy", async () => {
    const dbPath = join(tempDir, "sessions.db");
    const COUNTERPARTY_NEEDLE = "deadbeefcounterparty00000000000000000000000000000000000000000001";
    const TRANSCRIPT_NEEDLE = "TOP-SECRET-PLAINTEXT-NEEDLE-9f3a";

    const mgr = await initManager(dbPath);
    await insertSessionRow(mgr, COUNTERPARTY_NEEDLE);
    mgr.recordTranscriptMessage("alice", "sess-needle-id", 0, "sent", new TextEncoder().encode(TRANSCRIPT_NEEDLE));

    const raw = await allDbBytes(dbPath);

    // (a) No row data in cleartext.
    expect(raw.includes(Buffer.from(COUNTERPARTY_NEEDLE, "latin1"))).toBe(false);
    expect(raw.includes(Buffer.from(TRANSCRIPT_NEEDLE, "latin1"))).toBe(false);
    // (b) No SQLite STRUCTURE in cleartext — schema identifiers must be encrypted too (kills a
    // column-only cipher that leaves the schema readable, and the plaintext-header case).
    for (const schemaToken of ["SQLite format 3", "CREATE TABLE", "sessions", "transcript", "counterparty_pubkey"]) {
      expect(raw.includes(Buffer.from(schemaToken, "latin1"))).toBe(false);
    }
    expect(isPlaintextSqliteFile(dbPath)).toBe(false);
    // (c) High entropy — kills a reversible scramble (XOR/base64) that would preserve the sparse
    // SQLite file's low entropy while passing the needle/structure checks above.
    expect(entropyBitsPerByte(raw)).toBeGreaterThan(7.0);

    // (d) It is genuinely SQLCipher, not a homegrown cipher: cipher_version is reported on the keyed
    // handle (a plain SQLite/scramble DB cannot answer this pragma).
    const keyed = openEncryptedDatabaseAtPath(dbPath);
    const cipherVersion = keyed.pragma?.("cipher_version", { simple: true });
    keyed.close();
    expect(typeof cipherVersion).toBe("string");
    expect(String(cipherVersion).length).toBeGreaterThan(0);
  });

  it("AC-001: plain node:sqlite cannot read the encrypted file; the keyed handle can", async () => {
    const dbPath = join(tempDir, "sessions.db");
    const mgr = await initManager(dbPath);
    await insertSessionRow(mgr, "cphex");

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
    await insertSessionRow(mgr, "cphex");
    mgr.recordTranscriptMessage("alice", "sess-needle-id", 0, "sent", new TextEncoder().encode("hello"));
    mgr.recordTranscriptMessage("alice", "sess-needle-id", 1, "received", new TextEncoder().encode("world"));

    const out = mgr.readTranscript("alice", "sess-needle-id");
    expect(out.messages.map((m) => m.text)).toEqual(["hello", "world"]);
    expect(out.messages.map((m) => m.direction)).toEqual(["sent", "received"]);
    // No separate transcript-key file is created (the per-column cipher and its side key are gone).
    await expect(stat(`${dbPath}.transcript-key`)).rejects.toThrow();
  });

  it("AC-011/DEC-2: a 0600 32-byte key file is created beside a fresh DB", async () => {
    const dbPath = join(tempDir, "sessions.db");
    await initManager(dbPath);
    const st = await stat(dbKeyPathFor(dbPath));
    expect(st.size).toBe(32);
    expect(st.mode & 0o777).toBe(0o600);
  });

  it("AC-011/SI-002: a WRONG key file on an existing DB fails closed THROUGH initialize() and leaves the DB byte-identical", async () => {
    const dbPath = join(tempDir, "sessions.db");

    // Build a real encrypted DB with data, then release the handle so the file is final.
    const mgr = await initManager(dbPath);
    await insertSessionRow(mgr, "cphex-intact");
    mgr.recordTranscriptMessage("alice", "sess-needle-id", 0, "sent", new TextEncoder().encode("intact-data"));
    mgr.getDb().close();

    const before = await readFile(dbPath);

    // Corrupt the key file with 32 wrong-but-valid-length bytes (the realistic "restored a mismatched
    // key / DB from different backups" case). resolveDbKey only checks length, so this reaches the
    // real open path inside initialize().
    await writeFile(dbKeyPathFor(dbPath), Buffer.alloc(32, 0x07), { mode: 0o600 });

    // The DAEMON path must fail closed — a regression that catches the mismatch and silently
    // recreates a fresh (or plaintext) store would be caught here.
    const mgr2 = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new StubNodeFactory(), logger: makeLogger(), dbPath });
    let thrown: unknown;
    try {
      await mgr2.initialize();
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(DbEncryptionError);
    expect((thrown as DbEncryptionError).code).toBe("db_encryption_key_mismatch");

    // The operator's encrypted DB is untouched: not recreated, not truncated, not turned plaintext.
    const after = await readFile(dbPath);
    expect(after.equals(before)).toBe(true);
    expect(isPlaintextSqliteFile(dbPath)).toBe(false);
  });

  it("AC-011/SI-002: openEncryptedDatabase rejects a wrong key with the db_encryption_key_mismatch code", async () => {
    const dbPath = join(tempDir, "sessions.db");
    const mgr = await initManager(dbPath);
    mgr.getDb().close();

    try {
      openEncryptedDatabase(dbPath, new Uint8Array(32).fill(7));
      throw new Error("expected open with wrong key to throw");
    } catch (err) {
      expect(err).toBeInstanceOf(DbEncryptionError);
      expect((err as DbEncryptionError).code).toBe("db_encryption_key_mismatch");
    }
  });

  it("AC-011/SI-002: resolveDbKey fails closed (db_encryption_key_mismatch) when the DB exists but the key file is gone", async () => {
    const dbPath = join(tempDir, "sessions.db");
    const mgr = await initManager(dbPath);
    mgr.getDb().close();
    await rm(dbKeyPathFor(dbPath));
    try {
      resolveDbKey(dbPath, dbKeyPathFor(dbPath));
      throw new Error("expected resolveDbKey to throw");
    } catch (err) {
      expect(err).toBeInstanceOf(DbEncryptionError);
      expect((err as DbEncryptionError).code).toBe("db_encryption_key_mismatch");
    }
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
