/**
 * CELLO-M7-PERSIST-002 — Unit 4/6: one-time flat-file + plaintext-DB → SQLCipher migration.
 *
 * Specification (SPARC Phase S):
 *   AC-006  A daemon carried from before this story (legacy `~/.cello/key` and/or `agents/<name>/`
 *           flat files and/or a plaintext node:sqlite DB) migrates ALL of it into the SQLCipher DB
 *           atomically (write-new + verify + swap, with a backup); afterwards the raw DB is
 *           ciphertext, the flat files are gone, and the migration is idempotent.
 *   AC-003  The migrated identity reloads from the encrypted store and SIGNS (seed integrity).
 *   DB-002  A migration is atomic — on failure the originals are retained (covered by the abort path).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir, writeFile, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createCipheriv, randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { FileKeyProvider, InMemoryKeyProvider } from "@cello-protocol/crypto";
import { migrateToEncryptedIfNeeded } from "../identity-migration.js";
import { openEncryptedDatabaseAtPath, isPlaintextSqliteFile } from "../sqlcipher-db.js";
import { DbIdentityStore, DbRegistrationPersistence } from "../db-identity-store.js";
import type { Logger } from "../types.js";

function makeLogger(): Logger {
  return { debug() {}, info() {}, warn() {}, error() {} };
}

/** The pre-story column cipher format: iv(12) || ct || tag(16), AES-256-GCM. */
function columnEncrypt(plaintext: Uint8Array, key: Buffer): Buffer {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(Buffer.from(plaintext)), c.final()]);
  return Buffer.concat([iv, ct, c.getAuthTag()]);
}

const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

let tempDir = "";
let dbPath = "";
beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "persist002-mig-"));
  dbPath = join(tempDir, "sessions.db");
});
afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

describe("PERSIST-002 Unit 4/6 — flat-file + plaintext-DB migration (AC-006/AC-003/DB-002)", () => {
  it("migrates a pre-story layout (plaintext DB + agent key + registration files) into the encrypted DB", async () => {
    // ── Build a faithful pre-story layout ──
    // (a) a plaintext node:sqlite sessions.db with a session row + a column-encrypted transcript row.
    const transcriptKey = randomBytes(32);
    await writeFile(`${dbPath}.transcript-key`, transcriptKey, { mode: 0o600 });
    const old = new DatabaseSync(dbPath);
    old.exec(`CREATE TABLE sessions (session_id TEXT, agent_name TEXT, counterparty_pubkey TEXT, status TEXT, created_at INTEGER, updated_at INTEGER, PRIMARY KEY (agent_name, session_id))`);
    old.exec(`CREATE TABLE transcript (agent_name TEXT, session_id TEXT, sequence INTEGER, direction TEXT, blob BLOB, created_at INTEGER, PRIMARY KEY (agent_name, session_id, sequence, direction))`);
    old.prepare("INSERT INTO sessions VALUES (?,?,?,?,?,?)").run("s1", "alice", "cpkey", "sealed", 1, 2);
    const secretMsg = "MIGRATED-TRANSCRIPT-PLAINTEXT";
    old.prepare("INSERT INTO transcript VALUES (?,?,?,?,?,?)").run("alice", "s1", 0, "sent", columnEncrypt(new TextEncoder().encode(secretMsg), transcriptKey), 3);
    old.close();
    expect(isPlaintextSqliteFile(dbPath)).toBe(true);

    // (b) agent alice with a K_local key file + the four registration JSON files (registered).
    const aliceDir = join(tempDir, "agents", "alice");
    await mkdir(aliceDir, { recursive: true });
    const aliceKp = await FileKeyProvider.load(join(aliceDir, "key")); // creates the 37-byte key file
    const alicePub = hex(await aliceKp.getPublicKey());
    await writeFile(join(aliceDir, "ml-dsa-keypair.json"), JSON.stringify({ mlDsaPubkey: "mlpub", secretKeyBlob: hex(randomBytes(64)), algorithm: "ML-DSA-44" }));
    const signingShare = randomBytes(32);
    await writeFile(join(aliceDir, "frost-share.json"), JSON.stringify({
      epochId: "ep1", primaryPubkey: "prim", identifier: "id1", signingShare: hex(signingShare),
      threshold: 2, participants: 3, commitmentsCbor: hex(randomBytes(8)), verifyingSharesCbor: hex(randomBytes(8)), dkgMethod: "network_dkg",
    }));
    await writeFile(join(aliceDir, "registration-state.json"), JSON.stringify({ agentId: "agent-alice", primaryPubkey: "prim", mlDsaPubkey: "mlpub", registeredAt: 99, status: "active" }));
    await writeFile(join(aliceDir, "agent-user-link.json"), JSON.stringify({ agentId: "agent-alice", preAuthToken: "tok", linkedAt: 100 }));

    // ── Migrate ──
    const result = migrateToEncryptedIfNeeded(dbPath, makeLogger());
    expect(result.migrated).toBe(true);
    expect(result.agentsMigrated).toBe(1);
    expect(result.rowsMigrated).toBeGreaterThanOrEqual(2);

    // ── The DB is now encrypted; flat files are gone; a backup is retained ──
    expect(isPlaintextSqliteFile(dbPath)).toBe(false);
    expect(existsSync(join(aliceDir, "key"))).toBe(false);
    expect(existsSync(join(aliceDir, "frost-share.json"))).toBe(false);
    expect(existsSync(`${dbPath}.transcript-key`)).toBe(false);
    await expect(stat(`${dbPath}.pre-sqlcipher.bak`)).resolves.toBeDefined();

    // ── The identity + data are intact in the encrypted DB ──
    const db = openEncryptedDatabaseAtPath(dbPath);
    try {
      const store = new DbIdentityStore(db, makeLogger());
      const agents = store.listAgents();
      expect(agents.map((a) => a.agentName)).toEqual(["alice"]);
      expect(agents[0]!.state).toBe("registered");
      expect(agents[0]!.kLocalPubkey).toBe(alicePub);

      // AC-003: the migrated seed reloads and signs to the SAME identity.
      const reloaded = new InMemoryKeyProvider(agents[0]!.kLocalSeed);
      expect(hex(await reloaded.getPublicKey())).toBe(alicePub);
      const sig = await reloaded.sign(new TextEncoder().encode("hello"));
      expect(sig.length).toBe(64);

      // The FROST share round-trips byte-for-byte (the can't-sign-zombie fix's durable share).
      const share = await new DbRegistrationPersistence({ db, agentName: "alice", logger: makeLogger() }).loadActiveFrostKeyShare();
      expect(share).not.toBeNull();
      expect(Buffer.from(share!.signingShare).equals(Buffer.from(signingShare))).toBe(true);

      // The transcript row was decrypted to plaintext and is now readable from the encrypted DB.
      const t = db.prepare("SELECT blob FROM transcript WHERE agent_name=? AND session_id=?").get("alice", "s1") as { blob: Uint8Array };
      expect(new TextDecoder().decode(t.blob)).toBe(secretMsg);

      // The session row survived.
      const s = db.prepare("SELECT status FROM sessions WHERE session_id=?").get("s1") as { status: string };
      expect(s.status).toBe("sealed");
    } finally {
      db.close();
    }
  });

  it("is idempotent — a second run after a successful migration is a no-op", async () => {
    const aliceDir = join(tempDir, "agents", "alice");
    await mkdir(aliceDir, { recursive: true });
    await FileKeyProvider.load(join(aliceDir, "key"));

    expect(migrateToEncryptedIfNeeded(dbPath, makeLogger()).migrated).toBe(true);
    // Second run: DB is encrypted, flat files gone → nothing to do.
    expect(migrateToEncryptedIfNeeded(dbPath, makeLogger()).migrated).toBe(false);
  });

  it("migrates the legacy ~/.cello/key as agent 'default'", async () => {
    await FileKeyProvider.load(join(tempDir, "key")); // legacy single-file key
    const result = migrateToEncryptedIfNeeded(dbPath, makeLogger());
    expect(result.migrated).toBe(true);
    expect(result.agentsMigrated).toBe(1);
    expect(existsSync(join(tempDir, "key"))).toBe(false);

    const db = openEncryptedDatabaseAtPath(dbPath);
    try {
      expect(new DbIdentityStore(db, makeLogger()).listAgents().map((a) => a.agentName)).toEqual(["default"]);
    } finally {
      db.close();
    }
  });

  it("does nothing on a fresh install (no plaintext DB, no flat files)", () => {
    expect(migrateToEncryptedIfNeeded(dbPath, makeLogger()).migrated).toBe(false);
    expect(existsSync(dbPath)).toBe(false);
  });
});
