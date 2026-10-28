/**
 * The daemon's pairing row, on a real SQLCipher database on disk.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openEncryptedDatabase, resolveDbKey, dbKeyPathFor, type DaemonDatabase } from "../sqlcipher-db.js";
import { DbPairingStore } from "../pairing-store.js";
import { seedAgentKeys } from "./helpers/seed-agents.js";
import type { Logger } from "../types.js";
import type { DaemonCredential } from "@cello-protocol/crypto";

const logger: Logger = { debug() {}, info() {}, warn() {}, error() {} };

describe("DbPairingStore", () => {
  let dir: string;
  let dbPath: string;
  const open = (): DaemonDatabase => openEncryptedDatabase(dbPath, resolveDbKey(dbPath, dbKeyPathFor(dbPath)));

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "cello-pairing-store-"));
    dbPath = join(dir, "cello.db");
  });
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

  it("1. the daemon key is created once and is the same key after the database is closed and reopened", async () => {
    let db = open();
    const first = new DbPairingStore(db, logger).daemonKey().pubkeyHex;
    expect(first).toMatch(/^[0-9a-f]{64}$/);
    db.close();
    db = open();
    const store = new DbPairingStore(db, logger);
    expect(store.daemonKey().pubkeyHex).toBe(first);
    // The reloaded seed really is the key named by the pubkey column.
    expect(Buffer.from(await store.daemonKey().keyProvider.getPublicKey()).toString("hex")).toBe(first);
    db.close();
  });

  it("1b. a populated daemon DB gains the table without losing a pre-existing agent row", async () => {
    let db = open();
    const seeded = await seedAgentKeys(db, ["alice"], logger);
    db.close();
    db = open();
    new DbPairingStore(db, logger).daemonKey();
    const row = db.prepare("SELECT agent_id, k_local_pubkey FROM agents WHERE agent_name = 'alice'").get() as
      { agent_id: string; k_local_pubkey: string } | undefined;
    expect(row).toEqual({ agent_id: seeded.get("alice")!.agentId, k_local_pubkey: seeded.get("alice")!.pubkeyHex });
    db.close();
  });

  it("12. clearing the credential keeps the daemon key", () => {
    const db = open();
    const store = new DbPairingStore(db, logger);
    const key = store.daemonKey().pubkeyHex;
    const cred: DaemonCredential = { v: 1, daemon_pubkey: key, account_id: "acct-1", nonce: "n1", issued_at: "2026-10-28T00:00:00Z", sig: "00" };
    store.saveCredential(cred);
    expect(store.credential()).toEqual(cred);
    store.clearCredential();
    expect(store.credential()).toBeNull();
    expect(new DbPairingStore(db, logger).daemonKey().pubkeyHex).toBe(key);
    db.close();
  });
});
