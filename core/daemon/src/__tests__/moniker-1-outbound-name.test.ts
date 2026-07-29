/**
 * MONIKER-1 — outbound name (M8C-MONIKER-SPEC §MONIKER-1).
 *
 * Tests are written RED-first per SPARC Phase R.
 *
 * An agent's outbound name defaults to its AGENT NAME — no separate "self-moniker"
 * concept exists (AC1). An optional per-agent override is persisted on the agents
 * table (AC2 — NOT the config store, D14), validated at set-time with the shared
 * MONIKER-0 validator so an invalid value can never be stored (AC3). The name is
 * local: it is never sent to the directory (AC4 — registration path untouched).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { DatabaseSync } from "node:sqlite";
import { PassthroughGatewayClient } from "@cello-protocol/gateway";
import { startDaemon, type DaemonHandle, type DaemonConfig } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import { openEncryptedDatabaseAtPath } from "../sqlcipher-db.js";
import { DbIdentityStore, ensureIdentitySchema } from "../db-identity-store.js";
import type { Logger } from "../types.js";

function makeLogger(): Logger {
  return { debug() {}, info() {}, warn() {}, error() {} };
}

const colNames = (db: DatabaseSync): string[] =>
  (db.prepare("PRAGMA table_info(agents)").all() as Array<{ name: string }>).map((c) => c.name);

// ─── AC2: the additive, guarded migration ────────────────────────────────────

describe("MONIKER-1 AC2 — moniker column migration", () => {
  it("a fresh DB gets the column via CREATE (no ALTER needed)", () => {
    const db = new DatabaseSync(":memory:");
    ensureIdentitySchema(db);
    expect(colNames(db)).toContain("moniker");
  });

  it("adds the column to a pre-moniker agents table, idempotently", () => {
    const db = new DatabaseSync(":memory:");
    // A pre-moniker table: stable-agent_id shape WITH the M8B column, WITHOUT moniker.
    db.exec(`CREATE TABLE agents (
      agent_id TEXT PRIMARY KEY, agent_name TEXT NOT NULL, k_local_seed BLOB NOT NULL,
      k_local_pubkey TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'created',
      frost_directory_node_ids TEXT,
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`);
    db.exec(`INSERT INTO agents (agent_id, agent_name, k_local_seed, k_local_pubkey, created_at, updated_at)
      VALUES ('id1', 'alice', x'00', 'aa', 1, 1)`);
    expect(colNames(db)).not.toContain("moniker");

    ensureIdentitySchema(db);

    expect(colNames(db)).toContain("moniker");
    // Existing rows → NULL, no data loss.
    const row = db.prepare("SELECT agent_name, moniker FROM agents WHERE agent_id = 'id1'").get() as {
      agent_name: string;
      moniker: string | null;
    };
    expect(row.agent_name).toBe("alice");
    expect(row.moniker).toBeNull();
    // SQLite has no ADD COLUMN IF NOT EXISTS — a second run must not throw.
    expect(() => ensureIdentitySchema(db)).not.toThrow();
  });

  it("a table missing BOTH quorum and moniker columns receives BOTH ALTERs", () => {
    // Guards the independent-`if` structure: a chained `else if` would apply only the
    // first missing-column ALTER and silently skip the second.
    const db = new DatabaseSync(":memory:");
    db.exec(`CREATE TABLE agents (
      agent_id TEXT PRIMARY KEY, agent_name TEXT NOT NULL, k_local_seed BLOB NOT NULL,
      k_local_pubkey TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'created',
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`);
    expect(colNames(db)).not.toContain("frost_directory_node_ids");
    expect(colNames(db)).not.toContain("moniker");

    ensureIdentitySchema(db);

    expect(colNames(db)).toContain("frost_directory_node_ids");
    expect(colNames(db)).toContain("moniker");
    expect(() => ensureIdentitySchema(db)).not.toThrow();
  });
});

// ─── AC1 + AC3: store-level persistence, default, and the invalid-write backstop ──

describe("MONIKER-1 — DbIdentityStore moniker accessors", () => {
  function makeStore(): { store: DbIdentityStore; db: DatabaseSync } {
    const db = new DatabaseSync(":memory:");
    const store = new DbIdentityStore(db, makeLogger());
    return { store, db };
  }

  const seed = new Uint8Array(32).fill(7);

  it("AC1 — outbound name defaults to the agent name (no override stored)", () => {
    const { store } = makeStore();
    store.createAgent("alice", seed, "aa".repeat(32));
    expect(store.getMoniker("alice")).toBeNull();
    expect(store.getOutboundName("alice")).toBe("alice");
  });

  it("AC2 — a set override persists and wins; clearing restores the default", () => {
    const { store } = makeStore();
    store.createAgent("alice", seed, "aa".repeat(32));
    expect(store.setMoniker("alice", "Wonderland_Alice")).toBe(true);
    expect(store.getMoniker("alice")).toBe("Wonderland_Alice");
    expect(store.getOutboundName("alice")).toBe("Wonderland_Alice");
    // Clear via explicit null → back to the agent-name default.
    expect(store.setMoniker("alice", null)).toBe(true);
    expect(store.getMoniker("alice")).toBeNull();
    expect(store.getOutboundName("alice")).toBe("alice");
  });

  it("AC3 — the store is the backstop: an invalid moniker can never be stored", () => {
    const { store, db } = makeStore();
    store.createAgent("alice", seed, "aa".repeat(32));
    expect(() => store.setMoniker("alice", "Bob Eve")).toThrow();
    expect(() => store.setMoniker("alice", 'Bob"')).toThrow();
    expect(() => store.setMoniker("alice", "A".repeat(65))).toThrow();
    // Nothing landed in the column.
    const row = db.prepare("SELECT moniker FROM agents WHERE agent_name = 'alice'").get() as {
      moniker: string | null;
    };
    expect(row.moniker).toBeNull();
  });

  it("returns false for a missing or retired agent — never a silent no-op success", () => {
    const { store } = makeStore();
    expect(store.setMoniker("ghost", "Casper")).toBe(false);
    store.createAgent("bob", seed, "bb".repeat(32));
    store.retireAgent("bob");
    expect(store.setMoniker("bob", "Robert")).toBe(false);
    expect(store.getOutboundName("ghost")).toBeNull();
  });
});

// ─── AC2/AC3: the daemon handler over real IPC ───────────────────────────────

let tempDir = "";
let handle: DaemonHandle | null = null;
const clients: IpcClient[] = [];

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "moniker1-"));
});
afterEach(async () => {
  for (const c of clients) { try { c.close(); } catch { /* ignore */ } }
  clients.length = 0;
  if (handle) { await handle.stop(); handle = null; }
  await rm(tempDir, { recursive: true, force: true });
});

function makeConfig(): DaemonConfig {
  return {
      securityGateway: new PassthroughGatewayClient(),
    celloDir: tempDir,
    socketPath: join(tempDir, "daemon.sock"),
    lockFilePath: join(tempDir, "daemon.lock"),
    maxConnections: 16,
    version: "0.0.1-test",
    logger: makeLogger(),
  };
}

async function connect(socketPath: string): Promise<IpcClient> {
  const client = await connectToDaemon(socketPath);
  clients.push(client);
  await client.send("ipc.connect", { clientType: "mcp" });
  return client;
}

describe("MONIKER-1 — cello_set_moniker handler", () => {
  it("sets, persists (survives a daemon restart), and clears the override", async () => {
    const config = makeConfig();
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_create_agent", { name: "alice" });

    const set = (await client.send("cello_set_moniker", { agent: "alice", moniker: "Wonderland_Alice" })) as {
      ok: boolean; agent?: string; moniker?: string | null;
    };
    expect(set.ok).toBe(true);
    expect(set.agent).toBe("alice");
    expect(set.moniker).toBe("Wonderland_Alice");

    // Durability: restart the daemon, the override is still there (agents table, not memory).
    await handle.stop();
    handle = await startDaemon(config);
    const client2 = await connect(config.socketPath);
    const db = openEncryptedDatabaseAtPath(join(tempDir, "sessions.db"));
    try {
      expect(new DbIdentityStore(db, makeLogger()).getMoniker("alice")).toBe("Wonderland_Alice");
    } finally {
      db.close();
    }

    // Clear via explicit null.
    const cleared = (await client2.send("cello_set_moniker", { agent: "alice", moniker: null })) as {
      ok: boolean; moniker?: string | null;
    };
    expect(cleared.ok).toBe(true);
    expect(cleared.moniker).toBeNull();
  });

  it("rejects an invalid moniker at set-time with a clean error — never stores it", async () => {
    const config = makeConfig();
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_create_agent", { name: "alice" });

    const bad = (await client.send("cello_set_moniker", { agent: "alice", moniker: "Not A Valid Name!" })) as {
      ok: boolean; reason?: string; guidance?: string;
    };
    expect(bad.ok).toBe(false);
    expect(bad.reason).toBe("invalid_moniker");
    expect(bad.guidance).toBeTruthy();

    const db = openEncryptedDatabaseAtPath(join(tempDir, "sessions.db"));
    try {
      expect(new DbIdentityStore(db, makeLogger()).getMoniker("alice")).toBeNull();
    } finally {
      db.close();
    }
  });

  it("rejects a MISSING moniker param — absence is not a clear", async () => {
    // Review Finding 3: `params?.moniker ?? null` treated an omitted key as an explicit clear,
    // so a malformed request silently deleted a stored override and reported success. JSON
    // preserves explicit null, so absence is distinguishable and must be rejected.
    const config = makeConfig();
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_create_agent", { name: "alice" });
    await client.send("cello_set_moniker", { agent: "alice", moniker: "Wonderland_Alice" });

    const missing = (await client.send("cello_set_moniker", { agent: "alice" })) as {
      ok: boolean; reason?: string;
    };
    expect(missing.ok).toBe(false);
    expect(missing.reason).toBe("missing_params");

    // The stored override survived the malformed request.
    const db = openEncryptedDatabaseAtPath(join(tempDir, "sessions.db"));
    try {
      expect(new DbIdentityStore(db, makeLogger()).getMoniker("alice")).toBe("Wonderland_Alice");
    } finally {
      db.close();
    }
  });

  it("fails loud for an unknown agent", async () => {
    const config = makeConfig();
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    const missing = (await client.send("cello_set_moniker", { agent: "ghost", moniker: "Casper" })) as {
      ok: boolean; reason?: string;
    };
    expect(missing.ok).toBe(false);
    expect(missing.reason).toBe("agent_not_found");
  });
});
