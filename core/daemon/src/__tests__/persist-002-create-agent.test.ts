/**
 * CELLO-M7-PERSIST-002 — Unit 4 (AC-004): the explicit agent-creation path.
 *
 * A brand-new operator (empty CELLO_DIR, no key anywhere) can create an agent end-to-end from
 * cello-client alone: cello_create_agent generates a fresh K_local seed and writes it as an `agents`
 * row in the encrypted DB — NO key file — and wires the agent in so it is immediately usable. Creation
 * is explicit (cello_start_agent never auto-creates on a typo).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway";
import { startDaemon, type DaemonHandle, type DaemonConfig } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import { openEncryptedDatabaseAtPath } from "../sqlcipher-db.js";
import { DbIdentityStore } from "../db-identity-store.js";
import { InMemoryKeyProvider } from "@cello-protocol/crypto";
import type { Logger } from "../types.js";

function makeLogger(): Logger {
  return { debug() {}, info() {}, warn() {}, error() {} };
}

let tempDir = "";
let handle: DaemonHandle | null = null;
const clients: IpcClient[] = [];

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "persist002-create-"));
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

describe("PERSIST-002 Unit 4 — cello_create_agent (AC-004)", () => {
  it("creates a fresh agent as a DB row (no key file) and makes it immediately usable", async () => {
    const config = makeConfig();
    handle = await startDaemon(config); // empty CELLO_DIR → zero agents
    const client = await connect(config.socketPath);

    const created = (await client.send("cello_create_agent", { name: "alice" })) as { ok: boolean; name?: string; pubkey?: string };
    expect(created.ok).toBe(true);
    expect(created.name).toBe("alice");
    expect(created.pubkey).toMatch(/^[0-9a-f]{64}$/);

    // AC-002/AC-004: NO key file anywhere — the identity is a row in the encrypted DB only.
    await expect(stat(join(tempDir, "agents", "alice", "key"))).rejects.toThrow();
    const db = openEncryptedDatabaseAtPath(join(tempDir, "sessions.db"));
    try {
      const agents = new DbIdentityStore(db, makeLogger()).listAgents();
      const alice = agents.find((a) => a.agentName === "alice")!;
      expect(alice).toBeDefined();
      expect(alice.kLocalPubkey).toBe(created.pubkey);
      // TEETH (test-attacker #1): the STORED SEED must actually derive the returned pubkey — a hollow
      // impl that stores an unrelated seed (and signs as a different identity after restart) fails here.
      const derived = Buffer.from(await new InMemoryKeyProvider(alice.kLocalSeed).getPublicKey()).toString("hex");
      expect(derived).toBe(created.pubkey);
    } finally {
      db.close();
    }

    // The created agent appears and is usable without a restart (start + use succeed).
    const list = (await client.send("cello_list_agents")) as { ok: boolean; agents: Array<{ name: string }> };
    expect(list.agents.map((a) => a.name)).toContain("alice");
    expect(((await client.send("cello_start_agent", { name: "alice" })) as { ok: boolean }).ok).toBe(true);
    expect(((await client.send("cello_use_agent", { name: "alice" })) as { ok: boolean }).ok).toBe(true);
  });

  it("rejects a duplicate name with agent_already_exists (no silent overwrite)", async () => {
    const config = makeConfig();
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    const first = (await client.send("cello_create_agent", { name: "bob" })) as { ok: boolean; pubkey?: string };
    expect(first.ok).toBe(true);
    const dup = (await client.send("cello_create_agent", { name: "bob" })) as { ok: boolean; reason?: string };
    expect(dup.ok).toBe(false);
    expect(dup.reason).toBe("agent_already_exists");

    // The original identity is untouched.
    const db = openEncryptedDatabaseAtPath(join(tempDir, "sessions.db"));
    try {
      expect(new DbIdentityStore(db, makeLogger()).listAgents().find((a) => a.agentName === "bob")!.kLocalPubkey).toBe(first.pubkey);
    } finally {
      db.close();
    }
  });

  it("rejects an invalid agent name with invalid_agent_name", async () => {
    const config = makeConfig();
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    const res = (await client.send("cello_create_agent", { name: "bad name/with spaces" })) as { ok: boolean; reason?: string };
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("invalid_agent_name");
  });

  it("cello_start_agent does NOT auto-create on an unknown name (creation is explicit)", async () => {
    const config = makeConfig();
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    const res = (await client.send("cello_start_agent", { name: "ghost" })) as { ok: boolean; reason?: string };
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("agent_not_found");
    // No row was created for the typo.
    const db = openEncryptedDatabaseAtPath(join(tempDir, "sessions.db"));
    try {
      expect(new DbIdentityStore(db, makeLogger()).listAgents()).toHaveLength(0);
    } finally {
      db.close();
    }
  });
});
