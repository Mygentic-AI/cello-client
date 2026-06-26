/**
 * CELLO-M7-REMOVE-001 — DOD-REMOVE-1 (local re-key + retire-and-keep + name reuse).
 *
 * `cello remove-agent X` RETIRES an agent: it flips the local `agents` row to state='retired' WITHOUT
 * deleting the row, its keys, or its history, and FREES the human name so a NEW agent can reuse it. The
 * store is re-keyed from `agent_name` PK to a stable `agent_id` PK with `agent_name` unique only among
 * non-retired rows — so the retired identity survives (accountability, SI-002) while the name becomes
 * available again, and the recreated agent is a DISTINCT identity (different agent_id + K_local).
 *
 * Fast inner loop: drives the REAL daemon over IPC (create/remove/list/start) and inspects the REAL
 * encrypted DB. The live-binary slice is j-remove.spine.test.ts.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startDaemon, type DaemonHandle, type DaemonConfig } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import { openEncryptedDatabaseAtPath } from "../sqlcipher-db.js";
import { InMemoryKeyProvider } from "@cello-protocol/crypto";
import type { Logger } from "../types.js";

function makeLogger(): Logger {
  return { debug() {}, info() {}, warn() {}, error() {} };
}

let tempDir = "";
let handle: DaemonHandle | null = null;
const clients: IpcClient[] = [];

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "remove001-"));
});
afterEach(async () => {
  for (const c of clients) { try { c.close(); } catch { /* ignore */ } }
  clients.length = 0;
  if (handle) { await handle.stop(); handle = null; }
  await rm(tempDir, { recursive: true, force: true });
});

function makeConfig(): DaemonConfig {
  return {
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

type CreateRes = { ok: boolean; name?: string; pubkey?: string; agentId?: string; reason?: string };
type RemoveRes = { ok: boolean; name?: string; agentId?: string; oneWay?: boolean; guidance?: string; reason?: string };

/** Read a row from the encrypted `agents` table by name+state (the accountability read). */
function readRow(dir: string, name: string, state: string): { agent_id: string; agent_name: string; state: string; k_local_seed: Uint8Array } | undefined {
  const db = openEncryptedDatabaseAtPath(join(dir, "sessions.db"));
  try {
    return db
      .prepare("SELECT agent_id, agent_name, state, k_local_seed FROM agents WHERE agent_name = ? AND state = ?")
      .get(name, state) as { agent_id: string; agent_name: string; state: string; k_local_seed: Uint8Array } | undefined;
  } finally {
    db.close();
  }
}

describe("REMOVE-001 DOD-REMOVE-1 — retire-and-keep + name reuse (local)", () => {
  it("retires an agent (row+keys kept, state=retired) and frees the name for a NEW distinct identity", async () => {
    const config = makeConfig();
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    // Create X — capture its stable agent_id + pubkey.
    const created = (await client.send("cello_create_agent", { name: "ada" })) as CreateRes;
    expect(created.ok, JSON.stringify(created)).toBe(true);
    expect(created.agentId, "create-agent must return a stable agent_id").toMatch(/^[0-9a-f-]{8,}$/);
    const id1 = created.agentId!;
    const pub1 = created.pubkey!;

    // Remove X — one-way, with guidance; echoes the retired agent_id.
    const removed = (await client.send("cello_remove_agent", { name: "ada" })) as RemoveRes;
    expect(removed.ok, JSON.stringify(removed)).toBe(true);
    expect(removed.oneWay).toBe(true);
    expect(typeof removed.guidance).toBe("string");
    expect(removed.agentId).toBe(id1);

    // SI-002 (local): the retired row is KEPT — same agent_id, state=retired, K_local seed intact.
    const retired = readRow(tempDir, "ada", "retired");
    expect(retired, "the retired agent row must still exist (accountability survives)").toBeDefined();
    expect(retired!.agent_id).toBe(id1);
    expect(retired!.k_local_seed?.length, "K_local seed must be kept (32-byte Ed25519 seed)").toBe(32);
    // and the kept seed still derives the original pubkey (a real identity, not a tombstone flag).
    const derived = Buffer.from(await new InMemoryKeyProvider(new Uint8Array(retired!.k_local_seed)).getPublicKey()).toString("hex");
    expect(derived).toBe(pub1);

    // The retired agent is gone from the live runtime: list excludes it, start fails.
    const list1 = (await client.send("cello_list_agents")) as { agents: Array<{ name: string }> };
    expect(list1.agents.map((a) => a.name)).not.toContain("ada");
    const startRetired = (await client.send("cello_start_agent", { name: "ada" })) as { ok: boolean; reason?: string };
    expect(startRetired.ok).toBe(false);
    expect(startRetired.reason).toBe("agent_not_found");

    // Name reuse: create-agent ada SUCCEEDS as a NEW identity — different agent_id AND different K_local.
    const recreated = (await client.send("cello_create_agent", { name: "ada" })) as CreateRes;
    expect(recreated.ok, JSON.stringify(recreated)).toBe(true);
    expect(recreated.agentId).not.toBe(id1);
    expect(recreated.pubkey).not.toBe(pub1);

    // Two rows for 'ada' now: the retired id1 + the active id2 (state='created').
    const active = readRow(tempDir, "ada", "created");
    expect(active!.agent_id).toBe(recreated.agentId);
    expect(readRow(tempDir, "ada", "retired")!.agent_id).toBe(id1);

    // The new ada is live and usable.
    const list2 = (await client.send("cello_list_agents")) as { agents: Array<{ name: string }> };
    expect(list2.agents.map((a) => a.name)).toContain("ada");
    expect(((await client.send("cello_start_agent", { name: "ada" })) as { ok: boolean }).ok).toBe(true);
  });

  it("tears down the ONLINE runtime on removal (not just the agents list): state+current notifications, re-election", async () => {
    // Teeth for the online-teardown branch (test-attacker): a removal that only splices the in-memory
    // `agents` array — leaving keyProviders / onlineAgents / the standing receiver / the keystone / the
    // connection's current agent untouched — would still pass list/use/start (all gate on `agents[]`).
    // So assert the OBSERVABLE side-effects of the real teardown that an agents-splice-only stub cannot
    // produce: the agent.removal dispatches agent_state_changed(reason='removed') AND resets the
    // connection's current agent (agent_current_changed→null). Neither fires under a splice-only stub.
    const config = makeConfig();
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    await client.send("cello_create_agent", { name: "nora" });
    expect(((await client.send("cello_start_agent", { name: "nora" })) as { ok: boolean }).ok).toBe(true);
    expect(((await client.send("cello_use_agent", { name: "nora" })) as { ok: boolean }).ok).toBe(true);

    const notes: Array<{ notification: string; data: Record<string, unknown> }> = [];
    client.onNotification((n) => notes.push(n as unknown as { notification: string; data: Record<string, unknown> }));

    expect(((await client.send("cello_remove_agent", { name: "nora" })) as RemoveRes).ok).toBe(true);

    // Let the pushed notification frames arrive.
    for (let i = 0; i < 20 && notes.length < 2; i++) await new Promise((r) => setTimeout(r, 50));
    const stateNote = notes.find((n) => n.notification === "agent_state_changed" && n.data["agentName"] === "nora");
    expect(stateNote, `agent_state_changed must fire on removal: ${JSON.stringify(notes)}`).toBeDefined();
    expect(stateNote!.data["reason"], "the retired agent is taken offline with reason 'removed'").toBe("removed");
    const currentNote = notes.find((n) => n.notification === "agent_current_changed");
    expect(currentNote, "the connection's current agent must be reset on removal").toBeDefined();
    expect(currentNote!.data["toAgent"], "current agent resets to null (not left pointing at the retired agent)").toBeNull();

    // Re-election path runs cleanly: recreate nora (the keystone disposer fires + re-wires, no stacking)
    // and it is immediately usable.
    expect(((await client.send("cello_create_agent", { name: "nora" })) as CreateRes).ok).toBe(true);
    expect(((await client.send("cello_start_agent", { name: "nora" })) as { ok: boolean }).ok).toBe(true);
    expect(((await client.send("cello_use_agent", { name: "nora" })) as { ok: boolean }).ok).toBe(true);
  });

  it("rejects removing a name with no active agent (fail-loud agent_not_found)", async () => {
    const config = makeConfig();
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    const ghost = (await client.send("cello_remove_agent", { name: "ghost" })) as RemoveRes;
    expect(ghost.ok).toBe(false);
    expect(ghost.reason).toBe("agent_not_found");
    expect(typeof ghost.guidance).toBe("string");

    // And after retiring the only agent, removing the same name again is agent_not_found (it's retired,
    // not active) — remove is one-way and never re-retires a tombstone.
    await client.send("cello_create_agent", { name: "x" });
    expect(((await client.send("cello_remove_agent", { name: "x" })) as RemoveRes).ok).toBe(true);
    expect(((await client.send("cello_remove_agent", { name: "x" })) as RemoveRes).reason).toBe("agent_not_found");
  });
});
