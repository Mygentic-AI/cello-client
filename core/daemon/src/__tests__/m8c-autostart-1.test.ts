/**
 * CELLO-M8C-AUTOSTART-1 — cello_use_agent auto-starts; F5/F18 riders
 *
 * Clause coverage (M8C-BUILD-JOURNAL Entry 7, D12 revised):
 * - A1: cello_use_agent on a loaded-but-offline agent auto-starts it, then selects it (login →
 *   use_agent, no explicit cello_start_agent).
 * - A2: cello_start_agent still brings an agent online WITHOUT selecting it.
 * - A3: use_agent on a nonexistent agent leaves the current selection UNCHANGED (no half-select);
 *   an unregistered agent selects with a non-blocking not_registered warning.
 * - A4 (F18): with exactly one agent online and none selected, a name-defaulting tool USES it;
 *   two online + none selected still errors no_current_agent.
 * - A5 (F5): cello_status reports the current agent as state:"online" + selected:true, never
 *   state:"current".
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import { FileKeyProvider } from "@cello-protocol/crypto";
import type { Logger, DaemonConfig, AgentInfo } from "../types.js";

describe("M8C-AUTOSTART-1: use_agent auto-start + F5/F18", () => {
  let tempDir: string;
  let logger: Logger;
  let handle: DaemonHandle | null;
  let clients: IpcClient[];

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    tempDir = await mkdtemp(join(tmpdir(), "cello-autostart-"));
    logger = { debug() {}, info() {}, warn() {}, error() {} };
    handle = null;
    clients = [];
  });

  afterEach(async () => {
    for (const c of clients) { try { c.close(); } catch { /* closed */ } }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
    delete process.env["CELLO_ENV"];
  });

  function makeConfig(): DaemonConfig {
    return {
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
    };
  }

  async function setupWithAgents(...names: string[]): Promise<DaemonConfig> {
    for (const name of names) {
      await mkdir(join(tempDir, "agents", name), { recursive: true });
      await FileKeyProvider.load(join(tempDir, "agents", name, "key"));
    }
    return makeConfig();
  }

  async function connect(socketPath: string): Promise<IpcClient> {
    const client = await connectToDaemon(socketPath);
    clients.push(client);
    await client.send("ipc.connect", { clientType: "mcp" });
    return client;
  }

  type Result = Record<string, unknown>;
  const agentsOf = (r: Result) => (r["agents"] as AgentInfo[]);

  // ─── A1: use_agent auto-starts a loaded-but-offline agent ───
  it("A1: cello_use_agent auto-starts an offline agent then selects it", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    // No cello_start_agent first — use_agent alone must bring alice online AND select her.
    const res = (await client.send("cello_use_agent", { name: "alice" })) as Result;
    expect(res["ok"]).toBe(true);

    const status = (await client.send("cello_status", {})) as Result;
    const alice = agentsOf(status).find((a) => a.name === "alice")!;
    expect(alice.state).toBe("online");
    expect(alice.selected).toBe(true);
  });

  // ─── A2: cello_start_agent brings online WITHOUT selecting ───
  it("A2: cello_start_agent brings an agent online but does not select it", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    const res = (await client.send("cello_start_agent", { name: "alice" })) as Result;
    expect(res["ok"]).toBe(true);

    const status = (await client.send("cello_status", {})) as Result;
    const alice = agentsOf(status).find((a) => a.name === "alice")!;
    expect(alice.state).toBe("online");
    expect(alice.selected ?? false).toBe(false); // online but NOT selected
  });

  // ─── A3: no half-selected state on failure; not_registered is a non-blocking warning ───
  it("A3: use_agent on a nonexistent agent leaves selection unchanged", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    await client.send("cello_use_agent", { name: "alice" }); // alice now current
    const bad = (await client.send("cello_use_agent", { name: "ghost" })) as Result;
    expect(bad["ok"]).toBe(false);

    const status = (await client.send("cello_status", {})) as Result;
    const selected = agentsOf(status).filter((a) => a.selected);
    expect(selected.map((a) => a.name)).toEqual(["alice"]); // still alice, no half-select to ghost
  });

  it("A3: use_agent on an unregistered agent selects it with a non-blocking not_registered warning", async () => {
    const config = await setupWithAgents("alice"); // setupWithAgents does NOT register
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    const res = (await client.send("cello_use_agent", { name: "alice" })) as Result;
    expect(res["ok"]).toBe(true); // NON-blocking — still selected
    expect(res["warning"]).toBe("not_registered");
  });

  // ─── A4 (F18): sole-online agent is used when none selected ───
  it("A4: with exactly one agent online and none selected, a name-defaulting tool uses it", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    await client.send("cello_start_agent", { name: "alice" }); // online, NOT current
    // cello_get_relay_receipts defaults name to the current agent; with none set + sole-online,
    // F18 must resolve to alice instead of no_current_agent.
    const res = (await client.send("cello_get_relay_receipts", {})) as Result;
    expect(res["reason"]).not.toBe("no_current_agent");
    expect(res["ok"]).toBe(true);
  });

  it("A4: with two agents online and none selected, a name-defaulting tool still errors no_current_agent", async () => {
    const config = await setupWithAgents("alice", "bob");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    await client.send("cello_start_agent", { name: "alice" });
    await client.send("cello_start_agent", { name: "bob" });
    const res = (await client.send("cello_get_relay_receipts", {})) as Result;
    expect(res["reason"]).toBe("no_current_agent"); // ambiguous — must NOT guess
  });

  // ─── A5 (F5): status no longer overloads state with "current" ───
  it("A5: cello_status reports the current agent as state:online + selected:true, never state:current", async () => {
    const config = await setupWithAgents("alice", "bob");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    await client.send("cello_start_agent", { name: "bob" }); // online, not selected
    await client.send("cello_use_agent", { name: "alice" }); // online + selected

    const status = (await client.send("cello_status", {})) as Result;
    const all = agentsOf(status);
    expect(all.some((a) => (a.state as string) === "current")).toBe(false); // NEVER "current"

    const alice = all.find((a) => a.name === "alice")!;
    const bob = all.find((a) => a.name === "bob")!;
    expect(alice.state).toBe("online");
    expect(alice.selected).toBe(true);
    expect(bob.state).toBe("online");
    expect(bob.selected ?? false).toBe(false);
  });
});
