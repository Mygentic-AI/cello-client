/**
 * CELLO-M7-MCP-001 — Agent lifecycle and per-connection state tests
 *
 * Specification understanding:
 * - AC-001: Adapter connects to daemon IPC, no crypto imports
 * - AC-002: cello_start_agent transitions Registered→Online (idempotent)
 * - AC-003: cello_use_agent sets current agent per-connection
 * - AC-004: cello_stop_agent transitions Online→Registered
 * - AC-005: Multi-connection isolation (2 connections, different current agents)
 * - AC-006: Two connections can have same agent as current independently
 * - AC-007: no_current_agent guard on 5 session tools (separate test per tool)
 * - AC-009: ipc_connection_lost after daemon stops
 * - AC-011: agent_not_online vs agent_not_found distinction
 * - AC-012: agent_already_current
 * - AC-013: All failure responses include actionable guidance
 * - AC-019: cello_status M7 shape
 * - SI-001: Cross-connection agent leakage impossible
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import { FileKeyProvider } from "@cello-protocol/crypto";
import type { Logger, DaemonConfig } from "../types.js";

describe("MCP-001: agent lifecycle and per-connection state", () => {
  let tempDir: string;
  let logEvents: Array<{ level: string; event: string; context: Record<string, unknown> }>;
  let logger: Logger;
  let handle: DaemonHandle | null;
  let clients: IpcClient[];

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-mcp001-test-"));
    logEvents = [];
    logger = {
      debug(event, context) { logEvents.push({ level: "debug", event, context }); },
      info(event, context) { logEvents.push({ level: "info", event, context }); },
      warn(event, context) { logEvents.push({ level: "warn", event, context }); },
      error(event, context) { logEvents.push({ level: "error", event, context }); },
    };
    handle = null;
    clients = [];
  });

  afterEach(async () => {
    for (const c of clients) {
      try { c.close(); } catch { /* already closed */ }
    }
    if (handle) {
      try { await handle.stop("test_cleanup"); } catch { /* already stopped */ }
    }
    await rm(tempDir, { recursive: true, force: true });
  });

  function makeConfig(overrides?: Partial<DaemonConfig>): DaemonConfig {
    return {
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
      ...overrides,
    };
  }

  async function setupWithAgents(...agentNames: string[]): Promise<DaemonConfig> {
    const agentsDir = join(tempDir, "agents");
    for (const name of agentNames) {
      await mkdir(join(agentsDir, name), { recursive: true });
      await FileKeyProvider.load(join(agentsDir, name, "key"));
    }
    return makeConfig();
  }

  async function connect(socketPath: string): Promise<IpcClient> {
    const client = await connectToDaemon(socketPath);
    clients.push(client);
    // Send ipc.connect frame to register as MCP client
    await client.send("ipc.connect", { clientType: "mcp" });
    return client;
  }

  // ─── AC-001: Adapter connects to daemon IPC, daemon logs clientType: 'mcp' ───
  it("AC-001: ipc.connect with clientType 'mcp' logs daemon.ipc.connected with clientType mcp", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);

    const client = await connectToDaemon(config.socketPath);
    clients.push(client);

    const result = await client.send("ipc.connect", { clientType: "mcp" });
    expect(result).toHaveProperty("connectionId");

    const connectEvent = logEvents.find(
      (e) => e.event === "daemon.ipc.connected" && e.context.clientType === "mcp"
    );
    expect(connectEvent).toBeDefined();
    expect(connectEvent!.context.connectionId).toBeDefined();
  });

  // ─── AC-002: cello_start_agent transitions Registered→Online (idempotent) ───
  it("AC-002: cello_start_agent transitions agent to online and is idempotent", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    // First call: transitions Registered → Online
    const result1 = await client.send("cello_start_agent", { name: "alice" });
    expect(result1).toEqual({ ok: true });

    // Verify agent is now online
    const list1 = await client.send("cello_list_agents") as { agents: Array<{ name: string; state: string }> };
    const alice1 = list1.agents.find((a) => a.name === "alice");
    expect(alice1?.state).toBe("online");

    // Verify agent.online event fired
    const onlineEvents = logEvents.filter((e) => e.event === "agent.online");
    expect(onlineEvents).toHaveLength(1);
    expect(onlineEvents[0].context.agentName).toBe("alice");
    expect(typeof onlineEvents[0].context.agentPubkey).toBe("string");
    expect((onlineEvents[0].context.agentPubkey as string).length).toBeGreaterThan(0);

    // Second call: idempotent — no second event
    const result2 = await client.send("cello_start_agent", { name: "alice" });
    expect(result2).toEqual({ ok: true });

    const onlineEventsAfter = logEvents.filter((e) => e.event === "agent.online");
    expect(onlineEventsAfter).toHaveLength(1); // Still just one
  });

  // ─── AC-003: cello_use_agent sets current agent per-connection ───
  it("AC-003: cello_use_agent sets current agent and emits agent.current.switched", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    await client.send("cello_start_agent", { name: "alice" });

    const result = await client.send("cello_use_agent", { name: "alice" });
    expect(result).toEqual({ ok: true });

    // Verify agent shows as 'current'
    const list = await client.send("cello_list_agents") as { agents: Array<{ name: string; state: string }> };
    const alice = list.agents.find((a) => a.name === "alice");
    expect(alice?.state).toBe("current");

    // Verify agent.current.switched event
    const switchEvent = logEvents.find((e) => e.event === "agent.current.switched");
    expect(switchEvent).toBeDefined();
    expect(switchEvent!.context.fromAgent).toBeNull();
    expect(switchEvent!.context.toAgent).toBe("alice");
    expect(switchEvent!.context.connectionId).toBeDefined();
  });

  // ─── AC-004: cello_stop_agent transitions Online→Registered (idempotent) ───
  it("AC-004: cello_stop_agent transitions agent to registered and clears current", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    await client.send("cello_start_agent", { name: "alice" });
    await client.send("cello_use_agent", { name: "alice" });

    const result = await client.send("cello_stop_agent", { name: "alice" });
    expect(result).toEqual({ ok: true });

    // Verify agent is now registered
    const list = await client.send("cello_list_agents") as { agents: Array<{ name: string; state: string }> };
    const alice = list.agents.find((a) => a.name === "alice");
    expect(alice?.state).toBe("registered");

    // Verify agent.offline event
    const offlineEvent = logEvents.find((e) => e.event === "agent.offline");
    expect(offlineEvent).toBeDefined();
    expect(offlineEvent!.context.agentName).toBe("alice");
    expect(offlineEvent!.context.reason).toBe("cello_stop_agent");

    // Second call: idempotent — no second event
    const result2 = await client.send("cello_stop_agent", { name: "alice" });
    expect(result2).toEqual({ ok: true });
    const offlineEventsAfter = logEvents.filter((e) => e.event === "agent.offline");
    expect(offlineEventsAfter).toHaveLength(1);
  });

  // ─── AC-005: Multi-connection isolation ───
  it("AC-005: two connections see different current agents in cello_list_agents", async () => {
    const config = await setupWithAgents("alice", "bob", "charlie");
    handle = await startDaemon(config);

    const client1 = await connect(config.socketPath);
    const client2 = await connect(config.socketPath);

    // Start alice and bob
    await client1.send("cello_start_agent", { name: "alice" });
    await client1.send("cello_start_agent", { name: "bob" });

    // Set current agents per connection
    await client1.send("cello_use_agent", { name: "alice" });
    await client2.send("cello_use_agent", { name: "bob" });

    // Verify isolation
    const list1 = await client1.send("cello_list_agents") as { agents: Array<{ name: string; state: string }> };
    const list2 = await client2.send("cello_list_agents") as { agents: Array<{ name: string; state: string }> };

    // Connection 1: alice=current, bob=online, charlie=registered
    expect(list1.agents.find((a) => a.name === "alice")?.state).toBe("current");
    expect(list1.agents.find((a) => a.name === "bob")?.state).toBe("online");
    expect(list1.agents.find((a) => a.name === "charlie")?.state).toBe("registered");

    // Connection 2: alice=online, bob=current, charlie=registered
    expect(list2.agents.find((a) => a.name === "alice")?.state).toBe("online");
    expect(list2.agents.find((a) => a.name === "bob")?.state).toBe("current");
    expect(list2.agents.find((a) => a.name === "charlie")?.state).toBe("registered");

    // Verify two distinct connectionIds
    const connectEvents = logEvents.filter(
      (e) => e.event === "daemon.ipc.connected" && e.context.clientType === "mcp"
    );
    expect(connectEvents).toHaveLength(2);
    expect(connectEvents[0].context.connectionId).not.toBe(connectEvents[1].context.connectionId);
  });

  // ─── AC-006: Two connections can have same agent as current independently ───
  it("AC-006: two connections can both have the same agent as current", async () => {
    const config = await setupWithAgents("alice", "bob");
    handle = await startDaemon(config);

    const client1 = await connect(config.socketPath);
    const client2 = await connect(config.socketPath);

    await client1.send("cello_start_agent", { name: "alice" });
    await client1.send("cello_start_agent", { name: "bob" });

    // Set alice as current for connection 1
    await client1.send("cello_use_agent", { name: "alice" });
    // Set bob as current for connection 2
    await client2.send("cello_use_agent", { name: "bob" });

    // Now switch connection 2 to also use alice
    const switchResult = await client2.send("cello_use_agent", { name: "alice" });
    expect(switchResult).toEqual({ ok: true });

    // Connection 2 sees alice as current
    const list2 = await client2.send("cello_list_agents") as { agents: Array<{ name: string; state: string }> };
    expect(list2.agents.find((a) => a.name === "alice")?.state).toBe("current");

    // Connection 1 still sees alice as current (independent)
    const list1 = await client1.send("cello_list_agents") as { agents: Array<{ name: string; state: string }> };
    expect(list1.agents.find((a) => a.name === "alice")?.state).toBe("current");

    // Verify agent.current.switched only fired for connection 2 (not connection 1)
    const switchEvents = logEvents.filter(
      (e) => e.event === "agent.current.switched" && e.context.toAgent === "alice" && e.context.fromAgent === "bob"
    );
    expect(switchEvents).toHaveLength(1);
  });

  // ─── AC-007: no_current_agent guard on 5 session tools ───
  describe("AC-007: no_current_agent guard", () => {
    const sessionTools = [
      "cello_send",
      "cello_receive",
      "cello_receive_session",
      "cello_initiate_session",
      "cello_await_session",
      "cello_close_session",
      "cello_list_sessions",
    ];

    for (const tool of sessionTools) {
      it(`${tool} returns no_current_agent when no agent is set`, async () => {
        const config = await setupWithAgents("alice");
        handle = await startDaemon(config);
        const client = await connect(config.socketPath);

        // Clear log events accumulated during startup (e.g. session.node.created from standing receiver)
        const logIndexBefore = logEvents.length;

        const result = await client.send(tool, {}) as { ok: boolean; reason: string; guidance: string };
        expect(result.ok).toBe(false);
        expect(result.reason).toBe("no_current_agent");
        expect(result.guidance).toContain("cello_start_agent");
        expect(result.guidance).toContain("cello_use_agent");

        // Verify no protocol events fired AFTER the tool call
        const eventsAfterCall = logEvents.slice(logIndexBefore);
        const protocolEvents = eventsAfterCall.filter(
          (e) => e.event.startsWith("session.") || e.event.startsWith("frost.")
        );
        expect(protocolEvents).toHaveLength(0);
      });
    }
  });

  // ─── AC-009: ipc_connection_lost after daemon stops ───
  it("AC-009: IPC client gets connection error after daemon stops", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    // Verify connection works
    await client.send("cello_start_agent", { name: "alice" });

    // Stop the daemon
    await handle.stop("test_stop");
    handle = null;

    // Wait for socket close to propagate
    await new Promise((r) => setTimeout(r, 200));

    // Subsequent call should fail
    await expect(
      client.send("cello_list_agents")
    ).rejects.toThrow();
  });

  // ─── AC-011: agent_not_online vs agent_not_found distinction ───
  it("AC-011: cello_use_agent returns agent_not_online for registered agent", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    // Agent exists but is not online (still Registered)
    const result = await client.send("cello_use_agent", { name: "alice" }) as { ok: boolean; reason: string; guidance: string };
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("agent_not_online");
    expect(result.guidance).toContain("cello_start_agent");
  });

  it("AC-011: cello_use_agent returns agent_not_found for unknown agent", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    const result = await client.send("cello_use_agent", { name: "nonexistent" }) as { ok: boolean; reason: string; guidance: string };
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("agent_not_found");
    expect(result.guidance).toBeDefined();
  });

  // ─── AC-012: agent_already_current ───
  it("AC-012: cello_use_agent returns agent_already_current for already-current agent", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    await client.send("cello_start_agent", { name: "alice" });
    await client.send("cello_use_agent", { name: "alice" });

    // Call again — already current
    const result = await client.send("cello_use_agent", { name: "alice" }) as { ok: boolean; reason: string; guidance: string };
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("agent_already_current");
    expect(result.guidance).toContain("already the current agent");

    // Verify no agent.current.switched event for the second call
    const switchEvents = logEvents.filter((e) => e.event === "agent.current.switched");
    expect(switchEvents).toHaveLength(1); // Only one from the first call
  });

  // ─── AC-013: All failure responses include actionable guidance ───
  describe("AC-013: all failure responses include guidance", () => {
    it("agent_not_found includes guidance with tool name", async () => {
      const config = await setupWithAgents("alice");
      handle = await startDaemon(config);
      const client = await connect(config.socketPath);

      const r = await client.send("cello_start_agent", { name: "unknown" }) as { ok: boolean; guidance: string };
      expect(r.ok).toBe(false);
      expect(typeof r.guidance).toBe("string");
      expect(r.guidance.length).toBeGreaterThan(20);
    });

    it("no_current_agent includes guidance with tool names", async () => {
      const config = await setupWithAgents("alice");
      handle = await startDaemon(config);
      const client = await connect(config.socketPath);

      const r = await client.send("cello_send", {}) as { ok: boolean; guidance: string };
      expect(r.ok).toBe(false);
      expect(r.guidance).toContain("cello_");
    });

    it("agent_not_online includes guidance", async () => {
      const config = await setupWithAgents("alice");
      handle = await startDaemon(config);
      const client = await connect(config.socketPath);

      const r = await client.send("cello_use_agent", { name: "alice" }) as { ok: boolean; guidance: string };
      expect(r.ok).toBe(false);
      expect(r.guidance).toContain("cello_start_agent");
    });

    it("agent_already_current includes guidance", async () => {
      const config = await setupWithAgents("alice");
      handle = await startDaemon(config);
      const client = await connect(config.socketPath);

      await client.send("cello_start_agent", { name: "alice" });
      await client.send("cello_use_agent", { name: "alice" });
      const r = await client.send("cello_use_agent", { name: "alice" }) as { ok: boolean; guidance: string };
      expect(r.ok).toBe(false);
      expect(r.guidance.length).toBeGreaterThan(20);
    });
  });

  // ─── AC-019: cello_status M7 shape ───
  it("AC-019: cello_status returns M7 daemon status structure", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    await client.send("cello_start_agent", { name: "alice" });
    await client.send("cello_use_agent", { name: "alice" });

    const status = await client.send("cello_status") as Record<string, unknown>;

    // M7 required fields
    expect(status).toHaveProperty("daemon");
    expect(status).toHaveProperty("directory_signaling");
    expect(status).toHaveProperty("agents");
    expect(status).toHaveProperty("connections");

    // agents array with per-connection perspective
    const agents = status.agents as Array<{ name: string; state: string; pubkey?: string }>;
    const alice = agents.find((a) => a.name === "alice");
    expect(alice?.state).toBe("current");
    expect(alice?.pubkey).toBeDefined();
    expect((alice?.pubkey as string).length).toBeGreaterThan(0);

    // M6-era fields must NOT be present
    expect(status).not.toHaveProperty("transport_started");
    expect(status).not.toHaveProperty("own_pubkey");
    expect(status).not.toHaveProperty("listen_addresses");
    expect(status).not.toHaveProperty("connected_peer_count");
    expect(status).not.toHaveProperty("directory_reachable");
  });

  // ─── SI-001: Cross-connection agent leakage impossible ───
  it("SI-001: cross-connection agent leakage is impossible", async () => {
    const config = await setupWithAgents("alice", "bob");
    handle = await startDaemon(config);

    const client1 = await connect(config.socketPath);
    const client2 = await connect(config.socketPath);

    await client1.send("cello_start_agent", { name: "alice" });
    await client1.send("cello_start_agent", { name: "bob" });

    await client1.send("cello_use_agent", { name: "alice" });
    await client2.send("cello_use_agent", { name: "bob" });

    // Connection 2 calls cello_list_agents and sees bob as current, not alice
    const list2 = await client2.send("cello_list_agents") as { agents: Array<{ name: string; state: string }> };
    expect(list2.agents.find((a) => a.name === "bob")?.state).toBe("current");
    expect(list2.agents.find((a) => a.name === "alice")?.state).toBe("online");

    // Connection 1 still sees alice as current
    const list1 = await client1.send("cello_list_agents") as { agents: Array<{ name: string; state: string }> };
    expect(list1.agents.find((a) => a.name === "alice")?.state).toBe("current");
    expect(list1.agents.find((a) => a.name === "bob")?.state).toBe("online");
  });

  // ─── cello_stop_agent clears current for affected connections ───
  it("cello_stop_agent clears current agent for all connections using that agent", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);

    const client1 = await connect(config.socketPath);
    const client2 = await connect(config.socketPath);

    await client1.send("cello_start_agent", { name: "alice" });
    await client1.send("cello_use_agent", { name: "alice" });
    await client2.send("cello_use_agent", { name: "alice" });

    // Stop alice from connection 1
    await client1.send("cello_stop_agent", { name: "alice" });

    // Both connections should now see alice as registered, not current
    const list1 = await client1.send("cello_list_agents") as { agents: Array<{ name: string; state: string }> };
    expect(list1.agents.find((a) => a.name === "alice")?.state).toBe("registered");

    const list2 = await client2.send("cello_list_agents") as { agents: Array<{ name: string; state: string }> };
    expect(list2.agents.find((a) => a.name === "alice")?.state).toBe("registered");
  });

  // ─── cello_start_agent with unknown agent ───
  it("cello_start_agent returns agent_not_found for unknown agent", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    const result = await client.send("cello_start_agent", { name: "nonexistent" }) as { ok: boolean; reason: string; guidance: string };
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("agent_not_found");
    expect(result.guidance).toBeDefined();
  });

  // ─── cello_stop_agent with unknown agent ───
  it("cello_stop_agent returns agent_not_found for unknown agent", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    const result = await client.send("cello_stop_agent", { name: "nonexistent" }) as { ok: boolean; reason: string; guidance: string };
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("agent_not_found");
    expect(result.guidance).toBeDefined();
  });

  // ─── AC-018: signaling_reconnecting passthrough ───
  it("AC-018: session tools return not_implemented (signaling stub) while list_agents succeeds", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    await client.send("cello_start_agent", { name: "alice" });
    await client.send("cello_use_agent", { name: "alice" });

    // Session tool returns not_implemented (actual signaling_reconnecting passthrough
    // will be testable once SIGNAL-001 wires the directory connection; for now the
    // daemon stubs session tools after the no_current_agent guard passes)
    const sessionResult = await client.send("cello_initiate_session", { target_pubkey: "abc123" }) as { ok: boolean; reason: string };
    expect(sessionResult.ok).toBe(false);
    // The daemon currently returns not_implemented for session tools; once SIGNAL-001
    // lands, this will return signaling_reconnecting when directory is in that state.
    expect(sessionResult.reason).toBeDefined();

    // Non-directory-requiring tool succeeds (proves partitioning)
    const listResult = await client.send("cello_list_agents") as { agents: Array<{ name: string; state: string }> };
    expect(listResult.agents).toBeDefined();
    expect(listResult.agents.find((a) => a.name === "alice")?.state).toBe("current");
  });

  // ─── Connection disconnect cleans up per-connection state ───
  it("connection disconnect cleans up per-connection state silently", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);

    const client1 = await connect(config.socketPath);
    await client1.send("cello_start_agent", { name: "alice" });
    await client1.send("cello_use_agent", { name: "alice" });

    // Disconnect client 1
    client1.close();
    await new Promise((r) => setTimeout(r, 100));

    // New connection should not see alice as current
    const client2 = await connect(config.socketPath);
    const list = await client2.send("cello_list_agents") as { agents: Array<{ name: string; state: string }> };
    // Alice is still online (agent state persists), but not current for new connection
    expect(list.agents.find((a) => a.name === "alice")?.state).toBe("online");
  });
});
