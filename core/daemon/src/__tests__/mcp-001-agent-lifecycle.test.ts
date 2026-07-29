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
import { PassthroughGatewayClient } from "@cello-protocol/gateway";
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
      securityGateway: new PassthroughGatewayClient(),
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
    const list1 = await client.send("cello_list_agents") as { agents: Array<{ name: string; state: string; selected?: boolean }> };
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

    const result = await client.send("cello_use_agent", { name: "alice" }) as { ok: boolean };
    expect(result.ok).toBe(true); // M8C-AUTOSTART-1: may also carry a non-blocking not_registered warning

    // Verify agent shows as selected (M8C-AUTOSTART-1 F5: selected flag, not state:"current")
    const list = await client.send("cello_list_agents") as { agents: Array<{ name: string; state: string; selected?: boolean }> };
    const alice = list.agents.find((a) => a.name === "alice");
    expect(alice?.selected).toBe(true);

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
    const list = await client.send("cello_list_agents") as { agents: Array<{ name: string; state: string; selected?: boolean }> };
    const alice = list.agents.find((a) => a.name === "alice");
    expect(alice?.state).toBe("registered");

    // Verify agent.offline event
    const offlineEvent = logEvents.find((e) => e.event === "agent.offline");
    expect(offlineEvent).toBeDefined();
    expect(offlineEvent!.context.agentName).toBe("alice");
    expect(offlineEvent!.context.reason).toBe("stopped");

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
    const list1 = await client1.send("cello_list_agents") as { agents: Array<{ name: string; state: string; selected?: boolean }> };
    const list2 = await client2.send("cello_list_agents") as { agents: Array<{ name: string; state: string; selected?: boolean }> };

    // Connection 1: alice=current, bob=online, charlie=registered
    expect(list1.agents.find((a) => a.name === "alice")?.selected).toBe(true);
    expect(list1.agents.find((a) => a.name === "bob")?.state).toBe("online");
    expect(list1.agents.find((a) => a.name === "charlie")?.state).toBe("registered");

    // Connection 2: alice=online, bob=current, charlie=registered
    expect(list2.agents.find((a) => a.name === "alice")?.state).toBe("online");
    expect(list2.agents.find((a) => a.name === "bob")?.selected).toBe(true);
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
    const switchResult = await client2.send("cello_use_agent", { name: "alice" }) as { ok: boolean };
    expect(switchResult.ok).toBe(true); // M8C-AUTOSTART-1: may also carry a not_registered warning

    // Connection 2 sees alice as current
    const list2 = await client2.send("cello_list_agents") as { agents: Array<{ name: string; state: string; selected?: boolean }> };
    expect(list2.agents.find((a) => a.name === "alice")?.selected).toBe(true);

    // Connection 1 still sees alice as current (independent)
    const list1 = await client1.send("cello_list_agents") as { agents: Array<{ name: string; state: string; selected?: boolean }> };
    expect(list1.agents.find((a) => a.name === "alice")?.selected).toBe(true);

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

  // ─── CC-3: F18 sole-online fallback on the session-action tools ───
  // Pre-CC-3 these tools hard-failed no_current_agent unless a current agent was explicitly selected
  // for the connection — even with exactly one agent online (the post-/mcp-reconnect papercut). CC-3
  // routes them through resolveCurrentAgent: explicit { name } > current > sole online agent.
  describe("CC-3: session-action tools resolve the sole online agent (F18)", () => {
    it("cello_list_sessions resolves the sole ONLINE agent when none is selected (was no_current_agent)", async () => {
      const config = await setupWithAgents("alice");
      handle = await startDaemon(config);
      const client = await connect(config.socketPath);
      // Online, but NOT cello_use_agent → this connection's currentAgent stays null. Pre-CC-3 the guard
      // only accepted connState.currentAgent, so this returned no_current_agent. It must now resolve.
      await client.send("cello_start_agent", { name: "alice" });

      const result = await client.send("cello_list_sessions", {}) as { ok: boolean; reason?: string };
      expect(result.reason).not.toBe("no_current_agent");
      expect(result.ok).toBe(true);
    });

    it("stays no_current_agent when TWO agents are online and none is selected (ambiguous — must not guess)", async () => {
      const config = await setupWithAgents("alice", "bob");
      handle = await startDaemon(config);
      const client = await connect(config.socketPath);
      await client.send("cello_start_agent", { name: "alice" });
      await client.send("cello_start_agent", { name: "bob" });

      const result = await client.send("cello_list_sessions", {}) as { ok: boolean; reason?: string };
      expect(result.ok).toBe(false);
      expect(result.reason).toBe("no_current_agent");
    });

    it("explicit { agent } selects THAT agent even with two online (pins the selected agent, not just non-failure)", async () => {
      const config = await setupWithAgents("alice", "bob");
      handle = await startDaemon(config);
      const client = await connect(config.socketPath);
      await client.send("cello_start_agent", { name: "alice" });
      await client.send("cello_start_agent", { name: "bob" });

      // A session owned by bob only — so the list result proves WHICH agent { agent } selected, not
      // merely that the call didn't fail (a resolver bug returning the wrong agent would still be ok:true).
      const bobSession = "b0".repeat(16);
      await handle.getSessionNodeManager().createSessionNode(bobSession, "bob", "cc".repeat(32), "peer-bob", "corr-bob");

      const bobList = await client.send("cello_list_sessions", { agent: "bob", filter: "all" }) as { ok: boolean; reason?: string; sessions: Array<{ sessionId: string }> };
      expect(bobList.reason).not.toBe("no_current_agent");
      expect(bobList.ok).toBe(true);
      expect(bobList.sessions.some((s) => s.sessionId === bobSession)).toBe(true);

      // alice must NOT see bob's session — proves { agent: "alice" } selected alice, not "the first online agent".
      const aliceList = await client.send("cello_list_sessions", { agent: "alice", filter: "all" }) as { sessions: Array<{ sessionId: string }> };
      expect(aliceList.sessions.some((s) => s.sessionId === bobSession)).toBe(false);
    });
  });

  // ─── CC-5 / F21: force-abandon + dead-half-open reap ───
  describe("CC-5/F21: half-open session terminal-escape (force) + reap-on-read", () => {
    // Seed a session row directly (no libp2p node needed): abandonSession's retireSessionNode is a no-op
    // when there is no live node, and the reaper/close read from the DB.
    // DOD-AGENT-ID-JOINKEY-1: `sessions`/`transcript` are keyed by the stable agent_id, never
    // agent_name. `setupWithAgents` already gave this daemon a real `agents` row for each name (the
    // flat-file + one-time migration path), so resolve it rather than writing the mutable name.
    function seedSession(agent: string, sid: string, opts: { status?: string; createdAt?: number; messageCount?: number }): void {
      const now = opts.createdAt ?? Date.now();
      const agentId = handle!.getSessionNodeManager().resolveAgentId(agent);
      handle!.getSessionNodeManager().getDb().prepare(
        `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
      ).run(sid, agentId, "cc".repeat(32), opts.status ?? "active", now, now, opts.messageCount ?? 1);
    }
    function seedReceivedMessage(agent: string, sid: string): void {
      const agentId = handle!.getSessionNodeManager().resolveAgentId(agent);
      handle!.getSessionNodeManager().getDb().prepare(
        `INSERT OR IGNORE INTO transcript (agent_id, session_id, sequence, direction, blob, created_at)
         VALUES (?, ?, 0, 'received', ?, ?)`,
      ).run(agentId, sid, Buffer.from("hi from counterparty"), Date.now());
    }
    async function openSids(client: IpcClient): Promise<string[]> {
      const r = (await client.send("cello_list_sessions", { filter: "open" })) as { sessions: Array<{ sessionId: string }> };
      return r.sessions.map((s) => s.sessionId);
    }
    async function statusOf(client: IpcClient, sid: string): Promise<string | undefined> {
      const r = (await client.send("cello_list_sessions", { filter: "all" })) as { sessions: Array<{ sessionId: string; status: string }> };
      return r.sessions.find((s) => s.sessionId === sid)?.status;
    }

    it("cello_close_session { force } abandons a session and drops it from the open list", async () => {
      const config = await setupWithAgents("alice");
      handle = await startDaemon(config);
      const client = await connect(config.socketPath);
      await client.send("cello_start_agent", { name: "alice" });
      await client.send("cello_use_agent", { name: "alice" });

      const sid = "f1".repeat(16); // fresh active session (won't be reaped) — the operator force-abandons it
      seedSession("alice", sid, { createdAt: Date.now() });
      expect(await openSids(client)).toContain(sid);

      const closed = (await client.send("cello_close_session", { session_id: sid, force: true })) as { ok: boolean; status?: string; reason?: string };
      expect(closed.ok).toBe(true);
      expect(closed.status).toBe("abandoned");
      expect(closed.reason).toBe("force_abandoned");

      expect(await openSids(client)).not.toContain(sid); // gone from open
      expect(await statusOf(client, sid)).toBe("abandoned"); // terminal in --all
    });

    it("reaps a DEAD half-open session on read — 0 RECEIVED + not alive + past TTL — even though message_count is 1 (its own Dispatched ack)", async () => {
      const config = await setupWithAgents("alice");
      handle = await startDaemon(config);
      const client = await connect(config.socketPath);
      await client.send("cello_start_agent", { name: "alice" });
      await client.send("cello_use_agent", { name: "alice" });

      const sid = "f2".repeat(16);
      // 1h old, message_count 1 (the auto-"Dispatched." leaf), 0 received, liveness "unknown" (never set).
      // Teeth: a reaper keyed on message_count===0 would MISS this; the correct 0-RECEIVED criterion reaps it.
      seedSession("alice", sid, { createdAt: Date.now() - 60 * 60 * 1000, messageCount: 1 });

      expect(await openSids(client)).not.toContain(sid); // reaped on the list read
      expect(await statusOf(client, sid)).toBe("abandoned");
    });

    it("does NOT reap a FRESH active session (younger than the grace TTL)", async () => {
      const config = await setupWithAgents("alice");
      handle = await startDaemon(config);
      const client = await connect(config.socketPath);
      await client.send("cello_start_agent", { name: "alice" });
      await client.send("cello_use_agent", { name: "alice" });

      const sid = "f3".repeat(16);
      seedSession("alice", sid, { createdAt: Date.now(), messageCount: 1 }); // just created
      expect(await openSids(client)).toContain(sid); // survives — a genuine new session must not be abandoned
      expect(await statusOf(client, sid)).toBe("active");
    });

    it("does NOT reap an OLD active session once the counterparty has spoken (a RECEIVED message)", async () => {
      const config = await setupWithAgents("alice");
      handle = await startDaemon(config);
      const client = await connect(config.socketPath);
      await client.send("cello_start_agent", { name: "alice" });
      await client.send("cello_use_agent", { name: "alice" });

      const sid = "f4".repeat(16);
      seedSession("alice", sid, { createdAt: Date.now() - 60 * 60 * 1000, messageCount: 2 });
      seedReceivedMessage("alice", sid); // counterparty established → not half-open, must survive
      expect(await openSids(client)).toContain(sid);
      expect(await statusOf(client, sid)).toBe("active");
    });

    it("does NOT reap an OLD, 0-received active session while the counterparty is LIVE (liveness 'alive')", async () => {
      const config = await setupWithAgents("alice");
      handle = await startDaemon(config);
      const client = await connect(config.socketPath);
      await client.send("cello_start_agent", { name: "alice" });
      await client.send("cello_use_agent", { name: "alice" });

      const sid = "f5".repeat(16);
      seedSession("alice", sid, { createdAt: Date.now() - 60 * 60 * 1000, messageCount: 1 }); // old, 0 received
      handle.getSessionNodeManager().markSessionLivenessForTest("alice", sid, "alive"); // peer connected, just silent
      // Teeth for the liveness gate (reviewer F-1): this is the ONLY case where BOTH the age and the
      // 0-received gates point to "reap" — so removing the `getSessionLiveness === "alive"` gate would
      // wrongly abandon a live, connected-but-quiet session. It MUST survive.
      expect(await openSids(client)).toContain(sid);
      expect(await statusOf(client, sid)).toBe("active");
    });

    it("CC-10: reaps a DEAD INTERRUPTED ghost on read — 0 received + not alive + past TTL (the invisible post-restart shape that silently ate the abuse budget)", async () => {
      const config = await setupWithAgents("alice");
      handle = await startDaemon(config);
      const client = await connect(config.socketPath);
      await client.send("cello_start_agent", { name: "alice" });
      await client.send("cello_use_agent", { name: "alice" });

      const sid = "f6".repeat(16);
      // 1h old, status 'interrupted' (daemon restart flipped it), 0 messages, 0 received, no node.
      // classifySession(interrupted, 0) → "failed" — it appears in NO list, yet pre-CC-10 it
      // counted toward the per-sender abuse bound forever. The read must reap it to terminal.
      seedSession("alice", sid, { status: "interrupted", createdAt: Date.now() - 60 * 60 * 1000, messageCount: 0 });

      expect(await openSids(client)).not.toContain(sid);
      expect(await statusOf(client, sid)).toBe("abandoned"); // reaped on the list read, not "interrupted"
    });

    it("CC-10 guard: does NOT reap an OLD interrupted session where the counterparty has spoken (a real resumable conversation)", async () => {
      const config = await setupWithAgents("alice");
      handle = await startDaemon(config);
      const client = await connect(config.socketPath);
      await client.send("cello_start_agent", { name: "alice" });
      await client.send("cello_use_agent", { name: "alice" });

      const sid = "f7".repeat(16);
      seedSession("alice", sid, { status: "interrupted", createdAt: Date.now() - 60 * 60 * 1000, messageCount: 6 });
      seedReceivedMessage("alice", sid); // the dd7493 shape — a real interrupted conversation
      expect(await openSids(client)).toContain(sid); // still resumable-visible
      expect(await statusOf(client, sid)).toBe("interrupted"); // NOT abandoned
    });
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

  // ─── AC-011: use_agent AUTO-STARTS an offline agent (M8C-AUTOSTART-1) vs agent_not_found ───
  // Supersedes the pre-M8C agent_not_online behavior: use_agent no longer requires a prior
  // cello_start_agent — it auto-starts a loaded-but-offline agent, then selects it (login → use_agent).
  it("AC-011: cello_use_agent auto-starts an offline (registered) agent and selects it", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    // Agent exists but is not online (still Registered) — use_agent must bring it online + select it.
    const result = await client.send("cello_use_agent", { name: "alice" }) as { ok: boolean };
    expect(result.ok).toBe(true);

    const list = await client.send("cello_list_agents") as { agents: Array<{ name: string; state: string; selected?: boolean }> };
    const alice = list.agents.find((a) => a.name === "alice");
    expect(alice?.state).toBe("online");
    expect(alice?.selected).toBe(true);
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

    it("not_registered warning includes actionable guidance (M8C-AUTOSTART-1)", async () => {
      const config = await setupWithAgents("alice");
      handle = await startDaemon(config);
      const client = await connect(config.socketPath);

      // use_agent auto-starts + selects an unregistered agent, and its non-blocking warning
      // carries next-step guidance (register to enable sessions).
      const r = await client.send("cello_use_agent", { name: "alice" }) as { ok: boolean; warning?: string; warning_guidance?: string };
      expect(r.ok).toBe(true);
      expect(r.warning).toBe("not_registered");
      expect(r.warning_guidance).toContain("cello register");
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
    // CC-4 (2026-07-07): the always-empty `connections` stub was dropped from the status surface.
    expect(status).not.toHaveProperty("connections");

    // agents array with per-connection perspective
    const agents = status.agents as Array<{ name: string; state: string; pubkey?: string }>;
    const alice = agents.find((a) => a.name === "alice");
    expect(alice?.selected).toBe(true);
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
    const list2 = await client2.send("cello_list_agents") as { agents: Array<{ name: string; state: string; selected?: boolean }> };
    expect(list2.agents.find((a) => a.name === "bob")?.selected).toBe(true);
    expect(list2.agents.find((a) => a.name === "alice")?.state).toBe("online");

    // Connection 1 still sees alice as current
    const list1 = await client1.send("cello_list_agents") as { agents: Array<{ name: string; state: string; selected?: boolean }> };
    expect(list1.agents.find((a) => a.name === "alice")?.selected).toBe(true);
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
    const list1 = await client1.send("cello_list_agents") as { agents: Array<{ name: string; state: string; selected?: boolean }> };
    expect(list1.agents.find((a) => a.name === "alice")?.state).toBe("registered");

    const list2 = await client2.send("cello_list_agents") as { agents: Array<{ name: string; state: string; selected?: boolean }> };
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
    const listResult = await client.send("cello_list_agents") as { agents: Array<{ name: string; state: string; selected?: boolean }> };
    expect(listResult.agents).toBeDefined();
    expect(listResult.agents.find((a) => a.name === "alice")?.selected).toBe(true);
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
    const list = await client2.send("cello_list_agents") as { agents: Array<{ name: string; state: string; selected?: boolean }> };
    // Alice is still online (agent state persists), but not current for new connection
    expect(list.agents.find((a) => a.name === "alice")?.state).toBe("online");
  });
});
