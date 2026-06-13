/**
 * CELLO-M7-MCP-002 — Notification routing tests
 *
 * Specification understanding:
 * - AC-001: agent_state_changed broadcast to ALL connections on cello_start_agent
 * - AC-002: agent_state_changed broadcast to ALL connections on cello_stop_agent
 * - AC-003: agent_current_changed sent ONLY to triggering connection
 * - AC-004: session_state_changed sent to all connections where agent is current
 * - AC-005: session_state_changed NOT sent to connections with different current agent
 * - AC-006: session seal produces session_state_changed with state 'sealed'
 * - AC-007: session interrupt produces session_state_changed with state 'interrupted'
 * - AC-008: All notifications include agent field
 * - AC-009: Connections without current agent still receive agent_state_changed
 * - AC-010: Disconnected connections do not receive notifications
 * - AC-011: Logger events fire with correct fields
 * - AC-012: Composition root wiring — notifications arrive via real IPC
 * - AC-013: Lateral catch audit (grep-based, separate test)
 * - SI-001: session_state_changed never leaks across agent boundaries
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import { NotificationDispatcher } from "../notification-dispatcher.js";
import { FileKeyProvider } from "@cello-protocol/crypto";
import type { Logger, DaemonConfig, IpcNotification } from "../types.js";

describe("MCP-002: notification routing", () => {
  let tempDir: string;
  let logEvents: Array<{ level: string; event: string; context: Record<string, unknown> }>;
  let logger: Logger;
  let handle: DaemonHandle | null;
  let clients: IpcClient[];

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    tempDir = await mkdtemp(join(tmpdir(), "cello-mcp002-test-"));
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
    delete process.env["CELLO_ENV"];
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
    await client.send("ipc.connect", { clientType: "mcp" });
    return client;
  }

  /**
   * Collect notifications from a client into a buffer.
   * Returns the buffer array that accumulates notifications asynchronously.
   */
  function collectNotifications(client: IpcClient): IpcNotification[] {
    const buffer: IpcNotification[] = [];
    client.onNotification((n) => buffer.push(n));
    return buffer;
  }

  /** Wait for notifications to propagate (IPC is local, usually <10ms). */
  async function waitForNotifications(ms = 100): Promise<void> {
    await new Promise((r) => setTimeout(r, ms));
  }

  // ─── AC-001: agent_state_changed broadcast on cello_start_agent ───
  it("AC-001: both connections receive agent_state_changed on cello_start_agent", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);

    const clientA = await connect(config.socketPath);
    const clientB = await connect(config.socketPath);

    const notifA = collectNotifications(clientA);
    const notifB = collectNotifications(clientB);

    await clientA.send("cello_start_agent", { name: "alice" });
    await waitForNotifications();

    // Both connections receive agent_state_changed
    const stateA = notifA.filter((n) => n.notification === "agent_state_changed");
    const stateB = notifB.filter((n) => n.notification === "agent_state_changed");

    expect(stateA).toHaveLength(1);
    expect(stateB).toHaveLength(1);

    expect(stateA[0].data).toEqual({
      agent: "alice",
      type: "agent_state_changed",
      agentName: "alice",
      state: "online",
      reason: "started",
    });
    expect(stateB[0].data).toEqual(stateA[0].data);
  });

  // ─── AC-002: agent_state_changed broadcast on cello_stop_agent ───
  it("AC-002: both connections receive agent_state_changed on cello_stop_agent", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);

    const clientA = await connect(config.socketPath);
    const clientB = await connect(config.socketPath);

    // Start agent first
    await clientA.send("cello_start_agent", { name: "alice" });
    // Wait for the "online" notification to propagate before registering handlers
    await waitForNotifications();

    const notifA = collectNotifications(clientA);
    const notifB = collectNotifications(clientB);

    await clientA.send("cello_stop_agent", { name: "alice" });
    await waitForNotifications();

    const stateA = notifA.filter((n) => n.notification === "agent_state_changed");
    const stateB = notifB.filter((n) => n.notification === "agent_state_changed");

    expect(stateA).toHaveLength(1);
    expect(stateB).toHaveLength(1);

    expect(stateA[0].data).toEqual({
      agent: "alice",
      type: "agent_state_changed",
      agentName: "alice",
      state: "offline",
      reason: "stopped",
    });
    expect(stateB[0].data).toEqual(stateA[0].data);
  });

  // ─── AC-003: agent_current_changed sent ONLY to triggering connection ───
  it("AC-003: only the triggering connection receives agent_current_changed", async () => {
    const config = await setupWithAgents("alice", "bob");
    handle = await startDaemon(config);

    const clientA = await connect(config.socketPath);
    const clientB = await connect(config.socketPath);

    await clientA.send("cello_start_agent", { name: "alice" });
    await clientA.send("cello_start_agent", { name: "bob" });

    // Set bob as current for A first so we can switch from bob to alice
    await clientA.send("cello_use_agent", { name: "bob" });

    const notifA = collectNotifications(clientA);
    const notifB = collectNotifications(clientB);

    // Switch A from bob to alice
    await clientA.send("cello_use_agent", { name: "alice" });
    await waitForNotifications();

    const currentChangedA = notifA.filter((n) => n.notification === "agent_current_changed");
    const currentChangedB = notifB.filter((n) => n.notification === "agent_current_changed");

    // Connection A receives the notification
    expect(currentChangedA).toHaveLength(1);
    expect(currentChangedA[0].data).toEqual({
      agent: "alice",
      type: "agent_current_changed",
      fromAgent: "bob",
      toAgent: "alice",
    });

    // Connection B does NOT receive it
    expect(currentChangedB).toHaveLength(0);
  });

  // ─── AC-004: session_state_changed sent to both connections with same current agent ───
  it("AC-004: both connections with alice as current receive session_state_changed", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);

    const clientA = await connect(config.socketPath);
    const clientB = await connect(config.socketPath);

    await clientA.send("cello_start_agent", { name: "alice" });
    await clientA.send("cello_use_agent", { name: "alice" });
    await clientB.send("cello_use_agent", { name: "alice" });

    const notifA = collectNotifications(clientA);
    const notifB = collectNotifications(clientB);

    // Trigger session_state_changed via internal event (create session node)
    await clientA.send("__test_emit_session_event", {
      type: "created",
      sessionId: "sess-001",
      agentName: "alice",
      counterpartyPubkey: "deadbeef",
      sessionPeerId: "peer-123",
      correlationId: "corr-001",
    });
    await waitForNotifications();

    const sessionA = notifA.filter((n) => n.notification === "session_state_changed");
    const sessionB = notifB.filter((n) => n.notification === "session_state_changed");

    expect(sessionA).toHaveLength(1);
    expect(sessionB).toHaveLength(1);

    expect(sessionA[0].data).toEqual({
      agent: "alice",
      type: "session_state_changed",
      agentName: "alice",
      sessionId: "sess-001",
      state: "created",
      counterpartyPubkey: "deadbeef",
    });
    expect(sessionB[0].data).toEqual(sessionA[0].data);
  });

  // ─── AC-005: session_state_changed NOT sent to connection with different current agent ───
  it("AC-005: connection with bob as current does NOT receive alice session events", async () => {
    const config = await setupWithAgents("alice", "bob");
    handle = await startDaemon(config);

    const clientA = await connect(config.socketPath);
    const clientB = await connect(config.socketPath);

    await clientA.send("cello_start_agent", { name: "alice" });
    await clientA.send("cello_start_agent", { name: "bob" });
    await clientA.send("cello_use_agent", { name: "alice" });
    await clientB.send("cello_use_agent", { name: "bob" });

    const notifA = collectNotifications(clientA);
    const notifB = collectNotifications(clientB);

    // Emit session event for alice
    await clientA.send("__test_emit_session_event", {
      type: "created",
      sessionId: "sess-002",
      agentName: "alice",
      counterpartyPubkey: "cafe0001",
      sessionPeerId: "peer-456",
      correlationId: "corr-002",
    });
    await waitForNotifications();

    // Connection A (alice current) receives it
    const sessionA = notifA.filter((n) => n.notification === "session_state_changed");
    expect(sessionA).toHaveLength(1);

    // Connection B (bob current) does NOT receive it
    const sessionB = notifB.filter((n) => n.notification === "session_state_changed");
    expect(sessionB).toHaveLength(0);
  });

  // ─── AC-006: session seal produces session_state_changed with state 'sealed' ───
  it("AC-006: session seal produces session_state_changed with state 'sealed'", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);

    const clientA = await connect(config.socketPath);
    const clientB = await connect(config.socketPath);

    await clientA.send("cello_start_agent", { name: "alice" });
    await clientA.send("cello_use_agent", { name: "alice" });
    await clientB.send("cello_use_agent", { name: "alice" });

    const notifA = collectNotifications(clientA);
    const notifB = collectNotifications(clientB);

    await clientA.send("__test_emit_session_event", {
      type: "destroyed",
      sessionId: "sess-003",
      agentName: "alice",
      counterpartyPubkey: "beef0001",
      state: "sealed",
      reason: "sealed",
    });
    await waitForNotifications();

    const sessionA = notifA.filter((n) => n.notification === "session_state_changed");
    const sessionB = notifB.filter((n) => n.notification === "session_state_changed");

    expect(sessionA).toHaveLength(1);
    expect(sessionB).toHaveLength(1);

    expect(sessionA[0].data).toEqual({
      agent: "alice",
      type: "session_state_changed",
      agentName: "alice",
      sessionId: "sess-003",
      state: "sealed",
      counterpartyPubkey: "beef0001",
    });
  });

  // ─── AC-007: session interrupt produces session_state_changed with state 'interrupted' ───
  it("AC-007: session interrupt produces session_state_changed with state 'interrupted'", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);

    const clientA = await connect(config.socketPath);
    const clientB = await connect(config.socketPath);

    await clientA.send("cello_start_agent", { name: "alice" });
    await clientA.send("cello_use_agent", { name: "alice" });
    await clientB.send("cello_use_agent", { name: "alice" });

    const notifA = collectNotifications(clientA);
    const notifB = collectNotifications(clientB);

    await clientA.send("__test_emit_session_event", {
      type: "destroyed",
      sessionId: "sess-004",
      agentName: "alice",
      counterpartyPubkey: "cafe0002",
      state: "interrupted",
      reason: "interrupted",
    });
    await waitForNotifications();

    const sessionA = notifA.filter((n) => n.notification === "session_state_changed");
    const sessionB = notifB.filter((n) => n.notification === "session_state_changed");

    expect(sessionA).toHaveLength(1);
    expect(sessionB).toHaveLength(1);

    expect(sessionA[0].data).toEqual({
      agent: "alice",
      type: "session_state_changed",
      agentName: "alice",
      sessionId: "sess-004",
      state: "interrupted",
      counterpartyPubkey: "cafe0002",
    });
  });

  // ─── AC-008: All notifications include agent field (all three types) ───
  it("AC-008: all three notification types include the agent field", async () => {
    const config = await setupWithAgents("alice", "bob");
    handle = await startDaemon(config);

    const clientA = await connect(config.socketPath);
    const notifA = collectNotifications(clientA);

    // 1. agent_state_changed — start alice
    await clientA.send("cello_start_agent", { name: "alice" });
    await clientA.send("cello_start_agent", { name: "bob" });
    await waitForNotifications();

    // 2. agent_current_changed — use alice (first use: fromAgent=null, toAgent=alice)
    await clientA.send("cello_use_agent", { name: "bob" });
    await waitForNotifications();

    // 3. session_state_changed — emit session event for bob
    await clientA.send("__test_emit_session_event", {
      type: "created",
      sessionId: "sess-ac008",
      agentName: "bob",
      counterpartyPubkey: "cdef1234",
    });
    await waitForNotifications();

    // Verify agent field on agent_state_changed
    const stateNotifs = notifA.filter((n) => n.notification === "agent_state_changed");
    expect(stateNotifs.length).toBeGreaterThanOrEqual(1);
    for (const n of stateNotifs) {
      expect(n.data!.agent).toBeDefined();
      expect(typeof n.data!.agent).toBe("string");
    }

    // Verify agent field on agent_current_changed
    const currentNotifs = notifA.filter((n) => n.notification === "agent_current_changed");
    expect(currentNotifs.length).toBeGreaterThanOrEqual(1);
    for (const n of currentNotifs) {
      expect(n.data!.agent).toBeDefined();
      expect(typeof n.data!.agent).toBe("string");
    }

    // Verify agent field on session_state_changed
    const sessionNotifs = notifA.filter((n) => n.notification === "session_state_changed");
    expect(sessionNotifs.length).toBeGreaterThanOrEqual(1);
    for (const n of sessionNotifs) {
      expect(n.data!.agent).toBeDefined();
      expect(typeof n.data!.agent).toBe("string");
    }
  });

  // ─── AC-009: Connections without current agent still receive agent_state_changed ───
  it("AC-009: connection with no current agent still receives agent_state_changed", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);

    const clientA = await connect(config.socketPath);
    const clientB = await connect(config.socketPath);

    // clientB has no current agent set
    const notifB = collectNotifications(clientB);

    await clientA.send("cello_start_agent", { name: "alice" });
    await waitForNotifications();

    const stateB = notifB.filter((n) => n.notification === "agent_state_changed");
    expect(stateB).toHaveLength(1);
    expect(stateB[0].data).toEqual({
      agent: "alice",
      type: "agent_state_changed",
      agentName: "alice",
      state: "online",
      reason: "started",
    });
  });

  // ─── AC-010: Disconnected connections do not receive notifications ───
  it("AC-010: disconnected connection does not receive notifications", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);

    const clientA = await connect(config.socketPath);
    const clientB = await connect(config.socketPath);

    const notifB = collectNotifications(clientB);

    // Disconnect B
    clientB.close();
    await waitForNotifications(150); // Allow disconnect to propagate

    // Now trigger an agent start
    await clientA.send("cello_start_agent", { name: "alice" });
    await waitForNotifications();

    // B did not receive anything after disconnect
    const stateB = notifB.filter((n) => n.notification === "agent_state_changed");
    expect(stateB).toHaveLength(0);

    // No error in daemon — it continues broadcasting to remaining connections
    const errorEvents = logEvents.filter((e) => e.level === "error");
    expect(errorEvents).toHaveLength(0);
  });

  // ─── AC-011: Logger events fire with correct fields ───
  it("AC-011: agent.online logged with agentName and agentPubkey", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    await client.send("cello_start_agent", { name: "alice" });

    const onlineEvent = logEvents.find((e) => e.event === "agent.online");
    expect(onlineEvent).toBeDefined();
    expect(onlineEvent!.context.agentName).toBe("alice");
    expect(onlineEvent!.context.agentPubkey).toBeDefined();
    expect(typeof onlineEvent!.context.agentPubkey).toBe("string");
  });

  it("AC-011: agent.offline logged with agentName and reason", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    await client.send("cello_start_agent", { name: "alice" });
    await client.send("cello_stop_agent", { name: "alice" });

    const offlineEvent = logEvents.find((e) => e.event === "agent.offline");
    expect(offlineEvent).toBeDefined();
    expect(offlineEvent!.context.agentName).toBe("alice");
    expect(offlineEvent!.context.reason).toBe("stopped");
  });

  it("AC-011: agent.current.switched logged with connectionId, fromAgent, toAgent", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    await client.send("cello_start_agent", { name: "alice" });
    await client.send("cello_use_agent", { name: "alice" });

    const switchEvent = logEvents.find((e) => e.event === "agent.current.switched");
    expect(switchEvent).toBeDefined();
    expect(switchEvent!.context.connectionId).toBeDefined();
    expect(switchEvent!.context.fromAgent).toBeNull();
    expect(switchEvent!.context.toAgent).toBe("alice");
  });

  it("AC-011: session.node.created logged with correct fields on test event", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    await client.send("cello_start_agent", { name: "alice" });
    await client.send("cello_use_agent", { name: "alice" });

    // Clear previous log events (standing receiver etc)
    const idxBefore = logEvents.length;

    await client.send("__test_emit_session_event", {
      type: "created",
      sessionId: "sess-log-001",
      agentName: "alice",
      counterpartyPubkey: "abcd",
      sessionPeerId: "peer-log-001",
      correlationId: "corr-log-001",
    });

    const createdEvents = logEvents.slice(idxBefore).filter((e) => e.event === "session.node.created");
    expect(createdEvents).toHaveLength(1);
    expect(createdEvents[0].context.sessionId).toBe("sess-log-001");
    expect(createdEvents[0].context.agentName).toBe("alice");
    expect(createdEvents[0].context.sessionPeerId).toBe("peer-log-001");
    expect(createdEvents[0].context.correlationId).toBe("corr-log-001");
  });

  it("AC-011: session.node.destroyed logged with correct fields on test event", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    await client.send("cello_start_agent", { name: "alice" });
    await client.send("cello_use_agent", { name: "alice" });

    const idxBefore = logEvents.length;

    await client.send("__test_emit_session_event", {
      type: "destroyed",
      sessionId: "sess-log-002",
      agentName: "alice",
      counterpartyPubkey: "efgh",
      state: "sealed",
      reason: "sealed",
    });

    const destroyedEvents = logEvents.slice(idxBefore).filter((e) => e.event === "session.node.destroyed");
    expect(destroyedEvents).toHaveLength(1);
    expect(destroyedEvents[0].context.sessionId).toBe("sess-log-002");
    expect(destroyedEvents[0].context.agentName).toBe("alice");
    expect(destroyedEvents[0].context.reason).toBe("sealed");
  });

  // ─── AC-012: Composition root wiring — real daemon integration ───
  it("AC-012: notification arrives via real IPC when agent state changes", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);

    const client = await connect(config.socketPath);
    const notifs = collectNotifications(client);

    // Trigger a real state change
    await client.send("cello_start_agent", { name: "alice" });
    await waitForNotifications();

    // Verify notification arrived via IPC (not just logged)
    const stateNotifs = notifs.filter((n) => n.notification === "agent_state_changed");
    expect(stateNotifs).toHaveLength(1);
    expect(stateNotifs[0].data!.agent).toBe("alice");
    expect(stateNotifs[0].data!.state).toBe("online");
  });

  // ─── SI-001: session_state_changed never leaks across agent boundaries ───
  it("SI-001: session events for agent A never reach connection with agent B as current", async () => {
    const config = await setupWithAgents("alice", "bob");
    handle = await startDaemon(config);

    const clientX = await connect(config.socketPath); // agent A current
    const clientY = await connect(config.socketPath); // agent B current

    await clientX.send("cello_start_agent", { name: "alice" });
    await clientX.send("cello_start_agent", { name: "bob" });
    await clientX.send("cello_use_agent", { name: "alice" });
    await clientY.send("cello_use_agent", { name: "bob" });

    const notifY = collectNotifications(clientY);

    // Emit session event for alice
    await clientX.send("__test_emit_session_event", {
      type: "created",
      sessionId: "sess-si-001",
      agentName: "alice",
      counterpartyPubkey: "si001pub",
      sessionPeerId: "peer-si-001",
      correlationId: "corr-si-001",
    });
    await waitForNotifications(200);

    // Connection Y (bob current) MUST NOT have any session_state_changed for alice
    const leakedSessionNotifs = notifY.filter(
      (n) => n.notification === "session_state_changed" && n.data?.agentName === "alice"
    );
    expect(leakedSessionNotifs).toHaveLength(0);
  });

  // ─── notification.dispatch.failed logged at DEBUG when sendNotification fails ───
  it("notification.dispatch.failed logged when sendNotification throws", () => {
    // Unit test of NotificationDispatcher directly — no daemon, no real socket.
    // This guarantees the catch path is exercised unconditionally.

    const unitLogEvents: Array<{ level: string; event: string; context: Record<string, unknown> }> = [];
    const unitLogger: Logger = {
      debug(event, context) { unitLogEvents.push({ level: "debug", event, context }); },
      info(event, context) { unitLogEvents.push({ level: "info", event, context }); },
      warn(event, context) { unitLogEvents.push({ level: "warn", event, context }); },
      error(event, context) { unitLogEvents.push({ level: "error", event, context }); },
    };

    const throwingSender = (_connId: string, _notif: IpcNotification): boolean => {
      throw new Error("EPIPE: broken pipe");
    };

    const dispatcher = new NotificationDispatcher({
      logger: unitLogger,
      sendNotification: throwingSender,
      getConnectionIds: () => ["conn-1"],
    });

    dispatcher.registerConnection("conn-1");
    dispatcher.dispatchAgentStateChanged("alice", "online", "started");

    const dispatchFailed = unitLogEvents.filter((e) => e.event === "notification.dispatch.failed");
    expect(dispatchFailed).toHaveLength(1);
    expect(dispatchFailed[0].level).toBe("debug");
    expect(dispatchFailed[0].context.connectionId).toBe("conn-1");
    expect(dispatchFailed[0].context.notificationType).toBe("agent_state_changed");
    expect(dispatchFailed[0].context.error).toBe("EPIPE: broken pipe");
  });

  // ─── SI-002: No key material in notification payloads ───
  it("SI-002: notification construction sites do not reference prohibited key fields", async () => {
    const { readFileSync, readdirSync, statSync } = await import("node:fs");
    const { join: pathJoin } = await import("node:path");

    const prohibitedFields = /privateKey|signingShare|localShare|secretKey|identityKey/;

    function scanDir(dir: string): string[] {
      const violations: string[] = [];
      for (const entry of readdirSync(dir)) {
        const full = pathJoin(dir, entry);
        if (statSync(full).isDirectory()) {
          if (entry === "node_modules" || entry === "__tests__" || entry === "dist") continue;
          violations.push(...scanDir(full));
        } else if (entry.endsWith(".ts") && !entry.endsWith(".test.ts")) {
          const content = readFileSync(full, "utf-8");
          const lines = content.split("\n");
          for (let i = 0; i < lines.length; i++) {
            if (lines[i].includes("notification") && prohibitedFields.test(lines[i])) {
              violations.push(`${full}:${i + 1}: ${lines[i].trim()}`);
            }
          }
        }
      }
      return violations;
    }

    const daemonSrc = pathJoin(__dirname, "..");
    const adapterSrc = pathJoin(__dirname, "..", "..", "..", "adapter-claude-code", "src");

    const violations = [...scanDir(daemonSrc), ...scanDir(adapterSrc)];
    expect(violations).toEqual([]);
  });

  it("notification.dispatch.failed logged when sendNotification returns false", () => {

    const unitLogEvents: Array<{ level: string; event: string; context: Record<string, unknown> }> = [];
    const unitLogger: Logger = {
      debug(event, context) { unitLogEvents.push({ level: "debug", event, context }); },
      info(event, context) { unitLogEvents.push({ level: "info", event, context }); },
      warn(event, context) { unitLogEvents.push({ level: "warn", event, context }); },
      error(event, context) { unitLogEvents.push({ level: "error", event, context }); },
    };

    const falseSender = (_connId: string, _notif: IpcNotification): boolean => false;

    const dispatcher = new NotificationDispatcher({
      logger: unitLogger,
      sendNotification: falseSender,
      getConnectionIds: () => ["conn-1"],
    });

    dispatcher.registerConnection("conn-1");
    dispatcher.dispatchAgentStateChanged("alice", "online", "started");

    const dispatchFailed = unitLogEvents.filter((e) => e.event === "notification.dispatch.failed");
    expect(dispatchFailed).toHaveLength(1);
    expect(dispatchFailed[0].level).toBe("debug");
    expect(dispatchFailed[0].context.error).toBe("sendNotification returned false");
  });
});
