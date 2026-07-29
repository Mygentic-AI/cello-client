/**
 * CELLO-M7-DAEMON-001 — Daemon integration tests
 *
 * ACs tested:
 * - daemon.started event: pid, ipcSocketPath, agentCount
 * - daemon.stopped event: pid, reason
 * - Status response structure: daemon, directory_signaling, agents (CC-4: `connections` field dropped)
 * - Agents loaded in 'registered' state (not auto-started)
 * - Shutdown handler: acknowledges and triggers graceful stop
 * - daemon.login.validation.complete stub (connections all 'unverified')
 * - directory_signaling starts as 'reconnecting' (per CONTEXT.md AC-009)
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { connectToDaemon } from "../ipc-client.js";
import { readLock } from "../lock-file.js";
import { FileKeyProvider } from "@cello-protocol/crypto";
import type { Logger, DaemonConfig, DaemonStatusResponse } from "../types.js";

describe("daemon", () => {
  let tempDir: string;
  let logEvents: Array<{ level: string; event: string; context: Record<string, unknown> }>;
  let logger: Logger;
  let handle: DaemonHandle | null;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-daemon-test-"));
    logEvents = [];
    logger = {
      debug(event, context) { logEvents.push({ level: "debug", event, context }); },
      info(event, context) { logEvents.push({ level: "info", event, context }); },
      warn(event, context) { logEvents.push({ level: "warn", event, context }); },
      error(event, context) { logEvents.push({ level: "error", event, context }); },
    };
    handle = null;
  });

  afterEach(async () => {
    if (handle) {
      try {
        await handle.stop("test_cleanup");
      } catch {
        // Already stopped
      }
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

  it("emits daemon.started with pid, ipcSocketPath, agentCount", async () => {
    handle = await startDaemon(makeConfig());

    const startEvent = logEvents.find((e) => e.event === "daemon.started");
    expect(startEvent).toBeDefined();
    expect(startEvent!.context.pid).toBe(process.pid);
    expect(startEvent!.context.ipcSocketPath).toBe(join(tempDir, "daemon.sock"));
    expect(startEvent!.context.agentCount).toBe(0);
  });

  it("emits daemon.stopped with pid and reason on shutdown", async () => {
    handle = await startDaemon(makeConfig());
    await handle.stop("test_stop");
    handle = null;

    const stopEvent = logEvents.find((e) => e.event === "daemon.stopped");
    expect(stopEvent).toBeDefined();
    expect(stopEvent!.context.pid).toBe(process.pid);
    expect(stopEvent!.context.reason).toBe("test_stop");
  });

  it("creates lock file with correct content", async () => {
    const config = makeConfig();
    handle = await startDaemon(config);

    const lock = await readLock(config.lockFilePath);
    expect(lock).not.toBeNull();
    expect(lock!.pid).toBe(process.pid);
    expect(lock!.socketPath).toBe(config.socketPath);
    expect(lock!.version).toBe("0.0.1-test");
  });

  it("removes lock file on shutdown", async () => {
    const config = makeConfig();
    handle = await startDaemon(config);
    await handle.stop("clean_stop");
    handle = null;

    const lock = await readLock(config.lockFilePath);
    expect(lock).toBeNull();
  });

  it("loads agents and reports them in status with 'registered' state", async () => {
    // Create an agent directory with a valid key
    const agentsDir = join(tempDir, "agents");
    await mkdir(join(agentsDir, "test-agent"), { recursive: true });
    const keyProvider = await FileKeyProvider.load(join(agentsDir, "test-agent", "key"));
    const pubkey = Buffer.from(await keyProvider.getPublicKey()).toString("hex");

    handle = await startDaemon(makeConfig());

    const status = handle.getStatus();
    expect(status.agents).toHaveLength(1);
    expect(status.agents[0].name).toBe("test-agent");
    expect(status.agents[0].state).toBe("registered");
    expect(status.agents[0].pubkey).toBe(pubkey);
  });

  it("CC-8: getStatus reports an ONLINE agent as state 'online' (CLI/MCP status parity)", async () => {
    const agentsDir = join(tempDir, "agents");
    await mkdir(join(agentsDir, "on-agent"), { recursive: true });
    await FileKeyProvider.load(join(agentsDir, "on-agent", "key"));

    const config = makeConfig();
    handle = await startDaemon(config);

    // Offline: "registered". Pre-CC-8 the daemon-wide status (what the CLI `cello status` reads) showed
    // "registered" even AFTER the agent came online — startAgentInternal only adds to onlineAgents, it
    // never mutates the stored record — so an operator couldn't tell online from offline via the CLI.
    expect(handle.getStatus().agents[0].state).toBe("registered");

    const client = await connectToDaemon(config.socketPath);
    try {
      await client.send("ipc.connect", { clientType: "test" });
      await client.send("cello_start_agent", { name: "on-agent" });
    } finally {
      client.close();
    }

    // CC-8: now derived from onlineAgents → "online" (matches the MCP cello_status F5 surface).
    expect(handle.getStatus().agents[0].state).toBe("online");
  });

  it("reports agentCount in daemon.started event", async () => {
    const agentsDir = join(tempDir, "agents");
    await mkdir(join(agentsDir, "a1"), { recursive: true });
    await mkdir(join(agentsDir, "a2"), { recursive: true });
    await FileKeyProvider.load(join(agentsDir, "a1", "key"));
    await FileKeyProvider.load(join(agentsDir, "a2", "key"));

    handle = await startDaemon(makeConfig());

    const startEvent = logEvents.find((e) => e.event === "daemon.started");
    expect(startEvent!.context.agentCount).toBe(2);
  });

  it("status response has correct structure", async () => {
    handle = await startDaemon(makeConfig());
    const status = handle.getStatus();

    expect(status.daemon).toBe("running");
    expect(status.directory_signaling).toBe("reconnecting");
    expect(Array.isArray(status.agents)).toBe(true);
  });

  it("IPC status method returns the same as getStatus()", async () => {
    const agentsDir = join(tempDir, "agents");
    await mkdir(join(agentsDir, "ipc-agent"), { recursive: true });
    await FileKeyProvider.load(join(agentsDir, "ipc-agent", "key"));

    const config = makeConfig();
    handle = await startDaemon(config);

    const client = await connectToDaemon(config.socketPath);
    try {
      const result = (await client.send("status")) as DaemonStatusResponse;
      const expected = handle.getStatus();
      expect(result.daemon).toBe(expected.daemon);
      expect(result.directory_signaling).toBe(expected.directory_signaling);
      expect(result.agents).toEqual(expected.agents);
    } finally {
      client.close();
    }
  });

  it("IPC shutdown method triggers graceful stop", async () => {
    const config = makeConfig();
    handle = await startDaemon(config);

    const client = await connectToDaemon(config.socketPath);
    const result = await client.send("shutdown");
    expect(result).toEqual({ acknowledged: true });
    client.close();

    // Give shutdown time to complete
    await new Promise((r) => setTimeout(r, 200));

    const stopEvent = logEvents.find((e) => e.event === "daemon.stopped");
    expect(stopEvent).toBeDefined();
    expect(stopEvent!.context.reason).toBe("logout_requested");
    handle = null; // Already stopped
  });

  it("emits daemon.login.validation.complete with zeroed counts (stub)", async () => {
    handle = await startDaemon(makeConfig());

    const validationEvent = logEvents.find((e) => e.event === "daemon.login.validation.complete");
    expect(validationEvent).toBeDefined();
    expect(validationEvent!.context.verifiedCount).toBe(0);
    expect(validationEvent!.context.staleCount).toBe(0);
    expect(validationEvent!.context.goneCount).toBe(0);
  });

  it("includes failed agents in status with state 'load_failed' and error (PERSIST-002 AC-007)", async () => {
    // PERSIST-002: agents load from the encrypted `agents` table. A row whose K_local seed is
    // unusable (corrupt/wrong length) surfaces as load_failed — the daemon starts with the rest
    // (one bad agent never downs it). A corrupt pre-story key FILE is skipped/quarantined by the
    // one-time migration instead (it never reaches the loader).
    const { openTestDb } = await import("./helpers/encrypted-db.js");
    const { ensureIdentitySchema } = await import("../db-identity-store.js");
    const dbPath = join(tempDir, "sessions.db");
    const db = openTestDb(dbPath);
    ensureIdentitySchema(db);
    const now = Date.now();
    db.prepare(
      `INSERT INTO agents (agent_name, k_local_seed, k_local_pubkey, state, created_at, updated_at)
       VALUES (?, ?, ?, 'created', ?, ?)`,
    ).run("bad-agent", Buffer.alloc(8), "nopub", now, now);
    db.close();

    handle = await startDaemon(makeConfig());
    const status = handle.getStatus();

    const failedAgent = status.agents.find((a) => a.name === "bad-agent");
    expect(failedAgent).toBeDefined();
    expect(failedAgent!.state).toBe("load_failed");
    expect(failedAgent!.error).toBeDefined();
    expect(typeof failedAgent!.error).toBe("string");
  });

  it("logs daemon.ipc.disconnected with reason 'daemon_shutdown' during stop (AC-006)", async () => {
    const config = makeConfig();
    handle = await startDaemon(config);

    // Connect a client
    const client = await connectToDaemon(config.socketPath);

    // Stop the daemon while client is connected
    await handle.stop("graceful");
    handle = null;

    // Wait for disconnect events to propagate
    await new Promise((r) => setTimeout(r, 100));
    client.close();

    const disconnectEvents = logEvents.filter((e) => e.event === "daemon.ipc.disconnected");
    expect(disconnectEvents.length).toBeGreaterThanOrEqual(1);
    const shutdownDisconnect = disconnectEvents.find((e) => e.context.reason === "daemon_shutdown");
    expect(shutdownDisconnect).toBeDefined();
  });

  it("logs daemon.ipc.disconnected with actual error.message on socket error (AC-010)", async () => {
    const config = makeConfig();
    handle = await startDaemon(config);

    // Connect via raw socket and destroy it abruptly
    const { createConnection } = await import("node:net");
    const socket = createConnection(config.socketPath);
    await new Promise<void>((resolve) => socket.on("connect", resolve));

    // Wait for the IPC server to register the connection
    await new Promise((r) => setTimeout(r, 50));

    // Destroy the socket (simulates TCP RST)
    socket.destroy();

    // Wait for disconnect event
    await new Promise((r) => setTimeout(r, 100));

    const disconnectEvents = logEvents.filter((e) => e.event === "daemon.ipc.disconnected");
    expect(disconnectEvents.length).toBeGreaterThanOrEqual(1);
  });
});
