/**
 * CELLO-M7-DAEMON-001 — Daemon integration tests
 *
 * ACs tested:
 * - daemon.started event: pid, ipcSocketPath, agentCount
 * - daemon.stopped event: pid, reason
 * - Status response structure: daemon, directory_signaling, agents, connections
 * - Agents loaded in 'registered' state (not auto-started)
 * - Shutdown handler: acknowledges and triggers graceful stop
 * - daemon.login.validation.complete stub (connections all 'unverified')
 * - directory_signaling starts as 'lost' (no signaling stream yet)
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
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
    expect(status.directory_signaling).toBe("lost");
    expect(Array.isArray(status.agents)).toBe(true);
    expect(Array.isArray(status.connections)).toBe(true);
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
      expect(result.connections).toEqual(expected.connections);
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

  it("connections are empty (no directory signaling yet)", async () => {
    handle = await startDaemon(makeConfig());
    const status = handle.getStatus();
    expect(status.connections).toEqual([]);
  });
});
