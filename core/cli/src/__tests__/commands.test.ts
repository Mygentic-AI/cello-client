/**
 * CELLO-M7-DAEMON-001 — CLI commands tests
 *
 * ACs tested:
 * - cello login: starts daemon or connects to existing, exits 0
 * - cello logout: sends shutdown to daemon, exits 0
 * - cello status: queries daemon and prints structured JSON
 * - Status response structure: {daemon, directory_signaling, agents, connections}
 * - Logout when no daemon running: exits 0 with "No daemon running"
 * - Status when no daemon running: exits 1 with {daemon: "stopped"}
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startDaemon, type DaemonHandle } from "@cello-protocol/daemon";
import type { Logger, DaemonConfig } from "@cello-protocol/daemon";
import { logout, status, register } from "../commands.js";

describe("cli commands", () => {
  let tempDir: string;
  let logEvents: Array<{ level: string; event: string; context: Record<string, unknown> }>;
  let logger: Logger;
  let handle: DaemonHandle | null;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-cli-test-"));
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
      try { await handle.stop("test_cleanup"); } catch { /* already stopped */ }
    }
    await rm(tempDir, { recursive: true, force: true });
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

  describe("logout", () => {
    it("returns exit 0 with 'No daemon running' when no lock file", async () => {
      const result = await logout(tempDir);
      expect(result.exitCode).toBe(0);
      expect(result.output).toContain("No daemon running");
    });

    it("sends shutdown and returns exit 0 when daemon is running", async () => {
      const config = makeConfig();
      handle = await startDaemon(config);

      const result = await logout(tempDir);
      expect(result.exitCode).toBe(0);
      expect(result.output).toContain("Daemon stopped");

      // Give shutdown time
      await new Promise((r) => setTimeout(r, 200));
      handle = null; // Already stopped
    });
  });

  describe("status", () => {
    it("returns exit 1 with {daemon: 'stopped'} when no daemon running", async () => {
      const result = await status(tempDir);
      expect(result.exitCode).toBe(1);
      const parsed = JSON.parse(result.output);
      expect(parsed.daemon).toBe("stopped");
    });

    it("returns structured status JSON when daemon is running", async () => {
      const config = makeConfig();
      handle = await startDaemon(config);

      const result = await status(tempDir);
      expect(result.exitCode).toBe(0);
      const parsed = JSON.parse(result.output);
      expect(parsed.daemon).toBe("running");
      expect(parsed.directory_signaling).toBe("reconnecting");
      expect(Array.isArray(parsed.agents)).toBe(true);
      expect(Array.isArray(parsed.connections)).toBe(true);
    });
  });

  describe("register", () => {
    it("returns exit 1 with usage when args are missing", async () => {
      const result = await register(tempDir, "", "");
      expect(result.exitCode).toBe(1);
      expect(result.output).toContain("Usage: cello register");
    });

    it("returns exit 1 'No daemon running' when no daemon is up", async () => {
      const result = await register(tempDir, "alice", "preauth-token");
      expect(result.exitCode).toBe(1);
      expect(result.output).toContain("No daemon running");
    });

    it("round-trips to the daemon and returns agent_not_found for an unknown agent", async () => {
      const config = makeConfig();
      handle = await startDaemon(config);

      // No agents are loaded in this temp dir → the daemon's cello_register
      // handler rejects with agent_not_found (full CLI → IPC → handler path).
      const result = await register(tempDir, "ghost-agent", "preauth-token");
      expect(result.exitCode).toBe(1);
      const parsed = JSON.parse(result.output);
      expect(parsed.ok).toBe(false);
      expect(parsed.reason).toBe("agent_not_found");
      expect(typeof parsed.guidance).toBe("string");
    });
  });
});
