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
import { startDaemon, acquireLock, type DaemonHandle } from "@cello-protocol/daemon";
import type { Logger, DaemonConfig } from "@cello-protocol/daemon";
import { createServer, type Server } from "node:net";
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
    // A well-formed pre-auth token ("CELLO-" + 33 base58 chars) so the client-side format checks
    // pass and the call reaches the daemon path (M8C-ONBOARD-ERRORS-1).
    const VALID_TOKEN = "CELLO-" + "1".repeat(33);

    it("returns exit 1 with usage when the agent is missing", async () => {
      const result = await register(tempDir, "", "");
      expect(result.exitCode).toBe(1);
      expect(result.output).toContain("Usage: cello register");
    });

    // M8C-ONBOARD-ERRORS-1 (R3): a missing token gets a specific, actionable message — NOT a bare
    // Usage dump — that names what's missing and how to get it.
    it("returns a specific missing-token message (not a Usage dump)", async () => {
      const result = await register(tempDir, "alice", "");
      expect(result.exitCode).toBe(1);
      expect(result.output).toContain("missing the pre-auth token");
      expect(result.output).toContain("CELLO_PREAUTH_TOKEN");
    });

    // M8C-ONBOARD-ERRORS-1 (R4): a malformed token is caught client-side with a specific message,
    // BEFORE any pointless DKG round-trip to a generic dkg_failed. The classic case: pasting the
    // literal words "CELLO_PREAUTH_TOKEN" (underscore) instead of a real "CELLO-" token.
    it("catches a malformed token client-side (CELLO_PREAUTH_TOKEN typo) with a specific message", async () => {
      const result = await register(tempDir, "alice", "CELLO_PREAUTH_TOKEN");
      expect(result.exitCode).toBe(1);
      expect(result.output).toContain("start with 'CELLO-'");
      expect(result.output).not.toContain("No daemon running"); // short-circuited before the daemon
    });

    // A CELLO- token of the wrong length passes the client-side prefix gate (D13: the client checks
    // only the stable brand prefix; the directory is the authority on the full format) and reaches
    // the daemon — here there's no daemon, so it surfaces "No daemon running", not a client "malformed".
    it("lets a wrong-length CELLO- token through the client gate to the daemon", async () => {
      const result = await register(tempDir, "alice", "CELLO-tooshort");
      expect(result.exitCode).toBe(1);
      expect(result.output).toContain("No daemon running");
    });

    it("returns exit 1 'No daemon running' when no daemon is up (well-formed token)", async () => {
      const result = await register(tempDir, "alice", VALID_TOKEN);
      expect(result.exitCode).toBe(1);
      expect(result.output).toContain("No daemon running");
    });

    it("round-trips to the daemon and returns agent_not_found for an unknown agent", async () => {
      const config = makeConfig();
      handle = await startDaemon(config);

      // No agents are loaded in this temp dir → the daemon's cello_register
      // handler rejects with agent_not_found (full CLI → IPC → handler path).
      const result = await register(tempDir, "ghost-agent", VALID_TOKEN);
      expect(result.exitCode).toBe(1);
      const parsed = JSON.parse(result.output);
      expect(parsed.ok).toBe(false);
      expect(parsed.reason).toBe("agent_not_found");
      expect(typeof parsed.guidance).toBe("string");
    });

    // M8C-ONBOARD-NEXTSTEP-1 (reviewer F1): on SUCCESS the output carries next-step + state
    // legibility. A fake daemon returns ok so the success branch is exercised (a real register
    // needs the directory's DKG). Guards against a regression that drops the guidance.
    it("appends next-step + state-legibility guidance on a successful registration", async () => {
      const socketPath = join(tempDir, "fake-daemon.sock");
      const server: Server = createServer((socket) => {
        socket.on("data", (chunk: Buffer) => {
          const line = chunk.toString("utf-8").trim();
          if (!line) return;
          const req = JSON.parse(line) as { id: string | number; method: string };
          if (req.method === "cello_register") {
            socket.write(JSON.stringify({ id: req.id, result: { ok: true, agent_id: "id-1", primary_pubkey: "pk-1" } }) + "\n");
          }
        });
      });
      await new Promise<void>((resolve) => server.listen(socketPath, resolve));
      await acquireLock(join(tempDir, "daemon.lock"), { pid: process.pid, socketPath, version: "0.0.1-test" });

      try {
        const result = await register(tempDir, "alice", VALID_TOKEN);
        expect(result.exitCode).toBe(0);
        expect(result.output).toContain("cello status");     // next step
        expect(result.output).toContain("connecting");        // state legibility
        expect(result.output).toContain("connected");
        expect(result.output).toContain("cello login");       // recovery hint
      } finally {
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    });
  });
});
