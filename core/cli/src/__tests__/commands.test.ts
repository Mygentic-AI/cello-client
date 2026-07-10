/**
 * CELLO-M7-DAEMON-001 — CLI commands tests
 *
 * ACs tested:
 * - cello login: starts daemon or connects to existing, exits 0
 * - cello logout: sends shutdown to daemon, exits 0
 * - cello status: queries daemon and prints structured JSON
 * - Status response structure: {daemon, directory_signaling, agents} (CC-4: `connections` dropped)
 * - Logout when no daemon running: exits 0 with "No daemon running"
 * - Status when no daemon running: exits 1 with {daemon: "stopped"}
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startDaemon, acquireLock, readLock, connectToDaemon, type DaemonHandle } from "@cello-protocol/daemon";
import type { Logger, DaemonConfig } from "@cello-protocol/daemon";
import { createServer, type Server } from "node:net";
import { login, logout, status, register, createAgent, monikerSet } from "../commands.js";

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

    // ─── DOD-LOGOUT-WAIT-1 ─────────────────────────────────────────────────────────────────
    // `cello logout && cello login` printed "Daemon already running." and left the operator
    // logged OUT: logout returned the instant the shutdown request was WRITTEN, while the
    // daemon was still dying — connectOrStart then saw a live pid + connectable socket and
    // reported alreadyRunning. "Daemon stopped." for a daemon that is still running is the
    // SENDRAW-1 lie at the CLI surface. logout must not return success until the daemon is
    // actually gone.
    describe("DOD-LOGOUT-WAIT-1: logout waits for actual daemon death", () => {
      it("AC1: on return, the socket refuses connections and the lock file is gone — no grace delay", async () => {
        const config = makeConfig();
        handle = await startDaemon(config);

        const result = await logout(tempDir);
        expect(result.exitCode).toBe(0);
        expect(result.output).toContain("Daemon stopped");
        handle = null;

        // IMMEDIATELY on return — the exact inputs connectOrStart consults:
        await expect(readLock(config.lockFilePath)).resolves.toBeNull();
        await expect(connectToDaemon(config.socketPath)).rejects.toThrow();
      });

      it("AC2 (Andre's live transcript): logout;login against a REAL spawned daemon yields 'Daemon started.' — never 'Daemon already running.'", async () => {
        // An in-process daemon dies too fast to reproduce the race — the live bug needs a
        // separate PROCESS that takes real time to shut down, exactly as production. So: spawn
        // the real built daemon via login, then logout && login with no delay.
        const daemonBin = join(import.meta.dirname, "../../../daemon/dist/bin/cello-daemon.js");
        const first = await login(tempDir, daemonBin, logger);
        expect(first.exitCode).toBe(0);
        expect(first.output.startsWith("Daemon started.")).toBe(true);

        try {
          const outLogout = await logout(tempDir);
          expect(outLogout.exitCode).toBe(0);
          expect(outLogout.output).toContain("Daemon stopped");

          // No delay — the exact `cello logout && cello login` shape.
          const res = await login(tempDir, daemonBin, logger);
          expect(res.exitCode).toBe(0);
          expect(res.output.startsWith("Daemon started.")).toBe(true);
          expect(res.output).not.toContain("already running");
        } finally {
          // logout now WAITS for death, so this reliably reaps the spawned daemon.
          await logout(tempDir);
        }
      }, 45_000);

      it("emits an immediate 'Shutting down' progress line so the operator knows the command activated", async () => {
        const config = makeConfig();
        handle = await startDaemon(config);

        const progress: string[] = [];
        const result = await logout(tempDir, (line) => progress.push(line));
        expect(progress.some((l) => /shutting down/i.test(l))).toBe(true);
        expect(result.output).toContain("Daemon stopped");
        handle = null;
      });

      it("a stale lock (dead pid) → 'No daemon running.' exit 0, and the stale lock is cleaned up", async () => {
        const config = makeConfig();
        // A pid that cannot be alive (beyond pid_max) + no listening socket.
        await acquireLock(config.lockFilePath, { pid: 999999999, socketPath: config.socketPath, version: "0.0.1-test" });

        const result = await logout(tempDir);
        expect(result.exitCode).toBe(0);
        expect(result.output).toContain("No daemon running");
        await expect(readLock(config.lockFilePath)).resolves.toBeNull();
      });
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
    });
  });

  // MONIKER-1 AC2/AC3: `cello moniker set|clear` round-trips to the daemon's cello_set_moniker.
  describe("moniker", () => {
    it("sets and clears the outbound-name override against a live daemon", async () => {
      const config = makeConfig();
      handle = await startDaemon(config);
      const create = await createAgent(tempDir, "alice");
      expect(create.exitCode).toBe(0);

      const set = await monikerSet(tempDir, "Wonderland_Alice", "alice");
      expect(set.exitCode).toBe(0);
      expect(JSON.parse(set.output)).toMatchObject({ ok: true, agent: "alice", moniker: "Wonderland_Alice" });

      const cleared = await monikerSet(tempDir, null, "alice");
      expect(cleared.exitCode).toBe(0);
      expect(JSON.parse(cleared.output)).toMatchObject({ ok: true, agent: "alice", moniker: null });
    });

    it("surfaces the daemon's invalid_moniker rejection verbatim", async () => {
      const config = makeConfig();
      handle = await startDaemon(config);
      await createAgent(tempDir, "alice");

      const bad = await monikerSet(tempDir, "not a valid name", "alice");
      expect(bad.exitCode).toBe(1);
      const parsed = JSON.parse(bad.output);
      expect(parsed.ok).toBe(false);
      expect(parsed.reason).toBe("invalid_moniker");
    });

    it("returns {daemon: stopped} when no daemon is running", async () => {
      const result = await monikerSet(tempDir, "Bob", "alice");
      expect(result.exitCode).toBe(1);
      expect(result.output).toContain("stopped");
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
        // CC-6 (reviewer-aligned copy): readiness is expressed via the REAL cello status output —
        // agent state 'online' + directory_signaling 'connected' (the old "connecting" wording never
        // appeared in that output).
        expect(result.output).toContain("online");            // state legibility (ready state)
        expect(result.output).toContain("connected");         // directory_signaling ready
        expect(result.output).toContain("cello login");       // recovery hint
      } finally {
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    });
  });
});
