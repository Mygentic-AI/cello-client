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

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startDaemon, acquireLock, readLock, connectToDaemon, isProcessAlive, type DaemonHandle, PassthroughGatewayClient } from "@cello-protocol/daemon";
import type { Logger, DaemonConfig } from "@cello-protocol/daemon";
import { createServer, type Server } from "node:net";
import { login, logout, status, register, createAgent } from "../commands.js";
import { monikerSet, settingsGet, settingsSet, startAgent } from "../parity-commands.js";

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
      securityGateway: new PassthroughGatewayClient(),
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

        const started = Date.now();
        const result = await logout(tempDir);
        expect(result.exitCode).toBe(0);
        expect(result.output).toContain("Daemon stopped");
        handle = null;

        // IMMEDIATELY on return — the exact inputs connectOrStart consults:
        await expect(readLock(config.lockFilePath)).resolves.toBeNull();
        await expect(connectToDaemon(config.socketPath)).rejects.toThrow();
        // Anti-sleep pin (review): logout POLLS — it returns promptly once the daemon dies,
        // well inside the 5s bound. A flat sleep-to-deadline hollow fails this.
        expect(Date.now() - started).toBeLessThan(3_000);
      });

      it("AC2 (Andre's live transcript): logout;login against a REAL spawned daemon yields 'Daemon started.' — never 'Daemon already running.'", async () => {
        // An in-process daemon dies too fast to reproduce the race — the live bug needs a
        // separate PROCESS that takes real time to shut down, exactly as production. So: spawn
        // the real built daemon via login, then logout && login with no delay.
        const daemonBin = join(import.meta.dirname, "../../../daemon/dist/bin/cello-daemon.js");
        const first = await login(tempDir, daemonBin, logger);
        try {
          // Review F2: these asserts live INSIDE the try — a failure here must still reap the
          // spawned daemon via the finally-logout, or CI leaks a detached process.
          expect(first.exitCode).toBe(0);
          expect(first.output.startsWith("Daemon started.")).toBe(true);

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

      // DOD-SINGLE-DAEMON-1 (AC4) — the kill switch may not lie.
      //
      // logout used to open with `if (!lock) return "No daemon running."` — the ABSENCE of a JSON file
      // was taken as proof that no daemon exists. But an exiting orphan unlinks a healthy daemon's
      // lock (that is DOD-DAEMON-CLEANUP-1's entire subject), and so does `rm ~/.cello/daemon.lock`,
      // and so does any daemon still running the PRE-FIX binary — which is every daemon in the field
      // during the upgrade. In that state the operator runs `cello logout` to stop their agent, is
      // told it was never running, and walks away while it is still online, still on the directory,
      // and still extending the hash chain.
      //
      // A real spawned daemon, its lock file deleted out from under it. logout must still kill it.
      it("AC4: a live daemon whose daemon.lock was DELETED is still found and actually stopped", async () => {
        const daemonBin = join(import.meta.dirname, "../../../daemon/dist/bin/cello-daemon.js");
        const started = await login(tempDir, daemonBin, logger);
        expect(started.exitCode).toBe(0);

        const lockFilePath = join(tempDir, "daemon.lock");
        const live = await readLock(lockFilePath);
        expect(live).not.toBeNull();
        const daemonPid = live!.pid;
        expect(isProcessAlive(daemonPid)).toBe(true);

        // The cascade: something removed the lock while the daemon runs on, healthy and serving.
        await rm(lockFilePath);
        await expect(readLock(lockFilePath)).resolves.toBeNull();

        const result = await logout(tempDir);

        // It must NOT report "No daemon running" — and, more to the point, the process must be dead.
        expect(result.output).not.toContain("No daemon running");
        expect(result.exitCode).toBe(0);
        expect(result.output).toContain("Daemon stopped");

        // The assertion that actually matters: the kill switch killed something.
        await vi.waitFor(() => expect(isProcessAlive(daemonPid)).toBe(false), { timeout: 10_000 });
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
        expect(result.output).toContain("Removed a stale daemon.lock");
        await expect(readLock(config.lockFilePath)).resolves.toBeNull();
      });

      // DOD-SINGLE-DAEMON-1: the REUSED-pid case, which the dead-pid test above cannot reach.
      // After a crash the OS may hand the dead daemon's pid number to an unrelated process. The lock
      // then names a pid that IS alive, so `isProcessAlive` says "a daemon is running", the socket
      // does not answer, and logout used to return exit 1 "Failed to stop daemon" — forever, never
      // cleaning the lock up. The operator's only way out was deleting the file by hand.
      //
      // The pid here is the test runner's: real, alive, and emphatically not a daemon. Nothing holds
      // the singleton lock, and THAT is what settles it — not the pid, and not the file.
      it("a stale lock naming a REUSED (live, non-daemon) pid → 'No daemon running.' exit 0, lock cleaned up", async () => {
        const config = makeConfig();
        await acquireLock(config.lockFilePath, { pid: process.pid, socketPath: config.socketPath, version: "0.0.1-test" });

        const result = await logout(tempDir);
        expect(result.exitCode).toBe(0);
        expect(result.output).toContain("No daemon running");
        await expect(readLock(config.lockFilePath)).resolves.toBeNull();
      });

      // Review F1 (blocking): the FAIL-LOUD timeout branch was unguarded — an implementation
      // whose timeout printed "Daemon stopped." exit 0 (the exact lie this unit kills) passed
      // the suite. A fake daemon acknowledges the shutdown but never dies: live pid (ours),
      // lock never removed, socket stays up.
      it("timeout: a daemon that acknowledges but never dies → exit 1 naming pid + socket, NEVER 'Daemon stopped.'", async () => {
        const config = makeConfig();
        await acquireLock(config.lockFilePath, { pid: process.pid, socketPath: config.socketPath, version: "0.0.1-test" });
        const server: Server = createServer((socket) => {
          socket.on("data", (chunk: Buffer) => {
            const line = chunk.toString("utf-8").trim();
            if (!line) return;
            const req = JSON.parse(line) as { id: string | number; method: string };
            // Acknowledge shutdown like the real daemon (daemon.ts shutdown handler), then
            // deliberately stay up — the hung-daemon shape.
            socket.write(JSON.stringify({ id: req.id, result: { acknowledged: true } }) + "\n");
          });
        });
        await new Promise<void>((resolve) => server.listen(config.socketPath, resolve));

        try {
          const result = await logout(tempDir, undefined, { timeoutMs: 600, pollMs: 25 });
          expect(result.exitCode).toBe(1);
          expect(result.output).not.toContain("Daemon stopped");
          expect(result.output).toContain(String(process.pid));
          expect(result.output).toContain(config.socketPath);
          expect(result.output).toMatch(/did not complete/i);
        } finally {
          await new Promise<void>((resolve) => server.close(() => resolve()));
        }
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
  //
  // These now live on the PARITY path (§1.3): settings/moniker are agent-scoped, so they resolve
  // their agent through withDaemon's use-agent replay like every other agent-scoped command, instead
  // of a private connection helper that skipped it. That also puts them on the §3 bash contract —
  // JSON to stdout, the daemon's structured error VERBATIM to stderr, exit code branching on ok —
  // which is what these assertions changed to. The DAEMON behavior they pin is unchanged.
  describe("moniker", () => {
    it("sets and clears the outbound-name override against a live daemon", async () => {
      const config = makeConfig();
      handle = await startDaemon(config);
      const create = await createAgent(tempDir, "alice");
      expect(create.exitCode).toBe(0);
      // The parity replay refuses to act as an OFFLINE agent (it will not silently resurrect one),
      // so an agent-scoped command needs her online — which is the production shape anyway.
      await startAgent(tempDir, "alice", {});

      const set = await monikerSet(tempDir, "Wonderland_Alice", { agent: "alice" });
      expect(set.exitCode).toBe(0);
      expect(JSON.parse(set.stdout)).toMatchObject({ ok: true, agent: "alice", moniker: "Wonderland_Alice" });

      const cleared = await monikerSet(tempDir, null, { agent: "alice" });
      expect(cleared.exitCode).toBe(0);
      expect(JSON.parse(cleared.stdout)).toMatchObject({ ok: true, agent: "alice", moniker: null });
    });

    it("surfaces the daemon's invalid_moniker rejection verbatim", async () => {
      const config = makeConfig();
      handle = await startDaemon(config);
      await createAgent(tempDir, "alice");
      await startAgent(tempDir, "alice", {});

      const bad = await monikerSet(tempDir, "not a valid name", { agent: "alice" });
      expect(bad.exitCode).toBe(1);
      expect(bad.stdout).toBe(""); // a failure never lands on stdout
      const parsed = JSON.parse(bad.stderr);
      expect(parsed.ok).toBe(false);
      expect(parsed.reason).toBe("invalid_moniker");
    });

    it("fails loud when no daemon is running", async () => {
      const result = await monikerSet(tempDir, "Bob", { agent: "alice" });
      expect(result.exitCode).toBe(1);
      expect(result.stdout).toBe("");
      expect(JSON.parse(result.stderr).reason).toBe("daemon_not_running");
    });
  });

  describe("settings (DOD-SETTINGS-SURFACE-1)", () => {
    it("sets a bound override and reads it back against a live daemon", async () => {
      const config = makeConfig();
      handle = await startDaemon(config);
      expect((await createAgent(tempDir, "alice")).exitCode).toBe(0);
      await startAgent(tempDir, "alice", {});

      const set = await settingsSet(tempDir, "bounds.known.max_sessions", "8", { agent: "alice" });
      expect(set.exitCode).toBe(0);
      expect(JSON.parse(set.stdout)).toMatchObject({ ok: true, key: "bounds.known.max_sessions", value: "8" });

      const get = await settingsGet(tempDir, "bounds.known.max_sessions", { agent: "alice" });
      expect(get.exitCode).toBe(0);
      expect(JSON.parse(get.stdout)).toMatchObject({ ok: true, value: "8" });

      // An unset key returns null (the built-in default is used).
      const unset = await settingsGet(tempDir, "away.default", { agent: "alice" });
      expect(JSON.parse(unset.stdout)).toMatchObject({ ok: true, value: null });
    });

    it("surfaces the daemon's invalid_value / invalid_key rejections verbatim (INV-TIER-BOUND at the surface)", async () => {
      const config = makeConfig();
      handle = await startDaemon(config);
      await createAgent(tempDir, "alice");
      await startAgent(tempDir, "alice", {});

      for (const bad of ["Infinity", "-5", "0"]) {
        const r = await settingsSet(tempDir, "bounds.known.max_sessions", bad, { agent: "alice" });
        expect(r.exitCode).toBe(1);
        expect(r.stdout).toBe("");
        expect(JSON.parse(r.stderr).reason).toBe("invalid_value");
      }
      const badKey = await settingsSet(tempDir, "bounds.knwon.max_sessions", "8", { agent: "alice" });
      expect(badKey.exitCode).toBe(1);
      expect(JSON.parse(badKey.stderr).reason).toBe("invalid_key");
    });

    it("fails loud when no daemon is running", async () => {
      const result = await settingsGet(tempDir, "away.default", { agent: "alice" });
      expect(result.exitCode).toBe(1);
      expect(result.stdout).toBe("");
      expect(JSON.parse(result.stderr).reason).toBe("daemon_not_running");
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
      // …and the literal words are still caught: they are not decodable as a capability either.
      expect(result.output).not.toContain("No daemon running"); // short-circuited before the daemon
    });

    // M12: a pre-auth CAPABILITY has neither legacy prefix — it is base64url JSON. Gating on the
    // prefixes alone rejected the very artifact preauth-capability.ts says to paste here, so a
    // capability could be minted, signed and accepted by every directory and still never get past
    // the client. It must reach the daemon, where the signature and validity window are verified.
    it("lets a pre-auth CAPABILITY through the client gate to the daemon", async () => {
      const capability = Buffer.from(
        JSON.stringify({
          nonce: "0".repeat(32),
          phone_stub_hash: "a".repeat(64),
          email_domain: "example.com",
          issued_at: "2026-07-29T00:00:00.000Z",
          expires_at: "2030-07-29T00:00:00.000Z",
          sig: "b".repeat(128),
        }),
        "utf8",
      ).toString("base64url");
      const result = await register(tempDir, "alice", capability);
      // Reached the daemon (absent here) rather than being refused as malformed by the CLI.
      expect(result.output).toContain("No daemon running");
      expect(result.output).not.toContain("look like a pre-auth token");
    });

    // A CELLO- token of the wrong length passes the client-side prefix gate (D13: the client checks
    // only the stable brand prefix; the directory is the authority on the full format) and reaches
    // the daemon — here there's no daemon, so it surfaces "No daemon running", not a client "malformed".
    it("lets a wrong-length CELLO- token through the client gate to the daemon", async () => {
      const result = await register(tempDir, "alice", "CELLO-tooshort");
      expect(result.exitCode).toBe(1);
      expect(result.output).toContain("No daemon running");
    });

    // The "DEV-" sentinel is the local DevTokenValidator's prefix. The CLI must NOT reject it client-side —
    // rejecting DEV- broke ALL local/spine registration (the CLI wanted CELLO-, the local validator wanted
    // DEV-, so no token satisfied both). It passes the gate and reaches the daemon (the real authority).
    it("lets a DEV- sentinel token through the client gate to the daemon (local dev registration)", async () => {
      const result = await register(tempDir, "alice", "DEV-local-test-token");
      expect(result.exitCode).toBe(1);
      expect(result.output).toContain("No daemon running");
      expect(result.output).not.toContain("start with 'CELLO-'"); // NOT rejected client-side as malformed
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
