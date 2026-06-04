/**
 * CELLO-M6B-001 — PID lock file tests
 *
 * Phase S — Specification:
 *
 * AC-001: When a second cello-mcp starts and a prior process is running, the new
 *   process sends SIGTERM, waits up to 5s, sends SIGKILL if needed, then writes
 *   its own PID. Verified by spawning real child processes.
 *
 * AC-002: When the lock file contains a stale PID (process not running), startup
 *   proceeds normally without sending any signals.
 *
 * AC-003: When cello-mcp receives SIGTERM/SIGINT or exits normally, the lock file
 *   is removed. Verified by checking file absence after signal handler.
 *
 * AC-004: The kill-prior-process step happens BEFORE opening SQLCipher. Verified
 *   by capturing stderr and asserting event ordering.
 *
 * AC-005: M7 multi-agent case — different agents use different lock files based
 *   on CELLO_AGENT_NAME env var.
 *
 * SI-001: SIGTERM must only target processes owned by the current user. EPERM is
 *   caught and logged, startup continues. Tested via dependency injection.
 *
 * Test type: unit (AC-002, AC-005, SI-001) / integration (AC-001, AC-003, AC-004)
 * MANDATORY: --pool-options.threads.maxThreads=1
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync, chmodSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";
import { acquireLockFile, getLockFilePath, releaseLockFile } from "../lock-file.js";

let testDir: string;

beforeEach(() => {
  // Create isolated temp directory for each test
  testDir = mkdtempSync(join(tmpdir(), "cello-lock-test-"));
});

afterEach(() => {
  // Clean up temp directory
  try {
    rmSync(testDir, { recursive: true, force: true });
  } catch {
    // Silent cleanup failure
  }
});

// ─── AC-002: Stale lock file (PID not running) ────────────────────────────────

describe("AC-002: Stale lock file handling", () => {
  it("when lock file contains a non-running PID, startup proceeds without error", async () => {
    // Use a mock killFn that throws ESRCH for the existence check (signal 0) —
    // this deterministically simulates a stale PID without relying on the system
    // not having a process at a specific PID number (which is non-deterministic
    // on Linux systems with elevated max PID values).
    const lockFilePath = join(testDir, "cello-mcp.pid");
    const stalePid = 54321; // Arbitrary — killFn mock makes it stale regardless
    writeFileSync(lockFilePath, String(stalePid), "utf8");

    const events: Array<{ event: string; context: Record<string, unknown> }> = [];
    const logger = {
      info: (event: string, context: Record<string, unknown>) =>
        events.push({ event, context }),
      warn: (event: string, context: Record<string, unknown>) =>
        events.push({ event, context }),
    };

    // Inject killFn: throws ESRCH for any signal to stalePid (simulates stale/dead process)
    const killFn = (pid: number, signal: number | NodeJS.Signals): void => {
      if (pid === stalePid) {
        const err = new Error("No such process") as NodeJS.ErrnoException;
        err.code = "ESRCH";
        throw err;
      }
      process.kill(pid, signal);
    };

    const cleanup = await acquireLockFile(lockFilePath, { killFn, logger });

    // Lock file now contains our PID
    const content = readFileSync(lockFilePath, "utf8").trim();
    expect(content).toBe(String(process.pid));

    // No prior.process.killed event (stale PID was not killed)
    const killedEvent = events.find((e) => e.event === "client.startup.prior.process.killed");
    expect(killedEvent).toBeUndefined();

    cleanup();
  });

  it("when lock file contains invalid content (non-numeric), startup proceeds", async () => {
    const lockFilePath = join(testDir, "cello-mcp.pid");
    writeFileSync(lockFilePath, "not-a-pid", "utf8");

    const cleanup = await acquireLockFile(lockFilePath);

    // Lock file now contains our PID
    const content = readFileSync(lockFilePath, "utf8").trim();
    expect(content).toBe(String(process.pid));

    cleanup();
  });

  it("when lock file contains PID 0, no signal is sent and startup proceeds", async () => {
    // POSIX: process.kill(0, signal) sends signal to the entire process group —
    // which includes the Claude Code parent. This must be treated as an invalid/dangerous
    // PID and rejected before any kill attempt.
    const lockFilePath = join(testDir, "cello-mcp.pid");
    writeFileSync(lockFilePath, "0", "utf8");

    const signals: Array<{ pid: number; signal: number | NodeJS.Signals }> = [];
    const killFn = (pid: number, signal: number | NodeJS.Signals): void => {
      signals.push({ pid, signal });
      // Do NOT call process.kill — we're asserting no kill attempt is made
    };

    const cleanup = await acquireLockFile(lockFilePath, { killFn });

    // No signal was sent — PID 0 was treated as stale/invalid
    expect(signals).toHaveLength(0);

    // Lock file now contains our PID
    const content = readFileSync(lockFilePath, "utf8").trim();
    expect(content).toBe(String(process.pid));

    cleanup();
  });

  it("when lock file contains a negative PID (-1), no signal is sent and startup proceeds", async () => {
    // POSIX: process.kill(-1, signal) sends signal to all processes the current user
    // can signal — equivalent to a broadcast kill. Must be rejected as invalid.
    const lockFilePath = join(testDir, "cello-mcp.pid");
    writeFileSync(lockFilePath, "-1", "utf8");

    const signals: Array<{ pid: number; signal: number | NodeJS.Signals }> = [];
    const killFn = (pid: number, signal: number | NodeJS.Signals): void => {
      signals.push({ pid, signal });
    };

    const cleanup = await acquireLockFile(lockFilePath, { killFn });

    // No signal was sent — negative PID was treated as stale/invalid
    expect(signals).toHaveLength(0);

    // Lock file now contains our PID
    const content = readFileSync(lockFilePath, "utf8").trim();
    expect(content).toBe(String(process.pid));

    cleanup();
  });

  it("when lock file does not exist, startup proceeds", async () => {
    const lockFilePath = join(testDir, "cello-mcp.pid");

    const cleanup = await acquireLockFile(lockFilePath);

    // Lock file is created with our PID
    expect(existsSync(lockFilePath)).toBe(true);
    const content = readFileSync(lockFilePath, "utf8").trim();
    expect(content).toBe(String(process.pid));

    cleanup();
  });
});

// ─── SI-001: EPERM handling ────────────────────────────────────────────────────

describe("SI-001: EPERM (cross-user process) handling", () => {
  it("when kill(priorPid, 0) throws EPERM, startup continues without crashing", async () => {
    const lockFilePath = join(testDir, "cello-mcp.pid");
    const crossUserPid = 12345; // Simulated PID of a process owned by another user
    writeFileSync(lockFilePath, String(crossUserPid), "utf8");

    const events: Array<{ event: string; context: Record<string, unknown> }> = [];
    const logger = {
      info: (event: string, context: Record<string, unknown>) =>
        events.push({ event, context }),
      warn: (event: string, context: Record<string, unknown>) =>
        events.push({ event, context }),
    };

    // Inject a kill function that throws EPERM
    const killFn = (pid: number, signal: number | NodeJS.Signals): void => {
      if (pid === crossUserPid && signal === 0) {
        const err = new Error("Operation not permitted") as NodeJS.ErrnoException;
        err.code = "EPERM";
        throw err;
      }
      // Default behavior for our own process
      process.kill(pid, signal);
    };

    const cleanup = await acquireLockFile(lockFilePath, { killFn, logger });

    // Startup succeeded — lock file now has our PID
    const content = readFileSync(lockFilePath, "utf8").trim();
    expect(content).toBe(String(process.pid));

    // EPERM was logged at warn level
    const epermEvent = events.find((e) => e.event === "client.startup.lock.eperm");
    expect(epermEvent).toBeDefined();
    expect(epermEvent?.context.priorPid).toBe(crossUserPid);
    expect(epermEvent?.context.reason).toContain("another user");

    // No kill attempt was made (EPERM detected during check phase)
    const killedEvent = events.find((e) => e.event === "client.startup.prior.process.killed");
    expect(killedEvent).toBeUndefined();

    cleanup();
  });
});

// ─── AC-003: Lock file cleanup on exit ─────────────────────────────────────────

describe("AC-003: Lock file cleanup on exit", () => {
  it("releaseLockFile removes the lock file", async () => {
    const lockFilePath = join(testDir, "cello-mcp.pid");

    const cleanup = await acquireLockFile(lockFilePath);

    // Lock file exists
    expect(existsSync(lockFilePath)).toBe(true);

    // Call cleanup
    cleanup();

    // Lock file is removed
    expect(existsSync(lockFilePath)).toBe(false);
  });

  it("releaseLockFile is idempotent (calling twice does not throw)", async () => {
    const lockFilePath = join(testDir, "cello-mcp.pid");

    const cleanup = await acquireLockFile(lockFilePath);
    cleanup();
    // Call again — should not throw
    cleanup();
  });

  it("releaseLockFile logs client.startup.lock.released event", async () => {
    const lockFilePath = join(testDir, "cello-mcp.pid");

    const events: Array<{ event: string; context: Record<string, unknown> }> = [];
    const logger = {
      info: (event: string, context: Record<string, unknown>) =>
        events.push({ event, context }),
      warn: (event: string, context: Record<string, unknown>) =>
        events.push({ event, context }),
    };

    const cleanup = await acquireLockFile(lockFilePath, { logger });
    cleanup();

    const releasedEvent = events.find((e) => e.event === "client.startup.lock.released");
    expect(releasedEvent).toBeDefined();
    expect(releasedEvent?.context.pid).toBe(process.pid);
  });
});

// ─── Observability: client.startup.lock.acquired (positive path) ───────────────

describe("Observability: client.startup.lock.acquired on successful write", () => {
  it("emits client.startup.lock.acquired with pid on a successful acquireLockFile call", async () => {
    const lockFilePath = join(testDir, "cello-mcp.pid");

    const events: Array<{ event: string; context: Record<string, unknown> }> = [];
    const logger = {
      info: (event: string, context: Record<string, unknown>) =>
        events.push({ event, context }),
      warn: (event: string, context: Record<string, unknown>) =>
        events.push({ event, context }),
    };

    const cleanup = await acquireLockFile(lockFilePath, { logger });

    const acquiredEvent = events.find((e) => e.event === "client.startup.lock.acquired");
    expect(acquiredEvent, "client.startup.lock.acquired must be emitted on success").toBeDefined();
    expect(acquiredEvent?.context.pid).toBe(process.pid);

    cleanup();
  });
});

// ─── AC-005: M7 multi-agent lock file paths ────────────────────────────────────

describe("AC-005: M7 multi-agent lock file paths", () => {
  it("different agent names produce different lock file paths", () => {
    const baseDir = testDir;

    const aliceLockPath = getLockFilePath("alice", baseDir);
    const bobLockPath = getLockFilePath("bob", baseDir);

    // Verify paths are distinct
    expect(aliceLockPath).not.toBe(bobLockPath);
    expect(aliceLockPath).toContain("alice");
    expect(bobLockPath).toContain("bob");
  });

  it("acquireLockFile creates nested directories (mkdir -p)", async () => {
    const lockFilePath = join(testDir, ".cello", "agents", "alice", "cello-mcp.pid");

    const cleanup = await acquireLockFile(lockFilePath);

    // Lock file exists in nested directory
    expect(existsSync(lockFilePath)).toBe(true);

    cleanup();
  });

  it("acquiring alice's lock and bob's lock are independent: each holds its own PID, neither cleanup affects the other", async () => {
    // This test verifies the non-interference guarantee for M7 multi-agent deployments.
    // If the path logic were ever changed to share a single lock file, one of the
    // acquireLockFile calls would kill the other agent's process (SIGTERM on our own PID)
    // and the assertions below would detect the regression.
    const aliceLockPath = getLockFilePath("alice", testDir);
    const bobLockPath = getLockFilePath("bob", testDir);

    // Acquire alice's lock first
    const cleanupAlice = await acquireLockFile(aliceLockPath);

    // Acquire bob's lock while alice's lock file exists — must NOT trigger a kill
    // (bob's path is different, so the prior-PID check never reads alice's file)
    const cleanupBob = await acquireLockFile(bobLockPath);

    // Both lock files exist with the current PID (this test process)
    expect(existsSync(aliceLockPath), "alice lock file must exist").toBe(true);
    expect(existsSync(bobLockPath), "bob lock file must exist").toBe(true);

    const alicePid = parseInt(readFileSync(aliceLockPath, "utf8").trim(), 10);
    const bobPid = parseInt(readFileSync(bobLockPath, "utf8").trim(), 10);
    expect(alicePid).toBe(process.pid);
    expect(bobPid).toBe(process.pid);

    // Releasing alice must not affect bob's lock file
    cleanupAlice();
    expect(existsSync(aliceLockPath), "alice lock file must be removed after alice cleanup").toBe(false);
    expect(existsSync(bobLockPath), "bob lock file must survive alice cleanup").toBe(true);

    // Releasing bob must not affect alice's (already released) lock file
    cleanupBob();
    expect(existsSync(bobLockPath), "bob lock file must be removed after bob cleanup").toBe(false);
  });
});

// ─── AC-001: Kill prior process integration test ───────────────────────────────

describe("AC-001: Kill prior running process (integration)", () => {
  it("when a prior process is running, the new process kills it and takes the lock", async () => {
    const lockFilePath = join(testDir, "cello-mcp.pid");

    // Spawn a long-running process A that holds the lock
    const scriptA = `
      const fs = require("fs");
      const lockPath = "${lockFilePath.replace(/\\/g, "\\\\")}";
      fs.mkdirSync(require("path").dirname(lockPath), { recursive: true });
      fs.writeFileSync(lockPath, String(process.pid), "utf8");
      // Block indefinitely
      setInterval(() => {}, 1000);
    `;
    let processA: ReturnType<typeof spawn> | undefined;
    let cleanup: (() => void) | undefined;

    try {
      processA = spawn(process.execPath, ["-e", scriptA], {
        stdio: "ignore",
        detached: false,
      });

      // Poll until process A writes its PID (avoids fixed-wait flake in slow CI)
      await new Promise<void>((resolve, reject) => {
        const deadline = Date.now() + 5000;
        const interval = setInterval(() => {
          if (existsSync(lockFilePath)) {
            clearInterval(interval);
            resolve();
          } else if (Date.now() > deadline) {
            clearInterval(interval);
            reject(new Error("processA did not write lock file within 5s"));
          }
        }, 50);
      });
      expect(existsSync(lockFilePath)).toBe(true);
      const priorPid = parseInt(readFileSync(lockFilePath, "utf8").trim(), 10);
      // processA.pid is the PID from spawn — cross-check with what was written to disk
      if (processA.pid !== undefined) {
        expect(priorPid).toBe(processA.pid);
      } else {
        throw new Error("processA failed to spawn (pid is undefined)");
      }

      // Process B acquires the lock (should kill process A).
      // Event collector records the log level alongside the event so we can assert
      // that SIGTERM kills are logged at info (clean exit) vs SIGKILL at warn (force kill).
      const events: Array<{ level: "info" | "warn"; event: string; context: Record<string, unknown> }> = [];
      const logger = {
        info: (event: string, context: Record<string, unknown>) =>
          events.push({ level: "info", event, context }),
        warn: (event: string, context: Record<string, unknown>) =>
          events.push({ level: "warn", event, context }),
      };

      cleanup = await acquireLockFile(lockFilePath, { logger });

      // Lock file now contains process B's PID (this test process)
      const newPid = parseInt(readFileSync(lockFilePath, "utf8").trim(), 10);
      expect(newPid).toBe(process.pid);

      // Process A should be killed
      await new Promise((resolve) => setTimeout(resolve, 200));
      const processAPid = processA.pid;
      let isARunning = true;
      try {
        process.kill(processAPid, 0);
      } catch {
        isARunning = false;
      }
      expect(isARunning).toBe(false);

      // client.startup.prior.process.killed event was logged
      const killedEvent = events.find((e) => e.event === "client.startup.prior.process.killed");
      expect(killedEvent).toBeDefined();
      expect(killedEvent?.context.priorPid).toBe(priorPid);
      expect(killedEvent?.context.signal).toMatch(/SIGTERM|SIGKILL/);
      // SIGTERM = graceful exit = logged at info level
      if (killedEvent?.context.signal === "SIGTERM") {
        expect(killedEvent?.level, "SIGTERM kill must be logged at info level").toBe("info");
      }
    } finally {
      // Guaranteed cleanup
      if (processA) {
        try { processA.kill("SIGKILL"); } catch {}
      }
      if (cleanup) {
        cleanup();
      }
    }
  }, 10000); // 10s timeout for process spawn/kill

  it("when prior process does not exit after SIGTERM, SIGKILL is sent (logged at warn)", async () => {
    const lockFilePath = join(testDir, "cello-mcp.pid");

    // Spawn a process that ignores SIGTERM
    const scriptIgnoreSigterm = `
      const fs = require("fs");
      const lockPath = "${lockFilePath.replace(/\\/g, "\\\\")}";
      fs.mkdirSync(require("path").dirname(lockPath), { recursive: true });
      fs.writeFileSync(lockPath, String(process.pid), "utf8");
      process.on("SIGTERM", () => {
        // Ignore SIGTERM — stay alive
      });
      setInterval(() => {}, 1000);
    `;
    let processA: ReturnType<typeof spawn> | undefined;
    let cleanup: (() => void) | undefined;

    try {
      processA = spawn(process.execPath, ["-e", scriptIgnoreSigterm], {
        stdio: "ignore",
        detached: false,
      });

      // Poll until processA writes its PID (avoids fixed-wait flake in slow CI)
      await new Promise<void>((resolve, reject) => {
        const deadline = Date.now() + 5000;
        const interval = setInterval(() => {
          if (existsSync(lockFilePath)) {
            clearInterval(interval);
            resolve();
          } else if (Date.now() > deadline) {
            clearInterval(interval);
            reject(new Error("processA did not write lock file within 5s"));
          }
        }, 50);
      });
      if (processA.pid === undefined) {
        throw new Error("processA failed to spawn (pid is undefined)");
      }
      const priorPid = parseInt(readFileSync(lockFilePath, "utf8").trim(), 10);

      // Event collector records both the event name and the log level (info vs warn)
      // so that a future regression that changes warn→info for SIGKILL is caught.
      const events: Array<{ level: "info" | "warn"; event: string; context: Record<string, unknown> }> = [];
      const logger = {
        info: (event: string, context: Record<string, unknown>) =>
          events.push({ level: "info", event, context }),
        warn: (event: string, context: Record<string, unknown>) =>
          events.push({ level: "warn", event, context }),
      };

      // Acquire lock — should escalate to SIGKILL
      cleanup = await acquireLockFile(lockFilePath, { logger });

      // Process A should be killed (SIGKILL cannot be ignored)
      await new Promise((resolve) => setTimeout(resolve, 200));
      const processAPid = processA.pid;
      let isARunning = true;
      try {
        process.kill(processAPid, 0);
      } catch {
        isARunning = false;
      }
      expect(isARunning).toBe(false);

      // SIGKILL event was logged at warn level (not info — spec says "logged at warn
      // level to distinguish a force-kill from a clean exit")
      const killedEvent = events.find(
        (e) => e.event === "client.startup.prior.process.killed" && e.context.signal === "SIGKILL",
      );
      expect(killedEvent, "SIGKILL kill event must be logged").toBeDefined();
      expect(killedEvent?.context.priorPid).toBe(priorPid);
      expect(killedEvent?.level, "SIGKILL must be logged at warn level, not info").toBe("warn");
    } finally {
      // Guaranteed cleanup
      if (processA) {
        try { processA.kill("SIGKILL"); } catch {}
      }
      if (cleanup) {
        cleanup();
      }
    }
  }, 10000); // 10s timeout (5s wait + spawn overhead)
});

// ─── acquireLockFile contract: no external I/O inside the call ─────────────────

/**
 * Verifies the lock-file module's internal contract: acquireLockFile completes
 * without blocking on external I/O (network, DB). This is a precondition for the
 * AC-004 ordering invariant that is tested at integration level in
 * cello-m6b-001-integration.test.ts (where the real binary is spawned and the
 * kill event is verified to precede the DB-open event in stderr).
 */
describe("acquireLockFile: no external I/O blocking", () => {
  it("acquireLockFile returns immediately when no prior process is present", async () => {
    const lockFilePath = join(testDir, "cello-mcp.pid");

    const t0 = Date.now();
    const cleanup = await acquireLockFile(lockFilePath);
    const duration = Date.now() - t0;

    // Should complete in <100ms (no network, no DB)
    expect(duration).toBeLessThan(100);

    cleanup();
  });
});

// ─── Observability events: remaining untested paths ──────────────────────────

describe("Observability: client.startup.lock.write.failed (non-fatal)", () => {
  it("when writeFileSync fails (read-only parent dir), logs warn event and returns no-op cleanup", async () => {
    // Create a read-only directory so writeFileSync inside it fails with EACCES
    const roDir = join(testDir, "readonly");
    mkdirSync(roDir, { recursive: true });
    chmodSync(roDir, 0o444); // read-only

    const lockFilePath = join(roDir, "cello-mcp.pid");

    const events: Array<{ event: string; context: Record<string, unknown> }> = [];
    const logger = {
      info: (event: string, context: Record<string, unknown>) =>
        events.push({ event, context }),
      warn: (event: string, context: Record<string, unknown>) =>
        events.push({ event, context }),
    };

    // acquireLockFile must NOT throw — the write.failed event is non-fatal
    const cleanup = await acquireLockFile(lockFilePath, { logger });

    // The warn event must be logged
    const writeFailedEvent = events.find((e) => e.event === "client.startup.lock.write.failed");
    expect(writeFailedEvent, "client.startup.lock.write.failed event must be logged").toBeDefined();
    expect(writeFailedEvent?.context.reason).toBeTruthy();

    // No lock.acquired event since write failed
    const acquiredEvent = events.find((e) => e.event === "client.startup.lock.acquired");
    expect(acquiredEvent).toBeUndefined();

    // Cleanup must be a no-op (not throw)
    expect(() => cleanup()).not.toThrow();

    // Restore directory permissions for cleanup
    chmodSync(roDir, 0o755);
  });
});

describe("Observability: client.startup.lock.read.failed (non-ENOENT read error)", () => {
  it("when readFileSync fails with non-ENOENT error (EISDIR), logs warn event and continues", async () => {
    // Create a directory at the lock file path — readFileSync will throw EISDIR (not ENOENT)
    const lockFilePath = join(testDir, "cello-mcp.pid");
    mkdirSync(lockFilePath, { recursive: true });

    const events: Array<{ event: string; context: Record<string, unknown> }> = [];
    const logger = {
      info: (event: string, context: Record<string, unknown>) =>
        events.push({ event, context }),
      warn: (event: string, context: Record<string, unknown>) =>
        events.push({ event, context }),
    };

    // acquireLockFile will also fail to write (lockFilePath is a dir) — non-fatal
    await acquireLockFile(lockFilePath, { logger });

    const readFailedEvent = events.find((e) => e.event === "client.startup.lock.read.failed");
    expect(readFailedEvent, "client.startup.lock.read.failed event must be logged").toBeDefined();
    expect(readFailedEvent?.context.reason).toBeTruthy();
  });
});

describe("Observability: client.startup.lock.check.failed (unknown kill error)", () => {
  it("when kill(pid, 0) throws unknown error code, logs warn event and startup continues", async () => {
    const lockFilePath = join(testDir, "cello-mcp.pid");
    const unknownPid = 54321;
    writeFileSync(lockFilePath, String(unknownPid), "utf8");

    const events: Array<{ event: string; context: Record<string, unknown> }> = [];
    const logger = {
      info: (event: string, context: Record<string, unknown>) =>
        events.push({ event, context }),
      warn: (event: string, context: Record<string, unknown>) =>
        events.push({ event, context }),
    };

    // Inject a killFn that throws with an unknown error code
    const killFn = (pid: number, signal: number | NodeJS.Signals): void => {
      if (pid === unknownPid && signal === 0) {
        const err = new Error("Unknown OS error") as NodeJS.ErrnoException;
        err.code = "EUNKNOWN";
        throw err;
      }
      process.kill(pid, signal);
    };

    const cleanup = await acquireLockFile(lockFilePath, { killFn, logger });

    const checkFailedEvent = events.find((e) => e.event === "client.startup.lock.check.failed");
    expect(checkFailedEvent, "client.startup.lock.check.failed event must be logged").toBeDefined();
    expect(checkFailedEvent?.context.priorPid).toBe(unknownPid);
    expect(checkFailedEvent?.context.reason).toBeTruthy();

    // Startup still proceeded — lock file has our PID
    const content = readFileSync(lockFilePath, "utf8").trim();
    expect(content).toBe(String(process.pid));

    cleanup();
  });
});

describe("Observability: client.startup.prior.kill.failed (kill throws on SIGTERM)", () => {
  it("when killFn throws on SIGTERM (process exited between check and kill), logs warn and startup continues", async () => {
    const lockFilePath = join(testDir, "cello-mcp.pid");
    const targetPid = 67890;
    writeFileSync(lockFilePath, String(targetPid), "utf8");

    const events: Array<{ event: string; context: Record<string, unknown> }> = [];
    const logger = {
      info: (event: string, context: Record<string, unknown>) =>
        events.push({ event, context }),
      warn: (event: string, context: Record<string, unknown>) =>
        events.push({ event, context }),
    };

    // Inject killFn: signal 0 first check returns (running), SIGTERM throws ESRCH
    // (race: process exited between the existence check and the kill call)
    let checkCount = 0;
    const killFn = (pid: number, signal: number | NodeJS.Signals): void => {
      if (pid === targetPid) {
        if (signal === 0) {
          checkCount++;
          if (checkCount === 1) {
            return; // first check: appears running
          }
          // subsequent checks: gone
          const err = new Error("No such process") as NodeJS.ErrnoException;
          err.code = "ESRCH";
          throw err;
        }
        if (signal === "SIGTERM") {
          // Race: process exited just before we sent SIGTERM
          const err = new Error("No such process") as NodeJS.ErrnoException;
          err.code = "ESRCH";
          throw err;
        }
      }
      process.kill(pid, signal);
    };

    const cleanup = await acquireLockFile(lockFilePath, { killFn, logger });

    const killFailedEvent = events.find((e) => e.event === "client.startup.prior.kill.failed");
    expect(killFailedEvent, "client.startup.prior.kill.failed event must be logged").toBeDefined();
    expect(killFailedEvent?.context.priorPid).toBe(targetPid);
    expect(killFailedEvent?.context.signal).toBe("SIGTERM");
    expect(killFailedEvent?.context.reason).toBeTruthy();

    // Startup still proceeded — lock file has our PID
    const content = readFileSync(lockFilePath, "utf8").trim();
    expect(content).toBe(String(process.pid));

    cleanup();
  });
});

// ─── Observability: client.startup.prior.process.killed NOT emitted on SIGTERM race ─

describe("Observability: prior.process.killed not emitted when SIGTERM threw (I-1 regression)", () => {
  it("when SIGTERM throws (race: process already dead), prior.process.killed is NOT emitted", async () => {
    // Regression test for the double-event scenario:
    // If SIGTERM throws (process exited between existence check and kill),
    // the implementation must NOT emit prior.process.killed, because the
    // taxonomy says this event fires "after successfully killing a prior process."
    // Emitting it when the kill failed contradicts the "successfully" qualifier.
    const lockFilePath = join(testDir, "cello-mcp.pid");
    const targetPid = 88888;
    writeFileSync(lockFilePath, String(targetPid), "utf8");

    const events: Array<{ event: string; context: Record<string, unknown> }> = [];
    const logger = {
      info: (event: string, context: Record<string, unknown>) =>
        events.push({ event, context }),
      warn: (event: string, context: Record<string, unknown>) =>
        events.push({ event, context }),
    };

    // killFn: signal 0 succeeds (process appears running), SIGTERM throws ESRCH
    // This simulates the race where the process dies between the check and the kill.
    let checkCount = 0;
    const killFn = (pid: number, signal: number | NodeJS.Signals): void => {
      if (pid === targetPid) {
        if (signal === 0) {
          checkCount++;
          if (checkCount === 1) {
            return; // first check: appears running
          }
          // subsequent checks: gone (after SIGTERM race-throw, polling sees ESRCH)
          const err = new Error("No such process") as NodeJS.ErrnoException;
          err.code = "ESRCH";
          throw err;
        }
        if (signal === "SIGTERM") {
          // Race: process already dead when we try to send SIGTERM
          const err = new Error("No such process") as NodeJS.ErrnoException;
          err.code = "ESRCH";
          throw err;
        }
      }
      process.kill(pid, signal);
    };

    const cleanup = await acquireLockFile(lockFilePath, { killFn, logger });

    // prior.kill.failed was logged (correct — kill attempt failed)
    const killFailedEvent = events.find((e) => e.event === "client.startup.prior.kill.failed");
    expect(killFailedEvent, "prior.kill.failed must be logged when SIGTERM throws").toBeDefined();

    // prior.process.killed must NOT be logged — we didn't successfully kill the process
    const killedEvent = events.find((e) => e.event === "client.startup.prior.process.killed");
    expect(killedEvent, "prior.process.killed must NOT be emitted when SIGTERM threw").toBeUndefined();

    cleanup();
  });
});

// ─── Observability: client.startup.lock.release.failed (non-ENOENT unlink failure) ─

describe("Observability: client.startup.lock.release.failed (non-ENOENT unlink failure)", () => {
  it("when unlinkSync fails with EACCES, logs warn event and does not throw", () => {
    // Uses dependency injection for unlinkFn — tests the non-ENOENT error path in
    // releaseLockFile without needing to manipulate real filesystem permissions.
    const lockFilePath = join(testDir, "cello-mcp.pid");

    const events: Array<{ event: string; context: Record<string, unknown> }> = [];
    const logger = {
      info: (event: string, context: Record<string, unknown>) =>
        events.push({ event, context }),
      warn: (event: string, context: Record<string, unknown>) =>
        events.push({ event, context }),
    };

    // Inject unlinkFn that throws EACCES (read-only filesystem, permission denied)
    const unlinkFn = (_path: string): void => {
      const err = new Error("Permission denied") as NodeJS.ErrnoException;
      err.code = "EACCES";
      throw err;
    };

    // releaseLockFile must NOT throw — the process is already exiting
    expect(() => releaseLockFile(lockFilePath, logger, unlinkFn)).not.toThrow();

    // lock.release.failed must be logged at warn level
    const releaseFailedEvent = events.find((e) => e.event === "client.startup.lock.release.failed");
    expect(releaseFailedEvent, "client.startup.lock.release.failed must be logged").toBeDefined();
    expect(releaseFailedEvent?.context.reason).toBeTruthy();
    expect(releaseFailedEvent?.context.pid).toBe(process.pid);
  });

  it("when unlinkSync throws ENOENT (already deleted), no event is logged and no throw", () => {
    // ENOENT is the idempotent case — lock file already removed by a prior cleanup call.
    // Verify it is silently ignored (no event, no throw).
    const lockFilePath = join(testDir, "cello-mcp.pid");

    const events: Array<{ event: string; context: Record<string, unknown> }> = [];
    const logger = {
      info: (event: string, context: Record<string, unknown>) =>
        events.push({ event, context }),
      warn: (event: string, context: Record<string, unknown>) =>
        events.push({ event, context }),
    };

    const unlinkFn = (_path: string): void => {
      const err = new Error("No such file or directory") as NodeJS.ErrnoException;
      err.code = "ENOENT";
      throw err;
    };

    expect(() => releaseLockFile(lockFilePath, logger, unlinkFn)).not.toThrow();

    // No event logged for ENOENT — it is the expected idempotent case
    const releaseFailedEvent = events.find((e) => e.event === "client.startup.lock.release.failed");
    expect(releaseFailedEvent).toBeUndefined();
    // And no released event either — unlock didn't succeed
    const releasedEvent = events.find((e) => e.event === "client.startup.lock.released");
    expect(releasedEvent).toBeUndefined();
  });
});
