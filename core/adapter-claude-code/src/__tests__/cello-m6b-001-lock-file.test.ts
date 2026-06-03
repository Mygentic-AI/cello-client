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
import { mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";
import { acquireLockFile, getLockFilePath } from "../lock-file.js";

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
    const lockFilePath = join(testDir, "cello-mcp.pid");
    const stalePid = 999999; // Extremely unlikely to be a real running process
    writeFileSync(lockFilePath, String(stalePid), "utf8");

    const events: Array<{ event: string; context: Record<string, unknown> }> = [];
    const logger = {
      info: (event: string, context: Record<string, unknown>) =>
        events.push({ event, context }),
      warn: (event: string, context: Record<string, unknown>) =>
        events.push({ event, context }),
    };

    const cleanup = await acquireLockFile(lockFilePath, { logger });

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

      // Wait for process A to write its PID
      await new Promise((resolve) => setTimeout(resolve, 500));
      expect(existsSync(lockFilePath)).toBe(true);
      const priorPid = parseInt(readFileSync(lockFilePath, "utf8").trim(), 10);
      expect(priorPid).toBe(processA.pid);

      // Process B acquires the lock (should kill process A)
      const events: Array<{ event: string; context: Record<string, unknown> }> = [];
      const logger = {
        info: (event: string, context: Record<string, unknown>) =>
          events.push({ event, context }),
        warn: (event: string, context: Record<string, unknown>) =>
          events.push({ event, context }),
      };

      cleanup = await acquireLockFile(lockFilePath, { logger });

      // Lock file now contains process B's PID (this test process)
      const newPid = parseInt(readFileSync(lockFilePath, "utf8").trim(), 10);
      expect(newPid).toBe(process.pid);

      // Process A should be killed
      await new Promise((resolve) => setTimeout(resolve, 200));
      let isARunning = true;
      try {
        process.kill(processA.pid!, 0);
      } catch {
        isARunning = false;
      }
      expect(isARunning).toBe(false);

      // client.startup.prior.process.killed event was logged
      const killedEvent = events.find((e) => e.event === "client.startup.prior.process.killed");
      expect(killedEvent).toBeDefined();
      expect(killedEvent?.context.priorPid).toBe(priorPid);
      expect(killedEvent?.context.signal).toMatch(/SIGTERM|SIGKILL/);
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

      // Wait for lock file to be written
      await new Promise((resolve) => setTimeout(resolve, 500));
      const priorPid = parseInt(readFileSync(lockFilePath, "utf8").trim(), 10);

      const events: Array<{ event: string; context: Record<string, unknown> }> = [];
      const logger = {
        info: (event: string, context: Record<string, unknown>) =>
          events.push({ event, context }),
        warn: (event: string, context: Record<string, unknown>) =>
          events.push({ event, context }),
      };

      // Acquire lock — should escalate to SIGKILL
      cleanup = await acquireLockFile(lockFilePath, { logger });

      // Process A should be killed (SIGKILL cannot be ignored)
      await new Promise((resolve) => setTimeout(resolve, 200));
      let isARunning = true;
      try {
        process.kill(processA.pid!, 0);
      } catch {
        isARunning = false;
      }
      expect(isARunning).toBe(false);

      // SIGKILL event was logged at warn level
      const killedEvent = events.find(
        (e) => e.event === "client.startup.prior.process.killed" && e.context.signal === "SIGKILL",
      );
      expect(killedEvent).toBeDefined();
      expect(killedEvent?.context.priorPid).toBe(priorPid);
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

// ─── AC-004: Kill-before-DB ordering ────────────────────────────────────────────

/**
 * AC-004: The kill-prior-process step must happen BEFORE opening SQLCipher.
 * This is verified in the cello-mcp.ts integration test by checking stderr output.
 * Here we verify the lock-file module's contract: acquireLockFile completes
 * synchronously (no async DB operations inside it).
 */
describe("AC-004: acquireLockFile completes before caller proceeds to DB open", () => {
  it("acquireLockFile returns immediately (does not block on external I/O)", async () => {
    const lockFilePath = join(testDir, "cello-mcp.pid");

    const t0 = Date.now();
    const cleanup = await acquireLockFile(lockFilePath);
    const duration = Date.now() - t0;

    // Should complete in <100ms (no network, no DB)
    expect(duration).toBeLessThan(100);

    cleanup();
  });
});
