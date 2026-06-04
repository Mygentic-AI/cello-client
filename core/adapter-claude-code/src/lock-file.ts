/**
 * lock-file.ts — PID lock file manager for single-instance cello-mcp process
 *
 * CELLO-M6B-001: Every new cello-mcp startup kills any prior process holding
 * the same lock file, ensuring exactly one cello-mcp per agent at all times.
 *
 * Pseudocode (Phase P):
 *
 * acquireLockFile(lockFilePath, opts?):
 *   1. Read lockFilePath. If it doesn't exist, skip to step 7.
 *   2. Parse PID from file content (trim whitespace, parseInt).
 *   3. Check if process with that PID is running (kill(priorPid, 0)).
 *      - If ESRCH (no such process) → stale lock → skip to step 7.
 *      - If EPERM (permission denied) → process exists but owned by another user → warn and continue to step 7.
 *      - If process is running and killable → proceed to step 4.
 *   4. Send SIGTERM to prior process.
 *   5. Poll every 100ms for up to 5 seconds, checking if process still exists (kill(priorPid, 0)).
 *   6. If still running after 5s, send SIGKILL. Log at warn level.
 *   7. Create lock file directory (mkdir -p) if needed.
 *   8. Write current process.pid to lockFilePath.
 *   9. Return a cleanup function that removes the lock file.
 *
 * releaseLockFile(lockFilePath):
 *   1. Call fs.unlinkSync(lockFilePath), catch ENOENT silently.
 *
 * Dependency injection for testability:
 *   - killFn: (pid: number, signal: number | NodeJS.Signals) => void
 *     Defaults to process.kill. Tests inject a mock that throws for EPERM scenarios.
 */

import { readFileSync, writeFileSync, unlinkSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";

/**
 * Get the lock file path for a given agent name.
 * Used by both cello-mcp.ts and tests to ensure path logic is consistent.
 *
 * @param agentName - Optional agent name (M7+ multi-agent support)
 * @param baseDir - Base directory for .cello (defaults to homedir())
 * @returns Absolute path to the lock file
 */
export function getLockFilePath(
  agentName: string | null,
  baseDir = homedir(),
): string {
  return agentName
    ? join(baseDir, ".cello", "agents", agentName, "cello-mcp.pid")
    : join(baseDir, ".cello", "cello-mcp.pid");
}

export interface LockFileOptions {
  /**
   * Injected kill function for testing. Defaults to process.kill.
   * Tests can inject a mock that throws { code: 'EPERM' } to simulate cross-user scenarios.
   */
  killFn?: (pid: number, signal: number | NodeJS.Signals) => void;
  /**
   * Logger for observability events. If not provided, no events are logged.
   */
  logger?: {
    info: (event: string, context: Record<string, unknown>) => void;
    warn: (event: string, context: Record<string, unknown>) => void;
  };
}

/**
 * Acquire the PID lock file. If a prior process is running, kill it (SIGTERM → wait → SIGKILL).
 * Returns a cleanup function that releases the lock file on exit.
 *
 * AC-001, AC-002, AC-004, SI-001
 */
export async function acquireLockFile(
  lockFilePath: string,
  opts?: LockFileOptions,
): Promise<() => void> {
  const killFn = opts?.killFn ?? process.kill.bind(process);
  const logger = opts?.logger;

  // Step 1-3: Check for prior process
  let priorPid: number | null = null;
  try {
    const content = readFileSync(lockFilePath, "utf8").trim();
    priorPid = parseInt(content, 10);
    if (isNaN(priorPid)) {
      // Invalid PID in file — treat as stale
      priorPid = null;
    }
  } catch (err: unknown) {
    // ENOENT = no lock file exists → proceed to write
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      // Unexpected read error (permissions, etc) — non-fatal, log and continue
      logger?.warn("client.startup.lock.read.failed", {
        reason: (err as Error).message,
      });
    }
    priorPid = null;
  }

  if (priorPid !== null) {
    // Check if process is running
    let isRunning = false;
    try {
      killFn(priorPid, 0); // signal 0 = check existence without killing
      isRunning = true;
    } catch (err: unknown) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "ESRCH") {
        // No such process — stale lock
        isRunning = false;
      } else if (code === "EPERM") {
        // Process exists but owned by another user (SI-001)
        logger?.warn("client.startup.lock.eperm", {
          priorPid,
          reason: "process owned by another user",
        });
        isRunning = false; // Treat as stale — we cannot kill it, proceed with our own lock
      } else {
        // Unknown error — log and treat as not running
        logger?.warn("client.startup.lock.check.failed", {
          priorPid,
          reason: (err as Error).message,
        });
        isRunning = false;
      }
    }

    if (isRunning) {
      // Step 4: Send SIGTERM
      try {
        killFn(priorPid, "SIGTERM");
      } catch (err: unknown) {
        // Kill failed (race: process exited between check and kill) — non-fatal
        logger?.warn("client.startup.prior.kill.failed", {
          priorPid,
          signal: "SIGTERM",
          reason: (err as Error).message,
        });
      }

      // Step 5: Poll for up to 5 seconds
      const startTime = Date.now();
      const timeout = 5000;
      let stillRunning = true;

      // Check immediately after SIGTERM (most processes exit quickly)
      try {
        killFn(priorPid, 0);
        stillRunning = true;
      } catch {
        stillRunning = false;
      }

      // Only poll if still running after immediate check
      while (stillRunning && Date.now() - startTime < timeout) {
        await new Promise((resolve) => setTimeout(resolve, 100));
        try {
          killFn(priorPid, 0);
          stillRunning = true;
        } catch {
          // Process exited
          stillRunning = false;
          break;
        }
      }

      // Step 6: Escalate to SIGKILL if needed
      if (stillRunning) {
        try {
          killFn(priorPid, "SIGKILL");
          logger?.warn("client.startup.prior.process.killed", {
            priorPid,
            signal: "SIGKILL",
          });
        } catch (err: unknown) {
          logger?.warn("client.startup.prior.kill.failed", {
            priorPid,
            signal: "SIGKILL",
            reason: (err as Error).message,
          });
        }
      } else {
        // Graceful exit (SIGTERM succeeded)
        logger?.info("client.startup.prior.process.killed", {
          priorPid,
          signal: "SIGTERM",
        });
      }
    }
  }

  // Step 7-8: Write own PID to lock file
  try {
    mkdirSync(dirname(lockFilePath), { recursive: true });
    writeFileSync(lockFilePath, String(process.pid), "utf8");
    logger?.info("client.startup.lock.acquired", { pid: process.pid });
  } catch (err: unknown) {
    // Lock file write failure is non-fatal (orphan detection will be broken, but process runs)
    logger?.warn("client.startup.lock.write.failed", {
      reason: (err as Error).message,
    });
    // Emit actionable warning to stderr
    process.stderr.write(`cello-mcp: WARNING — unable to write lock file at ${lockFilePath}\n`);
    process.stderr.write(`cello-mcp: Orphan process detection is disabled. Check directory permissions.\n`);
  }

  // Step 9: Return cleanup function
  return () => releaseLockFile(lockFilePath, logger);
}

/**
 * Release the lock file. Called on SIGTERM/SIGINT/normal exit.
 * AC-003
 */
export function releaseLockFile(
  lockFilePath: string,
  logger?: { info: (event: string, context: Record<string, unknown>) => void },
): void {
  try {
    unlinkSync(lockFilePath);
    logger?.info("client.startup.lock.released", { pid: process.pid });
  } catch (err: unknown) {
    // ENOENT is expected if cleanup ran twice — silent
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      // Unexpected error — non-fatal
    }
  }
}
