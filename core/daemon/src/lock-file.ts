/**
 * Lock file management for the CELLO daemon.
 *
 * Pseudocode:
 * 1. acquireLock(path, content):
 *    - Write JSON content to path.tmp atomically
 *    - Rename path.tmp → path (atomic on POSIX)
 *    - Return true on success
 *
 * 2. readLock(path):
 *    - Read file, parse JSON
 *    - Validate shape: {pid: number, socketPath: string, version: string}
 *    - Return parsed content or null if missing/invalid
 *
 * 3. isProcessAlive(pid):
 *    - process.kill(pid, 0) — signal 0 checks existence without killing
 *    - Return true if no error thrown
 *
 * 4. removeLock(path):
 *    - Unlink the file, ignoring ENOENT
 */

import { readFile, writeFile, rename, stat, unlink } from "node:fs/promises";
import type { LockFileContent, Logger } from "./types.js";

export async function readLock(lockPath: string): Promise<LockFileContent | null> {
  let raw: string;
  try {
    raw = await readFile(lockPath, "utf-8");
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return null;
    }
    throw err;
  }

  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    if (
      typeof parsed.pid !== "number" ||
      typeof parsed.socketPath !== "string" ||
      typeof parsed.version !== "string"
    ) {
      return null;
    }
    return { pid: parsed.pid, socketPath: parsed.socketPath, version: parsed.version };
  } catch {
    return null;
  }
}

export async function acquireLock(lockPath: string, content: LockFileContent): Promise<void> {
  const tmpPath = lockPath + ".tmp";
  const json = JSON.stringify(content, null, 2) + "\n";
  await writeFile(tmpPath, json, { mode: 0o600 });
  try {
    await rename(tmpPath, lockPath);
  } catch (err: unknown) {
    try { await unlink(tmpPath); } catch { /* best-effort cleanup */ }
    throw err;
  }
}

export async function removeLock(lockPath: string, logger: Logger): Promise<void> {
  try {
    await unlink(lockPath);
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      logger.warn("daemon.lock.remove.failed", {
        lockPath,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }
}

/**
 * DOD-DAEMON-CLEANUP-1 (AC1) — remove the lock ONLY if it is still ours.
 *
 * An exiting daemon must not disarm a daemon it does not own. By the time we shut down, a DIFFERENT
 * daemon may have written this lock; deleting it would leave that healthy daemon unreachable
 * (`cello logout` reports "No daemon running") and the next `cello login` would spawn a third beside
 * it. That is the cascade — the obvious recovery action, killing the orphan, propagates the bug.
 *
 * `removeLock` (unconditional) is still correct for the CLI's stale-lock cleanup, where the lock
 * belongs to a process that is provably gone. It is NOT correct on the way out of a live daemon.
 */
export async function removeLockIfOwned(
  lockPath: string,
  ownPid: number,
  logger: Logger,
): Promise<void> {
  const lock = await readLock(lockPath);
  if (lock === null) {
    // readLock returns null for BOTH "absent" and "unparseable" — so this is the one place that
    // cannot tell "nothing to do" from "something is wrong". Distinguish them: a lock file that
    // exists but cannot be read (truncated by a full disk, a partial write) is left alone, because we
    // cannot prove it is ours — but it is said out loud rather than passed over in silence.
    try {
      await stat(lockPath);
      logger.warn("daemon.lock.unreadable", { ownPid, lockPath });
    } catch {
      // Genuinely absent. Nothing to remove, nothing to report.
    }
    return;
  }

  if (lock.pid !== ownPid) {
    // SI: a daemon that declines to remove a lock says so. Silence here is what made the live
    // incident so hard to see.
    logger.info("daemon.lock.not_ours", { ownPid, lockPid: lock.pid, lockPath });
    return;
  }

  await removeLock(lockPath, logger);
}

export function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}
