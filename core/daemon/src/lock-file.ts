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

import { readFile, writeFile, rename, unlink } from "node:fs/promises";
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
  await rename(tmpPath, lockPath);
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

export function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}
