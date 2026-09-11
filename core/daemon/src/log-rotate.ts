import { openSync, renameSync, statSync } from "node:fs";

/**
 * DOD-M15-LOGBOUND-1 part B — bound `daemon.log` by rotating it at SPAWN.
 *
 * **The daemon does not own its log file, and that constraint decides the whole design.**
 * `spawnDaemon` does `openSync(logPath, "a")` and hands that descriptor to the child as stdout
 * and stderr. The daemon therefore writes to a file *handle*, not to a path: renaming the file
 * underneath it moves nothing, because the handle follows the inode and the daemon carries on
 * filling the renamed file.
 *
 * So the spawner is the only party that can rotate cleanly, and spawn is the only moment at
 * which nothing holds the handle. That is why this is here and not in the daemon, and it is why
 * {@link openLogHandle} does both steps in one function — the rotate-then-open ORDER is the
 * property, and a property split across two call sites is a property waiting to be reversed.
 *
 * **What this does NOT cover, deliberately:** a daemon that runs for weeks without restarting is
 * still unbounded, because this only fires at spawn. Closing that means the daemon policing its
 * own inherited handle, which is the complex half — `052-LOGCEILING`, suggested post-launch and
 * not yet ruled. Nothing here waits on it.
 */

/**
 * Cap for the live file: 64 MB. With one previous generation kept, the ceiling across restarts
 * is 128 MB.
 *
 * A starting point rather than a finding. For scale: the measured file was 176 MB, of which 168 MB
 * was one repeated line that part A of this unit now collapses, and the ordinary remainder grew at
 * roughly 3 MB/day under heavy development.
 */
export const LOG_ROTATE_CAP_BYTES = 64 * 1024 * 1024;

/** Name of the single previous generation. There is deliberately no `.2`. */
function rotatedPathFor(logPath: string): string {
  return `${logPath}.1`;
}

/**
 * Rename `logPath` to `logPath.1` if it is over `capBytes`, replacing any older `.1`.
 *
 * Returns whether a rotation happened. **Never throws**, and that is a contract rather than
 * defensiveness: a daemon that refuses to start because it could not tidy its log would be a
 * strictly worse outcome than an oversized log. Both failure modes here — the file not existing
 * (the first ever spawn) and the rename failing (permissions, a read-only directory) — leave the
 * caller free to open the path exactly as it does today.
 *
 * **It never truncates.** A truncation of the live file either races the writer or throws away
 * the tail, and the tail is the only part anyone reads.
 */
export function rotateLogIfOversized(logPath: string, capBytes: number = LOG_ROTATE_CAP_BYTES): boolean {
  try {
    if (statSync(logPath).size <= capBytes) return false;
    renameSync(logPath, rotatedPathFor(logPath));
    return true;
  } catch {
    // ENOENT on the first spawn, EACCES/EROFS/EXDEV on a rename that cannot happen. None of
    // them is a reason to fail a daemon start.
    return false;
  }
}

/**
 * Rotate if needed, THEN open the log for append and return the descriptor.
 *
 * The ordering is the point. Open first and the rename moves only the name, leaving the daemon
 * writing into the renamed inode — the rotation would appear to work and bound nothing.
 */
export function openLogHandle(logPath: string, capBytes: number = LOG_ROTATE_CAP_BYTES): number {
  rotateLogIfOversized(logPath, capBytes);
  return openSync(logPath, "a");
}
