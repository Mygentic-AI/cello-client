import { openSync, renameSync, statSync, writeSync } from "node:fs";
import { extractErrorMessage } from "./error-message.js";

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
 * **⚠️ WHAT THIS DOES NOT BOUND, and it is the machines that need it most.** Rotation fires only
 * on the `connectOrStart` path, which is how an operator's CLI starts the daemon. The demo box and
 * the Hermes box start it under systemd, running `dist/bin/cello-daemon.js` directly — that path
 * never reaches here, so **those two long-lived daemons are not bounded by this at all**. They are
 * also the ones that run for weeks without restarting, which is the case
 * `052-LOGCEILING` covers (suggested post-launch, not yet ruled). Stated here rather than left to
 * be discovered, because "rotation shipped" would otherwise read as a bound that those machines have.
 */

/**
 * Cap for the live file: 64 MB. With one previous generation kept, the ceiling across restarts
 * is 128 MB.
 *
 * A starting point rather than a finding. For scale: the measured file was 180 MB, of which 168 MB
 * was one repeated line that part A of this unit now collapses, and the ordinary remainder grew at
 * roughly 3 MB/day under heavy development.
 */
export const LOG_ROTATE_CAP_BYTES = 64 * 1024 * 1024;

/** Name of the single previous generation. There is deliberately no `.2`. */
function rotatedPathFor(logPath: string): string {
  return `${logPath}.1`;
}

function sizeOf(path: string): number | null {
  try {
    return statSync(path).size;
  } catch {
    return null;
  }
}

/** What a rotation attempt did, so the caller can put it on the record either way. */
export type RotateOutcome =
  | { rotated: true; bytes: number; rotatedTo: string }
  | { rotated: false; reason: "under_cap" | "absent" | "raced" | "failed"; error?: string };

/**
 * Rename `logPath` to `logPath.1` if it is over `capBytes`, replacing any older `.1`.
 *
 * **Never throws**, and that is a contract rather than defensiveness: a daemon that refuses to
 * start because it could not tidy its log would be a strictly worse outcome than an oversized log.
 * It reports what happened instead of being silent about it — see {@link openLogHandle}, which is
 * where the reporting lands.
 *
 * **It never truncates.** A truncation of the live file either races the writer or throws away
 * the tail, and the tail is the only part anyone reads.
 */
export function rotateLogIfOversized(logPath: string, capBytes: number = LOG_ROTATE_CAP_BYTES): RotateOutcome {
  const size = sizeOf(logPath);
  if (size === null) return { rotated: false, reason: "absent" };
  if (size <= capBytes) return { rotated: false, reason: "under_cap" };

  /**
   * ⚠️ RE-STAT IMMEDIATELY BEFORE THE RENAME, because rotation is the one thing on this path that
   * the singleton lock does NOT cover. `connectOrStart` states plainly that two callers can probe
   * the lock as free at the same instant and both spawn. Both then arrive here. The damaging
   * interleaving is: B sees an oversized file, A renames it to `.1` and opens a fresh one, then B
   * renames that fresh near-empty file over `.1` — and 64 MB of retained history is replaced by a
   * few bytes, losing exactly the tail rotation exists to keep. The window is small and the loser
   * exits seconds later, but the cost of losing is the whole point of the feature.
   */
  const stillOversized = sizeOf(logPath);
  if (stillOversized === null || stillOversized <= capBytes) return { rotated: false, reason: "raced" };

  // And never let a smaller file replace a larger kept generation, whatever the reason.
  const kept = sizeOf(rotatedPathFor(logPath));
  if (kept !== null && kept > stillOversized) return { rotated: false, reason: "raced" };

  try {
    renameSync(logPath, rotatedPathFor(logPath));
    return { rotated: true, bytes: stillOversized, rotatedTo: rotatedPathFor(logPath) };
  } catch (err) {
    // EACCES / EROFS / EXDEV — a read-only or wrong-owner ~/.cello. None of them is a reason to
    // fail a daemon start, and all of them mean this machine has no bound at all.
    return { rotated: false, reason: "failed", error: extractErrorMessage(err) };
  }
}

/**
 * Rotate if needed, THEN open the log for append and return the descriptor.
 *
 * The ordering is the point. Open first and the rename moves only the name, leaving the daemon
 * writing into the renamed inode — the rotation would appear to work and bound nothing.
 *
 * **The outcome is written as the first line of the fresh file**, because the alternative is a log
 * that starts mid-story. Someone sent a 4 MB `daemon.log` to chase a failure that began before the
 * restart has no way to know that `daemon.log.1` exists unless the file says so. And a rotation
 * that FAILED has to say so loudest of all: it means the bound this unit ships does not exist on
 * this machine, and nothing else would ever mention it.
 */
export function openLogHandle(logPath: string, capBytes: number = LOG_ROTATE_CAP_BYTES): number {
  const outcome = rotateLogIfOversized(logPath, capBytes);
  const fd = openSync(logPath, "a");
  if (outcome.rotated) {
    writeNotice(fd, {
      level: "info", event: "daemon.log.rotated",
      bytes: outcome.bytes, rotatedTo: outcome.rotatedTo,
      impact: "everything logged before this line is in the file named by rotatedTo",
    });
  } else if (outcome.reason === "failed") {
    writeNotice(fd, {
      level: "warn", event: "daemon.log.rotate.failed",
      reason: outcome.reason, error: outcome.error ?? "",
      impact: "daemon.log is over its cap and could not be rotated, so it is unbounded on this machine",
    });
  }
  return fd;
}

function writeNotice(fd: number, fields: Record<string, unknown>): void {
  try {
    writeSync(fd, JSON.stringify({ ...fields, ts: new Date().toISOString() }) + "\n");
  } catch {
    // The notice is the least important thing this function does. Failing to write it must not
    // cost the caller its descriptor.
  }
}
