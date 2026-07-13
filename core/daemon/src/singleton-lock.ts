/**
 * DOD-SINGLE-DAEMON-1 — the daemon singleton, enforced by the kernel.
 *
 * `daemon.lock` is a JSON file, and a file cannot answer "is a daemon running?". Anyone may delete
 * it; a `kill -9` leaves it behind naming a pid that is dead — or, worse, one the OS has since REUSED
 * for an unrelated process, which makes `isProcessAlive()` say "yes" forever. Every stale-lock
 * heuristic ever written is an attempt to guess what only the kernel actually knows.
 *
 * So we ask the kernel. The daemon takes a real POSIX write lock (`fcntl`) on a dedicated file and
 * holds it for its entire lifetime. Two processes cannot hold it at once, and the kernel drops it the
 * instant the holder dies — SIGKILL, panic, `kill -9`, however it goes. There is no stale state to
 * clean up and no recovery step to get wrong.
 *
 * ## Why SQLite is the lock
 *
 * Node has no `flock`. `fs.constants.O_EXLOCK` exists only on macOS/BSD — using it would leave every
 * Linux operator (including the EC2 demo agent) with NO lock at all, which is worse than none because
 * it looks like one. A native `flock` addon (`fs-ext`) compiles from source, and install time is a
 * cost every operator pays on every version bump (see CLAUDE.md — the client is a heavy local node,
 * not a thin wrapper).
 *
 * `@signalapp/sqlcipher` is already a daemon dependency, ships prebuilt (no compile), and SQLite's
 * whole business is taking correct `fcntl` locks on every POSIX platform. `locking_mode = exclusive`
 * plus one header write acquires the exclusive lock and holds it until the connection closes. A
 * second process gets SQLITE_BUSY immediately (`busy_timeout = 0`). SQLite also tracks locks per
 * inode inside the process, so this correctly refuses a second daemon in the SAME process too —
 * which raw `fcntl`, whose locks are per-process, would not.
 *
 * The lock database holds no rows and never will. It is a mutex that happens to be spelled in SQL.
 *
 * ## The division of labour with daemon.lock (AC4)
 *
 * The OS lock DECIDES whether a daemon may start. `daemon.lock` only SUPPLIES METADATA — it is how we
 * learn the holder's pid to name in the error, because `fcntl` will not tell us. If the JSON is
 * missing, stale, or lying, the worst outcome is a less specific error message. It can never admit a
 * second daemon, and it can never wedge a legitimate one out.
 *
 * ## The one constraint
 *
 * `~/.cello` must live on a LOCAL filesystem. POSIX `fcntl` locks are advisory-but-honoured on local
 * filesystems (APFS, ext4, xfs — macOS and the Linux hosts we run on); on NFSv3 without a working
 * `lockd`, and on some 9p/WSL2 setups, they can silently degrade to no-ops. There, two daemons would
 * both "acquire" and the singleton would be absent while appearing present. We do not attempt to
 * detect this — a real self-test needs a second process, which is far too much to do at every startup.
 * The lock path is logged in `daemon.singleton.acquired` so an operator debugging a two-daemon
 * situation can see exactly which file the kernel was asked about.
 */

import { join } from "node:path";
import { readFileSync } from "node:fs";
import { loadSignalModule, type SignalDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

/** The file the kernel lock is taken on. Holds no data — see the note above. */
export const SINGLETON_LOCK_FILENAME = "daemon.singleton";

export class DaemonAlreadyRunningError extends Error {
  /** The pid from `daemon.lock`, or null when that file is absent/unreadable/malformed. */
  readonly holderPid: number | null;

  constructor(holderPid: number | null) {
    super(
      holderPid === null
        ? "another daemon is already running (pid unknown — daemon.lock is missing or unreadable)"
        : `another daemon is already running (pid ${holderPid})`,
    );
    this.name = "DaemonAlreadyRunningError";
    this.holderPid = holderPid;
  }
}

export interface SingletonLock {
  /** Release the lock. The kernel would do this on process exit anyway; this is for in-process use. */
  release(): void;
}

/**
 * Read the holder's pid from the advisory `daemon.lock`. METADATA ONLY (AC4): this pid is used to
 * write a better error message and for nothing else. It never decides anything, so a stale or absent
 * file costs us a specific error message, never correctness.
 */
function readHolderPid(celloDir: string): number | null {
  try {
    const parsed = JSON.parse(readFileSync(join(celloDir, "daemon.lock"), "utf-8")) as Record<string, unknown>;
    return typeof parsed.pid === "number" ? parsed.pid : null;
  } catch {
    return null;
  }
}

function isBusy(err: unknown): boolean {
  const code = (err as { code?: unknown } | null)?.code;
  return typeof code === "string" && code.startsWith("SQLITE_BUSY");
}

/**
 * Take the exclusive OS lock for `celloDir`, or throw `DaemonAlreadyRunningError` if another process
 * holds it. Returns a handle that holds the lock until `release()` (or process death).
 *
 * Call this BEFORE opening the database, registering agents, or connecting to the directory (AC2):
 * a daemon that loses the race must do NONE of those things.
 */
/**
 * How long a STARTING daemon will wait for a contended lock before giving up.
 *
 * Not zero, and the reason is subtle. `probeSingletonLock()` does not read the lock — it TAKES it and
 * drops it. That means a probe (a concurrent `cello login`, a shim, a status check) holds the
 * exclusive lock for the few milliseconds it takes to open the file and write the header. With a zero
 * timeout, a daemon that reaches its acquisition inside that window would get SQLITE_BUSY and exit
 * "another daemon is already running" — when no other daemon exists at all. A read-only question must
 * never be able to kill the thing it is asking about.
 *
 * A genuine second daemon still loses within this bound, which is what AC2's "immediately" is for.
 */
const DAEMON_ACQUIRE_BUSY_TIMEOUT_MS = 3000;

/**
 * How long a PROBE waits before concluding the lock is held.
 *
 * Also not zero, and for the mirror of the reason above. A probe takes the lock too, so two probes
 * can collide with each other: a second `cello login`, or the MCP shim autostarting while the
 * operator types `cello login`. With a zero timeout the loser of that collision would report "held"
 * — i.e. "a daemon is already running" — when there is no daemon at all, and the caller would sit in
 * connectWithRetry for ten seconds before failing with a confident lie. That is precisely the class
 * of wrong-but-certain statement this whole story exists to abolish.
 *
 * A REAL daemon holds the lock forever, so waiting a little costs a probe nothing in the case that
 * matters — it still times out and still correctly answers "held". A transient probe-vs-probe
 * collision, meanwhile, resolves in milliseconds. Strictly better than zero in both directions.
 */
const PROBE_BUSY_TIMEOUT_MS = 500;

/** The daemon binary's exit code when it loses the singleton race — distinct from 1 = "broken". */
export const EXIT_ALREADY_RUNNING = 3;

function openLockDb(lockDbPath: string): SignalDatabase {
  const mod = loadSignalModule();
  const Ctor = mod.Database ?? mod.default;
  try {
    return new Ctor(lockDbPath);
  } catch (err: unknown) {
    // The file could not be opened at all (permissions, unwritable dir). NOT a contended lock —
    // never let this be mistaken for "a daemon is running".
    throw new Error(
      `Could not open the daemon singleton lock at ${lockDbPath}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

export function acquireSingletonLock(
  celloDir: string,
  logger: Logger,
  busyTimeoutMs: number = DAEMON_ACQUIRE_BUSY_TIMEOUT_MS,
): SingletonLock {
  const lockDbPath = join(celloDir, SINGLETON_LOCK_FILENAME);
  const db = openLockDb(lockDbPath);

  try {
    db.pragma(`busy_timeout = ${busyTimeoutMs}`);
    db.pragma("locking_mode = exclusive");
    // SQLite defers the actual lock acquisition until it has a reason to write. `user_version` is a
    // write to the database header — it takes the exclusive lock and stores nothing.
    db.pragma("user_version = 1");
  } catch (err: unknown) {
    try { db.close(); } catch { /* we are already failing; closing is best-effort */ }
    if (isBusy(err)) {
      const holderPid = readHolderPid(celloDir);
      logger.info("daemon.singleton.contended", { holderPid, lockPath: lockDbPath });
      throw new DaemonAlreadyRunningError(holderPid);
    }
    // Some other SQLite failure. Keep the frame — a bare SQLITE_* error here reads as a database
    // problem, when what actually failed was taking the singleton lock.
    throw new Error(
      `Could not take the daemon singleton lock at ${lockDbPath}: ${err instanceof Error ? err.message : String(err)}`,
      { cause: err },
    );
  }

  logger.info("daemon.singleton.acquired", { pid: process.pid, lockPath: lockDbPath });

  let released = false;
  return {
    release(): void {
      if (released) return;
      released = true;
      try {
        db.close();
      } catch (err: unknown) {
        logger.warn("daemon.singleton.release.failed", {
          error: err instanceof Error ? err.message : String(err),
        });
      }
    },
  };
}

/**
 * Is a daemon holding the lock for `celloDir` right now?
 *
 *   "held"    — a daemon is alive. Connect to it; never spawn beside it.
 *   "free"    — no daemon is running, whatever `daemon.lock` claims. Spawning is correct.
 *   "unknown" — we could not ask the kernel (native module missing, directory unreadable).
 *
 * The third answer is the point. "I could not determine whether a daemon is running" and "no daemon is
 * running" are different facts, and collapsing them into one boolean means the caller spawns on both —
 * so the one case where we are blind becomes the one case we start a second daemon. Callers must
 * refuse to spawn on "unknown" and surface the underlying error instead.
 *
 * Asking the kernel rather than trusting `daemon.lock` is also what makes a REUSED pid harmless: a
 * stale lock file naming a live-but-unrelated process would otherwise wedge `cello login` forever.
 *
 * The probe takes the lock and immediately drops it. The gap between the probe and a subsequent spawn
 * is safe: the daemon we spawn acquires the lock authoritatively and exits EXIT_ALREADY_RUNNING if it
 * loses that race — and the caller reads that exit code as "someone else won, connect to them", never
 * as a failure. Two probes can therefore both say "free" and both spawn, and exactly one daemon
 * survives.
 */
export function probeSingletonLock(celloDir: string, logger: Logger): "held" | "free" | "unknown" {
  try {
    acquireSingletonLock(celloDir, logger, PROBE_BUSY_TIMEOUT_MS).release();
    return "free";
  } catch (err: unknown) {
    if (err instanceof DaemonAlreadyRunningError) return "held";
    logger.warn("daemon.singleton.probe.failed", {
      error: err instanceof Error ? err.message : String(err),
    });
    return "unknown";
  }
}
