/**
 * Connect-or-start logic for the CELLO daemon.
 *
 * Pseudocode:
 * 1. connectOrStart(celloDir, logger):
 *    a. Try to connect to the daemon socket. If it answers, we are done.
 *    b. Otherwise ask the KERNEL whether a daemon holds the singleton lock (DOD-SINGLE-DAEMON-1):
 *       - HELD  → a daemon is alive but not answering (mid-startup, or its socket was destroyed).
 *                 Retry the connection, then fail loudly. NEVER spawn a second daemon beside it,
 *                 and never delete its lock.
 *       - FREE  → no daemon is running, whatever daemon.lock claims. Clear the stale lock, spawn,
 *                 and wait for the socket to accept connections.
 *
 * The lock FILE is not consulted to make this decision — only the OS lock is. A pid in a JSON file
 * can be dead, or REUSED by an unrelated process (in which case `isProcessAlive` says "alive"
 * forever, and a daemon that trusted it would never start again).
 */

import { spawn } from "node:child_process";
import { openSync } from "node:fs";
import { mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { readLock, removeLock } from "./lock-file.js";
import { probeSingletonLock, SINGLETON_LOCK_FILENAME, EXIT_ALREADY_RUNNING } from "./singleton-lock.js";
import { connectToDaemon, type IpcClient } from "./ipc-client.js";
import type { Logger } from "./types.js";

export interface ConnectResult {
  client: IpcClient;
  alreadyRunning: boolean;
}

export async function connectOrStart(
  celloDir: string,
  logger: Logger,
  daemonBin: string,
): Promise<ConnectResult> {
  // A CELLO_DIR that does not exist yet (first ever run) would make the singleton probe below fail to
  // open its lock file, and "I could not ask the kernel" would be reported as "I don't know whether a
  // daemon is running" — a blind spot invented out of an empty directory. Create it first; the daemon
  // does the same on startup, so this changes nothing except the quality of the answer.
  await mkdir(celloDir, { recursive: true });

  const lockFilePath = join(celloDir, "daemon.lock");
  const lock = await readLock(lockFilePath);
  // The socket path is deterministic; the lock's copy is metadata, and it may be stale.
  const socketPath = lock?.socketPath ?? join(celloDir, "daemon.sock");

  // 1. If a daemon is answering, we are done. This is the overwhelmingly common path.
  try {
    return { client: await connectToDaemon(socketPath), alreadyRunning: true };
  } catch {
    // Not answering. WHY it is not answering is the whole question — see below.
  }

  // 2. Ask the KERNEL whether a daemon is alive, not `daemon.lock`.
  //
  // DOD-SINGLE-DAEMON-1 (AC3): the old code asked `isProcessAlive(lock.pid)` and, when the socket
  // did not answer, called the lock "stale", deleted it, and spawned a second daemon onto the live
  // one's database. Both of its beliefs were unreliable: a pid can be REUSED (so a dead daemon's lock
  // looks alive forever), and a live daemon can legitimately not answer yet (it is mid-startup, or an
  // exiting orphan deleted its socket). The lock file cannot tell these apart. The OS lock can.
  const probe = probeSingletonLock(celloDir, logger);

  if (probe === "held") {
    // A daemon is holding the lock right now. Spawning beside it is never correct. It may simply be
    // mid-startup, so give it a moment to come up.
    const client = await connectWithRetry(celloDir, socketPath, logger, lock?.pid ?? null);
    return { client, alreadyRunning: true };
  }

  if (probe === "unknown") {
    // We could not ask the kernel. That is NOT permission to spawn: "I don't know whether a daemon is
    // running" must never be resolved by starting a second one. Fail loud with the real reason.
    throw new Error(
      "Could not determine whether a daemon is already running (the singleton lock could not be " +
      `checked at ${celloDir}). Refusing to start a second daemon on a guess. See the ` +
      "daemon.singleton.probe.failed log line for the underlying error.",
    );
  }

  // 3. The lock is genuinely free, so no daemon is running — whatever `daemon.lock` claims. Only now
  //    is spawning correct.
  if (lock) {
    logger.info("daemon.lock.stale", { pid: lock.pid, reason: "no_singleton_holder" });
    await removeLock(lockFilePath, logger);
  }
  const client = await spawnDaemon(celloDir, daemonBin, lockFilePath, logger);
  return { client, alreadyRunning: false };
}

/**
 * A daemon holds the singleton lock but is not answering. Wait for it, then fail LOUDLY.
 *
 * The loud failure is the point (SI). The alternative — the old behaviour — was to quietly start a
 * second daemon, which is the very thing that gives one machine two writers on one hash chain. An
 * operator who is told "a daemon is running but not answering" can act; an operator silently given a
 * second daemon cannot even see the problem.
 */
async function connectWithRetry(
  celloDir: string,
  socketPath: string,
  logger: Logger,
  holderPid: number | null,
): Promise<IpcClient> {
  const deadline = Date.now() + 10_000;
  let lastError: unknown;
  while (Date.now() < deadline) {
    try {
      return await connectToDaemon(socketPath);
    } catch (err: unknown) {
      lastError = err;
      await new Promise((r) => setTimeout(r, 150));
    }
  }
  logger.error("daemon.unreachable", { holderPid, socketPath });
  // The pid comes from daemon.lock — the very file this unit exists because it cannot be trusted. It
  // may be stale, or name a process that merely inherited the number. So it is offered as a hint, and
  // the operator is pointed at the authoritative answer: whoever holds the lock file open IS the
  // daemon. Telling someone to `kill` an unverified pid is how you get them to kill something else.
  const hint = holderPid === null ? "" : ` (daemon.lock names pid ${holderPid}, which may be stale)`;
  throw new Error(
    `A daemon is already running${hint} and holds the singleton lock, but is not answering on ` +
    `${socketPath} (${lastError instanceof Error ? lastError.message : String(lastError)}). ` +
    "Refusing to start a second daemon beside it — two daemons on one database is the failure this " +
    `prevents. To find the real holder: \`lsof ${join(celloDir, SINGLETON_LOCK_FILENAME)}\`, then stop ` +
    "that process and try again.",
  );
}

async function spawnDaemon(
  celloDir: string,
  daemonBin: string,
  lockFilePath: string,
  logger: Logger,
): Promise<IpcClient> {
  const socketPath = join(celloDir, "daemon.sock");
  const logPath = join(celloDir, "daemon.log");

  // The daemon's stdout/stderr go to a LOG FILE, never a pipe to this process.
  // A pipe (the previous design) breaks the moment the cli exits after reading the
  // daemon.started line — the daemon's next log write (e.g. directory.signaling.connected)
  // then hits a broken pipe and, with no stdout 'error' handler, EPIPE-crashes it. The
  // daemon would "start" and die a second later → ECONNREFUSED on the socket. Writing to
  // a file also gives operators a durable ~/.cello/daemon.log to debug from.
  const out = openSync(logPath, "a");
  const child = spawn(process.execPath, [daemonBin], {
    detached: true,
    stdio: ["ignore", out, out],
    env: {
      ...process.env,
      CELLO_DIR: celloDir,
    },
  });
  child.unref();

  // Readiness is detected by polling the IPC socket (deterministic path:
  // celloDir/daemon.sock) until the daemon is accepting connections — not by reading
  // stdout, which is now the log file. Track spawn/exit so we fail fast with context.
  let spawnError: Error | null = null;
  let exitCode: number | null | undefined;
  child.on("error", (err: Error) => { spawnError = err; });
  child.on("exit", (code: number | null) => { exitCode = code; });

  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (spawnError) throw spawnError;
    try {
      return await connectToDaemon(socketPath);
    } catch {
      // Not accepting yet (ENOENT/ECONNREFUSED). If the child has already exited, it
      // died during startup — surface the log tail rather than spinning to the deadline.
      if (exitCode !== undefined) {
        // ...unless it exited because it LOST THE SINGLETON RACE. Two callers can legitimately probe
        // "free" at the same instant (the probe is not a reservation) and both spawn; the kernel then
        // picks exactly one winner and the other exits EXIT_ALREADY_RUNNING. That is the design
        // working, not a failure: a healthy daemon is coming up right now. Reporting "Daemon exited
        // (code 3) during startup" to an operator whose daemon is fine would be this unit's own lie.
        // The distinct exit code exists precisely so we can tell these apart — so use it.
        if (exitCode === EXIT_ALREADY_RUNNING) {
          const winner = await readLock(lockFilePath);
          logger.info("daemon.spawn.lost_race", { holderPid: winner?.pid ?? null });
          return await connectWithRetry(celloDir, socketPath, logger, winner?.pid ?? null);
        }
        throw new Error(`Daemon exited (code ${exitCode}) during startup.\n${await daemonLogTail(logPath)}`);
      }
      await new Promise((r) => setTimeout(r, 150));
    }
  }
  throw new Error(`Daemon failed to start within 10 seconds.\n${await daemonLogTail(logPath)}`);
}

async function daemonLogTail(logPath: string): Promise<string> {
  try {
    const lines = (await readFile(logPath, "utf-8")).split("\n").filter((l) => l.trim().length > 0);
    return `--- daemon.log (last 15 lines) ---\n${lines.slice(-15).join("\n")}`;
  } catch {
    return `(no daemon.log at ${logPath})`;
  }
}
