/**
 * Connect-or-start logic for the CELLO daemon.
 *
 * Pseudocode:
 * 1. connectOrStart(celloDir, logger):
 *    a. Read lock file at ~/.cello/daemon.lock
 *    b. If lock exists:
 *       - Check if PID is alive (signal 0)
 *       - If alive, attempt to connect to socket
 *       - If connection succeeds, return existing daemon client
 *       - If connection fails (socket gone), remove stale lock and start fresh
 *    c. If lock doesn't exist or is stale:
 *       - Remove stale lock (log daemon_lock_stale_removed)
 *       - Spawn daemon as detached child process
 *       - Wait for daemon.started event (read from child stdout)
 *       - Return client connected to new daemon
 */

import { spawn } from "node:child_process";
import { openSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { readLock, removeLock, isProcessAlive } from "./lock-file.js";
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
  const lockFilePath = join(celloDir, "daemon.lock");

  // Read existing lock
  const lock = await readLock(lockFilePath);

  if (lock) {
    if (isProcessAlive(lock.pid)) {
      // Try connecting to the existing daemon
      try {
        const client = await connectToDaemon(lock.socketPath);
        return { client, alreadyRunning: true };
      } catch (err: unknown) {
        logger.info("daemon.lock.stale", {
          pid: lock.pid,
          reason: "socket_unreachable",
          error: err instanceof Error ? err.message : String(err),
        });
        await removeLock(lockFilePath, logger);
      }
    } else {
      // PID is dead — stale lock
      logger.info("daemon.lock.stale", {
        pid: lock.pid,
        reason: "process_dead",
      });
      await removeLock(lockFilePath, logger);
    }
  }

  // Start a new daemon
  const client = await spawnDaemon(celloDir, daemonBin, lockFilePath, logger);
  return { client, alreadyRunning: false };
}

async function spawnDaemon(
  celloDir: string,
  daemonBin: string,
  _lockFilePath: string,
  _logger: Logger,
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
