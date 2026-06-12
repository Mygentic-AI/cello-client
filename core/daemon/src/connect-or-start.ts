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
      } catch {
        // Socket exists but connection failed — daemon is in a bad state
        // Remove stale lock and start fresh
        logger.info("daemon.lock.stale", {
          pid: lock.pid,
          reason: "socket_unreachable",
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
  return new Promise<IpcClient>((resolve, reject) => {
    const child = spawn(process.execPath, [daemonBin], {
      detached: true,
      stdio: ["ignore", "pipe", "ignore"],
      env: {
        ...process.env,
        CELLO_DIR: celloDir,
      },
    });

    let stdoutBuf = "";
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error("Daemon failed to start within 10 seconds"));
    }, 10_000);

    child.stdout!.on("data", (chunk: Buffer) => {
      stdoutBuf += chunk.toString("utf-8");
      // Look for daemon.started event line
      const lines = stdoutBuf.split("\n");
      for (const line of lines) {
        if (line.trim().length === 0) continue;
        try {
          const event = JSON.parse(line) as Record<string, unknown>;
          if (event.event === "daemon.started") {
            clearTimeout(timeout);
            child.stdout!.removeAllListeners();
            child.unref();
            // Connect to the newly started daemon
            const socketPath = event.ipcSocketPath as string;
            connectToDaemon(socketPath).then(resolve).catch(reject);
            return;
          }
          if (event.event === "daemon.startup.failed") {
            clearTimeout(timeout);
            child.stdout!.removeAllListeners();
            reject(new Error(event.error as string || "Daemon startup failed"));
            return;
          }
        } catch {
          // Not JSON — ignore
        }
      }
    });

    child.on("error", (err: Error) => {
      clearTimeout(timeout);
      reject(err);
    });

    child.on("exit", (code: number | null) => {
      clearTimeout(timeout);
      if (code !== 0) {
        reject(new Error(`Daemon exited with code ${code}`));
      }
    });
  });
}
