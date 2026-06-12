/**
 * CLI command implementations for the `cello` binary.
 *
 * Pseudocode:
 * 1. login(celloDir, daemonBin):
 *    - Call connectOrStart(celloDir) to either connect to existing or spawn new daemon
 *    - Print status (already running / started)
 *    - Close IPC connection and exit 0
 *
 * 2. logout(celloDir):
 *    - Read lock file to find socket path
 *    - Connect to daemon
 *    - Send 'shutdown' method
 *    - Wait for acknowledgement
 *    - Exit 0
 *
 * 3. status(celloDir):
 *    - Read lock file to find socket path
 *    - Connect to daemon
 *    - Send 'status' method
 *    - Print response as structured JSON
 *    - Exit 0
 */

import { join } from "node:path";
import {
  connectOrStart,
  connectToDaemon,
  readLock,
  type DaemonStatusResponse,
  type Logger,
} from "@cello-protocol/daemon";

export interface CommandResult {
  exitCode: number;
  output: string;
}

export async function login(
  celloDir: string,
  daemonBin: string,
  logger: Logger,
): Promise<CommandResult> {
  try {
    const result = await connectOrStart(celloDir, logger, daemonBin);
    result.client.close();

    if (result.alreadyRunning) {
      return { exitCode: 0, output: "Daemon already running." };
    }
    return { exitCode: 0, output: "Daemon started." };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { exitCode: 1, output: `Failed to start daemon: ${message}` };
  }
}

export async function logout(celloDir: string): Promise<CommandResult> {
  const lockFilePath = join(celloDir, "daemon.lock");
  const lock = await readLock(lockFilePath);

  if (!lock) {
    return { exitCode: 0, output: "No daemon running." };
  }

  try {
    const client = await connectToDaemon(lock.socketPath);
    await client.send("shutdown");
    client.close();
    return { exitCode: 0, output: "Daemon stopped." };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { exitCode: 1, output: `Failed to stop daemon: ${message}` };
  }
}

export async function status(celloDir: string): Promise<CommandResult> {
  const lockFilePath = join(celloDir, "daemon.lock");
  const lock = await readLock(lockFilePath);

  if (!lock) {
    return {
      exitCode: 1,
      output: JSON.stringify({ daemon: "stopped" }, null, 2),
    };
  }

  try {
    const client = await connectToDaemon(lock.socketPath);
    const result = (await client.send("status")) as DaemonStatusResponse;
    client.close();
    return { exitCode: 0, output: JSON.stringify(result, null, 2) };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      exitCode: 1,
      output: JSON.stringify({ daemon: "unreachable", error: message }, null, 2),
    };
  }
}
