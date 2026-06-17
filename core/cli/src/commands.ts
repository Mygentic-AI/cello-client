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

/**
 * register(celloDir, agent, preAuthToken, phoneStub):
 *  - Read lock file to find socket path (daemon must be running)
 *  - Connect to daemon, send 'cello_register' with { agent, preAuthToken, phoneStub }
 *  - The daemon runs ML-DSA keygen → FROST DKG → register_success and persists
 *    the agent's key material + registration state + agent→user link.
 *  - Print structured JSON; exit 0 on success, 1 on failure.
 */
export async function register(
  celloDir: string,
  agent: string,
  preAuthToken: string,
  phoneStub = "",
): Promise<CommandResult> {
  if (!agent || !preAuthToken) {
    return {
      exitCode: 1,
      output: "Usage: cello register <agent> <preAuthToken>  (or set CELLO_PREAUTH_TOKEN). The pre-authorization ticket comes from the CELLO Operations Agent.",
    };
  }

  const lockFilePath = join(celloDir, "daemon.lock");
  const lock = await readLock(lockFilePath);
  if (!lock) {
    return { exitCode: 1, output: "No daemon running. Run 'cello login' first, then retry registration." };
  }

  try {
    const client = await connectToDaemon(lock.socketPath);
    const result = (await client.send("cello_register", { agent, preAuthToken, phoneStub })) as {
      ok: boolean;
      reason?: string;
      guidance?: string;
      agent_id?: string;
      primary_pubkey?: string;
    };
    client.close();

    if (!result.ok) {
      return {
        exitCode: 1,
        output: JSON.stringify({ ok: false, reason: result.reason, guidance: result.guidance }, null, 2),
      };
    }
    return {
      exitCode: 0,
      output: JSON.stringify(
        { ok: true, agent_id: result.agent_id, primary_pubkey: result.primary_pubkey },
        null,
        2,
      ),
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { exitCode: 1, output: `Failed to register: ${message}` };
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
