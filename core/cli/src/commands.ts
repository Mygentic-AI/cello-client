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

/**
 * createAgent(celloDir, name):
 *  - Connect to the daemon, send 'cello_create_agent' with { name }.
 *  - The daemon generates a fresh K_local seed, writes it as an `agents` row in the encrypted DB
 *    (PERSIST-002 — no key file), and wires the agent in so it can be registered immediately.
 */
export async function createAgent(celloDir: string, name: string): Promise<CommandResult> {
  if (!name) {
    return { exitCode: 1, output: "Usage: cello create-agent <name>  — creates a new local agent identity." };
  }

  const lockFilePath = join(celloDir, "daemon.lock");
  const lock = await readLock(lockFilePath);
  if (!lock) {
    return { exitCode: 1, output: "No daemon running. Run 'cello login' first, then retry create-agent." };
  }

  try {
    const client = await connectToDaemon(lock.socketPath);
    const result = (await client.send("cello_create_agent", { name })) as {
      ok: boolean;
      reason?: string;
      guidance?: string;
      name?: string;
      pubkey?: string;
      agentId?: string;
    };
    client.close();

    if (!result.ok) {
      return { exitCode: 1, output: JSON.stringify({ ok: false, reason: result.reason, guidance: result.guidance }, null, 2) };
    }
    return {
      exitCode: 0,
      output: JSON.stringify({ ok: true, name: result.name, pubkey: result.pubkey, agentId: result.agentId }, null, 2),
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { exitCode: 1, output: `Failed to create agent: ${message}` };
  }
}

/**
 * refreshShares(celloDir, name): M8B DOD-REFRESH-1.
 *  - Connect to the daemon, send 'cello_refresh_shares' with { name }.
 *  - The daemon runs a proactive share refresh across the consortium: every shareholder rotates its
 *    share to a new epoch, the group public key is unchanged, and old-epoch shares no longer sign.
 */
export async function refreshShares(celloDir: string, name: string): Promise<CommandResult> {
  if (!name) {
    return { exitCode: 1, output: "Usage: cello refresh <name>  — proactively refresh the agent's threshold shares (new epoch)." };
  }
  const lockFilePath = join(celloDir, "daemon.lock");
  const lock = await readLock(lockFilePath);
  if (!lock) {
    return { exitCode: 1, output: "No daemon running. Run 'cello login' first, then retry refresh." };
  }
  try {
    const client = await connectToDaemon(lock.socketPath);
    const result = (await client.send("cello_refresh_shares", { name })) as {
      ok: boolean;
      reason?: string;
      guidance?: string;
      epoch?: number;
      primary_pubkey?: string;
    };
    client.close();
    if (!result.ok) {
      return { exitCode: 1, output: JSON.stringify({ ok: false, reason: result.reason, guidance: result.guidance }, null, 2) };
    }
    return {
      exitCode: 0,
      output: JSON.stringify({ ok: true, epoch: result.epoch, primary_pubkey: result.primary_pubkey }, null, 2),
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { exitCode: 1, output: `Failed to refresh shares: ${message}` };
  }
}

/**
 * removeAgent(celloDir, name) — CELLO-M7-REMOVE-001 (DOD-REMOVE-1):
 *  - Connect to the daemon, send 'cello_remove_agent' with { name }.
 *  - The daemon RETIRES the agent (state=retired; row, keys, and history KEPT for accountability) and
 *    FREES the human name for reuse. One-way.
 */
export async function removeAgent(celloDir: string, name: string): Promise<CommandResult> {
  if (!name) {
    return { exitCode: 1, output: "Usage: cello remove-agent <name>  — retires a local agent (one-way) and frees its name." };
  }

  const lockFilePath = join(celloDir, "daemon.lock");
  const lock = await readLock(lockFilePath);
  if (!lock) {
    return { exitCode: 1, output: "No daemon running. Run 'cello login' first, then retry remove-agent." };
  }

  try {
    const client = await connectToDaemon(lock.socketPath);
    const result = (await client.send("cello_remove_agent", { name })) as {
      ok: boolean;
      reason?: string;
      guidance?: string;
      name?: string;
      agentId?: string;
      oneWay?: boolean;
      directoryRevocation?: string;
    };
    client.close();

    if (!result.ok) {
      return { exitCode: 1, output: JSON.stringify({ ok: false, reason: result.reason, guidance: result.guidance }, null, 2) };
    }
    return {
      exitCode: 0,
      output: JSON.stringify(
        {
          ok: true,
          name: result.name,
          agentId: result.agentId,
          oneWay: result.oneWay,
          // DOD-REMOVE-2: whether the signed revocation was recorded at the directory (recorded /
          // deferred — directory unreachable / skipped — never registered). The daemon's guidance
          // carries the actionable detail.
          directoryRevocation: result.directoryRevocation,
          message: result.guidance ?? "Agent retired (one-way). Its identity and history are kept; the name is free to reuse.",
        },
        null,
        2,
      ),
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { exitCode: 1, output: `Failed to remove agent: ${message}` };
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

export type SessionFilter = "open" | "closed" | "failed" | "all";

/**
 * `cello sessions [--open|--closed|--failed|--all] [--limit N]` — the full, queryable session
 * history (the discovery surface `cello status` deliberately does NOT dump). Defaults to OPEN
 * (live + resumable) so a long-lived agent's failed/closed history doesn't flood it, and caps the
 * count at the daemon's default limit. Output reports `totalMatched` so the operator can tell when
 * results were truncated.
 */
export async function sessions(
  celloDir: string,
  opts: { filter?: SessionFilter; limit?: number } = {},
): Promise<CommandResult> {
  const lockFilePath = join(celloDir, "daemon.lock");
  const lock = await readLock(lockFilePath);

  if (!lock) {
    return { exitCode: 1, output: JSON.stringify({ daemon: "stopped" }, null, 2) };
  }

  try {
    const client = await connectToDaemon(lock.socketPath);
    const params: Record<string, unknown> = {};
    if (opts.filter) params.filter = opts.filter;
    if (opts.limit !== undefined) params.limit = opts.limit;
    const result = await client.send("list_sessions", params);
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
