/**
 * CLI command implementations for the `cello` binary.
 */

import { join } from "node:path";
import {
  connectOrStart,
  connectToDaemon,
  readLock,
  removeLock,
  // isProcessAlive is deliberately NOT imported. "Is that pid alive?" is the wrong question in both
  // directions — a pid can be dead, or reused by an unrelated process. The kernel's lock is the only
  // thing that knows whether a daemon exists.
  probeSingletonLock,
  SINGLETON_LOCK_FILENAME,
  type DaemonStatusResponse,
  type IpcClient,
  type Logger,
} from "@cello-protocol/daemon";

/**
 * M8C-LOGINSTART-1 CORE: bring every loaded agent online. Called by `cello login` after the daemon
 * is up. login ALWAYS completes — a per-agent start failure is COLLECTED, never thrown, so one bad
 * agent can't abort login. `cello_start_agent` is idempotent, so re-login is safe. The per-agent
 * `autoStart: false` opt-out is PARKED until the M9 config store lands (D14).
 * Lives here rather than inline in login() so it is unit-testable against an in-process daemon.
 */
export async function autoStartAllAgents(
  client: IpcClient,
): Promise<{ started: string[]; failed: Array<{ name: string; reason: string }> }> {
  const started: string[] = [];
  const failed: Array<{ name: string; reason: string }> = [];
  const listRes = (await client.send("cello_list_agents")) as { agents?: Array<{ name: string }> };
  for (const a of listRes.agents ?? []) {
    try {
      const r = (await client.send("cello_start_agent", { name: a.name })) as { ok?: boolean; reason?: string };
      if (r.ok) started.push(a.name);
      else failed.push({ name: a.name, reason: r.reason ?? "unknown" });
    } catch (err: unknown) {
      failed.push({ name: a.name, reason: err instanceof Error ? err.message : String(err) });
    }
  }
  return { started, failed };
}

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
    // M8C-LOGINSTART-1: bring every registered agent online, then report. Never let this abort login.
    const head = result.alreadyRunning ? "Daemon already running." : "Daemon started.";
    let summary: string;
    try {
      await result.client.send("ipc.connect", { clientType: "cli" });
      summary = formatLoginSummary(await autoStartAllAgents(result.client));
    } catch (err: unknown) {
      // Auto-start is best-effort — the daemon IS up. Surface the reason but complete login (exit 0).
      summary = `Agents were not auto-started (${err instanceof Error ? err.message : String(err)}); run 'cello status' and start them with cello_use_agent.`;
    } finally {
      result.client.close();
    }
    return { exitCode: 0, output: `${head}\n${summary}` };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { exitCode: 1, output: `Failed to start daemon: ${message}` };
  }
}

/**
 * M8C-LOGINSTART-1: compose the operator-facing auto-start summary — every failed agent enumerated
 * by name + reason. Pure + exported so the enumeration string is directly testable.
 */
export function formatLoginSummary(result: { started: string[]; failed: Array<{ name: string; reason: string }> }): string {
  const parts: string[] = [];
  if (result.started.length > 0) parts.push(`Started ${result.started.length} agent(s): ${result.started.join(", ")}.`);
  if (result.failed.length > 0) {
    parts.push(
      `${result.failed.length} agent(s) failed to start: ${result.failed.map((f) => `${f.name} (${f.reason})`).join(", ")}. ` +
      "Run 'cello status' to check; a failed agent stays offline and can be retried with cello_use_agent.",
    );
  }
  if (result.started.length === 0 && result.failed.length === 0) parts.push("No registered agents to start.");
  return parts.join("\n");
}

// DOD-LOGOUT-WAIT-1: how long logout waits for the daemon to actually die after acknowledging
// the shutdown request, and how often it re-checks. A daemon closing SQLCipher + libp2p takes
// real time; 5 s is generous headroom, and a daemon still alive past it is genuinely stuck.
const LOGOUT_WAIT_TIMEOUT_MS = 5_000;
const LOGOUT_WAIT_POLL_MS = 50;

/**
 * DOD-LOGOUT-WAIT-1: is the daemon actually GONE — judged by the same evidence `connectOrStart`
 * consults, so a completed logout GUARANTEES the next login starts fresh.
 *
 * Two facts, both required, neither of them a file:
 *  1. nothing answers on the socket, and
 *  2. no process holds the singleton lock.
 *
 * (1) alone is not enough: a daemon wedged mid-shutdown may have closed its IPC server while still
 * holding the DB. (2) alone is not enough either, because a pre-singleton-lock daemon holds no
 * singleton lock at all — for those, "free" says nothing about whether it is alive, and only the
 * socket can tell us. Together they are exactly the conditions under which the next daemon can
 * safely start.
 *
 * Neither `isProcessAlive(lock.pid)` nor the lock FILE may be substituted for these two facts: a pid
 * can be reused, and a lock file can be deleted by anyone.
 */
async function daemonGone(celloDir: string, socketPath: string, logger: Logger): Promise<boolean> {
  try {
    // connectToDaemon has no connect timeout of its own — bound the probe so a pathological hang
    // cannot stall the poll loop past its deadline. On the expected path the socket is already gone,
    // so this fails fast (ENOENT/ECONNREFUSED).
    const probe = await Promise.race([
      connectToDaemon(socketPath),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("probe_timeout")), 500)),
    ]);
    probe.close();
    return false; // something still answers — the daemon is up
  } catch {
    // Nothing answers. Now make sure the process is really gone and not merely deaf: a daemon that
    // still holds the kernel lock is still alive, and the next login would refuse to start beside it.
    return probeSingletonLock(celloDir, logger) === "free";
  }
}

export async function logout(
  celloDir: string,
  onProgress?: (line: string) => void,
  // Injectable bounds so the timeout path is testable without a 5 s wait. Production (the bin)
  // passes nothing and gets the named defaults.
  waitOpts?: { timeoutMs?: number; pollMs?: number },
): Promise<CommandResult> {
  const lockFilePath = join(celloDir, "daemon.lock");
  const noopLogger: Logger = { debug() {}, info() {}, warn() {}, error() {} };
  const timeoutMs = waitOpts?.timeoutMs ?? LOGOUT_WAIT_TIMEOUT_MS;
  const pollMs = waitOpts?.pollMs ?? LOGOUT_WAIT_POLL_MS;

  // The socket path is DETERMINISTIC. `daemon.lock`'s copy of it is metadata, and metadata is not
  // to be trusted here.
  const socketPath = join(celloDir, "daemon.sock");
  const lock = await readLock(lockFilePath);

  // DOD-SINGLE-DAEMON-1 (AC4) — the lock file does not get to decide whether a daemon exists.
  //
  // Never short-circuit on `if (!lock) return "No daemon running."`. That is a KILL SWITCH REPORTING
  // SUCCESS WITHOUT DOING ANYTHING, and the state that triggers it is real: an exiting orphan unlinks
  // a HEALTHY daemon's lock (so does `rm ~/.cello/daemon.lock`). The operator then runs `cello logout`
  // to stop their agent, is told it was never running, and walks away — while the daemon is still
  // online, still on the directory, still extending the hash chain. A kill switch may not lie.
  //
  // So we ask the daemon itself. If something ANSWERS on the socket, a daemon is running — that is
  // the strongest evidence available, it needs no file, and it holds even for a pre-singleton-lock
  // daemon, which holds no singleton lock at all.
  let client: IpcClient;
  try {
    client = await connectToDaemon(socketPath);
  } catch (err: unknown) {
    // Nothing answered. Now the kernel decides — not the pid in the JSON, which may be dead, or
    // REUSED by an unrelated process (in which case `isProcessAlive` says "alive" forever).
    const probe = probeSingletonLock(celloDir, noopLogger);

    if (probe === "held") {
      // A daemon holds the lock but will not talk to us. We have NOT stopped it, and must not imply
      // otherwise. Point at the authoritative holder rather than a pid we did not verify.
      const named = lock ? ` (daemon.lock names pid ${lock.pid}, which may be stale)` : "";
      return {
        exitCode: 1,
        output:
          `A daemon is running${named} and holds the singleton lock, but is not answering on ` +
          `${socketPath} (${err instanceof Error ? err.message : String(err)}). It has NOT been ` +
          `stopped. Find the process that holds the lock with \`lsof ${join(celloDir, SINGLETON_LOCK_FILENAME)}\`, ` +
          "stop it, then re-run 'cello logout' to clean up.",
      };
    }

    if (probe === "unknown") {
      // We could not ask. Reporting "no daemon running" on a guess is the whole failure mode.
      return {
        exitCode: 1,
        output:
          `Could not determine whether a daemon is running: the singleton lock at ` +
          `${join(celloDir, SINGLETON_LOCK_FILENAME)} could not be checked. Refusing to report a ` +
          "daemon stopped without proof.",
      };
    }

    // probe === "free": nothing holds the lock and nothing answers. There is no daemon.
    if (!lock) {
      return { exitCode: 0, output: "No daemon running." };
    }
    // DOD-LOGOUT-WAIT-1: only CLAIM the removal when it actually happened — removeLock swallows
    // non-ENOENT errors into a (here discarded) warn, and printing "Removed" for a lock still on
    // disk would be this unit's own lie in miniature.
    const removed = await removeLock(lockFilePath, noopLogger)
      .then(async () => (await readLock(lockFilePath)) === null)
      .catch(() => false);
    return {
      exitCode: 0,
      output: removed
        ? "No daemon running. (Removed a stale daemon.lock — no daemon holds the singleton lock.)"
        : `No daemon running. (A stale daemon.lock remains at ${lockFilePath} and could not be removed — check its permissions.)`,
    };
  }

  try {
    await client.send("shutdown");
    client.close();
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { exitCode: 1, output: `Failed to stop daemon: ${message}` };
  }

  // The request is in — tell the operator NOW, then report "stopped" only when it is true.
  onProgress?.("Shutting down the daemon…");

  // DOD-LOGOUT-WAIT-1: do NOT return the instant the shutdown request is WRITTEN. That leaves a
  // window where `cello logout && cello login` finds the daemon mid-death — connectOrStart sees a
  // live pid + connectable socket and prints "Daemon already running.", leaving the operator logged
  // out while being told otherwise. Wait until the daemon is genuinely gone; "Daemon stopped." for a
  // daemon that is still running is the same class of lie as a success log on a failed send
  // (DOD-SENDRAW-1).
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await daemonGone(celloDir, socketPath, noopLogger)) {
      return { exitCode: 0, output: "Daemon stopped." };
    }
    await new Promise((r) => setTimeout(r, pollMs));
  }
  const who = lock ? `pid ${lock.pid}, ` : "";
  return {
    exitCode: 1,
    output:
      `Daemon shutdown did not complete within ${timeoutMs / 1000}s ` +
      `(${who}socket ${socketPath}). The daemon acknowledged the request but is ` +
      `still running — it may be stuck closing sessions or its database. Check 'cello status'; ` +
      `if it never exits, find it with \`lsof ${join(celloDir, SINGLETON_LOCK_FILENAME)}\`, stop it, ` +
      "and re-run 'cello logout' to clean up.",
  };
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
  // M8C-ONBOARD-ERRORS-1 (R3/R4): specific, actionable errors on the core onboarding path — never a
  // bare Usage dump, never a pointless DKG round-trip to a generic dkg_failed for an obviously
  // malformed token. Client-side because a typo'd token and a missing one are knowable without the
  // directory. (Unknown-agent stays the daemon's job — it already returns a good agent_not_found.)
  if (!agent) {
    return { exitCode: 1, output: "You didn't name an agent to register. Usage: cello register-agent <agent> <pre-auth-token>. See your agents with 'cello status'." };
  }
  if (!preAuthToken) {
    return {
      exitCode: 1,
      output: `You're missing the pre-auth token. Get a single-use token from the CELLO Operations Agent on Telegram, then run:\n  cello register-agent ${agent} <token>\nor set it in the environment:\n  CELLO_PREAUTH_TOKEN=<token> cello register-agent ${agent}\nThe token is single-use and expires in 24 hours.`,
    };
  }
  // Client-side gate on the STABLE brand prefix only (real tokens are "CELLO-" + 33 base58 chars).
  // Checking just the "CELLO-" prefix catches the common typo (pasting the literal words
  // "CELLO_PREAUTH_TOKEN") without hard-coding the exact length/alphabet — the directory stays the
  // authority on the full format, so a future format bump can't strand a valid token behind a
  // client-side "malformed". A wrong-length CELLO- token reaches the daemon and is rejected there
  // with a structured reason.
  if (!preAuthToken.startsWith("CELLO-")) {
    return {
      exitCode: 1,
      output: "That doesn't look like a pre-auth token — real ones start with 'CELLO-' followed by 33 characters. (Did you paste the words 'CELLO_PREAUTH_TOKEN' instead of the token itself?) Get a token from the CELLO Operations Agent on Telegram, then retry.",
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
      output:
        JSON.stringify(
          { ok: true, agent_id: result.agent_id, primary_pubkey: result.primary_pubkey },
          null,
          2,
        ) +
        // M8C-ONBOARD-NEXTSTEP-1: every command output carries the next step + state legibility.
        // Broken onto multiple lines — a dense one-liner buries the three status cues.
        `\n\nNext: run  cello status  to confirm '${agent}' is registered.\n` +
        `  • it's normal for this to take a minute or two while registration settles.\n` +
        `  • ready = the agent shows state 'online' and directory_signaling 'connected'.\n` +
        `  • if it stays offline, run  cello logout  then  cello login.`,
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
      verifying_shares_digest?: string;
    };
    client.close();
    if (!result.ok) {
      return { exitCode: 1, output: JSON.stringify({ ok: false, reason: result.reason, guidance: result.guidance }, null, 2) };
    }
    return {
      exitCode: 0,
      output: JSON.stringify({ ok: true, epoch: result.epoch, primary_pubkey: result.primary_pubkey, verifying_shares_digest: result.verifying_shares_digest }, null, 2),
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { exitCode: 1, output: `Failed to refresh shares: ${message}` };
  }
}

/**
 * relayReceipts(celloDir, name): M8B DOD-RELAYSIG-1.
 *  - Connect to the daemon, send 'cello_get_relay_receipts' with { name }.
 *  - Returns the agent's durably-stored, signature-verified relay ordering-record receipts.
 */
export async function relayReceipts(celloDir: string, name: string): Promise<CommandResult> {
  if (!name) {
    return { exitCode: 1, output: "Usage: cello relay-receipts <name>  — ADVANCED/DEBUG: the per-message proofs a relay signed when it "
        + "delivered for this agent. For a session's notarized seal, use 'cello sealed-receipt <session-id>'." };
  }
  const lockFilePath = join(celloDir, "daemon.lock");
  const lock = await readLock(lockFilePath);
  if (!lock) {
    return { exitCode: 1, output: "No daemon running. Run 'cello login' first, then retry receipts." };
  }
  try {
    const client = await connectToDaemon(lock.socketPath);
    const result = (await client.send("cello_get_relay_receipts", { name })) as {
      ok: boolean;
      reason?: string;
      guidance?: string;
      receipts?: unknown[];
    };
    client.close();
    if (!result.ok) {
      return { exitCode: 1, output: JSON.stringify({ ok: false, reason: result.reason, guidance: result.guidance }, null, 2) };
    }
    return { exitCode: 0, output: JSON.stringify({ ok: true, receipts: result.receipts ?? [] }, null, 2) };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { exitCode: 1, output: `Failed to get relay receipts: ${message}` };
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

/** M8C-CONTACT-1: `cello contact add/remove/list [--agent <name>]`. Shared connect+dispatch. */
async function contactCommand(
  celloDir: string,
  method: "cello_contact_add" | "cello_contact_remove" | "cello_contact_list" | "cello_contact_set_tier" | "cello_contact_set_away" | "cello_set_moniker" | "cello_settings_get" | "cello_settings_set",
  params: Record<string, unknown>,
): Promise<CommandResult> {
  const lockFilePath = join(celloDir, "daemon.lock");
  const lock = await readLock(lockFilePath);
  if (!lock) {
    return { exitCode: 1, output: JSON.stringify({ daemon: "stopped" }, null, 2) };
  }
  try {
    const client = await connectToDaemon(lock.socketPath);
    await client.send("ipc.connect", { clientType: "cli" });
    const result = (await client.send(method, params)) as { ok: boolean };
    client.close();
    return { exitCode: result.ok ? 0 : 1, output: JSON.stringify(result, null, 2) };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { exitCode: 1, output: JSON.stringify({ daemon: "unreachable", error: message }, null, 2) };
  }
}

export async function contactAdd(celloDir: string, pubkey: string, agent?: string): Promise<CommandResult> {
  const params: Record<string, unknown> = { pubkey };
  if (agent) params.agent = agent;
  return contactCommand(celloDir, "cello_contact_add", params);
}

export async function contactRemove(celloDir: string, pubkey: string, agent?: string): Promise<CommandResult> {
  const params: Record<string, unknown> = { pubkey };
  if (agent) params.agent = agent;
  return contactCommand(celloDir, "cello_contact_remove", params);
}

export async function contactList(celloDir: string, agent?: string): Promise<CommandResult> {
  const params: Record<string, unknown> = {};
  if (agent) params.agent = agent;
  return contactCommand(celloDir, "cello_contact_list", params);
}

/** DOD-CONTACT-VIEW-1: `cello contact tier <pubkey> <tier> [--agent <name>]`. Validation (a known
 *  0..4 constant) lives daemon-side; the CLI surfaces the verdict verbatim. */
export async function contactSetTier(celloDir: string, pubkey: string, tier: number, agent?: string): Promise<CommandResult> {
  const params: Record<string, unknown> = { pubkey, tier };
  if (agent) params.agent = agent;
  return contactCommand(celloDir, "cello_contact_set_tier", params);
}

/** DOD-AWAY-TIER-1: `cello contact away <pubkey> <message> [--agent <name>]` — set a per-contact away
 *  message (or clear it with an empty message → null). */
export async function contactSetAway(celloDir: string, pubkey: string, message: string | null, agent?: string): Promise<CommandResult> {
  const params: Record<string, unknown> = { pubkey, message };
  if (agent) params.agent = agent;
  return contactCommand(celloDir, "cello_contact_set_away", params);
}

/** DOD-SETTINGS-SURFACE-1: `cello settings get [key] [--agent <name>]` — a single key, or all set
 *  values when no key. Validation lives daemon-side; the CLI surfaces the verdict verbatim. */
export async function settingsGet(celloDir: string, key: string | undefined, agent?: string): Promise<CommandResult> {
  const params: Record<string, unknown> = {};
  if (key !== undefined) params.key = key;
  if (agent) params.agent = agent;
  return contactCommand(celloDir, "cello_settings_get", params);
}

/** DOD-SETTINGS-SURFACE-1: `cello settings set <key> <value> [--agent <name>]` — the daemon validates
 *  the key (known) and, for bound keys, a finite positive integer (rejects Infinity/negative/0). */
export async function settingsSet(celloDir: string, key: string, value: string, agent?: string): Promise<CommandResult> {
  const params: Record<string, unknown> = { key, value };
  if (agent) params.agent = agent;
  return contactCommand(celloDir, "cello_settings_set", params);
}

/** MONIKER-1: `cello moniker set <name>` / `cello moniker clear` — set (string) or clear (null)
 *  the agent's outbound-name override via cello_set_moniker. Validation lives daemon-side
 *  (shared MONIKER-0 rule); the CLI surfaces the daemon's verdict verbatim. */
export async function monikerSet(celloDir: string, moniker: string | null, agent?: string): Promise<CommandResult> {
  const params: Record<string, unknown> = { moniker };
  if (agent) params.agent = agent;
  return contactCommand(celloDir, "cello_set_moniker", params);
}

/** M8C-TGDOOR-1: `cello telegram set-token <bot_token> <allowlisted_chat_id>` — persists the
 *  daemon-wide bot credentials (narrow, dedicated surface; NOT folded into the parked `cello
 *  config`, since a bot token has no sensible default and can't wait for M9-CFG-001). */
export async function telegramSetToken(celloDir: string, botToken: string, chatId: string): Promise<CommandResult> {
  const lockFilePath = join(celloDir, "daemon.lock");
  const lock = await readLock(lockFilePath);
  if (!lock) {
    return { exitCode: 1, output: JSON.stringify({ daemon: "stopped" }, null, 2) };
  }
  try {
    const client = await connectToDaemon(lock.socketPath);
    await client.send("ipc.connect", { clientType: "cli" });
    const result = (await client.send("cello_telegram_set_token", { bot_token: botToken, allowlisted_chat_id: chatId })) as { ok: boolean };
    client.close();
    return { exitCode: result.ok ? 0 : 1, output: JSON.stringify(result, null, 2) };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { exitCode: 1, output: JSON.stringify({ daemon: "unreachable", error: message }, null, 2) };
  }
}
