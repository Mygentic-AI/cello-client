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
  removeLock,
  isProcessAlive,
  type DaemonStatusResponse,
  type IpcClient,
  type Logger,
} from "@cello-protocol/daemon";

/**
 * M8C-LOGINSTART-1 CORE: bring every loaded agent online. Called by `cello login` after the daemon
 * is up. login ALWAYS completes — a per-agent start failure is COLLECTED, never thrown (design-review
 * #8), so one bad agent can't abort login. `cello_start_agent` is idempotent, so re-login is safe.
 * The per-agent `autoStart: false` opt-out is PARKED until the M9 config store lands (D14).
 * Extracted (not inline in login) so it is unit-testable against an in-process daemon.
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
 * by name + reason (design-review #8). Pure + exported so the enumeration string is directly testable.
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
 * DOD-LOGOUT-WAIT-1: is the daemon behind `lock` actually GONE — judged by the same inputs
 * connectOrStart consults, so a completed logout GUARANTEES the next login starts fresh:
 *  - pid dead → login treats any remaining lock as stale and starts fresh; or
 *  - lock removed (the daemon's final shutdown cleanup) AND the socket refusing connections.
 * The pid check alone is not sufficient in-process (tests share the CLI's pid), and the lock
 * check alone is not sufficient for a crash that never cleaned up — together they cover both.
 */
async function daemonGone(lockFilePath: string, lock: { pid: number; socketPath: string }): Promise<boolean> {
  if (!isProcessAlive(lock.pid)) return true;
  const lockNow = await readLock(lockFilePath);
  if (lockNow && lockNow.pid === lock.pid) return false; // daemon hasn't finished its cleanup
  // Review F5: a lock re-acquired by a DIFFERENT pid means a new daemon already started — which
  // proves the old daemon's cleanup completed (its lock had to be gone for login to spawn). The
  // socket now belongs to the new daemon; probing it would wrongly report the OLD one alive.
  if (lockNow && lockNow.pid !== lock.pid) return true;
  try {
    // Review F4: connectToDaemon has no connect timeout of its own — bound the probe so a
    // pathological hang cannot stall the poll loop past its deadline. On the expected path the
    // lock is already gone, so this fails fast (ENOENT/ECONNREFUSED).
    const probe = await Promise.race([
      connectToDaemon(lock.socketPath),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("probe_timeout")), 500)),
    ]);
    probe.close();
    return false; // something still answers on the socket
  } catch {
    return true;
  }
}

export async function logout(
  celloDir: string,
  onProgress?: (line: string) => void,
  // Review F1: injectable bounds so the timeout path is testable without a 5 s wait. Production
  // (the bin) passes nothing and gets the named defaults.
  waitOpts?: { timeoutMs?: number; pollMs?: number },
): Promise<CommandResult> {
  const lockFilePath = join(celloDir, "daemon.lock");
  const lock = await readLock(lockFilePath);
  const noopLogger: Logger = { debug() {}, info() {}, warn() {}, error() {} };
  const timeoutMs = waitOpts?.timeoutMs ?? LOGOUT_WAIT_TIMEOUT_MS;
  const pollMs = waitOpts?.pollMs ?? LOGOUT_WAIT_POLL_MS;

  if (!lock) {
    return { exitCode: 0, output: "No daemon running." };
  }

  // DOD-LOGOUT-WAIT-1: a lock whose pid is dead is not a running daemon — say so (exit 0) and
  // clean the stale lock up so the next login doesn't have to. Review F3: only CLAIM the removal
  // when it actually happened — removeLock swallows non-ENOENT errors into a (here discarded)
  // warn, and printing "Removed" for a lock still on disk would be this unit's own lie in
  // miniature.
  if (!isProcessAlive(lock.pid)) {
    const removed = await removeLock(lockFilePath, noopLogger)
      .then(async () => (await readLock(lockFilePath)) === null)
      .catch(() => false);
    return {
      exitCode: 0,
      output: removed
        ? "No daemon running. (Removed a stale daemon.lock.)"
        : `No daemon running. (A stale daemon.lock remains at ${lockFilePath} and could not be removed — check its permissions.)`,
    };
  }

  try {
    const client = await connectToDaemon(lock.socketPath);
    await client.send("shutdown");
    client.close();
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { exitCode: 1, output: `Failed to stop daemon: ${message}` };
  }

  // The request is in — tell the operator NOW, then report "stopped" only when it is true.
  onProgress?.("Shutting down the daemon…");

  // DOD-LOGOUT-WAIT-1: returning the instant the shutdown request was WRITTEN left a window
  // where `cello logout && cello login` found the daemon mid-death — connectOrStart saw a live
  // pid + connectable socket and printed "Daemon already running.", leaving the operator logged
  // out while being told otherwise. Wait until the daemon is genuinely gone; "Daemon stopped."
  // for a daemon that is still running is the same class of lie as a success log on a failed
  // send (DOD-SENDRAW-1).
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await daemonGone(lockFilePath, lock)) {
      return { exitCode: 0, output: "Daemon stopped." };
    }
    await new Promise((r) => setTimeout(r, pollMs));
  }
  return {
    exitCode: 1,
    output:
      `Daemon shutdown did not complete within ${timeoutMs / 1000}s ` +
      `(pid ${lock.pid}, socket ${lock.socketPath}). The daemon acknowledged the request but is ` +
      `still running — it may be stuck closing sessions or its database. Check 'cello status'; ` +
      `if it never exits, stop it manually (kill ${lock.pid}) and re-run 'cello logout' to clean up.`,
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
    return { exitCode: 1, output: "You didn't name an agent to register. Usage: cello register <agent> <pre-auth-token>. See your agents with 'cello status'." };
  }
  if (!preAuthToken) {
    return {
      exitCode: 1,
      output: `You're missing the pre-auth token. Get a single-use token from the CELLO Operations Agent on Telegram, then run:\n  cello register ${agent} <token>\nor set it in the environment:\n  CELLO_PREAUTH_TOKEN=<token> cello register ${agent}\nThe token is single-use and expires in 24 hours.`,
    };
  }
  // Client-side gate on the STABLE brand prefix only (real tokens are "CELLO-" + 33 base58 chars).
  // Checking just the "CELLO-" prefix catches the common typo (pasting the literal words
  // "CELLO_PREAUTH_TOKEN") without hard-coding the exact length/alphabet — the directory stays the
  // authority on the full format, so a future format bump can't strand a valid token behind a
  // client-side "malformed" (reviewer F2 / D13). A wrong-length CELLO- token reaches the daemon and
  // is rejected there with a structured reason.
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
        // M8C-ONBOARD-NEXTSTEP-1 (R7): every command output carries the next step + state legibility.
        // CC-6 (P2-1): broken onto multiple lines — the dense one-liner buried the three status cues.
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
    return { exitCode: 1, output: "Usage: cello receipts <name>  — list the agent's stored relay ordering receipts." };
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
  method: "cello_contact_add" | "cello_contact_remove" | "cello_contact_list" | "cello_set_moniker",
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
