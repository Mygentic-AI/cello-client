/**
 * DOD-CLI-PARITY-1 Phases 1-2 — every daemon capability that was MCP-only, reachable from `cello`.
 *
 * Bash is the universal agent adapter: with these commands any bash-capable agent (not just Claude
 * Code or Hermes) operates a CELLO node — connect, send, receive, seal — with no MCP dependency.
 *
 * Each command is a THIN PASS-THROUGH: parse args → call the SAME daemon IPC handler the
 * corresponding cello_* MCP tool calls → emit the response under the §3 contract (json-out.ts).
 * No daemon changes, no second IPC client, no logic that the daemon owns (validation, tier bounds,
 * agent_id resolution) is duplicated here — the CLI surfaces the daemon's verdict, verbatim.
 *
 * ── The per-invocation current-agent problem (why `use-agent` persists) ──────────────────────
 * The daemon's "current agent" is PER-CONNECTION state. The MCP shim holds one long-lived socket,
 * so `cello_use_agent` sticks for the whole session. The CLI is the opposite: a fresh process and a
 * fresh connection per invocation, torn down microseconds later. A naive `cello use-agent alice`
 * pass-through would therefore set state on a dying socket and report ok:true while changing NOTHING
 * for the next command — a fabricated success of exactly the kind §3 forbids.
 *
 * So the selection is DURABLE: `use-agent` calls the real handler (which validates the agent and
 * auto-starts it — AUTOSTART-1) and, only if the daemon says ok, persists the name. Every
 * agent-scoped command then REPLAYS `cello_use_agent` on its new connection before dispatching.
 * That is not a parallel path — it is the same replay the MCP proxy performs after a reconnect
 * (ipc-proxy.ts invariant 1), reusing the existing handler.
 *
 * Agent resolution, in order: explicit `--agent` > the persisted selection > (omitted, so the
 * daemon applies its own sole-online-agent fallback, and stays ambiguous → no_current_agent when
 * two or more are online). If a replay FAILS, the command STOPS and surfaces that error — it never
 * shrugs and lets the daemon's fallback quietly run the work as a different agent.
 */

import { join } from "node:path";
import { readFile, writeFile, unlink } from "node:fs/promises";
import { connectToDaemon, readLock, type IpcClient } from "@cello-protocol/daemon";
import { emitIpcResult, emitTransportError, type EmittedOutput, type EmitOptions } from "./json-out.js";

export type CliOutput = EmittedOutput;

/** Options every parity command accepts. */
export interface ParityOptions extends EmitOptions {
  /** `--agent <name>` — overrides the persisted selection for this invocation only. */
  agent?: string;
}

/** Where `cello use-agent` records the selection: a plain text file the operator can read/delete. */
function currentAgentPath(celloDir: string): string {
  return join(celloDir, "current-agent");
}

/**
 * The persisted agent selection, or undefined if none was ever made.
 *
 * ENOENT — never selected — is the ONLY swallowed error (review F4). A blanket catch here would let
 * an unreadable file (EACCES, EISDIR, a corrupt mount) read as "no selection", after which the
 * daemon's sole-online fallback would quietly run the command as whatever agent happens to be up:
 * the operator's selection silently replaced by a different identity, exit 0. Anything that is not
 * "the file isn't there" is a real failure and is thrown.
 */
export async function readCurrentAgent(celloDir: string): Promise<string | undefined> {
  try {
    const raw = (await readFile(currentAgentPath(celloDir), "utf8")).trim();
    return raw.length > 0 ? raw : undefined;
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException)?.code === "ENOENT") return undefined; // never selected
    throw err;
  }
}

/**
 * Forget the persisted selection. Called by `stop-agent` (review F1): the daemon clears an agent
 * from every connection's current-agent state when it is stopped, so the CLI's durable mirror of
 * that state must be cleared too. Leaving it behind was a genuine defect — see stopAgent().
 */
async function clearCurrentAgent(celloDir: string): Promise<void> {
  try {
    await unlink(currentAgentPath(celloDir));
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException)?.code !== "ENOENT") throw err;
  }
}

async function writeCurrentAgent(celloDir: string, name: string): Promise<void> {
  await writeFile(currentAgentPath(celloDir), name + "\n", "utf8");
}

/**
 * Open a daemon connection, establish the current agent (if one is selected), run `fn`, and always
 * close. Transport failures come back as structured JSON on stderr — so a bash agent branches on
 * the same shape whether the daemon rejected the call or never received it.
 */
async function withDaemon(
  celloDir: string,
  opts: ParityOptions,
  agentScoped: boolean,
  fn: (client: IpcClient) => Promise<Record<string, unknown>>,
): Promise<CliOutput> {
  const lock = await readLock(join(celloDir, "daemon.lock"));
  if (!lock) {
    return emitTransportError(
      "daemon_not_running",
      "No daemon is running. Start it with 'cello login', then retry.",
      opts,
    );
  }

  let client: IpcClient;
  try {
    client = await connectToDaemon(lock.socketPath);
  } catch (err: unknown) {
    return emitTransportError(
      "daemon_unreachable",
      `Could not connect to the daemon at ${lock.socketPath}: ${err instanceof Error ? err.message : String(err)}. It may be mid-shutdown — check 'cello status'.`,
      opts,
    );
  }

  try {
    await client.send("ipc.connect", { clientType: "cli" });

    if (agentScoped) {
      // Review F2 — an EMPTY --agent must never be treated as "no --agent". `--agent "$VAR"` with
      // VAR unset yields "", which is not nullish: it would suppress the persisted selection, fail
      // the truthiness check below, run NO replay, and let the daemon's sole-online fallback execute
      // the command as whatever agent happened to be up — exit 0, wrong identity, silently. That is
      // the exact misroute this module exists to prevent, and the bash idiom makes it likely.
      if (opts.agent !== undefined && opts.agent.trim() === "") {
        return emitTransportError(
          "missing_agent_value",
          "--agent was given an empty value (an unset shell variable?). Name an agent explicitly, or omit --agent to use the selection from 'cello use-agent'.",
          opts,
        );
      }

      const selected = opts.agent ?? (await readCurrentAgent(celloDir));
      if (selected) {
        // Review F1 — the replay must not RESURRECT a stopped agent. cello_use_agent auto-starts an
        // offline agent (AUTOSTART-1), so replaying it blindly meant `cello stop-agent alice` could
        // be silently undone by the very next read-only command (`cello inbox`), bringing alice back
        // online and reachable with no signal. Stopping an agent is kill-switch-adjacent; a command
        // that reads must never re-arm it. The MCP surface never does this — the daemon clears the
        // agent from every connection on stop, and later calls get no_current_agent.
        //
        // So: only replay an agent that is ALREADY ONLINE. An offline selection fails loud, naming
        // the remedy, rather than quietly starting it or quietly running as someone else.
        if (!(await isAgentOnline(client, selected))) {
          return emitTransportError(
            "selected_agent_offline",
            `Agent '${selected}' is not online, so this command was not run as it. Bring it online with 'cello start-agent ${selected}' (or select another with 'cello use-agent <name>'). It is NOT auto-started here: that would silently undo a deliberate 'cello stop-agent'.`,
            opts,
          );
        }
        // The agent is online — claim it for this connection. A refusal (retired/unknown) stops the
        // command: continuing would let the sole-online fallback run it as a DIFFERENT agent.
        const used = (await client.send("cello_use_agent", { name: selected })) as Record<string, unknown>;
        if (used.ok !== true) {
          // Defensive: cello_use_agent is ok-bearing on every path today, but if it ever returned an
          // ok-less body, emitIpcResult would print IT as this command's successful result. Fail loud
          // on any shape that is not an explicit ok:false, rather than pass off the wrong body.
          if (used.ok === false) return emitIpcResult(used, opts);
          return emitTransportError(
            "unexpected_replay_response",
            `Selecting agent '${selected}' returned an unrecognized response, so the command was not run. This is a daemon/CLI version mismatch — check 'cello status'.`,
            opts,
          );
        }
      }
      // No selection at all → send nothing, and let the daemon apply its own documented fallback
      // (sole online agent; ambiguous → no_current_agent). Guessing here would misroute.
    }

    const result = await fn(client);
    return emitIpcResult(result, opts);
  } catch (err: unknown) {
    return emitTransportError(
      "ipc_error",
      `The daemon call failed: ${err instanceof Error ? err.message : String(err)}`,
      opts,
    );
  } finally {
    client.close();
  }
}

/**
 * Is this agent currently ONLINE? Asked via cello_list_agents (a real handler, no new IPC path) so
 * the replay can refuse to auto-start a stopped agent (review F1). Fails CLOSED: any unexpected
 * shape reads as "not online", which fails the command loud rather than resurrecting an agent the
 * operator deliberately stopped.
 */
async function isAgentOnline(client: IpcClient, name: string): Promise<boolean> {
  const res = (await client.send("cello_list_agents")) as { agents?: Array<{ name?: string; state?: string }> };
  return (res.agents ?? []).some((a) => a.name === name && a.state === "online");
}

/** The common case: one IPC call, agent-scoped unless stated otherwise. */
function ipcCommand(
  celloDir: string,
  method: string,
  params: Record<string, unknown>,
  opts: ParityOptions,
  agentScoped = true,
): Promise<CliOutput> {
  return withDaemon(celloDir, opts, agentScoped, async (client) => {
    return (await client.send(method, params)) as Record<string, unknown>;
  });
}

/** Drop undefined values so an omitted optional param is ABSENT, not an explicit `undefined`. */
function defined(params: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(params).filter(([, v]) => v !== undefined));
}

/**
 * The ONE place a CLI command's daemon IPC method is named (review T2).
 *
 * The registry's `ipcMethod` field is set FROM this map, and every function below dispatches FROM
 * this map — so the field that DoD §9's parity test audits is, by construction, the literal that is
 * actually sent. Previously the two were independent strings: the registry could say
 * `cello_contact_set_moniker` while the code called `cello_contact_set_away`, and the audit — which
 * only read the metadata — would happily pass. A comment-in-a-field is not a guarantee; this is.
 */
export const IPC_METHODS = {
  agents: "cello_list_agents",
  "start-agent": "cello_start_agent",
  "stop-agent": "cello_stop_agent",
  "use-agent": "cello_use_agent",
  inbox: "cello_check_notifications",
  transcript: "cello_get_transcript",
  "sealed-receipt": "cello_get_sealed_receipt",
  initiate: "cello_initiate_session",
  send: "cello_send",
  receive: "cello_receive",
  "receive-session": "cello_receive_session",
  close: "cello_close_session",
  "await-session": "cello_await_session",
  "contact-add": "cello_contact_add",
  "contact-remove": "cello_contact_remove",
  "contact-list": "cello_contact_list",
  "contact-set-tier": "cello_contact_set_tier",
  "contact-set-away": "cello_contact_set_away",
  "contact-set-moniker": "cello_contact_set_moniker",
} as const;

// ─── Group A: agent lifecycle ──────────────────────────────────────────────────────────────────

/** `cello agents` → cello_list_agents. Daemon-wide, not agent-scoped. */
export function listAgents(celloDir: string, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS.agents, {}, opts, false);
}

/** `cello start-agent <name>` → cello_start_agent. Brings an agent online WITHOUT claiming current. */
export function startAgent(celloDir: string, name: string, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["start-agent"], { name }, opts, false);
}

/**
 * `cello stop-agent <name>` → cello_stop_agent.
 *
 * Also CLEARS the persisted selection when it names this agent (review F1). The daemon clears a
 * stopped agent from every connection's current-agent state; the CLI's durable mirror of that state
 * must follow, or the next command would try to act as an agent the operator just stopped.
 */
export async function stopAgent(celloDir: string, name: string, opts: ParityOptions): Promise<CliOutput> {
  const out = await ipcCommand(celloDir, IPC_METHODS["stop-agent"], { name }, opts, false);
  if (out.exitCode === 0 && (await readCurrentAgent(celloDir)) === name) {
    await clearCurrentAgent(celloDir);
  }
  return out;
}

/**
 * `cello use-agent <name>` → cello_use_agent, and — only if the daemon accepts it — persists the
 * selection so it survives this process. The handler auto-starts the agent if offline (AUTOSTART-1).
 * A rejected selection is NEVER written: a later command must not silently act as an agent the
 * daemon refused.
 */
export async function useAgent(celloDir: string, name: string, opts: ParityOptions): Promise<CliOutput> {
  const out = await ipcCommand(celloDir, IPC_METHODS["use-agent"], { name }, opts, false);
  if (out.exitCode === 0) await writeCurrentAgent(celloDir, name);
  return out;
}

/** `cello inbox [--scope current|all]` → cello_check_notifications (the push-loss reconciler). */
export function inbox(
  celloDir: string,
  opts: ParityOptions & { scope?: "current" | "all" },
): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS.inbox, defined({ scope: opts.scope }), opts);
}

/** `cello transcript <session-id>` → cello_get_transcript (durable, survives a daemon restart). */
export function transcript(celloDir: string, sessionId: string, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS.transcript, { session_id: sessionId }, opts);
}

/**
 * `cello sealed-receipt <session-id>` → cello_get_sealed_receipt.
 *
 * NOT in the brief's mapping table, which listed cello_get_sealed_receipt as "already covered by
 * `receipts`". It is not: `cello receipts <name>` calls cello_get_relay_receipts — a DIFFERENT
 * handler (relay ordering receipts). The notarized bilateral SEAL receipt — the artifact the whole
 * close ceremony exists to produce, and the one an arbitrator reads — had no CLI surface at all.
 * Added under the standing rule: a real, non-stub handler with no CLI command gets one.
 */
export function sealedReceipt(celloDir: string, sessionId: string, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["sealed-receipt"], { session_id: sessionId }, opts);
}

// Review F3: the WHOLE address book now speaks the §3 contract, not just the three new sub-verbs.
// Previously add/remove/list/tier/away went through the legacy path (errors pretty-printed to
// STDOUT, no --pretty) while the new set-moniker used the parity path (errors to stderr) — so a
// bash script branching on stderr got DIFFERENT conventions between sub-verbs of the same command.
// One command, one contract. (Behavior change, journaled: contact failures now print JSON on stderr
// rather than stdout; the exit codes were already correct.)

/** `cello contact add <pubkey>` → cello_contact_add. */
export function contactAdd(celloDir: string, pubkey: string, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["contact-add"], { pubkey }, opts);
}

/** `cello contact remove <pubkey>` → cello_contact_remove. */
export function contactRemove(celloDir: string, pubkey: string, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["contact-remove"], { pubkey }, opts);
}

/** `cello contact list` → cello_contact_list. */
export function contactList(celloDir: string, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["contact-list"], {}, opts);
}

/** `cello contact set-tier <pubkey> <tier>` → cello_contact_set_tier. */
export function contactSetTier(celloDir: string, pubkey: string, tier: number, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["contact-set-tier"], { pubkey, tier }, opts);
}

/** `cello contact set-away <pubkey> <message>` → cello_contact_set_away (empty message clears it). */
export function contactSetAway(celloDir: string, pubkey: string, message: string | null, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["contact-set-away"], { pubkey, message }, opts);
}

/** `cello contact set-moniker <pubkey> <moniker>` → cello_contact_set_moniker (per-CONTACT pet name). */
export function contactSetMoniker(celloDir: string, pubkey: string, moniker: string | null, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["contact-set-moniker"], { pubkey, moniker }, opts);
}

// ─── Group B: live conversation (mirrors the MCP params EXACTLY) ───────────────────────────────

/** `cello initiate <target-pubkey>` → cello_initiate_session. Prints the session_id. */
export function initiate(celloDir: string, targetPubkey: string, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS.initiate, { target_pubkey: targetPubkey }, opts);
}

/**
 * `cello send <session-id> <message>` → cello_send.
 *
 * Honors read-before-write exactly as the MCP tool does: if the daemon returns session_not_current
 * (with its cursor), that verdict is surfaced VERBATIM and the command exits non-zero. It is never
 * auto-fixed by silently reading the transcript first — the operator/agent must catch up explicitly,
 * because a send that "worked" after a hidden read is a send whose ordering guarantees are a fiction.
 */
export function send(
  celloDir: string,
  sessionId: string,
  content: string,
  opts: ParityOptions & { governanceDecisions?: Record<string, string> },
): Promise<CliOutput> {
  return ipcCommand(
    celloDir,
    "cello_send",
    defined({ session_id: sessionId, content, governance_decisions: opts.governanceDecisions }),
    opts,
  );
}

/**
 * `cello receive <session-id> [--since-seq N] [--timeout-ms N]` → cello_receive.
 * Mirrors the MCP semantics exactly: with since_seq it is a stateless catch-up BATCH (no replay
 * race, timeout ignored); without it, it BLOCKS for the next live message until timeout_ms.
 */
export function receive(
  celloDir: string,
  sessionId: string,
  opts: ParityOptions & { sinceSeq?: number; timeoutMs?: number },
): Promise<CliOutput> {
  return ipcCommand(
    celloDir,
    "cello_receive",
    defined({ session_id: sessionId, timeout_ms: opts.timeoutMs, since_seq: opts.sinceSeq }),
    opts,
  );
}

/** `cello receive-session <session-id> [--timeout-ms N]` → cello_receive_session. */
export function receiveSession(
  celloDir: string,
  sessionId: string,
  opts: ParityOptions & { timeoutMs?: number },
): Promise<CliOutput> {
  return ipcCommand(
    celloDir,
    "cello_receive_session",
    defined({ session_id: sessionId, timeout_ms: opts.timeoutMs }),
    opts,
  );
}

/**
 * `cello close <session-id> [--force]` → cello_close_session. Normally triggers the bilateral seal
 * ceremony. --force is passed ONLY when asked for (mirroring the shim), since it forfeits the seal.
 */
export function closeSession(
  celloDir: string,
  sessionId: string,
  opts: ParityOptions & { force?: boolean },
): Promise<CliOutput> {
  const params = opts.force ? { session_id: sessionId, force: true } : { session_id: sessionId };
  return ipcCommand(celloDir, IPC_METHODS.close, params, opts);
}

/** `cello await-session [--timeout-ms N]` → cello_await_session. Blocks for an inbound doorbell. */
export function awaitSession(
  celloDir: string,
  opts: ParityOptions & { timeoutMs?: number },
): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["await-session"], defined({ timeout_ms: opts.timeoutMs }), opts);
}
