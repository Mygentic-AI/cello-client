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
 * ENOENT — never selected — is the ONLY swallowed error. A blanket catch here would let
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
 * Forget the persisted selection. Called by `set-agent-offline`: the daemon clears an agent from every
 * connection's current-agent state when it is stopped, so the CLI's durable mirror of that state
 * must be cleared too.
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
      // An EMPTY --agent must never be treated as "no --agent". `--agent "$VAR"` with
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
        // The replay must not RESURRECT a stopped agent. cello_use_agent auto-starts an offline
        // agent (AUTOSTART-1), so replaying it blindly would let `cello set-agent-offline alice` be
        // silently undone by the very next read-only command (`cello inbox`), bringing alice back
        // online and reachable with no signal. Stopping an agent is kill-switch-adjacent; a command
        // that reads must never re-arm it. The MCP surface never does this — the daemon clears the
        // agent from every connection on stop, and later calls get no_current_agent.
        //
        // So: only replay an agent that is ALREADY ONLINE. An offline selection fails loud, naming
        // the remedy, rather than quietly starting it or quietly running as someone else.
        if (!(await isAgentOnline(client, selected))) {
          return emitTransportError(
            "selected_agent_offline",
            `Agent '${selected}' is not online, so this command was not run as it. Bring it online with 'cello start-agent ${selected}' (or select another with 'cello use-agent <name>'). It is NOT auto-started here: that would silently undo a deliberate 'cello set-agent-offline'.`,
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
      } else {
        // NO selection. The daemon's fallback is "the sole ONLINE agent", and it refuses only when
        // two or more are online — so with several agents known and exactly one up, it runs the
        // command as that one. `cello set-agent-offline <selected>` clears the selection, which walks
        // straight into it: the next command silently re-targets whoever else happens to be online.
        //
        // With ONE known agent the fallback is unambiguous and useful (a fresh operator who never ran
        // `use-agent` still works). With more than one it is a guess about intent, and a guess must
        // not be made silently on the operator's behalf.
        const known = await listKnownAgents(client);
        if (known === null) {
          return emitTransportError(
            "agent_list_unavailable",
            "The daemon's agent list could not be read, so this command was not run — without it there is no way to tell whether an unselected command would target the agent you meant. Check 'cello status'.",
            opts,
          );
        }
        if (known.length > 1) {
          return emitTransportError(
            "no_agent_selected",
            `No agent is selected and the daemon knows ${known.length} (${known.join(", ")}), so this command was not run — it would otherwise have silently targeted whichever agent happened to be online. Choose one with 'cello use-agent <name>', or pass --agent <name>.`,
            opts,
          );
        }
      }
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
 * the replay can refuse to auto-start a stopped agent. Fails CLOSED: any unexpected shape reads as
 * "not online", which fails the command loud rather than resurrecting an agent the operator
 * deliberately stopped.
 */
async function isAgentOnline(client: IpcClient, name: string): Promise<boolean> {
  const res = (await client.send("cello_list_agents")) as { agents?: Array<{ name?: string; state?: string }> };
  return (res.agents ?? []).some((a) => a.name === name && a.state === "online");
}

/**
 * Every agent the daemon KNOWS — loaded, whether online or not. Used to decide whether "no
 * selection" is unambiguous (one agent) or a guess about the operator's intent (several).
 *
 * Counts KNOWN agents, not online ones. Counting only the online ones reopens the hole it exists to
 * close: stopping the selected agent drops the count to one, so the guess looks safe again at
 * exactly the moment the operator said they do not want that agent.
 *
 * FAILS CLOSED, like its sibling isAgentOnline. Returns null — never an empty list — when the daemon
 * answers with a shape it does not recognize. An empty list would sail through a `length > 1` guard
 * and hand the decision straight back to the daemon's sole-online fallback, which is the very thing
 * the guard is there to prevent. A counter that cannot count must not answer "one".
 */
async function listKnownAgents(client: IpcClient): Promise<string[] | null> {
  const res = (await client.send("cello_list_agents")) as { agents?: unknown };
  if (!Array.isArray(res.agents)) return null;
  return (res.agents as Array<{ name?: unknown }>)
    .map((a) => a.name)
    .filter((n): n is string => typeof n === "string");
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
 * CLI command name → the daemon IPC method it calls. The ONE place a CLI command's daemon IPC
 * method is named.
 *
 * The registry's `ipcMethod` field is set FROM this map, and every function below dispatches FROM
 * this map — so the field that DoD §9's parity test audits is, by construction, the literal that is
 * actually sent. Two independent strings would let the registry say `cello_contact_set_moniker`
 * while the code calls `cello_contact_set_away`, and the audit — which only reads the metadata —
 * would happily pass. A comment-in-a-field is not a guarantee; this is.
 *
 * The KEYS are the CLI/MCP capability names (DOD-ONBOARD-HELP-1 §2b: one vocabulary). The VALUES
 * are the daemon's IPC WIRE names, which deliberately do NOT move — the shim maps tool
 * `cello_agents` onto the existing `cello_list_agents` method. Renaming the wire would break a new
 * daemon talking to an OLD connect shim; connect has no daemon dependency, so nothing pins the two
 * together. That asymmetry is the whole reason this table exists rather than a string concat.
 */
export const IPC_METHODS = {
  agents: "cello_list_agents",
  "start-agent": "cello_start_agent",
  "set-agent-offline": "cello_set_agent_offline",
  "use-agent": "cello_use_agent",
  "stop-using-agent": "cello_stop_using_agent",
  inbox: "cello_check_notifications",
  sessions: "cello_list_sessions",
  transcript: "cello_get_transcript",
  "sealed-receipt": "cello_get_sealed_receipt",
  "initiate-session": "cello_initiate_session",
  send: "cello_send",
  receive: "cello_receive",
  "close-session": "cello_close_session",
  "await-session": "cello_await_session",
  "name-session": "cello_name_session",
  dismiss: "cello_dismiss",
  contacts: "cello_contact_list",
  "contact-add": "cello_contact_add",
  "contact-remove": "cello_contact_remove",
  "contact-set-tier": "cello_contact_set_tier",
  "contact-set-away": "cello_contact_set_away",
  "contact-set-moniker": "cello_contact_set_moniker",
  "contact-set-signal": "cello_contact_set_signal",
  "settings-get": "cello_settings_get",
  "settings-set": "cello_settings_set",
  "moniker-set": "cello_set_moniker",
  "doc-propose": "cello_doc_propose",
  "doc-inbox": "cello_doc_inbox",
  "doc-accept": "cello_doc_accept",
  "doc-refuse": "cello_doc_refuse",
  "doc-list": "cello_doc_list",
  "doc-read": "cello_doc_read",
  "doc-diff": "cello_doc_diff",
  "doc-write": "cello_doc_write",
  "doc-close": "cello_doc_close",
  "doc-kill": "cello_doc_kill",
  "attestation-consent-list": "cello_attestation_consent_list",
  "attestation-consent-accept": "cello_attestation_consent_accept",
  "attestation-consent-refuse": "cello_attestation_consent_refuse",
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
 * `cello set-agent-offline <name>` → cello_set_agent_offline. (Was `set-agent-offline`, renamed because
 * "stop" read as the opposite of `use-agent` when it is the opposite of `start-agent` — see the
 * handler comment in agent-handlers.ts.)
 *
 * Also CLEARS the persisted selection when it names this agent (review F1). The daemon clears an
 * offline agent from every connection's current-agent state; the CLI's durable mirror of that state
 * must follow, or the next command would try to act as an agent the operator just took offline.
 */
export async function setAgentOffline(celloDir: string, name: string, opts: ParityOptions): Promise<CliOutput> {
  const out = await ipcCommand(celloDir, IPC_METHODS["set-agent-offline"], { name }, opts, false);
  if (out.exitCode === 0 && (await readCurrentAgent(celloDir)) === name) {
    await clearCurrentAgent(celloDir);
  }
  return out;
}

/**
 * `cello stop-using-agent` — forget the CLI's persisted selection.
 *
 * IT DOES NOT RELEASE A LIVE MCP SESSION, AND MUST NOT CLAIM TO. Attendance is PER-CONNECTION. The
 * MCP shim holds one long-lived socket, which is what `isAttended()` sees; every CLI invocation is a
 * fresh ephemeral connection that starts with `currentAgent: null` and dies microseconds later. So
 * calling the daemon handler from here would always take its idempotent branch and answer "this
 * connection was not attending any agent" — true of the socket, and worthless to the operator, whose
 * agent is attended somewhere else entirely.
 *
 * That is exactly the gesture to expect: attended in Claude Code, step over to a terminal, run
 * `cello stop-using-agent`. Passing the daemon's reply through would print "nothing to release",
 * exit 0, delete the persisted selection, and leave the agent attended with its away message still
 * suppressed — a success message for the opposite of what happened, which is the same class of
 * defect as the name that started all this (review finding 2).
 *
 * So the CLI reports ITS OWN effect and names the half it cannot reach. The daemon call is skipped
 * rather than made-and-ignored: an IPC round-trip whose answer we would discard is not honesty, it
 * is theatre.
 */
export async function stopUsingAgent(celloDir: string, opts: ParityOptions): Promise<CliOutput> {
  const previous = await readCurrentAgent(celloDir);
  await clearCurrentAgent(celloDir);
  return emitIpcResult(
    previous
      ? {
          ok: true,
          cleared: previous,
          guidance:
            `Forgot the persisted CLI selection '${previous}'. A live MCP session attending this agent is ` +
            `NOT released — do that in the session itself with cello_stop_using_agent. To make the agent ` +
            `stop answering everywhere, use 'cello set-agent-offline ${previous}'.`,
        }
      : {
          ok: true,
          cleared: null,
          guidance: "No CLI agent selection was persisted, so there was nothing to forget.",
        },
    opts,
  );
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

/**
 * `cello sessions` → cello_list_sessions: THIS agent's sessions, matching the MCP tool exactly.
 *
 * DOD-CLI-SESSIONS-SCOPE-1. It used to call the daemon-wide `list_sessions` instead, whose comment
 * explained why — "for the `cello sessions` CLI which has no current agent". That was true when it
 * was written and stopped being true when `use-agent` became durable: the CLI has a persisted
 * selection now, and every other agent-scoped command replays it. The effect of the stale premise
 * was that `cello sessions` answered for ALL agents while `cello_sessions` answered for one, so the
 * two surfaces reported different open-session sets for the same selection — and a multi-agent
 * operator read another agent's rows as their own.
 *
 * The daemon-wide view is still reachable, as `--all-agents`, because it is genuinely useful for
 * "what is open anywhere on this machine". It is opt-in: a listing that silently answers for a
 * principal you did not ask about is the bug, not the feature.
 */
export function listSessions(
  celloDir: string,
  opts: ParityOptions & { filter?: string; limit?: number },
): Promise<CliOutput> {
  return ipcCommand(
    celloDir,
    IPC_METHODS.sessions,
    defined({ filter: opts.filter, limit: opts.limit }),
    opts,
  );
}

/** `cello transcript <session-id>` → cello_get_transcript (durable, survives a daemon restart). */
export function transcript(celloDir: string, sessionId: string, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS.transcript, { session_id: sessionId }, opts);
}

/**
 * `cello sealed-receipt <session-id>` → cello_get_sealed_receipt: the notarized bilateral SEAL
 * receipt, the artifact the whole close ceremony exists to produce and the one an arbitrator reads.
 *
 * NOT the same handler as `cello relay-receipts <name>`, which calls cello_get_relay_receipts
 * (per-message relay delivery proofs). The two are routinely conflated; they are different
 * artifacts and must keep distinct names.
 */
export function sealedReceipt(celloDir: string, sessionId: string, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["sealed-receipt"], { session_id: sessionId }, opts);
}

// The WHOLE address book speaks the §3 contract — every sub-verb, not just some. A bash script
// branching on stderr must not get DIFFERENT conventions between sub-verbs of the same command.
// One command, one contract: contact failures print JSON on stderr, never stdout.

/** `cello contact <pubkey> add` → cello_contact_add. */
export function contactAdd(celloDir: string, pubkey: string, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["contact-add"], { pubkey }, opts);
}

/** `cello contact remove <pubkey>` → cello_contact_remove. */
export function contactRemove(celloDir: string, pubkey: string, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["contact-remove"], { pubkey }, opts);
}

/** `cello contacts` → cello_contact_list. */
export function contactList(celloDir: string, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS.contacts, {}, opts);
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

// ─── Agent settings and outbound name ──────────────────────────────────────────────────────────
//
// AGENT-SCOPED: they write to one agent's row, so they resolve their agent through withDaemon's
// use-agent replay like every other agent-scoped command. Do not give them a private connection
// helper — a second connection path is a second agent-resolution rule, and one operator gesture must
// not mean two different things depending on which command it reaches.

/** `cello settings get [key]` → cello_settings_get. Omitted key returns the whole set. */
export function settingsGet(celloDir: string, key: string | undefined, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["settings-get"], defined({ key }), opts);
}

/** `cello settings set <key> <value>` → cello_settings_set. The DAEMON validates the key and, for
 *  bound keys, that the value is a finite positive integer; the CLI surfaces its verdict verbatim. */
export function settingsSet(celloDir: string, key: string, value: string | null, opts: ParityOptions): Promise<CliOutput> {
  // `value: null` CLEARS the setting (`cello settings clear <key>`), the same shape
  // cello_contact_set_away has always taken. Sent explicitly rather than as an omitted field: the
  // handler distinguishes "clear this" from "you forgot the value", and an absent key would read as
  // the latter.
  return ipcCommand(celloDir, IPC_METHODS["settings-set"], { key, value }, opts);
}

// ─── DOD-M9B-SURFACE-1: the security layer's control surface (policy D-4) ──────────────────────
//
// NOT agent-scoped: the security layer screens every message on this machine regardless of which
// agent is selected, so its config is per-INSTALL. Passing agentScoped=false keeps `cello config`
// working before any agent is selected — the state an operator is in when a misfiring guard has
// just blocked them and they need to fix it.

/** `cello config list` → every guard with its value AND its governance (version, direction, confirmed). */
export function gatewayConfigList(celloDir: string, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, "cello_config_list", {}, opts, false);
}

/** `cello config get <key>` → one guard, plus whether its version chain still verifies. */
export function gatewayConfigGet(celloDir: string, key: string, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, "cello_config_get", { key }, opts, false);
}

/**
 * `cello config set <key> <value>` — and THE human confirmation the whole D-4 decision rests on.
 *
 * Two phases, and the first one is not a dry run: the daemon attempts the change unconfirmed. If it
 * TIGHTENS, it is already applied and we print the result. If it LOOSENS, the store refuses it (no
 * row written) and answers `needs_confirmation` — only then do we prompt, and only then do we
 * re-send with `confirmed: true`.
 *
 * There is deliberately NO `--yes` flag (M9B-D16). A flag that lets a script confirm a loosening is
 * the environment-variable bypass with a friendlier name, and removing that bypass is the sibling
 * decision (D-5). If stdin is not a TTY there is no human here, so the answer is no.
 */
export function gatewayConfigSet(
  celloDir: string,
  key: string,
  value: string,
  opts: ParityOptions,
  prompt: (question: string) => Promise<ConfirmAnswer> = confirmAtTty,
): Promise<CliOutput> {
  return withDaemon(celloDir, opts, false, async (client) => {
    const first = (await client.send("cello_config_set", { key, value })) as Record<string, unknown>;
    if (first.reason !== "needs_confirmation") return first;

    // Render what is ACTUALLY changing. `set` REPLACES a list, so showing only the new value would
    // hide four dropped entries in a five-entry whitelist (review F7). `from: null` means the key
    // has never been configured and the built-in tightest default applies.
    const from = "from" in first ? first.from : undefined;
    const fromText = from === null || from === undefined
      ? "(never configured — the built-in default applies)"
      : JSON.stringify(from);
    const answer = await prompt(
      `This makes the security layer LESS protective:\n` +
        `  ${key}\n` +
        `    from: ${fromText}\n` +
        `    to:   ${value}\n` +
        `  ${String(first.guidance ?? "")}\n` +
        `Apply it?`,
    );

    if (answer === "no_tty") {
      // NOT the same as "the operator said no" (review F3). A CI job or an agent was never shown a
      // prompt, and telling it the human declined is a lie about what happened — and leaves it no
      // way forward. Name the cause and hand over the command.
      return {
        ok: false,
        reason: "not_a_tty",
        guidance:
          `Weakening '${key}' needs a human at a terminal, and this session has no interactive ` +
          `input. Run it yourself in a terminal: cello config set ${key} ${value}`,
      };
    }
    if (answer === "no") {
      // The operator was asked and said no. Not an error — and the absence of a stored row is the
      // proof that nothing changed.
      return { ok: false, reason: "declined", guidance: `'${key}' was NOT changed.` };
    }
    return (await client.send("cello_config_set", { key, value, confirmed: true })) as Record<string, unknown>;
  });
}

/** What a confirmation attempt actually resolved to. `no_tty` is NOT `no` — see F3 above. */
export type ConfirmAnswer = "yes" | "no" | "no_tty";

/**
 * Ask a yes/no question on the terminal. Returns `no_tty` — distinct from `no` — when stdin is not
 * a TTY: a pipe, a CI job or an agent spawning the CLI is not a human, and treating one as a human
 * who declined is the side door INV-10 exists to close, told as a misleading story.
 */
async function confirmAtTty(question: string): Promise<ConfirmAnswer> {
  if (!process.stdin.isTTY) return "no_tty";
  process.stderr.write(`${question} [y/N] `);
  const answer = await new Promise<string>((resolve) => {
    process.stdin.resume();
    process.stdin.setEncoding("utf8");
    const done = (value: string): void => {
      process.stdin.pause();
      process.stdin.off("data", onData);
      process.stdin.off("end", onEnd);
      process.stdin.off("error", onEnd);
      resolve(value);
    };
    // `end`/`error` as well as `data`: a terminal where the operator hits Ctrl-D closes stdin
    // without ever emitting data, and a promise that never settles is a hang — INV-6 says a
    // deadline always produces an answer, and "no" is the safe one.
    const onData = (chunk: string): void => done(chunk.trim().toLowerCase());
    const onEnd = (): void => done("");
    process.stdin.once("data", onData);
    process.stdin.once("end", onEnd);
    process.stdin.once("error", onEnd);
  });
  return answer === "y" || answer === "yes" ? "yes" : "no";
}

/**
 * `cello policy log` → cello_policy_log (DOD-M9B-AUDIT-1, policy D-11).
 *
 * Ships with the enforcement flip by decision: it is the answer to "did this new error come from
 * the security layer or from my own change?" — a lookup instead of a guess.
 */
export function policyLog(
  celloDir: string,
  opts: ParityOptions & { limit?: number; sinceMs?: number },
): Promise<CliOutput> {
  return ipcCommand(
    celloDir,
    "cello_policy_log",
    defined({ limit: opts.limit, since_ms: opts.sinceMs }),
    opts,
    false,
  );
}

/** `cello moniker set <name>` / `cello moniker clear` → cello_set_moniker. Null clears the override.
 *  This is the agent's OWN outbound name — not `contact set-moniker`, which names a COUNTERPARTY. */
export function monikerSet(celloDir: string, moniker: string | null, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["moniker-set"], { moniker }, opts);
}

// ─── Group B: live conversation (mirrors the MCP params EXACTLY) ───────────────────────────────

/** `cello initiate-session <target-pubkey>` → cello_initiate_session. Prints the session_id. */
export function initiate(
  celloDir: string,
  targetPubkey: string,
  opts: ParityOptions & { include?: string[]; exclude?: string[] },
): Promise<CliOutput> {
  const extra: Record<string, unknown> = {};
  if (opts.include) extra["include_signals"] = opts.include;
  if (opts.exclude) extra["exclude_signals"] = opts.exclude;
  return ipcCommand(celloDir, IPC_METHODS["initiate-session"], { target_pubkey: targetPubkey, ...extra }, opts);
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
  opts: ParityOptions & {
    governanceDecisions?: Record<string, string>;
    signal?: "over" | "standby" | "wrap";
    estMinutes?: number;
  },
): Promise<CliOutput> {
  const { signal, estMinutes } = opts;
  const token =
    signal === "over" ? " [[OVER]]" :
    signal === "wrap" ? " [[WRAP]]" :
    signal === "standby" ? ` [[STANDBY EST:${estMinutes}m]]` :
    "";
  return ipcCommand(
    celloDir,
    "cello_send",
    defined({ session_id: sessionId, content: content + token, governance_decisions: opts.governanceDecisions }),
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

/**
 * `cello close-session <session-id> [--force]` → cello_close_session. Normally triggers the bilateral seal
 * ceremony. --force is passed ONLY when asked for (mirroring the shim), since it forfeits the seal.
 */
export function closeSession(
  celloDir: string,
  sessionId: string,
  opts: ParityOptions & { force?: boolean; sessionName?: string },
): Promise<CliOutput> {
  const params: Record<string, unknown> = { session_id: sessionId };
  if (opts.force) params.force = true;
  // DOD-SESSION-NAME-1 (AC-A14): only sent when the operator asked for it. Omitted means "no name",
  // which is a meaningful state — never fill it in for them.
  if (opts.sessionName !== undefined) params.session_name = opts.sessionName;
  return ipcCommand(celloDir, IPC_METHODS["close-session"], params, opts);
}

/**
 * `cello name-session <session-id> <name...>` (or --clear) → cello_name_session.
 *
 * DOD-SESSION-NAME-1 (AC-A15). The name is taken from the remaining positionals and joined, so
 * multi-word names work without quoting: `cello name-session ab12… the deploy postmortem`.
 * `--clear` sends null, which is how you un-name a session.
 */
export function nameSession(
  celloDir: string,
  sessionId: string,
  sessionName: string | null,
  opts: ParityOptions,
): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["name-session"], { session_id: sessionId, session_name: sessionName }, opts);
}

/** `cello dismiss <session-id>` → cello_dismiss. Clears a terminal session from the inbox. */
export function dismissSession(
  celloDir: string,
  sessionId: string,
  opts: ParityOptions,
): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS.dismiss, { session_id: sessionId }, opts);
}

/** `cello await-session [--timeout-ms N]` → cello_await_session. Blocks for an inbound doorbell. */
export function awaitSession(
  celloDir: string,
  opts: ParityOptions & { timeoutMs?: number },
): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["await-session"], defined({ timeout_ms: opts.timeoutMs }), opts);
}

// ─── Group: attestation-consent (M10B / DOD-END-SURFACE-1) ─────────────────────────────────────────────────
// No `agent` argument on any of the three: they are scoped to the SELECTED agent by the daemon.
// Consent is a statement about oneself; naming another agent would be accepting on its behalf.

/** `cello attestation-consent list` → cello_attestation_consent_list. */
export function attestationConsentList(celloDir: string, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["attestation-consent-list"], {}, opts);
}

/** `cello attestation-consent accept <signal-hash>` → cello_attestation_consent_accept. */
export function attestationConsentAccept(celloDir: string, hashPrefix: string, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["attestation-consent-accept"], { hash_prefix: hashPrefix }, opts);
}

/** `cello attestation-consent refuse <hash> [message…]` → cello_attestation_consent_refuse. An empty message is OMITTED, not
 *  sent as "": silence is the default and it must be the literal absence of the field (M10B-D4). */
export function attestationConsentRefuse(celloDir: string, hashPrefix: string, message: string | null, opts: ParityOptions): Promise<CliOutput> {
  const params: Record<string, unknown> = { hash_prefix: hashPrefix };
  if (message !== null && message.length > 0) params.message = message;
  return ipcCommand(celloDir, IPC_METHODS["attestation-consent-refuse"], params, opts);
}

/** `cello contact <pubkey> set-signal <hash> <on|off|clear>` → cello_contact_set_signal.
 *  `clear` sends null — distinct from `off`, which is an explicit "never show this to them". */
export function contactSetSignal(
  celloDir: string, pubkey: string, hashPrefix: string, present: boolean | null, opts: ParityOptions,
): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["contact-set-signal"], { pubkey, hash_prefix: hashPrefix, present }, opts);
}

// ─── M14 / DOD-DOC-TOOLS-1 — federated documents ────────────────────────────────────────────────

/** `cello doc propose <peer-pubkey> [--type <t>] [--append-only] [--from-file <path>]` → cello_doc_propose. */
export function docPropose(
  celloDir: string,
  peerPubkey: string,
  opts: ParityOptions & { documentType?: string; appendOnly?: boolean; startingContent?: string },
): Promise<CliOutput> {
  return ipcCommand(
    celloDir,
    IPC_METHODS["doc-propose"],
    defined({
      peer_pubkey: peerPubkey,
      document_type: opts.documentType,
      append_only: opts.appendOnly === true ? true : undefined,
      starting_content: opts.startingContent,
    }),
    opts,
  );
}

/** `cello doc inbox` → cello_doc_inbox. Proposals awaiting a consent decision. */
export function docInbox(celloDir: string, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["doc-inbox"], {}, opts);
}

/** `cello doc accept <document-id>` → cello_doc_accept. */
export function docAccept(celloDir: string, documentId: string, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["doc-accept"], { document_id: documentId }, opts);
}

/** `cello doc refuse <document-id> [why…]` → cello_doc_refuse. An empty reason is OMITTED, so the
 *  daemon applies its own default rather than recording the empty string as the operator's words. */
export function docRefuse(
  celloDir: string,
  documentId: string,
  reason: string | null,
  opts: ParityOptions,
): Promise<CliOutput> {
  return ipcCommand(
    celloDir,
    IPC_METHODS["doc-refuse"],
    defined({ document_id: documentId, reason: reason !== null && reason.length > 0 ? reason : undefined }),
    opts,
  );
}

/** `cello doc list` → cello_doc_list. */
export function docList(celloDir: string, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["doc-list"], {}, opts);
}

/** `cello doc read <document-id>` → cello_doc_read. */
export function docRead(celloDir: string, documentId: string, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["doc-read"], { document_id: documentId }, opts);
}

/** `cello doc diff <document-id>` → cello_doc_diff. What changed since you last read it. */
export function docDiff(celloDir: string, documentId: string, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["doc-diff"], { document_id: documentId }, opts);
}

/** `cello doc write <document-id> <content…>` → cello_doc_write.
 *
 *  The COMPLETE new text, never a patch — the daemon diffs it against current state, so an offset
 *  cannot go stale under the peer's concurrent edit. */
export function docWrite(
  celloDir: string,
  documentId: string,
  content: string,
  opts: ParityOptions,
): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["doc-write"], { document_id: documentId, content }, opts);
}

/** `cello doc close <document-id>` → cello_doc_close. Bilateral: settles when both sides have said it. */
export function docClose(celloDir: string, documentId: string, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["doc-close"], { document_id: documentId }, opts);
}

/** `cello doc kill <document-id>` → cello_doc_kill. One-sided and immediate; the peer is told best-effort. */
export function docKill(celloDir: string, documentId: string, opts: ParityOptions): Promise<CliOutput> {
  return ipcCommand(celloDir, IPC_METHODS["doc-kill"], { document_id: documentId }, opts);
}
