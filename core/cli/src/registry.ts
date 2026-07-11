/**
 * DOD-CLI-PARITY-1 §4 — the command REGISTRY: the single source of truth for the `cello` CLI.
 *
 * Each entry carries { name, summary, help, flags, run }. Everything derives from this one table:
 *  - dispatch (src/bin/cello.ts) — no switch to keep in sync,
 *  - the `cello --help` described `Commands:` table — rendered from each entry's `summary`
 *    (this is DOD-ONBOARD-HELP-1's remaining gap; the old surface was a pipe-delimited blob),
 *  - per-command `cello <cmd> --help` — the pre-existing help text, moved here VERBATIM,
 *  - the recognized-flag set used to reject unknown flags before dispatch.
 *
 * Consequence, and the reason for the refactor: the help table, per-command help, and dispatch
 * CANNOT DRIFT, and adding a command FORCES adding its one-line summary.
 */

import { MONIKER_RE } from "@cello-protocol/protocol-types";
import type { Logger } from "@cello-protocol/daemon";
import {
  login,
  logout,
  status,
  register,
  createAgent,
  removeAgent,
  refreshShares,
  relayReceipts,
  sessions,
  type SessionFilter,
  contactAdd,
  contactRemove,
  contactList,
  contactSetTier,
  contactSetAway,
  settingsGet,
  settingsSet,
  monikerSet,
  telegramSetToken,
  type CommandResult,
} from "./commands.js";
import { splitAgentFlag } from "./arg-parse.js";
import {
  listAgents,
  startAgent,
  stopAgent,
  useAgent,
  inbox,
  transcript,
  contactSetMoniker,
  sealedReceipt,
  initiate,
  send,
  receive,
  receiveSession,
  closeSession,
  awaitSession,
} from "./parity-commands.js";

/** Read the whole of stdin — `cello send <id> --stdin` for message text with newlines/quotes. */
async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

/** What a command needs from the process to run. Injected so dispatch is testable in-process. */
export interface CommandContext {
  celloDir: string;
  daemonBin: string;
  logger: Logger;
  /** Progress lines printed BEFORE the result (e.g. logout's "Shutting down…"). */
  onProgress?: (line: string) => void;
}

/** The (stdout, stderr, exitCode) triple a command produces. See json-out.ts for the §3 contract. */
export interface CliOutput {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export interface FlagSpec {
  name: string;
  /** The flag takes the NEXT argv token as its value (so a dash-prefixed value isn't misread). */
  consumesValue?: boolean;
}

export interface CommandSpec {
  name: string;
  /** One line. Rendered as this command's row in the `cello --help` Commands: table. */
  summary: string;
  /** Full per-command help, printed by `cello <cmd> --help`. */
  help: string;
  flags?: readonly FlagSpec[];
  /**
   * The daemon IPC handler this command calls — i.e. the SAME handler the corresponding `cello_*`
   * MCP tool calls. Recorded here so the parity claim (DoD §9: "every cello_* MCP tool has a cello
   * command calling the same IPC handler") is AUDITABLE from the registry itself rather than by
   * reading each implementation. Absent for commands that are not a single IPC call (login, logout,
   * install) or that route to sub-handlers (contact, settings, moniker, telegram).
   */
  ipcMethod?: string;
  /**
   * True for commands that honor the §3 bash-adapter contract (JSON to stdout, structured error
   * VERBATIM to stderr, exit code branching on ok). Such commands automatically accept `--pretty`.
   */
  jsonOut?: boolean;
  run(ctx: CommandContext, args: string[]): Promise<CliOutput>;
}

/** Parse the parity commands' shared flags out of argv (`--agent`, `--pretty`, and value flags). */
function parityOpts(args: string[]): { agent?: string; pretty: boolean; positional: string[] } {
  const { agent, positional } = splitAgentFlag(args);
  const pretty = positional.includes("--pretty");
  return { agent, pretty, positional: positional.filter((a) => a !== "--pretty") };
}

/** Read `--flag <value>` out of a positional list, returning the value and the remaining args. */
function takeValueFlag(args: string[], flag: string): { value?: string; rest: string[] } {
  const i = args.indexOf(flag);
  if (i === -1) return { rest: args };
  return { value: args[i + 1], rest: args.filter((_, j) => j !== i && j !== i + 1) };
}

function numberOrUndefined(raw: string | undefined): number | undefined {
  if (raw === undefined) return undefined;
  const n = Number(raw);
  return Number.isFinite(n) ? n : undefined;
}

/** Adapt a legacy CommandResult (single `output` string, always stdout) to the CliOutput triple. */
function legacy(result: CommandResult): CliOutput {
  return { stdout: result.output, stderr: "", exitCode: result.exitCode };
}

/**
 * `--agent <name>` — recognized by every agent-scoped command.
 *
 * `consumesValue: false` is deliberate and is what checkArgs PARITY requires: the pre-existing
 * checkArgs never skipped --agent's value (only `--limit` did), and flipping this to true would
 * change `cello contact list --agent --bogus` from a fail-loud unknown_flag into a silently
 * accepted agent literally named "--bogus". The value is claimed by splitAgentFlag (arg-parse.ts),
 * which owns --agent parsing; checkArgs only needs to know the FLAG is legal. Same for install's
 * --agent / --hermes-home below.
 */
const AGENT_FLAG: readonly FlagSpec[] = [{ name: "--agent", consumesValue: false }];

/** Agent-scoped parity commands also take --pretty (granted automatically via `jsonOut`). */
const AGENT_AND_TIMEOUT: readonly FlagSpec[] = [
  { name: "--agent", consumesValue: false },
  { name: "--timeout-ms", consumesValue: true },
];

export const COMMANDS: readonly CommandSpec[] = [
  {
    name: "login",
    summary: "Start the local daemon (or connect to a running one) and bring your agents online.",
    help: "Usage: cello login  — start the daemon (or connect to an existing one).",
    async run(ctx) {
      return legacy(await login(ctx.celloDir, ctx.daemonBin, ctx.logger));
    },
  },
  {
    name: "logout",
    summary: "Stop the running daemon (waits until it is actually gone).",
    help: "Usage: cello logout  — send shutdown to the running daemon.",
    async run(ctx) {
      // DOD-LOGOUT-WAIT-1: logout WAITS for the daemon to actually die before claiming
      // "Daemon stopped." — the immediate progress line tells the operator the command
      // activated and the short pause is expected.
      return legacy(await logout(ctx.celloDir, ctx.onProgress));
    },
  },
  {
    name: "status",
    summary: "Show daemon + agent state as structured JSON.",
    help: "Usage: cello status  — query the daemon and print the structured status JSON.",
    async run(ctx) {
      return legacy(await status(ctx.celloDir));
    },
  },
  {
    name: "register",
    summary: "Register a local agent with the directory using a pre-auth token.",
    help:
      "Usage: cello register <agent> <pre-auth-token>  — register a LOCAL agent with the directory.\n" +
      "  The two-step onboarding: (1) 'cello create-agent <name>' makes the local identity; (2) 'cello register <name> <token>' registers it with the directory.\n" +
      "  The token is a single-use pre-authorization ticket from the CELLO Operations Agent on Telegram, format 'CELLO-' + 33 characters, valid 24h.\n" +
      "  Example:  cello register alice CELLO-3xY7...\n" +
      "  Env-var form (avoids retyping):  CELLO_PREAUTH_TOKEN=CELLO-3xY7... cello register alice\n" +
      "  Quoting is only needed if a value contains spaces (agent names and tokens never do).",
    async run(ctx, args) {
      // cello register <agent> [preAuthToken]  (token falls back to CELLO_PREAUTH_TOKEN so it need
      // not appear in shell history). Optional phone stub follows.
      const agent = args[0] ?? "";
      const preAuthToken = args[1] ?? process.env.CELLO_PREAUTH_TOKEN ?? "";
      const phoneStub = args[2] ?? "";
      return legacy(await register(ctx.celloDir, agent, preAuthToken, phoneStub));
    },
  },
  {
    name: "create-agent",
    summary: "Create a new local agent identity (does not touch the directory).",
    help:
      "Usage: cello create-agent <name>  — create a new LOCAL agent identity (does not touch the directory).\n" +
      // MONIKER-0 AC2: the regex text is DERIVED from the shared constant, never hand-typed.
      `  Name rule: 1–64 characters, letters/digits/'-'/'_' only, no spaces (regex ${MONIKER_RE.source}).\n` +
      "  Next step: 'cello register <name> <pre-auth-token>' to register it with the directory.",
    async run(ctx, args) {
      return legacy(await createAgent(ctx.celloDir, args[0] ?? ""));
    },
  },
  {
    name: "remove-agent",
    summary: "Retire a local agent (one-way) and free its name.",
    help: "Usage: cello remove-agent <name>  — retires a local agent (one-way) and frees its name.",
    async run(ctx, args) {
      return legacy(await removeAgent(ctx.celloDir, args[0] ?? ""));
    },
  },
  {
    name: "refresh",
    summary: "Refresh an agent's threshold shares (new epoch).",
    help: "Usage: cello refresh <name>  — proactively refresh the agent's threshold shares (new epoch).",
    async run(ctx, args) {
      return legacy(await refreshShares(ctx.celloDir, args[0] ?? ""));
    },
  },
  {
    name: "receipts",
    summary: "List an agent's stored relay ordering receipts.",
    help: "Usage: cello receipts <name>  — list the agent's stored relay ordering receipts.",
    async run(ctx, args) {
      return legacy(await relayReceipts(ctx.celloDir, args[0] ?? ""));
    },
  },
  {
    name: "sessions",
    summary: "List session history (open by default; --all for everything).",
    help:
      "Usage: cello sessions [--open|--closed|--failed|--all] [--limit N]  — list session history (defaults to open).",
    flags: [
      { name: "--open" },
      { name: "--closed" },
      { name: "--failed" },
      { name: "--all" },
      { name: "--limit", consumesValue: true },
    ],
    async run(ctx, args) {
      let filter: SessionFilter | undefined;
      if (args.includes("--all")) filter = "all";
      else if (args.includes("--closed")) filter = "closed";
      else if (args.includes("--failed")) filter = "failed";
      else if (args.includes("--open")) filter = "open";
      const limitIdx = args.indexOf("--limit");
      let limit: number | undefined;
      if (limitIdx !== -1 && args[limitIdx + 1] !== undefined) {
        const n = Number(args[limitIdx + 1]);
        if (Number.isFinite(n) && n > 0) limit = Math.floor(n);
      }
      return legacy(await sessions(ctx.celloDir, { filter, limit }));
    },
  },
  {
    name: "contact",
    summary: "Manage the per-agent address book (add, remove, list, set-tier, set-away, set-moniker).",
    help:
      "Usage: cello contact add <pubkey> [--agent <name>] | cello contact remove <pubkey> [--agent <name>] | cello contact list [--agent <name>]\n" +
      "       cello contact set-tier <pubkey> <0..4> [--agent <name>]      — trust tier (unknown|known|whitelisted|vip)\n" +
      "       cello contact set-away <pubkey> <message…> [--agent <name>]  — per-contact away text (empty clears it)\n" +
      "       cello contact set-moniker <pubkey> <moniker> [--agent <name>] — YOUR pet name for THEM (empty clears it)\n" +
      "  Per-agent contact whitelist (M8C-CONTACT-1). --agent defaults to the current/sole-online agent.\n" +
      "  Contacts are added automatically too: initiating a session to X, or accepting X's inbound request, adds X.\n" +
      "  Note: 'set-moniker' is the name YOU give a CONTACT. The top-level 'cello moniker' is your OWN outbound name.\n" +
      "  ('tier' and 'away' remain accepted as aliases of set-tier / set-away.)\n" +
      "  Example:  cello contact list --agent alice",
    flags: AGENT_FLAG,
    async run(ctx, args) {
      const { agent, positional } = splitAgentFlag(args);
      const [sub, pubkey, valueArg] = positional;
      if (sub === "add" && pubkey) return legacy(await contactAdd(ctx.celloDir, pubkey, agent));
      if (sub === "remove" && pubkey) return legacy(await contactRemove(ctx.celloDir, pubkey, agent));
      if (sub === "list") return legacy(await contactList(ctx.celloDir, agent));
      // set-tier / set-away are the DOD-CLI-PARITY-1 names; tier / away are the pre-existing verbs,
      // kept as aliases so no existing script or muscle-memory breaks.
      if ((sub === "set-tier" || sub === "tier") && pubkey && valueArg !== undefined) {
        // Daemon validates the value; a non-numeric arg surfaces as its invalid_tier verdict.
        return legacy(await contactSetTier(ctx.celloDir, pubkey, Number(valueArg), agent));
      }
      if ((sub === "set-away" || sub === "away") && pubkey) {
        // The rest of the args form the away text; empty → clear.
        const message = positional.slice(2).join(" ");
        return legacy(await contactSetAway(ctx.celloDir, pubkey, message.length > 0 ? message : null, agent));
      }
      if (sub === "set-moniker" && pubkey) {
        // DOD-CLI-PARITY-1: the per-CONTACT pet name (cello_contact_set_moniker) — was MCP-only.
        // Empty → null clears it, mirroring the tool.
        const moniker = positional.slice(2).join(" ");
        return contactSetMoniker(ctx.celloDir, pubkey, moniker.length > 0 ? moniker : null, { agent });
      }
      return {
        stdout: helpForSpec("contact"),
        stderr: "",
        exitCode: 1,
      };
    },
  },
  {
    name: "settings",
    summary: "Get or set an agent's reachability policy (session/byte bounds, away text).",
    help:
      "Usage: cello settings get [key] [--agent <name>] | cello settings set <key> <value> [--agent <name>]\n" +
      "  Per-agent reachability policy (DOD-SETTINGS-1). Keys: bounds.<tier>.max_sessions, bounds.<tier>.max_bytes\n" +
      "  (tier = unknown|known|whitelisted|vip; a finite positive integer), away.default, away.tier.<tier> (away text).\n" +
      "  An unset key uses the built-in default. Example:  cello settings set bounds.known.max_sessions 8 --agent alice",
    flags: AGENT_FLAG,
    async run(ctx, args) {
      const { agent, positional } = splitAgentFlag(args);
      const [sub, key, value] = positional;
      if (sub === "get") return legacy(await settingsGet(ctx.celloDir, key, agent)); // key optional → all
      if (sub === "set" && key && value !== undefined) {
        return legacy(await settingsSet(ctx.celloDir, key, value, agent));
      }
      return {
        stdout: "Usage: cello settings get [key] [--agent <name>] | cello settings set <key> <value> [--agent <name>]",
        stderr: "",
        exitCode: 1,
      };
    },
  },
  {
    name: "moniker",
    summary: "Set or clear the agent's OWN outbound display name (what a counterparty sees).",
    help:
      "Usage: cello moniker set <name> [--agent <agent>] | cello moniker clear [--agent <agent>]\n" +
      "  The agent's OUTBOUND name — what a counterparty's doorbell shows (MONIKER-1). Defaults to the agent name; 'set' stores an override, 'clear' restores the default.\n" +
      // MONIKER-0 AC2: the regex text is DERIVED from the shared constant, never hand-typed.
      `  Name rule: 1–64 characters, letters/digits/'-'/'_' only, no spaces (regex ${MONIKER_RE.source}).\n` +
      "  Local-only: never sent to the directory; the receiver treats it as an unverified hint (like caller ID).\n" +
      "  Example:  cello moniker set Wonderland_Alice --agent alice",
    flags: AGENT_FLAG,
    async run(ctx, args) {
      const { agent, positional } = splitAgentFlag(args);
      const [sub, name] = positional;
      if (sub === "set" && name) return legacy(await monikerSet(ctx.celloDir, name, agent));
      if (sub === "clear" && !name) return legacy(await monikerSet(ctx.celloDir, null, agent));
      return { stdout: helpForSpec("moniker"), stderr: "", exitCode: 1 };
    },
  },
  {
    name: "telegram",
    summary: "Configure the daemon-owned Telegram doorbell.",
    help:
      "Usage: cello telegram set-token <bot_token> <allowlisted_chat_id>  — configure the daemon-owned Telegram doorbell (M8C-TGDOOR-1).\n" +
      "  Starts a single long-lived poller immediately; the operator chat given is the ONLY one that ever receives doorbell events.",
    async run(ctx, args) {
      const [sub, botToken, chatId] = args;
      if (sub === "set-token" && botToken && chatId) {
        return legacy(await telegramSetToken(ctx.celloDir, botToken, chatId));
      }
      return { stdout: "Usage: cello telegram set-token <bot_token> <allowlisted_chat_id>", stderr: "", exitCode: 1 };
    },
  },
  {
    name: "install",
    summary: "Wire the local CELLO daemon into a Hermes Agent installation.",
    help:
      "Usage: cello install hermes --agent <name> [--hermes-home <path>]  — wire the local CELLO daemon into a Hermes Agent installation.\n" +
      "  Scaffolds the CELLO platform-adapter plugin into the Hermes home (default ~/.hermes), binds CELLO_AGENT_NAME in its .env,\n" +
      "  and registers via 'hermes plugins enable cello' + 'hermes mcp add cello'. Idempotent — re-run to upgrade.\n" +
      "  After installing, restart the gateway: hermes gateway restart",
    flags: [{ name: "--agent" }, { name: "--hermes-home" }],
    async run(_ctx, args) {
      const agentIdx = args.indexOf("--agent");
      const homeIdx = args.indexOf("--hermes-home");
      // Find the target positional, excluding both flags AND their values — so
      // `cello install --agent alice hermes` still resolves target=hermes.
      const target = args.find(
        (a, i) =>
          !a.startsWith("-") &&
          !(agentIdx !== -1 && i === agentIdx + 1) &&
          !(homeIdx !== -1 && i === homeIdx + 1),
      );
      if (target !== "hermes") {
        return { stdout: helpForSpec("install"), stderr: "", exitCode: 1 };
      }
      const { installHermes } = await import("./hermes/install-hermes.js");
      return legacy(
        await installHermes({
          agentName: agentIdx !== -1 ? (args[agentIdx + 1] ?? "") : "",
          hermesHome: homeIdx !== -1 ? args[homeIdx + 1] : undefined,
        }),
      );
    },
  },

  // ═══ DOD-CLI-PARITY-1 — the MCP-only capabilities, now reachable from bash ══════════════════
  // Each honors the §3 contract (jsonOut) and calls the SAME daemon handler as its cello_* MCP
  // tool (ipcMethod). Group A = operator control + address book; Group B = live conversation.

  {
    name: "agents",
    summary: "List every loaded agent and whether it is online.",
    help:
      "Usage: cello agents [--pretty]  — list all loaded agents (name, state).\n" +
      "  The CLI twin of the cello_list_agents MCP tool. Prints JSON; use --pretty for humans.",
    ipcMethod: "cello_list_agents",
    jsonOut: true,
    async run(ctx, args) {
      const { pretty } = parityOpts(args);
      return listAgents(ctx.celloDir, { pretty });
    },
  },
  {
    name: "start-agent",
    summary: "Bring an agent online (without selecting it as current).",
    help:
      "Usage: cello start-agent <name> [--pretty]  — bring a registered agent ONLINE.\n" +
      "  Does NOT select it as the current agent — use 'cello use-agent <name>' for that.\n" +
      "  Idempotent: starting an already-online agent is safe.",
    ipcMethod: "cello_start_agent",
    jsonOut: true,
    async run(ctx, args) {
      const { pretty, positional } = parityOpts(args);
      return startAgent(ctx.celloDir, positional[0] ?? "", { pretty });
    },
  },
  {
    name: "stop-agent",
    summary: "Take an agent offline.",
    help: "Usage: cello stop-agent <name> [--pretty]  — take an agent offline.",
    ipcMethod: "cello_stop_agent",
    jsonOut: true,
    async run(ctx, args) {
      const { pretty, positional } = parityOpts(args);
      return stopAgent(ctx.celloDir, positional[0] ?? "", { pretty });
    },
  },
  {
    name: "use-agent",
    summary: "Select the agent that later commands act as (auto-starts it; persists).",
    help:
      "Usage: cello use-agent <name> [--pretty]  — select the CURRENT agent for later commands.\n" +
      "  Auto-starts the agent if it is offline (AUTOSTART-1).\n" +
      "  The selection PERSISTS across invocations (recorded in <cello-dir>/current-agent), because\n" +
      "  each CLI command opens its own daemon connection — a selection that lived only on the socket\n" +
      "  would vanish the moment the command exited. Override per-command with '--agent <name>'.\n" +
      "  A selection the daemon rejects is not recorded.",
    ipcMethod: "cello_use_agent",
    jsonOut: true,
    async run(ctx, args) {
      const { pretty, positional } = parityOpts(args);
      return useAgent(ctx.celloDir, positional[0] ?? "", { pretty });
    },
  },
  {
    name: "inbox",
    summary: "Check pending session requests and unread counts (the push-loss reconciler).",
    help:
      "Usage: cello inbox [--scope current|all] [--agent <name>] [--pretty]  — poll for what you missed.\n" +
      "  Content-free: pending session requests + unread message counts. Non-destructive (it does not\n" +
      "  drain anything — 'cello await-session' owns that). --scope all covers every loaded agent.",
    flags: [
      { name: "--agent", consumesValue: false },
      { name: "--scope", consumesValue: true },
    ],
    ipcMethod: "cello_check_notifications",
    jsonOut: true,
    async run(ctx, args) {
      const { agent, pretty, positional } = parityOpts(args);
      const { value } = takeValueFlag(positional, "--scope");
      const scope = value === "all" ? "all" : value === "current" ? "current" : undefined;
      return inbox(ctx.celloDir, { agent, pretty, scope });
    },
  },
  {
    name: "transcript",
    summary: "Print a session's durable conversation transcript (sent + received).",
    help:
      "Usage: cello transcript <session-id> [--agent <name>] [--pretty]  — the durable transcript.\n" +
      "  Sent AND received messages in order; survives a daemon restart. This is also how you satisfy\n" +
      "  read-before-write after being away: read it, then 'cello send' is accepted.",
    flags: AGENT_FLAG,
    ipcMethod: "cello_get_transcript",
    jsonOut: true,
    async run(ctx, args) {
      const { agent, pretty, positional } = parityOpts(args);
      return transcript(ctx.celloDir, positional[0] ?? "", { agent, pretty });
    },
  },

  {
    name: "sealed-receipt",
    summary: "Print a closed session's notarized bilateral seal receipt.",
    help:
      "Usage: cello sealed-receipt <session-id> [--agent <name>] [--pretty]  — the NOTARIZED receipt.\n" +
      "  The artifact the bilateral close ceremony produces: per-party content frontiers and the sealed\n" +
      "  root both sides agree on. It attests RECEIPT, never assent (implies_assent: false) — an\n" +
      "  unanswered final message reads as delivered-but-unanswered, never as agreement.\n" +
      "  Distinct from 'cello receipts <name>', which lists RELAY ORDERING receipts (a different thing).",
    flags: AGENT_FLAG,
    ipcMethod: "cello_get_sealed_receipt",
    jsonOut: true,
    async run(ctx, args) {
      const { agent, pretty, positional } = parityOpts(args);
      return sealedReceipt(ctx.celloDir, positional[0] ?? "", { agent, pretty });
    },
  },

  // ─── Group B: live conversation ───────────────────────────────────────────────────────────
  {
    name: "initiate",
    summary: "Start a session with a target agent (by pubkey). Prints the session_id.",
    help:
      "Usage: cello initiate <target-pubkey> [--agent <name>] [--pretty]  — open a session.\n" +
      "  <target-pubkey> is the counterparty's hex public key. Prints the session_id you then pass to\n" +
      "  'cello send' / 'cello receive' / 'cello close'. Adds the counterparty to your address book.",
    flags: AGENT_FLAG,
    ipcMethod: "cello_initiate_session",
    jsonOut: true,
    async run(ctx, args) {
      const { agent, pretty, positional } = parityOpts(args);
      return initiate(ctx.celloDir, positional[0] ?? "", { agent, pretty });
    },
  },
  {
    name: "send",
    summary: "Send a message in a session (honors read-before-write).",
    help:
      "Usage: cello send <session-id> <message…> [--stdin] [--agent <name>] [--pretty]\n" +
      "  The message is the remaining arguments, or the whole of stdin with --stdin (for text with\n" +
      "  newlines/quotes). READ-BEFORE-WRITE: if the counterparty has spoken since you last read, the\n" +
      "  daemon rejects the send with session_not_current and its cursor — that verdict is printed\n" +
      "  verbatim and NOT auto-fixed. Catch up with 'cello transcript <session-id>', then resend.",
    flags: [
      { name: "--agent", consumesValue: false },
      { name: "--stdin", consumesValue: false },
    ],
    ipcMethod: "cello_send",
    jsonOut: true,
    async run(ctx, args) {
      const { agent, pretty, positional } = parityOpts(args);
      const useStdin = positional.includes("--stdin");
      const rest = positional.filter((a) => a !== "--stdin");
      const sessionId = rest[0] ?? "";
      const content = useStdin ? await readStdin() : rest.slice(1).join(" ");
      return send(ctx.celloDir, sessionId, content, { agent, pretty });
    },
  },
  {
    name: "receive",
    summary: "Receive the next message, or catch up in a batch with --since-seq.",
    help:
      "Usage: cello receive <session-id> [--since-seq N] [--timeout-ms N] [--agent <name>] [--pretty]\n" +
      "  Default: BLOCKS for the next live message (up to --timeout-ms, default 30000).\n" +
      "  With --since-seq N: stateless CATCH-UP — returns every message after sequence N as a batch,\n" +
      "  immediately (no replay race, --timeout-ms ignored). Mirrors cello_receive exactly.",
    flags: [
      { name: "--agent", consumesValue: false },
      { name: "--timeout-ms", consumesValue: true },
      { name: "--since-seq", consumesValue: true },
    ],
    ipcMethod: "cello_receive",
    jsonOut: true,
    async run(ctx, args) {
      const { agent, pretty, positional } = parityOpts(args);
      const since = takeValueFlag(positional, "--since-seq");
      const timeout = takeValueFlag(since.rest, "--timeout-ms");
      return receive(ctx.celloDir, timeout.rest[0] ?? "", {
        agent,
        pretty,
        sinceSeq: numberOrUndefined(since.value),
        timeoutMs: numberOrUndefined(timeout.value),
      });
    },
  },
  {
    name: "receive-session",
    summary: "Accept / join an inbound session request.",
    help:
      "Usage: cello receive-session <session-id> [--timeout-ms N] [--agent <name>] [--pretty]\n" +
      "  Joins an inbound session (the one 'cello await-session' told you about).",
    flags: AGENT_AND_TIMEOUT,
    ipcMethod: "cello_receive_session",
    jsonOut: true,
    async run(ctx, args) {
      const { agent, pretty, positional } = parityOpts(args);
      const timeout = takeValueFlag(positional, "--timeout-ms");
      return receiveSession(ctx.celloDir, timeout.rest[0] ?? "", {
        agent,
        pretty,
        timeoutMs: numberOrUndefined(timeout.value),
      });
    },
  },
  {
    name: "close",
    summary: "Close a session — triggers the bilateral seal ceremony.",
    help:
      "Usage: cello close <session-id> [--force] [--agent <name>] [--pretty]\n" +
      "  Normally runs the bilateral SEAL ceremony: both parties get a notarized receipt.\n" +
      "  --force abandons a half-open session that can never be sealed (a handshake the counterparty\n" +
      "  never joined). It FORFEITS the receipt — never use it on a healthy session.",
    flags: [
      { name: "--agent", consumesValue: false },
      { name: "--force", consumesValue: false },
    ],
    ipcMethod: "cello_close_session",
    jsonOut: true,
    async run(ctx, args) {
      const { agent, pretty, positional } = parityOpts(args);
      const force = positional.includes("--force");
      const rest = positional.filter((a) => a !== "--force");
      return closeSession(ctx.celloDir, rest[0] ?? "", { agent, pretty, force });
    },
  },
  {
    name: "await-session",
    summary: "Block until an inbound session request arrives (the doorbell).",
    help:
      "Usage: cello await-session [--timeout-ms N] [--agent <name>] [--pretty]\n" +
      "  BLOCKS until someone opens a session with you (default 30000ms), then prints the request.\n" +
      "  On expiry it returns {\"type\":\"timeout\"} and exits 0 — a timeout is a normal answer, not an\n" +
      "  error (this mirrors cello_await_session exactly). Branch on .type in scripts.",
    flags: AGENT_AND_TIMEOUT,
    ipcMethod: "cello_await_session",
    jsonOut: true,
    async run(ctx, args) {
      const { agent, pretty, positional } = parityOpts(args);
      const timeout = takeValueFlag(positional, "--timeout-ms");
      return awaitSession(ctx.celloDir, { agent, pretty, timeoutMs: numberOrUndefined(timeout.value) });
    },
  },
];

export function commandNames(): string[] {
  return COMMANDS.map((c) => c.name);
}

export function findCommand(name: string): CommandSpec | undefined {
  return COMMANDS.find((c) => c.name === name);
}

/**
 * Internal: a spec's help by name, for commands that print their own usage on bad input.
 *
 * Called with hardcoded names that MUST resolve, so a miss is a programmer error (a rename typo),
 * not a runtime condition. Throwing beats the old `?? ""` default, which would have printed an
 * EMPTY string with exit 1 — silently swallowing the operator's only guidance, and doing it in the
 * one code path whose entire job is to explain what went wrong.
 */
function helpForSpec(name: string): string {
  const spec = findCommand(name);
  if (!spec) throw new Error(`registry: no command '${name}' (a hardcoded help lookup is out of sync)`);
  return spec.help;
}

/**
 * The flags a command recognizes, derived from its registry entry. `--pretty` is granted
 * automatically to every command honoring the §3 JSON contract, so it can never be forgotten.
 */
export function flagsFor(name: string): ReadonlyMap<string, FlagSpec> {
  const spec = findCommand(name);
  const map = new Map<string, FlagSpec>();
  if (!spec) return map;
  for (const f of spec.flags ?? []) map.set(f.name, f);
  if (spec.jsonOut) map.set("--pretty", { name: "--pretty" });
  return map;
}

/**
 * DOD-ONBOARD-HELP-1: render the described `Commands:` table — each command on its own line with
 * its one-line summary (git / `claude --help` style). Arguments stay in per-command `--help`.
 */
export function renderCommandsTable(): string {
  const width = Math.max(...COMMANDS.map((c) => c.name.length));
  const rows = COMMANDS.map((c) => `  ${c.name.padEnd(width)}  ${c.summary}`);
  return `Commands:\n${rows.join("\n")}`;
}
