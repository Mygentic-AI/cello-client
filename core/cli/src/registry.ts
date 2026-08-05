/**
 * DOD-CLI-PARITY-1 §4 — the command REGISTRY: the single source of truth for the `cello` CLI.
 *
 * Each entry carries { name, summary, help, flags, run }. Everything derives from this one table:
 *  - dispatch (src/bin/cello.ts) — no switch to keep in sync,
 *  - the `cello --help` described `Commands:` table — rendered from each entry's `summary`,
 *  - per-command `cello <cmd> --help`,
 *  - the recognized-flag set used to reject unknown flags before dispatch.
 *
 * Consequence: the help table, per-command help, and dispatch CANNOT DRIFT, and adding a command
 * FORCES adding its one-line summary.
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
  telegramSetToken,
  attestations,
  trustSignals,
  type CommandResult,
} from "./commands.js";
import { splitAgentFlag } from "./arg-parse.js";
import {
  IPC_METHODS,
  listSessions,
  contactAdd,
  contactRemove,
  contactList,
  contactSetTier,
  contactSetSignal,
  docPropose,
  docInbox,
  docAccept,
  docRefuse,
  docList,
  docRead,
  docDiff,
  docWrite,
  attestationConsentList,
  attestationConsentAccept,
  attestationConsentRefuse,
  contactSetAway,
  listAgents,
  startAgent,
  setAgentOffline,
  stopUsingAgent,
  useAgent,
  inbox,
  transcript,
  contactSetMoniker,
  sealedReceipt,
  initiate,
  send,
  receive,
  closeSession,
  nameSession,
  dismissSession,
  awaitSession,
  settingsGet,
  settingsSet,
  gatewayConfigList,
  gatewayConfigGet,
  gatewayConfigSet,
  policyLog,
  monikerSet,
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

/**
 * DOD-ONBOARD-HELP-1 §1 — the help is GROUPED, not alphabetical, and the groups render in this
 * order. A new user reads it top-to-bottom as the order they will actually do things: get set up,
 * bring an agent online, hold a conversation, then look at what it produced.
 */
export const GROUP_ORDER = [
  "Setup",
  "Agents",
  "Messaging",
  "Sessions & receipts",
  // After the conversation surfaces, before the trust ones: a shared document is something two
  // agents DO together, so it belongs with the doing — not filed under "Other", where an operator
  // finds it only if they already know it exists.
  "Documents",
  "Contacts",
  // TWO GROUPS, NOT ONE. On the wire an attestation is a trust signal, and they sat together for
  // exactly that reason — which made the person-to-person primitive read as a wallet chore. What the
  // NETWORK verifies about you and what a PERSON says about a person are different affordances, and
  // the help is where an operator learns which is which. Attestations come first: it is the one that
  // needs two people, and the one nothing else here can substitute for.
  "Attestations",
  "Trust signals",
  // The security and governance layer's own surfaces. Its own group because burying them under
  // "Other" is how an operator fails to find the one command that unblocks a misfiring guard —
  // and how an agent that hits that guard has nothing concrete to relay.
  "Security",
  "Other",
] as const;

export type CommandGroup = (typeof GROUP_ORDER)[number];

export interface CommandSpec {
  name: string;
  /**
   * Which section of `cello --help` this command appears under. Registry metadata, so the table
   * cannot drift from dispatch — adding a command FORCES choosing where a reader will find it.
   * Within a group, commands render in DECLARATION order (logical, not alphabetical).
   */
  group: CommandGroup;
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

/**
 * A numeric flag given a NON-NUMERIC value must fail loud, never be silently dropped.
 *
 * If `--since-seq abc` parsed to undefined, `defined()` would strip it, turning a stateless
 * CATCH-UP into a 30-second BLOCKING live wait that returns `content: null` — a script asking
 * "what did I miss?" would be answered "nothing new" to a question it never asked. Silently
 * changing the meaning of a command is worse than refusing it.
 *
 * Throws a BadFlagValue, which run() converts to a structured error + exit 1.
 */
class BadFlagValue extends Error {
  constructor(readonly flag: string, readonly value: string) {
    super(`${flag} expects a number, got '${value}'`);
  }
}

function numberOrUndefined(raw: string | undefined, flag: string): number | undefined {
  if (raw === undefined) return undefined;
  const n = Number(raw);
  if (!Number.isFinite(n)) throw new BadFlagValue(flag, raw);
  return n;
}

/** Turn a BadFlagValue into the §3 structured error; rethrow anything else. */
function flagError(err: unknown): CliOutput {
  if (err instanceof BadFlagValue) {
    return {
      stdout: "",
      stderr: JSON.stringify({
        ok: false,
        reason: "invalid_flag_value",
        flag: err.flag,
        value: err.value,
        guidance: `${err.flag} expects a number. Got '${err.value}'. The command was NOT run — a dropped flag would have silently changed what it does.`,
      }),
      exitCode: 1,
    };
  }
  throw err;
}

/** Adapt a legacy CommandResult (single `output` string, always stdout) to the CliOutput triple. */
function legacy(result: CommandResult): CliOutput {
  return { stdout: result.output, stderr: "", exitCode: result.exitCode };
}

/**
 * `--agent <name>` — recognized by every agent-scoped command.
 *
 * `consumesValue: false` is deliberate: checkArgs must NOT skip --agent's value. Flipping this to
 * true would turn `cello contacts --agent --bogus` from a fail-loud unknown_flag into a silently
 * accepted agent literally named "--bogus". The value is claimed by splitAgentFlag (arg-parse.ts),
 * which owns --agent parsing; checkArgs only needs to know the FLAG is legal. Same for bridge's
 * --agent / --hermes-home below.
 */
const AGENT_FLAG: readonly FlagSpec[] = [{ name: "--agent", consumesValue: false }];

/** Agent-scoped parity commands also take --pretty (granted automatically via `jsonOut`). */
const AGENT_AND_TIMEOUT: readonly FlagSpec[] = [
  { name: "--agent", consumesValue: false },
  { name: "--timeout-ms", consumesValue: true },
];

export const COMMANDS: readonly CommandSpec[] = [
  // ═══ Setup — get a working agent, in the order you actually do it ═══════════════════════════
  {
    name: "login",
    group: "Setup",
    summary: "Start the local CELLO daemon and bring your agents online.",
    help: "Usage: cello login  — start the daemon (or connect to an existing one).",
    async run(ctx) {
      return legacy(await login(ctx.celloDir, ctx.daemonBin, ctx.logger));
    },
  },
  {
    name: "logout",
    group: "Setup",
    summary: "Stop the daemon. Waits until it has actually exited.",
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
    group: "Setup",
    summary: "Show whether the daemon is running and which agents are online.",
    help: "Usage: cello status  — query the daemon and print the structured status JSON.",
    async run(ctx) {
      return legacy(await status(ctx.celloDir));
    },
  },
  {
    name: "create-agent",
    group: "Setup",
    summary: "Create a new agent on this machine. Step 1 of 2.",
    help:
      "Usage: cello create-agent <name>  — create a new LOCAL agent identity (does not touch the directory).\n" +
      // MONIKER-0 AC2: the regex text is DERIVED from the shared constant, never hand-typed.
      `  Name rule: 1–64 characters, letters/digits/'-'/'_' only, no spaces (regex ${MONIKER_RE.source}).\n` +
      "  Next step: 'cello register-agent <name> <pre-auth-token>' to register it with the directory.",
    async run(ctx, args) {
      return legacy(await createAgent(ctx.celloDir, args[0] ?? ""));
    },
  },
  {
    name: "register-agent",
    group: "Setup",
    summary: "Publish an agent to the directory so others can reach it. Step 2 of 2.",
    help:
      "Usage: cello register-agent <agent> <pre-auth-token>  — register a LOCAL agent with the directory.\n" +
      "  The two-step onboarding: (1) 'cello create-agent <name>' makes the identity on this machine; (2) 'cello register-agent <name> <token>' publishes it to the directory so others can find and reach it.\n" +
      "  The token is a single-use pre-authorization ticket from the CELLO Operations Agent on Telegram, format 'CELLO-' + 33 characters, valid 24h.\n" +
      "  Example:  cello register-agent alice CELLO-3xY7...\n" +
      "  Env-var form (avoids retyping):  CELLO_PREAUTH_TOKEN=CELLO-3xY7... cello register-agent alice\n" +
      "  Quoting is only needed if a value contains spaces (agent names and tokens never do).",
    async run(ctx, args) {
      // cello register-agent <agent> [preAuthToken]  (token falls back to CELLO_PREAUTH_TOKEN so it
      // need not appear in shell history). Optional phone stub follows.
      const agent = args[0] ?? "";
      const preAuthToken = args[1] ?? process.env.CELLO_PREAUTH_TOKEN ?? "";
      const phoneStub = args[2] ?? "";
      return legacy(await register(ctx.celloDir, agent, preAuthToken, phoneStub));
    },
  },
  {
    name: "remove-agent",
    group: "Setup",
    summary: "Retire an agent permanently and free its name. Cannot be undone.",
    help: "Usage: cello remove-agent <name>  — retires a local agent (one-way) and frees its name.",
    async run(ctx, args) {
      return legacy(await removeAgent(ctx.celloDir, args[0] ?? ""));
    },
  },

  // ═══ Agents — day-to-day control of who is online and who you are acting as ═════════════════
  {
    name: "agents",
    group: "Agents",
    summary: "List your agents and whether each one is online.",
    help:
      "Usage: cello agents [--pretty]  — list all loaded agents (name, state).\n" +
      "  The CLI twin of the cello_agents MCP tool. Prints JSON; use --pretty for humans.",
    ipcMethod: IPC_METHODS.agents,
    jsonOut: true,
    async run(ctx, args) {
      const { pretty } = parityOpts(args);
      return listAgents(ctx.celloDir, { pretty });
    },
  },
  {
    name: "start-agent",
    group: "Agents",
    summary: "Bring an agent online so it can be reached.",
    help:
      "Usage: cello start-agent <name> [--pretty]  — bring a registered agent ONLINE.\n" +
      "  Does NOT select it as the current agent — use 'cello use-agent <name>' for that.\n" +
      "  Idempotent: starting an already-online agent is safe.",
    ipcMethod: IPC_METHODS["start-agent"],
    jsonOut: true,
    async run(ctx, args) {
      const { pretty, positional } = parityOpts(args);
      return startAgent(ctx.celloDir, positional[0] ?? "", { pretty });
    },
  },
  {
    name: "use-agent",
    group: "Agents",
    summary: "Select the agent that later commands operate through.",
    help:
      "Usage: cello use-agent <name> [--pretty]  — select the CURRENT agent for later commands.\n" +
      "  Brings the agent online first if it is offline (AUTOSTART-1).\n" +
      "  The selection PERSISTS across invocations (recorded in <cello-dir>/current-agent), because\n" +
      "  each CLI command opens its own daemon connection — a selection that lived only on the socket\n" +
      "  would vanish the moment the command exited. Override per-command with '--agent <name>'.\n" +
      "  A selection the daemon rejects is not recorded.",
    ipcMethod: IPC_METHODS["use-agent"],
    jsonOut: true,
    async run(ctx, args) {
      const { pretty, positional } = parityOpts(args);
      return useAgent(ctx.celloDir, positional[0] ?? "", { pretty });
    },
  },
  {
    name: "set-agent-offline",
    group: "Agents",
    summary: "Take an agent offline. It stops accepting anything until restarted.",
    help:
      "Usage: cello set-agent-offline <name> [--pretty]  — take an agent offline (reversible with start-agent).\n" +
      "  The agent becomes UNREACHABLE: inbound sessions are refused and it cannot even send an away\n" +
      "  message. To step away while staying reachable, use 'cello stop-using-agent' instead.",
    ipcMethod: IPC_METHODS["set-agent-offline"],
    jsonOut: true,
    async run(ctx, args) {
      const { pretty, positional } = parityOpts(args);
      return setAgentOffline(ctx.celloDir, positional[0] ?? "", { pretty });
    },
  },
  {
    name: "stop-using-agent",
    group: "Agents",
    summary: "Forget the CLI's persisted agent selection (does NOT release a live MCP session).",
    help:
      "Usage: cello stop-using-agent [--pretty]  — forget the selection made by 'cello use-agent'.\n" +
      "  Attendance is PER-CONNECTION: this clears the CLI's own durable selection only. An agent being\n" +
      "  attended by a live MCP session stays attended — release it THERE (cello_stop_using_agent) if you\n" +
      "  want its away message to start firing. To stop it answering everywhere: 'cello set-agent-offline'.",
    jsonOut: true,
    async run(ctx, args) {
      const { pretty } = parityOpts(args);
      return stopUsingAgent(ctx.celloDir, { pretty });
    },
  },
  {
    name: "refresh",
    group: "Agents",
    summary: "Rotate an agent's signing-key shares to a fresh epoch (routine key hygiene).",
    help:
      "Usage: cello refresh <name>  — rotate the agent's split signing-key shares to a new epoch.\n" +
      "  CELLO never holds your whole signing key in one place — it is split into shares held with the\n" +
      "  directory nodes. This runs a ceremony that replaces every share with a fresh one. Your public\n" +
      "  identity does NOT change and you do not re-register; old shares simply stop being usable.\n" +
      "  Requires the directory to be reachable (the agent must be online and connected).\n" +
      "  Occasional hygiene, not something you need day to day.",
    async run(ctx, args) {
      return legacy(await refreshShares(ctx.celloDir, args[0] ?? ""));
    },
  },

  // ═══ Messaging — the conversation itself ════════════════════════════════════════════════════
  {
    name: "initiate-session",
    group: "Messaging",
    summary: "Open a session with someone (by public key). Prints the session id.",
    help:
      "Usage: cello initiate-session <target-pubkey> [--agent <name>] [--include type1,type2] [--exclude type1,type2] [--pretty]\n" +
      "  <target-pubkey> is the counterparty's hex public key. Prints the session_id you then pass to\n" +
      "  'cello send' / 'cello receive' / 'cello close-session'. Adds them to your address book.\n" +
      "\n" +
      "  --include type1,type2  present ONLY these signal types (overrides defaults)\n" +
      "  --exclude type1,type2  remove these types from the default presentation bundle\n" +
      "  Both flags fail with an error if a type is not in 'cello trust-signals list'.",
    flags: AGENT_FLAG,
    ipcMethod: IPC_METHODS["initiate-session"],
    jsonOut: true,
    async run(ctx, args) {
      const { agent, pretty, positional } = parityOpts(args);
      const includeIdx = args.indexOf("--include");
      const excludeIdx = args.indexOf("--exclude");
      const include = includeIdx >= 0 ? (args[includeIdx + 1] ?? "").split(",").filter(Boolean) : undefined;
      const exclude = excludeIdx >= 0 ? (args[excludeIdx + 1] ?? "").split(",").filter(Boolean) : undefined;
      return initiate(ctx.celloDir, positional[0] ?? "", { agent, pretty, include, exclude });
    },
  },
  {
    name: "await-session",
    group: "Messaging",
    summary: "Wait for someone to open a session with you.",
    help:
      "Usage: cello await-session [--timeout-ms N] [--agent <name>] [--pretty]\n" +
      "  BLOCKS until someone opens a session with you (default 30000ms), then prints the request.\n" +
      "  On expiry it returns {\"type\":\"timeout\"} and exits 0 — a timeout is a normal answer, not an\n" +
      "  error (this mirrors cello_await_session exactly). Branch on .type in scripts.",
    flags: AGENT_AND_TIMEOUT,
    ipcMethod: IPC_METHODS["await-session"],
    jsonOut: true,
    async run(ctx, args) {
      const { agent, pretty, positional } = parityOpts(args);
      const timeout = takeValueFlag(positional, "--timeout-ms");
      try {
        return await awaitSession(ctx.celloDir, { agent, pretty, timeoutMs: numberOrUndefined(timeout.value, "--timeout-ms") });
      } catch (err: unknown) {
        return flagError(err);
      }
    },
  },
  {
    name: "close-session",
    group: "Messaging",
    summary: "End a session. Both sides sign off and get a tamper-proof receipt.",
    help:
      "Usage: cello close-session <session-id> [--session-name \"<text>\"] [--force] [--agent <name>] [--pretty]\n" +
      "  Both parties sign off on the whole conversation and each gets a notarized receipt\n" +
      "  ('cello sealed-receipt <session-id>' prints it).\n" +
      "  --session-name labels the session so you can tell it apart later ('cello sessions' shows it).\n" +
      "  It is PRIVATE — never sent to the counterparty, the relay, or the directory. Optional: leave\n" +
      "  it out rather than invent one, since an unnamed session is a hint it did not close cleanly.\n" +
      "  --force abandons a half-open session that can never be sealed (a handshake the counterparty\n" +
      "  never joined). It FORFEITS the receipt — never use it on a healthy session.",
    flags: [
      { name: "--agent", consumesValue: false },
      { name: "--force", consumesValue: false },
      { name: "--session-name", consumesValue: true },
    ],
    ipcMethod: IPC_METHODS["close-session"],
    jsonOut: true,
    async run(ctx, args) {
      const { agent, pretty, positional } = parityOpts(args);
      const force = positional.includes("--force");
      const rest = positional.filter((a) => a !== "--force");
      const nameIdx = rest.indexOf("--session-name");
      const sessionName = nameIdx === -1 ? undefined : rest[nameIdx + 1];
      const ids = nameIdx === -1 ? rest : rest.filter((_, i) => i !== nameIdx && i !== nameIdx + 1);
      return closeSession(ctx.celloDir, ids[0] ?? "", { agent, pretty, force, sessionName });
    },
  },
  {
    name: "name-session",
    group: "Messaging",
    summary: "Name a session so you can tell it apart from the others.",
    help:
      "Usage: cello name-session <session-id> <name...>   |   cello name-session <session-id> --clear\n" +
      "  Labels one of YOUR sessions. Works on any session — active, interrupted, or long sealed;\n" +
      "  naming an old conversation for the record is the point, not an edge case.\n" +
      "  The name is PRIVATE: never sent to the counterparty, the relay, or the directory, and it\n" +
      "  cannot change anything the protocol does. Renaming a sealed session does not touch its seal.\n" +
      "  Multi-word names need no quotes:  cello name-session ab12… the deploy postmortem\n" +
      "  --clear removes the name (an unnamed session is a hint it did not close cleanly).",
    flags: [
      { name: "--agent", consumesValue: false },
      { name: "--clear", consumesValue: false },
    ],
    ipcMethod: IPC_METHODS["name-session"],
    jsonOut: true,
    async run(ctx, args) {
      const { agent, pretty, positional } = parityOpts(args);
      const clear = positional.includes("--clear");
      const rest = positional.filter((a) => a !== "--clear");
      const [sessionId, ...words] = rest;
      // An empty name is NOT a clear. `cello name-session <id>` — a half-typed command, or one whose
      // "$NAME" was an unset shell variable — would otherwise join to "", which the daemon trims to
      // null and stores as a CLEAR: the operator wipes the label off a session while trying to read
      // the usage. Clearing is what --clear is for, and it has to be asked for.
      if (!clear && words.length === 0) {
        return legacy({
          exitCode: 1,
          output: "Usage: cello name-session <session-id> <name...>  — or --clear to remove the name.",
        });
      }
      // The name is every remaining positional, joined — so quoting is optional, which is the whole
      // point of taking it positionally rather than as a flag.
      const name = clear ? null : words.join(" ");
      return nameSession(ctx.celloDir, sessionId ?? "", name, { agent, pretty });
    },
  },
  {
    name: "dismiss",
    group: "Messaging",
    summary: "Dismiss a sealed session from your inbox after reading its transcript.",
    help:
      "Usage: cello dismiss <session-id> [--agent <name>] [--pretty]\n" +
      "  Clears a terminal (sealed/abandoned) session from your inbox.\n" +
      "  Use this after reading the transcript of an answering-machine style session.\n" +
      "  Sets a local read_at timestamp — never propagated, never part of the seal or hash chain.\n" +
      "  Only works on terminal sessions; active sessions are handled via cello receive.",
    flags: [
      { name: "--agent", consumesValue: true },
    ],
    ipcMethod: IPC_METHODS["dismiss"],
    jsonOut: true,
    async run(ctx, args) {
      const { agent, pretty, positional } = parityOpts(args);
      const [sessionId] = positional;
      if (!sessionId) {
        return legacy({ exitCode: 1, output: "Usage: cello dismiss <session-id>" });
      }
      return dismissSession(ctx.celloDir, sessionId, { agent, pretty });
    },
  },
  {
    name: "send",
    group: "Messaging",
    summary: "Send a message. Requires --over, --standby <min>, or --wrap. Blocked if you have unread messages.",
    help:
      "Usage: cello send <session-id> <message…> --over|--standby <min>|--wrap [--stdin] [--agent <name>] [--pretty]\n\n" +
      "  Every send REQUIRES exactly one signal flag declaring your next action:\n\n" +
      "    --over\n" +
      "        Your turn is complete. You are now entering read mode and waiting for\n" +
      "        a reply. Use this for most messages.\n\n" +
      "    --standby <min>\n" +
      "        Your turn is not yet complete, but your full response will take time.\n" +
      "        Use this when you want to acknowledge immediately — letting the other\n" +
      "        party know you received their message and are working on it — before\n" +
      "        going off to do the work. Replace <min> with your estimate in minutes.\n" +
      "        The other party does not need to reply. A follow-up message is coming\n" +
      "        in approximately <min> minutes.\n\n" +
      "    --wrap\n" +
      "        This is your final message. You intend to close the session after\n" +
      "        sending. No reply is expected or needed.\n\n" +
      "  The message is the remaining positional arguments, or the whole of stdin with --stdin\n" +
      "  (for text with newlines/quotes).\n\n" +
      "  If the other side has said something you have not read, the send is REFUSED and tells you\n" +
      "  how many messages are waiting. Read them ('cello receive <session-id>', or 'cello transcript\n" +
      "  <session-id>' for the whole conversation) and send again.",
    flags: [
      { name: "--agent", consumesValue: false },
      { name: "--stdin", consumesValue: false },
      { name: "--over", consumesValue: false },
      { name: "--standby", consumesValue: true },
      { name: "--wrap", consumesValue: false },
    ],
    ipcMethod: IPC_METHODS.send,
    jsonOut: true,
    async run(ctx, args) {
      const { agent, pretty, positional } = parityOpts(args);
      const useStdin = positional.includes("--stdin");
      const rest = positional.filter((a) => a !== "--stdin");

      // Extract signal flags.
      // takeValueFlag consumes "--standby" from `rest` regardless of whether a value follows — it
      // always removes the flag token itself. "No value" means value:undefined, not that the flag
      // was absent. Track flag presence separately so "--standby" with no value gets the specific
      // invalid_est_minutes error rather than the generic missing_signal error.
      const standbyFlagPresent = rest.includes("--standby");
      const standbyResult = takeValueFlag(rest, "--standby");
      const hasOver = standbyResult.rest.includes("--over");
      const hasWrap = standbyResult.rest.includes("--wrap");
      const hasStandby = standbyResult.value !== undefined;
      const positionalOnly = standbyResult.rest.filter((a) => a !== "--over" && a !== "--wrap");

      const signalCount = (hasOver ? 1 : 0) + (hasWrap ? 1 : 0) + (standbyFlagPresent ? 1 : 0);
      if (signalCount === 0) {
        return {
          stdout: "",
          stderr: JSON.stringify({
            ok: false,
            reason: "missing_signal",
            guidance:
              "Missing signal flag. Every 'cello send' must include --over, --standby <min>, or --wrap.\n\n" +
              "  --over           Your turn is complete; enter read mode.\n" +
              "  --standby <min>  Your turn is not yet complete; follow-up coming in <min> minutes.\n" +
              "  --wrap           Final message; you will close the session after sending.",
          }),
          exitCode: 1,
        };
      }
      if (signalCount > 1) {
        return {
          stdout: "",
          stderr: JSON.stringify({ ok: false, reason: "ambiguous_signal", guidance: "Provide exactly one of --over, --standby, or --wrap." }),
          exitCode: 1,
        };
      }

      let signal: "over" | "standby" | "wrap";
      let estMinutes: number | undefined;
      if (hasOver) {
        signal = "over";
      } else if (hasWrap) {
        signal = "wrap";
      } else {
        signal = "standby";
        if (!hasStandby) {
          return {
            stdout: "",
            stderr: JSON.stringify({ ok: false, reason: "invalid_est_minutes", guidance: "--standby requires a positive number of minutes, e.g. --standby 5" }),
            exitCode: 1,
          };
        }
        estMinutes = Number(standbyResult.value);
        if (!Number.isFinite(estMinutes) || estMinutes <= 0) {
          return {
            stdout: "",
            stderr: JSON.stringify({ ok: false, reason: "invalid_est_minutes", guidance: "--standby requires a positive number of minutes, e.g. --standby 5" }),
            exitCode: 1,
          };
        }
      }

      const sessionId = positionalOnly[0] ?? "";
      const content = useStdin ? await readStdin() : positionalOnly.slice(1).join(" ");
      return send(ctx.celloDir, sessionId, content, { agent, pretty, signal, estMinutes });
    },
  },
  {
    name: "receive",
    group: "Messaging",
    summary: "Read the next message, or catch up on everything you missed with --since-seq.",
    help:
      "Usage: cello receive <session-id> [--since-seq N] [--timeout-ms N] [--agent <name>] [--pretty]\n" +
      "  Default: WAITS for the next message (up to --timeout-ms, default 30000).\n" +
      "  With --since-seq N: returns every message after number N at once, immediately, without\n" +
      "  waiting — this is how you catch up after being away. Mirrors cello_receive exactly.",
    flags: [
      { name: "--agent", consumesValue: false },
      { name: "--timeout-ms", consumesValue: true },
      { name: "--since-seq", consumesValue: true },
    ],
    ipcMethod: IPC_METHODS.receive,
    jsonOut: true,
    async run(ctx, args) {
      const { agent, pretty, positional } = parityOpts(args);
      const since = takeValueFlag(positional, "--since-seq");
      const timeout = takeValueFlag(since.rest, "--timeout-ms");
      try {
        return await receive(ctx.celloDir, timeout.rest[0] ?? "", {
          agent,
          pretty,
          sinceSeq: numberOrUndefined(since.value, "--since-seq"),
          timeoutMs: numberOrUndefined(timeout.value, "--timeout-ms"),
        });
      } catch (err: unknown) {
        return flagError(err);
      }
    },
  },
  {
    name: "inbox",
    group: "Messaging",
    summary: "See who tried to reach you and what is unread, without reading anything.",
    help:
      "Usage: cello inbox [--scope current|all] [--agent <name>] [--pretty]  — what did I miss?\n" +
      "  Shows pending session requests and unread message COUNTS — never message content, and it\n" +
      "  does not mark anything as read ('cello receive' does that). Use it after being away.\n" +
      "  --scope all covers every agent you have, not just the current one.",
    flags: [
      { name: "--agent", consumesValue: false },
      { name: "--scope", consumesValue: true },
    ],
    ipcMethod: IPC_METHODS.inbox,
    jsonOut: true,
    async run(ctx, args) {
      const { agent, pretty, positional } = parityOpts(args);
      const { value } = takeValueFlag(positional, "--scope");
      // An UNRECOGNIZED scope must not silently become the default. A typo'd `--scope all` (e.g.
      // "al") would answer with `current`'s data and exit 0 — the operator reads "no
      // notifications" while another agent's inbox is full.
      if (value !== undefined && value !== "all" && value !== "current") {
        return {
          stdout: "",
          stderr: JSON.stringify({
            ok: false,
            reason: "invalid_flag_value",
            flag: "--scope",
            value,
            guidance: "--scope must be 'current' or 'all'. The command was NOT run — answering a different question than the one asked is worse than refusing.",
          }),
          exitCode: 1,
        };
      }
      return inbox(ctx.celloDir, { agent, pretty, scope: value });
    },
  },

  // ═══ Sessions & receipts — what the conversations left behind ═══════════════════════════════
  {
    name: "sessions",
    group: "Sessions & receipts",
    summary: "List your sessions (open by default; --all/--closed/--failed to filter).",
    help:
      "Usage: cello sessions [--open|--closed|--failed|--all] [--limit N] [--agent <name>] [--all-agents]\n" +
      "  Lists the SELECTED agent's session history (defaults to open). --all filters by status;\n" +
      "  --all-agents lists every agent's sessions on this daemon, each row labelled with its agent.",
    flags: [
      { name: "--open" },
      { name: "--closed" },
      { name: "--failed" },
      { name: "--all" },
      { name: "--limit", consumesValue: true },
      // DOD-CLI-SESSIONS-SCOPE-1: `--all` filters by STATUS; `--all-agents` widens the PRINCIPAL.
      // Two different axes that both read as "all" in a hurry — hence the explicit suffix.
      { name: "--all-agents" },
      ...AGENT_FLAG,
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
      // Scoped to the selected agent, like the MCP tool. --all-agents opts into the daemon-wide
      // view, which cannot be agent-scoped and therefore takes the non-parity path.
      if (args.includes("--all-agents")) {
        return legacy(await sessions(ctx.celloDir, { filter, limit }));
      }
      const { agent, pretty } = parityOpts(args);
      return listSessions(ctx.celloDir, { filter, limit, agent, pretty });
    },
  },
  {
    name: "transcript",
    group: "Sessions & receipts",
    summary: "Print the full conversation for a session — everything sent and received.",
    help:
      "Usage: cello transcript <session-id> [--agent <name>] [--pretty]  — the whole conversation.\n" +
      "  Sent AND received messages, in order. Stored on disk, so it survives a daemon restart.\n" +
      "  Reading it also catches you up, which un-blocks 'cello send' after you have been away.",
    flags: AGENT_FLAG,
    ipcMethod: IPC_METHODS.transcript,
    jsonOut: true,
    async run(ctx, args) {
      const { agent, pretty, positional } = parityOpts(args);
      return transcript(ctx.celloDir, positional[0] ?? "", { agent, pretty });
    },
  },
  {
    name: "sealed-receipt",
    group: "Sessions & receipts",
    // THE one users want. Named and described so it cannot be confused with relay-receipts.
    summary: "Print a closed session's notarized receipt — proof both sides signed off on the conversation.",
    help:
      "Usage: cello sealed-receipt <session-id> [--agent <name>] [--pretty]  — the NOTARIZED receipt.\n" +
      "  This is the proof CELLO exists to produce: when a session closes, both parties sign off on\n" +
      "  the whole conversation and the directory notarizes it. The receipt is tamper-evident — if a\n" +
      "  single message were altered, added or dropped, it would no longer match.\n" +
      "  It attests RECEIPT, never agreement (implies_assent: false) — an unanswered last message\n" +
      "  reads as delivered-but-unanswered, never as consent.\n" +
      "  NOT the same as 'cello relay-receipts', which is a low-level delivery-plumbing artifact.",
    flags: AGENT_FLAG,
    ipcMethod: IPC_METHODS["sealed-receipt"],
    jsonOut: true,
    async run(ctx, args) {
      const { agent, pretty, positional } = parityOpts(args);
      return sealedReceipt(ctx.celloDir, positional[0] ?? "", { agent, pretty });
    },
  },
  {
    name: "relay-receipts",
    group: "Sessions & receipts",
    // Per-MESSAGE signatures from a RELAY attesting it handled and ordered that message — NOT the
    // session seal. The name must stay clearly distinct from `sealed-receipt`: two names differing
    // by a single plural cannot be rescued by any description.
    summary: "Advanced/debug: per-message proofs signed by a relay. Not the session receipt — see 'sealed-receipt'.",
    help:
      "Usage: cello relay-receipts <name>  — ADVANCED / DEBUG. You almost certainly want\n" +
      "  'cello sealed-receipt <session-id>' instead.\n" +
      "  When a message cannot go directly to the other agent (they are offline, or the network is in\n" +
      "  the way), it goes via a relay. The relay signs a small receipt saying it handled that message\n" +
      "  and where it fell in the order. This lists those — a plumbing artifact for diagnosing\n" +
      "  delivery, one per message.\n" +
      "  It says NOTHING about the conversation being agreed or sealed. That is 'cello sealed-receipt'.",
    async run(ctx, args) {
      return legacy(await relayReceipts(ctx.celloDir, args[0] ?? ""));
    },
  },

  // ═══ Contacts — the address book (plural) and one contact (singular) ════════════════════════
  {
    name: "contacts",
    group: "Contacts",
    summary: "List your address book — everyone this agent knows, and how much they're trusted.",
    help:
      "Usage: cello contacts [--agent <name>] [--pretty]  — list the whole address book.\n" +
      "  Contacts are added automatically when you open a session with someone, or accept theirs.\n" +
      "  To act on ONE contact, use 'cello contact <pubkey> <operation>'.\n" +
      "  --agent defaults to the current agent (or the only online one).",
    flags: AGENT_FLAG,
    jsonOut: true,
    ipcMethod: IPC_METHODS.contacts,
    async run(ctx, args) {
      const { agent, pretty } = parityOpts(args);
      return contactList(ctx.celloDir, { agent, pretty });
    },
  },
  {
    name: "contact",
    group: "Contacts",
    summary: "Act on ONE contact: add, remove, set-tier, set-away, set-moniker.",
    help:
      "Usage: cello contact <pubkey> <operation> [args] [--agent <name>] [--pretty]\n" +
      "\n" +
      "  Operations:\n" +
      "    add                       add this peer to the address book\n" +
      "    remove                    remove them (they go back to being a stranger)\n" +
      "    set-tier <0..4>           how much they're trusted: 0=blocked, 1=stranger, 2=known,\n" +
      "                              3=trusted (reaches you even when you're away), 4=vip.\n" +
      "                              A higher tier RAISES their limits; it never removes the caps.\n" +
      "                              It does NOT change content screening — that is not yet active.\n" +
      "    set-away <message…>       what THIS person hears when you're away (empty clears it)\n" +
      "    set-signal <hash> on|off|clear\n" +
      "                              show or withhold ONE trust signal from THIS person. 'clear'\n" +
      "                              removes the choice (the signal's own default applies again) —\n" +
      "                              which is not the same as 'off'. Can only narrow: it never\n" +
      "                              presents something you have not accepted.\n" +
      "    set-moniker <name>        YOUR pet name for THEM (empty clears it). Always wins over the\n" +
      "                              name they offer — the one thing they cannot spoof.\n" +
      "\n" +
      "  To list the whole book, use 'cello contacts'.\n" +
      "  Note: 'set-moniker' names a CONTACT. 'cello moniker' sets your OWN outbound name.\n" +
      "  Example:  cello contact 178d420b… set-tier 3 --agent alice",
    flags: AGENT_FLAG,
    jsonOut: true, // the WHOLE address book honors §3 — one command, one contract
    async run(ctx, args) {
      const { agent, pretty, positional } = parityOpts(args);
      const o = { agent, pretty };
      // §3 SHAPE: `contact <pubkey> <op>` — the subject first, then what to do to them.
      const [pubkey, op, valueArg] = positional;
      if (!pubkey || !op) return { stdout: helpForSpec("contact"), stderr: "", exitCode: 1 };
      if (op === "add") return contactAdd(ctx.celloDir, pubkey, o);
      if (op === "remove") return contactRemove(ctx.celloDir, pubkey, o);
      if (op === "set-tier" && valueArg !== undefined) {
        // Daemon validates the value; a non-numeric arg surfaces as its invalid_tier verdict.
        return contactSetTier(ctx.celloDir, pubkey, Number(valueArg), o);
      }
      if (op === "set-away") {
        // The rest of the args form the away text; empty → clear.
        const message = positional.slice(2).join(" ");
        return contactSetAway(ctx.celloDir, pubkey, message.length > 0 ? message : null, o);
      }
      if (op === "set-signal") {
        // `cello contact <pubkey> set-signal <hash> <on|off|clear>`. Three words, because there are
        // three states: shown, withheld, and no-opinion. A boolean flag could not express the third.
        const [hash, choice] = positional.slice(2);
        const present = choice === "on" ? true : choice === "off" ? false : choice === "clear" ? null : undefined;
        if (!hash || present === undefined) return { stdout: helpForSpec("contact"), stderr: "", exitCode: 1 };
        return contactSetSignal(ctx.celloDir, pubkey, hash, present, o);
      }
      if (op === "set-moniker") {
        // Empty → null clears it, mirroring the tool.
        const moniker = positional.slice(2).join(" ");
        return contactSetMoniker(ctx.celloDir, pubkey, moniker.length > 0 ? moniker : null, o);
      }
      return { stdout: helpForSpec("contact"), stderr: "", exitCode: 1 };
    },
  },

  // ═══ Attestations — the person-to-person primitive ══════════════════════════════════════════
  // ITS OWN GROUP, deliberately. An attestation is a PERSON vouching for a PERSON; a trust signal is
  // the NETWORK verifying an attribute (GitHub age, phone, email). The wire format is the same, so it
  // is tempting to file them together — but they are different affordances, and burying attestation
  // under a wallet listing hides the one capability that makes collaboration possible.
  {
    name: "attestations",
    group: "Attestations",
    summary: "Endorse agents, issue general attestations, and check their status.",
    help:
      "Usage:\n" +
      "  cello attestations issue <pubkey> <text\u2026>\n" +
      "                                        \u2014 endorse them for something you have seen them do\n" +
      "  cello attestations issued             \u2014 the status of every attestation you have issued\n" +
      "\n" +
      "An attestation is YOUR words about ANOTHER agent \u2014 the person-to-person half of trust. The\n" +
      "network's own claims about you (GitHub account age, phone, email) are 'cello trust-signals'.\n" +
      "\n" +
      "Nothing you write is final on your say-so. It is sealed to the CELLO portal (the directory\n" +
      "cannot read it), screened, minted \u2014 and then the SUBJECT must accept it before anyone else can\n" +
      "see it. They may refuse, and a refusal may carry their reasoning back to you.\n" +
      "\n" +
      "The receiving direction \u2014 attestations others wrote about YOU \u2014 is 'cello attestation-consent'.\n" +
      "You cannot attest about yourself.\n" +
      "\n" +
      "Prose contains things that look like flags, so use -- to end flag parsing:\n" +
      "  cello attestations issue b23c24dd\u2026 -- cut p99 by -30ms on the auth path",
    async run(ctx, args) {
      const [sub, ...rest] = args;
      return legacy(await attestations(ctx.celloDir, sub ?? "", rest));
    },
  },

  // ═══ Trust signals — what the network verifies about you ════════════════════════════════════
  {
    name: "trust-signals",
    group: "Trust signals",
    summary: "Inspect and manage the trust signals in your local wallet.",
    flags: [{ name: "--all" }],
    help:
      "Usage:\n" +
      "  cello trust-signals list              \u2014 show every signal (type, hash, status, default, issued)\n" +
      "  cello trust-signals view <hash>       \u2014 decode and display a signal's full payload\n" +
      "  cello trust-signals enable <hash>     \u2014 include signal in the default presentation bundle\n" +
      "  cello trust-signals disable <hash>    \u2014 exclude signal from the default bundle\n" +
      "  cello trust-signals revoke <hash>     \u2014 tombstone at the directory AND delete locally\n" +
      "\n" +
      "Trust signals are verifiable claims about you (GitHub account age, phone, email, etc.) that your\n" +
      "agent presents to contacts during sessions. They are issued by the CELLO portal, notarized by\n" +
      "the directory, and held in your local encrypted wallet. To vouch for SOMEONE ELSE in your own\n" +
      "words, that is 'cello attestations issue' \u2014 a different thing with a different name.\n" +
      "\n" +
      "'list' shows the whole wallet, including attestations others wrote about you once you accepted\n" +
      "them. The 'def' column shows whether a signal is in the default bundle (\u2713 = yes, \u2013 = no).\n" +
      "Signals with _id suffix (github_id, etc.) start excluded by default. Use enable/disable to change.\n" +
      "\n" +
      "'revoke' deletes the signal locally AND sends a tombstone to the directory. This is the correct\n" +
      "way to retract a signal. The directory will stop delivering it to other agents.\n" +
      "\n" +
      "<hash> can be a prefix (min 8 chars). Example:\n" +
      "  cello trust-signals view b23c24dd\n" +
      "  cello trust-signals revoke b23c24dd",
    async run(ctx, args) {
      const [sub, ...rest] = args;
      return legacy(await trustSignals(ctx.celloDir, sub ?? "", rest));
    },
  },

  {
    name: "attestation-consent",
    group: "Attestations",
    summary: "Accept or refuse attestations others have written about you.",
    help:
      "Usage:\n" +
      "  cello attestation-consent list                    — attestations others wrote about you, awaiting your decision\n" +
      "  cello attestation-consent accept <hash>           — accept one: it becomes presentable to counterparties\n" +
      "  cello attestation-consent refuse <hash> [why…]    — refuse one: it stays inert and is never presented.\n" +
      "                                                    Anything after the hash is a message back to the\n" +
      "                                                    issuer (optional). With no message they are told\n" +
      "                                                    nothing.\n" +
      "\n" +
      "Anyone can write an attestation ABOUT your agent — it lands in your wallet unbidden. It is INERT\n" +
      "until you accept it: nothing pending is presented, counted, or visible to a counterparty. That is\n" +
      "the point of this command. Read the attester's words in 'list' before accepting, because\n" +
      "accepting is what puts your name behind someone else's claim about you.\n" +
      "\n" +
      "Refusing is not a deletion — the record stays so the decision is auditable — but a refused signal\n" +
      "is indistinguishable from one that was never issued, everywhere it is checked.\n" +
      "\n" +
      "These act on the SELECTED agent and take no --agent flag: consent is a statement about oneself,\n" +
      "and one agent does not accept on another's behalf. Select with 'cello use-agent <name>'.",
    jsonOut: true,
    async run(ctx, args) {
      const { pretty, positional } = parityOpts(args);
      const o = { pretty };
      const [sub, hash] = positional;
      if (sub === "list") return attestationConsentList(ctx.celloDir, o);
      if (sub === "accept" && hash) return attestationConsentAccept(ctx.celloDir, hash, o);
      if (sub === "refuse" && hash) {
        // Everything after the hash is the message — free text, so it is joined rather than parsed.
        const msg = positional.slice(2).join(" ");
        return attestationConsentRefuse(ctx.celloDir, hash, msg.length > 0 ? msg : null, o);
      }
      return { stdout: helpForSpec("attestation-consent"), stderr: "", exitCode: 1 };
    },
  },

  // ═══ Documents (M14 / DOD-DOC-TOOLS-1) ══════════════════════════════════════════════════════
  {
    name: "doc",
    group: "Documents",
    summary: "Share a living document with a counterparty — both sides edit, both sides converge.",
    help:
      "Usage:\n" +
      "  cello doc propose <peer-pubkey> [--type <t>] [--append-only] [--content <text>]\n" +
      "                                                    — offer a shared document. They must accept.\n" +
      "  cello doc inbox                                   — documents others have offered YOU, awaiting your decision\n" +
      "  cello doc accept <document-id>                    — accept one: their signed edits now apply to your copy\n" +
      "  cello doc refuse <document-id> [why…]             — refuse one\n" +
      "  cello doc list                                    — your documents and their state\n" +
      "  cello doc read <document-id>                      — the current text\n" +
      "  cello doc diff <document-id>                      — what changed since you last read it\n" +
      "  cello doc write <document-id> <text…>             — replace the text and publish the change\n" +
      "\n" +
      "A document is a STANDING AGREEMENT to apply a counterparty's signed operations to your local\n" +
      "copy. That is a bigger grant than receiving a message, which is why accepting is a separate,\n" +
      "deliberate act — after it, edits converge without asking you again. 'inbox' is where you read\n" +
      "what was offered before agreeing to it.\n" +
      "\n" +
      "'write' takes the COMPLETE new text, not a patch. The daemon diffs it against the current\n" +
      "state, so your offsets cannot go stale under an edit the peer made while you were typing.\n" +
      "\n" +
      "Publishing does NOT wait for the peer. A change is signed, logged, and delivered by a\n" +
      "background worker when they are reachable — so editing a shared document never depends on the\n" +
      "other party being awake. 'list' shows what has not yet been acknowledged.\n" +
      "\n" +
      "These act on the SELECTED agent unless you pass --agent. Select with 'cello use-agent <name>'.",
    jsonOut: true,
    async run(ctx, args) {
      const { pretty, agent, positional } = parityOpts(args);
      const o = { pretty, ...(agent !== undefined ? { agent } : {}) };
      const [sub, target] = positional;
      if (sub === "inbox") return docInbox(ctx.celloDir, o);
      if (sub === "list") return docList(ctx.celloDir, o);
      if (sub === "propose" && target) {
        const rest = positional.slice(2);
        const { value: documentType } = takeValueFlag(rest, "--type");
        const { value: startingContent } = takeValueFlag(rest, "--content");
        const appendOnly = rest.includes("--append-only");
        return docPropose(ctx.celloDir, target, {
          ...o,
          ...(documentType !== undefined ? { documentType } : {}),
          ...(startingContent !== undefined ? { startingContent } : {}),
          ...(appendOnly ? { appendOnly } : {}),
        });
      }
      if (sub === "accept" && target) return docAccept(ctx.celloDir, target, o);
      if (sub === "refuse" && target) {
        // Everything after the id is the reason — free text, so joined rather than parsed.
        const why = positional.slice(2).join(" ");
        return docRefuse(ctx.celloDir, target, why.length > 0 ? why : null, o);
      }
      if (sub === "read" && target) return docRead(ctx.celloDir, target, o);
      if (sub === "diff" && target) return docDiff(ctx.celloDir, target, o);
      if (sub === "write" && target) {
        // Joined, not positional[2] alone: the whole point is the COMPLETE text, and a shell splits
        // it on spaces. Taking only the first word would publish a one-word document and report
        // success.
        const content = positional.slice(2).join(" ");
        if (content.length === 0) {
          return { stdout: helpForSpec("doc"), stderr: "", exitCode: 1 };
        }
        return docWrite(ctx.celloDir, target, content, o);
      }
      return { stdout: helpForSpec("doc"), stderr: "", exitCode: 1 };
    },
  },

  // ═══ Other ══════════════════════════════════════════════════════════════════════════════════
  {
    name: "policy",
    group: "Security",
    summary: "Show what the security layer did to your messages — newest first.",
    help:
      "Usage: cello policy log [--limit <n>] [--since <ms-epoch>]\n" +
      "  Every screened message and what happened to it: clean, redacted, blocked or warned, with\n" +
      "  the rule that fired and the correlation id. This is how you tell whether\n" +
      "  a new failure came from the security layer or from something else — it is a lookup, not a\n" +
      "  guess. Default 50 entries, max 500. `chainValid: false` means the log itself was tampered\n" +
      "  with; do not reason from its contents until that is explained.\n" +
      "  Example:  cello policy log --limit 20",
    jsonOut: true,
    async run(ctx, args) {
      const { pretty, positional } = parityOpts(args);
      if (positional[0] !== "log") return { stdout: helpForSpec("policy"), stderr: "", exitCode: 1 };
      const { value: limitRaw } = takeValueFlag(positional, "--limit");
      const { value: sinceRaw } = takeValueFlag(positional, "--since");
      const limit = limitRaw !== undefined ? Number(limitRaw) : undefined;
      const sinceMs = sinceRaw !== undefined ? Number(sinceRaw) : undefined;
      return policyLog(ctx.celloDir, {
        pretty,
        ...(limit !== undefined && Number.isFinite(limit) ? { limit } : {}),
        ...(sinceMs !== undefined && Number.isFinite(sinceMs) ? { sinceMs } : {}),
      });
    },
  },
  {
    name: "config",
    group: "Security",
    summary: "Read or change the security layer's guards (screening, redaction, rate limits).",
    help:
      "Usage: cello config list | cello config get <key> | cello config set <key> <value>\n" +
      "  The security layer's own guards. Per-INSTALL, not per-agent — they apply to every agent here.\n" +
      "  Keys: autonomous_override (true|false), pii_whitelist (comma-separated, empty string clears),\n" +
      "        language_allow (comma-separated), rate_max_per_window (number, 0 = no cap), rate_window_ms.\n" +
      "  TIGHTENING a guard applies immediately. LOOSENING one asks you to confirm at the terminal —\n" +
      "  there is no --yes flag, because a flag a script can pass is not a human. Every change is\n" +
      "  versioned and hash-chained; 'list' shows the version, the direction, and whether a human\n" +
      "  confirmed it. Example:  cello config set pii_whitelist me@example.com",
    jsonOut: true,
    async run(ctx, args) {
      const { pretty, positional } = parityOpts(args);
      const opts = { pretty };
      const [sub, key, ...rest] = positional;
      if (sub === "list") return gatewayConfigList(ctx.celloDir, opts);
      if (sub === "get" && key) return gatewayConfigGet(ctx.celloDir, key, opts);
      // The value is the REST of the line joined, so a comma-separated list survives a shell that
      // split it on spaces (`pii_whitelist a@x.example, b@x.example`).
      if (sub === "set" && key && rest.length > 0) {
        return gatewayConfigSet(ctx.celloDir, key, rest.join(" "), opts);
      }
      return { stdout: helpForSpec("config"), stderr: "", exitCode: 1 };
    },
  },
  {
    name: "settings",
    group: "Other",
    summary: "Get or set how reachable an agent is (limits per trust tier, away messages).",
    help:
      "Usage: cello settings get [key] [--agent <name>] | cello settings set <key> <value> [--agent <name>]\n" +
      "       cello settings clear <key> [--agent <name>]  — unset it; the built-in default applies again\n" +
      "  Per-agent reachability policy (DOD-SETTINGS-1). Keys: bounds.<tier>.max_sessions, bounds.<tier>.max_bytes\n" +
      "  (tier = unknown|known|whitelisted|vip; a finite positive integer), away.default, away.tier.<tier> (away text).\n" +
      "  An unset key uses the built-in default. Example:  cello settings set bounds.known.max_sessions 8 --agent alice",
    flags: AGENT_FLAG,
    jsonOut: true,
    async run(ctx, args) {
      const { agent, pretty, positional } = parityOpts(args);
      const opts = { agent, pretty };
      const [sub, key, value] = positional;
      if (sub === "get") return settingsGet(ctx.celloDir, key, opts); // key optional → all
      if (sub === "set" && key && value !== undefined) {
        return settingsSet(ctx.celloDir, key, value, opts);
      }
      // `clear` mirrors `cello moniker clear` — the established verb for putting a setting back to
      // its built-in default. There is deliberately no second way to do this: `set <key> ""` stays
      // refused, because an empty away text is a VALUE that wins the resolution walk and blanks the
      // reply, which is not what "remove my away message" means.
      if (sub === "clear" && key) {
        return settingsSet(ctx.celloDir, key, null, opts);
      }
      return {
        stdout: "Usage: cello settings get [key] | cello settings set <key> <value> | cello settings clear <key>  [--agent <name>]",
        stderr: "",
        exitCode: 1,
      };
    },
  },
  {
    name: "moniker",
    group: "Other",
    summary: "Set the name OTHERS see when this agent contacts them (like caller ID).",
    help:
      "Usage: cello moniker set <name> [--agent <agent>] | cello moniker clear [--agent <agent>]\n" +
      "  Your OUTBOUND name — what shows up on the counterparty's screen when you reach them.\n" +
      "  Defaults to the agent name; 'set' overrides it, 'clear' restores the default.\n" +
      // MONIKER-0 AC2: the regex text is DERIVED from the shared constant, never hand-typed.
      `  Name rule: 1–64 characters, letters/digits/'-'/'_' only, no spaces (regex ${MONIKER_RE.source}).\n` +
      "  It is a HINT, not proof — like caller ID, the receiver is shown it as self-declared and can\n" +
      "  override it with their own pet name for you. Never sent to the directory.\n" +
      "  Example:  cello moniker set Wonderland_Alice --agent alice",
    flags: AGENT_FLAG,
    jsonOut: true,
    async run(ctx, args) {
      const { agent, pretty, positional } = parityOpts(args);
      const opts = { agent, pretty };
      const [sub, name] = positional;
      if (sub === "set" && name) return monikerSet(ctx.celloDir, name, opts);
      if (sub === "clear" && !name) return monikerSet(ctx.celloDir, null, opts);
      return { stdout: helpForSpec("moniker"), stderr: "", exitCode: 1 };
    },
  },
  {
    name: "telegram",
    group: "Other",
    summary: "Connect a Telegram bot to your daemon for notifications, status updates, etc.",
    help:
      "Usage: cello telegram set-token <bot_token> <allowlisted_chat_id>\n" +
      "  Connects a Telegram bot to your daemon so you get notified there (someone reaching you,\n" +
      "  status updates, and more over time). Starts polling immediately.\n" +
      "  The chat id you give is the ONLY chat that ever receives anything.",
    async run(ctx, args) {
      const [sub, botToken, chatId] = args;
      if (sub === "set-token" && botToken && chatId) {
        return legacy(await telegramSetToken(ctx.celloDir, botToken, chatId));
      }
      return { stdout: "Usage: cello telegram set-token <bot_token> <allowlisted_chat_id>", stderr: "", exitCode: 1 };
    },
  },
  {
    name: "bridge",
    group: "Other",
    // The runtime is a PARAMETER, not hardcoded Hermes. More runtimes are coming; neither the name
    // nor the description may claim otherwise.
    summary: "Bridge CELLO into a third-party agent runtime (Hermes, OpenClaw, …).",
    help:
      "Usage: cello bridge <runtime> --agent <name> [--hermes-home <path>]\n" +
      "  Wires the local CELLO daemon into a third-party agent runtime so that agent can use CELLO.\n" +
      "  Supported runtimes: hermes  (more coming).\n" +
      "\n" +
      "  hermes: scaffolds the CELLO plugin into the Hermes home (default ~/.hermes), binds\n" +
      "  CELLO_AGENT_NAME in its .env, and registers via 'hermes plugins enable cello' +\n" +
      "  'hermes mcp add cello'. Idempotent — re-run to upgrade.\n" +
      "  Afterwards, restart the gateway: hermes gateway restart\n" +
      "\n" +
      "  Example:  cello bridge hermes --agent alice",
    flags: [{ name: "--agent" }, { name: "--hermes-home" }],
    async run(_ctx, args) {
      const agentIdx = args.indexOf("--agent");
      const homeIdx = args.indexOf("--hermes-home");
      // Find the target positional, excluding both flags AND their values — so
      // `cello bridge --agent alice hermes` still resolves target=hermes.
      const target = args.find(
        (a, i) =>
          !a.startsWith("-") &&
          !(agentIdx !== -1 && i === agentIdx + 1) &&
          !(homeIdx !== -1 && i === homeIdx + 1),
      );
      if (target !== "hermes") {
        return { stdout: helpForSpec("bridge"), stderr: "", exitCode: 1 };
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
 * not a runtime condition. It THROWS rather than defaulting to `""`: an empty string with exit 1
 * would silently swallow the operator's only guidance, in the one code path whose entire job is to
 * explain what went wrong.
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
 * DOD-ONBOARD-HELP-1 §1: render the `Commands:` table GROUPED and in logical order.
 *
 * Sections in GROUP_ORDER, commands in declaration order within each — the order a reader would
 * actually do them. A flat/alphabetical table is wrong: it lists `register` (step 2) above
 * `create-agent` (step 1). Name column is padded across the WHOLE table (not per group) so the
 * summaries line up as one column down the page.
 */
export function renderCommandsTable(): string {
  const width = Math.max(...COMMANDS.map((c) => c.name.length));
  const sections = GROUP_ORDER.map((group) => {
    const rows = COMMANDS.filter((c) => c.group === group).map(
      (c) => `  ${c.name.padEnd(width)}  ${c.summary}`,
    );
    return rows.length === 0 ? null : `${group}:\n${rows.join("\n")}`;
  }).filter((s): s is string => s !== null);
  return sections.join("\n\n");
}
