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
  settingsGet,
  settingsSet,
  monikerSet,
  telegramSetToken,
  type CommandResult,
} from "./commands.js";
import { splitAgentFlag } from "./arg-parse.js";
import {
  IPC_METHODS,
  contactAdd,
  contactRemove,
  contactList,
  contactSetTier,
  contactSetAway,
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
  "Contacts",
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
 * Review F5 — a numeric flag given a NON-NUMERIC value must fail loud, never be silently dropped.
 *
 * `--since-seq abc` used to parse to undefined, which `defined()` then removed, which turned a
 * stateless CATCH-UP into a 30-second BLOCKING live wait that returns `content: null` — so a script
 * asking "what did I miss?" was answered "nothing new" to a question it never asked. Silently
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
 * `consumesValue: false` is deliberate and is what checkArgs PARITY requires: the pre-existing
 * checkArgs never skipped --agent's value (only `--limit` did), and flipping this to true would
 * change `cello contacts --agent --bogus` from a fail-loud unknown_flag into a silently
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
    name: "stop-agent",
    group: "Agents",
    summary: "Take an agent offline. It stops accepting anything until restarted.",
    help: "Usage: cello stop-agent <name> [--pretty]  — take an agent offline.",
    ipcMethod: IPC_METHODS["stop-agent"],
    jsonOut: true,
    async run(ctx, args) {
      const { pretty, positional } = parityOpts(args);
      return stopAgent(ctx.celloDir, positional[0] ?? "", { pretty });
    },
  },
  {
    name: "refresh",
    group: "Agents",
    // VERIFIED against the handler (cello_refresh_shares → runAgentRefresh), not guessed. It runs a
    // resharing ceremony with the directory nodes and moves the agent to a NEW key epoch. Routine
    // key hygiene — nothing is re-registered and the agent's public identity does not change.
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
      "Usage: cello initiate-session <target-pubkey> [--agent <name>] [--pretty]  — open a session.\n" +
      "  <target-pubkey> is the counterparty's hex public key. Prints the session_id you then pass to\n" +
      "  'cello send' / 'cello receive' / 'cello close-session'. Adds them to your address book.",
    flags: AGENT_FLAG,
    ipcMethod: IPC_METHODS["initiate-session"],
    jsonOut: true,
    async run(ctx, args) {
      const { agent, pretty, positional } = parityOpts(args);
      return initiate(ctx.celloDir, positional[0] ?? "", { agent, pretty });
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
      "Usage: cello close-session <session-id> [--force] [--agent <name>] [--pretty]\n" +
      "  Both parties sign off on the whole conversation and each gets a notarized receipt\n" +
      "  ('cello sealed-receipt <session-id>' prints it).\n" +
      "  --force abandons a half-open session that can never be sealed (a handshake the counterparty\n" +
      "  never joined). It FORFEITS the receipt — never use it on a healthy session.",
    flags: [
      { name: "--agent", consumesValue: false },
      { name: "--force", consumesValue: false },
    ],
    ipcMethod: IPC_METHODS["close-session"],
    jsonOut: true,
    async run(ctx, args) {
      const { agent, pretty, positional } = parityOpts(args);
      const force = positional.includes("--force");
      const rest = positional.filter((a) => a !== "--force");
      return closeSession(ctx.celloDir, rest[0] ?? "", { agent, pretty, force });
    },
  },
  {
    name: "send",
    group: "Messaging",
    // §4: "honors read-before-write" was jargon for a rule the operator meets as a REFUSAL. Say the
    // rule, and say that the tool will tell you.
    summary: "Send a message. Any unread messages must be read first — you'll be told, and blocked until you do.",
    help:
      "Usage: cello send <session-id> <message…> [--stdin] [--agent <name>] [--pretty]\n" +
      "  The message is the remaining arguments, or the whole of stdin with --stdin (for text with\n" +
      "  newlines/quotes).\n" +
      "  If the other side has said something you have not read, the send is REFUSED and tells you how\n" +
      "  many messages are waiting. Read them ('cello receive <session-id>', or 'cello transcript\n" +
      "  <session-id>' for the whole conversation) and send again. This is deliberate: you cannot\n" +
      "  reply to something you never saw. The refusal is printed verbatim and never auto-fixed.",
    flags: [
      { name: "--agent", consumesValue: false },
      { name: "--stdin", consumesValue: false },
    ],
    ipcMethod: IPC_METHODS.send,
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
      // Review F6: an UNRECOGNIZED scope must not silently become the default. A typo'd
      // `--scope all` (e.g. "al") would have answered with `current`'s data and exit 0 — the
      // operator reads "no notifications" while another agent's inbox is full.
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
    // VERIFIED against the handler (cello_get_relay_receipts → getRelayReceipts): per-MESSAGE
    // signatures from a RELAY attesting it handled and ordered that message. Renamed from
    // `receipts` because a name that differed from `sealed-receipt` by one plural could not be
    // rescued by any description — Andre could not tell them apart, and he wrote the protocol.
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
      "    set-moniker <name>        YOUR pet name for THEM (empty clears it). Always wins over the\n" +
      "                              name they offer — the one thing they cannot spoof.\n" +
      "\n" +
      "  To list the whole book, use 'cello contacts'.\n" +
      "  Note: 'set-moniker' names a CONTACT. 'cello moniker' sets your OWN outbound name.\n" +
      "  Example:  cello contact 178d420b… set-tier 3 --agent alice",
    flags: AGENT_FLAG,
    jsonOut: true, // review F3: the WHOLE address book honors §3 — one command, one contract
    async run(ctx, args) {
      const { agent, pretty, positional } = parityOpts(args);
      const o = { agent, pretty };
      // §3 SHAPE: `contact <pubkey> <op>` — the subject first, then what to do to them. (The old
      // shape was `contact <op> <pubkey>`, which read like a verb table rather than an address book.)
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
      if (op === "set-moniker") {
        // Empty → null clears it, mirroring the tool.
        const moniker = positional.slice(2).join(" ");
        return contactSetMoniker(ctx.celloDir, pubkey, moniker.length > 0 ? moniker : null, o);
      }
      return { stdout: helpForSpec("contact"), stderr: "", exitCode: 1 };
    },
  },

  // ═══ Other ══════════════════════════════════════════════════════════════════════════════════
  {
    name: "settings",
    group: "Other",
    summary: "Get or set how reachable an agent is (limits per trust tier, away messages).",
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
    // Renamed from `install`, which read as "install CELLO itself" and hardcoded Hermes — the
    // runtime is a PARAMETER. More runtimes are coming; the description must not claim otherwise.
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
 * DOD-ONBOARD-HELP-1 §1: render the `Commands:` table GROUPED and in logical order.
 *
 * Flat-and-arbitrary was the reopen: `register` appeared before `create-agent`, so the table
 * literally listed step 2 above step 1. Sections in GROUP_ORDER, commands in declaration order
 * within each — the order a reader would actually do them. Name column is padded across the WHOLE
 * table (not per group) so the summaries line up as one column down the page.
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
