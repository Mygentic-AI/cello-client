/**
 * M8B riders F1/F2 — CLI argument handling, extracted from src/bin/cello.ts so the
 * usage surface is testable without spawning the binary.
 *
 * F1: USAGE lists EVERY dispatchable command (refresh and receipts were missing).
 * F2: every subcommand answers --help/-h, and an unrecognized flag is REJECTED
 *     instead of being coerced into a positional argument (previously
 *     `cello register --help` tried to register an agent literally named "--help").
 */

import { MONIKER_RE } from "@cello-protocol/protocol-types";

export const KNOWN_COMMANDS = new Set([
  "login",
  "logout",
  "status",
  "register",
  "create-agent",
  "remove-agent",
  "refresh",
  "receipts",
  "sessions",
  "contact",
  "settings",
  "moniker",
  "telegram",
  "install",
] as const);

export type KnownCommand = typeof KNOWN_COMMANDS extends Set<infer T> ? T : never;

// CC-7 (P2-5 / DOD-ONBOARD-HELP-1): the top level opens with what CELLO is + the onboarding path a
// first-time user needs, then the command list. (Per-command `cello <cmd> --help` was already good.)
export const USAGE =
  "CELLO — a peer-to-peer identity & trust layer for agent-to-agent communication.\n" +
  "\n" +
  "First-time setup:  cello login  →  cello create-agent <name>  →  cello register <name> <token>  →  cello status\n" +
  "  (get <token> from the CELLO Operations Agent on Telegram; 'cello login' starts the local daemon.)\n" +
  "\n" +
  "Usage: cello <login|logout|status|register|create-agent|remove-agent|refresh|receipts|sessions|contact|settings|moniker|telegram|install>\n" +
  "Run 'cello <command> --help' for details on any command.";

/** Per-command usage lines (the same text the commands print on bad input). */
const COMMAND_HELP: Record<string, string> = {
  login: "Usage: cello login  — start the daemon (or connect to an existing one).",
  logout: "Usage: cello logout  — send shutdown to the running daemon.",
  status: "Usage: cello status  — query the daemon and print the structured status JSON.",
  register:
    "Usage: cello register <agent> <pre-auth-token>  — register a LOCAL agent with the directory.\n" +
    "  The two-step onboarding: (1) 'cello create-agent <name>' makes the local identity; (2) 'cello register <name> <token>' registers it with the directory.\n" +
    "  The token is a single-use pre-authorization ticket from the CELLO Operations Agent on Telegram, format 'CELLO-' + 33 characters, valid 24h.\n" +
    "  Example:  cello register alice CELLO-3xY7...\n" +
    "  Env-var form (avoids retyping):  CELLO_PREAUTH_TOKEN=CELLO-3xY7... cello register alice\n" +
    "  Quoting is only needed if a value contains spaces (agent names and tokens never do).",
  "create-agent":
    "Usage: cello create-agent <name>  — create a new LOCAL agent identity (does not touch the directory).\n" +
    // MONIKER-0 AC2: the regex text is DERIVED from the shared constant, never hand-typed.
    `  Name rule: 1–64 characters, letters/digits/'-'/'_' only, no spaces (regex ${MONIKER_RE.source}).\n` +
    "  Next step: 'cello register <name> <pre-auth-token>' to register it with the directory.",
  "remove-agent": "Usage: cello remove-agent <name>  — retires a local agent (one-way) and frees its name.",
  refresh: "Usage: cello refresh <name>  — proactively refresh the agent's threshold shares (new epoch).",
  receipts: "Usage: cello receipts <name>  — list the agent's stored relay ordering receipts.",
  sessions:
    "Usage: cello sessions [--open|--closed|--failed|--all] [--limit N]  — list session history (defaults to open).",
  contact:
    "Usage: cello contact add <pubkey> [--agent <name>] | cello contact remove <pubkey> [--agent <name>] | cello contact list [--agent <name>] | cello contact tier <pubkey> <0..4> [--agent <name>]\n" +
    "  Per-agent contact whitelist (M8C-CONTACT-1). --agent defaults to the current/sole-online agent.\n" +
    "  Contacts are added automatically too: initiating a session to X, or accepting X's inbound request, adds X.\n" +
    "  Example:  cello contact list --agent alice",
  settings:
    "Usage: cello settings get [key] [--agent <name>] | cello settings set <key> <value> [--agent <name>]\n" +
    "  Per-agent reachability policy (DOD-SETTINGS-1). Keys: bounds.<tier>.max_sessions, bounds.<tier>.max_bytes\n" +
    "  (tier = unknown|known|whitelisted|vip; a finite positive integer), away.default, away.tier.<tier> (away text).\n" +
    "  An unset key uses the built-in default. Example:  cello settings set bounds.known.max_sessions 8 --agent alice",
  moniker:
    "Usage: cello moniker set <name> [--agent <agent>] | cello moniker clear [--agent <agent>]\n" +
    "  The agent's OUTBOUND name — what a counterparty's doorbell shows (MONIKER-1). Defaults to the agent name; 'set' stores an override, 'clear' restores the default.\n" +
    // MONIKER-0 AC2: the regex text is DERIVED from the shared constant, never hand-typed.
    `  Name rule: 1–64 characters, letters/digits/'-'/'_' only, no spaces (regex ${MONIKER_RE.source}).\n` +
    "  Local-only: never sent to the directory; the receiver treats it as an unverified hint (like caller ID).\n" +
    "  Example:  cello moniker set Wonderland_Alice --agent alice",
  telegram:
    "Usage: cello telegram set-token <bot_token> <allowlisted_chat_id>  — configure the daemon-owned Telegram doorbell (M8C-TGDOOR-1).\n" +
    "  Starts a single long-lived poller immediately; the operator chat given is the ONLY one that ever receives doorbell events.",
  install:
    "Usage: cello install hermes --agent <name> [--hermes-home <path>]  — wire the local CELLO daemon into a Hermes Agent installation.\n" +
    "  Scaffolds the CELLO platform-adapter plugin into the Hermes home (default ~/.hermes), binds CELLO_AGENT_NAME in its .env,\n" +
    "  and registers via 'hermes plugins enable cello' + 'hermes mcp add cello'. Idempotent — re-run to upgrade.\n" +
    "  After installing, restart the gateway: hermes gateway restart",
};

export function helpForCommand(command: string): string {
  return COMMAND_HELP[command] ?? USAGE;
}

/** Flags each command recognizes. `--limit` consumes the following value. */
const COMMAND_FLAGS: Record<string, ReadonlySet<string>> = {
  sessions: new Set(["--open", "--closed", "--failed", "--all", "--limit"]),
  contact: new Set(["--agent"]),
  settings: new Set(["--agent"]),
  moniker: new Set(["--agent"]),
  install: new Set(["--agent", "--hermes-home"]),
};

export type ArgsCheck =
  | { kind: "ok" }
  | { kind: "help" }
  | { kind: "unknown_flag"; flag: string };

/**
 * F2: validate a subcommand's arguments BEFORE dispatch.
 *  - --help / -h ANYWHERE → help. This is a dedicated pre-scan so help wins even when it
 *    follows an unknown flag or sits where --limit would consume its value — asking for
 *    help must never be masked by another argument error.
 *  - any other dash-prefixed token the command does not recognize → unknown_flag
 *    (never silently coerced into a positional).
 */
/**
 * Split a subcommand's argv into the `--agent <name>` flag and the remaining positionals.
 * Extracted (MONIKER-1 review Finding 1) because the old inline filter used
 * `i === agentIdx + 1` unguarded: with --agent ABSENT, agentIdx is -1 and the predicate
 * silently dropped positional index 0 — `cello moniker set Bob` / `cello contact list`
 * printed usage instead of dispatching. The flag's value is excluded ONLY when the flag exists.
 */
export function splitAgentFlag(args: string[]): { agent: string | undefined; positional: string[] } {
  // POSIX `--` end-of-flags terminator (review F1): everything after the first `--` is a positional
  // VALUE, verbatim — so a value that starts with `-` (a negative number, or an away text like
  // "- back Monday") can be passed. --agent is recognized only BEFORE the terminator.
  const ddIdx = args.indexOf("--");
  const flagScan = ddIdx === -1 ? args : args.slice(0, ddIdx);
  const afterTerminator = ddIdx === -1 ? [] : args.slice(ddIdx + 1);
  const agentIdx = flagScan.indexOf("--agent");
  const agent = agentIdx !== -1 ? flagScan[agentIdx + 1] : undefined;
  const positional = flagScan
    .filter((a, i) => !(a === "--agent" || (agentIdx !== -1 && i === agentIdx + 1)))
    .concat(afterTerminator);
  return { agent, positional };
}

export function checkArgs(command: string, args: string[]): ArgsCheck {
  if (args.some((a) => a === "--help" || a === "-h")) return { kind: "help" };
  const known = COMMAND_FLAGS[command] ?? new Set<string>();
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--") break; // POSIX end-of-flags — everything after is a positional value (review F1)
    if (arg.startsWith("-")) {
      if (!known.has(arg)) return { kind: "unknown_flag", flag: arg };
      if (arg === "--limit") i++; // consumes its value
    }
  }
  return { kind: "ok" };
}
