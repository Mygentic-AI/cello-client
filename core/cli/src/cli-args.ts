/**
 * M8B riders F1/F2 — CLI argument handling, extracted from src/bin/cello.ts so the
 * usage surface is testable without spawning the binary.
 *
 * F1: USAGE lists EVERY dispatchable command (refresh and receipts were missing).
 * F2: every subcommand answers --help/-h, and an unrecognized flag is REJECTED
 *     instead of being coerced into a positional argument (previously
 *     `cello register --help` tried to register an agent literally named "--help").
 */

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
] as const);

export type KnownCommand = typeof KNOWN_COMMANDS extends Set<infer T> ? T : never;

export const USAGE =
  "Usage: cello <login|logout|status|register|create-agent|remove-agent|refresh|receipts|sessions>\n" +
  "Run 'cello <command> --help' for command-specific usage.";

/** Per-command usage lines (the same text the commands print on bad input). */
const COMMAND_HELP: Record<string, string> = {
  login: "Usage: cello login  — start the daemon (or connect to an existing one).",
  logout: "Usage: cello logout  — send shutdown to the running daemon.",
  status: "Usage: cello status  — query the daemon and print the structured status JSON.",
  register:
    "Usage: cello register <agent> [preAuthToken]  — register a loaded agent with the directory. Prefer CELLO_PREAUTH_TOKEN over the positional token (argv is visible in the process list).",
  "create-agent": "Usage: cello create-agent <name>  — creates a new local agent identity.",
  "remove-agent": "Usage: cello remove-agent <name>  — retires a local agent (one-way) and frees its name.",
  refresh: "Usage: cello refresh <name>  — proactively refresh the agent's threshold shares (new epoch).",
  receipts: "Usage: cello receipts <name>  — list the agent's stored relay ordering receipts.",
  sessions:
    "Usage: cello sessions [--open|--closed|--failed|--all] [--limit N]  — list session history (defaults to open).",
};

export function helpForCommand(command: string): string {
  return COMMAND_HELP[command] ?? USAGE;
}

/** Flags each command recognizes. `--limit` consumes the following value. */
const COMMAND_FLAGS: Record<string, ReadonlySet<string>> = {
  sessions: new Set(["--open", "--closed", "--failed", "--all", "--limit"]),
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
export function checkArgs(command: string, args: string[]): ArgsCheck {
  if (args.some((a) => a === "--help" || a === "-h")) return { kind: "help" };
  const known = COMMAND_FLAGS[command] ?? new Set<string>();
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith("-")) {
      if (!known.has(arg)) return { kind: "unknown_flag", flag: arg };
      if (arg === "--limit") i++; // consumes its value
    }
  }
  return { kind: "ok" };
}
