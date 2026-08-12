/**
 * CLI argument handling — validation that runs BEFORE dispatch, kept out of src/bin/cello.ts so the
 * usage surface is testable without spawning the binary.
 *
 * The rules it enforces: USAGE lists EVERY dispatchable command; every subcommand answers
 * --help/-h; an unrecognized flag is REJECTED rather than coerced into a positional (otherwise
 * `cello register --help` tries to register an agent literally named "--help").
 *
 * This module does not OWN the command list, the help text, or the flag table — it DERIVES all
 * three from the registry (registry.ts), the single source of truth. That is what makes drift
 * between dispatch, `cello --help`, and `cello <cmd> --help` structurally impossible rather than
 * merely discouraged.
 */

import { COMMANDS, commandNames, findCommand, flagsFor, renderCommandsTable } from "./registry.js";

// Re-exported for the dispatch layer and existing callers (its home is arg-parse.ts, which both
// this module and the registry depend on — see the import-cycle note there).
export { splitAgentFlag } from "./arg-parse.js";

/** Every dispatchable command — derived, so it cannot fall out of step with the registry. */
export const KNOWN_COMMANDS: ReadonlySet<string> = new Set(commandNames());

export type KnownCommand = string;

/**
 * The flags that come BEFORE any command — `cello --version`, `cello --help`.
 *
 * They were treated as unknown COMMANDS, so `cello --version` printed the entire help text and
 * exited 1. That is the first thing anyone runs to check an install, and it answered by looking
 * broken while being fine. `--help` had the same shape: correct output, exit 1, which is what a
 * script checks. The comment in `USAGE` above has always called it "the top-level `cello --help`" —
 * the text existed for a flag the dispatcher never actually recognised.
 *
 * Kept as a pure function here rather than an `if` in the bin, so it is testable without spawning
 * the binary — the reason every other argument rule lives in this module.
 */
export function topLevelFlag(command: string | undefined): "version" | "help" | undefined {
  if (command === "--version" || command === "-v") return "version";
  if (command === "--help" || command === "-h") return "help";
  return undefined;
}

/**
 * The top-level `cello --help`.
 *
 * Opens with what CELLO is + the onboarding path a first-time user needs. The command list is a
 * DESCRIBED table rendered from each registry entry's `summary`. Arguments stay in per-command
 * `--help`.
 */
export const USAGE =
  "CELLO — a peer-to-peer identity & trust layer for agent-to-agent communication.\n" +
  "\n" +
  "First-time setup:  cello login  →  cello create-agent <name>  →  cello register-agent <name> <token>  →  cello status\n" +
  "  (get <token> from the CELLO Operations Agent on Telegram; 'cello login' starts the local daemon.)\n" +
  "\n" +
  "Usage: cello <command> [args]\n" +
  "\n" +
  renderCommandsTable() +
  "\n" +
  "\n" +
  "Run 'cello <command> --help' for details on any command.\n" +
  // Scoped deliberately: only the parity commands (jsonOut) honor the full §3 contract — JSON on
  // stdout, structured error on stderr. The older commands (login, register-agent, …) still print
  // human text, and their failures go to stdout. Claiming the contract for EVERY command would be a
  // promise the binary does not keep, made to precisely the reader who would script against it.
  "The session and agent commands (agents, use-agent, initiate-session, send, receive, close-session,\n" +
  "…) print JSON and exit non-zero on failure, so any bash-capable agent can drive CELLO with no MCP\n" +
  "dependency. Where a command has an MCP tool, it carries the SAME name: cello send ↔ cello_send.";

/** Per-command help — the registry entry's own text, verbatim. */
export function helpForCommand(command: string, args: readonly string[] = []): string {
  // SUB-VERB HELP WINS. `-h` is answered here, before dispatch, so a per-verb help block inside
  // a command's own handler could never run — `cello doc propose -h` printed the whole doc list,
  // which names propose's six flags and explains none of them.
  const sub = args.find((a) => !a.startsWith("-"));
  if (sub) {
    const detail = findCommand(command)?.subHelp?.[sub];
    if (detail) return detail;
  }
  return findCommand(command)?.help ?? USAGE;
}

export type ArgsCheck =
  | { kind: "ok" }
  | { kind: "help" }
  | { kind: "unknown_flag"; flag: string };

/**
 * Validate a subcommand's arguments BEFORE dispatch.
 *  - --help / -h ANYWHERE → help. This is a dedicated pre-scan so help wins even when it
 *    follows an unknown flag or sits where a value-consuming flag would swallow it — asking for
 *    help must never be masked by another argument error.
 *  - any other dash-prefixed token the command does not recognize → unknown_flag
 *    (never silently coerced into a positional).
 *  - after a POSIX `--` terminator, everything is a positional VALUE, verbatim.
 */
export function checkArgs(command: string, args: string[]): ArgsCheck {
  // The help check MUST respect the `--` terminator too. It used to scan the whole argv, so
  // `cello attestations issue <pubkey> -- she walked me through the -h flag` printed help instead
  // of issuing the signal — the terminator was honoured for unknown flags and ignored for help,
  // which is the surprising half. Commands that take free prose (issue, consent refuse, contact
  // set-away) are exactly the ones where a bare `-h` appears as ordinary text.
  const terminator = args.indexOf("--");
  const flagArgs = terminator === -1 ? args : args.slice(0, terminator);
  if (flagArgs.some((a) => a === "--help" || a === "-h")) return { kind: "help" };
  const known = flagsFor(command);
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--") break; // POSIX end-of-flags — everything after is a positional value
    if (arg.startsWith("-")) {
      const spec = known.get(arg);
      if (!spec) return { kind: "unknown_flag", flag: arg };
      if (spec.consumesValue) i++; // its value is not itself a flag
    }
  }
  return { kind: "ok" };
}

/** The registry, re-exported for callers that want to enumerate commands (e.g. the dispatcher). */
export { COMMANDS };
