/**
 * CLI argument handling — validation that runs BEFORE dispatch, kept out of src/bin/cello.ts so the
 * usage surface is testable without spawning the binary.
 *
 * M8B riders F1/F2 (原): USAGE lists EVERY dispatchable command; every subcommand answers --help/-h;
 * an unrecognized flag is REJECTED rather than coerced into a positional (previously
 * `cello register --help` tried to register an agent literally named "--help").
 *
 * DOD-CLI-PARITY-1 Phase 0: this module no longer OWNS the command list, the help text, or the flag
 * table — it DERIVES all three from the registry (registry.ts), the single source of truth. That is
 * what makes drift between dispatch, `cello --help`, and `cello <cmd> --help` structurally
 * impossible rather than merely discouraged.
 */

import { COMMANDS, commandNames, findCommand, flagsFor, renderCommandsTable } from "./registry.js";

// Re-exported for the dispatch layer and existing callers (its home is arg-parse.ts, which both
// this module and the registry depend on — see the import-cycle note there).
export { splitAgentFlag } from "./arg-parse.js";

/** Every dispatchable command — derived, so it cannot fall out of step with the registry. */
export const KNOWN_COMMANDS: ReadonlySet<string> = new Set(commandNames());

export type KnownCommand = string;

/**
 * The top-level `cello --help`.
 *
 * CC-7 (P2-5 / DOD-ONBOARD-HELP-1): opens with what CELLO is + the onboarding path a first-time
 * user needs. DOD-CLI-PARITY-1 §7 closes the remaining gap — the command list is now a DESCRIBED
 * table rendered from each registry entry's `summary` (it used to be a single pipe-delimited blob
 * with no per-command descriptions). Arguments stay in per-command `--help`.
 */
export const USAGE =
  "CELLO — a peer-to-peer identity & trust layer for agent-to-agent communication.\n" +
  "\n" +
  "First-time setup:  cello login  →  cello create-agent <name>  →  cello register <name> <token>  →  cello status\n" +
  "  (get <token> from the CELLO Operations Agent on Telegram; 'cello login' starts the local daemon.)\n" +
  "\n" +
  "Usage: cello <command> [args]\n" +
  "\n" +
  renderCommandsTable() +
  "\n" +
  "\n" +
  "Run 'cello <command> --help' for details on any command.\n" +
  // Scoped deliberately: only the parity commands (jsonOut) honor the full §3 contract — JSON on
  // stdout, structured error on stderr. The older commands (login, register, …) still print human
  // text, and their failures go to stdout. Claiming the contract for EVERY command would be a
  // promise the binary does not keep, made to precisely the reader who would script against it.
  "The session and agent commands (agents, use-agent, initiate, send, receive, close, …) print JSON\n" +
  "and exit non-zero on failure, so any bash-capable agent can drive CELLO with no MCP dependency.";

/** Per-command help — the registry entry's own text, verbatim. */
export function helpForCommand(command: string): string {
  return findCommand(command)?.help ?? USAGE;
}

export type ArgsCheck =
  | { kind: "ok" }
  | { kind: "help" }
  | { kind: "unknown_flag"; flag: string };

/**
 * F2: validate a subcommand's arguments BEFORE dispatch.
 *  - --help / -h ANYWHERE → help. This is a dedicated pre-scan so help wins even when it
 *    follows an unknown flag or sits where a value-consuming flag would swallow it — asking for
 *    help must never be masked by another argument error.
 *  - any other dash-prefixed token the command does not recognize → unknown_flag
 *    (never silently coerced into a positional).
 *  - after a POSIX `--` terminator, everything is a positional VALUE, verbatim.
 */
export function checkArgs(command: string, args: string[]): ArgsCheck {
  if (args.some((a) => a === "--help" || a === "-h")) return { kind: "help" };
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
