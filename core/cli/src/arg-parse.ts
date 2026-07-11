/**
 * Shared argv parsing primitives.
 *
 * Extracted from cli-args.ts (DOD-CLI-PARITY-1 Phase 0) so that BOTH the registry (which parses a
 * command's args inside its run()) and cli-args (which validates them before dispatch) can use it
 * without an import cycle: cli-args → registry → arg-parse, never back.
 */

/**
 * Split a subcommand's argv into the `--agent <name>` flag and the remaining positionals.
 *
 * Extracted originally (MONIKER-1 review Finding 1) because the old inline filter used
 * `i === agentIdx + 1` unguarded: with --agent ABSENT, agentIdx is -1 and the predicate silently
 * dropped positional index 0 — `cello moniker set Bob` / `cello contact list` printed usage instead
 * of dispatching. The flag's value is excluded ONLY when the flag exists.
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
