/**
 * WHAT CAN BE DONE ABOUT IT — the half of a refusal that was missing.
 *
 * Every guard in this layer could say what it did. None could say what was AVAILABLE. An agent that
 * is told only "not sent" retries the same thing, gives up, or invents a workaround, and the
 * operator never learns a guard misfired. That gap put a coworker's agent in a loop within hours of
 * enforcing going live (journal C16): it was refused twice over a date flagged as a phone number,
 * and nothing it was told named the one command that would have cleared it.
 *
 * The rules these strings follow:
 *   - Name what the AGENT can do unaided first, when there is anything.
 *   - Name the OPERATOR's exact command second, as an INSTRUCTION not to run it — never as a claim
 *     that it is impossible. Review F5: the first version said "you cannot", and that is false. The
 *     TTY check is `process.stdin.isTTY`, and `script -q /dev/null cello config set …` flips it, so
 *     an agent with a shell could confirm its own loosening. `INV-10` says this honestly ("a
 *     friction gate, not a lock"); the one place that honesty was dropped was the string an LLM
 *     actually reads, while handing it the exact command. Tell it not to. Do not tell it it can't.
 *   - When a guard is deliberately NOT adjustable, SAY SO. Inventing a knob that does not exist is
 *     worse than the silence this replaces — the agent burns turns hunting for it.
 *   - Never echo the flagged VALUE back. The guidance is rendered into an LLM's context; repeating
 *     a secret to explain that it was redacted would undo the redaction.
 */

/** The five keys `cello config` exposes. Anything not here has no operator knob — say so instead. */
export type AdjustableGuard =
  | "pii_whitelist"
  | "autonomous_override"
  | "language_allow"
  | "rate_max_per_window"
  | "rate_window_ms";

/**
 * The operator's line for a guard that CAN be adjusted. `argHint` is a shape, never a real flagged
 * value — see the no-echo rule above.
 */
export function operatorCanRun(guard: AdjustableGuard, argHint: string): string {
  return (
    `IF THIS IS WRONG, relay this to your operator to run in their terminal. DO NOT run it ` +
    `yourself and do not try to work around the guard:\n  cello config set ${guard} ${argHint}\n` +
    `It asks them to confirm once. To see exactly what fired: cello policy log`
  );
}

/** For a guard with no knob. Better a plain "no" than an invented command. */
export function noOperatorOverride(what: string): string {
  return (
    `This guard is not adjustable — there is no setting that turns it off, deliberately. ${what} ` +
    `To see exactly what fired: cello policy log`
  );
}
