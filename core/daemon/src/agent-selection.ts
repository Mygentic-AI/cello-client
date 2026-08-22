/**
 * Which agent a call acts as, and HOW that was decided — `DOD-M15-SELECTION-1`,
 * `DOD-M15-IPCVISIBLE-1`.
 *
 * ─── The defect this is extracted from ─────────────────────────────────────────────────────────
 *
 * This logic was four lines inside `daemon.ts`, ending in:
 *
 *     if (onlineAgents.size === 1) return [...onlineAgents][0];
 *
 * A connection that had selected nothing therefore acted as whichever agent happened to be the only
 * one online. On a shared daemon that can be a DIFFERENT operator's agent, which is how it was
 * found: after a restart a released agent was silently reinstated under someone else's name.
 *
 * ─── Why the fallback is worse than it looks even when it picks the "right" agent ──────────────
 *
 * It produces a HALF-ATTENDED state. Tools resolve a subject and work; the notification dispatcher
 * routes doorbells by the connection's REGISTERED current agent, which this never sets. So the
 * session sends and receives on request but never wakes — and an operator reads that as the
 * protocol dropping messages, not as a selection that was never made.
 *
 * ─── AND WHY IT IS STILL HERE ──────────────────────────────────────────────────────────────────
 *
 * My first version switched the fallback OFF for MCP on that reasoning, and four tests said no. CC-3
 * added it deliberately, to fix "the post-/mcp-reconnect papercut": a reconnected session with
 * exactly one agent online used to hard-fail `no_current_agent`.
 *
 * `DOD-M15-SELECTION-1`'s answer is narrower than removal — *"if a fallback is wanted it is EXPLICIT
 * in the response, not announced as an accomplished fact"* — and it sequences the work: *"diagnosis
 * first… with the trigger field from DOD-M15-IPCVISIBLE-1 distinguishing replay from fallback in one
 * run."* So this module makes the decision ATTRIBUTABLE, which is the precondition, and changing
 * what the fallback DOES waits for the diagnosis that attribution makes possible.
 *
 * ─── Every path reports how it got there ───────────────────────────────────────────────────────
 *
 * Two agent switches fired one second after a reconnect on 2026-08-09 and neither could be
 * attributed, because an operator's explicit selection and the shim's reconnect replay arrive
 * identically. `fallback` is the third value `DOD-M15-IPCVISIBLE-1` asks for, and the one that was
 * invisible.
 */

/** How a call's acting agent was arrived at. Every branch reports one. */
export type SelectionTrigger =
  /** The caller named an agent on this call. */
  | "explicit"
  /** The connection had selected one earlier with `cello_use_agent`. */
  | "selected"
  /** Nothing was selected and one agent was online — a CLI convenience, never for a live session. */
  | "fallback"
  /**
   * The connection's choice was TAKEN AWAY — the agent was shut down or removed underneath it.
   *
   * NOT a voluntary release. `cello_stop_using_agent` deliberately does not set this: the operator
   * choosing to hold nothing stays eligible for the sole-online fallback, whereas a connection whose
   * agent vanished must not have a replacement guessed for it.
   */
  | "cleared"
  /** No agent could be determined. */
  | "none";

export interface SelectionConnState {
  currentAgent: string | null;
  /** Set by `cello_stop_using_agent`: this connection HAD an intent and gave it up. */
  clearedAgent?: string;
  /** `"mcp"` is a live session; anything else is treated as an ephemeral CLI invocation. */
  clientType?: string;
}

export function resolveCurrentAgentFor(opts: {
  connState: SelectionConnState | undefined;
  onlineAgents: ReadonlySet<string>;
  explicitAgent?: string;
  /** Called exactly once with the outcome, so the decision is attributable in the log. */
  onResolved?: (agent: string | null, trigger: SelectionTrigger) => void;
}): string | null {
  const report = (agent: string | null, trigger: SelectionTrigger): string | null => {
    opts.onResolved?.(agent, trigger);
    return agent;
  };

  if (opts.explicitAgent) return report(opts.explicitAgent, "explicit");
  if (opts.connState?.currentAgent) return report(opts.connState.currentAgent, "selected");

  /**
   * AN INVOLUNTARY CLEAR BLOCKS THE FALLBACK. Pre-existing behaviour, preserved.
   *
   * `clearedAgent` means the connection's agent was shut down or removed underneath it — do not
   * guess a replacement. A VOLUNTARY release (`cello_stop_using_agent`) deliberately does not set
   * it, because the operator choosing to hold nothing is not the same as having the choice taken,
   * and they stay eligible for the fallback.
   */
  if (opts.connState?.clearedAgent) return report(null, "cleared");

  /**
   * THE SOLE-ONLINE FALLBACK — behaviour UNCHANGED, visibility added.
   *
   * `DOD-M15-SELECTION-1` names this as the place a live MCP session gets bound to an identity it
   * never asked for, and the instinct is to switch it off for MCP. That is wrong, and the tests say
   * why: CC-3 introduced it deliberately to fix "the post-/mcp-reconnect papercut", where a
   * reconnected session hard-failed `no_current_agent` with exactly one agent online.
   *
   * The line's own answer is narrower than removal: *"if a fallback is wanted it is EXPLICIT in the
   * response, not announced as an accomplished fact."* And it sequences the work — *"diagnosis
   * first… with the trigger field from DOD-M15-IPCVISIBLE-1 distinguishing replay from fallback in
   * one run."* So this reports itself, and changing what it DOES waits for that diagnosis.
   *
   * Exactly one, never a guess between two: choosing between identities is a coin flip with the
   * operator's name on it, not a convenience.
   */
  if (opts.onlineAgents.size === 1) return report([...opts.onlineAgents][0]!, "fallback");

  return report(null, "none");
}
