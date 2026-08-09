/**
 * The one place an agent's state is decided.
 *
 * There are two status surfaces — the daemon-wide `getStatus()` the CLI prints, and the
 * per-connection `cello_status` the MCP tools call — and they had two separate copies of this
 * calculation. They already drifted once this week on a different field: the directory-health block
 * existed on one surface and not the other, which is why an operator whose sessions were all failing
 * could run `cello status` and be told nothing. Two copies of a truth claim is how that happens, so
 * this exists as a single function both surfaces call.
 *
 * The ladder is documented on `AgentState` in types.ts. Order here IS the semantics: the first
 * matching rung wins, worst fact first. An attended agent whose signaling is down reads
 * `connecting`, not `online` — the severe fact is the one stopping it doing its job, and it is the
 * one the operator needs. Reversing that would let attendance mask a dead connection, which is the
 * exact class of lie this enum replaces.
 */

import type { AgentState } from "./types.js";

/**
 * Is this agent RUNNING — started, and not switched off?
 *
 * Use this wherever the old code asked `state === "online"` and MEANT "started". Narrowing `online`
 * to also require an attendee changed the meaning of every such check silently: the string stayed
 * valid, so the compiler caught none of them, and the symptom was `cello settings set` refusing a
 * perfectly healthy agent with `selected_agent_offline`.
 *
 * The callers' actual question is the kill switch one — "may I claim this agent, or did the operator
 * deliberately stop it?" So the excluded states are the ones where claiming it would be wrong:
 * `stopped` and `paused` (resurrecting either would silently undo an operator's decision),
 * `unregistered` (nobody can reach it), and `load_failed`.
 *
 * `unattended` counts: nobody is at the desk, so a caller gets the away message rather than a live
 * reply, but the agent is up, reachable, and will record the session.
 *
 * `connecting` counts too, and that is deliberate. It is started; its directory stream is merely
 * still coming up, which is NORMAL for a minute after registering. Excluding it made local commands
 * — settings, moniker — refuse for want of a directory they never needed, which is the same
 * over-reach in the opposite direction.
 */
export function isAgentRunning(state: AgentState | string | undefined): boolean {
  return state === "online" || state === "unattended" || state === "connecting";
}

/** Everything the decision needs. Each field is a fact the daemon already tracks. */
export interface AgentStateInputs {
  /** The identity failed to load — a bad key file or database. Terminal. */
  loadFailed: boolean;
  /**
   * Registration left a FROST share for this agent.
   *
   * Deliberately NOT a stored "registered" flag. Registration IS the distributed key ceremony, and
   * the share is its durable product — so asking whether the share exists asks whether the thing
   * actually happened, rather than whether someone remembered to record that it had. Before this,
   * every agent on disk was labelled "registered" at load whether or not it ever was, so an agent
   * created and not yet registered was indistinguishable from a working one.
   */
  hasFrostShare: boolean;
  /** The operator deliberately took this agent offline — the kill switch. */
  deliberatelyOffline: boolean;
  /** The agent has been started in this daemon (it is in `onlineAgents`). */
  started: boolean;
  /** This agent's own directory signaling stream is connected. */
  signalingConnected: boolean;
  /** How many live connections are attending this agent right now. */
  attendance: number;
}

/**
 * Decide an agent's state. Pure — no clock, no I/O — so every rung is directly testable.
 */
export function resolveAgentState(i: AgentStateInputs): AgentState {
  // Nothing else is meaningful about an identity that would not load.
  if (i.loadFailed) return "load_failed";

  // Before anything about running: an agent the directory has never heard of cannot be reached by
  // anyone, however healthy it looks locally.
  if (!i.hasFrostShare) return "unregistered";

  // Deliberate outranks incidental. If the operator switched it off, telling them the signaling is
  // also down is noise about something they do not care about right now — and, worse, it would make
  // the kill switch working look like a fault.
  if (i.deliberatelyOffline) return "paused";

  if (!i.started) return "stopped";

  // Started but not yet on the directory. Distinct from `stopped` because the remedy is to wait,
  // not to act.
  if (!i.signalingConnected) return "connecting";

  // Ready either way from here. The only question left is whether anyone is there to answer.
  return i.attendance > 0 ? "online" : "unattended";
}
