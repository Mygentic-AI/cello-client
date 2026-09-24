/**
 * The agent list from ONE connection's point of view.
 *
 * Per-connection on purpose: which agent a connection has selected changes what it is shown, and
 * collapsing that into a daemon-wide list is how an operator ends up reading another connection's
 * state as their own.
 */
import { countAttendance } from "./co-attendance.js";
import type { AgentInfo, AgentState, ChannelSummary } from "./types.js";
import type { SessionNodeManager } from "./session-node-manager.js";

export interface ConnectionAgentsDeps {
  /** Live containers — copies would report a stale roster and a stale online set forever. */
  agents: ReadonlyArray<AgentInfo>;
  perConnectionState: ReadonlyMap<string, { currentAgent: string | null }>;
  onlineAgents: ReadonlySet<string>;
  sessionNodeManager: SessionNodeManager;
  agentStateFor: (a: AgentInfo) => AgentState;
  /**
   * M16 033-CHANNELVIEW: is this identity a broadcast channel? Reads the DB row live (a channel
   * registered after boot is honoured with no restart), so it partitions the same loaded registry
   * into agents and channels — no separate state, no separate list to fall out of sync.
   */
  isChannelAgent: (agentName: string) => boolean;
}

export function createConnectionAgents(deps: ConnectionAgentsDeps) {
  const { agents, perConnectionState, onlineAgents, sessionNodeManager, agentStateFor, isChannelAgent } = deps;

  // Build agent list from this connection's perspective
  function getAgentsForConnection(connectionId: string): AgentInfo[] {
    const connState = perConnectionState.get(connectionId);
    const currentAgent = connState?.currentAgent ?? null;

    return agents
      .filter((a) => a.state !== "load_failed")
      // M16 033-CHANNELVIEW: channels are NOT agents. They stay loaded and online, but no agent
      // surface (cello_status, cello_agents) may list one — an operator was reading test-open and
      // proof024b as agents. They are listed instead by getChannelsForConnection below.
      .filter((a) => !isChannelAgent(a.name))
      .map((a) => {
        // `state` reports READINESS only; selection is a SEPARATE `selected` flag. Never fold
        // selection into `state` — a selected agent is not at a different level of readiness than a
        // second healthy online agent. (This is why `current` was dropped from the enum.)
        const state = agentStateFor(a);
        const selected = onlineAgents.has(a.name) && a.name === currentAgent;
        return {
          name: a.name,
          state,
          /**
           * `selected` IS THIS CONNECTION'S VIEW, NOT THE AGENT'S — `DOD-M15-IPCVISIBLE-1` clause 3.
           *
           * Every `cello` CLI invocation opens a FRESH connection, which starts with no current
           * agent. So a client asking about its own state through the CLI always reads `false`, for
           * an agent it genuinely has selected in another session. Both Andre and a Hermes agent
           * misread it that way during one investigation, in opposite directions.
           *
           * The field name cannot be changed without breaking every reader, so it is ANNOTATED: the
           * sibling below says whose view this is, and `attended_by` says how many connections hold
           * this agent at all — which is the question people were actually asking.
           */
          selected,
          selected_by_this_connection: selected,
          attended_by: countAttendance(perConnectionState, a.name),
          pubkey: a.pubkey,
          // M8B F14 (fix 5): per-agent standing-receiver readiness on the MCP surface
          // (cello_status / cello_list_agents), so a deaf agent is visible to the operator.
          standing_receiver_ready: sessionNodeManager.getStandingReceiverReady(a.name),
          standing_receiver_reachability: sessionNodeManager.getStandingReceiverReachability(a.name),
          /**
           * DOD-M15-RELAYSLOTS-1: WHY it is not reachable, and what to do about it.
           *
           * `standing_receiver_reachability` says `retrying` or `unreachable` and stops there, which
           * for the person reading it is indistinguishable from the product being broken. The relay
           * now refuses for reasons someone can act on — no token from a directory yet, too many
           * sessions still open, this relay is misconfigured — each with a different next step, and
           * every one of them is wasted if it only reaches a log file. Absent when the last attempt
           * succeeded.
           */
          ...(sessionNodeManager.getStandingReceiverRefusal(a.name)
            ? { standing_receiver_refusal: sessionNodeManager.getStandingReceiverRefusal(a.name) }
            : {}),
          // DOD-COATTEND-VISIBLE-1 AC2: how many sessions are driving this agent, including this
          // one. Live, not a high-water mark — it drops when a session disconnects. `selected` says
          // whether YOU hold it; this says whether anyone else does too.
          attendance: countAttendance(perConnectionState, a.name),
        };
      });
  }

  /**
   * M16 033-CHANNELVIEW: the channels this daemon administers — the complement of the agent list
   * above, drawn from the SAME loaded registry so the two can never disagree about an identity.
   * Name + pubkey only: a channel is selected by nobody and driven by its administering agent, so
   * none of the per-agent readiness/selection fields apply. A load-failed identity is omitted from
   * both lists, exactly as the agent surface omits it.
   */
  function getChannelsForConnection(_connectionId: string): ChannelSummary[] {
    return agents
      .filter((a) => a.state !== "load_failed")
      .filter((a) => isChannelAgent(a.name))
      .map((a) => ({ name: a.name, pubkey: a.pubkey }));
  }

  return { getAgentsForConnection, getChannelsForConnection };
}
