/**
 * The agent list from ONE connection's point of view.
 *
 * Per-connection on purpose: which agent a connection has selected changes what it is shown, and
 * collapsing that into a daemon-wide list is how an operator ends up reading another connection's
 * state as their own.
 */
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
  /** M15D: who holds this agent, if anyone — the holder registry's display view. */
  holderFor: (agentName: string) => { label: string; since: string } | null;
}

export function createConnectionAgents(deps: ConnectionAgentsDeps) {
  const { agents, perConnectionState, onlineAgents, sessionNodeManager, agentStateFor, isChannelAgent, holderFor } = deps;

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
           * Every `cello` CLI invocation opens a fresh connection, so it reads `false` for an agent
           * held elsewhere. `holder` says who holds the agent at all, which is the question people
           * were actually asking.
           */
          selected,
          selected_by_this_connection: selected,
          holder: holderFor(a.name),
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
        };
      });
  }

  /**
   * M16 033-CHANNELVIEW: the channels this daemon administers — the complement of the agent list
   * above, drawn from the SAME loaded registry so the two can never disagree about an identity.
   * Name + pubkey only for a healthy channel: it is selected by nobody and driven by its
   * administering agent, so none of the per-agent readiness/selection fields apply. A `load_failed`
   * channel is NOT dropped (reviewer LOW): it would otherwise vanish from every surface — the agent
   * list excludes it as a channel, and this list would exclude it as load_failed. It is listed here
   * with its state, exactly as a broken agent stays visible as broken on the agent surface.
   */
  function getChannelsForConnection(_connectionId: string): ChannelSummary[] {
    return agents
      .filter((a) => isChannelAgent(a.name))
      .map((a) => a.state === "load_failed"
        ? { name: a.name, state: a.state, ...(a.error !== undefined ? { error: a.error } : {}) }
        : { name: a.name, pubkey: a.pubkey });
  }

  return { getAgentsForConnection, getChannelsForConnection };
}
