/**
 * M16 033-CHANNELVIEW — the agents/channels partition in `createConnectionAgents`.
 *
 * This is the pure factory behind `cello_status.agents` / `cello_status.channels`. The daemon-wide
 * `cello status` (daemon-status-report.ts) applies the same partition; both are covered here at the
 * level the logic lives, so a load_failed channel — an identity whose seed would not open — cannot
 * fall out of BOTH lists and vanish from every surface.
 */
import { describe, it, expect } from "vitest";
import { createConnectionAgents } from "../connection-agents.js";
import type { AgentInfo, AgentState } from "../types.js";
import type { SessionNodeManager } from "../session-node-manager.js";

// A SessionNodeManager stub exposing only what getAgentsForConnection reads.
const snmStub = {
  getStandingReceiverReady: () => true,
  getStandingReceiverReachability: () => "ready" as const,
  getStandingReceiverRefusal: () => undefined,
} as unknown as SessionNodeManager;

function build(agents: AgentInfo[], channels: Set<string>) {
  return createConnectionAgents({
    agents,
    perConnectionState: new Map(),
    onlineAgents: new Set(),
    sessionNodeManager: snmStub,
    agentStateFor: (a: AgentInfo): AgentState => a.state,
    isChannelAgent: (name: string) => channels.has(name),
  });
}

describe("M16 033-CHANNELVIEW: createConnectionAgents partitions agents from channels", () => {
  it("a healthy channel is under channels (name + pubkey), never under agents", () => {
    const { getAgentsForConnection, getChannelsForConnection } = build(
      [
        { name: "realagent", state: "online", pubkey: "aa".repeat(32) },
        { name: "chan", state: "online", pubkey: "cc".repeat(32) },
      ],
      new Set(["chan"]),
    );
    expect(getAgentsForConnection("c1").map((a) => a.name)).toEqual(["realagent"]);
    const chans = getChannelsForConnection("c1");
    expect(chans.map((c) => c.name)).toEqual(["chan"]);
    expect(chans[0]!.pubkey).toBe("cc".repeat(32));
  });

  // Reviewer LOW: a load_failed CHANNEL used to be dropped from both lists — the load_failed filter
  // removed it from channels, and the isChannelAgent filter removed it from agents. It must appear
  // under channels WITH its state, exactly as a load_failed agent is listed with its state.
  it("a load_failed channel is listed under channels WITH state load_failed, and not under agents", () => {
    const { getAgentsForConnection, getChannelsForConnection } = build(
      [
        { name: "realagent", state: "online", pubkey: "aa".repeat(32) },
        { name: "brokenchan", state: "load_failed", error: "corrupt seed" },
      ],
      new Set(["brokenchan"]),
    );
    // Not under agents.
    expect(getAgentsForConnection("c1").map((a) => a.name)).toEqual(["realagent"]);
    // Under channels, visible as broken.
    const chans = getChannelsForConnection("c1");
    expect(chans.map((c) => c.name)).toEqual(["brokenchan"]);
    expect(chans[0]!.state).toBe("load_failed");
  });
});
