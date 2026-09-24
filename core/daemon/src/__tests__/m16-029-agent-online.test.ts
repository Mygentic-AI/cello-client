/**
 * M16 029-COLLECTID — "is this agent online?" asked with the STABLE agent_id.
 *
 * The channel collector holds a subscription's `agent_id` and asks whether that agent is online. The
 * online sets (`onlineAgents`, `explicitlyOfflineAgents`) are keyed by NAME, so the id must be mapped
 * to a name first. Without that map every lookup missed and every subscriber looked offline forever —
 * no wake and no backstop ever fetched a post. `createIsAgentOnlineById` closes the join at the
 * boundary, keeping the collector on the stable key and the sets on the name.
 *
 * The ids and names are deliberately DIFFERENT ("id-7f3a" ↔ "alice"), so a test cannot pass by the
 * two happening to be equal — which is the exact accident that hid the defect.
 */
import { describe, it, expect } from "vitest";
import { createIsAgentOnlineById } from "../agent-online.js";

const ID = "id-7f3a";
const NAME = "alice";
const nameForId = (agentId: string): string | null => (agentId === ID ? NAME : null);

describe("M16 029 — createIsAgentOnlineById maps id → name before the online lookup", () => {
  it("1. an online agent is online when asked by id", () => {
    const isOnline = createIsAgentOnlineById({
      onlineAgents: new Set([NAME]),
      explicitlyOfflineAgents: new Set<string>(),
      agentNameForId: nameForId,
    });
    expect(isOnline(ID)).toBe(true);
  });

  it("2. the OLD lookup is what failed — has(id) is false because the set is keyed by name (green before and after)", () => {
    /**
     * This documents the defect that shipped: `onlineAgents.has(agentId)`. The set holds the name,
     * the collector passes the id, and the two never match — so every subscriber read as offline.
     */
    const onlineAgents = new Set([NAME]);
    expect(onlineAgents.has(ID)).toBe(false);
  });

  it("3. an explicitly offline agent is offline — the kill switch still holds through the id map", () => {
    const isOnline = createIsAgentOnlineById({
      onlineAgents: new Set([NAME]),
      explicitlyOfflineAgents: new Set([NAME]),
      agentNameForId: nameForId,
    });
    expect(isOnline(ID)).toBe(false);
  });

  it("4. an unknown id is offline — no such agent on this daemon, so do not collect", () => {
    const isOnline = createIsAgentOnlineById({
      onlineAgents: new Set([NAME]),
      explicitlyOfflineAgents: new Set<string>(),
      agentNameForId: () => null,
    });
    expect(isOnline("id-nobody")).toBe(false);
  });
});
