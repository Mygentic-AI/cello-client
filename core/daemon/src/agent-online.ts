/**
 * "Is this agent online?" for callers that hold the STABLE agent_id. The online sets are keyed by
 * name, so the id is mapped first. Without this the channel collector saw every agent as offline
 * and no subscriber ever fetched a post (029-COLLECTID).
 */
export function createIsAgentOnlineById(deps: {
  onlineAgents: ReadonlySet<string>;
  explicitlyOfflineAgents: ReadonlySet<string>;
  agentNameForId: (agentId: string) => string | null;
}): (agentId: string) => boolean {
  const { onlineAgents, explicitlyOfflineAgents, agentNameForId } = deps;
  return (agentId: string): boolean => {
    // Unknown id → no such agent on this daemon → offline. Never treat it as online.
    const name = agentNameForId(agentId);
    if (name === null) return false;
    return onlineAgents.has(name) && !explicitlyOfflineAgents.has(name);
  };
}
