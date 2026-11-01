/**
 * M15D 001-DAEMON — attendance, wired once: the holder registry, the attended/unattended/offline
 * answer a counterparty reads, the `holder` view responses carry, and the request guard.
 *
 * In the composition root's orbit because it needs both halves and neither owns the other: the
 * loaded roster (an agent's stable key) and the operator's explicit offline switch.
 */
import { HolderRegistry } from "./holder-registry.js";
import { createAttendanceGuard } from "./attendance-guard.js";
import type { LoadedAgent } from "./agent-loader.js";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { Logger } from "./types.js";

export interface AttendanceRootDeps {
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  /** Live containers — a copy would freeze the roster at boot. */
  loadedAgents: ReadonlyArray<LoadedAgent>;
  onlineAgents: ReadonlySet<string>;
  explicitlyOfflineAgents: ReadonlySet<string>;
  isChannelAgent: (agentName: string) => boolean;
  perConnectionState: Map<string, { currentAgent: string | null; clearedAgent?: string; clientType?: string }>;
}

export function createAttendanceRoot(deps: AttendanceRootDeps) {
  const { logger, sessionNodeManager, loadedAgents, onlineAgents, explicitlyOfflineAgents, perConnectionState, isChannelAgent } = deps;

  // A counterparty is told the moment an agent becomes reachable or stops being reachable.
  const holderRegistry = new HolderRegistry({
    agentKey: (agentName) => loadedAgents.find((a) => a.name === agentName)?.pubkey,
    onReachability: (agentName, reachable) => {
      if (explicitlyOfflineAgents.has(agentName)) return;
      sessionNodeManager.announceAttendance(agentName, reachable ? "attended" : "unattended");
    },
  });

  /**
   * DOD-M15-AWAYSCOPE-1 — the one answer to "is anyone attending this agent". `offline` is checked
   * FIRST: reporting a deliberately stopped agent as `unattended` tells the counterparty their
   * message will be read later, the opposite of what the switch means.
   */
  const currentAttendance = (agentName: string): "attended" | "unattended" | "offline" =>
    explicitlyOfflineAgents.has(agentName)
      ? "offline"
      : holderRegistry.isReachable(agentName) ? "attended" : "unattended";

  const holderFor = (agentName: string): { label: string; since: string } | null => {
    const h = holderRegistry.holderView(agentName);
    return h ? { label: h.label, since: h.since } : null;
  };

  const { admit } = createAttendanceGuard({
    logger, registry: holderRegistry, onlineAgents,
    getConnState: (connectionId) => perConnectionState.get(connectionId),
    isKnownAgent: (agentName) => loadedAgents.some((a) => a.name === agentName),
    isChannelAgent,
  });

  return { holderRegistry, currentAttendance, holderFor, admit };
}
