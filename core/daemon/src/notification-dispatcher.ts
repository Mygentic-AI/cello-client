/**
 * CELLO Daemon — NotificationDispatcher
 *
 * Owns the routing table for MCP notifications. Applies per-notification-type
 * routing rules:
 *   - agent_state_changed → ALL active IPC connections
 *   - agent_current_changed → triggering connection ONLY
 *   - session_state_changed → connections where affected agent is current
 *
 * Pseudocode (SPARC Phase P):
 *
 * registerConnection(connectionId, socket):
 *   1. Add entry to routing table: { connectionId → { socket, currentAgent: null } }
 *
 * unregisterConnection(connectionId):
 *   1. Remove entry from routing table
 *
 * setCurrentAgent(connectionId, agentName):
 *   1. Update currentAgent for the connection entry
 *
 * dispatchAgentStateChanged(agentName, state, reason):
 *   1. Build notification: { notification: "agent_state_changed", data: { agent, type, agentName, state, reason } }
 *   2. For each connection in routing table: write notification to socket
 *   3. On write error: log notification.dispatch.failed at DEBUG, discard for that connection
 *
 * dispatchAgentCurrentChanged(connectionId, fromAgent, toAgent):
 *   1. Build notification: { notification: "agent_current_changed", data: { agent: toAgent, type, fromAgent, toAgent } }
 *   2. Write to the ONE connection identified by connectionId
 *   3. On write error: log notification.dispatch.failed at DEBUG
 *
 * dispatchSessionStateChanged(agentName, sessionId, state, counterpartyPubkey):
 *   1. Build notification: { notification: "session_state_changed", data: { agent, type, agentName, sessionId, state, counterpartyPubkey } }
 *   2. For each connection where currentAgent === agentName: write notification
 *   3. On write error: log notification.dispatch.failed at DEBUG, discard for that connection
 */

import type { Logger, IpcNotification } from "./types.js";

export type NotificationSender = (connectionId: string, notification: IpcNotification) => boolean;

export interface NotificationDispatcherConfig {
  logger: Logger;
  sendNotification: NotificationSender;
  getConnectionIds: () => string[];
}

export class NotificationDispatcher {
  readonly #logger: Logger;
  readonly #sendNotification: NotificationSender;
  readonly #getConnectionIds: () => string[];
  // Maps connectionId → currentAgent name (null if not set)
  readonly #currentAgentMap = new Map<string, string | null>();

  constructor(config: NotificationDispatcherConfig) {
    this.#logger = config.logger;
    this.#sendNotification = config.sendNotification;
    this.#getConnectionIds = config.getConnectionIds;
  }

  registerConnection(connectionId: string): void {
    this.#currentAgentMap.set(connectionId, null);
  }

  unregisterConnection(connectionId: string): void {
    this.#currentAgentMap.delete(connectionId);
  }

  setCurrentAgent(connectionId: string, agentName: string | null): void {
    if (this.#currentAgentMap.has(connectionId)) {
      this.#currentAgentMap.set(connectionId, agentName);
    }
  }

  /**
   * Broadcast agent_state_changed to ALL active IPC connections.
   * Routing rule: all connections receive this, including those with no current agent.
   */
  dispatchAgentStateChanged(agentName: string, state: "online" | "offline", reason: string): void {
    const notification: IpcNotification = {
      notification: "agent_state_changed",
      data: {
        agent: agentName,
        type: "agent_state_changed",
        agentName,
        state,
        reason,
      },
    };

    for (const connectionId of this.#getConnectionIds()) {
      if (!this.#currentAgentMap.has(connectionId)) continue;
      this.#safeSend(connectionId, notification, "agent_state_changed");
    }
  }

  /**
   * Send agent_current_changed to the triggering connection ONLY.
   * Routing rule: only the connection that called cello_use_agent receives this.
   */
  dispatchAgentCurrentChanged(connectionId: string, fromAgent: string | null, toAgent: string | null): void {
    const notification: IpcNotification = {
      notification: "agent_current_changed",
      data: {
        agent: toAgent,
        type: "agent_current_changed",
        fromAgent,
        toAgent,
      },
    };

    this.#safeSend(connectionId, notification, "agent_current_changed");
  }

  /**
   * Send session_state_changed to connections where the affected agent is current.
   * Routing rule: only connections with currentAgent === agentName receive this.
   */
  dispatchSessionStateChanged(
    agentName: string,
    sessionId: string,
    state: string,
    counterpartyPubkey: string | null,
    // MONIKER-4 AC2: the resolved display label. Optional and additive — legacy call sites
    // omit it and the fields stay off the frame; counterpartyPubkey remains the anchor.
    who?: { who: string; whoKnown: boolean },
  ): void {
    const notification: IpcNotification = {
      notification: "session_state_changed",
      data: {
        agent: agentName,
        type: "session_state_changed",
        agentName,
        sessionId,
        state,
        counterpartyPubkey,
        ...(who !== undefined ? { who: who.who, whoKnown: who.whoKnown } : {}),
      },
    };

    for (const connectionId of this.#getConnectionIds()) {
      const currentAgent = this.#currentAgentMap.get(connectionId);
      if (currentAgent === agentName) {
        this.#safeSend(connectionId, notification, "session_state_changed");
      }
    }
  }

  /**
   * M8C-MSGWAKE-1 (channel stage 2): push a content-free `cello_message` doorbell to connections
   * where the affected agent is current — one per inbound message. Same routing as
   * session_state_changed. The payload carries only type + from (senderPubkey) + session_id; the
   * operator calls cello_receive to fetch content (INV-CONTENTFREE / SI-001 — NO content here).
   */
  dispatchCelloMessage(
    agentName: string,
    sessionId: string,
    from: string,
    // MONIKER-4 AC2: same additive label contract as dispatchSessionStateChanged; `from` anchors.
    who?: { who: string; whoKnown: boolean },
  ): void {
    // DOD-COATTEND-VISIBLE-1 AC2: the arrival alert carries the attendance count. Counted from the
    // SAME map the loop below routes on, so the number is exactly "how many sessions this doorbell
    // is about to wake" — it cannot drift from reality the way a separately-maintained counter could.
    //
    // INV-CONTENTFREE holds: a count of attending sessions is ROUTING metadata. It says nothing
    // about what arrived, who sent it, or how big it is. Anything that identified the content would
    // not be permitted here no matter how useful.
    let attendance = 0;
    for (const current of this.#currentAgentMap.values()) if (current === agentName) attendance += 1;

    const notification: IpcNotification = {
      notification: "cello_message",
      data: {
        agent: agentName,
        type: "cello_message",
        from,
        session_id: sessionId,
        attendance,
        ...(who !== undefined ? { who: who.who, whoKnown: who.whoKnown } : {}),
      },
    };

    for (const connectionId of this.#getConnectionIds()) {
      if (this.#currentAgentMap.get(connectionId) === agentName) {
        this.#safeSend(connectionId, notification, "cello_message");
      }
    }
  }

  #safeSend(connectionId: string, notification: IpcNotification, notificationType: string): void {
    try {
      const success = this.#sendNotification(connectionId, notification);
      if (!success) {
        this.#logger.debug("notification.dispatch.failed", {
          connectionId,
          notificationType,
          error: "sendNotification returned false",
        });
      }
    } catch (err: unknown) {
      this.#logger.debug("notification.dispatch.failed", {
        connectionId,
        notificationType,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }
}
