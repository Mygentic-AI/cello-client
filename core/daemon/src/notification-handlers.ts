/**
 * cello_check_notifications — the push-loss reconciler.
 *
 * Notifications are fire-and-forget: no ack, no redelivery. That is a deliberate trade (a delivery
 * guarantee on a doorbell is not worth the machinery), but it means a client that was away can miss
 * one entirely. This is how it finds out what it missed — by ASKING, from persisted state, rather
 * than by trusting that a push arrived.
 *
 * Which is why it is poll-only and reads the store: a reconciler that depended on the same channel
 * it exists to backstop would be no reconciler at all.
 */
import type { IpcHandler } from "./ipc-server.js";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { Logger } from "./types.js";
import type { ConnState } from "./contact-handlers.js";

export interface NotificationHandlerDeps {
  handlers: Map<string, IpcHandler>;
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  getConnState: (connectionId: string) => ConnState | undefined;
  resolveCurrentAgent: (connState: ConnState | undefined, explicitAgent?: string) => string | null;
  loadedAgents: ReadonlyArray<{ name: string; pubkey: string }>;
  reapExpiredInboundSessions: (agentName: string) => void;
  inboundSessionQueues: Map<string, Array<{ sessionId: string; counterpartyPubkeyHex: string; [k: string]: unknown }>>;
  expiredSessionRequests: Map<string, Array<{ sessionId: string; [k: string]: unknown }>>;
}

export function registerNotificationHandlers(deps: NotificationHandlerDeps): void {
  const {
    handlers, logger, sessionNodeManager, getConnState, resolveCurrentAgent,
    loadedAgents, reapExpiredInboundSessions, inboundSessionQueues, expiredSessionRequests,
  } = deps;

  // ─── M8C-INBOX-1 (N1/N4): cello_check_notifications — push-loss reconciler + poll-only inbox ───
  // Notifications are fire-and-forget (no ack, no redelivery); this is how a client discovers what
  // it missed while its shim was down/busy, and the primary inbox for poll-only clients (Bedrock,
  // cron). Content-free: pending session requests (from the in-memory queue, READ non-destructively —
  // cello_await_session owns draining) + unread message counts (derived from the persisted read
  // watermark, N2). No separate notification store; no ack verb (N4).
  handlers.set("cello_check_notifications", async (params, connectionId) => {
    const connState = getConnState(connectionId);
    const scope = params?.scope === "all" ? "all" : "current";

    let agentNames: string[];
    if (scope === "all") {
      agentNames = loadedAgents.map((a) => a.name);
    } else {
      // F18: an explicit current agent, else the sole-online agent; ambiguous → no_current_agent.
      const current = resolveCurrentAgent(connState);
      if (!current) {
        return {
          ok: false,
          reason: "no_current_agent",
          guidance: "No current agent for this connection. Call cello_use_agent to select one, or use scope:\"all\" to check every loaded agent.",
        };
      }
      agentNames = [current];
    }

    const agents = agentNames.map((agent) => {
      reapExpiredInboundSessions(agent); // M8C-TTL-1: expired ones surface below, not as "pending"
      const pending = (inboundSessionQueues.get(agent) ?? []).map((e) => ({
        session_id: e.sessionIdHex,
        from: e.counterpartyPubkeyHex,
      }));
      // M8C-TTL-1: expired requests stay VISIBLE (not silently dropped) — the operator can see
      // what they missed rather than a request just vanishing from the pending list.
      const expired = (expiredSessionRequests.get(agent) ?? []).map((e) => ({
        session_id: e.sessionIdHex,
        from: e.counterpartyPubkeyHex,
        expired_at: e.expiredAt,
      }));
      const unread = sessionNodeManager.getUnreadSummary(agent);
      const total_unread = unread.reduce((sum, u) => sum + u.unread_count, 0);
      // DOD-RENAME-1 AC3: pending rename notices surface HERE (the INBOX pull), never as a real-time
      // push. The offered name is rendered as an untrusted CLAIM (quoted, with the pubkey) plus the
      // command to adopt it — the daemon never auto-applies a self-declared name.
      const rename_notices = sessionNodeManager.getRenameNotices(agent).map((n) => ({
        pubkey: n.pubkey,
        your_name_for_them: n.moniker,
        claimed_name: n.offered_name,
        noticed_at: n.noticed_at,
        // Names the contact by the operator's OWN pet name (AC3); the self-declared name is a quoted,
        // untrusted claim; the adopt command carries its arguments so it is copy-pasteable.
        // The MCP call form below is translated WHOLE (arguments and all) for a CLI caller by
        // vocabulary.ts's CALL_FORMS — rewriting only the tool name would leave the tool's JSON
        // bolted onto a CLI verb, which looks like a command and is not one. `claimed_name` above
        // carries the peer's self-declared name UNTOUCHED, so the operator always has the raw value
        // even though the prose copy passes through the renderer.
        notice:
          `Your contact ${n.moniker !== null ? `"${n.moniker}" ` : ""}(${n.pubkey.slice(0, 16)}…) now calls themselves ` +
          `"${n.offered_name}" (self-declared — unverified). Adopt it: cello_contact_set_moniker ` +
          `{ pubkey: "${n.pubkey}", moniker: "${n.offered_name}" }, or ignore.`,
      }));
      return { agent, pending_session_requests: pending, expired_session_requests: expired, unread, total_unread, rename_notices };
    });

    const totalUnread = agents.reduce((sum, a) => sum + a.total_unread, 0);
    const totalPending = agents.reduce((sum, a) => sum + a.pending_session_requests.length, 0);
    // M8C-TTL-1 (reviewer finding, D19): surface expired-log size so unbounded growth (were the
    // cap ever removed or misconfigured) would be visible here, not just in an internal Map.
    const totalExpired = agents.reduce((sum, a) => sum + a.expired_session_requests.length, 0);
    logger.info("inbox.checked", { connectionId, scope, agentCount: agents.length, totalUnread, totalPending, totalExpired });
    return { ok: true, scope, agents };
  });
}
