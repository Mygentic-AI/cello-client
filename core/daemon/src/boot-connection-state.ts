/**
 * Phase 3 of boot: what the daemon remembers per IPC CONNECTION, rather than per agent.
 *
 * Which agent a connection has selected, which agents are online or explicitly offline, and the two
 * read positions — where a connection has read up to in a session, and how far the durable watermark
 * has been advanced on its behalf. A connection is not an agent: several connections can attend one
 * agent at once, and each keeps its own place in the conversation.
 *
 * ONE dependency — the session manager — and nothing late-bound.
 *
 * ⚠️ `forgetConnection` LIVES HERE FOR THE SAME REASON THE MAPS DO. A first cut left the eviction in
 * the composition root, 1,600 lines from the containers it releases, and with it the two comments
 * that say WHY each must die with its connection: the delivery bookmark was once the one
 * per-connection structure that outlived its connection — an unbounded leak on a daemon the CLI
 * reconnects to on every command — and a surviving take ledger made every reconnect look like a
 * theft, because a fresh connection starts at cursor -1 and every take the dead one recorded sits
 * above that bar. A module holding state with no visible release path reads as a leak. This was pure state with a few guards over it, sitting in
 * the middle of the boot sequence because that is where it happened to get written.
 */
import type { SessionNodeManager } from "./session-node-manager.js";

export interface BootConnectionStateDeps {
  sessionNodeManager: SessionNodeManager;
}

export function startBootConnectionState(deps: BootConnectionStateDeps) {
  const { sessionNodeManager } = deps;

  // Per-connection state: tracks which agent is "current" for each IPC connection.
  // Key = connectionId (assigned by IPC server), Value = current agent name or null.
  // `clearedAgent` remembers a selection this connection ONCE made and that was taken away (the agent
  // was stopped or retired). It is what stops resolveCurrentAgent from quietly re-targeting the next
  // call at some other agent that happens to be online — see there.
  const perConnectionState = new Map<string, { currentAgent: string | null; clearedAgent?: string; clientType: string }>();

  // Set of agents currently in "online" state (transitioned via cello_start_agent)
  const onlineAgents = new Set<string>();
  /**
   * M12-P16 (review F1): agents an operator DELIBERATELY took offline.
   *
   * Deliberately NOT `onlineAgents`. That set answers "has this agent been started through
   * cello_start_agent", which is not the same question as "may this agent receive": several
   * legitimate paths serve inbound sessions without ever populating it, so gating the inbound path
   * on it refuses real traffic (proven — it broke 27 tests across 7 suites). This set is empty
   * unless someone actually pressed the switch, so it can only ever refuse what the operator asked
   * to have refused.
   */
  const explicitlyOfflineAgents = new Set<string>();

  // M8C-CURSOR-1: per-connection, per-session read cursor (read-before-write gating).
  // Distinct from message_watermarks (INBOX-1, per-AGENT delivery watermark, persisted) — this is
  // per-CONNECTION, in-memory only, and intentionally dies with the connection (a fresh connection
  // has read nothing yet, so it must catch up before it may send — the WhatsApp-group-chat model
  // for two attended sessions on one agent). Key = connectionId → sessionId → highest sequence this
  // connection has read (or authored). Absent entry = -1 (nothing read yet).
  const connectionCursors = new Map<string, Map<string, number>>();
  function getConnectionCursor(connectionId: string, sessionId: string): number {
    return connectionCursors.get(connectionId)?.get(sessionId) ?? -1;
  }
  function advanceConnectionCursor(connectionId: string, sessionId: string, seq: number): void {
    let byId = connectionCursors.get(connectionId);
    if (!byId) { byId = new Map(); connectionCursors.set(connectionId, byId); }
    const prior = byId.get(sessionId) ?? -1;
    if (seq > prior) byId.set(sessionId, seq); // monotonic — never lowers
  }
  // M8C-CURSOR-1 (cello-unit-reviewer HIGH finding, confirmed by live reproduction): a
  // received-only delivery (cello_get_transcript's received view) must NOT blindly advance the
  // cursor to the max sequence it happened to see — leaf indices are shared and strictly
  // contiguous across BOTH directions (appendSessionLeaf always assigns leafCount, no gaps), so a
  // gap between the connection's actual cursor and that max can hide an unread SENT leaf authored
  // by a DIFFERENT local connection. Advancing past it would silently let this connection send
  // without ever having seen it — defeating the read-before-write guarantee (C4/C5). Only advance
  // through a CONTIGUOUS run of sequence numbers that were actually in this delivery, starting
  // right after the connection's current cursor; stop at the first gap.
  function safeCursorAdvance(connectionId: string, sessionId: string, deliveredSeqs: ReadonlySet<number>): void {
    let cursor = getConnectionCursor(connectionId, sessionId);
    while (deliveredSeqs.has(cursor + 1)) cursor += 1;
    advanceConnectionCursor(connectionId, sessionId, cursor);
  }

  // The per-connection DELIVERY bookmark that lived here is gone (2026-09-13). It started empty on
  // every new connection, so a reconnect re-served the whole conversation. `cello_receive` now reads
  // against the agent's persisted watermark — one bookmark per (agent, session).

  /**
   * DOD-CURSOR-DURABLE-1: the same hole-safe walk, applied to the PERSISTED per-(agent, session)
   * read watermark. Used by cello_get_transcript, whose delivery covers BOTH directions.
   *
   * Walks a CONTIGUOUS run from the agent's current watermark, stopping at the first gap — for the
   * identical reason safeCursorAdvance does: leaf indices are contiguous across both directions, so
   * a gap can hide an unread RECEIVED message (e.g. a row that failed to decrypt is absent from
   * `messages`). Advancing past it would mark unseen counterparty content as read and unblock a
   * send that never saw it — defeating the very guarantee this gate exists to enforce. Monotonic:
   * advanceLastDeliveredSeq takes MAX, so this can never lower a watermark.
   */
  function safeWatermarkAdvance(agentName: string, sessionId: string, deliveredSeqs: ReadonlySet<number>): void {
    let frontier = sessionNodeManager.getLastDeliveredSeq(agentName, sessionId);
    while (deliveredSeqs.has(frontier + 1)) frontier += 1;
    if (frontier >= 0) sessionNodeManager.advanceLastDeliveredSeq(agentName, sessionId, frontier);
  }
  /**
   * Release everything this connection held. The log context is built by the CALLER — the IPC server
   * merges it into its single `daemon.ipc.disconnected` line, and a second line under the same name
   * left neither carrying the whole picture.
   */
  function forgetConnection(connectionId: string): void {
    perConnectionState.delete(connectionId);
    connectionCursors.delete(connectionId); // M8C-CURSOR-1: cursor is connection-scoped, dies with it
  }

  // The two cursor MAPS are not returned — nothing outside reads them directly now that eviction
  // lives here. What escapes is the operations over them.
  return {
    perConnectionState, onlineAgents, explicitlyOfflineAgents, forgetConnection,
    getConnectionCursor, advanceConnectionCursor, safeCursorAdvance,
    safeWatermarkAdvance,
  };
}
