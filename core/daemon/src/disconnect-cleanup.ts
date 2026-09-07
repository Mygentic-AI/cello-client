/**
 * What the daemon forgets, and what it says, when an IPC connection closes.
 *
 * `daemon.ipc.connected` fired on every open and nothing on close, so a live client and a dead one
 * that was never cleaned up looked identical in the log. The attended agent is the field that
 * matters: attendance dropping was silent, and an agent losing its last attendee changes whether
 * away-messages fire and who receives doorbells — so a session that stopped waking is diagnosable
 * from the log rather than by guesswork.
 *
 * The three per-connection maps are released by the module that owns them; this is the reporting
 * half, and it returns its context rather than logging its own line, because the IPC server merges
 * it into the single `daemon.ipc.disconnected` entry. A second line under the same name left
 * neither carrying the whole picture and doubled every count.
 */
import type { IpcServer } from "./ipc-server.js";
import type { NotificationDispatcher } from "./notification-dispatcher.js";
import type { InboundSessionWaiter } from "./inbound-sessions.js";

export interface DisconnectCleanupDeps {
  ipcServer: IpcServer;
  /** Read this connection's selection before it is forgotten — the log needs what it was attending. */
  getConnState: (connectionId: string) => { currentAgent: string | null; clientType?: string } | undefined;
  /** How many connections still attend an agent, after this one goes. */
  countAttendanceFor: (agentName: string) => number;
  /** Releases the three per-connection maps. Lives with the maps, not here. */
  forgetConnection: (connectionId: string) => void;
  forgetTakeLedger: (connectionId: string) => void;
  /** Callers blocked in `cello_await_session` for an agent, so a dying connection releases them. */
  inboundSessionWaiters: Map<string, InboundSessionWaiter[]>;
  /**
   * ⚠️ A GETTER. The dispatcher is constructed BELOW this wiring and a disconnect can only happen
   * after the socket opens, which is later still.
   */
  getNotificationDispatcher: () => NotificationDispatcher;
}

export function wireDisconnectCleanup(deps: DisconnectCleanupDeps): void {
  const {
    ipcServer, getConnState, countAttendanceFor, forgetConnection, forgetTakeLedger,
    inboundSessionWaiters,
    getNotificationDispatcher,
  } = deps;

  // MCP-001: Clean up per-connection state when a connection disconnects
  // MCP-002: Also unregister from notification dispatcher
  ipcServer.onDisconnect((connectionId) => {
    /**
     * DOD-M15-IPCVISIBLE-1: SAY THAT IT CLOSED, and say what it was attending.
     *
     * `daemon.ipc.connected` fired on every open and nothing on close, so a live client and a dead
     * one that was never cleaned up looked identical in the log. The attended agent is the field
     * that matters: attendance dropping was silent, and an agent losing its last attendee changes
     * whether away-messages fire and who receives doorbells — so a session that stopped waking is
     * diagnosable from the log rather than by guesswork.
     */
    const closing = getConnState(connectionId);
    const stillAttending = closing?.currentAgent
      ? countAttendanceFor(closing.currentAgent) - 1
      : null;
    // RETURNED, not logged here — `ipcServer` merges this into its single
    // `daemon.ipc.disconnected` line. A second line under the same name left neither carrying the
    // whole picture and doubled every count (review F8).
    const disconnectContext: Record<string, unknown> = {
      clientType: closing?.clientType ?? "unknown",
      attendedAgent: closing?.currentAgent ?? null,
      ...(stillAttending !== null ? { remainingAttendance: stillAttending } : {}),
      ...(stillAttending === 0
        ? {
            impact:
              "that agent has no attending session left — inbound sessions are now answered with " +
              "its away message rather than a live reply, and its doorbells reach nobody",
          }
        : {}),
    };
    // The three per-connection maps are released by the module that owns them; the reasons each
    // must die with its connection live there, beside the containers.
    forgetConnection(connectionId);
    // DOD-COATTEND-VISIBLE-1 (review HIGH): the take ledger is connection-scoped for the SAME
    // reason and must die with the connection too. Leaving it behind made every reconnect look
    // like a theft: a fresh connection starts at cursor -1, so every take a now-dead connection
    // ever recorded sits above that bar and was reported as "another session took it" — on the
    // `cello` CLI, which opens a fresh connection per command, that fired on ordinary use, forever,
    // with no live sibling anywhere. A signal that fires on the normal case is not a signal, and
    // this one would have taught the operator to disbelieve the real theft it exists to announce.
    forgetTakeLedger(connectionId);
    getNotificationDispatcher().unregisterConnection(connectionId);
    // Seam 2 (review H2): evict any cello_await_session waiters owned by this connection.
    // Otherwise enqueueInboundSession would hand the next inbound session to a closed
    // connection's waiter and the event would be lost. deliver(null) clears the waiter's
    // timer and resolves its (now-orphaned) promise as a timeout.
    for (const [agentName, waiters] of inboundSessionWaiters) {
      const survivors: typeof waiters = [];
      for (const w of waiters) {
        if (w.connectionId === connectionId) w.deliver(null);
        else survivors.push(w);
      }
      if (survivors.length > 0) inboundSessionWaiters.set(agentName, survivors);
      else inboundSessionWaiters.delete(agentName);
    }
    return disconnectContext;
  });
}
