/**
 * DOD-PARK-DRAIN-1 — what an agent does when its directory signaling reconnects.
 *
 * Two things, IN ORDER: re-register the standing receiver on the fresh stream, then drain the
 * agent's parked mailbox. They used to be two concurrent `void`s, and the drain needs the node the
 * ensure builds (`content-park.ts` → `getStandingReceiverNode`). When the drain won that race it
 * failed `standing_receiver_unavailable` — 102 times in the 2026-08-04 incident log, against 84
 * relay failures and drains reporting `recovered: 0, failedRelays: 1`. The agent-start path already
 * chained ensure→drain correctly; this is the reconnect path catching up.
 *
 * Lives in its own module because the ordering IS the contract, and a contract that only exists
 * inside a 3,000-line composition root is one refactor away from being two `void`s again.
 */
import { extractErrorMessage } from "./session-relay-client.js";
import type { Logger } from "./types.js";

export interface ReconnectDrainDeps {
  logger: Logger;
  /** Only an ONLINE agent may acquire a receiver — a started-then-stopped agent must stay dark. */
  isAgentOnline: (agentName: string) => boolean;
  ensureStandingReceiver: (agentName: string) => Promise<void>;
  drainParked: (agentName: string) => Promise<void>;
}

/**
 * Build the `onConnected` callback for an agent's SignalingManager. Fire-and-forget by contract —
 * the signaling manager gets no promise to await — so every failure is logged here, under the name
 * of the stage that produced it.
 */
export function createReconnectDrain(deps: ReconnectDrainDeps): (agentName: string) => void {
  const { logger, isAgentOnline, ensureStandingReceiver, drainParked } = deps;
  return (agentName: string): void => {
    // Fires on the FIRST connect too, and an agent that was never started must not acquire a
    // receiver here. Re-entry at start is harmless — the ensure returns immediately when a receiver
    // exists or is being created.
    if (!isAgentOnline(agentName)) return;
    void ensureStandingReceiver(agentName)
      .then(
        () => drainParked(agentName).catch((err: unknown) => {
          logger.warn("content.recover.auto.failed", { agentName, error: extractErrorMessage(err) });
        }),
        (err: unknown) => {
          // The ensure failed, so there is no node for a pull to originate from. Report the
          // receiver failure — a drain attempted here would only add a second, misleading
          // `standing_receiver_unavailable` on top of the real cause.
          logger.warn("session.standing_receiver.reregister.failed", { agentName, error: extractErrorMessage(err) });
        },
      );
  };
}
