/**
 * DOD-PARK-DRAIN-1 — what an agent does when its directory signaling reconnects.
 *
 * Two things, and the ORDER is the contract: re-register the standing receiver on the fresh
 * stream, then drain the agent's parked mailbox. They used to be two concurrent `void`s, and the
 * drain needs the node the ensure builds (`content-park.ts` → `getStandingReceiverNode`). When the
 * drain won that race it failed `standing_receiver_unavailable` — 102 times in the 2026-08-04
 * incident log, against 84 relay failures and drains reporting `recovered: 0, failedRelays: 1`.
 * The agent-start path already chained ensure→drain correctly; this is the reconnect path
 * catching up.
 *
 * THE DRAIN IS UNCONDITIONAL; only the ENSURE is gated on the agent being online. That asymmetry
 * is deliberate: production opens a directory connection for every LOADED agent at startup,
 * started or not, and each of those connects drained that agent's mailbox before this module
 * existed. The pull is keyed by the agent's pubkey and dials from ANY ready standing receiver, so
 * it works for an agent that has none of its own — whereas giving a receiver to an agent nobody
 * started would accept inbound sessions on its behalf.
 *
 * Lives in its own module because the ordering IS the contract, and a contract that only exists
 * inside a 3,000-line composition root is one refactor away from being two `void`s again.
 */
import { extractErrorMessage } from "./error-message.js";
import type { Logger } from "./types.js";

export interface ReconnectDrainDeps {
  logger: Logger;
  /** Only an ONLINE agent may acquire a receiver — a started-then-stopped agent must stay dark. */
  isAgentOnline: (agentName: string) => boolean;
  ensureStandingReceiver: (agentName: string) => Promise<void>;
  drainParked: (agentName: string) => Promise<void>;
  /**
   * M12-P12: the SENDER half. `drainParked` pulls what OTHERS parked for this agent; this re-parks
   * what THIS agent failed to deposit. Both are stranded by the same relay churn, so both belong on
   * the same reconnect — draining only the inbound half leaves the outbound message lost.
   * Optional so existing callers/tests keep compiling; absent means sender re-park is skipped.
   */
  flushSender?: (agentName: string) => Promise<void>;
}

/**
 * Build the `onConnected` callback for an agent's SignalingManager. Fire-and-forget by contract —
 * the signaling manager gets no promise to await — so every failure is logged here, under the name
 * of the stage that produced it.
 */
export function createReconnectDrain(deps: ReconnectDrainDeps): (agentName: string) => void {
  const { logger, isAgentOnline, ensureStandingReceiver, drainParked, flushSender } = deps;

  const drain = (agentName: string): Promise<void> => {
    // Sender re-park first: it needs the receiver the ensure step just rebuilt, and a failure here
    // must not cost the inbound pull — hence its own catch rather than a shared chain.
    // Wrapped rather than `flushSender(agentName).catch(...)`: a dep that throws SYNCHRONOUSLY would
    // otherwise propagate out of drain() and take the inbound pull with it — the exact coupling the
    // separate catch exists to prevent.
    if (flushSender) {
      void Promise.resolve()
        .then(() => flushSender(agentName))
        .catch((err: unknown) => {
          logger.warn("content.park.flush.failed", { agentName, stage: "reconnect", error: extractErrorMessage(err) });
        });
    }
    return drainParked(agentName).catch((err: unknown) => {
      logger.warn("content.recover.auto.failed", { agentName, stage: "reconnect", error: extractErrorMessage(err) });
    });
  };

  return (agentName: string): void => {
    // The ensure fires on the FIRST connect too, and an agent that was never started must not
    // acquire a receiver here. Re-entry at start is harmless — the ensure returns immediately when
    // a receiver exists or is being created.
    if (!isAgentOnline(agentName)) {
      void drain(agentName);
      return;
    }
    void ensureStandingReceiver(agentName).then(
      () => drain(agentName),
      (err: unknown) => {
        logger.warn("session.standing_receiver.reregister.failed", { agentName, error: extractErrorMessage(err) });
        // Drain anyway. A failed ensure does not mean the pull has nowhere to run from: the
        // content park dials from ANY ready standing receiver — two agents on one daemon is a
        // supported configuration (DOD-LOOP-1) — and the mailbox is keyed by this agent's pubkey.
        // Skipping here would strand content for a reason that only holds on a single-agent daemon.
        return drain(agentName);
      },
    );
  };
}
