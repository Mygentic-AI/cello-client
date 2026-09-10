/**
 * 048-SWEEPTICK — running the collection sweep while the daemon is up, not only when it reconnects.
 *
 * ─── THE DEFECT THIS CLOSES ────────────────────────────────────────────────────────────────────
 *
 * 043-SIGNALDELIVERY C2 built `createTrustSignalSweep` and wired it to `onConnected` and to nothing
 * else. So collection happened once per CONNECTION. A daemon that connects in the morning and stays
 * up never swept again that day, whatever was delivered to the other nodes in the meantime — and
 * `pickup_queue` does not replicate, so nothing else was ever going to bring those signals over.
 *
 * Measured: an endorsement sat 23 minutes at a node this daemon was not attached to, on a fleet
 * with nothing wrong with it, and arrived the instant the daemon was restarted. The whole fleet
 * reported healthy throughout, which is the part that makes it expensive to find.
 *
 * C2's own order said *"trigger on stream auth, never on login"*, and that was the right correction
 * to what it was fixing — a login-time trigger misses a reconnect after a closed laptop. It was not
 * sufficient on its own, and neither the order's assertions nor its review caught that, because both
 * were checking the trigger that WAS specified. **A specification that names a mechanism tends to
 * scope its own review to that mechanism.**
 *
 * ─── WHY THIS IS A WRAPPER AND NOT A CHANGE TO THE SWEEP ───────────────────────────────────────
 *
 * `onConnected` KEEPS its trigger. A daemon back from a closed laptop should collect immediately
 * rather than wait out an interval, so this adds a second trigger rather than moving the first —
 * `sweepAndTick` sweeps now AND arms the tick, and drops into the existing call site unchanged.
 *
 * Overlap is deliberately NOT handled here. `createTrustSignalSweep` already holds a per-agent
 * in-flight set (C2 review, finding 4) and a tick that lands mid-sweep is turned away by it. A
 * second guard would pass its own tests while leaving the real one unexercised, and two guards for
 * one property is how they drift.
 *
 * ─── ONLINE IS CHECKED PER TICK, AND THE TICK DOES NOT STOP ITSELF ─────────────────────────────
 *
 * The order asks for the tick to stop when the agent goes offline. It is implemented as a check per
 * tick instead, and the difference is worth stating because it looks weaker and is not.
 *
 * What the order is protecting is the round trips: sweeping for an offline agent is a visiting
 * connection to every node for somebody who is not listening, and the check prevents every one of
 * them. What it cannot be implemented as is self-cancellation on the first offline tick, because
 * **coming back online does not necessarily fire `onConnected` again** — `cello_set_agent_offline`
 * leaves the signaling manager connected, so a later `cello_start_agent` finds the cached manager
 * and no connect event occurs. A tick that cancelled itself would therefore never restart, and the
 * agent would silently return to the exact behaviour this unit exists to remove. That failure would
 * be invisible: collection would work, then quietly stop, with nothing in the log to say so.
 *
 * The timer is genuinely cleared by `stop`/`stopAll`, which is what the agent's signaling teardown
 * and daemon shutdown call.
 */
import type { KeyProvider } from "@cello-protocol/crypto";
import type { Logger } from "./types.js";
import type { TrustSignalSweep } from "./trust-signal-sweep.js";
import { extractErrorMessage } from "./error-message.js";

/**
 * How often a connected, online agent re-sweeps the other nodes.
 *
 * FIVE MINUTES, and the trade is real in both directions. Each tick opens an authenticated visiting
 * connection to every OTHER node in the fleet and triggers that node's drain, so the cost scales
 * with fleet size and agent count — too frequent is load on every directory for nothing. Too rare
 * and this defect survives in a slower form: the worst case for a signal is one whole interval, and
 * the thing being fixed is a 23-minute wait.
 *
 * Five minutes puts the worst case an order of magnitude under what was observed while keeping the
 * steady-state cost at a handful of connections an hour per agent. Move it knowingly.
 */
export const SWEEP_TICK_INTERVAL_MS = 5 * 60_000;

export interface TrustSignalSweepTickerDeps {
  logger: Logger;
  /** The C2 sweep, unmodified. Its in-flight guard is what makes overlap safe. */
  sweep: TrustSignalSweep;
  /**
   * Whether this agent is ONLINE — started through `cello_start_agent` and not switched off.
   *
   * Not "is its signaling connected": an agent taken offline by the kill switch keeps its signaling
   * manager, and collecting trust signals for an agent the operator switched off is the kill switch
   * failing to switch something off.
   */
  isAgentOnline: (agentName: string) => boolean;
  /** Overridable for tests only; production uses SWEEP_TICK_INTERVAL_MS. */
  intervalMs?: number;
}

export interface TrustSignalSweepTicker {
  /**
   * Sweep NOW and arm the periodic tick for this agent. Idempotent per agent — a flapping stream
   * fires the connect trigger repeatedly and must not stack intervals.
   *
   * Same signature as `TrustSignalSweep`, so it substitutes at the existing call site.
   */
  sweepAndTick: TrustSignalSweep;
  /** End one agent's tick. */
  stop: (agentName: string) => void;
  /** End every tick — daemon shutdown. */
  stopAll: () => void;
}

export function createTrustSignalSweepTicker(deps: TrustSignalSweepTickerDeps): TrustSignalSweepTicker {
  const { logger, sweep, isAgentOnline } = deps;
  const intervalMs = deps.intervalMs ?? SWEEP_TICK_INTERVAL_MS;
  const timers = new Map<string, NodeJS.Timeout>();

  function arm(
    agentName: string,
    agentKeyProvider: KeyProvider,
    agentPubkeyHex: string,
    homeNodeId: string | undefined,
  ): void {
    if (timers.has(agentName)) return;
    // Whether the PREVIOUS tick skipped, so the skip line marks a transition rather than repeating.
    let wasSkipping = false;
    const timer = setInterval(() => {
      if (!isAgentOnline(agentName)) {
        // ONCE PER OFFLINE STRETCH, not once per tick. An operator asking why a signal has not
        // arrived needs to see that we deliberately did not look — they need it once. Review
        // measured the alternative: the tick is armed for EVERY loaded agent at boot, online or
        // not, so an operator running one of four agents would get three timers writing this line
        // every five minutes forever — 864 lines a day stating that the system is working as
        // designed. `daemon.log` reaching 176 MB of one condition talking to itself is a defect
        // this milestone already has an order open for; adding a second source of it while fixing
        // a different bug is not a trade worth making.
        if (!wasSkipping) {
          logger.info("trust_signal.sweep.tick_skipped", { agentName, reason: "agent_offline" });
          wasSkipping = true;
        }
        return;
      }
      if (wasSkipping) {
        logger.info("trust_signal.sweep.tick_resumed", { agentName });
        wasSkipping = false;
      }
      // Never awaited — nothing here is on a path an operator waits on. The catch LOGS, because a
      // background sweep that fails in silence is how the original defect survived for weeks.
      //
      // Failure must not end the tick. This is the only thing running collection for a long-lived
      // daemon, so a swallowed-and-stopped tick would put the agent back to reconnect-only
      // collection after appearing to work — a worse version of the bug, because it starts healthy.
      // homeNodeId CAPTURED, not dropped. Nothing supplies it today — `signaling-wiring.ts` types
      // the getter as three arguments — so this is inert. It is here because skipping the node whose
      // drain already ran is the obvious next optimisation on this exact path, and the moment
      // someone wires it the connect sweep would skip home while every tick visited it, with
      // nothing asserting the divergence.
      void sweep(agentName, agentKeyProvider, agentPubkeyHex, homeNodeId, "tick").catch((err: unknown) => {
        logger.warn("trust_signal.sweep.tick_failed", { agentName, reason: extractErrorMessage(err) });
      });
    }, intervalMs);
    // Do not hold the daemon open for up to a whole interval after everything else has shut down.
    timer.unref?.();
    timers.set(agentName, timer);
    logger.info("trust_signal.sweep.tick_armed", { agentName, intervalMs });
  }

  return {
    sweepAndTick: (agentName, agentKeyProvider, agentPubkeyHex, homeNodeId) => {
      arm(agentName, agentKeyProvider, agentPubkeyHex, homeNodeId);
      // "connect", explicitly. This is the `onConnected` path and its log line has to say so, or the
      // tick's line cannot be told apart from it — which is exactly why this unit was unverifiable.
      return sweep(agentName, agentKeyProvider, agentPubkeyHex, homeNodeId, "connect");
    },
    stop: (agentName: string) => {
      const timer = timers.get(agentName);
      if (!timer) return;
      clearInterval(timer);
      timers.delete(agentName);
      logger.info("trust_signal.sweep.tick_stopped", { agentName });
    },
    stopAll: () => {
      for (const timer of timers.values()) clearInterval(timer);
      timers.clear();
    },
  };
}
