/**
 * M16 018-PUBCOLLECT — what actually RUNS the collector.
 *
 * ⚠️ **WITHOUT THIS, SUBSCRIBING DOES NOTHING.** `ChannelCollector` fetches when it is called, and
 * a subscriber has nobody to call it: there is no inbound event for a channel post — the relay holds
 * a queue and waits to be asked. A collector nobody schedules is a subscriber who never receives
 * anything, with every component reporting healthy. The publishing half shipped wired and this half
 * did not, which is the same hole twice in one milestone.
 *
 * ─── The interval, and why it is bounded by retention ────────────────────────────────────────
 *
 * A relay drops posts on its own schedule. If the gap between collections is longer than a channel's
 * retention, a subscriber can miss a post that was delivered, held for its full life and swept —
 * never seeing it, and never recording a gap either, because the number is below the floor by the
 * time anyone looks. The interval therefore has to stay well under the shortest retention any
 * channel uses, and the default retention is seven days. Five minutes is three orders of magnitude
 * inside that, which is the margin this needs to be safe against a channel configured far shorter.
 *
 * ─── Jitter is derived from the channel key, not random ──────────────────────────────────────
 *
 * Every subscriber to a popular channel would otherwise poll its two relays at the same moment —
 * the relays see the entire audience arrive at once, every interval, for ever. The offset is
 * derived from the channel's public key so it is STABLE for a given subscriber: a random offset
 * re-rolled each tick spreads the load just as well but makes the cadence unpredictable to the
 * operator watching it, and makes a slow channel impossible to distinguish from a jittery one.
 *
 * ─── Backoff is per channel, and only on FAILURE ─────────────────────────────────────────────
 *
 * A channel whose relays are both down is asked less and less often, up to a ceiling, so a dead
 * channel costs little. Any success resets it immediately: the point is to stop hammering something
 * broken, not to punish a channel for a bad afternoon.
 */
import { createHash } from "node:crypto";
import type { Logger } from "./types.js";
import type { ChannelCollector } from "./channel-collector.js";
import type { ChannelSubscriptionStore } from "./channel-subscription-store.js";
import { extractErrorMessage } from "./error-message.js";

/** See the header: bounded by the shortest retention any channel may configure. */
export const COLLECT_TICK_INTERVAL_MS = 5 * 60_000;
/** The widest the pubkey-derived offset can push a channel's tick. */
export const COLLECT_JITTER_MS = 60_000;
/** A failing channel is backed off to at most this, then stays there until it succeeds. */
export const COLLECT_MAX_BACKOFF_MS = 30 * 60_000;

export interface ChannelCollectTickDeps {
  logger: Logger;
  collector: ChannelCollector;
  subscriptions: ChannelSubscriptionStore;
  /**
   * Whether this agent is ONLINE. Collecting for an agent the operator switched off is the kill
   * switch failing to switch something off — the same rule the trust-signal tick follows.
   */
  isAgentOnline: (agentId: string) => boolean;
  intervalMs?: number;
  jitterMs?: number;
  maxBackoffMs?: number;
}

export interface ChannelCollectTicker {
  /** Begin collecting. Idempotent: a second call does not stack a second timer. */
  start: () => void;
  /** One pass over every active subscription. Exposed so a test drives it without a clock. */
  collectAllDue: (now: number) => Promise<void>;
  stop: () => void;
}

/**
 * A stable offset in [0, jitterMs) for a channel, from its public key. Same channel, same
 * subscriber, same offset every time — see the header for why that beats a fresh random each tick.
 */
export function jitterForChannel(channelHex: string, agentId: string, jitterMs: number): number {
  if (jitterMs <= 0) return 0;
  const digest = createHash("sha256").update(`${agentId}:${channelHex}`, "utf8").digest();
  return digest.readUInt32BE(0) % jitterMs;
}

export function createChannelCollectTicker(deps: ChannelCollectTickDeps): ChannelCollectTicker {
  const { logger, collector, subscriptions, isAgentOnline } = deps;
  const intervalMs = deps.intervalMs ?? COLLECT_TICK_INTERVAL_MS;
  const jitterMs = deps.jitterMs ?? COLLECT_JITTER_MS;
  const maxBackoffMs = deps.maxBackoffMs ?? COLLECT_MAX_BACKOFF_MS;

  /** When each subscription is next due, and how far it has been backed off. */
  const nextDue = new Map<string, number>();
  const backoff = new Map<string, number>();
  /**
   * Subscriptions with a pass still running. A tick that lands on one is SKIPPED rather than
   * queued: a slow relay would otherwise stack passes that all fetch the same posts, and each one
   * holds a database write.
   */
  const inFlight = new Set<string>();
  let timer: NodeJS.Timeout | null = null;

  const keyOf = (agentId: string, channelHex: string): string => `${agentId}:${channelHex}`;

  async function collectAllDue(now: number): Promise<void> {
    for (const sub of subscriptions.active()) {
      const key = keyOf(sub.agent_id, sub.channel_pubkey);
      if (inFlight.has(key)) continue;
      // Checked PER SUBSCRIPTION, not once for the pass: one agent being offline must not stop
      // another agent's channels from collecting.
      if (!isAgentOnline(sub.agent_id)) continue;

      const due = nextDue.get(key);
      if (due === undefined) {
        // First sight of this subscription: collect now, then settle into the jittered cadence. A
        // new subscriber waiting a full interval for its first post looks broken and is.
        nextDue.set(key, now);
      } else if (now < due) {
        continue;
      }

      inFlight.add(key);
      try {
        await collector.collectOnce(sub.agent_id, sub.channel_pubkey);
        await collector.repairGaps(sub.agent_id, sub.channel_pubkey);
        backoff.delete(key);
        nextDue.set(key, now + intervalMs + jitterForChannel(sub.channel_pubkey, sub.agent_id, jitterMs));
      } catch (err: unknown) {
        // ⚠️ LOGGED, never swallowed and never fatal to the loop. A background collection that fails
        // in silence is a subscriber who simply stops receiving, with nothing anywhere saying why —
        // and one channel's bad relay must not stop every other channel on this daemon.
        const next = Math.min(maxBackoffMs, (backoff.get(key) ?? intervalMs) * 2);
        backoff.set(key, next);
        nextDue.set(key, now + next + jitterForChannel(sub.channel_pubkey, sub.agent_id, jitterMs));
        logger.warn("channel.collect.tick_failed", {
          channel_pubkey: sub.channel_pubkey,
          reason: extractErrorMessage(err),
          next_attempt_in_ms: next,
        });
      } finally {
        inFlight.delete(key);
      }
    }
  }

  return {
    start(): void {
      if (timer !== null) return;
      // The pass runs every interval and decides per subscription what is due; the jitter lives in
      // the due times rather than in the timer, so one slow channel cannot drag the others.
      timer = setInterval(() => {
        void collectAllDue(Date.now()).catch((err: unknown) => {
          logger.warn("channel.collect.pass_failed", { reason: extractErrorMessage(err) });
        });
      }, intervalMs);
      // Never hold the process open for a background poll.
      timer.unref?.();
      logger.info("channel.collect.started", { interval_ms: intervalMs, jitter_ms: jitterMs });
    },
    collectAllDue,
    stop(): void {
      if (timer !== null) clearInterval(timer);
      timer = null;
    },
  };
}
