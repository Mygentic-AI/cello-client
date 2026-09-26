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

/**
 * ⚠️ **THIS IS A BACKSTOP, NOT THE DELIVERY MECHANISM — 021-WAKE changed what it is FOR.**
 *
 * At five minutes this timer WAS how a post reached anyone, and the feature was email with a
 * five-minute inbox check. Delivery is now the wake (021): the publisher asks a directory to poke
 * the members and they fetch at once.
 *
 * The timer keeps a job because push is best-effort, and it is the only thing that covers a post
 * sitting on a relay with nobody told: the publisher's daemon never sent the wake, the frame was
 * lost while the signaling stream rotated, or the peer forward never reached this subscriber's
 * node. It does not go to zero, because the case it cannot otherwise repair is a channel that goes
 * QUIET right after the message you missed — which is exactly the "relays going down now" post.
 */
export const COLLECT_TICK_INTERVAL_MS = 60 * 60_000;
/**
 * The widest the pubkey-derived offset can push a channel's tick — **a proportion of the interval,
 * which is why it is written as one.** A fixed 60 seconds was right for a 5-minute tick and is a
 * narrow band inside an hour: the fleet would clump into the same minute every hour, which is the
 * thundering herd this exists to prevent, arriving less often and so harder to notice.
 */
export const COLLECT_JITTER_MS = COLLECT_TICK_INTERVAL_MS / 2;
/**
 * A failing channel is backed off to at most this, then stays there until it succeeds.
 *
 * ⚠️ **IT HAS TO EXCEED THE INTERVAL OR IT IS NOT A BACKOFF.** At 30 minutes against an hourly
 * poll, a FAILING channel became due sooner than a healthy one — the first failure computed
 * `min(30min, 60min×2)` = 30 minutes, and every subsequent one stayed there. This number was sized
 * for a five-minute interval and not re-derived when the interval moved, which is the whole
 * mistake: a constant that only makes sense relative to another constant should be written
 * relative to it.
 */
export const COLLECT_MAX_BACKOFF_MS = 4 * COLLECT_TICK_INTERVAL_MS;

/**
 * Randomness added to a RETRY, on top of the stable per-channel jitter.
 *
 * ⚠️ **THE STEADY-STATE TIMER IS NOT THE STAMPEDE RISK — RECOVERY IS.** When a relay returns after
 * an outage, every daemon that has been failing is on the retry path, not the timer, and
 * `jitterForChannel` is stable per (agent, channel) so it does not stagger the returning WAVE: all
 * of them back off to the same ceiling and come due on the same pass. This is the one place a
 * re-rolled random belongs, because the thing being spread is a moment rather than a schedule.
 */
export const COLLECT_RETRY_SPREAD_MS = 10 * 60_000;

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
  /** M16 021-WAKE: random spread on the RETRY path only. Set to 0 in a test that needs determinism. */
  retrySpreadMs?: number;
  /**
   * 043-POSTERS Part F: the admin's own channels' poster lanes, collected on this same schedule so
   * the admin's daemon can ring members for a poster's post. Its failures are its own to log.
   */
  adminPass?: () => Promise<void>;
}

export interface ChannelCollectTicker {
  /** Begin collecting. Idempotent: a second call does not stack a second timer. */
  start: () => void;
  /** One pass over every active subscription. Exposed so a test drives it without a clock. */
  collectAllDue: (now: number) => Promise<void>;
  /**
   * M16 021-WAKE: the doorbell rang — collect this agent's channels NOW.
   *
   * ⚠️ **EVERY channel this agent follows, because the wake names none.** The frame is deliberately
   * empty so that channel→member never travels a second wire; the daemon already knows what it
   * subscribes to, and fetching all of them is what makes the empty frame sufficient.
   */
  collectNow: (agentId: string) => Promise<void>;
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
  const retrySpreadMs = deps.retrySpreadMs ?? COLLECT_RETRY_SPREAD_MS;

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
        // Stable jitter spreads channels across subscribers; the RANDOM part spreads the moment a
        // whole fleet returns after an outage, which stable jitter cannot do because every failing
        // channel lands on the same ceiling.
        nextDue.set(key, now + next
          + jitterForChannel(sub.channel_pubkey, sub.agent_id, jitterMs)
          + Math.floor(Math.random() * retrySpreadMs));
        logger.warn("channel.collect.tick_failed", {
          channel_pubkey: sub.channel_pubkey,
          reason: extractErrorMessage(err),
          next_attempt_in_ms: next,
        });
      } finally {
        inFlight.delete(key);
      }
    }
    await deps.adminPass?.();
  }

  /**
   * M16 021-WAKE — a doorbell arrived for this agent. Fetch its channels at once.
   *
   * ⚠️ **IT DOES NOT TOUCH `nextDue`, and that is deliberate.** A wake that reset the schedule would
   * let a chatty channel keep pushing the backstop out for every OTHER channel on this agent — and
   * the backstop is the only thing that repairs a wake that never arrived.
   *
   * ⚠️ The online check is repeated here. The kill switch has to hold on this path too: collecting
   * for an agent the operator switched off is the switch failing to switch something off, and a
   * doorbell must not become the way around it.
   */
  async function collectNow(agentId: string): Promise<void> {
    if (!isAgentOnline(agentId)) {
      // 029-COLLECTID: name the agent that was skipped, so the next reader sees WHICH one.
      logger.debug("channel.collect.wake_ignored", { reason: "agent_offline", agentId });
      return;
    }
    for (const sub of subscriptions.active()) {
      if (sub.agent_id !== agentId) continue;
      const key = keyOf(sub.agent_id, sub.channel_pubkey);
      if (inFlight.has(key)) continue;
      inFlight.add(key);
      try {
        await collector.collectOnce(sub.agent_id, sub.channel_pubkey);
        await collector.repairGaps(sub.agent_id, sub.channel_pubkey);
        backoff.delete(key);
      } catch (err: unknown) {
        // One channel's bad relay must not stop the rest of this agent's channels collecting. The
        // timer's own backoff is untouched: this pass is extra, not a replacement for it.
        logger.warn("channel.collect.wake_failed", {
          channel_pubkey: sub.channel_pubkey, reason: extractErrorMessage(err),
        });
      } finally {
        inFlight.delete(key);
      }
    }
  }

  return {
    collectNow,
    start(): void {
      if (timer !== null) return;
      /**
       * ⚠️ **ONE PASS NOW, BEFORE THE TIMER — and leaving this out made the order's own worst case
       * twelve times worse.** At a five-minute interval a daemon that had just started waited five
       * minutes for its first collection; at sixty it waits an hour. Your laptop was shut
       * overnight, you open it, the daemon reconnects — and nothing is fetched until the next hour.
       * The offline subscriber is exactly the case the backstop exists for.
       *
       * It is also what makes a NEW subscription arrive promptly: `collectAllDue` treats first
       * sight as due immediately, but only a pass can notice it.
       */
      void collectAllDue(Date.now()).catch((err: unknown) => {
        logger.warn("channel.collect.pass_failed", { reason: extractErrorMessage(err) });
      });
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
