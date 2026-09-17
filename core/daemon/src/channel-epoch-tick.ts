/**
 * The channel epoch cap, enforced — M16 008-EPOCH.
 *
 * Every tick, for each of this daemon's own channel identities, seal the open epoch if it is due:
 * 24 hours after its first leaf or at 1,000 leaves, or sooner if the channel declared a shorter cap.
 * The cap is what bounds how long a channel can equivocate, so it runs without anyone attending the
 * channel and is not something a setting can switch off.
 *
 * A failure on one channel is logged by the sealer and does not stop the others. The timer `unref`s
 * so it never holds the process open, and is returned so shutdown can clear it.
 */
import { randomUUID } from "node:crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { Logger } from "./types.js";
import { ChannelEpochSealStore } from "./channel-epoch-seal-store.js";
import { ChannelEpochSealer, EPOCH_MAX_AGE_MS, EPOCH_MAX_LEAVES, sealerAlreadyLogged } from "./channel-epoch-sealer.js";
import { channelAgentLookup } from "./db-identity-store.js";
import { extractErrorMessage } from "./error-message.js";

/** Once a minute: the overshoot is at most a minute on a cap measured in a day. */
export const CHANNEL_EPOCH_TICK_MS = 60_000;

/**
 * `CELLO_CHANNEL_EPOCH_TICK_MS` may SHORTEN the tick (tests use it), never lengthen it. A day-long
 * tick would double the window a channel can equivocate in, and past 2^31-1 ms Node silently
 * replaces the delay with 1 ms.
 */
export function channelEpochTickIntervalMs(raw: string | undefined): number {
  const n = Number(raw);
  return raw !== undefined && Number.isSafeInteger(n) && n >= 250 && n <= CHANNEL_EPOCH_TICK_MS ? n : CHANNEL_EPOCH_TICK_MS;
}

export interface ChannelEpochTickDeps {
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  /** This daemon's agents, live: a channel registered after boot is picked up on the next tick. */
  agents: ReadonlyArray<{ name: string; pubkey?: string }>;
  getKeyProvider: (agentName: string) => KeyProvider | undefined;
  /** Injectable clock for tests; the daemon uses the wall clock. */
  now?: () => number;
}

export function startChannelEpochTick(deps: ChannelEpochTickDeps): { timer: NodeJS.Timeout; tick: () => Promise<void> } {
  const { logger, sessionNodeManager, agents, getKeyProvider } = deps;
  const isChannelAgent = channelAgentLookup(sessionNodeManager, logger);
  let sealer: ChannelEpochSealer | null = null;
  const sealerFor = (): ChannelEpochSealer =>
    (sealer ??= new ChannelEpochSealer({
      log: sessionNodeManager.getChannelLogStore(),
      sealStore: new ChannelEpochSealStore(sessionNodeManager.getDb(), logger),
      getKeyProvider: (hex) => {
        const agent = agents.find((a) => a.pubkey === hex);
        return (agent && getKeyProvider(agent.name)) ?? null;
      },
      logger,
      now: deps.now ?? (() => Date.now()),
    }));

  // A stored policy that fails validation must not switch the cap off: enforce the protocol maxima,
  // which are the strictest values a channel could not have shortened below, and say so at error.
  const storedPolicyOrMaxima = (channelPubkeyHex: string, correlationId: string) => {
    const stored = sessionNodeManager.getChannelLogStore().epochPolicy(channelPubkeyHex);
    try {
      return ChannelEpochSealer.validatePolicy(stored);
    } catch (err) {
      logger.error("channel.epoch.seal_failed", {
        correlationId, channel_pubkey: channelPubkeyHex, reason: "policy_invalid", error: extractErrorMessage(err),
        stored_max_age_ms: stored.maxAgeMs, stored_max_leaves: stored.maxLeaves,
        impact: "this channel's stored epoch cap is invalid, so the protocol maxima (24 hours, 1,000 leaves) are enforced instead",
      });
      return { maxAgeMs: EPOCH_MAX_AGE_MS, maxLeaves: EPOCH_MAX_LEAVES };
    }
  };

  const tick = async (): Promise<void> => {
    let checked = 0;
    let sealedCount = 0;
    for (const { name, pubkey } of agents) {
      if (!pubkey || !isChannelAgent(name)) continue;
      const agent = { name, pubkey };
      checked++;
      const correlationId = randomUUID();
      try {
        const s = sealerFor();
        const outcome = await s.sealIfDue(agent.pubkey, storedPolicyOrMaxima(agent.pubkey, correlationId), correlationId);
        if (outcome.sealed) sealedCount++;
      } catch (err) {
        // A channel that has never published has no log yet — nothing to seal, and not a failure.
        if ((err as { code?: string }).code === "channel_unknown") continue;
        // The sealer already logged this failure at the right level; a second line would double it.
        if (sealerAlreadyLogged(err)) continue;
        logger.warn("channel.epoch.cap_tick_failed", {
          correlationId, channel_pubkey: agent.pubkey, error: extractErrorMessage(err),
          impact: "this channel's open epoch was not sealed this tick; the next tick retries",
        });
      }
    }
    logger.debug("channel.epoch.cap_tick", { channels_checked: checked, sealed_count: sealedCount });
  };

  const timer = setInterval(() => { void tick(); }, channelEpochTickIntervalMs(process.env["CELLO_CHANNEL_EPOCH_TICK_MS"]));
  timer.unref?.();
  return { timer, tick };
}
