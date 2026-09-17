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
import { ChannelEpochSealer } from "./channel-epoch-sealer.js";
import { channelAgentLookup } from "./db-identity-store.js";
import { extractErrorMessage } from "./error-message.js";

/** Once a minute: the overshoot is at most a minute on a cap measured in a day. */
export const CHANNEL_EPOCH_TICK_MS = 60_000;

export interface ChannelEpochTickDeps {
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  /** This daemon's agents, live: a channel registered after boot is picked up on the next tick. */
  agents: ReadonlyArray<{ name: string; pubkey?: string }>;
  getKeyProvider: (agentName: string) => KeyProvider | undefined;
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
      now: () => Date.now(),
    }));

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
        const policy = ChannelEpochSealer.validatePolicy(sessionNodeManager.getChannelLogStore().epochPolicy(agent.pubkey));
        const outcome = await s.sealIfDue(agent.pubkey, policy, correlationId);
        if (outcome.sealed) sealedCount++;
      } catch (err) {
        // A channel that has never published has no log yet — nothing to seal, and not a failure.
        if ((err as { code?: string }).code === "channel_unknown") continue;
        logger.warn("channel.epoch.cap_tick_failed", {
          correlationId, channel_pubkey: agent.pubkey, error: extractErrorMessage(err),
          impact: "this channel's open epoch was not sealed this tick; the next tick retries",
        });
      }
    }
    logger.debug("channel.epoch.cap_tick", { channels_checked: checked, sealed_count: sealedCount });
  };

  const override = Number(process.env["CELLO_CHANNEL_EPOCH_TICK_MS"]);
  const intervalMs = Number.isFinite(override) && override >= 250 ? override : CHANNEL_EPOCH_TICK_MS;
  const timer = setInterval(() => { void tick(); }, intervalMs);
  timer.unref?.();
  return { timer, tick };
}
