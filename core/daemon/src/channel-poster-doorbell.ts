/**
 * M16 043-POSTERS Part F — the doorbell for a POSTER's post, rung by the ADMIN's daemon.
 *
 * A poster cannot ring the members itself (the directory rings only for the channel's admin). So the
 * admin's daemon reads its own channels' poster lanes on its existing collection schedule, as a
 * reader, and when a new poster post has arrived it rings the members through the SAME wake path an
 * admin post uses. When the admin's machine is off, poster posts still reach members at their own
 * scheduled collection — just without a ring.
 */
import type { ChannelAccess } from "@cello-protocol/protocol-types";
import type { Logger } from "./types.js";
import { extractErrorMessage } from "./error-message.js";

export interface PosterDoorbellDeps {
  logger: Logger;
  collectPosterLanesAsAdmin: (
    adminAgentId: string, channelHex: string, view: { access: ChannelAccess; relays: string[]; admin_pubkey: string },
  ) => Promise<{ delivered: number; posters: string[] }>;
  /** The channels this daemon administers with posting other than `admin`. */
  postingChannels: () => string[];
  /** The channel's config as this daemon recorded it, or null. */
  channelConfig: (channelHex: string) => { access: ChannelAccess; relays: string[]; admin_pubkey?: string } | null;
  /** The loaded admin agent for an admin pubkey: its name (the wake rides it) and stable id. */
  adminAgent: (adminPubkeyHex: string) => { name: string; agentId: string } | null;
  isAgentOnline: (agentId: string) => boolean;
  /** The existing member wake — the same one an admin post rings. */
  sendWake: (agentName: string, channelHex: string) => Promise<void>;
}

export function createPosterDoorbell(deps: PosterDoorbellDeps): () => Promise<void> {
  return async function posterDoorbellPass(): Promise<void> {
    for (const channelHex of deps.postingChannels()) {
      const cfg = deps.channelConfig(channelHex);
      const admin = cfg?.admin_pubkey ? deps.adminAgent(cfg.admin_pubkey) : null;
      // The kill switch holds here too: an admin agent switched off rings nobody.
      if (!cfg || !admin || !deps.isAgentOnline(admin.agentId)) continue;
      try {
        const got = await deps.collectPosterLanesAsAdmin(admin.agentId, channelHex, {
          access: cfg.access, relays: cfg.relays, admin_pubkey: cfg.admin_pubkey ?? "",
        });
        if (got.delivered === 0) continue;
        deps.logger.info("channel.poster_post.doorbell", { channel_pubkey: channelHex, count: got.delivered, posters: got.posters });
        await deps.sendWake(admin.name, channelHex);
      } catch (err: unknown) {
        deps.logger.warn("channel.poster_post.doorbell_failed", { channel_pubkey: channelHex, reason: extractErrorMessage(err) });
      }
    }
  };
}
