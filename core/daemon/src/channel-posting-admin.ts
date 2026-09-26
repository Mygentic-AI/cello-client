/**
 * M16 043-POSTERS Part E — the admin's side of posting: who may post, their passes, the lease.
 *
 *   posting  admin    only the admin posts (the default — today's behaviour)
 *            listed   the admin names posters (`channel_members.can_post`)
 *            members  every active member is a poster (issued at admission too)
 *
 * A pass is signed by the CHANNEL key and EXPIRES (the lease). The renewal tick re-issues any live
 * pass with under two days left, so an admin who is online keeps its posters posting and one gone
 * longer than the lease lets every pass lapse — then only the admin posts. A pass is recorded only
 * once it was DELIVERED, so an unreached poster is simply retried on the next tick.
 *
 * Remove / eject / switch to `admin` REVOKE: the revocation (poster, time) is published in the
 * channel info record, the relay refuses any pass issued at or before it, and the tick stops
 * renewing. A later re-add issues a pass after the revocation time.
 *
 * ⚠️ A channel whose posting is `admin` with NO revocations publishes `ext: null` — exactly the
 * record it published before 043.
 */
import type { KeyProvider } from "@cello-protocol/crypto";
import {
  encodeChannelPosterPass, encodeChannelPosterPassFrame, signChannelPosterPass,
  type ChannelInfoExt, type ChannelPosting,
} from "@cello-protocol/protocol-types";
import type { Logger } from "./types.js";
import type { ChannelConfigStore } from "./channel-config-store.js";
import type { ChannelMembershipStore } from "./channel-membership-store.js";
import { grantIsLive, type ChannelPosterGrantStore } from "./channel-poster-grant-store.js";
import { extractErrorMessage } from "./error-message.js";

/** Re-issue a pass when less than this is left. */
export const POSTER_RENEW_BEFORE_MS = 2 * 24 * 60 * 60 * 1000;
/** How often the renewal tick runs. */
export const POSTER_RENEW_TICK_MS = 60 * 60 * 1000;

export interface ChannelPostingAdminDeps {
  logger: Logger;
  config: ChannelConfigStore;
  members: ChannelMembershipStore;
  grants: ChannelPosterGrantStore;
  /** The channel key, when this daemon administers the channel. */
  channelKeyFor: (channelHex: string) => KeyProvider | null;
  /** The admin agent's NAME (sessions ride it), when this daemon administers the channel. */
  adminAgentNameFor: (channelHex: string) => string | null;
  /** The channels whose passes the tick renews. */
  postingChannels: () => string[];
  /** Deliver a frame to a member over a sealed session. `false` = unreached. */
  sendFrame: (agentName: string, memberHex: string, frame: Uint8Array) => Promise<boolean>;
  /** Sign and deposit the channel's info record (which carries `infoExt`). */
  depositInfo: (agentName: string, channelHex: string) => Promise<unknown>;
  now?: () => number;
}

export type PostingAnswer = { ok: true } | { ok: false; reason: string; guidance?: string };

/** The info record's ext: null for `admin` with no revocations — exactly today's record. */
export function postingInfoExt(
  config: Pick<ChannelConfigStore, "get">, grants: Pick<ChannelPosterGrantStore, "revocations">, channelHex: string,
): ChannelInfoExt | null {
  const posting = config.get(channelHex)?.posting ?? "admin";
  const revoked = grants.revocations(channelHex).map((r) => ({
    poster_pubkey: new Uint8Array(Buffer.from(r.poster_pubkey, "hex")), revoked_at: r.revoked_at,
  }));
  return posting === "admin" && revoked.length === 0 ? null : { posting, revoked };
}

export function createChannelPostingAdmin(deps: ChannelPostingAdminDeps) {
  const { logger, config, members, grants } = deps;
  const now = deps.now ?? (() => Date.now());

  /**
   * 044-POSTERBELL: channels whose membership changed since their posters last got a pass. A pass
   * carries the member list, so a change (admit or eject) means every current poster holds a stale
   * list until it is re-sent. The next renewal tick re-issues them regardless of remaining lease —
   * without this an ejected member would linger in a poster's ring targets until the pass expired.
   */
  const membersDirty = new Set<string>();
  const markMembersChanged = (channelHex: string): void => { membersDirty.add(channelHex); };

  /** Who should hold a pass right now. */
  const postersOf = (channelHex: string): string[] => {
    const posting = config.get(channelHex)?.posting ?? "admin";
    if (posting === "listed") return members.canPostMembers(channelHex);
    if (posting === "members") return members.activeMembers(channelHex);
    return [];
  };

  /** The channel's current active member pubkeys (bytes) — carried on every pass so posters can ring. */
  const memberBytes = (channelHex: string): Uint8Array[] =>
    members.activeMembers(channelHex).map((m) => new Uint8Array(Buffer.from(m, "hex")));

  /** Sign, send, and — only once delivered — record one pass. */
  const issue = async (channelHex: string, posterHex: string): Promise<boolean> => {
    const channelKey = deps.channelKeyFor(channelHex);
    const agentName = deps.adminAgentNameFor(channelHex);
    if (!channelKey || !agentName) return false;
    const leaseMs = (config.get(channelHex)?.poster_lease_seconds ?? 604800) * 1000;
    const issuedAt = now();
    const pass = await signChannelPosterPass(channelKey, {
      poster_pubkey: new Uint8Array(Buffer.from(posterHex, "hex")), issued_at: issuedAt, expires_at: issuedAt + leaseMs,
    });
    let delivered = false;
    try {
      // 044-POSTERBELL: the pass carries the channel's current members, outside the signed pass.
      delivered = await deps.sendFrame(agentName, posterHex, encodeChannelPosterPassFrame(encodeChannelPosterPass(pass), memberBytes(channelHex)));
    } catch (err: unknown) {
      logger.warn("channel.poster_pass.unreached", { channel_pubkey: channelHex, poster_pubkey: posterHex, reason: extractErrorMessage(err) });
      return false;
    }
    if (!delivered) {
      logger.warn("channel.poster_pass.unreached", { channel_pubkey: channelHex, poster_pubkey: posterHex, reason: "no_session" });
      return false;
    }
    grants.recordIssued(channelHex, posterHex, pass.issued_at, pass.expires_at);
    return true;
  };

  /**
   * Revoke every live pass held by someone no longer a poster, and renew every live poster pass
   * with under two days left. A poster whose last pass was revoked is NOT re-issued here — only an
   * explicit add, an admission or a switch of mode does that.
   */
  const reconcile = async (channelHex: string): Promise<boolean> => {
    const posters = new Set(postersOf(channelHex));
    let changed = false;
    for (const g of grants.all(channelHex)) {
      if (grantIsLive(g) && !posters.has(g.poster_pubkey)) {
        grants.revoke(channelHex, g.poster_pubkey, now());
        changed = true;
      }
    }
    // 044-POSTERBELL: a membership change forces a re-send to every current poster so the new member
    // list reaches them now, not only when a pass nears expiry. Cleared once the re-send is done.
    const forceResend = membersDirty.delete(channelHex);
    for (const poster of posters) {
      const g = grants.get(channelHex, poster);
      if (!g || !grantIsLive(g)) continue;
      if (!forceResend && g.expires_at - now() >= POSTER_RENEW_BEFORE_MS) continue;
      if (await issue(channelHex, poster)) changed = true;
    }
    return changed;
  };

  const deposit = async (channelHex: string): Promise<void> => {
    const agentName = deps.adminAgentNameFor(channelHex);
    if (agentName) await deps.depositInfo(agentName, channelHex);
  };

  const needAdmin = (channelHex: string): PostingAnswer | null =>
    deps.channelKeyFor(channelHex) && deps.adminAgentNameFor(channelHex) && config.get(channelHex)
      ? null
      : { ok: false, reason: "channel_not_local", guidance: "This daemon does not administer that channel." };

  return {
    infoExt: (channelHex: string): ChannelInfoExt | null => postingInfoExt(config, grants, channelHex),

    async setPosting(channelHex: string, posting: ChannelPosting, leaseDays?: number): Promise<PostingAnswer> {
      if (posting !== "admin" && posting !== "listed" && posting !== "members") {
        return { ok: false, reason: "bad_posting", guidance: "Posting is one of: admin, listed, members." };
      }
      if (leaseDays !== undefined && (!Number.isSafeInteger(leaseDays) || leaseDays < 1)) {
        return { ok: false, reason: "bad_lease", guidance: "--lease-days is a whole number of days, at least 1." };
      }
      const refused = needAdmin(channelHex);
      if (refused) return refused;
      const lease = leaseDays !== undefined ? leaseDays * 86400 : (config.get(channelHex)?.poster_lease_seconds ?? 604800);
      config.setPosting(channelHex, posting, lease);
      await reconcile(channelHex);
      // A switch of mode issues to every poster that does not hold a live pass.
      for (const poster of postersOf(channelHex)) {
        const g = grants.get(channelHex, poster);
        if (!g || !grantIsLive(g)) await issue(channelHex, poster);
      }
      await deposit(channelHex);
      return { ok: true };
    },

    async addPoster(channelHex: string, posterHex: string): Promise<PostingAnswer> {
      const refused = needAdmin(channelHex);
      if (refused) return refused;
      const cfg = config.get(channelHex);
      if (cfg?.access === "public") {
        return { ok: false, reason: "public_channel", guidance: "A public channel has no members to name as posters; use members posting or post as admin." };
      }
      if (cfg?.posting !== "listed") {
        return { ok: false, reason: "posting_not_listed", guidance: "Set posting to listed first: cello channel posting <channel> listed." };
      }
      if (members.statusOf(channelHex, posterHex) !== "active") {
        return { ok: false, reason: "not_an_active_member", guidance: "A poster must be an active member of the channel." };
      }
      members.setCanPost(channelHex, posterHex, true);
      await issue(channelHex, posterHex);
      await deposit(channelHex);
      return { ok: true };
    },

    async removePoster(channelHex: string, posterHex: string): Promise<PostingAnswer> {
      const refused = needAdmin(channelHex);
      if (refused) return refused;
      members.setCanPost(channelHex, posterHex, false);
      grants.revoke(channelHex, posterHex, now());
      await deposit(channelHex);
      return { ok: true };
    },

    /** `members` posting: a newly admitted member is a poster at once. */
    async onAdmitted(channelHex: string, memberHex: string): Promise<void> {
      // 044-POSTERBELL: the roster changed, so every poster's stored member list is now stale.
      markMembersChanged(channelHex);
      if (config.get(channelHex)?.posting !== "members") return;
      if (await issue(channelHex, memberHex)) await deposit(channelHex);
    },

    /** An ejected member's pass is revoked and never renewed. */
    async onEjected(channelHex: string, memberHex: string): Promise<void> {
      // 044-POSTERBELL: the roster changed; the next tick re-sends passes so the ejected member
      // drops out of every poster's ring targets.
      markMembersChanged(channelHex);
      const g = grants.get(channelHex, memberHex);
      if (!g || !grantIsLive(g)) return;
      grants.revoke(channelHex, memberHex, now());
      await deposit(channelHex);
    },

    /** One renewal pass over every posting channel; the info record is re-deposited where anything changed. */
    async tick(): Promise<void> {
      for (const channelHex of deps.postingChannels()) {
        if (needAdmin(channelHex)) continue;
        try {
          if (await reconcile(channelHex)) await deposit(channelHex);
        } catch (err: unknown) {
          logger.warn("channel.poster_renew.failed", { channel_pubkey: channelHex, reason: extractErrorMessage(err) });
        }
      }
    },

    /** Daemon start: re-deposit every posting channel's record, then renew hourly. Returns the stopper. */
    start(): () => void {
      void (async () => {
        for (const channelHex of deps.postingChannels()) {
          if (!needAdmin(channelHex)) await deposit(channelHex).catch(() => {});
        }
      })();
      const timer = setInterval(() => { void this.tick(); }, POSTER_RENEW_TICK_MS);
      timer.unref();
      return () => { clearInterval(timer); };
    },
  };
}

export type ChannelPostingAdmin = ReturnType<typeof createChannelPostingAdmin>;
