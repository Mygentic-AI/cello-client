/**
 * M16 019-MEMBERSHIP — the join exchange, the eject re-key, and the operator's channel verbs.
 * M16 045-NOTICEBELL — every admin notice (pass, removal, eject, new key, delete) is a signed record
 * plus a directory ring (`channel-notices.ts`); no session is ever opened for one.
 * M16 046-JOINBELL — joining is the same: a signed request on the relays, a ring, a signed answer
 * (`channel-join-exchange.ts`). No channel action opens a session.
 *
 * The publishing half is wired next door in `channel-publish-wiring.ts`; this is membership. Both
 * exist because a module registered into nothing is a feature that does not exist — the mistake 017
 * shipped and 018 repeated on its other half.
 */
import type { Logger } from "./types.js";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { KeyProvider } from "@cello-protocol/crypto";
import {
  buildChannelFetchKeyTbs, encodeNoticeEjectBody, encodeNoticePassBody, signChannelRelayRecord, encodeChannelRelayRecord,
} from "@cello-protocol/protocol-types";
import { generateGroupKey, wrapGroupKeyFor, deriveFetchKey, decryptBody, encryptBody } from "@cello-protocol/crypto";
import { ChannelMembershipStore } from "./channel-membership-store.js";
import { ChannelSubscriptionStore } from "./channel-subscription-store.js";
import { ChannelConfigStore } from "./channel-config-store.js";
import { ChannelPosterPassStore } from "./channel-poster-pass-store.js";
import { ChannelLanePositionStore } from "./channel-lane-position-store.js";
import { ChannelPosterGrantStore } from "./channel-poster-grant-store.js";
import { createChannelPostingAdmin } from "./channel-posting-admin.js";
import {
  ensureCurrentGroupKey, createChannelJoiner, createChannelJoinAdmin, applyJoinAnswer,
  ChannelJoinRequestStore, ChannelJoinSeenStore,
  type LocalChannelAdmin, type AdminLookupOutcome,
} from "./channel-join-exchange.js";
import {
  createChannelAdminLookup, askDirectoryAboutChannel, type ChannelAdminOutcome, type SignalingLike,
} from "./channel-admin-lookup.js";
import { createChannelSubscribe } from "./channel-subscribe.js";
import { ChannelInboxStore } from "./channel-inbox-store.js";
import { extractErrorMessage } from "./error-message.js";
import { ChannelNoticeSeenStore, createChannelNoticeReader, writeChannelNotice } from "./channel-notices.js";

/** 045-NOTICEBELL: how often a member re-reads its notices when no ring arrived (the backstop). */
export const NOTICE_BACKSTOP_TICK_MS = 60 * 60_000;
/** 046-JOINBELL: how often an admin checks its channels' relay records are published and current. */
export const RELAY_RECORD_TICK_MS = 60_000;

type Handler = (params: Record<string, unknown> | undefined, connectionId: string) => Promise<unknown>;

/**
 * M16 032-NOTICES — the three content-free channel doorbells, as the wirings see them. Each takes an
 * agent ID and maps it to the daemon's display NAME (`agentNameForId`) before reaching the
 * dispatcher, which routes to connections where that name is current — the same rule cello_message
 * follows. Defined here and shared by both wirings; the composition root supplies the one
 * implementation (it holds the late-bound dispatcher).
 */
export interface ChannelNotify {
  /** A collect pass advanced this agent's delivered position: `count` new posts, now at `through`. */
  /** `posters` (043-POSTERS): who wrote, when the posts came from poster lanes. */
  channelPosts: (agentId: string, channelHex: string, count: number, through: number, posters?: string[]) => void;
  /** This agent's own join request was answered — or expired with no answer (046 Decision 11). */
  channelJoinAnswer: (agentId: string, channelHex: string, outcome: "admitted" | "pending" | "refused" | "expired", reason?: string) => void;
  /** A new pending request landed on an invite-only channel this agent administers. */
  channelJoinRequest: (adminAgentId: string, channelHex: string, subscriberHex: string) => void;
  /**
   * 038-RETESTFIX Part E: this agent's membership ENDED — it was ejected, or the channel was deleted.
   * Its own doorbell (rendered with the shortened key), not a refused join answer.
   */
  channelMembershipEnded: (agentId: string, channelHex: string, reason: "ejected" | "channel_closed") => void;
  /**
   * 044-POSTERBELL Part E3: the admin removed this agent as a poster (or closed posting). Its own
   * content-free doorbell, rendered with the shortened key.
   */
  channelPosterRemoved: (agentId: string, channelHex: string) => void;
}

export interface ChannelMembershipWiringDeps {
  handlers: Map<string, Handler>;
  logger: Logger;
  getDb: () => DaemonDatabase;
  /** Every agent this daemon loaded. A channel IS one of them — looked up by pubkey, never by name. */
  loadedAgents: ReadonlyArray<{ name: string; pubkey: string; keyProvider: KeyProvider }>;
  keyProviders: Map<string, KeyProvider>;
  resolveAgentId: (agentName: string) => string;
  /** 043-POSTERS: re-deposit a channel's info record (late-bound to the publishing wiring). */
  depositChannelInfo?: (agentName: string, channelHex: string) => Promise<unknown>;
  /** 043-POSTERS: this agent's local moniker for a pubkey, or null — how a read names a post's writer. */
  contactMoniker?: (agentName: string, pubkeyHex: string) => string | null;
  resolveCurrentAgent: (connectionId: string, explicitAgent?: string) => string | null;
  /**
   * 041-HELPTRUTH Part A: is this loaded agent a CHANNEL identity rather than an operator agent? A
   * channel follows and administers nothing, so `cello channels` with no selection lists operator
   * agents only — the same agents/channels partition 033-CHANNELVIEW draws on every other surface.
   */
  isChannelAgent: (agentName: string) => boolean;
  /**
   * 041-HELPTRUTH Part B: the last published seq for a channel this agent administers, or null when
   * the log is empty / this daemon holds no key. From the publishing half, which owns the log — so
   * this half reads the post count rather than reimplementing the log.
   */
  channelLastSeq: (channelHex: string) => number | null;
  /**
   * 041-HELPTRUTH Part C: the channel's signed info record as its relays hold it, tried in order,
   * first that answers. From the publishing half, which owns the relay client. `info` (a member's)
   * verifies it against the channel key before showing it.
   */
  fetchChannelInfo: (relays: string[], channelHex: string) => Promise<Uint8Array | null>;
  /**
   * M16 020-CHANADMIN: an agent's directory connection, by NAME (the daemon's own key for it), or
   * null when it has none. The subscriber asks on ITS OWN authenticated stream — the directory
   * answers a client that has proved its agent key, which is the difference between this frame and
   * the relay's copy of it.
   */
  signalingFor: (agentName: string) => SignalingLike | null;
  /** M16 032-NOTICES: the content-free doorbells for a join answer and a new join request. */
  notify: ChannelNotify;
  /**
   * 038-RETESTFIX Part B: collect a newly-active subscription's existing posts at once. Wired to the
   * SAME `collectNow` the wake uses (the publishing half's ticker), so a fresh acceptance does not
   * wait for the next post's wake or the backstop poll. It keeps its own online check.
   */
  collectNow: (agentId: string) => void;
  /**
   * M16 034-LIFECYCLE: prune every post the channel holds, on both relays, through the log's last
   * seq — the delete verb's second step. From the publishing half, which owns the log and the
   * publisher, so this half does not reimplement prune. `pruned: 0` with no relays when this daemon
   * holds no key for the channel or the log is empty — never a false success.
   */
  pruneAllPosts: (agentName: string, channelHex: string) =>
    Promise<{ pruned: number; relays: Array<{ relay: string; ok: boolean; reason?: string }> }>;
  /**
   * M16 045-NOTICEBELL: the relay and directory halves of a channel notice, from the publishing
   * half, which owns the relay client and rings the directory. A notice is a signed record plus a
   * ring — never a session.
   */
  noticeTransport: () => {
    depositNotice: (relays: string[], record: Uint8Array) => Promise<number>;
    fetchNotices: (relays: string[], slot: Uint8Array) => Promise<Uint8Array[]>;
    /** 046-JOINBELL: the join slot halves, same relay client. */
    depositJoin: (relays: string[], record: Uint8Array) => Promise<{ accepted: number; refusals: string[] }>;
    fetchJoins: (relays: string[], slot: Uint8Array) => Promise<Uint8Array[]>;
    ringMembers: (adminAgentName: string, channelHex: string, members: string[]) => Promise<boolean>;
    /** The kill switch: the notice ring and backstop skip an agent the operator switched off. */
    isAgentOnline: (agentId: string) => boolean;
  };
}

/**
 * M16 020-CHANADMIN — where the subscriber's admin key comes from.
 *
 * The join exchange compares the agent that answered against this. It is deliberately the ONLY
 * source: the session proves who the counterparty is and says nothing about their authority over a
 * channel, so "whoever answered" is exactly the hole the check exists to close.
 *
 * Two sources, in order:
 *  1. **This daemon's own settings**, when we publish the channel. No round trip, and no directory
 *     outage in the path of a join to a channel running on this very machine.
 *  2. **The directory**, for everything else. Before 020 there was no step 2 and this returned null
 *     for every channel not published here — so nobody could join anybody else's channel, or their
 *     own from a second device.
 *
 * ⚠️ **`null` MEANS REFUSE, AND EVERY UNKNOWN STILL ENDS HERE.** A directory that cannot be reached,
 * one that faults, a pubkey that is not a channel, and a lookup that throws all answer `null`, which
 * the exchange refuses as `admin_unresolved`. 020 removes a refusal that was firing on every
 * channel; it must not weaken the one that remains.
 */
export function createProfileAdminPubkey(deps: {
  members: ChannelMembershipStore;
  lookup: (agentId: string, channelHex: string) => Promise<ChannelAdminOutcome>;
  logger: Logger;
}): (channelHex: string, agentId: string) => Promise<AdminLookupOutcome> {
  return async function profileAdminPubkey(channelHex: string, agentId: string): Promise<AdminLookupOutcome> {
    // The ADMIN this daemon recorded, not the channel's own key — the two are different agents, and
    // comparing a key with itself is what the first version of this did.
    const settings = deps.members.settings(channelHex);
    if (settings && settings.admin_pubkey.length > 0) {
      return { ok: true, adminPubkeyHex: settings.admin_pubkey };
    }

    try {
      const outcome = await deps.lookup(agentId, channelHex);
      if (outcome.kind === "admin") return { ok: true, adminPubkeyHex: outcome.adminPubkeyHex };
      // M16 021-WAKE item 21: the reason goes BACK, not just into a log. `admin_unresolved` alone
      // cannot tell a dead stream from an unrolled directory from a channel that does not exist.
      // 038-RETESTFIX Part D: `channel_revoked` is the directory saying the channel was deleted — the
      // subscribe `lookupAdmin` below turns it into `{ kind: "revoked" }`; the exchange fails closed
      // on it like any other non-admin outcome.
      const reason = outcome.kind === "not_a_channel" ? "not_a_channel"
        : outcome.kind === "revoked" ? "channel_revoked"
        : outcome.reason;
      deps.logger.info("channel.join.admin_unresolved", { channel_pubkey: channelHex, reason });
      return { ok: false, reason };
    } catch (err: unknown) {
      // This runs inside the inbound content path. An exception escaping would surface as a broken
      // session rather than a refused join, which is a worse answer to the same question.
      const reason = extractErrorMessage(err);
      deps.logger.warn("channel.join.admin_unresolved", { channel_pubkey: channelHex, reason });
      return { ok: false, reason };
    }
  };
}

function needAgent(deps: ChannelMembershipWiringDeps, params: Record<string, unknown> | undefined, connectionId: string):
  { ok: true; agentName: string } | { ok: false; answer: Record<string, unknown> } {
  const agentName = deps.resolveCurrentAgent(connectionId, params?.["agent"] as string | undefined);
  if (agentName === null) {
    return {
      ok: false,
      answer: { ok: false, reason: "no_current_agent", guidance: "Name the agent, or select one with cello_use_agent." },
    };
  }
  return { ok: true, agentName };
}

function needChannel(params: Record<string, unknown> | undefined):
  { ok: true; channelHex: string } | { ok: false; answer: Record<string, unknown> } {
  const raw = params?.["channel"];
  if (typeof raw !== "string" || !/^[0-9a-fA-F]{64}$/.test(raw)) {
    return {
      ok: false,
      answer: { ok: false, reason: "bad_channel", guidance: "Pass the channel's 64-character hex public key as `channel`." },
    };
  }
  return { ok: true, channelHex: raw.toLowerCase() };
}

export interface ChannelMembershipWiring {
  /** M16 045-NOTICEBELL: read and apply this agent's channel notices — what a ring (the wake) calls. */
  checkNotices: (agentId: string) => Promise<void>;
  /** M16 046-JOINBELL: the directory rang this admin: `joinerHex` asked to join `channelHex`. */
  onJoinBell: (channelHex: string, joinerHex: string) => Promise<void>;
  /**
   * The same, from the raw `channel_join_bell` frame. The ring names a channel and a joiner and is
   * trusted for nothing else: a malformed one is dropped, and a forged one reads an empty slot.
   */
  onJoinBellFrame: (frame: Record<string, unknown>) => Promise<void>;
  /** Stops the notice backstop tick. */
  stop: () => void;
  /** M16 046-JOINBELL: publish relay records now, so a channel just created is joinable at once. */
  publishRelayRecordsNow: () => void;
  /**
   * The channel's CURRENT fetch key, signed, or undefined when this daemon holds no group key for
   * it. Handed to the publishing half so a re-key reaches the relays on the very next post — which
   * is what makes an ejection lock the member out at the relay and not only at the ciphertext.
   */
  currentFetchKey: (channelHex: string) => Promise<{ pubkey: Uint8Array; time_ms: number; signature: Uint8Array } | undefined>;
  /**
   * M16 021-WAKE: the channel's ACTIVE members, which is who a post's doorbell is rung for. Pending
   * and ejected rows are excluded by the store — waking a pending request would tell somebody who
   * has not been admitted that a post exists, and waking an ejected member is the thing the
   * ejection undid.
   */
  activeMembers: (channelHex: string) => string[];
  /**
   * M16 028-GROUPPUB: encrypt a post body under the channel's CURRENT group key, minting generation
   * 1 if no member has been admitted yet. Handed to the publishing half so a private channel can
   * publish before anyone joins and the first member can still read that post. Rejects
   * `channel_group_key_unavailable` when this daemon holds no admin key for the channel — never a
   * plaintext fallback. Public channels never reach here; the publisher does not encrypt them.
   */
  encryptBodyFor: (channelHex: string, seq: number, plaintext: Uint8Array) => Promise<Uint8Array>;
}

export function wireChannelMembership(deps: ChannelMembershipWiringDeps): ChannelMembershipWiring {
  const { handlers, logger } = deps;

  const members = new ChannelMembershipStore(deps.getDb(), logger);
  const subscriptions = new ChannelSubscriptionStore(deps.getDb(), logger);
  // Reads the `channel_config` table the publish half writes — for `channel info` on a channel this
  // daemon administers (035-INFOCLI item 1). Same table, read-only here.
  const channelConfig = new ChannelConfigStore(deps.getDb(), logger);
  const posterPasses = new ChannelPosterPassStore(deps.getDb(), logger);
  const lanePositions = new ChannelLanePositionStore(deps.getDb(), logger);

  /**
   * ⚠️ A CHANNEL IS AN AGENT THIS DAEMON HOLDS, looked up BY PUBKEY — the same rule the publisher
   * follows, because the pubkey is the identity and the name is a mutable label. In this release the
   * publisher and the admin are the SAME daemon; that is ASSERTED by returning null when the key is
   * not here, rather than assumed anywhere downstream.
   */
  const localChannelAdmin = (channelHex: string): LocalChannelAdmin | null => {
    const channel = deps.loadedAgents.find((a) => a.pubkey.toLowerCase() === channelHex.toLowerCase());
    if (!channel) return null;

    /**
     * ⚠️ **THE ADMIN IS A DIFFERENT AGENT FROM THE CHANNEL, and reading the channel's own key here
     * was a defect.** The channel signs posts and never converses; the ADMIN holds the sessions and
     * answers join requests. A subscriber compares the agent that answered against the admin key, so
     * returning the channel's key made that comparison a key against itself — it could never
     * succeed, in either direction, and the check was safe only by never passing.
     *
     * The admin is whichever agent ran the channel's setup, recorded then. No row, or an agent this
     * daemon no longer holds, means this daemon cannot answer for the channel — which is the truth.
     */
    const settings = members.settings(channelHex);
    if (!settings || settings.admin_pubkey.length === 0) return null;
    const adminAgent = deps.loadedAgents.find((a) => a.pubkey.toLowerCase() === settings.admin_pubkey.toLowerCase());
    if (!adminAgent) return null;
    const adminKp = deps.keyProviders.get(adminAgent.name);
    if (!adminKp) return null;

    return {
      agentId: deps.resolveAgentId(adminAgent.name),
      adminPubkeyHex: adminAgent.pubkey,
      channelKeyProvider: channel.keyProvider,
      adminKeyProvider: adminKp,
    };
  };

  /**
   * The join path carries an agent ID; `signalingFor` is keyed by the daemon's agent NAME. Resolved
   * the same way `keyProviderFor` does it just below — by walking the loaded agents, because the ID
   * is the stable key and the name is a mutable label.
   */
  const signalingForAgentId = (agentId: string): SignalingLike | null => {
    const agent = deps.loadedAgents.find((a) => deps.resolveAgentId(a.name) === agentId);
    return agent ? deps.signalingFor(agent.name) : null;
  };

  const adminLookup = createChannelAdminLookup({ signalingFor: signalingForAgentId, logger });
  const profileAdminPubkey = createProfileAdminPubkey({ members, logger, lookup: adminLookup });

  const keyProviderFor = (agentId: string): KeyProvider | null => {
    const agent = deps.loadedAgents.find((a) => deps.resolveAgentId(a.name) === agentId);
    return agent ? (deps.keyProviders.get(agent.name) ?? null) : null;
  };


  // Late-bound: the publishing half (which owns the relay client) is built after this one.
  const noticeRelays = {
    deposit: (relays: string[], record: Uint8Array) => deps.noticeTransport().depositNotice(relays, record),
    fetch: (relays: string[], slot: Uint8Array) => deps.noticeTransport().fetchNotices(relays, slot),
  };
  const ringMembers = (agentName: string, ch: string, list: string[]): Promise<boolean> =>
    deps.noticeTransport().ringMembers(agentName, ch, list);

  /**
   * M16 045-NOTICEBELL: write one sealed notice for one member into the channel's relays. `false` =
   * no relay took it (logged by the writer). A throw (no key, a bad member key) is logged and false —
   * one member must never stop an eject or a pass round.
   */
  const writeNotice = async (
    channelHex: string, memberHex: string, type: "pass" | "eject" | "group_key" | "join_answer", body: Uint8Array,
  ): Promise<boolean> => {
    const admin = localChannelAdmin(channelHex);
    const relays = members.settings(channelHex)?.relays ?? [];
    if (!admin || relays.length === 0) return false;
    try {
      return await writeChannelNotice({ relays: noticeRelays, logger }, admin.channelKeyProvider, relays, memberHex, type, body);
    } catch (err: unknown) {
      logger.warn("channel.notice.unwritten", { channel_pubkey: channelHex, member_pubkey: memberHex, type, reason: extractErrorMessage(err) });
      return false;
    }
  };

  /** The admin agent's NAME for a channel this daemon administers — the ring rides its stream. */
  const adminAgentNameFor = (channelHex: string): string | null => {
    const adminHex = members.settings(channelHex)?.admin_pubkey.toLowerCase();
    return deps.loadedAgents.find((a) => a.pubkey.toLowerCase() === adminHex)?.name ?? null;
  };

  const raiseNotice = (event: string, channelHex: string, subscriberHex: string): void => {
    logger.info(event, { channel_pubkey: channelHex, subscriber_pubkey: subscriberHex });
    // M16 032-NOTICES: a pending request was a log line nobody reads. Ring the admin's join-request
    // doorbell too — the admin agent is resolved from the channel, since the notice carries only the
    // channel and the subscriber. No local admin (a channel this daemon does not administer) means
    // there is nobody here to wake, which the getter below simply skips.
    const admin = localChannelAdmin(channelHex);
    if (admin) deps.notify.channelJoinRequest(admin.agentId, channelHex, subscriberHex);
  };

  // 043-POSTERS: the posting setting, listed posters, passes and their hourly renewal (the lease).
  const postingAdmin = createChannelPostingAdmin({
    logger, config: channelConfig, members, grants: new ChannelPosterGrantStore(deps.getDb(), logger),
    channelKeyFor: (ch) => localChannelAdmin(ch)?.channelKeyProvider ?? null,
    adminAgentNameFor,
    postingChannels: () => channelConfig.postingChannels(),
    // 045-NOTICEBELL: a pass is a sealed notice plus a ring; a removal is the info record plus a ring.
    sendPass: async (ch, poster, passCbor, memberList) => {
      if (!(await writeNotice(ch, poster, "pass", encodeNoticePassBody(passCbor, memberList)))) return false;
      const name = adminAgentNameFor(ch);
      if (name) await ringMembers(name, ch, [poster]);
      return true;
    },
    ringPoster: async (ch, poster) => {
      const name = adminAgentNameFor(ch);
      if (name) await ringMembers(name, ch, [poster]);
    },
    depositInfo: (agentName, ch) => deps.depositChannelInfo?.(agentName, ch) ?? Promise.resolve(),
  });
  postingAdmin.start();

  const joinRequests = new ChannelJoinRequestStore(deps.getDb());
  const joinRelays = {
    depositJoin: (relays: string[], record: Uint8Array) => deps.noticeTransport().depositJoin(relays, record),
    fetchJoin: (relays: string[], slot: Uint8Array) => deps.noticeTransport().fetchJoins(relays, slot),
    fetchInfo: (relays: string[], ch: string) => deps.fetchChannelInfo(relays, ch),
  };

  /** M16 046-JOINBELL — the admin half: a ring names a joiner; read the slot, decide, answer, ring back. */
  const joinAdmin = createChannelJoinAdmin({
    logger, members, subscriptions, seen: new ChannelJoinSeenStore(deps.getDb()), relays: joinRelays,
    localChannelAdmin,
    writeAnswer: (ch, joiner, answer) => writeNotice(ch, joiner, "join_answer", answer),
    ringJoiner: async (ch, joiner) => {
      const name = adminAgentNameFor(ch);
      if (name) await ringMembers(name, ch, [joiner]);
    },
    raiseRequest: (ch, joiner) => raiseNotice("channel.join.pending", ch, joiner),
    // 043-POSTERS: `members` posting issues a pass the moment someone is admitted.
    onAdmitted: (ch, sub) => { void postingAdmin.onAdmitted(ch, sub).catch(() => {}); },
  });

  /** M16 046-JOINBELL — the joiner half: relays from the directory's record, a signed request, a ring. */
  const joiner = createChannelJoiner({
    logger, requests: joinRequests, relays: joinRelays, keyProviderFor,
    directory: {
      lookup: (agentId, ch) => adminLookup(agentId, ch),
      ring: async (agentName, ch) => {
        const signaling = deps.signalingFor(agentName);
        if (!signaling) return { ok: false, reason: "signaling_unavailable" };
        const res = await askDirectoryAboutChannel(signaling, { type: "channel_join_ring", channel_pubkey: new Uint8Array(Buffer.from(ch, "hex")) },
          ["channel_join_ring_ack", "channel_join_ring_error"], ch);
        if (!res.ok) return res;
        if (res.frame["type"] === "channel_join_ring_ack") return { ok: true };
        return { ok: false, reason: typeof res.frame["reason"] === "string" ? res.frame["reason"] : "refused" };
      },
    },
  });

  /**
   * M16 045-NOTICEBELL — the member half: on a ring (the wake) or the backstop tick, read the
   * directory's revocation, the info record and this agent's own notice slots; verify; apply; ring
   * the agent's doorbell once on a real change.
   */
  const noticeReader = createChannelNoticeReader({
    logger, subscriptions, posterPasses, seen: new ChannelNoticeSeenStore(deps.getDb()), relays: noticeRelays,
    keyProviderFor,
    fetchInfo: (relays, ch) => deps.fetchChannelInfo(relays, ch),
    channelRevoked: async (agentId, ch) => (await adminLookup(agentId, ch)).kind === "revoked",
    onMembershipEnded: (agentId, ch, reason) => deps.notify.channelMembershipEnded(agentId, ch, reason),
    onPosterRemoved: (agentId, ch) => deps.notify.channelPosterRemoved(agentId, ch),
    joins: {
      requests: joinRequests,
      apply: (o, answer) => applyJoinAnswer({ subscriptions, requests: joinRequests, logger, keyProviderFor }, o, answer),
      onAnswer: (agentId, ch, outcome, reason) => {
        deps.notify.channelJoinAnswer(agentId, ch, outcome, reason);
        // 038-RETESTFIX Part B: a fresh subscription collects the channel's existing posts at once.
        if (outcome === "admitted") deps.collectNow(agentId);
      },
    },
  });
  const noticeTimer = setInterval(() => {
    // A throw inside a timer callback is an uncaught exception and takes the daemon down, and the
    // two async calls would otherwise reject unhandled — so every failure here is a log line.
    const tickFailed = (err: unknown): void => {
      logger.warn("channel.notice.tick_failed", { reason: extractErrorMessage(err) });
    };
    try {
      joinAdmin.sweepLapsed(members.administeredChannels());
      const agentIds = new Set([...subscriptions.active().map((s) => s.agent_id), ...joinRequests.agentsWithRequests()]);
      for (const agentId of agentIds) {
        if (!deps.noticeTransport().isAgentOnline(agentId)) continue;
        noticeReader.checkNotices(agentId).catch(tickFailed);
        // 046: re-ring each outstanding join request — an admin offline at the first ring hears this one.
        const name = deps.loadedAgents.find((a) => deps.resolveAgentId(a.name) === agentId)?.name;
        if (name) joiner.reRing(name, agentId).catch(tickFailed);
      }
    } catch (err: unknown) {
      tickFailed(err);
    }
  }, NOTICE_BACKSTOP_TICK_MS);
  noticeTimer.unref();


  /**
   * M16 046-JOINBELL Decision 10 — publish each administered channel's relay record to the directory,
   * signed by the channel key, and again whenever its relays change. A stranger finds where to ask to
   * join ONLY through this record. Checked every RELAY_RECORD_TICK_MS; sends nothing when the relays
   * last acknowledged in this process are unchanged.
   */
  const publishedRelays = new Map<string, string>();
  const publishRelayRecords = async (): Promise<void> => {
    for (const channelHex of members.administeredChannels()) {
      const admin = localChannelAdmin(channelHex);
      const relays = members.settings(channelHex)?.relays ?? [];
      const name = adminAgentNameFor(channelHex);
      const signaling = name ? deps.signalingFor(name) : null;
      if (!admin || relays.length === 0 || !signaling || publishedRelays.get(channelHex) === relays.join("\n")) continue;
      try {
        const record = await signChannelRelayRecord(admin.channelKeyProvider, { relays, signed_at: Date.now() });
        const res = await askDirectoryAboutChannel(signaling,
          { type: "channel_relay_record_set", channel_pubkey: record.channel_pubkey, record: encodeChannelRelayRecord(record) },
          ["channel_relay_record_ack", "channel_relay_record_error"], channelHex);
        if (res.ok && res.frame["type"] === "channel_relay_record_ack") {
          publishedRelays.set(channelHex, relays.join("\n"));
          logger.info("channel.relay_record.published", { channel_pubkey: channelHex, relays: relays.length });
        } else {
          logger.warn("channel.relay_record.unpublished", { channel_pubkey: channelHex, reason: res.ok ? String(res.frame["reason"] ?? "refused") : res.reason });
        }
      } catch (err: unknown) {
        logger.warn("channel.relay_record.unpublished", { channel_pubkey: channelHex, reason: extractErrorMessage(err) });
      }
    }
  };
  const relayRecordTimer = setInterval(() => {
    // The channel list is read outside the per-channel try, so a failure there (a closed database)
    // would otherwise escape as an unhandled rejection.
    publishRelayRecords().catch((err: unknown) => {
      logger.warn("channel.relay_record.tick_failed", { reason: extractErrorMessage(err) });
    });
  }, RELAY_RECORD_TICK_MS);
  relayRecordTimer.unref();

  // ─── Operator verbs ───────────────────────────────────────────────────────────────────────────

  /**
   * M16 022-SUBSCRIBE — the three verbs that make the other eleven mean anything. Until this, no
   * production code sent a join request and nothing read a post back out.
   */
  const subscribe = createChannelSubscribe({
    logger,
    subscriptions,
    inbox: new ChannelInboxStore(deps.getDb(), logger),
    // 043-POSTERS: poster lanes are read from their own positions, and each post names its writer.
    lanePositions,
    posterName: (agentId, pubkeyHex) => {
      const agent = deps.loadedAgents.find((a) => deps.resolveAgentId(a.name) === agentId);
      return agent ? (deps.contactMoniker?.(agent.name, pubkeyHex) ?? null) : null;
    },
    /**
     * ⚠️ **THE SAME SOURCE THE ADMIN CHECK USES, and the first version used a different one.** It
     * went straight to the directory, so joining a channel THIS daemon administers answered
     * `unavailable` — while the check that runs on the answer resolves it locally. Two sources for
     * one fact is how they drift.
     */
    lookupAdmin: async (agentId, channelHex) => {
      const found = await profileAdminPubkey(channelHex, agentId);
      if (found.ok) return { kind: "admin" as const, adminPubkeyHex: found.adminPubkeyHex };
      if (found.reason === "not_a_channel") return { kind: "not_a_channel" as const };
      // 038-RETESTFIX Part D: the directory said the channel is revoked (deleted) — surfaced so
      // `info`/`join` report `channel_deleted` rather than a generic `unavailable`.
      if (found.reason === "channel_revoked") return { kind: "revoked" as const };
      return { kind: "unavailable" as const, reason: found.reason };
    },
    /**
     * 035-INFOCLI item 1: what THIS daemon knows about a channel it administers — the SAME
     * `channel_config` table the publisher half writes (setup/create), read here for `info`. Reading
     * one table from a second store instance is one source of truth, not two.
     */
    channelConfig: (channelHex) => channelConfig.get(channelHex),
    decrypt: (agentId, channelHex, seq, body) => {
      const keys = subscriptions.keysFor(agentId, channelHex);
      const out = decryptBody(keys, new Uint8Array(Buffer.from(channelHex, "hex")), seq, body);
      return Promise.resolve(out.ok ? out.plaintext : null);
    },
    // 041-HELPTRUTH Part C: a member's `info` refreshes the description from the channel's relays.
    fetchInfo: (relays, channelHex) => deps.fetchChannelInfo(relays, channelHex),
  });

  handlers.set("cello_channel_info", async (params, connectionId) => {
    const agent = needAgent(deps, params, connectionId);
    if (!agent.ok) return agent.answer;
    const channel = needChannel(params);
    if (!channel.ok) return channel.answer;
    return subscribe.info(deps.resolveAgentId(agent.agentName), channel.channelHex);
  });

  handlers.set("cello_channel_join", async (params, connectionId) => {
    const agent = needAgent(deps, params, connectionId);
    if (!agent.ok) return agent.answer;
    const channel = needChannel(params);
    if (!channel.ok) return channel.answer;
    const note = typeof params?.["note"] === "string" ? (params["note"]) : undefined;
    return joiner.join(agent.agentName, deps.resolveAgentId(agent.agentName), channel.channelHex, note);
  });

  handlers.set("cello_channel_read", async (params, connectionId) => {
    const agent = needAgent(deps, params, connectionId);
    if (!agent.ok) return agent.answer;
    const channel = needChannel(params);
    if (!channel.ok) return channel.answer;
    return subscribe.read(deps.resolveAgentId(agent.agentName), channel.channelHex, params?.["all"] === true);
  });

  /**
   * The channels one agent follows and runs. `listedFor` (034-LIFECYCLE) shows active AND
   * ejected/closed so an operator whose channel went quiet sees WHY, and hides only `left`, which is
   * their own choice; `active()` (collector-only) would have dropped the ejected and closed ones.
   */
  const channelsForAgent = (agentName: string): Array<Record<string, unknown>> => {
    const agentId = deps.resolveAgentId(agentName);
    // Channels this agent FOLLOWS — role "member" (041-HELPTRUTH Part B).
    const rows: Array<Record<string, unknown>> = subscriptions.listedFor(agentId).map((s) => ({
      channel: s.channel_pubkey,
      moniker: s.moniker,
      access: s.access,
      status: s.status,
      delivered_through: s.delivered_through,
      processed_through: s.processed_through,
      // What the operator actually wants to know: how much is waiting.
      // 043-POSTERS: the admin lane plus every poster lane.
      unread: Math.max(0, s.delivered_through - s.processed_through) + lanePositions.unread(agentId, s.channel_pubkey),
      role: "member",
    }));
    // 041-HELPTRUTH Part B: channels this agent RUNS — the config rows whose admin is this agent's
    // key. The help says `cello channels` lists what you follow AND publish; before this it listed
    // subscriptions only, so an admin who ran four channels and followed none saw an empty list.
    const agentPubkey = deps.loadedAgents.find((a) => a.name === agentName)?.pubkey;
    if (agentPubkey !== undefined) {
      for (const c of channelConfig.listForAdmin(agentPubkey)) {
        // Only a live channel identity: an ordinary agent's key (a setup mistake) or a deleted
        // channel's key leaves a settings row behind that is not a channel anyone runs.
        const holder = deps.loadedAgents.find((a) => a.pubkey.toLowerCase() === c.channel_pubkey.toLowerCase());
        if (!holder || !deps.isChannelAgent(holder.name)) continue;
        rows.push({
          channel: c.channel_pubkey,
          // The channel identity's display name, looked up by its pubkey (never by name).
          name: deps.loadedAgents.find((a) => a.pubkey.toLowerCase() === c.channel_pubkey.toLowerCase())?.name ?? null,
          access: c.access,
          relays: c.relays,
          posts: deps.channelLastSeq(c.channel_pubkey),
          role: "admin",
        });
      }
    }
    return rows;
  };

  handlers.set("cello_channels", async (params, connectionId) => {
    const explicit = typeof params?.["agent"] === "string" ? (params["agent"]) : undefined;
    // 041-HELPTRUTH review LOW: an explicit `--agent` that names no operator agent is an ERROR that
    // names it, not an empty list — an empty list reads as "this agent runs/follows nothing", which
    // is a different, misleading fact. A channel identity is not an operator agent, so it is rejected
    // here too. (No explicit `--agent` falls through to the current-agent / all-agents branches.)
    if (explicit !== undefined && !deps.loadedAgents.some((a) => a.name === explicit && !deps.isChannelAgent(a.name))) {
      return Promise.resolve({
        ok: false, reason: "agent_unknown",
        guidance: `No agent named '${explicit}' on this daemon. Run 'cello agents' to see the agents you have.`,
      });
    }
    const current = deps.resolveCurrentAgent(connectionId, explicit);
    // 041-HELPTRUTH Part A: with neither `--agent` nor a selected agent, list EVERY operator agent's
    // channels grouped, instead of refusing `no_current_agent` — a shell that never selected an agent
    // still wants to see what is here. Channel identities are not operator agents and are left out.
    if (current === null) {
      return Promise.resolve({
        ok: true,
        agents: deps.loadedAgents
          .filter((a) => !deps.isChannelAgent(a.name))
          .map((a) => ({ agent: a.name, channels: channelsForAgent(a.name) })),
      });
    }
    return Promise.resolve({ ok: true, channels: channelsForAgent(current) });
  });

  handlers.set("cello_channel_set_moniker", async (params, connectionId) => {
    const agent = needAgent(deps, params, connectionId);
    if (!agent.ok) return agent.answer;
    const channel = needChannel(params);
    if (!channel.ok) return channel.answer;
    const moniker = params?.["moniker"];
    if (typeof moniker !== "string" || moniker.length === 0) {
      return { ok: false, reason: "bad_moniker", guidance: "Pass a `moniker`: what you want to call this channel." };
    }
    subscriptions.setMoniker(deps.resolveAgentId(agent.agentName), channel.channelHex, moniker);
    return Promise.resolve({ ok: true, channel: channel.channelHex, moniker });
  });

  handlers.set("cello_channel_leave", async (params, connectionId) => {
    const agent = needAgent(deps, params, connectionId);
    if (!agent.ok) return agent.answer;
    const channel = needChannel(params);
    if (!channel.ok) return channel.answer;
    // 046-JOINBELL Decision 12: leaving a channel you have only ASKED to join withdraws the request.
    const agentId = deps.resolveAgentId(agent.agentName);
    if (joinRequests.get(agentId, channel.channelHex) && !subscriptions.get(agentId, channel.channelHex)) {
      const withdrawn = await joiner.withdraw(agent.agentName, agentId, channel.channelHex);
      return withdrawn.ok
        ? { ok: true, channel: channel.channelHex, withdrawn: true, guidance: "Your join request was withdrawn." }
        : { ok: false, reason: withdrawn.reason };
    }
    try {
      subscriptions.markLeft(agentId, channel.channelHex);
    } catch (err: unknown) {
      return { ok: false, reason: extractErrorMessage(err) };
    }
    return Promise.resolve({
      ok: true,
      channel: channel.channelHex,
      // ⚠️ LEAVING IS LOCAL, and saying so matters: an operator who thinks the publisher was told
      // may expect to be removed from a member list they are still on.
      guidance: "You have stopped collecting this channel. Nothing was sent — the publisher does not know, and your keys are kept so old posts stay readable.",
    });
  });

  /**
   * Eject a member and re-key the channel.
   *
   * ⚠️ **THE GENERATION BUMP AND THE STATUS FLIP ARE ONE TRANSACTION** (in the store). What happens
   * HERE is the delivery, and a delivery that fails does NOT undo the ejection: the member is out at
   * the relay the moment the next deposit carries the new fetch key, whether or not every remaining
   * member has collected their new key yet.
   *
   * 045-NOTICEBELL: the new key reaches each remaining member as a sealed `group_key` notice on the
   * relays, read on the ring or the member's backstop tick — never a session. A member whose notice no
   * relay took is named in `unreached`.
   */
  handlers.set("cello_channel_eject", async (params, connectionId) => {
    const agent = needAgent(deps, params, connectionId);
    if (!agent.ok) return agent.answer;
    const channel = needChannel(params);
    if (!channel.ok) return channel.answer;
    const subscriber = params?.["subscriber"];
    if (typeof subscriber !== "string" || !/^[0-9a-fA-F]{64}$/.test(subscriber)) {
      return { ok: false, reason: "bad_subscriber", guidance: "Pass the member's 64-character hex public key as `subscriber`." };
    }

    const admin = localChannelAdmin(channel.channelHex);
    if (!admin) {
      return {
        ok: false, reason: "channel_not_local",
        guidance: "This daemon does not hold that channel's key, and ejecting is the admin's own act. Cross-daemon admin is not in this release.",
      };
    }

    let outcome: { generation: number; remaining: string[] };
    try {
      outcome = members.eject(channel.channelHex, subscriber.toLowerCase());
    } catch (err: unknown) {
      return { ok: false, reason: extractErrorMessage(err) };
    }

    /**
     * The new key, wrapped once per REMAINING member — the ejected one is simply not in this list.
     *
     * ⚠️ STORED FIRST, against the admin's own agent id. If the process died between minting and
     * storing, the channel's settings would say generation N while no key for N existed anywhere:
     * every subsequent publish would encrypt under a key no member was ever given, and the channel
     * would go permanently silent for everyone rather than for the one person ejected.
     */
    const gk = generateGroupKey(outcome.generation);
    subscriptions.addKey(admin.agentId, channel.channelHex, gk, Date.now());
    const channelPubkey = await admin.channelKeyProvider.getPublicKey();
    const ejectedHex = subscriber.toLowerCase();

    /**
     * M16 045-NOTICEBELL: the new key goes to each REMAINING member as a sealed `group_key` notice on
     * the channel's relays — never a session. A member whose notice no relay took is named in
     * `unreached`; one failure never stops the loop.
     */
    let delivered = 0;
    const unreached: string[] = [];
    for (const member of outcome.remaining) {
      let written = false;
      try {
        const bundle = await wrapGroupKeyFor(gk, channelPubkey, new Uint8Array(Buffer.from(member, "hex")), admin.adminKeyProvider);
        written = await writeNotice(channel.channelHex, member, "group_key", bundle);
      } catch (err: unknown) {
        logger.warn("channel.rekey.member_unreached", {
          channel_pubkey: channel.channelHex, member_pubkey: member, generation: outcome.generation, reason: extractErrorMessage(err),
        });
      }
      if (written) delivered += 1;
      else unreached.push(member);
    }

    logger.info("channel.rekey.completed", {
      channel_pubkey: channel.channelHex,
      generation: outcome.generation,
      member_count: outcome.remaining.length,
      delivered_count: delivered,
      failed_count: unreached.length,
    });

    // The ejected member's own notice, then ONE ring for everyone the eject concerns. The ejection
    // holds at the relay regardless of whether they are told.
    const memberNotified = await writeNotice(channel.channelHex, ejectedHex, "eject", encodeNoticeEjectBody(channelPubkey));
    if (!memberNotified) {
      logger.info("channel.eject.notice.unreached", { channel_pubkey: channel.channelHex, member_pubkey: ejectedHex });
    }
    await ringMembers(agent.agentName, channel.channelHex, [ejectedHex, ...outcome.remaining.filter((m) => !unreached.includes(m))]);
    // 043-POSTERS: an ejected member's posting pass is revoked and never renewed.
    await postingAdmin.onEjected(channel.channelHex, ejectedHex);

    return {
      ok: true,
      channel: channel.channelHex,
      generation: outcome.generation,
      delivered,
      unreached,
      member_notified: memberNotified,
      guidance: unreached.length > 0
        ? `${String(unreached.length)} member(s) could not be given the new key (no relay took their notice) and still hold the old one. The ejection itself is done.`
        : undefined,
    };
  });

  /**
   * M16 034-LIFECYCLE — delete a channel this daemon administers.
   *
   * ⚠️ **ADMIN ONLY, AND THE CHANNEL KEY MUST BE HELD LOCALLY** — `localChannelAdmin` returns null
   * otherwise, and a delete never runs for a channel this daemon does not hold. In order:
   *   (a) read who to tell — every active AND pending member;
   *   (b) prune the whole log on both relays (needs the channel key the retire purges);
   *   (c) retire the channel identity through `cello_remove_agent` — revocation at the directory;
   *   (d) ring the members (045-NOTICEBELL), so their first check already reads "deleted".
   * Unreachable members are named, not fatal — the channel is gone regardless of who was told.
   */
  handlers.set("cello_channel_delete", async (params, connectionId) => {
    const agent = needAgent(deps, params, connectionId);
    if (!agent.ok) return agent.answer;
    const channel = needChannel(params);
    if (!channel.ok) return channel.answer;

    const admin = localChannelAdmin(channel.channelHex);
    if (!admin) {
      return {
        ok: false, reason: "channel_not_local",
        guidance: "This daemon does not hold that channel's key, and deleting is the admin's own act. Cross-daemon admin is not in this release.",
      };
    }

    // (a) Who to tell: every active and pending member, read NOW — a successful retire forgets these rows.
    const toNotify = [...members.activeMembers(channel.channelHex), ...members.pendingMembers(channel.channelHex)];

    // (b) Prune everything on both relays. Done BEFORE the retire, which purges the channel key the
    // prune signature needs.
    const pruned = await deps.pruneAllPosts(agent.agentName, channel.channelHex);

    // (c) Retire the channel identity through the EXISTING remove path, addressed by the channel's
    // display NAME (the pubkey is the identity; remove takes the name).
    //
    // ⚠️ **A FAILED RETIRE IS REPORTED, NOT SWALLOWED.** The notices and prune already ran, so the
    // delete is still `ok: true` — but the channel identity is STILL LOADED, and answering a bare
    // `ok: true` hid that. `retired: false` with the reason and operator guidance says what did not
    // happen and how to finish it by hand.
    const channelAgentName = deps.loadedAgents
      .find((a) => a.pubkey.toLowerCase() === channel.channelHex)?.name;
    const removeAgent = deps.handlers.get("cello_remove_agent");
    let retired = false;
    let retireReason: string | undefined;
    if (channelAgentName !== undefined && removeAgent) {
      const removed = (await removeAgent({ name: channelAgentName }, connectionId)) as { ok?: boolean; reason?: string };
      retired = removed.ok === true;
      if (!retired) {
        retireReason = removed.reason ?? "retire_failed";
        logger.warn("channel.delete.retire_failed", {
          channel_pubkey: channel.channelHex, name: channelAgentName, reason: retireReason,
        });
      }
    } else {
      retireReason = "channel_agent_not_loaded";
      logger.warn("channel.delete.retire_failed", {
        channel_pubkey: channel.channelHex, reason: retireReason,
      });
    }

    /**
     * (d) M16 045-NOTICEBELL: RING the members AFTER the retire has recorded the revocation at the
     * directory, so a rung member's first check already reads "deleted". The ring rides the ADMIN
     * agent's stream (the directory accepts a revoked channel's recorded admin), so the channel key
     * the retire purged is not needed. No session is opened. A ring that could not be sent leaves
     * them to find the revocation on their backstop tick.
     */
    const rung = await ringMembers(agent.agentName, channel.channelHex, toNotify);
    const membersNotified = rung ? toNotify.length : 0;
    const membersUnreached: string[] = rung ? [] : toNotify;
    if (!rung) {
      for (const member of toNotify) {
        logger.info("channel.delete.notice.unreached", { channel_pubkey: channel.channelHex, member_pubkey: member });
      }
    }

    /**
     * 039-NEWCHANFIX Part B: ONLY after a SUCCESSFUL retire, forget the channel's local admin rows —
     * its settings/config and its member rows — so a deleted channel no longer answers `info`/`join`
     * from local state and asks the directory like any other daemon, which is where the revoked
     * answer comes from. The post log is KEPT (the admin's own record). A FAILED retire forgets
     * nothing: the channel identity is still loaded and the operator's guidance to finish by hand
     * still needs these rows.
     */
    if (retired) {
      // One call clears both: the settings and the config are the same `channel_config` row.
      members.forget(channel.channelHex);
      logger.info("channel.delete.local_forgotten", { channel_pubkey: channel.channelHex });
    }

    logger.info("channel.deleted", {
      channel_pubkey: channel.channelHex,
      members_notified: membersNotified,
      members_unreached: membersUnreached.length,
      relays_pruned: pruned.relays.filter((r) => r.ok).length,
      retired,
    });

    return {
      ok: true,
      channel: channel.channelHex,
      members_notified: membersNotified,
      members_unreached: membersUnreached,
      relays: pruned.relays,
      retired,
      ...(retired ? {} : { retire_reason: retireReason }),
      // Members are told and the relays are pruned either way. When the identity did not retire, the
      // channel is still loaded on this daemon — say so and how to finish it. Retiring an agent is
      // terminal-only (no MCP tool), so the guidance names the CLI verb, not a cello_* token.
      ...(retired ? {} : {
        guidance: `Members were notified and the relays were pruned, but the channel identity '${channelAgentName ?? channel.channelHex}' is still loaded (${retireReason ?? "retire_failed"}). Run cello remove-agent '${channelAgentName ?? ""}' to retire it.`,
      }),
    };
  });

  handlers.set("cello_channel_approve", async (params, connectionId) => {
    const agent = needAgent(deps, params, connectionId);
    if (!agent.ok) return agent.answer;
    const channel = needChannel(params);
    if (!channel.ok) return channel.answer;
    const subscriber = params?.["subscriber"];
    if (typeof subscriber !== "string" || !/^[0-9a-fA-F]{64}$/.test(subscriber)) {
      return { ok: false, reason: "bad_subscriber" };
    }
    const result = await joinAdmin.approve(channel.channelHex, subscriber.toLowerCase());
    return result.ok ? { ok: true, channel: channel.channelHex } : { ok: false, reason: result.reason };
  });

  // ─── 043-POSTERS: who may post ───────────────────────────────────────────────────────────────
  handlers.set("cello_channel_posting", async (params, connectionId) => {
    const agent = needAgent(deps, params, connectionId);
    if (!agent.ok) return agent.answer;
    const channel = needChannel(params);
    if (!channel.ok) return channel.answer;
    const lease = params?.["lease_days"];
    return postingAdmin.setPosting(channel.channelHex, params?.["posting"] as "admin" | "listed" | "members",
      typeof lease === "number" ? lease : undefined);
  });

  const posterVerb = async (
    act: "add" | "remove", params: Record<string, unknown> | undefined, connectionId: string, poster: unknown,
  ): Promise<unknown> => {
    const agent = needAgent(deps, params, connectionId);
    if (!agent.ok) return agent.answer;
    const channel = needChannel(params);
    if (!channel.ok) return channel.answer;
    if (typeof poster !== "string" || !/^[0-9a-fA-F]{64}$/.test(poster)) {
      return { ok: false, reason: "bad_poster", guidance: "Pass the agent's 64-character hex public key as `poster`." };
    }
    return act === "add"
      ? postingAdmin.addPoster(channel.channelHex, poster.toLowerCase())
      : postingAdmin.removePoster(channel.channelHex, poster.toLowerCase());
  };
  handlers.set("cello_channel_poster_add", (params, connectionId) => posterVerb("add", params, connectionId, params?.["poster"]));
  handlers.set("cello_channel_poster_remove", (params, connectionId) => posterVerb("remove", params, connectionId, params?.["poster"]));

  handlers.set("cello_channel_refuse", async (params, connectionId) => {
    const agent = needAgent(deps, params, connectionId);
    if (!agent.ok) return agent.answer;
    const channel = needChannel(params);
    if (!channel.ok) return channel.answer;
    const subscriber = params?.["subscriber"];
    if (typeof subscriber !== "string" || !/^[0-9a-fA-F]{64}$/.test(subscriber)) {
      return { ok: false, reason: "bad_subscriber" };
    }
    const result = await joinAdmin.refuse(channel.channelHex, subscriber.toLowerCase());
    return result.ok ? { ok: true, channel: channel.channelHex } : { ok: false, reason: result.reason };
  });

  return {
    // The kill switch holds here too: a ring for a switched-off agent reads nothing.
    checkNotices: (agentId: string) => (deps.noticeTransport().isAgentOnline(agentId) ? noticeReader.checkNotices(agentId) : Promise.resolve()),
    onJoinBell: (channelHex: string, joinerHex: string) => joinAdmin.onBell(channelHex, joinerHex),
    onJoinBellFrame: (frame: Record<string, unknown>) => {
      const asHex = (v: unknown): string | null => (v instanceof Uint8Array && v.length === 32 ? Buffer.from(v).toString("hex") : null);
      const channelHex = asHex(frame["channel_pubkey"]);
      const joinerHex = asHex(frame["joiner_pubkey"]);
      return channelHex && joinerHex ? joinAdmin.onBell(channelHex, joinerHex) : Promise.resolve();
    },
    stop: () => { clearInterval(noticeTimer); clearInterval(relayRecordTimer); },
    /** 046-JOINBELL: publish relay records now — a channel just created is joinable at once, not a tick later. */
    publishRelayRecordsNow: (): void => {
      publishRelayRecords().catch((err: unknown) => {
        logger.warn("channel.relay_record.tick_failed", { reason: extractErrorMessage(err) });
      });
    },
    activeMembers: (channelHex: string) => members.activeMembers(channelHex),
    /**
     * ⚠️ **NO PLAINTEXT FALLBACK, EVER.** No admin key held for this channel, or no group key mint
     * possible (a public channel, which never reaches here anyway), throws
     * `channel_group_key_unavailable` — the publisher must refuse rather than deposit readable bytes
     * under an `access` that promises members-only.
     */
    encryptBodyFor: async (channelHex, seq, plaintext) => {
      const admin = localChannelAdmin(channelHex);
      if (!admin) throw new Error("channel_group_key_unavailable");
      const gk = ensureCurrentGroupKey({ members, subscriptions, now: Date.now }, admin.agentId, channelHex);
      if (!gk) throw new Error("channel_group_key_unavailable");
      const out = encryptBody(gk, new Uint8Array(Buffer.from(channelHex, "hex")), seq, plaintext);
      logger.debug("channel.post.encrypted", { channel_pubkey: channelHex, seq, generation: gk.generation });
      return Promise.resolve(out);
    },
    currentFetchKey: async (channelHex) => {
      const admin = localChannelAdmin(channelHex);
      if (!admin) return undefined;
      // The NEWEST generation this daemon holds for its own channel. `keysFor` returns them newest
      // first, so a re-key is picked up by the next publish without anything else being told.
      const newest = subscriptions.keysFor(admin.agentId, channelHex)[0];
      if (!newest) return undefined;

      const fetchKey = await deriveFetchKey(newest, new Uint8Array(Buffer.from(channelHex, "hex")));
      const timeMs = Date.now();
      /**
       * ⚠️ SIGNED WITH THE CHANNEL KEY, and it must be: the post's signature does not cover the
       * fetch key, so without one of its own anyone who could read a post could replay its bytes
       * inside the clock window, attach their own key and take the channel over.
       */
      const signature = await admin.channelKeyProvider.sign(
        buildChannelFetchKeyTbs(new Uint8Array(Buffer.from(channelHex, "hex")), fetchKey.publicKey, timeMs),
      );
      return { pubkey: fetchKey.publicKey, time_ms: timeMs, signature };
    },
  };
}
