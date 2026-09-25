/**
 * M16 022-SUBSCRIBE — the half nobody could reach.
 *
 * Fifteen orders built publish, relay, fetch, decrypt, membership, ejection and a push doorbell,
 * and `encodeChannelJoinRequest` was called by nothing outside a test. This is what starts a
 * subscription and what reads it back.
 *
 * ⚠️ **A SUBSCRIBER NEVER HANDLES A RELAY.** Relays are the publisher's choice and the publisher's
 * problem. Every entry point here takes a channel's public key and nothing else: the directory says
 * who administers it, a session with that admin carries the request, and the ACCEPTANCE supplies
 * the relays, access, guidance and the group key. An earlier draft of the order had `info` taking a
 * relay argument — wrong, and contradicted by the frame 019 already shipped.
 */
import type { Logger } from "./types.js";
import {
  encodeChannelJoinRequest, decodeChannelInfo, verifyChannelInfo, type ChannelAccess,
} from "@cello-protocol/protocol-types";
import type { ChannelSubscriptionStore } from "./channel-subscription-store.js";
import type { ChannelInboxStore } from "./channel-inbox-store.js";
import { extractErrorMessage } from "./error-message.js";

export type ChannelInfoResult =
  | {
      ok: true; channelHex: string; adminPubkeyHex: string;
      // Added from LOCAL knowledge only (035-INFOCLI item 1). The directory names just the admin;
      // these come from the config store (a channel this daemon administers) or the subscription
      // store (a channel followed here). `status` is present only for a followed channel.
      access?: ChannelAccess; guidance?: string; relays?: string[];
      status?: "active" | "left" | "ejected" | "closed";
      // 041-HELPTRUTH Part C: for a FOLLOWED channel, where `guidance` came from. `"relay"` is a
      // fresh, signature-verified record fetched just now; `"stored"` is the value from admission,
      // used when no relay answered or the record did not verify. Absent for an administered channel
      // (this daemon signs its own) or a channel it neither administers nor follows.
      description_source?: "relay" | "stored";
      // Present only when this daemon knows nothing beyond the admin — neither administers nor
      // follows the channel — so a reader is told how to see the description and relays.
      detail?: string;
    }
  // 038-RETESTFIX Part D: `channel_deleted` — the directory says this channel's identity is revoked,
  // OR this member holds a local subscription marked `closed` (it received the channel_closed notice).
  // `status: "closed"` rides only the local-subscription case.
  | { ok: false; reason: "not_a_channel" | "unavailable" | "channel_deleted"; detail?: string; guidance?: string; status?: "closed" };

export type ChannelJoinResult =
  | { ok: true; channelHex: string; state: "requested" }
  // 038-RETESTFIX Part D: `channel_deleted` — a join to a revoked channel is refused BEFORE any
  // session is opened.
  | { ok: false; reason: "not_a_channel" | "unavailable" | "no_session" | "send_failed" | "channel_deleted"; detail?: string; guidance?: string };

export interface ReadPost {
  seq: number;
  title: string;
  body: string;
  published_at: number;
}

export type ChannelReadResult =
  | { ok: true; posts: ReadPost[]; through: number; undecryptable: number[] }
  | { ok: false; reason: "not_subscribed" | "failed"; detail?: string };

export interface ChannelSubscribeDeps {
  logger: Logger;
  subscriptions: ChannelSubscriptionStore;
  /** Where the COLLECTOR puts a subscriber's posts. Not the publisher's log — different table. */
  inbox: ChannelInboxStore;
  /** Who the DIRECTORY says administers a channel. 020's lookup, unchanged. */
  lookupAdmin: (agentId: string, channelHex: string) => Promise<
    { kind: "admin"; adminPubkeyHex: string }
    | { kind: "not_a_channel" }
    // 038-RETESTFIX Part D: the directory answered that this channel's identity is revoked (deleted).
    | { kind: "revoked" }
    | { kind: "unavailable"; reason: string }
  >;
  /** An open session with that agent, opening one if needed. Null when it cannot be reached. */
  sessionWith: (agentName: string, counterpartyHex: string) => Promise<
    { ok: true; sessionId: string } | { ok: false; reason: string; guidance?: string }
  >;
  sendInSession: (agentName: string, sessionId: string, content: Uint8Array) => Promise<void>;
  /**
   * What THIS daemon has decided about a channel it administers (the config store `create`/`setup`
   * write), or null when it holds no config for that channel. Read-only — `info` never writes it.
   */
  channelConfig: (channelHex: string) => { access: ChannelAccess; guidance: string; relays: string[] } | null;
  /** This agent's own public key — the subscriber identity the request names. */
  agentPubkey: (agentName: string) => string | null;
  /** Decrypt one stored post body for this subscription, or null if no key fits. */
  decrypt: (agentId: string, channelHex: string, seq: number, body: Uint8Array) => Promise<Uint8Array | null>;
  /**
   * 041-HELPTRUTH Part C: the channel's signed info record as its relays hold it, or null when none
   * answers. Tries the relays in order and returns the first record; the CALLER decodes, verifies
   * and matches it against the channel key — this only fetches bytes.
   */
  fetchInfo: (relays: string[], channelHex: string) => Promise<Uint8Array | null>;
}

export function createChannelSubscribe(deps: ChannelSubscribeDeps) {
  /**
   * The directory names the admin; LOCAL knowledge adds the rest when this daemon has it (035 item 1).
   *
   * ⚠️ **NO DIRECTORY CHANGE, and the added fields come from LOCAL stores only.** The directory
   * answers `not_a_channel` / `unavailable` / the admin key and nothing else — access, the
   * description and the relays are the publisher's, learned by administering the channel (config
   * store) or by following it (subscription store). A daemon that does neither cannot know them, so
   * it says how to find out rather than inventing a value.
   */
  async function info(agentId: string, channelHex: string): Promise<ChannelInfoResult> {
    const found = await deps.lookupAdmin(agentId, channelHex);
    const sub = deps.subscriptions.get(agentId, channelHex);

    /**
     * 038-RETESTFIX Part D: a channel this member knows is gone reads as `channel_deleted`. Two
     * sources: the directory's explicit `revoked` answer, OR a local subscription already marked
     * `closed` (this member received the channel_closed notice, and the fleet may not be rolled yet
     * so the directory could still answer `admin`). The closed status rides only the local case.
     *
     * ⚠️ **ONLY AN EXPLICIT `revoked` OR a local `closed` — never an `unavailable`/error (MUST NOT
     * CHANGE item 3).** A directory outage stays `unavailable`; it must not read as deleted.
     */
    if (found.kind === "revoked" || sub?.status === "closed") {
      return {
        ok: false, reason: "channel_deleted",
        guidance: "This channel was deleted by its admin.",
        ...(sub?.status === "closed" ? { status: "closed" as const } : {}),
      };
    }
    if (found.kind === "not_a_channel") return { ok: false, reason: "not_a_channel" };
    if (found.kind === "unavailable") return { ok: false, reason: "unavailable", detail: found.reason };

    const base = { ok: true as const, channelHex, adminPubkeyHex: found.adminPubkeyHex };

    // Administering the channel is the fullest source — this daemon holds the config it signs from.
    const cfg = deps.channelConfig(channelHex);
    if (cfg) return { ...base, access: cfg.access, guidance: cfg.guidance, relays: cfg.relays };

    // Following it carries access, relays and this member's status from the acceptance. The
    // DESCRIPTION, though, was frozen at admission — so refresh it from the channel's relays, which
    // is what the info-set help promises a member sees. Never show an unverified description.
    if (sub) {
      const fresh = await currentDescription(agentId, channelHex, sub.relays, sub.guidance, sub.guidance_updated_at);
      return {
        ...base, access: sub.access, guidance: fresh.guidance, relays: sub.relays,
        status: sub.status, description_source: fresh.source,
      };
    }

    // Neither administered nor followed here: only the admin is known.
    return { ...base, detail: "Join the channel to see its description and relays." };
  }

  /**
   * 041-HELPTRUTH Part C — the CURRENT description for a followed channel.
   *
   * Asks the subscription's relays for the signed info record, decodes it, verifies its signature
   * against the CHANNEL key, checks the record names THIS channel, and checks its signed `updated_at`
   * is STRICTLY NEWER than the stored one (`storedUpdatedAt`; 0 for the admission text). On success
   * returns that description (source `"relay"`) and writes it back with its `updated_at`. On any miss
   * — no relay answered, a decode failure, a bad signature, a record for another channel, or an older
   * or equal `updated_at` (a replayed record) — it falls back to the stored description (source
   * `"stored"`) and leaves the store untouched. An unverified description is NEVER returned.
   */
  async function currentDescription(
    agentId: string, channelHex: string, relays: string[], stored: string, storedUpdatedAt: number,
  ): Promise<{ guidance: string; source: "relay" | "stored" }> {
    let raw: Uint8Array | null = null;
    try {
      raw = await deps.fetchInfo(relays, channelHex);
    } catch {
      // A relay fault is a fall-back, not a failure of `info` — the stored description still stands.
      raw = null;
    }
    if (raw !== null) {
      const decoded = decodeChannelInfo(raw);
      const wanted = channelHex.toLowerCase();
      if (
        decoded.ok
        && Buffer.from(decoded.info.channel_pubkey).toString("hex") === wanted
        && verifyChannelInfo(decoded.info)
        // Replay guard: a validly-signed but OLDER record must not overwrite a newer stored one.
        && decoded.info.updated_at > storedUpdatedAt
      ) {
        deps.subscriptions.setGuidance(agentId, channelHex, decoded.info.guidance, decoded.info.updated_at);
        return { guidance: decoded.info.guidance, source: "relay" };
      }
      deps.logger.info("channel.info.record_not_adopted", { channel_pubkey: channelHex });
    }
    return { guidance: stored, source: "stored" };
  }

  /**
   * Ask to join. Directory → admin → session → request.
   *
   * ⚠️ **THIS ONLY ASKS.** The answer arrives asynchronously as a join frame and is handled by the
   * exchange (019), which runs the admin check (020) before accepting any key. Nothing here may
   * shortcut that: a verb that recorded a subscription on send would make an unanswered request
   * look like membership.
   */
  async function join(agentName: string, agentId: string, channelHex: string, note?: string): Promise<ChannelJoinResult> {
    const found = await deps.lookupAdmin(agentId, channelHex);
    if (found.kind === "not_a_channel") return { ok: false, reason: "not_a_channel" };
    // 038-RETESTFIX Part D: refuse a join to a revoked channel BEFORE any session is opened — the
    // directory has said the channel is gone, so there is no admin to ask and nothing to join.
    if (found.kind === "revoked") {
      return { ok: false, reason: "channel_deleted", guidance: "This channel was deleted by its admin." };
    }
    if (found.kind === "unavailable") return { ok: false, reason: "unavailable", detail: found.reason };

    /**
     * ⚠️ **THIS VERB DOES NOT BRANCH ON ACCESS, AND MUST NOT.** The directory's answer carries
     * `registered`, `channel` and `admin_pubkey` and says nothing about access, so this side cannot
     * know whether a channel is public, open or invite-only. It sends the same join request either
     * way; the admin's half decides. Since 036-PUBLICSUB the admin ADMITS a public join (with an
     * empty-bundle acceptance carrying the relays) rather than refusing it, so a public subscription
     * now completes through the ordinary path.
     */
    const subscriberHex = deps.agentPubkey(agentName);
    if (subscriberHex === null) return { ok: false, reason: "no_session", detail: "agent_unknown" };

    const opened = await deps.sessionWith(agentName, found.adminPubkeyHex);
    if (!opened.ok) {
      // ⚠️ THE REAL REFUSAL TRAVELS. The first version discarded it and said "could not open a
      // session with the admin", which pointed at the counterparty and the network for what was a
      // field name in the caller.
      return { ok: false, reason: "no_session", detail: opened.reason };
    }
    const sessionId = opened.sessionId;

    try {
      const frame = encodeChannelJoinRequest({
        channel_pubkey: new Uint8Array(Buffer.from(channelHex, "hex")),
        subscriber_pubkey: new Uint8Array(Buffer.from(subscriberHex, "hex")),
        note: note ?? "",
      });
      await deps.sendInSession(agentName, sessionId, frame);
    } catch (err: unknown) {
      return { ok: false, reason: "send_failed", detail: extractErrorMessage(err) };
    }

    deps.logger.info("channel.join.requested", { channel_pubkey: channelHex, admin: found.adminPubkeyHex.slice(0, 16) });
    return { ok: true, channelHex, state: "requested" };
  }

  /**
   * Read posts after the read position, oldest first, and advance it.
   *
   * ⚠️ **TWO POSITIONS, AND THIS TOUCHES ONLY THE SECOND.** `delivered_through` is how far the
   * daemon has FETCHED and belongs to the collector; `processed_through` is how far a person has
   * SEEN. Advancing the wrong one silently skips posts that have not been collected yet.
   *
   * ⚠️ **A POST THAT WILL NOT DECRYPT IS REPORTED, NOT SKIPPED.** `unknown_generation` means a
   * re-key this subscriber never received — usually an ejection. Skipping it quietly makes being
   * ejected look like a channel that went quiet.
   */
  async function read(agentId: string, channelHex: string, all = false): Promise<ChannelReadResult> {
    const sub = deps.subscriptions.get(agentId, channelHex);
    if (!sub) return { ok: false, reason: "not_subscribed" };

    try {
      // Bounded by `delivered_through`: the collector owns what has been FETCHED, and reading past
      // that edge would advance the read position over posts nobody has yet.
      const from = all ? 1 : sub.processed_through + 1;
      const stored = deps.inbox.range(agentId, channelHex, from, sub.delivered_through);
      const posts: ReadPost[] = [];
      const undecryptable: number[] = [];
      let highest = sub.processed_through;

      for (const entry of stored) {
        /**
         * ⚠️ **A PUBLIC CHANNEL'S POSTS ARE STORED IN CLEAR (028, 036-PUBLICSUB) — do not decrypt.**
         * There is no group key for a public subscription, so routing the body through `decryptBody`
         * would find no key and report every post `undecryptable`. The body IS the plaintext.
         */
        const plain = sub.access === "public"
          ? entry.body
          : await deps.decrypt(agentId, channelHex, entry.seq, entry.body);
        if (plain === null) {
          /**
           * ⚠️ **THE READ POSITION STOPS HERE.** Naming the post and then advancing past it is
           * "announced once, then skipped for ever": a subscriber who missed a re-key sees
           * `undecryptable: [7,8,9]`, later receives the key, and those three are now behind the
           * position and will never be shown. Stopping means the next read retries them.
           */
          undecryptable.push(entry.seq);
          break;
        } else {
          // The TITLE travels in clear on the artifact; only the body is sealed. So a post whose
          // body will not open still has a name, which is what makes `undecryptable` actionable.
          posts.push({
            seq: entry.seq,
            title: entry.title,
            body: Buffer.from(plain).toString("utf8"),
            published_at: entry.published_at,
          });
        }
        if (entry.seq > highest) highest = entry.seq;
      }

      // `--all` re-reads without moving the position: a caller reviewing history must not have that
      // count as having seen anything new.
      if (!all && highest > sub.processed_through) {
        deps.subscriptions.advanceProcessed(agentId, channelHex, highest);
      }
      return { ok: true, posts, through: all ? sub.processed_through : highest, undecryptable };
    } catch (err: unknown) {
      return { ok: false, reason: "failed", detail: extractErrorMessage(err) };
    }
  }

  return { info, join, read };
}
