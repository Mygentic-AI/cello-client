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
import { encodeChannelJoinRequest } from "@cello-protocol/protocol-types";
import type { ChannelSubscriptionStore } from "./channel-subscription-store.js";
import type { ChannelInboxStore } from "./channel-inbox-store.js";
import { extractErrorMessage } from "./error-message.js";

export type ChannelInfoResult =
  | { ok: true; channelHex: string; adminPubkeyHex: string }
  | { ok: false; reason: "not_a_channel" | "unavailable"; detail?: string };

export type ChannelJoinResult =
  | { ok: true; channelHex: string; state: "requested" }
  | { ok: false; reason: "not_a_channel" | "unavailable" | "no_session" | "send_failed"; detail?: string };

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
    { kind: "admin"; adminPubkeyHex: string } | { kind: "not_a_channel" } | { kind: "unavailable"; reason: string }
  >;
  /** An open session with that agent, opening one if needed. Null when it cannot be reached. */
  sessionWith: (agentName: string, counterpartyHex: string) => Promise<string | null>;
  sendInSession: (agentName: string, sessionId: string, content: Uint8Array) => Promise<void>;
  /** This agent's own public key — the subscriber identity the request names. */
  agentPubkey: (agentName: string) => string | null;
  /** Decrypt one stored post body for this subscription, or null if no key fits. */
  decrypt: (agentId: string, channelHex: string, seq: number, body: Uint8Array) => Promise<Uint8Array | null>;
}

export function createChannelSubscribe(deps: ChannelSubscribeDeps) {
  /** Directory only. One argument, the channel key. */
  async function info(agentId: string, channelHex: string): Promise<ChannelInfoResult> {
    const found = await deps.lookupAdmin(agentId, channelHex);
    if (found.kind === "admin") return { ok: true, channelHex, adminPubkeyHex: found.adminPubkeyHex };
    if (found.kind === "not_a_channel") return { ok: false, reason: "not_a_channel" };
    return { ok: false, reason: "unavailable", detail: found.reason };
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
    if (found.kind === "unavailable") return { ok: false, reason: "unavailable", detail: found.reason };

    const subscriberHex = deps.agentPubkey(agentName);
    if (subscriberHex === null) return { ok: false, reason: "no_session", detail: "agent_unknown" };

    const sessionId = await deps.sessionWith(agentName, found.adminPubkeyHex);
    if (sessionId === null) return { ok: false, reason: "no_session", detail: "could not open a session with the admin" };

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
        const plain = await deps.decrypt(agentId, channelHex, entry.seq, entry.body);
        if (plain === null) {
          undecryptable.push(entry.seq);
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
