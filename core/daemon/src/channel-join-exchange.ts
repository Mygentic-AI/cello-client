/**
 * ChannelJoinExchange — M16 019-MEMBERSHIP Part B, both sides of joining a channel.
 *
 * A channel never converses. Its ADMIN is an ordinary agent, so a join is a typed exchange inside a
 * normal sealed session with that admin — no new transport, no relay frames, no special case in the
 * session layer.
 *
 * ─── The two identity checks, and why each is load-bearing ───────────────────────────────────
 *
 * **ADMIN side: the session counterparty must BE the subscriber the frame names.** The frame says
 * who is joining and the session says who is talking; if they may differ, anyone can enrol a third
 * party — and, worse, receive that third party's key bundle themselves, because the bundle is
 * wrapped for the pubkey in the frame and sent down the session they are holding.
 *
 * **SUBSCRIBER side: the answering agent must be the admin in the channel's DIRECTORY PROFILE.**
 * The session proves who the counterparty is. It does not prove they are this channel's admin. Drop
 * this check and any agent that can open a session with you hands you a key bundle and a relay pair
 * and becomes your channel: you read their posts believing them to be somebody else's, and the
 * immutable `admin_pubkey` the design rests on protects nobody.
 *
 * ─── What is NOT decided here ────────────────────────────────────────────────────────────────
 *
 * Invite-only admission is the admin AGENT's decision. A request lands as `pending` and raises a
 * notice; nothing in this file approves one. There is no heuristic, no allowlist, no auto-approve.
 */
import {
  decodeChannelJoinRequest, decodeChannelJoinAccepted, decodeChannelJoinRefused, decodeChannelRekey,
  encodeChannelJoinAccepted, encodeChannelJoinRefused, encodeChannelRekey,
  isChannelJoinFrame,
  type ChannelJoinRefusedReason,
} from "@cello-protocol/protocol-types";
import {
  generateGroupKey, wrapGroupKeyFor, unwrapGroupKey, type GroupKey,
} from "@cello-protocol/crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { Logger } from "./types.js";
import type { ChannelMembershipStore } from "./channel-membership-store.js";
import type { ChannelSubscriptionStore } from "./channel-subscription-store.js";
import { extractErrorMessage } from "./error-message.js";

/** What this daemon knows about a channel it administers. `null` means it does not administer one. */
export interface LocalChannelAdmin {
  agentId: string;
  adminPubkeyHex: string;
  channelKeyProvider: KeyProvider;
  adminKeyProvider: KeyProvider;
}

/**
 * M16 021-WAKE item 21: the admin, or WHY there isn't one.
 *
 * ⚠️ The refusal is unchanged — anything other than `ok` leaves the join refused, exactly as the
 * bare `null` did. What is new is that the cause travels with it, so `admin_unresolved` stops being
 * a word an operator can do nothing with.
 */
export type AdminLookupOutcome =
  | { ok: true; adminPubkeyHex: string }
  | { ok: false; reason: string };

export interface ChannelJoinExchangeDeps {
  logger: Logger;
  members: ChannelMembershipStore;
  subscriptions: ChannelSubscriptionStore;
  /** Put a frame on an open session. The session layer owns delivery; this owns the decisions. */
  sendInSession: (sessionId: string, content: Uint8Array) => Promise<void>;
  localChannelAdmin: (channelHex: string) => LocalChannelAdmin | null;
  /**
   * The channel's admin AS THE DIRECTORY REPORTS IT. `null` means the lookup could not be resolved,
   * which FAILS CLOSED — an unreachable directory must not become "whoever answered is the admin".
   */
  profileAdminPubkey: (channelHex: string, agentId: string) => Promise<AdminLookupOutcome>;
  keyProviderFor: (agentId: string) => KeyProvider | null;
  raiseNotice: (event: string, channelHex: string, subscriberHex: string) => void;
  /**
   * M16 032-NOTICES: how THIS agent's own join request was answered — `admitted` when an acceptance
   * is stored, `pending` on a `pending_approval` refusal, `refused` (+ the reason word) on any other
   * refusal. The wiring turns it into the content-free `channel_join_answer` doorbell. Optional and
   * additive: an older wiring omits it and the exchange behaves exactly as before. A re-key is NOT
   * an answer to a join and never rings this — that is out of scope (notices for re-key).
   */
  onJoinAnswer?: (agentId: string, channelHex: string, outcome: "admitted" | "pending" | "refused", reason?: string) => void;
  now?: () => number;
}

export type SubscriberJoinResult =
  | { ok: true; channelHex: string; generation: number }
  | {
      ok: false;
      reason: "not_a_join_frame" | "malformed" | "not_admin_of_channel" | "admin_unresolved" | "key_unwrap_failed" | "no_key_provider" | "refused_by_admin";
      /**
       * M16 021-WAKE item 21: WHY, when the reason alone cannot say.
       *
       * ⚠️ `admin_unresolved` is an exit-point label. A dead signaling stream, a ten-second timeout
       * against a directory that has not been rolled, a channel the directory has never heard of
       * and a database fault all arrive at that one word, and the operator cannot tell which. The
       * cause survived only in a log line one step upstream, which is not where anyone looks when a
       * join is refused.
       */
      detail?: string;
    };

export interface ChannelJoinExchange {
  /** An inbound frame on the ADMIN's daemon. `consumed: false` means it was not a join frame. */
  onAdminFrame: (sessionId: string, counterpartyHex: string, content: Uint8Array) => Promise<{ consumed: boolean }>;
  /** An inbound acceptance or re-key on the SUBSCRIBER's daemon. */
  onSubscriberFrame: (agentId: string, sessionId: string, counterpartyHex: string, content: Uint8Array) => Promise<SubscriberJoinResult>;
  /** The admin agent's explicit decision on a pending invite-only request. */
  approve: (channelHex: string, subscriberHex: string, sessionId: string) => Promise<{ ok: true } | { ok: false; reason: string }>;
  /** Refuse a pending request by name. */
  refuse: (channelHex: string, subscriberHex: string, sessionId: string) => Promise<{ ok: true } | { ok: false; reason: string }>;
}

/**
 * The channel's CURRENT group key for its admin: the key at `settings.key_generation`, started at 1
 * and minted if absent, stored under the admin's own agent id. Used by BOTH admitting a member and
 * publishing, so a post made before anyone joined is readable by the first member.
 * `undefined` for a public channel or a channel with no membership settings.
 *
 * ⚠️ **THE ADMIN STORES ITS OWN CHANNEL'S GROUP KEY IN THE SAME TABLE ITS SUBSCRIBERS USE**, under
 * its own agent id. A key held only in this process is lost on restart — and then the second member
 * admitted after a restart gets a DIFFERENT key at the same generation, so the two decrypt different
 * halves of the channel and neither can tell why. The admin is a reader of its own channel; storing
 * the key where readers keep keys is the honest place for it.
 *
 * ⚠️ **THE GENERATION COMES FROM SETTINGS, NOT FROM "NEWEST KEY HELD".** `settings.key_generation`,
 * started with `members.startGeneration` when it is still 0 — exactly what admitting a member does.
 * Both the exchange and the publisher reach this ONE function, so a post published before anyone
 * joined and the first member's key are the same bytes at the same generation.
 */
export function ensureCurrentGroupKey(
  deps: { members: ChannelMembershipStore; subscriptions: ChannelSubscriptionStore; now: () => number },
  adminAgentId: string,
  channelHex: string,
): GroupKey | undefined {
  const settings = deps.members.settings(channelHex);
  // No membership settings, or a public channel, has no group key and mints none.
  if (!settings || settings.access === "public") return undefined;

  let generation = settings.key_generation;
  if (generation === 0) generation = deps.members.startGeneration(channelHex);

  const held = deps.subscriptions.keysFor(adminAgentId, channelHex).find((k) => k.generation === generation);
  if (held) return held;
  const minted = generateGroupKey(generation);
  deps.subscriptions.addKey(adminAgentId, channelHex, minted, deps.now());
  return minted;
}

export function createChannelJoinExchange(deps: ChannelJoinExchangeDeps): ChannelJoinExchange {
  const { logger, members, subscriptions } = deps;
  const now = deps.now ?? (() => Date.now());

  async function refuseTo(sessionId: string, channelPubkey: Uint8Array, reason: ChannelJoinRefusedReason): Promise<void> {
    logger.info("channel.join.refused", {
      channel_pubkey: Buffer.from(channelPubkey).toString("hex"), reason,
    });
    await deps.sendInSession(sessionId, encodeChannelJoinRefused({ channel_pubkey: channelPubkey, reason }));
  }

  async function acceptInto(
    sessionId: string, channelHex: string, subscriberHex: string, admin: LocalChannelAdmin,
  ): Promise<{ ok: true } | { ok: false; reason: string }> {
    const settings = members.settings(channelHex);
    /**
     * ⚠️ RETURNS A REASON RATHER THAN NOTHING. This used to return silently, and `approve` reported
     * `ok: true` on top of it — so an admin believed they had admitted somebody who received no key
     * and no relays, and the member's daemon heard nothing at all.
     */
    if (!settings) return { ok: false, reason: "channel_not_configured_for_membership" };

    const channelPubkeyPublic = await admin.channelKeyProvider.getPublicKey();
    /**
     * ⚠️ **A PUBLIC CHANNEL IS ADMITTED WITH NO KEY (036-PUBLICSUB).** Its posts are not encrypted,
     * so there is nothing to mint or wrap — the acceptance carries the relays, guidance and retention
     * and an EMPTY bundle. Minting a key here would store bytes nobody uses and that no ejection could
     * ever bite. The empty bundle is exactly what the frame requires for `access: "public"`.
     */
    if (settings.access === "public") {
      await deps.sendInSession(sessionId, encodeChannelJoinAccepted({
        channel_pubkey: channelPubkeyPublic,
        key_bundle: new Uint8Array(0),
        guidance: settings.guidance,
        retention_seconds: settings.retention_seconds,
        access: "public",
        relays: settings.relays,
        members_visible: settings.members_visible,
      }));
      logger.info("channel.member.joined", {
        channel_pubkey: channelHex, subscriber_pubkey: subscriberHex, access: "public",
      });
      return { ok: true };
    }

    // The SAME mint-or-reuse the publisher reaches, so a post made before this member joined is
    // readable with the very key delivered here. `undefined` only for the states settings rules out
    // above (absent) or a public channel (handled above), so it is defended, not expected.
    const gk = ensureCurrentGroupKey({ members, subscriptions, now }, admin.agentId, channelHex);
    if (!gk) return { ok: false, reason: "channel_not_configured_for_membership" };
    const generation = gk.generation;

    const channelPubkey = await admin.channelKeyProvider.getPublicKey();
    const bundle = await wrapGroupKeyFor(
      gk, channelPubkey, new Uint8Array(Buffer.from(subscriberHex, "hex")), admin.adminKeyProvider,
    );
    await deps.sendInSession(sessionId, encodeChannelJoinAccepted({
      channel_pubkey: channelPubkey,
      key_bundle: bundle,
      guidance: settings.guidance,
      retention_seconds: settings.retention_seconds,
      // `public` cannot reach here — the caller refuses it — and the frame refuses it too.
      access: settings.access === "invite_only" ? "invite_only" : "open",
      relays: settings.relays,
      members_visible: settings.members_visible,
    }));
    logger.info("channel.member.joined", {
      channel_pubkey: channelHex, subscriber_pubkey: subscriberHex, generation,
    });
    return { ok: true };
  }

  return {
    async onAdminFrame(sessionId, counterpartyHex, content): Promise<{ consumed: boolean }> {
      // Not a join frame means somebody is TALKING. Consuming it would make a person's message
      // vanish instead of reaching the operator — the same rule the document router follows.
      if (!isChannelJoinFrame(content)) return { consumed: false };

      const decoded = decodeChannelJoinRequest(content);
      if (!decoded.ok) {
        /**
         * ⚠️ LOGGED, because this frame is now GONE. It is consumed — structured traffic, not
         * conversation — so it never reaches the operator's transcript. Returning silently meant any
         * counterparty could send a CBOR array whose first element was one of the four type strings
         * and have it disappear with nothing recorded anywhere. The decoder already produces a
         * reason and a detail; there is no excuse for discarding them.
         */
        logger.warn("channel.join.frame_undecodable", {
          reason: decoded.reason, detail: decoded.detail, sender: counterpartyHex,
        });
        return { consumed: true };
      }

      const channelPubkey = decoded.frame.channel_pubkey;
      const channelHex = Buffer.from(channelPubkey).toString("hex");
      const namedSubscriber = Buffer.from(decoded.frame.subscriber_pubkey).toString("hex");
      /**
       * ⚠️ THE COUNTERPARTY, NOT THE FRAME'S CLAIM. `namedSubscriber` is whatever the caller wrote;
       * logging it before the check below let a prober put an arbitrary pubkey in an operator's log
       * and make it look like that party had asked to join. The session's counterparty is the only
       * identity here that anything has proven.
       */
      logger.info("channel.join.requested", {
        channel_pubkey: channelHex, counterparty_pubkey: counterpartyHex,
      });

      /**
       * ⚠️ **THE COUNTERPARTY MUST BE THE SUBSCRIBER THE FRAME NAMES.** Otherwise anyone can enrol a
       * third party — and receive that party's key bundle down the session they are holding.
       * Refused as `not_admin_of_channel` rather than a more specific reason: to a caller who is not
       * who they claim, "this is not your join" and "this is not my channel" are the same answer,
       * and a distinct one would tell a prober which channels this daemon administers.
       */
      if (namedSubscriber !== counterpartyHex.toLowerCase()) {
        await refuseTo(sessionId, channelPubkey, "not_admin_of_channel");
        return { consumed: true };
      }

      const admin = deps.localChannelAdmin(channelHex);
      if (!admin) {
        await refuseTo(sessionId, channelPubkey, "not_admin_of_channel");
        return { consumed: true };
      }

      const settings = members.settings(channelHex);
      if (!settings) {
        await refuseTo(sessionId, channelPubkey, "not_admin_of_channel");
        return { consumed: true };
      }

      const status = members.statusOf(channelHex, namedSubscriber);
      if (status === "active") {
        await refuseTo(sessionId, channelPubkey, "already_member");
        return { consumed: true };
      }
      // ⚠️ AN EJECTED MEMBER CANNOT SIMPLY ASK AGAIN. Re-admitting on request would undo the
      // ejection the moment they retried — which is exactly why the ejected row is never deleted.
      if (status === "ejected") {
        await refuseTo(sessionId, channelPubkey, "ejected");
        return { consumed: true };
      }
      if (status === "pending") {
        await refuseTo(sessionId, channelPubkey, "pending_approval");
        return { consumed: true };
      }

      // Open and public both admit at once — the difference is only the key. A public channel's
      // posts are not encrypted, so its acceptance carries none; `acceptInto` sends the empty-bundle
      // frame for it (Andre's Option B, 036-PUBLICSUB). `already_member` above already handled a
      // repeat, so this admits a first-time reader.
      if (settings.access === "open" || settings.access === "public") {
        members.admit(channelHex, namedSubscriber, "active", now());
        await acceptInto(sessionId, channelHex, namedSubscriber, admin);
        return { consumed: true };
      }

      // invite_only: recorded as PENDING and handed to the admin agent. Nothing here approves it.
      members.admit(channelHex, namedSubscriber, "pending", now());
      logger.info("channel.join.pending", { channel_pubkey: channelHex, subscriber_pubkey: namedSubscriber });
      deps.raiseNotice("channel.join.pending", channelHex, namedSubscriber);
      await refuseTo(sessionId, channelPubkey, "pending_approval");
      return { consumed: true };
    },

    async onSubscriberFrame(agentId, sessionId, counterpartyHex, content): Promise<SubscriberJoinResult> {
      if (!isChannelJoinFrame(content)) return { ok: false, reason: "not_a_join_frame" };

      /**
       * An acceptance OR a re-key. Narrowed into two locals rather than kept as a pair of results,
       * so the compiler knows which one carries a frame — a non-null assertion here would be the
       * kind of "I know better" that survives a later edit changing which branch can be reached.
       */
      const acceptedResult = decodeChannelJoinAccepted(content);
      const acceptedFrame = acceptedResult.ok ? acceptedResult.frame : null;
      let rekeyFrame: import("@cello-protocol/protocol-types").ChannelRekey | null = null;
      if (!acceptedFrame) {
        const rekeyResult = decodeChannelRekey(content);
        if (rekeyResult.ok) rekeyFrame = rekeyResult.frame;
      }
      if (!acceptedFrame && !rekeyFrame) {
        /**
         * M16 032-NOTICES: a REFUSAL is the admin's answer to THIS agent's own request. Store
         * nothing — a refusal grants no key and no subscription — but report the outcome so the
         * operator is not left silent. `pending_approval` means the request is queued for an
         * invite-only admin; every other reason is a terminal refusal, and the reason word travels
         * so the operator knows why (the fixed refusal vocabulary only, never free text).
         */
        const refused = decodeChannelJoinRefused(content);
        if (refused.ok) {
          const reason = refused.frame.reason;
          const refusedHex = Buffer.from(refused.frame.channel_pubkey).toString("hex");
          /**
           * M16 034-LIFECYCLE: an `ejected` / `channel_closed` refusal is not the answer to a fresh
           * request — it is the admin telling an EXISTING member they are out (that one alone, or the
           * whole channel is gone). Mark the subscription so it stops looking like a normal one; the
           * kept keys are untouched, so earlier posts stay readable.
           *
           * ⚠️ **REMOVING A SUBSCRIPTION IS PRIVILEGED — ONLY ITS STORED ADMIN MAY.** The session
           * proves who the peer IS, not that they administer the channel; the accept/rekey branch
           * below makes the same admin check for the same reason. Without it, any peer that can open a
           * session could mark you ejected or your channel deleted. So: only when a subscription
           * exists (nothing to change otherwise — this is then an answer to a fresh request that falls
           * through to the doorbell) AND the sender is its admin do we mark and ring the removal
           * doorbell. A non-admin sender changes nothing and rings nothing; it is logged and dropped.
           */
          if (reason === "ejected" || reason === "channel_closed") {
            const sub = subscriptions.get(agentId, refusedHex);
            if (sub !== null) {
              if (sub.admin_pubkey.toLowerCase() !== counterpartyHex.toLowerCase()) {
                logger.warn("channel.join.refused.not_admin", {
                  channel_pubkey: refusedHex, sender: counterpartyHex, reason,
                });
                return { ok: false, reason: "not_admin_of_channel" };
              }
              if (reason === "ejected") subscriptions.markEjected(agentId, refusedHex);
              else subscriptions.markClosed(agentId, refusedHex);
            }
          }
          if (reason === "pending_approval") deps.onJoinAnswer?.(agentId, refusedHex, "pending");
          else deps.onJoinAnswer?.(agentId, refusedHex, "refused", reason);
          return { ok: false, reason: "refused_by_admin", detail: reason };
        }
        return { ok: false, reason: "malformed" };
      }

      const channelPubkey = acceptedFrame ? acceptedFrame.channel_pubkey : rekeyFrame!.channel_pubkey;
      const channelHex = Buffer.from(channelPubkey).toString("hex");

      /**
       * ⚠️ **THE ADMIN CHECK, AGAINST THE DIRECTORY PROFILE.** Not against whoever answered: the
       * session proves identity, not authority. Without this any agent that can open a session with
       * you becomes your channel, and the immutable admin key protects nobody.
       *
       * A lookup that cannot be RESOLVED fails closed. An unreachable directory must never mean
       * "accept whoever this is" — that would make a network problem into an admission.
       */
      /**
       * ⚠️ **A RE-KEY ASKS NOBODY: the admin was checked when the subscription was made, and is
       * stored on it.** Going back to the directory for one would put a network round trip, and a
       * directory outage, in the path of every re-key — and a re-key is how an EJECTION reaches the
       * remaining members, so losing one is the thing with a cost. It is also what closed the
       * exposure this check opened: an unsolicited re-key naming any pubkey would otherwise have
       * bought a stranger a directory lookup, on a handler the session layer is waiting for.
       *
       * The asking agent goes with the acceptance case, because the lookup rides THAT agent's own
       * authenticated directory stream rather than any connection that happens to be open.
       */
      const storedAdmin = rekeyFrame ? (subscriptions.get(agentId, channelHex)?.admin_pubkey ?? null) : null;
      const looked: AdminLookupOutcome = storedAdmin !== null
        ? { ok: true, adminPubkeyHex: storedAdmin }
        : await deps.profileAdminPubkey(channelHex, agentId);
      if (!looked.ok) {
        // The cause travels with the refusal now. It used to live only in a log line one step
        // upstream, which is not where anyone looks when a join is refused.
        logger.warn("channel.join.refused", {
          channel_pubkey: channelHex, reason: "admin_unresolved", detail: looked.reason,
        });
        return { ok: false, reason: "admin_unresolved", detail: looked.reason };
      }
      const profileAdmin = looked.adminPubkeyHex;
      if (profileAdmin.toLowerCase() !== counterpartyHex.toLowerCase()) {
        logger.warn("channel.join.refused", {
          channel_pubkey: channelHex, reason: "not_admin_of_channel",
          answered_by: counterpartyHex, profile_admin: profileAdmin,
        });
        return { ok: false, reason: "not_admin_of_channel" };
      }

      /**
       * ⚠️ **A PUBLIC ACCEPTANCE CARRIES NO KEY — store the subscription, unwrap nothing (036-PUBLICSUB).**
       * Reached ONLY after the admin check above, exactly as the keyed path is: the security property
       * that the answering agent must be the channel's directory admin is identical for public. A
       * public channel's posts are read in clear, so calling `unwrapGroupKey`/`addKey` here would try
       * to open an empty bundle and store a phantom key. The upsert records the relays, guidance and
       * retention the same as `open`; `onJoinAnswer` rings `admitted`, same as any admission.
       */
      if (acceptedFrame && acceptedFrame.access === "public") {
        subscriptions.upsert({
          agent_id: agentId,
          channel_pubkey: channelHex,
          admin_pubkey: profileAdmin,
          access: "public",
          relays: acceptedFrame.relays,
          guidance: acceptedFrame.guidance,
          retention_seconds: acceptedFrame.retention_seconds,
          joined_at: now(),
        });
        deps.onJoinAnswer?.(agentId, channelHex, "admitted");
        return { ok: true, channelHex, generation: 0 };
      }

      const myKeys = deps.keyProviderFor(agentId);
      if (!myKeys) return { ok: false, reason: "no_key_provider" };

      const bundle = acceptedFrame ? acceptedFrame.key_bundle : rekeyFrame!.key_bundle;
      const unwrapped = await unwrapGroupKey(bundle, channelPubkey, myKeys);
      if (!unwrapped.ok) {
        logger.warn("channel.join.refused", { channel_pubkey: channelHex, reason: unwrapped.reason });
        return { ok: false, reason: "key_unwrap_failed" };
      }

      // An ACCEPTANCE brings the subscription with it; a RE-KEY only adds a key to one that exists.
      if (acceptedFrame) {
        subscriptions.upsert({
          agent_id: agentId,
          channel_pubkey: channelHex,
          admin_pubkey: profileAdmin,
          access: acceptedFrame.access,
          relays: acceptedFrame.relays,
          // STORED, not just decoded. What the channel is for and how long its posts last are the
          // two things a subscriber has no other way to learn.
          guidance: acceptedFrame.guidance,
          retention_seconds: acceptedFrame.retention_seconds,
          joined_at: now(),
        });
      }
      subscriptions.addKey(agentId, channelHex, unwrapped.gk, now());
      // M16 032-NOTICES: an ACCEPTANCE stored means this agent is IN — ring "admitted". A re-key
      // also lands a key here but is not an answer to a join, so it never rings (out of scope).
      if (acceptedFrame) deps.onJoinAnswer?.(agentId, channelHex, "admitted");
      return { ok: true, channelHex, generation: unwrapped.gk.generation };
    },

    async approve(channelHex, subscriberHex, sessionId): Promise<{ ok: true } | { ok: false; reason: string }> {
      const admin = deps.localChannelAdmin(channelHex);
      if (!admin) return { ok: false, reason: "channel_not_local" };
      try {
        members.approve(channelHex, subscriberHex);
      } catch (err: unknown) {
        return { ok: false, reason: extractErrorMessage(err) };
      }
      // The delivery's verdict is the ANSWER. Reporting `ok` regardless told an admin they had
      // admitted somebody who in fact received nothing.
      return acceptInto(sessionId, channelHex, subscriberHex, admin);
    },

    async refuse(channelHex, subscriberHex, sessionId): Promise<{ ok: true } | { ok: false; reason: string }> {
      const admin = deps.localChannelAdmin(channelHex);
      if (!admin) return { ok: false, reason: "channel_not_local" };
      const channelPubkey = await admin.channelKeyProvider.getPublicKey();
      /**
       * ⚠️ **CONDITIONAL ON `pending`, AND THAT CONDITION IS THE POINT.** This used to upsert
       * `ejected` unconditionally, so a refusal typed against an existing MEMBER answered `ok`,
       * marked them ejected, and left them holding the current group key and fetch key — reading
       * indefinitely while the table said otherwise. Refusing is not ejecting: an eject re-keys the
       * channel, and a refusal has nothing to re-key because they were never in.
       */
      try {
        members.refusePending(channelHex, subscriberHex);
      } catch (err: unknown) {
        return { ok: false, reason: extractErrorMessage(err) };
      }
      await refuseTo(sessionId, channelPubkey, "refused_by_admin");
      return { ok: true };
    },
  };
}

/** Re-exported so the caller does not need a second import to build a re-key frame. */
export { encodeChannelRekey };
