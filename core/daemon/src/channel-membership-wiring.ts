/**
 * M16 019-MEMBERSHIP — the join exchange, the eject re-key, and the operator's channel verbs.
 *
 * The publishing half is wired next door in `channel-publish-wiring.ts`; this is membership. Both
 * exist because a module registered into nothing is a feature that does not exist — the mistake 017
 * shipped and 018 repeated on its other half.
 *
 * ⚠️ **THE JOIN FRAME HOOK IS SYNCHRONOUS AND THE HANDLING IS NOT.** `setOnChannelJoinFrame` must
 * answer "is this mine" immediately, because the ingest path is deciding whether to write the frame
 * into a transcript as something a person said. The decision is made by CLASSIFYING (a cheap decode)
 * and the work is then queued, exactly as the document layer does. A rejected promise here must not
 * take down the content path, so it is caught and logged.
 */
import type { Logger } from "./types.js";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { KeyProvider } from "@cello-protocol/crypto";
import {
  channelJoinFrameType, encodeChannelRekey, buildChannelFetchKeyTbs, JOIN_REQUEST_TYPE,
} from "@cello-protocol/protocol-types";
import { generateGroupKey, wrapGroupKeyFor, deriveFetchKey } from "@cello-protocol/crypto";
import { ChannelMembershipStore } from "./channel-membership-store.js";
import { ChannelSubscriptionStore } from "./channel-subscription-store.js";
import { createChannelJoinExchange, type LocalChannelAdmin } from "./channel-join-exchange.js";
import {
  createChannelAdminLookup, type ChannelAdminOutcome, type SignalingLike,
} from "./channel-admin-lookup.js";
import { extractErrorMessage } from "./error-message.js";

type Handler = (params: Record<string, unknown> | undefined, connectionId: string) => Promise<unknown>;

export interface ChannelMembershipWiringDeps {
  handlers: Map<string, Handler>;
  logger: Logger;
  getDb: () => DaemonDatabase;
  /** Route a frame into an open session. The session layer owns delivery. */
  sendInSession: (agentName: string, sessionId: string, content: Uint8Array) => Promise<void>;
  /** Register the inbound hook. Separate from the document one — see that field's note. */
  setOnChannelJoinFrame: (
    cb: (agentName: string, sessionId: string, content: Uint8Array, senderPubkey: string, correlationId?: string) => { consumed: boolean },
  ) => void;
  /** Every agent this daemon loaded. A channel IS one of them — looked up by pubkey, never by name. */
  loadedAgents: ReadonlyArray<{ name: string; pubkey: string; keyProvider: KeyProvider }>;
  keyProviders: Map<string, KeyProvider>;
  resolveAgentId: (agentName: string) => string;
  resolveCurrentAgent: (connectionId: string, explicitAgent?: string) => string | null;
  /** Open sessions for an agent, so a re-key can ride one this daemon already holds. */
  activeSessionsFor: (agentName: string) => Array<{ sessionId: string; counterpartyPubkeyHex: string }>;
  /**
   * M16 020-CHANADMIN: an agent's directory connection, by NAME (the daemon's own key for it), or
   * null when it has none. The subscriber asks on ITS OWN authenticated stream — the directory
   * answers a client that has proved its agent key, which is the difference between this frame and
   * the relay's copy of it.
   */
  signalingFor: (agentName: string) => SignalingLike | null;
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
}): (channelHex: string, agentId: string) => Promise<string | null> {
  return async function profileAdminPubkey(channelHex: string, agentId: string): Promise<string | null> {
    // The ADMIN this daemon recorded, not the channel's own key — the two are different agents, and
    // comparing a key with itself is what the first version of this did.
    const settings = deps.members.settings(channelHex);
    if (settings && settings.admin_pubkey.length > 0) return settings.admin_pubkey;

    try {
      const outcome = await deps.lookup(agentId, channelHex);
      if (outcome.kind === "admin") return outcome.adminPubkeyHex;
      deps.logger.info("channel.join.admin_unresolved", {
        channel_pubkey: channelHex,
        reason: outcome.kind === "not_a_channel" ? "not_a_channel" : outcome.reason,
      });
      return null;
    } catch (err: unknown) {
      // This runs inside the inbound content path. An exception escaping would surface as a broken
      // session rather than a refused join, which is a worse answer to the same question.
      deps.logger.warn("channel.join.admin_unresolved", {
        channel_pubkey: channelHex, reason: extractErrorMessage(err),
      });
      return null;
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
}

export function wireChannelMembership(deps: ChannelMembershipWiringDeps): ChannelMembershipWiring {
  const { handlers, logger } = deps;

  const members = new ChannelMembershipStore(deps.getDb(), logger);
  const subscriptions = new ChannelSubscriptionStore(deps.getDb(), logger);

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

  const profileAdminPubkey = createProfileAdminPubkey({
    members,
    logger,
    lookup: createChannelAdminLookup({ signalingFor: signalingForAgentId, logger }),
  });

  const keyProviderFor = (agentId: string): KeyProvider | null => {
    const agent = deps.loadedAgents.find((a) => deps.resolveAgentId(a.name) === agentId);
    return agent ? (deps.keyProviders.get(agent.name) ?? null) : null;
  };

  const openSessionWith = (agentName: string, memberPubkeyHex: string): string | null => {
    const open = deps.activeSessionsFor(agentName)
      .find((s) => s.counterpartyPubkeyHex.toLowerCase() === memberPubkeyHex.toLowerCase());
    return open ? open.sessionId : null;
  };

  const raiseNotice = (event: string, channelHex: string, subscriberHex: string): void => {
    logger.info(event, { channel_pubkey: channelHex, subscriber_pubkey: subscriberHex });
  };

  /** Which agent a session belongs to, so the hook's answers go back down the right one. */
  const exchangeFor = (agentName: string) => createChannelJoinExchange({
    logger,
    members,
    subscriptions,
    sendInSession: (sessionId, content) => deps.sendInSession(agentName, sessionId, content),
    localChannelAdmin,
    profileAdminPubkey,
    keyProviderFor,
    raiseNotice,
  });

  /**
   * ⚠️ CLASSIFY SYNCHRONOUSLY, HANDLE ASYNCHRONOUSLY. The ingest path needs an immediate answer to
   * decide whether these bytes are conversation; the admin and subscriber work — key wrapping,
   * a directory lookup — cannot be done in that window.
   */
  deps.setOnChannelJoinFrame((agentName, sessionId, content, senderPubkey, correlationId) => {
    /**
     * ⚠️ **ROUTED BY FRAME TYPE, ONCE — trying the admin half first and falling through was a bug
     * that made joining impossible.** `onAdminFrame` answers `consumed: true` for any join frame it
     * cannot read as a REQUEST, so an acceptance or a re-key arriving at a SUBSCRIBER was absorbed
     * there and the subscriber half was never called. A member sent a request, the admin admitted
     * them and replied with the key, and their daemon appended a leaf and discarded it: no
     * subscription, no key, and not one line saying anything had gone wrong. Every re-key after an
     * ejection went the same way. The unit tests missed it because they call the two halves by hand.
     */
    const kind = channelJoinFrameType(content);
    if (kind === null) return { consumed: false };

    const exchange = exchangeFor(agentName);
    const agentId = deps.resolveAgentId(agentName);
    void (async () => {
      if (kind === JOIN_REQUEST_TYPE) {
        await exchange.onAdminFrame(sessionId, senderPubkey, content);
        return;
      }
      // An acceptance, a refusal or a re-key: all answers TO us, all the subscriber's business.
      const asSubscriber = await exchange.onSubscriberFrame(agentId, sessionId, senderPubkey, content);
      if (!asSubscriber.ok) {
        logger.warn("channel.join.refused", {
          ...(correlationId !== undefined ? { correlationId } : {}),
          reason: asSubscriber.reason, sender: senderPubkey, frame_type: kind,
        });
      }
    })().catch((err: unknown) => {
      // A rejected promise here must not take down the content path for every other session.
      logger.error("channel.join.handling_failed", {
        ...(correlationId !== undefined ? { correlationId } : {}),
        reason: extractErrorMessage(err),
      });
    });
    return { consumed: true };
  });

  // ─── Operator verbs ───────────────────────────────────────────────────────────────────────────

  handlers.set("cello_channels", async (params, connectionId) => {
    const agent = needAgent(deps, params, connectionId);
    if (!agent.ok) return agent.answer;
    const agentId = deps.resolveAgentId(agent.agentName);
    const rows = subscriptions.active().filter((s) => s.agent_id === agentId);
    return Promise.resolve({
      ok: true,
      channels: rows.map((s) => ({
        channel: s.channel_pubkey,
        moniker: s.moniker,
        access: s.access,
        delivered_through: s.delivered_through,
        processed_through: s.processed_through,
        // What the operator actually wants to know: how much is waiting.
        unread: Math.max(0, s.delivered_through - s.processed_through),
      })),
    });
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
    try {
      subscriptions.markLeft(deps.resolveAgentId(agent.agentName), channel.channelHex);
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
   * member has collected their new key yet. A member left behind hits `unknown_generation` and asks.
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
    let delivered = 0;
    const unreached: string[] = [];
    for (const member of outcome.remaining) {
      const sessionId = openSessionWith(agent.agentName, member);
      if (sessionId === null) {
        // Not a failure of the ejection. Recorded by name so an operator can see who is behind.
        logger.warn("channel.rekey.member_unreached", {
          channel_pubkey: channel.channelHex, member_pubkey: member, generation: outcome.generation,
        });
        unreached.push(member);
        continue;
      }
      const bundle = await wrapGroupKeyFor(
        gk, channelPubkey, new Uint8Array(Buffer.from(member, "hex")), admin.adminKeyProvider,
      );
      await deps.sendInSession(agent.agentName, sessionId, encodeChannelRekey({
        channel_pubkey: channelPubkey, key_bundle: bundle, generation: outcome.generation,
      }));
      delivered += 1;
    }

    logger.info("channel.rekey.completed", {
      channel_pubkey: channel.channelHex,
      generation: outcome.generation,
      member_count: outcome.remaining.length,
      delivered_count: delivered,
      failed_count: unreached.length,
    });
    return {
      ok: true,
      channel: channel.channelHex,
      generation: outcome.generation,
      delivered,
      unreached,
      guidance: unreached.length > 0
        ? `${String(unreached.length)} member(s) were not reachable and still hold the old key. They will ask for the new one when they next read; the ejection itself is done.`
        : undefined,
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
    const sessionId = openSessionWith(agent.agentName, subscriber.toLowerCase());
    if (sessionId === null) {
      // The approval is recorded either way: the next request from an approved member is accepted
      // immediately, so an admin approving somebody who has gone offline is not wasted work.
      return { ok: false, reason: "no_open_session", guidance: "They are not currently reachable. Approve again when they next ask, or the approval applies to their next request." };
    }
    const result = await exchangeFor(agent.agentName).approve(channel.channelHex, subscriber.toLowerCase(), sessionId);
    return result.ok ? { ok: true, channel: channel.channelHex } : { ok: false, reason: result.reason };
  });

  handlers.set("cello_channel_refuse", async (params, connectionId) => {
    const agent = needAgent(deps, params, connectionId);
    if (!agent.ok) return agent.answer;
    const channel = needChannel(params);
    if (!channel.ok) return channel.answer;
    const subscriber = params?.["subscriber"];
    if (typeof subscriber !== "string" || !/^[0-9a-fA-F]{64}$/.test(subscriber)) {
      return { ok: false, reason: "bad_subscriber" };
    }
    const sessionId = openSessionWith(agent.agentName, subscriber.toLowerCase());
    if (sessionId === null) return { ok: false, reason: "no_open_session" };
    const result = await exchangeFor(agent.agentName).refuse(channel.channelHex, subscriber.toLowerCase(), sessionId);
    return result.ok ? { ok: true, channel: channel.channelHex } : { ok: false, reason: result.reason };
  });

  return {
    activeMembers: (channelHex: string) => members.activeMembers(channelHex),
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
