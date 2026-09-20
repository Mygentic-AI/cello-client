/**
 * M16 018-PUBCOLLECT — everything the channel publishing verbs need, assembled in one place.
 *
 * ⚠️ The publisher is built PER CHANNEL AGENT and only when its key is loaded — a channel is an
 * agent whose key this daemon holds, and a publisher without one could sign nothing. `null` makes
 * the verb answer `channel_unknown`, which is the truth: this daemon does not publish for it.
 *
 * Order 017's own wiring gap is why this module is registered in the same commit as the handlers it
 * serves: a handler nothing calls is a feature that does not exist, and `startup-ordering.test.ts`
 * is what caught exactly that here.
 */
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { ScreenContext, ScreenVerdict } from "@cello-protocol/gateway";
import { Buffer } from "node:buffer";
import { registerChannelPublishHandlers, recordChannelConfig, depositChannelInfo } from "./channel-publish-handlers.js";
import { registerChannelCreateHandler } from "./channel-create-handler.js";
import { DbIdentityStore } from "./db-identity-store.js";
import { ChannelPublisher } from "./channel-publisher.js";
import { ChannelLogStore } from "./channel-log-store.js";
import { ChannelConfigStore, type ChannelConfig } from "./channel-config-store.js";
import { ChannelRelayClient } from "./channel-relay-client.js";
import { ChannelCollector } from "./channel-collector.js";
import { ChannelSubscriptionStore } from "./channel-subscription-store.js";
import { ChannelInboxStore } from "./channel-inbox-store.js";
import { createChannelCollectTicker } from "./channel-collect-tick.js";
import { createChannelWakeSender } from "./channel-wake-sender.js";

type Handler = (params: Record<string, unknown> | undefined, connectionId: string) => Promise<unknown>;

export interface ChannelPublishWiringDeps {
  handlers: Map<string, Handler>;
  logger: Logger;
  getDb: () => DaemonDatabase;
  /** M16 021-WAKE: who a post's doorbell is rung for. From the membership half, which owns the list. */
  activeMembers: (channelHex: string) => string[];
  /** M16 021-WAKE: the publishing agent's own directory connection, by agent NAME. */
  signalingFor: (agentName: string) => { sendRaw(frame: unknown): Promise<{ ok: boolean; reason?: string }> } | null;
  getNode: () => CelloNode | null;
  screenOutbound: (content: Uint8Array, ctx: ScreenContext) => Promise<ScreenVerdict>;
  /** Every agent this daemon loaded, read per lookup so one added after boot is publishable. */
  loadedAgents: ReadonlyArray<{ name: string; pubkey: string; keyProvider: KeyProvider }>;
  keyProviders: Map<string, KeyProvider>;
  resolveCurrentAgent: (connectionId: string, explicitAgent?: string) => string | null;
  /**
   * M16 019: the channel's current fetch key, signed, or undefined when this daemon holds no group
   * key for it. Injected rather than derived here so the membership half owns the group key and
   * this half never has to hold one.
   */
  currentFetchKey?: (channelHex: string) => Promise<{ pubkey: Uint8Array; time_ms: number; signature: Uint8Array } | undefined>;
  /**
   * Online AND not explicitly switched off — the same pair every other background loop here reads.
   * Collecting for an agent the operator switched off is the kill switch failing to switch off.
   */
  isAgentOnline: (agentId: string) => boolean;
}

export function wireChannelPublishing(
  deps: ChannelPublishWiringDeps,
): { stop: () => void; collectNow: (agentId: string) => Promise<void> } {
  const { logger, keyProviders } = deps;

  const log = new ChannelLogStore(deps.getDb(), logger);
  const config = new ChannelConfigStore(deps.getDb(), logger);
  const relay = new ChannelRelayClient({ getNode: deps.getNode, logger });

  /**
   * The channel key is looked up BY PUBKEY, because that is what a post is signed with and what a
   * subscriber verifies against — the agent NAME is a display label and may be reused.
   */
  const channelKeyByPubkey = (channelHex: string): KeyProvider | null => {
    const want = channelHex.toLowerCase();
    const match = deps.loadedAgents.find((a) => a.pubkey.toLowerCase() === want);
    return match ? match.keyProvider : null;
  };

  const buildPublisher = (agentName: string): ChannelPublisher | null => {
    if (!keyProviders.has(agentName)) return null;
    return new ChannelPublisher({
      logger,
      log,
      deposit: (addr, req) => relay.deposit(addr, {
        post_cbor: req.post_cbor,
        ...(req.fetch_key ? { fetch_key: req.fetch_key } : {}),
      }),
      /**
       * ⚠️ **THE KEY THAT MAKES AN EJECTION BITE AT THE RELAY.** Derived from the channel's current
       * group key, signed with the CHANNEL key because the post's signature does not cover it, and
       * sent with each deposit so a re-key reaches the relays on the very next post. `undefined`
       * means this daemon holds no group key for that channel — a public one, or one it does not
       * administer — and the relay then serves it to anyone, which for a public channel is correct.
       */
      currentFetchKey: deps.currentFetchKey,
      depositInfo: (addr, req) => relay.depositInfo(addr, { info_cbor: req.info_cbor }),
      prune: (addr, req) => relay.prune(addr, {
        channel_pubkey: Buffer.from(req.channelHex, "hex"),
        through_seq: req.throughSeq,
        time_ms: req.timeMs,
        signature: req.signature,
      }),
      relayHead: (addr, channelHex) => relay.head(addr, Buffer.from(channelHex, "hex")),
      // The screen has no session to name, so it names what it IS screening. Borrowing a session id
      // would file channel posts in another conversation's governance history.
      screenOutbound: (bytes, ctx) =>
        deps.screenOutbound(bytes, {
          direction: "outbound",
          agentName: ctx.agentName,
          sessionId: `channel:${agentName}`,
          ...(ctx.correlationId !== undefined ? { correlationId: ctx.correlationId } : {}),
        }),
      getChannelKey: channelKeyByPubkey,
      getAgentKey: (name) => keyProviders.get(name) ?? null,
      /**
       * ⚠️ **THERE IS NO GROUP KEY UNTIL 019**, so a private channel REFUSES to publish rather than
       * depositing a body that looks encrypted and is not. Publishing plaintext under an `access`
       * that promises members-only would put the operator's content on two relays under a claim
       * this code cannot keep — the one failure the whole encrypt step exists to prevent.
       */
      encryptBody: () => Promise.reject(new Error("channel_group_key_unavailable")),
      channelInfo: (channelHex) => config.get(channelHex),
    });
  };

  /**
   * M16 021-WAKE. The publishing agent asks on ITS OWN directory stream — the directory checks the
   * caller is the channel's admin, so it has to be that agent's connection and not any that happens
   * to be open.
   */
  const sendWake = createChannelWakeSender({
    logger,
    activeMembers: (channelHex) => deps.activeMembers(channelHex),
    signalingFor: (agentId) => deps.signalingFor(agentId),
  });

  const setChannelConfig = (agentName: string, channelHex: string, cfg: ChannelConfig):
    { ok: true } | { ok: false; reason: string; guidance?: string } => {
    // The channel key must be one this daemon HOLDS. Recording relays for a channel we cannot
    // sign for would leave every later verb failing on a key lookup, which describes neither the
    // mistake nor how to correct it.
    if (channelKeyByPubkey(channelHex) === null) {
      return {
        ok: false, reason: "channel_key_not_held",
        guidance: "This daemon does not hold that channel's key. A channel is an agent — create it with 'cello create-agent' and use its public key here.",
      };
    }
    if (!keyProviders.has(agentName)) {
      return { ok: false, reason: "no_such_agent", guidance: `${agentName} is not an agent this daemon holds.` };
    }
    /**
     * ⚠️ **THE ADMIN AGENT IS RECORDED HERE, and it is what makes the channel joinable at all.**
     * `agentName` is the agent running the setup, and in this release the publisher and the admin
     * are the same operator — so that agent's key is the one a subscriber will check the answering
     * party against. Leaving it empty was how 019's first cut produced a channel that refused
     * every join with `not_admin_of_channel` on a channel it demonstrably administered.
     */
    const adminAgent = deps.loadedAgents.find((a) => a.name === agentName);
    config.set(channelHex, { ...cfg, admin_pubkey: adminAgent?.pubkey ?? "" }, Date.now());
    return { ok: true };
  };

  registerChannelPublishHandlers({
    handlers: deps.handlers,
    logger,
    resolveCurrentAgent: deps.resolveCurrentAgent,
    getPublisher: buildPublisher,
    wakeMembers: (agentName, channelHex) => sendWake(agentName, channelHex),
    setChannelConfig,
  });

  /**
   * M16 024-CREATE: the one command that brings a channel into existence, composing register →
   * config → info-set in-process. The three steps are the EXISTING code, reused: registration goes
   * through the `cello_register` handler, and config/info-set through the functions the publish
   * handlers were refactored onto (`recordChannelConfig` / `depositChannelInfo`).
   */
  registerChannelCreateHandler({
    handlers: deps.handlers,
    logger,
    resolveCurrentAgent: deps.resolveCurrentAgent,
    agentPubkey: (agentName) => deps.loadedAgents.find((a) => a.name === agentName)?.pubkey ?? null,
    registerChannel: async ({ name, preAuthToken, adminPubkeyHex, access, correlationId }) => {
      const register = deps.handlers.get("cello_register");
      if (!register) {
        // Unreachable in production — registered at boot. A miss here is a WIRING bug, not an
        // operator error, so it throws rather than mislabelling itself as a failed create step.
        throw new Error("channel_create_wiring: the register handler is not wired");
      }

      // Refuse a name that is ALREADY a registered identity before anything runs. Re-registering it
      // would either clobber it or spend the token on a DKG for an identity that already exists.
      const existing = new DbIdentityStore(deps.getDb(), logger).getAgentForRevocation(name);
      if (existing && existing.state === "registered") {
        return {
          ok: false, reason: "channel_name_registered",
          guidance: `'${name}' is already a registered identity, so it cannot be created as a channel. Choose a different name.`,
        };
      }

      // Fold the mint in: over MCP there is no cello_create_agent tool, so an agent could never
      // satisfy a "create the identity first" precondition. When the name has no local key, mint it
      // here through the existing handler; if the mint fails, nothing was created.
      let mintedHere = false;
      if (!keyProviders.has(name)) {
        const createAgent = deps.handlers.get("cello_create_agent");
        if (!createAgent) throw new Error("channel_create_wiring: the create-agent handler is not wired");
        const made = (await createAgent({ name }, "internal:channel-create")) as { ok?: boolean; reason?: string; guidance?: string };
        if (made?.ok !== true) {
          return { ok: false, reason: made?.reason ?? "agent_create_failed", guidance: made?.guidance };
        }
        mintedHere = true;
      }

      const reg = (await register(
        { agent: name, preAuthToken, channel: true, adminPubkeyHex, access, correlationId },
        "internal:channel-create",
      )) as { ok?: boolean; reason?: string };
      if (reg?.ok !== true) {
        // Roll back an identity WE minted so a failed create leaves nothing behind — "nothing exists
        // yet" is the register step's contract. `reason` is passed up; the guidance is deliberately
        // NOT (the create handler writes its own, which names `cello channel create`, never
        // `register-agent` — that would spend the next token on an ordinary agent that can never
        // become a channel).
        if (mintedHere) {
          const removeAgent = deps.handlers.get("cello_remove_agent");
          if (removeAgent) await removeAgent({ name }, "internal:channel-create").catch(() => undefined);
        }
        return { ok: false, reason: reg?.reason ?? "register_failed" };
      }

      // The channel's own pubkey is its loaded K_local key — what a post is signed with and what
      // config/info-set are addressed by (the agent NAME is a mutable display label). Resolve it the
      // way register-handler does, from the loaded key material that a successful register guarantees.
      const loaded = deps.loadedAgents.find((a) => a.name === name);
      const kp = keyProviders.get(name);
      const channelPubkeyHex = loaded?.pubkey ?? (kp ? Buffer.from(await kp.getPublicKey()).toString("hex") : undefined);
      if (channelPubkeyHex === undefined) {
        throw new Error("channel_create_wiring: registered channel key not loaded");
      }
      return { ok: true, channelPubkeyHex };
    },
    applyChannelConfig: (agentName, channelHex, cfg) =>
      recordChannelConfig({ logger, setChannelConfig }, agentName, channelHex, cfg),
    depositChannelInfo: (agentName, channelHex, correlationId) =>
      depositChannelInfo({ getPublisher: buildPublisher }, agentName, channelHex, correlationId),
  });

  /**
   * ⚠️ THE SUBSCRIBER HALF, AND IT NEEDS A SCHEDULE TO EXIST AT ALL. There is no inbound event for a
   * channel post — the relay holds a queue and waits to be asked — so a collector nobody calls is a
   * subscriber who receives nothing while every component reports healthy.
   */
  const subscriptions = new ChannelSubscriptionStore(deps.getDb(), logger);
  const inbox = new ChannelInboxStore(deps.getDb(), logger);
  const collector = new ChannelCollector({
    logger,
    subscriptions,
    inbox,
    fetch: (addr, req) => relay.fetch(addr, req),
    /**
     * ⚠️ **PUBLIC CHANNELS ONLY, UNTIL 019.** `undefined` means "send no auth", which is correct for
     * a public channel and correct nowhere else: 019 owns the fetch key. A non-public channel is
     * refused by the RELAY rather than silently fetched — the failure is visible and belongs to the
     * side that can check it.
     */
    fetchAuth: () => Promise.resolve(undefined),
    // The reader count is best-effort and never affects delivery, so declaring nothing costs only
    // the publisher's view of how many read a post. 019 records the membership this reads from.
    localAgentKeys: () => [],
    /**
     * ⚠️ NOT IMPLEMENTED, AND IT SAYS SO. Asking the publisher to re-deposit needs a session to the
     * publishing agent, which is 019's join path. Until then the OTHER RELAY is the whole repair —
     * `repairGaps` tries that first and usually closes the gap there. A silent no-op would let a
     * permanent gap look like one still being worked on.
     */
    requestRepair: (_agentId, channelHex, from, to) => {
      logger.warn("channel.repair.unavailable", {
        channel_pubkey: channelHex, from, to,
        impact: "neither relay holds these posts; asking the publisher directly needs the join path (019)",
      });
      return Promise.resolve();
    },
  });

  const ticker = createChannelCollectTicker({
    logger, collector, subscriptions,
    isAgentOnline: deps.isAgentOnline,
  });
  ticker.start();

  return {
    stop: () => { ticker.stop(); },
    // M16 021-WAKE: what the doorbell calls. Exposed rather than wired here because the frame
    // arrives on the agent's signaling stream, which this module does not own.
    collectNow: (agentId: string) => ticker.collectNow(agentId),
  };
}
