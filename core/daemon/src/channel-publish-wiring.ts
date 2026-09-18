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
import { registerChannelPublishHandlers } from "./channel-publish-handlers.js";
import { ChannelPublisher } from "./channel-publisher.js";
import { ChannelLogStore } from "./channel-log-store.js";
import { ChannelConfigStore } from "./channel-config-store.js";
import { ChannelRelayClient } from "./channel-relay-client.js";

type Handler = (params: Record<string, unknown> | undefined, connectionId: string) => Promise<unknown>;

export interface ChannelPublishWiringDeps {
  handlers: Map<string, Handler>;
  logger: Logger;
  getDb: () => DaemonDatabase;
  getNode: () => CelloNode | null;
  screenOutbound: (content: Uint8Array, ctx: ScreenContext) => Promise<ScreenVerdict>;
  /** Every agent this daemon loaded, read per lookup so one added after boot is publishable. */
  loadedAgents: ReadonlyArray<{ pubkey: string; keyProvider: KeyProvider }>;
  keyProviders: Map<string, KeyProvider>;
  resolveCurrentAgent: (connectionId: string, explicitAgent?: string) => string | null;
}

export function wireChannelPublishing(deps: ChannelPublishWiringDeps): void {
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
      db: deps.getDb(),
      logger,
      log,
      deposit: (addr, req) => relay.deposit(addr, { post_cbor: req.post_cbor }),
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

  registerChannelPublishHandlers({
    handlers: deps.handlers,
    logger,
    resolveCurrentAgent: deps.resolveCurrentAgent,
    getPublisher: buildPublisher,
  });
}
