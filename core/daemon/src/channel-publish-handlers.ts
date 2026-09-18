/**
 * M16 018-PUBCOLLECT — the operator's IPC verbs for publishing on a channel.
 *
 *   cello_channel_publish    publish a post to the channel's relays
 *   cello_channel_info_set   sign and deposit the channel's info record
 *   cello_channel_prune      drop everything through a post number, oldest end only
 *   cello_channel_resend     refill a relay that lost content, or fill a newly added one
 *
 * **IPC only — no MCP tools.** These are the publisher's own administration of a channel it holds
 * the key to, and the caller is a human at a terminal, not an agent mid-conversation. The MCP
 * surface for channels is a later tier; adding one here would put a publishing verb in reach of
 * anything that can drive an agent's tools.
 *
 * Every verb answers `{ ok: false, reason, guidance }` rather than throwing, because the far side is
 * a CLI that has to print something a person can act on.
 */
import type { Logger } from "./types.js";
import type { ChannelPublisher } from "./channel-publisher.js";

type Handler = (params: Record<string, unknown> | undefined, connectionId: string) => Promise<unknown>;

export interface ChannelPublishDeps {
  handlers: Map<string, Handler>;
  logger: Logger;
  getPublisher: (agentName: string) => ChannelPublisher | null;
  /** The daemon's single agent-selection rule, injected rather than re-implemented here. */
  resolveCurrentAgent: (connectionId: string, explicitAgent?: string) => string | null;
}

function needAgent(deps: ChannelPublishDeps, params: Record<string, unknown> | undefined, connectionId: string):
  { ok: true; agentName: string } | { ok: false; answer: Record<string, unknown> } {
  const agentName = deps.resolveCurrentAgent(connectionId, params?.["agent"] as string | undefined);
  if (agentName === null) {
    return {
      ok: false,
      answer: {
        ok: false, reason: "no_current_agent",
        guidance: "Name the agent, or select one for this connection with cello_use_agent.",
      },
    };
  }
  return { ok: true, agentName };
}

function needChannel(params: Record<string, unknown> | undefined):
  { ok: true; channelHex: string } | { ok: false; answer: Record<string, unknown> } {
  const raw = params?.["channel"];
  // 64 hex characters, checked here rather than deeper: a malformed pubkey that reaches the log
  // creates a channel row under a key nothing will ever publish to again.
  if (typeof raw !== "string" || !/^[0-9a-fA-F]{64}$/.test(raw)) {
    return {
      ok: false,
      answer: {
        ok: false, reason: "bad_channel",
        guidance: "Pass the channel's 64-character hex public key as `channel`.",
      },
    };
  }
  return { ok: true, channelHex: raw.toLowerCase() };
}

export function registerChannelPublishHandlers(deps: ChannelPublishDeps): void {
  const { handlers, logger } = deps;

  handlers.set("cello_channel_publish", async (params, connectionId) => {
    const agent = needAgent(deps, params, connectionId);
    if (!agent.ok) return agent.answer;
    const channel = needChannel(params);
    if (!channel.ok) return channel.answer;

    const title = params?.["title"];
    const body = params?.["body"];
    if (typeof title !== "string" || typeof body !== "string") {
      return { ok: false, reason: "bad_post", guidance: "Pass a `title` and a `body`, both strings." };
    }
    const publisher = deps.getPublisher(agent.agentName);
    if (!publisher) {
      return { ok: false, reason: "channel_unknown", guidance: `${agent.agentName} is not a channel this daemon publishes for.` };
    }

    const result = await publisher.publish(agent.agentName, channel.channelHex, title, body);
    if (result.ok) {
      return {
        ok: true, seq: result.seq,
        relays_ok: result.deposited.filter((d) => d.ok).map((d) => d.relay),
        relays_failed: result.deposited.filter((d) => !d.ok).map((d) => d.relay),
      };
    }
    logger.info("channel.publish.refused", { channel_pubkey: channel.channelHex, reason: result.reason });
    return {
      ok: false, reason: result.reason, detail: result.detail,
      // `no_relay_accepted` is the one refusal where the post SURVIVES, and a caller that did not
      // know that would publish it again and burn a second post number on the same content.
      guidance: result.reason === "no_relay_accepted"
        // `cello channel resend`, NOT the handler's own name: these verbs are terminal-only, so a
        // `cello_*` token here would hand the operator a command that does not exist on any surface
        // they can reach.
        ? "No relay took the post. It is in your log — retry with 'cello channel resend' rather than publishing it again."
        : undefined,
    };
  });

  handlers.set("cello_channel_info_set", async (params, connectionId) => {
    const agent = needAgent(deps, params, connectionId);
    if (!agent.ok) return agent.answer;
    const channel = needChannel(params);
    if (!channel.ok) return channel.answer;
    const publisher = deps.getPublisher(agent.agentName);
    if (!publisher) return { ok: false, reason: "channel_unknown" };

    const result = await publisher.publishInfo(agent.agentName, channel.channelHex);
    return result.ok ? { ok: true, bytes: result.info_cbor.length } : { ok: false, reason: result.reason };
  });

  handlers.set("cello_channel_prune", async (params, connectionId) => {
    const agent = needAgent(deps, params, connectionId);
    if (!agent.ok) return agent.answer;
    const channel = needChannel(params);
    if (!channel.ok) return channel.answer;

    const through = params?.["through_seq"];
    if (typeof through !== "number" || !Number.isSafeInteger(through) || through < 1) {
      return { ok: false, reason: "bad_seq", guidance: "Pass `through_seq`: the last post number to drop." };
    }
    const publisher = deps.getPublisher(agent.agentName);
    if (!publisher) return { ok: false, reason: "channel_unknown" };

    const result = await publisher.pruneChannel(agent.agentName, channel.channelHex, through);
    return { ok: true, pruned: result.pruned, relays: result.relays };
  });

  handlers.set("cello_channel_resend", async (params, connectionId) => {
    const agent = needAgent(deps, params, connectionId);
    if (!agent.ok) return agent.answer;
    const channel = needChannel(params);
    if (!channel.ok) return channel.answer;

    const relay = params?.["relay"];
    if (typeof relay !== "string" || relay.length === 0) {
      return { ok: false, reason: "bad_relay", guidance: "Pass `relay`: the multiaddr to refill." };
    }
    const publisher = deps.getPublisher(agent.agentName);
    if (!publisher) return { ok: false, reason: "channel_unknown" };

    const result = await publisher.resendMissing(agent.agentName, channel.channelHex, relay);
    return { ok: true, deposited: result.deposited };
  });
}
