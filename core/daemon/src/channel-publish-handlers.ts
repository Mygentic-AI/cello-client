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
import { DEFAULT_RETENTION_SECONDS, type ChannelConfig } from "./channel-config-store.js";

type Handler = (params: Record<string, unknown> | undefined, connectionId: string) => Promise<unknown>;

export interface ChannelPublishDeps {
  handlers: Map<string, Handler>;
  logger: Logger;
  getPublisher: (agentName: string) => ChannelPublisher | null;
  /**
   * Record the publisher's decisions for a channel it holds the key to. REFUSES when this daemon
   * does not hold that channel's key — otherwise an operator could record relays for somebody
   * else's channel and every later verb would fail with a key error instead of the real reason.
   */
  setChannelConfig: (agentName: string, channelHex: string, config: ChannelConfig) =>
    { ok: true } | { ok: false; reason: string; guidance?: string };
  /**
   * Read the channel's current config, or null when this daemon holds none. Used by
   * `cello_channel_info_set` to change ONE field (the guidance) while keeping the others, so it
   * never has to re-supply the relays/access to edit the description (035-INFOCLI item 2).
   */
  getChannelConfig: (channelHex: string) => ChannelConfig | null;
  /** The daemon's single agent-selection rule, injected rather than re-implemented here. */
  resolveCurrentAgent: (connectionId: string, explicitAgent?: string) => string | null;
  /**
   * M16 021-WAKE: ring the doorbell for this channel's members after a post lands.
   *
   * ⚠️ **IT CANNOT FAIL A PUBLISH.** The post is deposited and durable before this is called, and
   * every failure inside it is logged and dropped — an unreachable directory means subscribers
   * collect on their backstop poll, which is what the poll is for.
   */
  wakeMembers?: (agentName: string, channelHex: string) => Promise<void>;
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

/**
 * 035-INFOCLI item 5: a channel relay must be a real, dialable multiaddr.
 *
 * ⚠️ **THE `/p2p/<peer id>` TAIL IS REQUIRED, NOT DECORATION.** The peer id is how the relay is
 * AUTHENTICATED on connect — a directory-picked relay and the libp2p relays the enforcer runs all
 * carry one (`/ip4/…/tcp/…/p2p/12D3KooW…`). An address without it is not a usable relay: setup used
 * to accept a bare hostname like `relay-usc1.cello.mygentic.ai`, and every later publish then failed
 * on a dial that never had a peer to reach.
 *
 * Shape: `/dns4|dns6|ip4|ip6/<host>/tcp/<port>` then any transport segments (`/tls/ws`, …) and
 * ending in `/p2p/<peer id>`.
 */
const RELAY_MULTIADDR_RE = /^\/(dns4|dns6|ip4|ip6)\/[^/]+\/tcp\/\d+(\/[^/]+)*\/p2p\/[A-Za-z0-9]+$/;

function badRelay(relay: string): Record<string, unknown> {
  return {
    ok: false, reason: "bad_relay",
    guidance: `'${relay}' is not a usable relay. A relay must be a multiaddr of the form /dns4|dns6|ip4|ip6/<host>/tcp/<port>/…/p2p/<peer id> — the peer id (…/p2p/12D3KooW…) is how the relay is authenticated when the channel dials it.`,
  };
}

/**
 * Record a publisher's decisions for a channel it holds the key to — the SAME code
 * `cello_channel_config` runs, extracted so `cello_channel_create` (024) composes it rather than
 * copying it. Returns only success/failure; the config handler adds its own operator-facing shape.
 */
export function recordChannelConfig(
  deps: Pick<ChannelPublishDeps, "logger" | "setChannelConfig">,
  agentName: string,
  channelHex: string,
  cfg: ChannelConfig,
): { ok: true } | { ok: false; reason: string; guidance?: string } {
  const saved = deps.setChannelConfig(agentName, channelHex, cfg);
  if (!saved.ok) return { ok: false, reason: saved.reason, guidance: saved.guidance };
  deps.logger.info("channel.config.recorded", {
    channel_pubkey: channelHex, access: cfg.access, relays: cfg.relays.length,
  });
  return { ok: true };
}

/**
 * Sign and deposit a channel's info record — the SAME code `cello_channel_info_set` runs, extracted
 * so `cello_channel_create` (024) composes it rather than copying it.
 */
export async function depositChannelInfo(
  deps: Pick<ChannelPublishDeps, "getPublisher">,
  agentName: string,
  channelHex: string,
  correlationId?: string,
): Promise<
  | { ok: true; bytes: number; relays_ok: string[]; relays_failed: Array<{ relay: string; reason?: string }> }
  | { ok: false; reason: string; detail?: string; guidance?: string }
> {
  const publisher = deps.getPublisher(agentName);
  if (!publisher) return { ok: false, reason: "channel_unknown" };

  const result = await publisher.publishInfo(agentName, channelHex, correlationId);
  if (!result.ok) {
    return {
      ok: false, reason: result.reason, detail: result.detail,
      guidance: result.reason === "no_relay_accepted"
        ? "No relay took the channel's description, so nobody can discover this channel yet. Check the relays are reachable and run it again."
        : undefined,
    };
  }
  return {
    ok: true,
    bytes: result.info_cbor.length,
    // WHICH relays hold it, not just that it was signed. A subscriber can only find this channel
    // through a relay that actually took the record.
    relays_ok: result.relays.filter((r) => r.ok).map((r) => r.relay),
    relays_failed: result.relays.filter((r) => !r.ok).map((r) => ({ relay: r.relay, reason: r.reason })),
  };
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
      // The doorbell, after the post is durable and never before: a wake for a post that failed to
      // deposit would send every member to fetch something that is not there.
      await deps.wakeMembers?.(agent.agentName, channel.channelHex);
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

  /**
   * Record what this publisher has decided about its own channel: which relays it publishes to,
   * whether it is public, what it is for, how long posts are kept.
   *
   * ⚠️ **NOTHING ELSE WRITES THIS, AND WITHOUT IT NO CHANNEL CAN PUBLISH AT ALL.** The publisher
   * reads the relay pair from here; with no row, every verb answers `channel_unknown` for ever. The
   * first version of this unit shipped the four verbs with no way to create the row they all read.
   *
   * It does NOT deposit anything. `cello_channel_info_set` signs and publishes the description to
   * the relays; this is the local decision it is signed from. Keeping them apart means a publisher
   * can change its mind and re-publish, rather than the relays' copy being the only record.
   */
  handlers.set("cello_channel_config", async (params, connectionId) => {
    const agent = needAgent(deps, params, connectionId);
    if (!agent.ok) return agent.answer;
    const channel = needChannel(params);
    if (!channel.ok) return channel.answer;

    const rawRelays = params?.["relays"];
    const relays = Array.isArray(rawRelays) ? rawRelays.filter((r): r is string => typeof r === "string") : [];
    if (relays.length === 0 || relays.length !== (rawRelays as unknown[]).length) {
      return {
        ok: false, reason: "bad_relays",
        guidance: "Pass `relays`: the multiaddrs this channel publishes to. Two is the design — one is a single point of failure, and the subscriber takes the union of both.",
      };
    }
    // 035-INFOCLI item 5: each relay must be a real, /p2p-terminated multiaddr — a bare hostname or
    // a multiaddr with no peer id cannot be dialed, and accepting it made every later verb fail on a
    // relay it could never reach.
    const badRelayValue = relays.find((r) => !RELAY_MULTIADDR_RE.test(r));
    if (badRelayValue !== undefined) return badRelay(badRelayValue);
    const access = params?.["access"];
    if (access !== "public" && access !== "open" && access !== "invite_only") {
      return {
        ok: false, reason: "bad_access",
        guidance: "Pass `access`: public (anyone can read), open (anyone may ask to join) or invite_only.",
      };
    }
    /**
     * ⚠️ **ACCESS IS FIXED AT CREATE (036-PUBLICSUB reviewer M-1).** Subscribers joined the access
     * they were told, and a subscriber's read decides plaintext-vs-decrypt from its STORED access —
     * so flipping public→open here would make existing readers try to decrypt a plaintext post, and
     * open→public would strip a channel's encryption out from under them. A channel that wants
     * different access is a different channel (the directory's V67 note). Relays remain changeable;
     * only an access that DIFFERS from the stored one is refused, so re-running setup to change
     * relays with the same access is fine, and create (which writes the first config) is unaffected.
     */
    const existing = deps.getChannelConfig(channel.channelHex);
    if (existing && existing.access !== access) {
      return {
        ok: false, reason: "access_is_fixed",
        guidance: "A channel's access is set when it is created and cannot change — subscribers joined the one they were told. Create a new channel with the access you want.",
      };
    }

    const guidance = typeof params?.["guidance"] === "string" ? params["guidance"] : "";
    const retention = params?.["retention_seconds"];
    const retention_seconds = typeof retention === "number" && Number.isSafeInteger(retention) && retention > 0
      ? retention
      : DEFAULT_RETENTION_SECONDS;

    const recorded = recordChannelConfig(deps, agent.agentName, channel.channelHex, {
      access, relays, guidance, retention_seconds,
    });
    if (!recorded.ok) return { ok: false, reason: recorded.reason, guidance: recorded.guidance };

    return {
      ok: true, channel: channel.channelHex, access, relays, retention_seconds,
      guidance: "Recorded locally. Run 'cello channel info-set' to publish the description so subscribers can find the channel.",
    };
  });

  handlers.set("cello_channel_info_set", async (params, connectionId) => {
    const agent = needAgent(deps, params, connectionId);
    if (!agent.ok) return agent.answer;
    const channel = needChannel(params);
    if (!channel.ok) return channel.answer;

    /**
     * 035-INFOCLI item 2: `--guidance <text>` CHANGES the description. Store it in the same config
     * the deposit is signed from, THEN deposit — so the record carries the new text and `channel
     * info` reads it back. Absent guidance, nothing is stored and this is the old deposit-only path.
     */
    const guidance = params?.["guidance"];
    if (typeof guidance === "string") {
      const cfg = deps.getChannelConfig(channel.channelHex);
      if (!cfg) {
        // No local config means this daemon does not administer the channel, so there is nothing to
        // edit — the same shape `cello_channel_config` gives for a channel whose key it does not hold.
        return {
          ok: false, reason: "channel_unknown",
          guidance: "This daemon holds no config for that channel, so there is no description to change. Set it up first with 'cello channel setup' or 'cello channel create'.",
        };
      }
      const saved = deps.setChannelConfig(agent.agentName, channel.channelHex, { ...cfg, guidance });
      if (!saved.ok) return { ok: false, reason: saved.reason, guidance: saved.guidance };
    }
    return depositChannelInfo(deps, agent.agentName, channel.channelHex);
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
    const stillHolding = result.relays.filter((r) => !r.ok);
    return {
      ok: true,
      pruned: result.pruned,
      relays: result.relays,
      // The log is pruned either way — that part is local and cannot fail halfway. A relay that did
      // not drop its copy KEEPS SERVING those posts, and saying so is the difference between an
      // operator who knows their content is still out there and one who believes it is gone.
      guidance: stillHolding.length > 0
        ? `Your own copy is pruned. ${String(stillHolding.length)} relay(s) did not drop theirs and will keep serving those posts until retention expires.`
        : undefined,
    };
  });

  handlers.set("cello_channel_resend", async (params, connectionId) => {
    const agent = needAgent(deps, params, connectionId);
    if (!agent.ok) return agent.answer;
    const channel = needChannel(params);
    if (!channel.ok) return channel.answer;

    const publisher = deps.getPublisher(agent.agentName);
    if (!publisher) return { ok: false, reason: "channel_unknown" };

    /**
     * ⚠️ **NO RELAY NAMED MEANS ALL OF THEM**, and that is the ordinary case. Requiring the operator
     * to type a multiaddr made this verb impossible to run from the terminal, which left a relay
     * that lost content with no repair path at all — the one job this verb has. Naming a relay
     * stays available for the case where only one needs refilling.
     */
    const raw = params?.["relay"];
    if (raw !== undefined && (typeof raw !== "string" || raw.length === 0)) {
      return { ok: false, reason: "bad_relay", guidance: "Pass `relay` as a multiaddr, or leave it out to refill every relay." };
    }
    const targets = typeof raw === "string" ? [raw] : publisher.relaysFor(channel.channelHex);
    if (targets.length === 0) {
      return {
        ok: false, reason: "channel_unknown",
        guidance: "This daemon has no relays recorded for that channel, so there is nothing to refill.",
      };
    }

    const per: Array<{ relay: string; deposited: number }> = [];
    for (const target of targets) {
      const result = await publisher.resendMissing(agent.agentName, channel.channelHex, target);
      per.push({ relay: target, deposited: result.deposited });
    }
    return { ok: true, deposited: per.reduce((n, r) => n + r.deposited, 0), relays: per };
  });
}
