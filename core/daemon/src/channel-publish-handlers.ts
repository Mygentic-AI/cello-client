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
  /**
   * 044-POSTERBELL: a POSTER's own doorbell, rung after its post lands, carrying a relay receipt as
   * proof. Same "cannot fail a publish" contract as `wakeMembers`. Called instead of `wakeMembers`
   * when the publish was a poster publish (the result carries a `poster_receipt_cbor`).
   */
  ringPosterWake?: (agentName: string, channelHex: string, relayReceiptCbor: Uint8Array) => Promise<void>;
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
      //
      // 044-POSTERBELL: a POSTER rings the members ITSELF, carrying a relay receipt as proof — the
      // admin is no longer in the path. A poster publish carries `poster_receipt_cbor`; an admin
      // publish does not, and rings by its admin binding exactly as before.
      if (result.poster_receipt_cbor) {
        await deps.ringPosterWake?.(agent.agentName, channel.channelHex, result.poster_receipt_cbor);
      } else {
        await deps.wakeMembers?.(agent.agentName, channel.channelHex);
      }
      return {
        ok: true, seq: result.seq,
        relays_ok: result.deposited.filter((d) => d.ok).map((d) => d.relay),
        relays_failed: result.deposited.filter((d) => !d.ok).map((d) => d.relay),
      };
    }
    logger.info("channel.publish.refused", { channel_pubkey: channel.channelHex, reason: result.reason });
    /**
     * 044-POSTERBELL Part E2: a removed poster is TOLD, plainly, and never sent to resend. When the
     * relays refused because the admin removed this poster (or the pass lapsed), the reason is the
     * relay's own, the guidance says so, and there is no "resend" advice — a resend would be refused
     * identically, and the post has already been dropped from the lane.
     */
    const removedPoster: Record<string, string> = {
      pass_revoked: "The admin removed you as a poster on this channel. Your earlier posts stay.",
      posting_closed: "This channel no longer accepts poster posts; only the admin posts now. Your earlier posts stay.",
      pass_expired: "Your posting pass for this channel has expired; the admin renews it while online. Your earlier posts stay.",
    };
    if (result.reason in removedPoster) {
      return { ok: false, reason: result.reason, guidance: removedPoster[result.reason] };
    }
    /**
     * 040-CLEANUP Part E / 041 Part E2: when EVERY relay refused `not_a_channel`, there are TWO
     * causes and the guidance must cover both. A channel created in the last minute has not reached
     * the relays yet (their short negative cache holds `not_a_channel` for up to 30s) — wait and
     * resend. But an OLDER channel refused this way may have been deleted, so also point at
     * `channel info`. The first version assumed only the new-channel case, which read as wrong for a
     * channel that was actually gone. Any other refusal keeps the ordinary "post is in your log" text.
     */
    const deposited = result.deposited ?? [];
    const allNotAChannel = deposited.length > 0 && deposited.every((d) => d.ok === false && d.reason === "not_a_channel");
    return {
      ok: false, reason: result.reason, detail: result.detail,
      // `no_relay_accepted` is the one refusal where the post SURVIVES, and a caller that did not
      // know that would publish it again and burn a second post number on the same content.
      guidance: result.reason !== "no_relay_accepted"
        ? undefined
        : allNotAChannel
          // `cello channel resend`/`cello channel info`, NOT the handlers' own names: these verbs are
          // terminal-only, so a `cello_*` token here would name a command that exists on no surface
          // the operator can reach.
          ? `The relays do not know this channel. If you created it in the last minute, they need up to 30 seconds — run \`cello channel resend ${channel.channelHex}\` in half a minute. If it is older, check \`cello channel info ${channel.channelHex}\`: it may have been deleted.`
          : "No relay took the post. It is in your log — retry with 'cello channel resend' rather than publishing it again.",
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

    /**
     * 038-RETESTFIX Part A: an absent field KEEPS the stored value on a re-setup, and only falls to
     * the empty/default when there is no stored config (a create). The first cut defaulted an absent
     * guidance to "" and an absent retention to the default unconditionally, so re-running setup to
     * change the relays WIPED the channel's description (live F34). `existing` is the config store's
     * current row, already read above for the access check.
     */
    const guidance = typeof params?.["guidance"] === "string"
      ? params["guidance"]
      : (existing ? existing.guidance : "");
    const retention = params?.["retention_seconds"];
    const retention_seconds = typeof retention === "number" && Number.isSafeInteger(retention) && retention > 0
      ? retention
      : (existing ? existing.retention_seconds : DEFAULT_RETENTION_SECONDS);

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
    let guidanceChanged = false;
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
      guidanceChanged = true;
    }
    const deposited = await depositChannelInfo(deps, agent.agentName, channel.channelHex);
    /**
     * 040-CLEANUP Part C: the new description IS saved locally above, but if no relay took the
     * deposit the change has not reached subscribers — they still read the OLD text. The generic
     * "nobody can discover this channel" line does not say that, so an operator who changed the
     * description thinks it landed. Say plainly that the save is local-only and how to retry.
     * Only when the description was actually CHANGED — an unchanged re-deposit has no "old text".
     */
    if (guidanceChanged && !deposited.ok && deposited.reason === "no_relay_accepted") {
      return {
        ok: false, reason: "no_relay_accepted",
        guidance: `Saved here, but no relay took it — subscribers still see the old description. Run \`cello channel info-set ${channel.channelHex}\` again to retry.`,
      };
    }
    return deposited;
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
    const targets = typeof raw === "string" ? [raw] : publisher.relaysFor(channel.channelHex, agent.agentName);
    if (targets.length === 0) {
      return {
        ok: false, reason: "channel_unknown",
        guidance: "This daemon has no relays recorded for that channel, so there is nothing to refill.",
      };
    }

    const per: Array<{ relay: string; deposited: number }> = [];
    let rung = false;
    for (const target of targets) {
      const result = await publisher.resendMissing(agent.agentName, channel.channelHex, target);
      // 039 review: a refusal is not "nothing to resend". It is the same for every relay, so the
      // first one answers for all of them and names why nothing was sent.
      if (result.refused === "channel_unknown") {
        return {
          ok: false, reason: "channel_unknown",
          guidance: "This daemon has no settings for that channel (it may have been deleted), so it cannot tell who may read it and sends nothing.",
        };
      }
      if (result.refused === "no_fetch_key") {
        return {
          ok: false, reason: "key_unavailable",
          guidance: "This channel has no group key yet, so the relays cannot be told who may read it; admit a member first.",
        };
      }
      // 043-POSTERS: a poster refilling its own lane needs a live pass and its own key.
      if (result.refused === "no_posting_pass" || result.refused === "key_unavailable") {
        return {
          ok: false, reason: result.refused,
          guidance: result.refused === "no_posting_pass"
            ? "This agent holds no unexpired posting pass for that channel; the admin renews passes while online."
            : "This agent's key is not loaded.",
        };
      }
      per.push({ relay: target, deposited: result.deposited });
      // 044-POSTERBELL: a poster refilling its lane rings the members too, with a receipt from this
      // resend. One ring for the whole resend — the first relay that yielded a receipt is enough.
      if (result.poster_receipt_cbor && !rung) {
        rung = true;
        await deps.ringPosterWake?.(agent.agentName, channel.channelHex, result.poster_receipt_cbor);
      }
    }
    return { ok: true, deposited: per.reduce((n, r) => n + r.deposited, 0), relays: per };
  });
}
