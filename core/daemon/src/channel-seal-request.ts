/**
 * Requested seals, the publisher-side half — M16 011-SEALREQ.
 *
 * Until an epoch is sealed, a subscriber has authenticity but no proof against equivocation, so a
 * subscriber may ASK the publisher to seal early. A seal costs a directory threshold signature, and
 * "anyone can make the publisher burn one" is a grinding lever. Hence the settled rule:
 *
 *   - a request is honored at most ONCE PER CHANNEL PER HOUR, for everyone — the publisher's own
 *     request goes through this same gate, because the publisher's daemon is a client that can be
 *     scripted and the limiter protects the directory;
 *   - inside the window a request is a no-op that REPORTS the latest seal, so the requester still
 *     has a root to verify against — it never seals "to be helpful";
 *   - only an honored request consumes the window: an empty epoch sealed nothing, so it must not
 *     deny a real request an hour later.
 *
 * The window is in memory only. A restart resets it; the directory keeps its own limiter.
 * The relay frame that carries a subscriber's request lands on `requestSeal` in a later tier.
 */
import { randomUUID } from "node:crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import { ChannelEpochSealer } from "./channel-epoch-sealer.js";
import { ChannelEpochSealStore } from "./channel-epoch-seal-store.js";
import type { ChannelLogStore } from "./channel-log-store.js";
import { DbIdentityStore } from "./db-identity-store.js";
import type { IpcHandler } from "./ipc-server.js";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

export const SEAL_REQUEST_WINDOW_MS = 60 * 60 * 1000;

export type SealRequestOutcome =
  | { honored: true; epoch_index: number; epoch_root: Uint8Array; leaf_count: number }
  | { honored: false; reason: "rate_limited"; latest_epoch_index: number | null; latest_epoch_root: Uint8Array | null; retry_after_ms: number }
  | { honored: false; reason: "epoch_empty"; latest_epoch_index: number | null; latest_epoch_root: Uint8Array | null }
  | { honored: false; reason: "channel_unknown" | "key_unavailable" };

export class ChannelSealRequestGate {
  readonly #deps: { sealer: ChannelEpochSealer; sealStore: ChannelEpochSealStore; logger: Logger; now: () => number };
  /** channel pubkey hex → when its last request was HONORED. Nothing else writes it. */
  readonly #lastHonoredAt = new Map<string, number>();
  /**
   * channel pubkey hex → the seal currently being attempted for it. The window check and this
   * reservation happen with no await between them, so a request arriving mid-seal waits for that
   * seal and then meets the window it set, instead of starting a second seal of the same epoch.
   */
  readonly #inFlight = new Map<string, Promise<unknown>>();

  constructor(deps: { sealer: ChannelEpochSealer; sealStore: ChannelEpochSealStore; logger: Logger; now: () => number }) {
    this.#deps = deps;
  }

  /** requester: "publisher" or the requesting subscriber's pubkey hex. */
  async requestSeal(channelPubkeyHex: string, requester: string, correlationId: string): Promise<SealRequestOutcome> {
    const { sealer, sealStore, logger, now } = this.#deps;
    const latest = () => {
      const l = sealStore.latest(channelPubkeyHex);
      return { latest_epoch_index: l?.epoch_index ?? null, latest_epoch_root: l?.epoch_root ?? null };
    };

    // A request that finds a seal in flight waits for it; that seal's own caller sees its outcome or error.
    for (let pending = this.#inFlight.get(channelPubkeyHex); pending; pending = this.#inFlight.get(channelPubkeyHex)) {
      await pending.catch(() => undefined);
    }

    // elapsed < WINDOW → report the latest seal, seal nothing; elapsed >= WINDOW honors.
    const last = this.#lastHonoredAt.get(channelPubkeyHex);
    const t = now();
    if (last !== undefined && t - last < SEAL_REQUEST_WINDOW_MS) {
      const retry_after_ms = SEAL_REQUEST_WINDOW_MS - (t - last);
      logger.info("channel.seal_request.rate_limited", { correlationId, channel_pubkey: channelPubkeyHex, requester, retry_after_ms });
      return { honored: false, reason: "rate_limited", ...latest(), retry_after_ms };
    }

    const attempt = sealer.sealNow(channelPubkeyHex, correlationId);
    this.#inFlight.set(channelPubkeyHex, attempt);
    let outcome: Awaited<typeof attempt>;
    try {
      outcome = await attempt;
    } finally {
      this.#inFlight.delete(channelPubkeyHex);
    }
    if (!outcome.sealed) {
      // Nothing was sealed, so the window stays open.
      if (outcome.reason === "epoch_empty") return { honored: false, reason: "epoch_empty", ...latest() };
      return { honored: false, reason: outcome.reason };
    }
    this.#lastHonoredAt.set(channelPubkeyHex, t);
    logger.info("channel.seal_request.honored", { correlationId, channel_pubkey: channelPubkeyHex, requester, epoch_index: outcome.epoch_index });
    return { honored: true, epoch_index: outcome.epoch_index, epoch_root: outcome.epoch_root, leaf_count: outcome.leaf_count };
  }
}

export interface ChannelSealHandlerDeps {
  handlers: Map<string, IpcHandler>;
  logger: Logger;
  sessionNodeManager: { getDb(): DaemonDatabase; getChannelLogStore(): ChannelLogStore };
  getKeyProvider: (agentName: string) => KeyProvider | undefined;
  now?: () => number;
}

const hex = (b: Uint8Array | null): string | null => (b ? Buffer.from(b).toString("hex") : null);

/** `cello_channel_seal { agent }` — the publisher's own seal, through the same limiter. */
export function registerChannelSealHandler(deps: ChannelSealHandlerDeps): void {
  const { handlers, logger, sessionNodeManager, getKeyProvider } = deps;
  const identities = () => new DbIdentityStore(sessionNodeManager.getDb(), logger);
  // One gate for the daemon's lifetime: a gate per call would forget the window. Built on first use
  // because the database is not needed until a seal is asked for.
  let gate: ChannelSealRequestGate | null = null;
  const gateFor = (): ChannelSealRequestGate => {
    if (gate) return gate;
    const now = deps.now ?? (() => Date.now());
    const sealStore = new ChannelEpochSealStore(sessionNodeManager.getDb(), logger);
    const sealer = new ChannelEpochSealer({
      log: sessionNodeManager.getChannelLogStore(), sealStore, logger, now,
      getKeyProvider: (channelHex) => {
        const agent = identities().listAgents().find((a) => a.kLocalPubkey === channelHex && a.state !== "retired");
        return (agent && getKeyProvider(agent.agentName)) ?? null;
      },
    });
    return (gate = new ChannelSealRequestGate({ sealer, sealStore, logger, now }));
  };

  handlers.set("cello_channel_seal", async (params) => {
    const name = params?.agent;
    if (typeof name !== "string" || name === "") {
      return { ok: false, reason: "missing_params", guidance: "Provide 'agent': the name of the channel agent whose open epoch should be sealed." };
    }
    const store = identities();
    const agent = store.listAgents().find((a) => a.agentName === name && a.state !== "retired");
    if (!agent) {
      return {
        ok: false, reason: "agent_not_found",
        guidance: `No agent named '${name}' exists on this daemon. Check the name with cello_agents, then retry with the channel agent's exact name.`,
      };
    }
    if (!store.isChannelAgent(name)) {
      return {
        ok: false, reason: "not_a_channel",
        guidance: `'${name}' is not a broadcast channel on this daemon, so it has no epoch to seal. Pass the name of a channel agent (one registered with channel: true).`,
      };
    }
    const outcome = await gateFor().requestSeal(agent.kLocalPubkey, "publisher", randomUUID());
    if (outcome.honored) return { ...outcome, epoch_root: hex(outcome.epoch_root) };
    if (outcome.reason === "rate_limited" || outcome.reason === "epoch_empty") {
      return { ...outcome, latest_epoch_root: hex(outcome.latest_epoch_root) };
    }
    return outcome;
  });
}
