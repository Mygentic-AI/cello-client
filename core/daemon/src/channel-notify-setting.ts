/**
 * Per-channel push/pull: the gate that decides whether a new post rings an agent, and the handler that
 * sets it. Storage is in ChannelSubscriptionStore (`notify`).
 *
 * `pull` still fetches and stores every post and keeps the unread count. Only the doorbell for new
 * posts is withheld, so the agent, or a cron job, reads with `cello channel read` on its own schedule.
 * Every other channel doorbell (a join answer, an ejection, a poster removal) still rings: those are
 * about the agent's own membership, not about how busy the channel is.
 */
import type { ChannelNotify } from "./channel-membership-wiring.js";
import { ChannelSubscriptionStore, type ChannelNotifyMode, type ChannelSubscription } from "./channel-subscription-store.js";
import type { NotificationDispatcher } from "./notification-dispatcher.js";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

type Handler = (params: Record<string, unknown> | undefined, connectionId: string) => Promise<unknown>;

/**
 * Wrap the daemon's channel doorbells so a `pull` channel's new-post doorbell is dropped.
 *
 * A lookup that throws rings anyway: a broken setting must never cost an agent a notification, and a
 * duplicate doorbell is harmless where a missing one is not.
 */
export function gateChannelNotify(
  base: ChannelNotify,
  subscriptions: { notifyFor: (agentId: string, channelHex: string) => ChannelNotifyMode },
): ChannelNotify {
  return {
    ...base,
    channelPosts: (agentId, channelHex, count, through, posters) => {
      let mode: ChannelNotifyMode = "push";
      try {
        mode = subscriptions.notifyFor(agentId, channelHex);
      } catch {
        mode = "push";
      }
      if (mode === "pull") return;
      base.channelPosts(agentId, channelHex, count, through, posters);
    },
  };
}

export interface ChannelNotifyHandlerDeps {
  resolveCurrentAgent: (connectionId: string, explicitAgent?: string) => string | null;
  resolveAgentId: (agentName: string) => string;
  subscriptions: {
    get: (agentId: string, channelHex: string) => ChannelSubscription | null;
    setNotify: (agentId: string, channelHex: string, mode: ChannelNotifyMode) => void;
  };
}

/** `cello_channel_set_notify`: the wire method behind `cello channel notify` and `cello_channel_notify`. */
export function registerChannelNotifyHandler(handlers: Map<string, Handler>, deps: ChannelNotifyHandlerDeps): void {
  handlers.set("cello_channel_set_notify", (params, connectionId) => {
    const agentName = deps.resolveCurrentAgent(connectionId, params?.["agent"] as string | undefined);
    if (agentName === null) {
      return Promise.resolve({ ok: false, reason: "no_current_agent", guidance: "Name the agent, or select one with cello_use_agent." });
    }
    const raw = params?.["channel"];
    if (typeof raw !== "string" || !/^[0-9a-fA-F]{64}$/.test(raw)) {
      return Promise.resolve({ ok: false, reason: "bad_channel", guidance: "Pass the channel's 64-character hex public key as `channel`." });
    }
    const mode = params?.["mode"];
    if (mode !== "push" && mode !== "pull") {
      return Promise.resolve({
        ok: false, reason: "bad_mode",
        guidance: "Pass `mode`: \"push\" to be told when new posts arrive, or \"pull\" to read them yourself with the channel read tool.",
      });
    }
    const channelHex = raw.toLowerCase();
    const agentId = deps.resolveAgentId(agentName);
    if (deps.subscriptions.get(agentId, channelHex) === null) {
      return Promise.resolve({
        ok: false, reason: "not_following",
        guidance: "This agent does not follow that channel. Join it first, then choose push or pull.",
      });
    }
    deps.subscriptions.setNotify(agentId, channelHex, mode);
    return Promise.resolve({
      ok: true, channel: channelHex, notify: mode,
      guidance: mode === "pull"
        ? "New posts are still collected and counted as unread, but this agent is no longer told when they arrive. Read them with the channel read tool."
        : "This agent is told when new posts arrive.",
    });
  });
}

/**
 * The daemon's real channel doorbells: each maps the agent id to its current display name and dispatches
 * only when one is current (a retired agent has nobody to wake). INV-CONTENTFREE lives in the dispatcher;
 * this only routes. The dispatcher is passed as a GETTER: the composition root declares it after these
 * are built, so it is read at ring time and never at construction.
 */
export function dispatcherNotify(dispatcher: () => NotificationDispatcher, named: (agentId: string) => string | null): ChannelNotify {
  return {
    channelPosts: (id, ch, count, through, posters) => { const n = named(id); if (n !== null) dispatcher().dispatchChannelPosts(n, ch, count, through, posters); },
    channelJoinAnswer: (id, ch, outcome, reason) => { const n = named(id); if (n !== null) dispatcher().dispatchChannelJoinAnswer(n, ch, outcome, reason); },
    channelJoinRequest: (id, ch, sub, note) => { const n = named(id); if (n !== null) dispatcher().dispatchChannelJoinRequest(n, ch, sub, note); },
    channelMembershipEnded: (id, ch, reason) => { const n = named(id); if (n !== null) dispatcher().dispatchChannelMembershipEnded(n, ch, reason); },
    channelPosterRemoved: (id, ch) => { const n = named(id); if (n !== null) dispatcher().dispatchChannelPosterRemoved(n, ch); },
  };
}

export interface WireChannelNotifyDeps {
  /** The daemon's real doorbells; the returned object rings through these unless a channel is `pull`. */
  base: ChannelNotify;
  handlers: Map<string, Handler>;
  getDb: () => DaemonDatabase;
  logger: Logger;
  resolveCurrentAgent: (connectionId: string, explicitAgent?: string) => string | null;
  resolveAgentId: (agentName: string) => string;
}

/**
 * The composition the daemon uses: registers `cello_channel_set_notify` and returns the doorbells with
 * the pull gate on. Both read the setting from the same store, read live at ring time so a change takes
 * effect on the next post.
 *
 * One store per database handle. Constructing one runs CREATE TABLE IF NOT EXISTS and a column check,
 * which is too much for every new-post doorbell; the handle can change, so the store is cached against
 * the handle and not built once for good.
 */
export function wireChannelNotify(deps: WireChannelNotifyDeps): ChannelNotify {
  let cache: { db: unknown; store: ChannelSubscriptionStore } | null = null;
  const subs = (): ChannelSubscriptionStore => {
    const db = deps.getDb();
    if (cache === null || cache.db !== db) cache = { db, store: new ChannelSubscriptionStore(db, deps.logger) };
    return cache.store;
  };
  registerChannelNotifyHandler(deps.handlers, {
    resolveCurrentAgent: deps.resolveCurrentAgent,
    resolveAgentId: deps.resolveAgentId,
    subscriptions: {
      get: (agentId, channelHex) => subs().get(agentId, channelHex),
      setNotify: (agentId, channelHex, mode) => { subs().setNotify(agentId, channelHex, mode); },
    },
  });
  return gateChannelNotify(deps.base, { notifyFor: (agentId, channelHex) => subs().notifyFor(agentId, channelHex) });
}
