/**
 * M16 021-WAKE — the publisher's half of the doorbell.
 *
 * Once a post is on the relays, ask the directory to poke this channel's members so they fetch now
 * instead of at their next backstop tick. That is the whole difference between a channel that is
 * useful for "I'm taking the relays down in a minute" and one that is email with an inbox check.
 *
 * ⚠️ **NOTHING HERE CAN FAIL A PUBLISH, and that is the entire error policy.** By the time this
 * runs the post is deposited and durable. A directory that is unreachable, a refusal, a thrown
 * stream — every one of them leaves a published post that subscribers WILL collect on their timer.
 * Surfacing any of it as a publish failure would tell an operator nothing was published when
 * everything was, which is both wrong and alarming. They are logged and dropped.
 */
import type { Logger } from "./types.js";
import { extractErrorMessage } from "./error-message.js";

/** Just the send half of a `SignalingManager` — structural, so this is testable without one. */
export interface WakeSignaling {
  sendRaw(frame: unknown): Promise<{ ok: boolean; reason?: string }>;
}

export interface ChannelWakeSenderDeps {
  logger: Logger;
  /** The channel's ACTIVE members. Pending and ejected rows are excluded by the store. */
  activeMembers: (channelHex: string) => string[];
  /** The publishing agent's own directory connection, or null when it has none. */
  signalingFor: (agentId: string) => WakeSignaling | null;
}

/** The one `channel_wake_request` frame, shared by a post's doorbell and an admin notice's ring. */
function sendWakeRequest(signaling: WakeSignaling, channelHex: string, members: string[]): Promise<{ ok: boolean; reason?: string }> {
  return signaling.sendRaw({
    type: "channel_wake_request",
    channel_pubkey: new Uint8Array(Buffer.from(channelHex, "hex")),
    agent_pubkeys: members.map((m) => new Uint8Array(Buffer.from(m, "hex"))),
  });
}

/**
 * M16 045-NOTICEBELL — ring NAMED members about a channel notice (eject, new key, pass, removal,
 * delete). The admin agent asks on its own directory stream, exactly as a post's doorbell does; the
 * directory stores nothing. AWAITED, unlike a post's doorbell: the admin verb reports whether the
 * ring went out. `false` = no stream, a refusal, or a throw — each logged, never thrown.
 */
export async function ringChannelMembers(
  deps: { logger: Logger; signalingFor: (agentName: string) => WakeSignaling | null },
  adminAgentName: string, channelHex: string, members: string[],
): Promise<boolean> {
  if (members.length === 0) return true;
  const signaling = deps.signalingFor(adminAgentName);
  if (!signaling) {
    deps.logger.warn("channel.notice.ring_skipped", { channel_pubkey: channelHex, reason: "signaling_unavailable", members: members.length });
    return false;
  }
  try {
    const res = await sendWakeRequest(signaling, channelHex, members);
    if (!res.ok) {
      deps.logger.warn("channel.notice.ring_refused", { channel_pubkey: channelHex, reason: res.reason ?? "unknown", members: members.length });
      return false;
    }
    deps.logger.info("channel.notice.rung", { channel_pubkey: channelHex, members: members.length });
    return true;
  } catch (err: unknown) {
    deps.logger.warn("channel.notice.ring_failed", { channel_pubkey: channelHex, reason: extractErrorMessage(err), members: members.length });
    return false;
  }
}

/**
 * Returns a function to call AFTER a successful publish. It resolves as soon as the frame is
 * handed to the transport — it is a nudge, not a handshake, and the publisher must never block on
 * a directory's reply to finish publishing.
 */
export function createChannelWakeSender(
  deps: ChannelWakeSenderDeps,
): (adminAgentId: string, channelHex: string) => Promise<void> {
  return function sendWake(adminAgentId: string, channelHex: string): Promise<void> {
    try {
      const members = deps.activeMembers(channelHex);
      if (members.length === 0) {
        // A request naming nobody can only be refused, and it would still spend one of the
        // channel's rate-limit tokens doing it.
        return Promise.resolve();
      }

      const signaling = deps.signalingFor(adminAgentId);
      if (!signaling) {
        deps.logger.debug("channel.wake.skipped", {
          channel_pubkey: channelHex,
          reason: "signaling_unavailable",
          impact: "subscribers collect this post on their backstop poll instead of at once",
        });
        return Promise.resolve();
      }

      /**
       * ⚠️ **NOT AWAITED.** The reply is for the directory's own logs; waiting for it would put a
       * network round trip inside the publish path for information the publisher does not act on.
       * The rejection handler exists so a dead stream is a log line rather than an unhandled
       * rejection taking down the process.
       */
      void sendWakeRequest(signaling, channelHex, members).then(
        (res) => {
          if (!res.ok) {
            deps.logger.debug("channel.wake.refused", {
              channel_pubkey: channelHex, reason: res.reason ?? "unknown",
              impact: "subscribers collect this post on their backstop poll instead of at once",
            });
          }
        },
        (err: unknown) => {
          deps.logger.debug("channel.wake.failed", {
            channel_pubkey: channelHex, reason: extractErrorMessage(err),
            impact: "subscribers collect this post on their backstop poll instead of at once",
          });
        },
      );
      return Promise.resolve();
    } catch (err: unknown) {
      // Reading the member list is the only thing left that can throw here, and a publish that
      // succeeded must not be reported as failed because the doorbell could not be rung.
      deps.logger.warn("channel.wake.failed", {
        channel_pubkey: channelHex, reason: extractErrorMessage(err),
        impact: "subscribers collect this post on their backstop poll instead of at once",
      });
      return Promise.resolve();
    }
  };
}

/**
 * M16 044-POSTERBELL — a POSTER's own doorbell.
 *
 * When a poster posts, its daemon rings the channel's members itself — the admin is no longer in the
 * path. The ring carries the poster's PASS (its authority) and one RELAY RECEIPT (proof it just
 * posted); the directory checks those instead of an admin binding. Targets are the members the admin
 * last sent with the pass, minus the poster itself.
 *
 * ⚠️ **NOTHING HERE CAN FAIL A PUBLISH.** By the time this runs the post is on the relays. A missing
 * pass, no members yet, no directory stream, a refusal — every one is a log line and a fall back to
 * the members' backstop poll, never a publish failure.
 */
export interface PosterWakeSenderDeps {
  logger: Logger;
  /** The poster's held pass row for a channel: its pass bytes and the members it should ring. */
  posterPassFor: (agentId: string, channelHex: string) => { pass_cbor: Uint8Array; members: string[] } | null;
  /** The poster's own pubkey hex, so it never rings itself. */
  ownPubkeyHex: (agentName: string) => string | null;
  /** The poster agent's own directory connection (keyed by agent name), or null when it has none. */
  signalingFor: (agentName: string) => WakeSignaling | null;
  resolveAgentId: (agentName: string) => string;
}

export function createPosterWakeSender(
  deps: PosterWakeSenderDeps,
): (agentName: string, channelHex: string, relayReceiptCbor: Uint8Array) => Promise<void> {
  return function ringPosterWake(agentName: string, channelHex: string, relayReceiptCbor: Uint8Array): Promise<void> {
    try {
      const agentId = deps.resolveAgentId(agentName);
      const held = deps.posterPassFor(agentId, channelHex);
      if (!held) {
        deps.logger.debug("channel.poster_wake.skipped", {
          channel_pubkey: channelHex, reason: "no_pass",
          impact: "members collect this post on their backstop poll instead of at once",
        });
        return Promise.resolve();
      }
      const own = deps.ownPubkeyHex(agentName)?.toLowerCase();
      const targets = held.members.filter((m) => m.toLowerCase() !== own);
      if (targets.length === 0) {
        // Nobody but the poster to ring: a request naming nobody can only be refused.
        return Promise.resolve();
      }
      const signaling = deps.signalingFor(agentName);
      if (!signaling) {
        deps.logger.debug("channel.poster_wake.skipped", {
          channel_pubkey: channelHex, reason: "signaling_unavailable",
          impact: "members collect this post on their backstop poll instead of at once",
        });
        return Promise.resolve();
      }
      // Not awaited: the reply is for the directory's own logs; the poster does not act on it.
      void signaling.sendRaw({
        type: "channel_wake_request",
        channel_pubkey: new Uint8Array(Buffer.from(channelHex, "hex")),
        agent_pubkeys: targets.map((m) => new Uint8Array(Buffer.from(m, "hex"))),
        poster_pass: held.pass_cbor,
        relay_receipt: relayReceiptCbor,
      }).then(
        (res) => {
          if (!res.ok) {
            deps.logger.debug("channel.poster_wake.refused", {
              channel_pubkey: channelHex, reason: res.reason ?? "unknown",
              impact: "members collect this post on their backstop poll instead of at once",
            });
          }
        },
        (err: unknown) => {
          deps.logger.debug("channel.poster_wake.failed", {
            channel_pubkey: channelHex, reason: extractErrorMessage(err),
            impact: "members collect this post on their backstop poll instead of at once",
          });
        },
      );
      return Promise.resolve();
    } catch (err: unknown) {
      deps.logger.warn("channel.poster_wake.failed", {
        channel_pubkey: channelHex, reason: extractErrorMessage(err),
        impact: "members collect this post on their backstop poll instead of at once",
      });
      return Promise.resolve();
    }
  };
}
