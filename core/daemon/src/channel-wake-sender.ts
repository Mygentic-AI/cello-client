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
      void signaling.sendRaw({
        type: "channel_wake_request",
        channel_pubkey: new Uint8Array(Buffer.from(channelHex, "hex")),
        agent_pubkeys: members.map((m) => new Uint8Array(Buffer.from(m, "hex"))),
      }).then(
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
