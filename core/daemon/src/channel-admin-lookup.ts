/**
 * M16 020-CHANADMIN — asking a directory who administers a channel.
 *
 * A subscriber that has been handed a group key must check the agent that handed it over against
 * what the directory says about the channel. The session proves who the counterparty IS; it says
 * nothing about whether they have any authority over this channel. Without the check, any agent that
 * can open a session with you becomes your channel.
 *
 * 019 built the check and it could not run: the answer lives in the directory's profile and no
 * client-facing frame carried it. `channel_admin_query` (020, directory side) does, on the
 * authenticated signaling stream. This is the client half.
 *
 * ⚠️ **"NOT A CHANNEL" AND "I COULD NOT FIND OUT" ARE DIFFERENT ANSWERS, and the whole value of this
 * module is keeping them apart.** A negative is authoritative — the subscriber acts on it. A
 * timeout, a down stream, a malformed reply or a directory-side `lookup_failed` are all the absence
 * of an answer, and they leave the join refused. Collapsed into the negative, a directory outage
 * would read as a verdict about the channel, and the step after that is accepting a key from
 * whoever happened to answer.
 */
import type { Logger } from "./types.js";
import { extractErrorMessage } from "./error-message.js";

/**
 * The part of a `SignalingManager` this needs. Structural rather than the class, so the lookup can
 * be exercised without standing up a directory connection.
 */
export interface SignalingLike {
  registerInboundHandler(handler: (frame: Record<string, unknown>) => void): () => void;
  sendRaw(frame: unknown): Promise<{ ok: boolean; reason?: string }>;
}

export type ChannelAdminOutcome =
  /** A registered channel, and the agent the directory says administers it. */
  | { kind: "admin"; adminPubkeyHex: string }
  /** The directory answered, and this pubkey is not a channel — unregistered, or an ordinary agent. */
  | { kind: "not_a_channel" }
  /**
   * 038-RETESTFIX Part D: the directory answered that this channel's identity is revoked (deleted).
   * An authoritative answer the client acts on — distinct from `not_a_channel` (never a channel) and
   * from `unavailable` (no answer). Returned ONLY on an explicit `revoked: true`.
   */
  | { kind: "revoked" }
  /** No answer. NOT a verdict about the channel. */
  | { kind: "unavailable"; reason: string };

export interface ChannelAdminLookupDeps {
  /** The asking agent's directory connection, or null when it has none. */
  signalingFor: (agentId: string) => SignalingLike | null;
  logger: Logger;
  timeoutMs?: number;
}

const DEFAULT_TIMEOUT_MS = 10_000;

/** 64 lowercase hex characters, or nothing. A partial admin key must not reach a comparison. */
function adminPubkeyOf(frame: Record<string, unknown>): string | null {
  const raw = frame["admin_pubkey"];
  if (typeof raw !== "string" || !/^[0-9a-fA-F]{64}$/.test(raw)) return null;
  return raw.toLowerCase();
}

function echoedChannelHex(frame: Record<string, unknown>): string | null {
  const raw = frame["channel_pubkey"];
  if (raw instanceof Uint8Array) return Buffer.from(raw).toString("hex");
  if (Buffer.isBuffer(raw)) return (raw as Buffer).toString("hex");
  if (typeof raw === "string" && /^[0-9a-fA-F]{64}$/.test(raw)) return raw.toLowerCase();
  return null;
}

export function createChannelAdminLookup(
  deps: ChannelAdminLookupDeps,
): (agentId: string, channelHex: string) => Promise<ChannelAdminOutcome> {
  const timeoutMs = deps.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  return async function lookup(agentId: string, channelHexRaw: string): Promise<ChannelAdminOutcome> {
    const channelHex = channelHexRaw.toLowerCase();
    const signaling = deps.signalingFor(agentId);
    if (!signaling) {
      // Answer now rather than waiting out the timeout for a reply that was never coming — this runs
      // on the inbound join path, once per frame.
      return { kind: "unavailable", reason: "signaling_unavailable" };
    }

    let resolveFrame!: (f: Record<string, unknown>) => void;
    const pending = new Promise<Record<string, unknown>>((r) => { resolveFrame = r; });

    /**
     * ⚠️ **MATCHED ON THE ECHOED PUBKEY, not on the frame type alone.** The signaling stream is one
     * multiplexed stream shared by every lookup this agent has in flight. Taking the first
     * `channel_admin_result` that arrives would let two concurrent joins each accept the other's
     * answer — and then the admin check runs against a different channel's administrator, where a
     * match proves nothing.
     */
    const unregister = signaling.registerInboundHandler((frame) => {
      const t = frame["type"];
      if (t !== "channel_admin_result" && t !== "channel_admin_error") return;
      /**
       * ⚠️ **THE ERROR IS MATCHED THE SAME WAY, and it was not at first.** An unmatched error
       * resolved whichever lookup happened to be waiting: two joins in flight, a database fault on
       * the first channel, and the second was refused although the directory had answered it
       * perfectly. It fails closed, so nothing unsafe — it just turns one channel's outage into
       * every concurrent join's refusal, which is a bad trade for a field.
       */
      if (echoedChannelHex(frame) !== channelHex) return;
      resolveFrame(frame);
    });

    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const sent = await signaling.sendRaw({
        type: "channel_admin_query",
        channel_pubkey: new Uint8Array(Buffer.from(channelHex, "hex")),
      });
      if (!sent.ok) {
        // The transport's own reason, never a guess about the directory or the channel.
        return { kind: "unavailable", reason: sent.reason ?? "signaling_unavailable" };
      }

      const timeoutP = new Promise<Record<string, unknown>>((r) => {
        timer = setTimeout(() => r({ type: "__timeout__" }), timeoutMs);
      });
      const frame = await Promise.race([pending, timeoutP]);

      if (frame["type"] === "__timeout__") {
        deps.logger.warn("directory.channel.admin.lookup.failed", { channel: channelHex.slice(0, 16), reason: "timeout" });
        return { kind: "unavailable", reason: "timeout" };
      }
      if (frame["type"] === "channel_admin_error") {
        const reason = typeof frame["reason"] === "string" ? frame["reason"] : "lookup_failed";
        deps.logger.warn("directory.channel.admin.lookup.failed", { channel: channelHex.slice(0, 16), reason });
        return { kind: "unavailable", reason };
      }

      /**
       * ⚠️ **SHAPE FIRST, AND THIS WAS A DEFECT THE TEST CAUGHT.** `registered !== true` is true for
       * a field that is ABSENT as well as one that is `false` — so a reply missing the field
       * entirely read as an authoritative "not a channel", which is precisely the collapse this
       * module exists to prevent. A frame that does not carry both booleans is a directory that
       * replied with something we cannot read, and that is not knowing.
       */
      if (typeof frame["registered"] !== "boolean" || typeof frame["channel"] !== "boolean") {
        deps.logger.warn("directory.channel.admin.lookup.failed", { channel: channelHex.slice(0, 16), reason: "malformed_reply" });
        return { kind: "unavailable", reason: "malformed_reply" };
      }

      /**
       * 038-RETESTFIX Part D: an EXPLICIT `revoked: true` is a settled "the channel was deleted"
       * answer, told apart from `not_a_channel`. Checked before the `registered` branch because a
       * revoked channel answers `registered: false`. Requires `=== true`, so absence or a store fault
       * is never read as deleted (MUST NOT CHANGE item 3).
       */
      if (frame["revoked"] === true) {
        deps.logger.info("directory.channel.admin.lookup", { channel: channelHex.slice(0, 16), answered: "revoked" });
        return { kind: "revoked" };
      }

      if (frame["registered"] !== true || frame["channel"] !== true) {
        // An answer, and a settled one: the subscriber is looking at something that is not a channel.
        deps.logger.info("directory.channel.admin.lookup", { channel: channelHex.slice(0, 16), answered: "not_a_channel" });
        return { kind: "not_a_channel" };
      }

      const adminPubkeyHex = adminPubkeyOf(frame);
      if (adminPubkeyHex === null) {
        /**
         * A registered channel whose answer carries no usable admin key. Reading a missing or
         * malformed field as `""` would put an empty key into the comparison against whoever
         * answered — which either matches nothing for ever or, worse, matches an empty counterparty.
         * So it is `unavailable`: there is no admin to check against, and that is not knowing.
         *
         * ⚠️ **NAMED FOR THE REGISTRATION, NOT THE WIRE.** Calling this `malformed_reply` sent the
         * operator to debug the protocol, when the directory answered exactly as designed about a
         * channel that was registered without an administrator. The reason has to point at the
         * thing that is actually wrong.
         */
        deps.logger.warn("directory.channel.admin.lookup.failed", { channel: channelHex.slice(0, 16), reason: "channel_without_admin" });
        return { kind: "unavailable", reason: "channel_without_admin" };
      }

      deps.logger.info("directory.channel.admin.lookup", { channel: channelHex.slice(0, 16), answered: "admin" });
      return { kind: "admin", adminPubkeyHex };
    } catch (err: unknown) {
      return { kind: "unavailable", reason: extractErrorMessage(err) };
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      unregister();
    }
  };
}
