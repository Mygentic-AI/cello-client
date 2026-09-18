/**
 * M16 020-CHANADMIN — asking the directory who administers a channel.
 *
 * This is the lookup behind the subscriber's admin check. The check itself was built in 019 and
 * could never run: there was no client-facing frame carrying the answer, so it refused every channel
 * this daemon did not itself administer.
 *
 * ⚠️ **THE DISTINCTION EVERY TEST HERE IS ABOUT: "it is not a channel" and "I could not find out"
 * are different answers.** The first is authoritative and the subscriber acts on it. The second is a
 * directory being unreachable or faulting, and it must leave the join refused. Collapse them and an
 * outage becomes a reason to accept a group key from whoever answered.
 */
import { describe, it, expect, vi } from "vitest";
import type { Logger } from "../types.js";
import { createChannelAdminLookup, type SignalingLike } from "../channel-admin-lookup.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const AGENT = "agent-1";
const CHANNEL = "c1".repeat(32);
const OTHER_CHANNEL = "c2".repeat(32);
const ADMIN = "ad".repeat(32);

/** A signaling manager that answers with whatever `reply` builds from the outgoing frame. */
function fakeSignaling(reply: (sent: Record<string, unknown>) => Record<string, unknown> | null): SignalingLike & {
  sentFrames: Record<string, unknown>[];
} {
  const handlers = new Set<(f: Record<string, unknown>) => void>();
  const sentFrames: Record<string, unknown>[] = [];
  return {
    sentFrames,
    registerInboundHandler(h) {
      handlers.add(h);
      return () => handlers.delete(h);
    },
    async sendRaw(frame: unknown) {
      const sent = frame as Record<string, unknown>;
      sentFrames.push(sent);
      const answer = reply(sent);
      if (answer) queueMicrotask(() => { for (const h of handlers) h(answer); });
      return { ok: true as const };
    },
  };
}

function resultFor(channelHex: string, over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    type: "channel_admin_result",
    channel_pubkey: new Uint8Array(Buffer.from(channelHex, "hex")),
    registered: true,
    channel: true,
    admin_pubkey: ADMIN,
    ...over,
  };
}

function lookupWith(signaling: SignalingLike | null, timeoutMs = 50) {
  return createChannelAdminLookup({
    signalingFor: () => signaling,
    logger: silent,
    timeoutMs,
  });
}

describe("M16 020 — the channel admin lookup", () => {
  it("7. a channel the directory knows resolves to its administrator", async () => {
    const sig = fakeSignaling(() => resultFor(CHANNEL));
    const out = await lookupWith(sig)(AGENT, CHANNEL);
    expect(out).toEqual({ kind: "admin", adminPubkeyHex: ADMIN });

    const sent = sig.sentFrames[0];
    expect(sent["type"]).toBe("channel_admin_query");
    expect(Buffer.from(sent["channel_pubkey"] as Uint8Array).toString("hex")).toBe(CHANNEL);
  });

  it("8. unregistered, and registered-but-not-a-channel, are both 'not a channel'", async () => {
    const unknown = await lookupWith(
      fakeSignaling(() => resultFor(CHANNEL, { registered: false, channel: false, admin_pubkey: "" })),
    )(AGENT, CHANNEL);
    expect(unknown).toEqual({ kind: "not_a_channel" });

    // ⚠️ Being registered is not being a channel. An ordinary agent's pubkey carries no admin, and
    // an empty admin compared against whoever answered is a comparison that can only go wrong.
    const plain = await lookupWith(
      fakeSignaling(() => resultFor(CHANNEL, { channel: false, admin_pubkey: "" })),
    )(AGENT, CHANNEL);
    expect(plain).toEqual({ kind: "not_a_channel" });
  });

  it("9. an answer about a DIFFERENT channel is ignored, and the lookup times out", async () => {
    /**
     * ⚠️ **THE CROSS-TALK TEST, AND WITHOUT IT THE ECHO IS DECORATION.** The signaling stream is
     * one multiplexed stream and replies are matched by frame type. Two joins in flight would each
     * take the other's answer — so a subscriber joining channel A would check the agent that
     * answered against channel B's administrator, and a match there means nothing at all.
     *
     * The directory's answer here is well-formed and names a real admin. It is simply about the
     * wrong channel, and the only thing that can tell is the echoed pubkey.
     */
    const sig = fakeSignaling(() => resultFor(OTHER_CHANNEL));
    const out = await lookupWith(sig)(AGENT, CHANNEL);
    expect(out.kind).toBe("unavailable");
    if (out.kind === "unavailable") expect(out.reason).toBe("timeout");
  });

  it("9b. an ERROR about a different channel does not settle this lookup either", async () => {
    /**
     * ⚠️ **ONE CHANNEL'S FAULT MUST NOT REFUSE EVERY OTHER JOIN IN FLIGHT.** The error frame first
     * shipped with no channel on it, and was taken by whichever lookup was waiting — so a database
     * fault on channel A refused a join to channel B that the directory had answered correctly. It
     * fails closed, which is why nothing caught it; it just spreads one outage across everything
     * the agent is doing.
     */
    const sig = fakeSignaling(() => ({
      type: "channel_admin_error",
      channel_pubkey: new Uint8Array(Buffer.from(OTHER_CHANNEL, "hex")),
      reason: "lookup_failed",
    }));
    const out = await lookupWith(sig)(AGENT, CHANNEL);
    expect(out.kind).toBe("unavailable");
    if (out.kind === "unavailable") expect(out.reason, "timed out rather than taking the other channel's fault").toBe("timeout");
  });

  it("9c. a channel with no administrator names the REGISTRATION, not the wire", async () => {
    // The directory answered exactly as designed, about a channel registered without an admin.
    // Calling this `malformed_reply` sent the operator to debug the protocol.
    const sig = fakeSignaling(() => resultFor(CHANNEL, { admin_pubkey: "" }));
    const out = await lookupWith(sig)(AGENT, CHANNEL);
    expect(out.kind).toBe("unavailable");
    if (out.kind === "unavailable") expect(out.reason).toBe("channel_without_admin");
  });

  it("10. a directory fault is UNAVAILABLE and never 'not a channel'", async () => {
    /**
     * ⚠️ **THE SECURITY-CARRYING CASE.** `lookup_failed` means the directory could not look. Read as
     * a negative it says "that is not a channel" about a channel that plainly is — and the
     * subscriber's next move after a clean negative is nothing like its next move after not knowing.
     */
    const sig = fakeSignaling(() => ({
      type: "channel_admin_error",
      channel_pubkey: new Uint8Array(Buffer.from(CHANNEL, "hex")),
      reason: "lookup_failed",
    }));
    const out = await lookupWith(sig)(AGENT, CHANNEL);
    expect(out.kind).toBe("unavailable");
    if (out.kind === "unavailable") expect(out.reason).toBe("lookup_failed");
  });

  it("11. no signaling connection answers immediately, and never waits out the timeout", async () => {
    // A daemon whose directory stream is down cannot ask. Waiting would stall the join handler for
    // the full timeout on every frame, for an answer that was never coming.
    const started = Date.now();
    const out = await lookupWith(null, 5_000)(AGENT, CHANNEL);
    expect(out.kind).toBe("unavailable");
    if (out.kind === "unavailable") expect(out.reason).toBe("signaling_unavailable");
    expect(Date.now() - started).toBeLessThan(1_000);
  });

  it("11b. a send that fails carries the transport's own reason, not a guess", async () => {
    const sig: SignalingLike = {
      registerInboundHandler: () => () => {},
      sendRaw: async () => ({ ok: false as const, reason: "signaling_reconnecting" }),
    };
    const out = await lookupWith(sig)(AGENT, CHANNEL);
    expect(out).toEqual({ kind: "unavailable", reason: "signaling_reconnecting" });
  });

  it("12. silence times out as unavailable", async () => {
    const sig = fakeSignaling(() => null);
    const out = await lookupWith(sig)(AGENT, CHANNEL);
    expect(out.kind).toBe("unavailable");
    if (out.kind === "unavailable") expect(out.reason).toBe("timeout");
  });

  it("12b. a malformed reply is unavailable, not an admin and not a negative", async () => {
    // A reply came back and did not parse — a protocol or version anomaly on a directory that DID
    // respond. Reading a missing admin_pubkey as "" would compare an empty key against the answerer.
    const sig = fakeSignaling(() => ({ type: "channel_admin_result", channel_pubkey: new Uint8Array(Buffer.from(CHANNEL, "hex")) }));
    const out = await lookupWith(sig)(AGENT, CHANNEL);
    expect(out.kind).toBe("unavailable");
    // Named, or this assertion would also pass against a valid reply being called unavailable.
    if (out.kind === "unavailable") expect(out.reason).toBe("malformed_reply");
  });

  it("12c. the inbound handler is unregistered once the lookup settles", async () => {
    // Every join frame runs one of these. A handler left behind per lookup is an unbounded leak on
    // the daemon's hottest inbound path.
    const unregister = vi.fn();
    const sig: SignalingLike = {
      registerInboundHandler: (h) => {
        queueMicrotask(() => h(resultFor(CHANNEL)));
        return unregister;
      },
      sendRaw: async () => ({ ok: true as const }),
    };
    await lookupWith(sig)(AGENT, CHANNEL);
    expect(unregister).toHaveBeenCalled();
  });
});
