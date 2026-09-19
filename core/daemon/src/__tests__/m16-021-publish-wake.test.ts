/**
 * M16 021-WAKE — the publisher's half of the doorbell.
 *
 * After a post is on the relays, the publisher asks its directory to wake the channel's members so
 * they fetch now rather than at their next backstop tick. This is the decision layer: WHO is named,
 * WHEN it is sent, and — the part that matters most — what happens when it fails.
 *
 * ⚠️ **A WAKE THAT FAILS MUST NOT FAIL THE POST.** The post is already deposited and durable by the
 * time this runs. Turning a doorbell failure into a publish failure would make an operator believe
 * nothing was published when in fact everything was, and the subscribers' backstop poll would
 * deliver it anyway — so the error would be wrong as well as alarming.
 */
import { describe, it, expect, vi } from "vitest";
import type { Logger } from "../types.js";
import { createChannelWakeSender } from "../channel-wake-sender.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const CHANNEL = "c1".repeat(32);
const MEMBER_A = "a1".repeat(32);
const MEMBER_B = "b2".repeat(32);
const ADMIN_AGENT = "admin-agent-1";

function sender(over: {
  members?: string[];
  signaling?: { sendRaw: (f: unknown) => Promise<{ ok: boolean; reason?: string }> } | null;
} = {}) {
  const sent: Record<string, unknown>[] = [];
  const signaling = over.signaling === undefined
    ? {
        sendRaw: (f: unknown) => { sent.push(f as Record<string, unknown>); return Promise.resolve({ ok: true }); },
      }
    : over.signaling;
  const send = createChannelWakeSender({
    logger: silent,
    activeMembers: () => over.members ?? [MEMBER_A, MEMBER_B],
    signalingFor: () => signaling,
  });
  return { send, sent };
}

describe("M16 021 — the publisher asks for its members to be woken", () => {
  it("10. one request, naming the channel and its active members", async () => {
    const { send, sent } = sender();
    await send(ADMIN_AGENT, CHANNEL);

    expect(sent).toHaveLength(1);
    expect(sent[0]["type"]).toBe("channel_wake_request");
    expect(Buffer.from(sent[0]["channel_pubkey"] as Uint8Array).toString("hex")).toBe(CHANNEL);
    const named = (sent[0]["agent_pubkeys"] as Uint8Array[]).map((b) => Buffer.from(b).toString("hex"));
    expect(named.sort()).toEqual([MEMBER_A, MEMBER_B].sort());
  });

  it("10b. a channel with no members sends NOTHING", async () => {
    // A request naming nobody is a round trip that can only be refused, and it would still cost the
    // channel a token from its bucket.
    const { send, sent } = sender({ members: [] });
    await send(ADMIN_AGENT, CHANNEL);
    expect(sent).toEqual([]);
  });

  it("10c. NO SIGNALING CONNECTION IS NOT AN ERROR — the post already happened", async () => {
    /**
     * ⚠️ The post is deposited and durable before this runs. A publisher whose directory stream is
     * down has published perfectly well; its subscribers simply hear on their backstop poll instead
     * of at once. Raising here would report a failure that did not occur.
     */
    const { send, sent } = sender({ signaling: null });
    await expect(send(ADMIN_AGENT, CHANNEL)).resolves.toBeUndefined();
    expect(sent).toEqual([]);
  });

  it("10d. a REFUSED wake does not throw either", async () => {
    // rate_limited, not_the_channel_admin, a directory fault — all of them leave a published post
    // that will be collected on the timer. None of them is the publisher's emergency.
    const { send } = sender({
      signaling: { sendRaw: () => Promise.resolve({ ok: false, reason: "signaling_lost" }) },
    });
    await expect(send(ADMIN_AGENT, CHANNEL)).resolves.toBeUndefined();
  });

  it("10e. a sendRaw that THROWS does not escape into the publish path", async () => {
    const { send } = sender({
      signaling: { sendRaw: () => Promise.reject(new Error("stream exploded")) },
    });
    await expect(send(ADMIN_AGENT, CHANNEL)).resolves.toBeUndefined();
  });

  it("10f. the wake is not awaited for its answer — it is a nudge, not a handshake", async () => {
    /**
     * ⚠️ The publisher must not block on a directory's reply to finish publishing. It sends and
     * moves on; the ack exists for the directory's own logs, not for this path.
     */
    const slow = vi.fn(() => new Promise<{ ok: boolean }>(() => { /* never settles */ }));
    const send = createChannelWakeSender({
      logger: silent,
      activeMembers: () => [MEMBER_A],
      signalingFor: () => ({ sendRaw: slow as unknown as (f: unknown) => Promise<{ ok: boolean }> }),
    });
    await expect(Promise.race([
      send(ADMIN_AGENT, CHANNEL),
      new Promise((r) => setTimeout(() => r("timed out"), 200)),
    ])).resolves.toBeUndefined();
    expect(slow).toHaveBeenCalled();
  });
});
