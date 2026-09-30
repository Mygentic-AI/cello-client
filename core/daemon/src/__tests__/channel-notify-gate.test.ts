/**
 * The two pieces that make push/pull real: the gate that suppresses a channel's doorbell, and the
 * handler that sets the mode. The store is tested in channel-notify-setting.test.ts.
 */
import { describe, it, expect } from "vitest";
import type { ChannelNotify } from "../channel-membership-wiring.js";
import { gateChannelNotify, registerChannelNotifyHandler } from "../channel-notify-setting.js";

const A = "aa".repeat(32);
const B = "cc".repeat(32);

function recorder() {
  const calls: string[] = [];
  const base: ChannelNotify = {
    channelPosts: (id, ch, count) => { calls.push(`posts ${id} ${ch.slice(0, 2)} ${String(count)}`); },
    channelJoinAnswer: (id, ch) => { calls.push(`answer ${id} ${ch.slice(0, 2)}`); },
    channelJoinRequest: (id, ch) => { calls.push(`request ${id} ${ch.slice(0, 2)}`); },
    channelMembershipEnded: (id, ch) => { calls.push(`ended ${id} ${ch.slice(0, 2)}`); },
    channelPosterRemoved: (id, ch) => { calls.push(`poster ${id} ${ch.slice(0, 2)}`); },
  };
  return { calls, base };
}

describe("gateChannelNotify", () => {
  it("rings for a push channel", () => {
    const { calls, base } = recorder();
    const gated = gateChannelNotify(base, { notifyFor: () => "push" });
    gated.channelPosts("agent-1", A, 3, 9);
    expect(calls).toEqual(["posts agent-1 aa 3"]);
  });

  it("stays silent for a pull channel, for that channel only", () => {
    const { calls, base } = recorder();
    const gated = gateChannelNotify(base, { notifyFor: (_id, ch) => (ch === A ? "pull" : "push") });
    gated.channelPosts("agent-1", A, 3, 9);
    gated.channelPosts("agent-1", B, 1, 4);
    expect(calls).toEqual(["posts agent-1 cc 1"]);
  });

  it("only posts are silenced: a join answer, an ejection and the rest still ring on a pull channel", () => {
    const { calls, base } = recorder();
    const gated = gateChannelNotify(base, { notifyFor: () => "pull" });
    gated.channelJoinAnswer("agent-1", A, "admitted");
    gated.channelJoinRequest("agent-1", A, "dd".repeat(32), "note");
    gated.channelMembershipEnded("agent-1", A, "ejected");
    gated.channelPosterRemoved("agent-1", A);
    expect(calls).toEqual(["answer agent-1 aa", "request agent-1 aa", "ended agent-1 aa", "poster agent-1 aa"]);
  });

  it("a lookup that throws rings anyway: a broken setting must never eat a notification", () => {
    const { calls, base } = recorder();
    const gated = gateChannelNotify(base, { notifyFor: () => { throw new Error("db closed"); } });
    gated.channelPosts("agent-1", A, 2, 5);
    expect(calls).toEqual(["posts agent-1 aa 2"]);
  });
});

describe("cello_channel_set_notify", () => {
  function setup(opts: { following?: boolean; agent?: string | null } = {}) {
    const handlers = new Map<string, (p: Record<string, unknown> | undefined, c: string) => Promise<unknown>>();
    const set: Array<[string, string, string]> = [];
    registerChannelNotifyHandler(handlers, {
      resolveCurrentAgent: (_c, explicit) => (opts.agent === null ? null : (explicit ?? opts.agent ?? "alice")),
      resolveAgentId: (name) => `id-${name}`,
      subscriptions: {
        get: (_id, ch) => (opts.following === false ? null : ({ channel_pubkey: ch } as never)),
        setNotify: (id, ch, mode) => { set.push([id, ch, mode]); },
      },
    });
    return { call: handlers.get("cello_channel_set_notify")!, set };
  }

  it("sets pull for the named agent and channel", async () => {
    const { call, set } = setup();
    const out = await call({ channel: A.toUpperCase(), mode: "pull", agent: "bob" }, "conn-1");
    expect(out).toMatchObject({ ok: true, channel: A, notify: "pull" });
    expect(set).toEqual([["id-bob", A, "pull"]]);
  });

  it("accepts push, so a pull can be undone", async () => {
    const { call, set } = setup();
    expect(await call({ channel: A, mode: "push" }, "conn-1")).toMatchObject({ ok: true, notify: "push" });
    expect(set).toEqual([["id-alice", A, "push"]]);
  });

  it("refuses a mode that is neither, and changes nothing", async () => {
    const { call, set } = setup();
    expect(await call({ channel: A, mode: "mute" }, "conn-1")).toMatchObject({ ok: false, reason: "bad_mode" });
    expect(await call({ channel: A }, "conn-1")).toMatchObject({ ok: false, reason: "bad_mode" });
    expect(set).toEqual([]);
  });

  it("refuses a channel key that is not 64 hex characters", async () => {
    const { call } = setup();
    expect(await call({ channel: "abc", mode: "pull" }, "conn-1")).toMatchObject({ ok: false, reason: "bad_channel" });
  });

  it("refuses a channel this agent does not follow, instead of silently recording nothing", async () => {
    const { call, set } = setup({ following: false });
    expect(await call({ channel: A, mode: "pull" }, "conn-1")).toMatchObject({ ok: false, reason: "not_following" });
    expect(set).toEqual([]);
  });

  it("refuses when no agent is named or selected", async () => {
    const { call } = setup({ agent: null });
    expect(await call({ channel: A, mode: "pull" }, "conn-1")).toMatchObject({ ok: false, reason: "no_current_agent" });
  });
});
