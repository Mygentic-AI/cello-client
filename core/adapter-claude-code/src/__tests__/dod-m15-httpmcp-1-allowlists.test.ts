/**
 * 082-HTTPMCP — the two allowlists, in isolation (pure logic; no sockets).
 *
 * Tool allowlist: a file of tool names, `*` for all, `-name` to remove; no file means every
 * registered tool except DEFAULT_DENIED_TOOLS; a given file is authoritative.
 * Agent guard: any agent a caller names is resolved to an IDENTITY (pubkey) and refused before the
 * daemon is called unless permitted.
 */
import { describe, it, expect, vi } from "vitest";
import { registerCelloTools, type ToolSink } from "../cello-tools.js";
import {
  DEFAULT_DENIED_TOOLS,
  ToolsFileError,
  collectToolNames,
  resolveAllowedTools,
} from "../tool-allowlist.js";
import { guardProxy, makeNotificationPermit, resolvePermittedAgents } from "../agent-guard.js";

vi.stubEnv("CELLO_DOCUMENTS", "");
const ALL = collectToolNames();

describe("082 tool allowlist", () => {
  it("collects the registry from the ONE registration function", () => {
    expect(ALL).toContain("cello_send");
    expect(ALL).toContain("cello_use_agent");
    expect(ALL.length).toBe(new Set(ALL).size);
    expect(ALL.length).toBeGreaterThanOrEqual(60);
  });

  it("DEFAULT_DENIED_TOOLS names exactly four tools, all real", () => {
    expect([...DEFAULT_DENIED_TOOLS].sort()).toEqual([
      "cello_config_set",
      "cello_contact_set_tier",
      "cello_set_agent_offline",
      "cello_settings_set",
    ]);
    for (const t of DEFAULT_DENIED_TOOLS) expect(ALL, `${t} must be a registered tool`).toContain(t);
  });

  it("no file → every registered tool except the default-denied set", () => {
    const got = resolveAllowedTools(ALL, undefined);
    expect([...got].sort()).toEqual(ALL.filter((t) => !DEFAULT_DENIED_TOOLS.includes(t)).sort());
  });

  it("`*` alone → every registered tool, INCLUDING the default-denied ones", () => {
    expect([...resolveAllowedTools(ALL, "*\n")].sort()).toEqual([...ALL].sort());
  });

  it("`*` then `-cello_send` → everything but send", () => {
    const got = resolveAllowedTools(ALL, "# all but send\n*\n-cello_send\n");
    expect(got.has("cello_send")).toBe(false);
    expect(got.size).toBe(ALL.length - 1);
  });

  it("a plain list → exactly that list; blank lines and comments ignored", () => {
    const got = resolveAllowedTools(ALL, "\n# read only\ncello_agents\n  cello_inbox  \n");
    expect([...got].sort()).toEqual(["cello_agents", "cello_inbox"]);
  });

  it("a given file is authoritative: listing a default-denied tool allows it", () => {
    const got = resolveAllowedTools(ALL, "cello_config_set\ncello_agents\n");
    expect(got.has("cello_config_set")).toBe(true);
  });

  it("an unknown tool name fails startup and NAMES it", () => {
    let err: unknown;
    try {
      resolveAllowedTools(ALL, "cello_agents\ncello_no_such_tool\n");
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ToolsFileError);
    expect((err as ToolsFileError).reason).toBe("unknown_tool");
    expect((err as ToolsFileError).message).toContain("cello_no_such_tool");
  });

  it("`-name` of an unknown tool also fails", () => {
    expect(() => resolveAllowedTools(ALL, "*\n-cello_no_such_tool\n")).toThrow(/cello_no_such_tool/);
  });

  it("a file that leaves nothing allowed fails startup", () => {
    let err: unknown;
    try {
      resolveAllowedTools(ALL, "# nothing\n");
    } catch (e) {
      err = e;
    }
    expect((err as ToolsFileError).reason).toBe("empty_set");
  });
});

const A = "aa".repeat(32);
const B = "bb".repeat(32);
const C = "cc".repeat(32);

function roster(list: Array<{ name: string; pubkey: string }>) {
  return { agents: list.map((a) => ({ ...a, state: "online" })) };
}

function recorder(rosterFn: () => unknown) {
  const calls: Array<{ method: string; params: Record<string, unknown> | undefined }> = [];
  return {
    calls,
    inner: {
      async call(method: string, params?: Record<string, unknown>) {
        calls.push({ method, params });
        if (method === "cello_list_agents") return rosterFn();
        return { ok: true, method };
      },
    },
  };
}

describe("082 agent guard", () => {
  const R = () => roster([{ name: "alice", pubkey: A }, { name: "bob", pubkey: B }]);

  it("resolves names OR pubkeys to identities; unknown entries throw naming them and the existing list", async () => {
    const { inner } = recorder(R);
    const ok = await resolvePermittedAgents(inner, ["alice", B]);
    expect([...ok.permitted].sort()).toEqual([A, B].sort());
    await expect(resolvePermittedAgents(inner, ["alice", "zed"])).rejects.toMatchObject({
      reason: "agent_unknown",
      message: expect.stringMatching(/zed[\s\S]*alice[\s\S]*bob/),
    });
    await expect(resolvePermittedAgents(inner, [])).rejects.toMatchObject({ reason: "agents_empty" });
  });

  it("a name in cello_use_agent that is not permitted is refused and the daemon never sees the call", async () => {
    const { inner, calls } = recorder(R);
    const g = guardProxy(inner, new Set([A]));
    const out = (await g.call("cello_use_agent", { name: "bob" })) as Record<string, unknown>;
    expect(out["ok"]).toBe(false);
    expect(out["reason"]).toBe("agent_not_permitted");
    expect(String(out["guidance"])).toContain("alice");
    expect(calls.map((c) => c.method)).not.toContain("cello_use_agent");
  });

  it("a permitted agent passes through with its params unchanged", async () => {
    const { inner, calls } = recorder(R);
    const g = guardProxy(inner, new Set([A]));
    await g.call("cello_use_agent", { name: "alice" });
    const forwarded = calls.find((c) => c.method === "cello_use_agent");
    expect(forwarded?.params).toEqual({ name: "alice" });
  });

  it("the optional `agent` param on any other tool is checked the same way", async () => {
    const { inner, calls } = recorder(R);
    const g = guardProxy(inner, new Set([A]));
    const bad = (await g.call("cello_contact_list", { agent: "bob" })) as Record<string, unknown>;
    expect(bad["reason"]).toBe("agent_not_permitted");
    await g.call("cello_contact_list", { agent: "alice" });
    await g.call("cello_contact_list", {});
    expect(calls.filter((c) => c.method === "cello_contact_list").map((c) => c.params)).toEqual([
      { agent: "alice" },
      {},
    ]);
  });

  it("a NAME is compared by identity: a reused name that now means another agent is refused", async () => {
    let live = roster([{ name: "alice", pubkey: A }]);
    const { inner } = recorder(() => live);
    const g = guardProxy(inner, new Set([A]));
    live = roster([{ name: "carol", pubkey: A }, { name: "alice", pubkey: C }]);
    const out = (await g.call("cello_use_agent", { name: "alice" })) as Record<string, unknown>;
    expect(out["reason"]).toBe("agent_not_permitted");
    const viaNewName = (await g.call("cello_use_agent", { name: "carol" })) as Record<string, unknown>;
    expect(viaNewName["ok"]).toBe(true);
  });

  it("an agent the daemon does not know is refused, not forwarded", async () => {
    const { inner, calls } = recorder(R);
    const g = guardProxy(inner, new Set([A]));
    const out = (await g.call("cello_use_agent", { name: "nobody" })) as Record<string, unknown>;
    expect(out["reason"]).toBe("agent_not_permitted");
    expect(calls.map((c) => c.method)).not.toContain("cello_use_agent");
  });

  it("cello_list_agents is filtered to the permitted set", async () => {
    const { inner } = recorder(R);
    const g = guardProxy(inner, new Set([A]));
    const out = (await g.call("cello_list_agents")) as { agents: Array<{ name: string }> };
    expect(out.agents.map((a) => a.name)).toEqual(["alice"]);
  });

  it("`all` (no restriction) returns the inner proxy untouched", () => {
    const { inner } = recorder(R);
    expect(guardProxy(inner, "all")).toBe(inner);
  });

  it("a NAME-keyed agent tool is one of exactly the three the guard checks under `name`", () => {
    const shapes = new Map<string, string[]>();
    registerCelloTools({ tool: (n: string, _d: string, shape: Record<string, unknown>) => { shapes.set(n, Object.keys(shape)); } } as unknown as ToolSink, { call: async () => undefined });
    const withName = [...shapes].filter(([, keys]) => keys.includes("name")).map(([n]) => n).sort();
    // cello_channel_create's `name` is a channel name, not an agent; any NEW tool with `name` must be decided here.
    expect(withName).toEqual(["cello_channel_create", "cello_set_agent_offline", "cello_start_agent", "cello_use_agent"]);
    for (const [n, keys] of shapes) {
      const agentish = keys.filter((k) => /agent/i.test(k) && k !== "agent");
      expect(agentish, `${n} names an agent under a key the guard does not check`).toEqual([]);
    }
  });

  it("with no agent named, the connection's current agent is checked: an unpermitted current agent is refused", async () => {
    const { inner, calls } = recorder(R);
    const bad = guardProxy(inner, new Set([A]), () => {}, () => "bob");
    const out = (await bad.call("cello_send", { session_id: "s" })) as Record<string, unknown>;
    expect(out["reason"]).toBe("agent_not_permitted");
    expect(calls.map((c) => c.method)).not.toContain("cello_send");
    const good = guardProxy(inner, new Set([A]), () => {}, () => "alice");
    await good.call("cello_send", { session_id: "s" });
    expect(calls.map((c) => c.method)).toContain("cello_send");
  });

  it("an `agent` that is not a string is refused, not forwarded", async () => {
    const { inner, calls } = recorder(R);
    const g = guardProxy(inner, new Set([A]));
    for (const bad of [42, { name: "alice" }, ["alice"], null]) {
      const out = (await g.call("cello_contact_list", { agent: bad })) as Record<string, unknown>;
      expect(out["reason"], JSON.stringify(bad)).toBe("agent_not_permitted");
    }
    expect(calls.map((c) => c.method)).not.toContain("cello_contact_list");
  });

  it("a name two roster entries share is refused unless BOTH are permitted", async () => {
    const dup = () => roster([{ name: "alice", pubkey: A }, { name: "alice", pubkey: C }]);
    const { inner, calls } = recorder(dup);
    const out = (await guardProxy(inner, new Set([A])).call("cello_use_agent", { name: "alice" })) as Record<string, unknown>;
    expect(out["reason"]).toBe("agent_not_permitted");
    expect(calls.map((c) => c.method)).not.toContain("cello_use_agent");
  });

  it("a roster row missing its pubkey stops the call with a named reason; nothing is forwarded", async () => {
    const { inner, calls } = recorder(() => ({ agents: [{ name: "alice" }] }));
    const out = (await guardProxy(inner, new Set([A])).call("cello_use_agent", { name: "alice" })) as Record<string, unknown>;
    expect(out["reason"]).toBe("agent_roster_unreadable");
    expect(String(out["guidance"])).toContain("cello status");
    expect(calls.map((c) => c.method)).not.toContain("cello_use_agent");
  });

  it("a daemon that is down answers with its own recovery, not a permission refusal", async () => {
    const down = { ok: false, reason: "daemon_not_running", guidance: "start it" };
    const { inner } = recorder(() => down);
    const out = (await guardProxy(inner, new Set([A])).call("cello_use_agent", { name: "alice" })) as Record<string, unknown>;
    expect(out["reason"]).toBe("daemon_not_running");
  });

  it("notifications: judged on a FRESH roster; not-permitted, no-agent and unreadable-roster frames are dropped with their cause", async () => {
    let live = R();
    const logged: Array<Record<string, unknown>> = [];
    const { inner } = recorder(() => live);
    const permit = makeNotificationPermit(inner, new Set([A]), (_e, ctx) => logged.push(ctx ?? {}));
    expect(await permit({ data: { agent: "alice" } })).toBe(true);
    expect(await permit({ data: { agent: "bob" } })).toBe(false);
    expect(await permit({ data: { agent: "ghost" } })).toBe(false);
    expect(await permit({ data: {} })).toBe(false);
    live = roster([{ name: "carol", pubkey: A }]);
    expect(await permit({ data: { agent: "carol" } }), "a permitted agent renamed after the session began").toBe(true);
    expect(await permit({ data: { agent: "alice" } }), "the old name no longer means the permitted agent").toBe(false);
    live = { agents: "nope" } as never;
    expect(await permit({ data: { agent: "carol" } })).toBe(false);
    expect(logged.map((l) => l["cause"])).toEqual(["not_permitted", "not_permitted", "no_agent_in_frame", "not_permitted", "roster_unreadable"]);
  });
});
