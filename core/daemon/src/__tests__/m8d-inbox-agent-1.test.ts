/**
 * DOD-INBOX-AGENT-1 (debt — from M8C) — `cello_check_notifications` ignores an explicit agent.
 *
 * Found while closing DOD-RECEPTIONIST-AGENT-1. That line stopped the receptionist SUBAGENT from
 * re-pointing other terminals through the machine-wide `~/.cello/current-agent` file, by passing
 * `--agent` on the CLI. The receptionist SKILL has the identical defect one layer up and could not
 * be fixed the same way, because the door does not exist on the MCP surface:
 *
 *   `cello_check_notifications` calls `resolveCurrentAgent(connState)` — with NO explicit-agent
 *   argument — while every sibling handler calls `resolveCurrentAgent(connState, params?.agent)`.
 *
 * `resolveCurrentAgent` already supports the argument (`daemon.ts:1764`, `explicitAgent` wins). This
 * one caller just never passes it. So `{ agent: "bob" }` is accepted, ignored, and answered for
 * whichever agent the CONNECTION happens to hold — a silent misroute that exits ok:true. The skill's
 * own step 1 tells its operator to "pass it explicitly as the `agent` parameter on every call rather
 * than relying on the connection's current selection, which another session or an MCP reconnect can
 * change underneath you" — advice the tool could not honour.
 *
 * Why it bites specifically: two skills in ONE Claude Code session share ONE MCP socket, so the
 * second `cello_use_agent` re-points the first. That is the same collision as the receptionist's,
 * with a socket standing in for the shared file.
 *
 * Labelled DEBT, not M8D (procedure §5d): the defect predates this milestone. It is fixed here
 * because M8D surfaced it and because leaving it means the fix that just shipped one layer down
 * cannot be applied one layer up.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";

describe("DOD-INBOX-AGENT-1: cello_check_notifications honours an explicit agent", () => {
  let fx: TwoConnectionFixture;

  beforeEach(async () => {
    fx = await startTwoConnectionFixture({ agents: ["alice", "bob"], dirPrefix: "cello-m8d-inbox-" });
  });

  afterEach(async () => {
    await fx.cleanup();
  });

  it("I1: an explicit { agent } wins over the connection's own selection", async () => {
    const conn = await fx.connectAs("alice");

    // The caller names bob. Today the parameter is accepted and silently dropped, and alice's
    // inbox comes back under ok:true — the caller has no way to tell it was answered for the
    // wrong desk.
    const res = (await conn.send("cello_check_notifications", { agent: "bob", scope: "current" })) as Record<string, unknown>;
    expect(res.ok).toBe(true);
    expect((res.agents as Array<{ agent: string }>).map((a) => a.agent)).toEqual(["bob"]);
  });

  it("I2 (the collision this exists for): two connections on ONE daemon each get their OWN desk", async () => {
    // The MCP case: two skills in one Claude Code session share one socket, so a sibling's
    // cello_use_agent re-points this one. An explicit agent must survive that.
    const connA = await fx.connectAs("alice");
    const connB = await fx.connectAs("bob");

    // B re-points ITS connection; A's selection is untouched, but the explicit param is what must
    // make A's answer independent of any of it.
    await connB.send("cello_use_agent", { name: "alice" });

    const a = (await connA.send("cello_check_notifications", { agent: "alice", scope: "current" })) as Record<string, unknown>;
    const b = (await connB.send("cello_check_notifications", { agent: "bob", scope: "current" })) as Record<string, unknown>;

    expect((a.agents as Array<{ agent: string }>).map((x) => x.agent)).toEqual(["alice"]);
    expect((b.agents as Array<{ agent: string }>).map((x) => x.agent)).toEqual(["bob"]);
  });

  it("I3 (no silent fallback): an UNKNOWN agent is refused, never answered as somebody else", async () => {
    const conn = await fx.connectAs("alice");

    const res = (await conn.send("cello_check_notifications", { agent: "carol", scope: "current" })) as Record<string, unknown>;
    // The hazard is not the error — it is quietly returning alice's inbox labelled carol, or
    // falling back to the connection's selection because the named agent could not be found.
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("agent_not_found");
    expect(String(res.guidance)).toMatch(/carol/);
    expect(res.agents).toBeUndefined();
  });

  it("I4 (unchanged): with no explicit agent, the connection's selection still answers", async () => {
    // The regression guard. Every existing caller passes no agent and must behave exactly as before.
    const conn = await fx.connectAs("alice");

    const res = (await conn.send("cello_check_notifications", { scope: "current" })) as Record<string, unknown>;
    expect(res.ok).toBe(true);
    expect((res.agents as Array<{ agent: string }>).map((a) => a.agent)).toEqual(["alice"]);
  });

  it("I5 (unchanged): scope 'all' ignores the explicit agent, as it must — it means every agent", async () => {
    const conn = await fx.connectAs("alice");

    const res = (await conn.send("cello_check_notifications", { agent: "bob", scope: "all" })) as Record<string, unknown>;
    expect(res.ok).toBe(true);
    const names = (res.agents as Array<{ agent: string }>).map((a) => a.agent).sort();
    expect(names).toEqual(["alice", "bob"]);
  });
});
