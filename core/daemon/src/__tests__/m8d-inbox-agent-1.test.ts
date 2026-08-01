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
import { resolveNamedAgent } from "../resolve-named-agent.js";

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

  it("I6 (review HIGH): an EMPTY name is refused — it must never read as 'no name given'", async () => {
    const conn = await fx.connectAs("alice");
    const res = (await conn.send("cello_check_notifications", { agent: "", scope: "current" })) as Record<string, unknown>;
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("missing_agent_value");
    expect(res.agents).toBeUndefined();
  });

  it("I7 (review HIGH): a NON-STRING name is refused, not silently dropped", async () => {
    // MCP callers are shielded by zod; direct-IPC callers are not, and §5a is explicit that
    // unreachability is a property of today's call graph rather than of the code.
    const conn = await fx.connectAs("alice");
    for (const bad of [123, ["bob"], { name: "bob" }, true]) {
      const res = (await conn.send("cello_check_notifications", { agent: bad as never, scope: "current" })) as Record<string, unknown>;
      expect(res.ok, `agent: ${JSON.stringify(bad)} must be refused`).toBe(false);
      expect(res.reason).toBe("invalid_agent_value");
      expect(res.agents).toBeUndefined();
    }
  });

  it("I8 (review MEDIUM): scope 'all' VALIDATES the name too — one parameter, one answer", async () => {
    // The guard used to sit inside the `current` branch, so the same parameter was refused when
    // empty and silently ignored when unknown, depending only on scope. Accept-and-ignore on one
    // branch of the fix is still accept-and-ignore.
    const conn = await fx.connectAs("alice");
    const res = (await conn.send("cello_check_notifications", { agent: "carol", scope: "all" })) as Record<string, unknown>;
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("agent_not_found");
  });

  it("I10 (observability): a refusal is logged, so a misrouted poll is findable after the fact", async () => {
    const conn = await fx.connectAs("alice");
    await conn.send("cello_check_notifications", { agent: "carol", scope: "current" });
    const rejected = fx.eventsNamed("inbox.agent.rejected");
    expect(rejected).toHaveLength(1);
    expect(rejected[0].ctx).toMatchObject({ reason: "agent_not_found", scope: "current" });
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

/**
 * The guard itself, unit-tested directly.
 *
 * SCOPE, stated so this is not mistaken for end-to-end coverage: driving a load_failed agent
 * through a real daemon means inserting a corrupt K_local seed into the encrypted store, since
 * agents load from the DB and fail when InMemoryKeyProvider rejects the seed — a fixture seam that
 * would exist only for this test. The helper is pure, so it is tested as one. The DAEMON's use of
 * it is covered by I3/I6/I7/I8 above.
 */
describe("resolveNamedAgent: the shared guard", () => {
  const known = [
    { name: "alice", state: "online" },
    { name: "broken", state: "load_failed", error: "bad seed length" },
  ];

  it("names nothing → the caller falls back to its own resolution", () => {
    expect(resolveNamedAgent(undefined, known)).toEqual({ ok: true, agent: null });
    expect(resolveNamedAgent(null, known)).toEqual({ ok: true, agent: null });
  });

  it("names a real agent → that agent", () => {
    expect(resolveNamedAgent("alice", known)).toEqual({ ok: true, agent: "alice" });
  });

  it("a LOAD-FAILED agent is reported as itself, never as missing", () => {
    // "does not exist — check cello_agents" would be an exit-point label standing in for the cause:
    // cello_agents FILTERS load_failed agents out, so the operator sees nothing there and confirms
    // the wrong diagnosis, never reaching cello_status, which shows the real error.
    const res = resolveNamedAgent("broken", known);
    expect(res.ok).toBe(false);
    expect((res as { reason: string }).reason).toBe("agent_load_failed");
    const guidance = (res as { guidance: string }).guidance;
    expect(guidance).toMatch(/cello_status/);
    expect(guidance).toMatch(/bad seed length/);      // the real cause travels with it
    expect(guidance).toMatch(/omits agents in this state/); // and why cello_agents will mislead
  });

  it("a caller-supplied name is capped before it is echoed back", () => {
    const res = resolveNamedAgent("z".repeat(500), known);
    expect((res as { reason: string }).reason).toBe("agent_not_found");
    // The name is echoed into guidance an LLM reads back; an unbounded caller string does not belong
    // in it, even from a same-privilege caller.
    expect((res as { guidance: string }).guidance.length).toBeLessThan(400);
  });
});
