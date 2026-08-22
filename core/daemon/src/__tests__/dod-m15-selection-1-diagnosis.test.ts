/**
 * DOD-M15-SELECTION-1 — THE DIAGNOSIS, which the line asks for before any behaviour changes.
 *
 * > *"Diagnosis first: reproduce with a daemon restart after a release, with the trigger field from
 * > `DOD-M15-IPCVISIBLE-1` distinguishing replay from fallback in one run."*
 *
 * I skipped that once already and had to revert: I read *"silently binding a live MCP session to an
 * identity it never asked for is not defensible"*, switched the sole-online fallback off for MCP,
 * and four tests stopped me — CC-3 added it deliberately to fix the post-reconnect papercut.
 *
 * ─── The apparent contradiction this file exists to settle ─────────────────────────────────────
 *
 * Two shipped rules look like they disagree:
 *
 *   `DOD-RELEASE-1`  — a voluntary release must NOT set `clearedAgent`: *"the operator chose to hold
 *                      nothing, and must still be eligible for the sole-online fallback rather than
 *                      locked out of it for the session."*
 *   `DOD-M15-SELECTION-1` — *"A release survives a reconnect. After `cello_stop_using_agent`, a
 *                      reconnect attends NOTHING until something asks again."*
 *
 * One says stay eligible; the other says attend nothing. They only conflict if RESOLVING A SUBJECT
 * and ATTENDING are the same act. They are not, and that distinction is the whole answer:
 *
 *   **Resolving a subject** answers "which agent is this CALL about" — per-call, no lasting effect.
 *   **Attending** registers the connection with the notification dispatcher, and is what decides
 *   whether doorbells arrive and whether an inbound session gets a live reply or an away message.
 *
 * The sole-online fallback does the first and never the second. So both rules can hold at once —
 * and whether they actually DO is a measurement, not an argument. That is what this file measures.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startDaemon, connectToDaemon, type DaemonHandle, type DaemonConfig } from "../index.js";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import type { Logger } from "../types.js";

describe("DOD-M15-SELECTION-1 diagnosis: what a release actually leaves behind", () => {
  let dir: string;
  let handle: DaemonHandle | null = null;
  let logEvents: Array<{ event: string; context: Record<string, unknown> }>;

  const logger = (): Logger => ({
    debug: (event, context) => logEvents.push({ event, context: context ?? {} }),
    info: (event, context) => logEvents.push({ event, context: context ?? {} }),
    warn: (event, context) => logEvents.push({ event, context: context ?? {} }),
    error: (event, context) => logEvents.push({ event, context: context ?? {} }),
  });

  function makeConfig(): DaemonConfig {
    return {
      securityGateway: new PassthroughGatewayClient(),
      celloDir: dir,
      socketPath: join(dir, "daemon.sock"),
      lockFilePath: join(dir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger: logger(),
    } as DaemonConfig;
  }

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "m15-selection-diag-"));
    logEvents = [];
  });
  afterEach(async () => {
    if (handle) await handle.stop("graceful").catch(() => {});
    handle = null;
    await rm(dir, { recursive: true, force: true });
  });

  it("★ after a release and a RECONNECT, the new connection attends NOTHING", async () => {
    /**
     * Clause 1, measured rather than argued.
     *
     * `clearedAgent` is per-connection and dies with the connection, so a reconnect carries none —
     * which is why this looked like it must be broken. But `attended_by` counts connections whose
     * REGISTERED current agent is this one, and the fallback never registers: it answers "which
     * agent is this call about" and stops there.
     *
     * If this passes, the clause already holds and the remaining work is clause 2 only. If it
     * fails, the release is being undone by the fallback and that is the defect to fix.
     */
    handle = await startDaemon(makeConfig());
    const sock = join(dir, "daemon.sock");

    const first = await connectToDaemon(sock);
    await first.send("ipc.connect", { clientType: "mcp" });
    await first.send("cello_create_agent", { name: "solo" });
    await first.send("cello_start_agent", { name: "solo" });
    await first.send("cello_use_agent", { name: "solo" });
    await first.send("cello_stop_using_agent", {});
    first.close();
    await new Promise((r) => setTimeout(r, 120));

    // THE RECONNECT — a brand-new connection, exactly what `/mcp` reconnect produces.
    const second = await connectToDaemon(sock);
    await second.send("ipc.connect", { clientType: "mcp" });

    /**
     * THE FALLBACK MUST ACTUALLY RUN FIRST, or this test measures nothing. Review F1: the original
     * asked only `cello_list_agents`, which returns `getAgentsForConnection` and never resolves an
     * agent at all. So `attended_by` was 0 for a reason with no connection to the property — and
     * the mutation this test exists to catch (`connState.currentAgent = agent` inside the fallback
     * branch) left it green.
     *
     * `cello_list_sessions` is the cheapest call that DOES resolve, proven by the next test. Making
     * it the first call is what turns this from a restatement into a measurement.
     */
    const fellBack = (await second.send("cello_list_sessions", {})) as Record<string, unknown>;
    expect(
      fellBack["agent_selection"],
      "PRECONDITION: the fallback must have run on this connection, or the attendance assertion " +
        "below is vacuous — it would read 0 on a connection that never resolved anything.",
    ).toBe("fallback");

    const listed = (await second.send("cello_list_agents", {})) as {
      agents?: Array<Record<string, unknown>>;
    };
    second.close();

    const solo = (listed.agents ?? []).find((a) => a["name"] === "solo");
    expect(solo, "the agent must still exist — releasing attends nothing, it does not remove").toBeDefined();
    expect(
      solo?.["attended_by"],
      "After a release and a reconnect the agent is being ATTENDED by a connection that never " +
        "asked for it — so doorbells route to a session the operator deliberately let go of, and " +
        "an inbound session gets a live reply from a session that is not watching.",
    ).toBe(0);
    expect(
      solo?.["selected_by_this_connection"],
      "and the reconnected connection must not report it as its own selection",
    ).toBe(false);
  }, 30_000);

  it("a fallback RESOLVES a subject on that same reconnected connection — and says it did", async () => {
    /**
     * The other half, and why clause 1 passing is not the whole answer. The reconnected connection
     * attends nothing, but a name-defaulting tool still WORKS on it — that is CC-3's papercut fix
     * and it is deliberate.
     *
     * The result is a HALF-ATTENDED state: tools resolve, doorbells do not arrive. An operator
     * reads that as the protocol dropping messages rather than as a selection nobody made, which is
     * exactly what clause 2 asks to be made explicit.
     */
    handle = await startDaemon(makeConfig());
    const sock = join(dir, "daemon.sock");

    const c = await connectToDaemon(sock);
    await c.send("ipc.connect", { clientType: "mcp" });
    await c.send("cello_create_agent", { name: "solo" });
    await c.send("cello_start_agent", { name: "solo" });

    const before = logEvents.length;
    await c.send("cello_list_sessions", {});
    c.close();

    const fallback = logEvents.slice(before).find((e) => e.event === "agent.current.fallback");
    expect(
      fallback,
      "the fallback resolved a subject for a connection that selected nothing, and said nothing",
    ).toBeDefined();
    expect(fallback?.context["agentName"]).toBe("solo");
  }, 30_000);

  it("★ CLAUSE 2: a fallback is EXPLICIT IN THE RESPONSE, not announced as an accomplished fact", async () => {
    /**
     * *"If a fallback is wanted it is EXPLICIT in the response, not announced as an accomplished
     * fact."*
     *
     * The diagnosis above settled what the harm actually is. It is not that the fallback picks a
     * wrong agent — with one online it picks the only one there is. It is the HALF-ATTENDED state:
     * the call resolves and works, and doorbells never arrive, because attendance was never
     * registered. An operator reads that as the protocol dropping messages rather than as a
     * selection nobody made.
     *
     * So the response says which agent it acted as and that this was a fallback, with the verb that
     * fixes it. Added at the IPC boundary — the ONE place every response passes through — so a
     * handler added tomorrow cannot forget it.
     */
    handle = await startDaemon(makeConfig());
    const sock = join(dir, "daemon.sock");

    const c = await connectToDaemon(sock);
    await c.send("ipc.connect", { clientType: "mcp" });
    await c.send("cello_create_agent", { name: "solo" });
    await c.send("cello_start_agent", { name: "solo" });

    const res = (await c.send("cello_list_sessions", {})) as Record<string, unknown>;
    c.close();

    expect(
      res["acting_as"],
      "the response must name the agent it acted as — the caller never selected one",
    ).toBe("solo");
    expect(res["agent_selection"]).toBe("fallback");

    /**
     * THE CLAIM, not a token in it — hollow-test Q4, and review F10. `toMatch(/cello_use_agent/)`
     * alone stayed green when the entire body was replaced with the bare string "Run
     * cello_use_agent." — dropping the half-attended explanation that is the whole point of the
     * notice. The verb is the cheapest part to assert and the least of what has to be there.
     */
    const guidance = String(res["agent_selection_guidance"]);
    expect(guidance, "it must name the agent it silently acted as").toContain("solo");
    expect(guidance, "it must say this is not an attendance").toMatch(/NOT an attendance/);
    expect(guidance, "it must name the missed-doorbell consequence").toMatch(/will not WAKE/);
    expect(
      guidance,
      "and the AWAY consequence — the counterparty is told you are away while you sit here able " +
        "to answer, which is the half the operator's correspondent actually sees",
    ).toMatch(/AWAY/);
    expect(guidance, "plus the verb that fixes it").toContain("cello_use_agent");
    expect(
      guidance,
      "and it must NOT offer naming-the-agent as a remedy: that settles which agent a call is " +
        "about and leaves the connection exactly as unattended, so an agent taking that option " +
        "believes it has acted on the warning and is still deaf (review F6)",
    ).toMatch(/NOT a remedy/);
  }, 30_000);

  it("a connection that SELECTED an agent gets no fallback notice", async () => {
    /**
     * The counterexample. A notice on every response would fire on the ordinary case — the defect
     * this milestone keeps naming: a signal that fires on the normal case is not a signal, and it
     * trains the reader to ignore the one that is real.
     */
    handle = await startDaemon(makeConfig());
    const sock = join(dir, "daemon.sock");

    const c = await connectToDaemon(sock);
    await c.send("ipc.connect", { clientType: "mcp" });
    await c.send("cello_create_agent", { name: "solo" });
    await c.send("cello_start_agent", { name: "solo" });
    await c.send("cello_use_agent", { name: "solo" });

    const res = (await c.send("cello_list_sessions", {})) as Record<string, unknown>;
    c.close();

    expect(res["agent_selection"], "an explicit selection is not a fallback").toBeUndefined();
    expect(res["acting_as"]).toBeUndefined();
  }, 30_000);

  it("★ the notice does NOT stick: the call AFTER a fallback carries nothing", async () => {
    /**
     * Review F5 — the mutation the whole suite was blind to. Deleting the read-and-clear left every
     * test green, because each one made at most ONE call after a fallback. A sticky notice is the
     * milestone's own recurring defect wearing a new hat: a signal that fires on the ordinary case
     * is not a signal, and it trains the reader to ignore the real one.
     *
     * The shape that breaks is a SECOND call on the SAME connection.
     */
    handle = await startDaemon(makeConfig());
    const sock = join(dir, "daemon.sock");

    const c = await connectToDaemon(sock);
    await c.send("ipc.connect", { clientType: "mcp" });
    await c.send("cello_create_agent", { name: "solo" });
    await c.send("cello_start_agent", { name: "solo" });

    const first = (await c.send("cello_list_sessions", {})) as Record<string, unknown>;
    expect(first["agent_selection"], "PRECONDITION: the first call must fall back").toBe("fallback");

    // Same connection, an agent named outright — this call did not fall back and must not say it did.
    const second = (await c.send("cello_list_sessions", { agent: "solo" })) as Record<string, unknown>;
    c.close();

    expect(
      second["agent_selection"],
      "The notice from the PREVIOUS call rode this response. A call that named its agent is being " +
        "told it did not, which makes the notice noise on the ordinary path.",
    ).toBeUndefined();
    expect(second["acting_as"]).toBeUndefined();
  }, 30_000);

  it("★ a fallback on a SLOW call does not tag a fast concurrent call that named its agent", async () => {
    /**
     * Review F3, and the reason the notice is stored per-REQUEST rather than per-connection.
     *
     * Claude Code issues tool calls in parallel, and the IPC layer keys pending calls by id with no
     * serialization. With the notice held on the connection, whichever response finished FIRST took
     * it — so the call that fell back could be silent while a call that named its agent explicitly
     * was told it had not.
     *
     * Two calls in flight at once is the shape that breaks. Both are sent before either is awaited.
     */
    handle = await startDaemon(makeConfig());
    const sock = join(dir, "daemon.sock");

    const c = await connectToDaemon(sock);
    await c.send("ipc.connect", { clientType: "mcp" });
    await c.send("cello_create_agent", { name: "solo" });
    await c.send("cello_start_agent", { name: "solo" });

    const fellBack = c.send("cello_list_sessions", {}) as Promise<Record<string, unknown>>;
    const named = c.send("cello_list_sessions", { agent: "solo" }) as Promise<Record<string, unknown>>;
    const [a, b] = await Promise.all([fellBack, named]);
    c.close();

    expect(a["agent_selection"], "the call that fell back is the one that must carry the notice").toBe("fallback");
    expect(
      b["agent_selection"],
      "the notice rode the wrong response: a call that named 'solo' explicitly was told no agent " +
        "was selected, while the call that actually fell back may have said nothing.",
    ).toBeUndefined();
  }, 30_000);

  it("★ a handler that THROWS after falling back does not leak its notice onto the next call", async () => {
    /**
     * Review F4. The error path built its response without consuming the notice, so a handler that
     * resolved the fallback and then threw left it behind — where it attached itself to the
     * connection's next SUCCESSFUL response, including `cello_use_agent`, the one call that is an
     * explicit selection by definition.
     *
     * A per-request store cannot do this: the store dies with the request whether it returned or
     * threw. But "cannot" is a claim, and this milestone keeps catching comments that assert a
     * property the code does not hold — so it is measured.
     *
     * Finding a genuinely THROWING handler took a probe: none of them throw deliberately, they all
     * return `{ok:false}` error objects. `cello_close_session` with a non-string `session_id` is the
     * one reachable path — it resolves the agent into SQL bind param 1 (the fallback fires there),
     * then dies binding param 2. Resolve-then-throw, which is exactly the ordering F4 needs.
     */
    handle = await startDaemon(makeConfig());
    const sock = join(dir, "daemon.sock");

    const c = await connectToDaemon(sock);
    await c.send("ipc.connect", { clientType: "mcp" });
    await c.send("cello_create_agent", { name: "solo" });
    await c.send("cello_start_agent", { name: "solo" });

    const before = logEvents.length;
    let threw = false;
    await c
      .send("cello_close_session", { session_id: { evil: true } as unknown as string })
      .catch(() => {
        threw = true;
      });

    expect(threw, "PRECONDITION: this call must actually reject, or there is no leak to leak").toBe(true);
    expect(
      logEvents.slice(before).some((e) => e.event === "agent.current.fallback"),
      "PRECONDITION: and it must have FALLEN BACK before throwing, or the notice never existed",
    ).toBe(true);

    const after = (await c.send("cello_use_agent", { name: "solo" })) as Record<string, unknown>;
    c.close();

    expect(
      after["agent_selection"],
      "a notice left behind by a failed call rode the response to cello_use_agent — the one call " +
        "that is an explicit selection by definition.",
    ).toBeUndefined();
    expect(after["acting_as"]).toBeUndefined();
  }, 30_000);

  it("★ a CLI caller is told a command it can actually TYPE", async () => {
    /**
     * Review F2, and the finding that made this unit's guidance actively wrong rather than merely
     * thin. The notice was spread in at the IPC write, which is DOWNSTREAM of `renderForSurface` —
     * so `isInstructionKey` (any key ending in `guidance`) never saw it, and an operator running
     * `cello inbox` was told to *"Run cello_use_agent"*. That is not a command. `cello use-agent`
     * is. The vocabulary layer exists for precisely this and was bypassed by ordering.
     *
     * The audit that guards shipped prose cannot catch it either: `cello_use_agent` IS a real tool
     * name, so an allowlist check passes while the operator is stranded.
     */
    handle = await startDaemon(makeConfig());
    const sock = join(dir, "daemon.sock");

    const c = await connectToDaemon(sock);
    await c.send("ipc.connect", { clientType: "cli" });
    await c.send("cello_create_agent", { name: "solo" });
    await c.send("cello_start_agent", { name: "solo" });

    const res = (await c.send("cello_list_sessions", {})) as Record<string, unknown>;
    c.close();

    const guidance = String(res["agent_selection_guidance"]);
    expect(res["agent_selection"], "PRECONDITION: this call must have fallen back").toBe("fallback");
    expect(guidance, "a terminal user cannot run an MCP tool name").toContain("cello use-agent");
    expect(guidance, "and must not be handed the untypeable form").not.toContain("cello_use_agent");
  }, 30_000);

  it("a connection that never sent ipc.connect still gets the notice", async () => {
    /**
     * Review F8. The notice was written only `if (agent && connState)`, and `perConnectionState` is
     * populated at `ipc.connect` — which the CLI's own `withIpc` does not send. So every plain
     * `cello` invocation fell back and was told nothing, while the log line fired regardless: the
     * clause asks for explicit IN THE RESPONSE, and those callers had it in the log only.
     */
    handle = await startDaemon(makeConfig());
    const sock = join(dir, "daemon.sock");

    const setup = await connectToDaemon(sock);
    await setup.send("ipc.connect", { clientType: "mcp" });
    await setup.send("cello_create_agent", { name: "solo" });
    await setup.send("cello_start_agent", { name: "solo" });
    setup.close();

    // No `ipc.connect` — exactly what `withIpc` in core/cli does.
    const bare = await connectToDaemon(sock);
    const res = (await bare.send("cello_list_sessions", {})) as Record<string, unknown>;
    bare.close();

    expect(
      res["agent_selection"],
      "this caller fell back and the response said nothing about it — explicit in the log only",
    ).toBe("fallback");
    expect(res["acting_as"]).toBe("solo");
  }, 30_000);
});