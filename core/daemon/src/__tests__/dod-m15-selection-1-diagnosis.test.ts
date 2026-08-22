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
    expect(
      String(res["agent_selection_guidance"]),
      "and it must name the half-attended consequence plus the verb that fixes it",
    ).toMatch(/cello_use_agent/);
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
});