/**
 * DOD-RELEASE-1 — cello_stop_using_agent: release an agent WITHOUT taking it offline.
 *
 * WHY THIS EXISTS
 *
 * `cello_use_agent` requires a name, so a connection could SWITCH agents but never LET GO of one.
 * The only thing that cleared a selection was `cello_set_agent_offline` (then named
 * `cello_stop_agent`) — which operates on a completely different axis:
 *
 *   lifecycle  — cello_start_agent / cello_set_agent_offline    (offline ⇄ online)
 *   attendance — cello_use_agent   / cello_stop_using_agent     (who this connection drives)
 *
 * The old name read as the opposite of `use_agent` while being the opposite of `start_agent`. An
 * operator wanting to step away so their agent's AWAY message could fire ran it and took the agent
 * fully offline instead — at which point inbound sessions were refused outright and no away message
 * could be produced. Both states look identical from outside ("nobody is answering") and behave
 * nothing alike.
 *
 * The distinction these tests defend: RELEASING LEAVES THE AGENT ONLINE. That is the entire point —
 * it is how an operator becomes reachable-but-absent rather than simply gone. A release that
 * silently took the agent offline would be the original bug wearing the new name.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import { FileKeyProvider } from "@cello-protocol/crypto";
import type { Logger, DaemonConfig } from "../types.js";

interface AgentList { agents: Array<{ name: string; state: string; selected?: boolean; standing_receiver_ready?: boolean }> }

describe("DOD-RELEASE-1: cello_stop_using_agent", () => {
  let tempDir: string;
  let logEvents: Array<{ level: string; event: string; context: Record<string, unknown> }>;
  let logger: Logger;
  let handle: DaemonHandle | null;
  let clients: IpcClient[];

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-release-test-"));
    logEvents = [];
    logger = {
      debug(event, context) { logEvents.push({ level: "debug", event, context }); },
      info(event, context) { logEvents.push({ level: "info", event, context }); },
      warn(event, context) { logEvents.push({ level: "warn", event, context }); },
      error(event, context) { logEvents.push({ level: "error", event, context }); },
    };
    handle = null;
    clients = [];
  });

  afterEach(async () => {
    for (const c of clients) { try { c.close(); } catch { /* already closed */ } }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* already stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
  });

  async function setupWithAgents(...agentNames: string[]): Promise<DaemonConfig> {
    const agentsDir = join(tempDir, "agents");
    for (const name of agentNames) {
      await mkdir(join(agentsDir, name), { recursive: true });
      await FileKeyProvider.load(join(agentsDir, name, "key"));
    }
    return {
      securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
    };
  }

  async function connect(socketPath: string): Promise<IpcClient> {
    const client = await connectToDaemon(socketPath);
    clients.push(client);
    await client.send("ipc.connect", { clientType: "mcp" });
    return client;
  }

  it("releases the current agent and reports which one", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    await client.send("cello_start_agent", { name: "alice" });
    await client.send("cello_use_agent", { name: "alice" });

    const result = await client.send("cello_stop_using_agent", {}) as { ok: boolean; released: string | null };
    expect(result.ok).toBe(true);
    expect(result.released).toBe("alice");

    const list = await client.send("cello_list_agents") as AgentList;
    expect(list.agents.find((a) => a.name === "alice")?.selected).toBe(false);
  });

  // THE LOAD-BEARING ONE. A release that took the agent offline would reproduce the exact bug this
  // tool was built to fix, and every other assertion in this file would still pass.
  //
  // `state: "online"` ALONE IS NOT ENOUGH, and the first version of this test made that mistake.
  // `state` is derived purely from the `onlineAgents` Set, and `agent.offline` is logged only inside
  // the set-offline handler — so this implementation passed both:
  //
  //     connState.currentAgent = null;
  //     await sessionNodeManager.removeStandingReceiverForAgent(fromAgent);  // ← agent is now deaf
  //
  // onlineAgents still holds alice, so `state` reads "online"; no `agent.offline` fires. The agent
  // is unreachable and every assertion is green — and it is WORSE than being offline, because
  // cello_use_agent sees `onlineAgents.has(name)`, skips the autostart, and never re-arms the
  // receiver. So assert REACHABILITY, which is the property the operator actually has.
  it("LEAVES THE AGENT ONLINE AND REACHABLE — the whole difference from set_agent_offline", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    await client.send("cello_start_agent", { name: "alice" });
    await client.send("cello_use_agent", { name: "alice" });

    const before = await client.send("cello_list_agents") as AgentList;
    expect(before.agents.find((a) => a.name === "alice")?.standing_receiver_ready).toBe(true);

    await client.send("cello_stop_using_agent", {});

    const after = await client.send("cello_list_agents") as AgentList;
    const alice = after.agents.find((a) => a.name === "alice");
    expect(alice?.state).toBe("online");
    // The assertion that kills the bypass: the standing receiver is what accepts inbound sessions
    // and produces the away reply. Tear it down and the agent is deaf while still reading "online".
    expect(alice?.standing_receiver_ready).toBe(true);

    // And no lifecycle transition was logged — releasing is not a state change for the agent.
    expect(logEvents.filter((e) => e.event === "agent.offline")).toHaveLength(0);
  });

  it("logs agent.current.released with the agent it let go of", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    await client.send("cello_start_agent", { name: "alice" });
    await client.send("cello_use_agent", { name: "alice" });
    await client.send("cello_stop_using_agent", {});

    const released = logEvents.find((e) => e.event === "agent.current.released");
    expect(released).toBeDefined();
    expect(released!.context.fromAgent).toBe("alice");
  });

  it("is idempotent and says so when nothing is attended", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    const result = await client.send("cello_stop_using_agent", {}) as { ok: boolean; released: string | null; guidance?: string };
    expect(result.ok).toBe(true);
    expect(result.released).toBeNull();
    expect(result.guidance).toContain("not attending");
  });

  it("can re-attend after releasing — the release is not a one-way door", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    await client.send("cello_start_agent", { name: "alice" });
    await client.send("cello_use_agent", { name: "alice" });
    await client.send("cello_stop_using_agent", {});

    const reselect = await client.send("cello_use_agent", { name: "alice" }) as { ok: boolean };
    expect(reselect.ok).toBe(true);
    const list = await client.send("cello_list_agents") as AgentList;
    expect(list.agents.find((a) => a.name === "alice")?.selected).toBe(true);
  });

  // A release must NOT set `clearedAgent`. That flag means "this connection's choice was taken away
  // from it, do not guess a replacement" — it exists for the agent being shut down or removed under
  // a connection. A voluntary release is the opposite: the operator chose to hold nothing, and must
  // still be eligible for the sole-online fallback rather than locked out of it for the session.
  it("does not poison the sole-online fallback the way an involuntary clear does", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    await client.send("cello_start_agent", { name: "alice" });
    await client.send("cello_use_agent", { name: "alice" });
    await client.send("cello_stop_using_agent", {});

    // With alice the sole online agent and no explicit selection, an agent-scoped call must still
    // resolve to her. If the release had set clearedAgent, this would refuse with no_current_agent.
    // Asserted POSITIVELY. `expect(reason).not.toBe("no_current_agent")` was satisfiable by any
    // unrelated failure shape — a test that passes when the call breaks for a different reason.
    const contacts = await client.send("cello_contact_list", {}) as { ok?: boolean; agent?: string; reason?: string };
    expect(contacts.ok).toBe(true);
    expect(contacts.agent).toBe("alice");
  });

  // Attendance is PER-CONNECTION: one session releasing must not yank the agent out from under
  // another that is still driving it. This is the two-attendants case that surfaced the whole gap.
  it("only releases this connection's selection, never another connection's", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const connA = await connect(config.socketPath);
    const connB = await connect(config.socketPath);

    await connA.send("cello_start_agent", { name: "alice" });
    await connA.send("cello_use_agent", { name: "alice" });
    await connB.send("cello_use_agent", { name: "alice" });

    await connA.send("cello_stop_using_agent", {});

    const listA = await connA.send("cello_list_agents") as AgentList;
    const listB = await connB.send("cello_list_agents") as AgentList;
    expect(listA.agents.find((a) => a.name === "alice")?.selected).toBe(false);
    expect(listB.agents.find((a) => a.name === "alice")?.selected).toBe(true);
  });
});
