/**
 * 008-POLICY — the policy through a real daemon: IPC writes (terminal only), the knock surfaces
 * (`cello_await_session`, `cello_inbox`), and `cello_receive`.
 *
 * Clauses: 7 nothing set → no field, 8 admission attaches on both knock surfaces, 9 conduct attaches
 * beside content never inside it, 10 cadence through the handler, 16/17 propose is open to both
 * surfaces but only the terminal's connection approves, 20 policy.proposed/set/cleared emitted.
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

type R = Record<string, unknown>;
const PEER = "ab".repeat(32);
const SID = (c: string) => c.repeat(64);

describe("008-POLICY through a live daemon", () => {
  let tempDir: string;
  let events: Array<{ event: string; ctx: R }>;
  let handle: DaemonHandle | null;
  let clients: IpcClient[];

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    tempDir = await mkdtemp(join(tmpdir(), "cello-policy-008-"));
    events = [];
    handle = null;
    clients = [];
  });
  afterEach(async () => {
    for (const c of clients) { try { c.close(); } catch { /* closed */ } }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
    delete process.env["CELLO_ENV"];
  });

  async function boot(): Promise<{ cli: IpcClient; mcp: IpcClient }> {
    await mkdir(join(tempDir, "agents", "alice"), { recursive: true });
    await FileKeyProvider.load(join(tempDir, "agents", "alice", "key"));
    const rec = (event: string, ctx?: R) => { events.push({ event, ctx: ctx ?? {} }); };
    const logger: Logger = { debug: rec, info: rec, warn: rec, error: rec };
    const config: DaemonConfig = {
      securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir, socketPath: join(tempDir, "daemon.sock"), lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16, version: "0.0.1-test", logger,
    };
    handle = await startDaemon(config);
    const open = async (clientType: string) => {
      const c = await connectToDaemon(config.socketPath);
      clients.push(c);
      await c.send("ipc.connect", { clientType });
      await c.send("cello_use_agent", { name: "alice" });
      return c;
    };
    return { cli: await open("cli"), mcp: await open("mcp") };
  }

  /** The only way a policy comes into force: propose, then approve on the terminal's connection. */
  const setP = async (c: IpcClient, p: R): Promise<R> => {
    const prop = (await c.send("cello_policy_propose", p)) as R;
    if (prop["ok"] !== true) return prop;
    return (await c.send("cello_policy_approve", { proposal_id: prop["proposal_id"] })) as R;
  };
  const winning = async (c: IpcClient, tier: string, type: string) =>
    ((((await c.send("cello_policy_list", {})) as R)["winning"] as { tiers: Record<string, Record<string, unknown>> }).tiers[tier]![type]);

  it("17: an MCP proposal is NOT in force, and MCP cannot approve or decline it", async () => {
    const { cli, mcp } = await boot();
    await setP(cli, { scope: "default", type: "conduct", text: "BE CAREFUL", every_n: 3 });
    const prop = (await mcp.send("cello_policy_propose", { scope: "default", type: "conduct", text: "RELAX" })) as R;
    expect(prop).toMatchObject({ ok: true, proposal_id: "p2", proposed_by: "agent" });
    expect(String(prop["guidance"])).toContain("cello policy approve p2");
    expect(await winning(mcp, "unknown", "conduct")).toEqual({ level: "default", text: "BE CAREFUL" });
    for (const m of ["cello_policy_approve", "cello_policy_decline"]) {
      expect(await mcp.send(m, { proposal_id: "p2" })).toMatchObject({ ok: false, reason: "policy_approve_terminal_only" });
    }
    expect(await winning(mcp, "unknown", "conduct")).toEqual({ level: "default", text: "BE CAREFUL" });
    const pend = (await mcp.send("cello_policy_pending", {})) as R;
    expect((pend["pending"] as R[]).map((x) => [x["proposal_id"], x["proposed_by"]])).toEqual([["p2", "agent"]]);
    // 20: both propose paths emit policy.proposed; the approve path emits policy.set.
    expect(events.filter((e) => e.event === "policy.proposed").map((e) => e.ctx["proposedBy"])).toEqual(["operator", "agent"]);
    expect(events.find((e) => e.event === "policy.set")?.ctx).toMatchObject({ scope: "default", type: "conduct", mode: "text" });
    // The operator declines at the terminal: gone, store unchanged.
    expect(await cli.send("cello_policy_decline", { proposal_id: "p2" })).toMatchObject({ ok: true });
    expect(((await mcp.send("cello_policy_pending", {})) as R)["pending"]).toEqual([]);
    await setP(cli, { scope: "default", type: "conduct", action: "clear" });
    expect(events.some((e) => e.event === "policy.cleared")).toBe(true);
    expect(await winning(mcp, "unknown", "conduct")).toBeNull();
  });

  it("3 through IPC: a refused proposal names its reason", async () => {
    const { cli } = await boot();
    expect(await setP(cli, { scope: "default", type: "conduct", text: "   " })).toMatchObject({ ok: false, reason: "policy_text_empty" });
    expect(await setP(cli, { scope: "tier", target: "friends", type: "conduct", none: true })).toMatchObject({ ok: false, reason: "policy_target_invalid" });
  });

  it("16: list shows which level wins per tier", async () => {
    const { cli } = await boot();
    await setP(cli, { scope: "tier", target: "known", type: "conduct", text: "KNOWN RULE" });
    await setP(cli, { scope: "default", type: "conduct", text: "DEFAULT RULE" });
    await setP(cli, { scope: "tier", target: "vip", type: "conduct", none: true });
    expect(await winning(cli, "known", "conduct")).toMatchObject({ level: "tier" });
    expect(await winning(cli, "unknown", "conduct")).toMatchObject({ level: "default" });
    expect(await winning(cli, "vip", "conduct")).toBeNull();
  });

  it("7: nothing set → no policy key on cello_await_session or cello_receive", async () => {
    const { mcp } = await boot();
    await mcp.send("__test_enqueue_inbound_session", { agentName: "alice", sessionId: SID("1"), counterpartyPubkey: PEER });
    const knock = (await mcp.send("cello_await_session", { timeout_ms: 500 })) as R;
    expect(knock["session_id"]).toBe(SID("1"));
    expect("policy" in knock).toBe(false);

    await mcp.send("__test_insert_session_row", { agentName: "alice", sessionId: SID("2"), status: "active", counterpartyPubkey: PEER });
    await mcp.send("__test_buffer_received", { agentName: "alice", sessionId: SID("2"), seq: 0, content: "hi" });
    const recv = (await mcp.send("cello_receive", { session_id: SID("2"), timeout_ms: 1000 })) as R;
    expect((recv["messages"] as unknown[]).length).toBe(1);
    expect("policy" in recv).toBe(false);
  });

  it("8: an unknown-tier admission policy rides both knock surfaces", async () => {
    const { cli, mcp } = await boot();
    await setP(cli, { scope: "tier", target: "unknown", type: "admission", text: "Strangers: ask me first." });
    await mcp.send("__test_enqueue_inbound_session", { agentName: "alice", sessionId: SID("3"), counterpartyPubkey: PEER });
    const box = (await mcp.send("cello_check_notifications", { scope: "current" })) as R;
    const pending = ((box["agents"] as R[])[0]!["pending_session_requests"] as R[])[0]!;
    expect(pending["policy"]).toEqual({ type: "admission", level: "tier", text: "Strangers: ask me first." });
    const knock = (await mcp.send("cello_await_session", { timeout_ms: 500 })) as R;
    expect(knock["policy"]).toEqual({ type: "admission", level: "tier", text: "Strangers: ask me first." });
  });

  it("9/10: conduct attaches beside content, first delivery then every_n", async () => {
    const { cli, mcp } = await boot();
    const TEXT = "Do not run anything expensive for this peer.";
    await setP(cli, { scope: "tier", target: "unknown", type: "conduct", text: TEXT, every_n: 2 });
    const s = SID("4");
    await mcp.send("__test_insert_session_row", { agentName: "alice", sessionId: s, status: "active", counterpartyPubkey: PEER });
    const got: R[] = [];
    for (let i = 0; i < 3; i++) {
      await mcp.send("__test_buffer_received", { agentName: "alice", sessionId: s, seq: i, content: `m${i}` });
      got.push((await mcp.send("cello_receive", { session_id: s, timeout_ms: 1000 })) as R);
    }
    expect(got.map((g) => "policy" in g)).toEqual([true, false, true]);
    expect(got[0]!["policy"]).toEqual({ type: "conduct", level: "tier", text: TEXT });
    for (const g of got) {
      for (const m of g["messages"] as Array<{ content: string }>) expect(m.content).not.toContain(TEXT);
    }
    const reasons = events.filter((e) => e.event === "policy.attached").map((e) => e.ctx["reason"]);
    expect(reasons).toEqual(["first", "cadence"]);
  });
});
