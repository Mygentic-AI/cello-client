/**
 * DOD-M12B-INBOX-TRUTH-1 — `pending_session_requests` describes an ALREADY-ACCEPTED session.
 *
 * THE DEFECT, measured 2026-08-17. The field is produced from the in-memory notification queue and
 * its true meaning is "no `cello_await_session` has claimed this notice yet". It is read — by every
 * agent, and by its own name — as "this session has not been accepted". The two readings point in
 * opposite directions about what the operator should do next.
 *
 * The producer settles it. `acceptInboundAssignment` accepts the session and hands off the standing
 * receiver, and only THEN calls `enqueueInboundSession` (`inbound-sessions.ts`). So at the instant a
 * row appears in this list the session is live, readable with `cello_receive` and repliable with
 * `cello_send`. The project's own skill file says the same thing out loud: *"Inbound sessions are
 * auto-accepted by the standing receiver — there is no separate accept step."*
 *
 * Cost: hours on 2026-08-17, and a confidently wrong report that two agents disagreed about whether
 * a session existed. They never did — one side was reading this field as a to-do list.
 *
 * `expired_session_requests` carries the SAME misreading and is fixed with it: the reaper moves an
 * entry there when the NOTICE passes its TTL unclaimed, and it only does so for a session whose
 * record was NOT terminal, so "expired" names a notice we stopped showing, never a session that
 * went away. An operator who reads it as "that session is gone" abandons a live session.
 *
 * The fix is additive — per-entry `accepted: true` plus guidance. The field NAMES are unchanged on
 * purpose: they are the wire surface the shim, the CLI and both skill files already speak, and a
 * rename would trade one day of confusion for a compatibility break.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon, type DaemonHandle, INBOUND_SESSION_TTL_MS } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import { FileKeyProvider } from "@cello-protocol/crypto";
import type { Logger, DaemonConfig } from "../types.js";

const SID64 = (a: string) => a.repeat(64).slice(0, 64);

type R = Record<string, unknown>;
type AgentInbox = {
  agent: string;
  pending_session_requests: Array<{ session_id: string; from: string; accepted?: boolean }>;
  pending_session_requests_guidance?: string;
  expired_session_requests: Array<{ session_id: string; accepted?: boolean }>;
  expired_session_requests_guidance?: string;
};

describe("DOD-M12B-INBOX-TRUTH-1: the inbox does not report accepted sessions as unaccepted", () => {
  let tempDir: string;
  let logger: Logger;
  let handle: DaemonHandle | null;
  let clients: IpcClient[];

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    tempDir = await mkdtemp(join(tmpdir(), "cello-inbox-truth-"));
    logger = { debug() {}, info() {}, warn() {}, error() {} };
    handle = null;
    clients = [];
  });

  afterEach(async () => {
    for (const c of clients) { try { c.close(); } catch { /* closed */ } }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
    delete process.env["CELLO_ENV"];
  });

  async function setupWithAgents(...names: string[]): Promise<DaemonConfig> {
    for (const name of names) {
      await mkdir(join(tempDir, "agents", name), { recursive: true });
      await FileKeyProvider.load(join(tempDir, "agents", name, "key"));
    }
    return {
      securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir, socketPath: join(tempDir, "daemon.sock"), lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16, version: "0.0.1-test", logger,
    };
  }

  async function connect(socketPath: string): Promise<IpcClient> {
    const client = await connectToDaemon(socketPath);
    clients.push(client);
    await client.send("ipc.connect", { clientType: "mcp" });
    return client;
  }

  async function inboxFor(client: IpcClient, agent: string): Promise<AgentInbox> {
    const res = (await client.send("cello_check_notifications", { scope: "current" })) as R;
    const agents = res["agents"] as AgentInbox[];
    return agents.find((a) => a.agent === agent)!;
  }

  it("a pending entry states that the session is ALREADY ACCEPTED", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_use_agent", { name: "alice" });

    const s = SID64("d");
    await client.send("__test_enqueue_inbound_session", { agentName: "alice", sessionId: s, counterpartyPubkey: "cp" });

    const box = await inboxFor(client, "alice");
    expect(box.pending_session_requests.map((p) => p.session_id)).toEqual([s]);
    // The per-entry fact, ahead of any prose the caller may not read.
    expect(box.pending_session_requests[0].accepted).toBe(true);
  });

  it("the guidance says the session is readable NOW, and that await_session only drains the notice", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_use_agent", { name: "alice" });
    await client.send("__test_enqueue_inbound_session", { agentName: "alice", sessionId: SID64("d"), counterpartyPubkey: "cp" });

    const guidance = (await inboxFor(client, "alice")).pending_session_requests_guidance ?? "";
    // It must say the session is already accepted...
    expect(guidance).toMatch(/already accepted/i);
    // ...name what the caller can do RIGHT NOW instead of hunting for an accept step...
    expect(guidance).toMatch(/cello_receive/);
    expect(guidance).toMatch(/cello_send/);
    // ...and say what "pending" is actually about, so the word stops meaning the session.
    expect(guidance).toMatch(/cello_await_session/);
    expect(guidance).toMatch(/notice/i);
  });

  it("emits no pending guidance when there is nothing pending — the surface stays quiet", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_use_agent", { name: "alice" });

    const box = await inboxFor(client, "alice");
    expect(box.pending_session_requests).toEqual([]);
    expect(box.pending_session_requests_guidance).toBeUndefined();
  });

  it("an EXPIRED entry says the notice expired, not the session — it too was accepted", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_use_agent", { name: "alice" });

    const s = SID64("e");
    await client.send("__test_enqueue_inbound_session", {
      agentName: "alice", sessionId: s, counterpartyPubkey: "cp",
      enqueuedAtOverride: Date.now() - INBOUND_SESSION_TTL_MS - 1000,
    });

    const box = await inboxFor(client, "alice");
    expect(box.expired_session_requests.map((e) => e.session_id)).toEqual([s]);
    expect(box.expired_session_requests[0].accepted).toBe(true);

    const guidance = box.expired_session_requests_guidance ?? "";
    expect(guidance).toMatch(/notice/i);
    // The reaper only expires notices whose session record was NOT terminal, so it must not read as
    // "this session is over" — that is the reading that abandons a live session.
    expect(guidance).toMatch(/cello_sessions|still (be )?(live|active|open)/i);
  });

  it("N4 still holds — the inbox peeks, cello_await_session still drains the notice", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_use_agent", { name: "alice" });

    const s = SID64("f");
    await client.send("__test_enqueue_inbound_session", { agentName: "alice", sessionId: s, counterpartyPubkey: "cp" });
    await inboxFor(client, "alice");

    const drained = (await client.send("cello_await_session", { timeout_ms: 500 })) as R;
    expect(drained["session_id"] ?? drained["sessionId"]).toBe(s);
  });
});
