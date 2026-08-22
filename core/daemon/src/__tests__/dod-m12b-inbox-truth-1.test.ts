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
 * entry there when the NOTICE passes its TTL unclaimed, so "expired" names a notice we stopped
 * showing, never a session that went away. An operator who reads it as "that session is gone"
 * abandons a live session.
 *
 * That claim was NOT true when this file was first written. The reaper tested `tooOld` before
 * `terminal`, so a notice that was both past its TTL and already sealed landed in the expired list
 * under prose saying the session may still be live — the guidance would have been wrong about a
 * finished session. The reaper now reaps terminal first, and the last test below pins that overlap
 * so the ordering cannot be flipped back without the prose going with it.
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

  it("a notice that is BOTH expired and SEALED is reaped as terminal, never listed as expired", async () => {
    // The overlap the guidance depends on. `expired_session_requests` says the session may still be
    // live; a sealed session must therefore never appear in it, or that sentence is a lie about a
    // conversation that is over.
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_use_agent", { name: "alice" });

    const s = SID64("t");
    await client.send("__test_enqueue_inbound_session", {
      agentName: "alice", sessionId: s, counterpartyPubkey: "cp",
      enqueuedAtOverride: Date.now() - INBOUND_SESSION_TTL_MS - 1000,   // past TTL...
    });
    await client.send("__test_insert_session_row", { agentName: "alice", sessionId: s, status: "sealed" }); // ...AND sealed

    const box = await inboxFor(client, "alice");
    expect(box.pending_session_requests).toEqual([]);
    expect(box.expired_session_requests.map((e) => e.session_id)).not.toContain(s);
  });

  it("the refused list survives the ended-unread branch — the two returns carry the same keys", async () => {
    // The defect's SHAPE is "a field present on one return object and absent on its sibling", so
    // this asserts the shape, not the instance: an agent that happens to have ended-unread history
    // must not lose a surface an agent without it has. `refused_session_requests` was the field
    // that went missing (M12-P18's cap visibility), and nothing covered it before or after.
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_use_agent", { name: "alice" });

    const snm = handle.getSessionNodeManager();
    const refused = SID64("r");
    const ended = SID64("x");
    // An ended-unread row, which is what selects the OTHER return branch.
    await client.send("__test_insert_session_row", { agentName: "alice", sessionId: ended, status: "sealed" });
    snm.recordTranscriptMessage("alice", ended, 0, "received", new TextEncoder().encode("unread"), "seed");
    /**
     * A REAL reason, not an invented one.
     *
     * This seeded `"sender_cap"`, which no refusal path emits — the test seam took a free-form
     * string, so it could prove the inbox handles a code production never produces.
     * `DOD-M15-GUARD-HEARD-1` closed the union and the seam now validates against it, so this had
     * to become a reason that actually exists. It is the capacity bound this test is about.
     */
    await client.send("__test_record_refusal", {
      agentName: "alice", sessionId: refused, counterpartyPubkey: "cp",
      reason: "abuse_bound_sessions_per_sender",
    });

    const box = (await inboxFor(client, "alice")) as unknown as Record<string, unknown>;
    const refusedList = box["refused_session_requests"] as Array<{ session_id: string }> | undefined;
    expect(box["ended_unread"], "this test must exercise the ended-unread return branch").toBeDefined();
    expect(refusedList?.map((r) => r.session_id) ?? []).toContain(refused);
  });
});
