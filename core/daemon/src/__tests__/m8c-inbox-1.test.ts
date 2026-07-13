/**
 * CELLO-M8C-INBOX-1 — cello_check_notifications (push-loss reconciler) + watermark + F4
 *
 * Clause coverage (M8C-BUILD-JOURNAL Entry 9):
 * - N1: cello_check_notifications({ scope }) — current (default) vs all, labelled per agent.
 * - N2: unread = received transcript rows with sequence > last_delivered_seq watermark (received-only).
 * - N3: the watermark is monotonic (what cello_receive advances on delivery).
 * - N4: INBOX reads the pending inbound queue NON-destructively (await_session still gets the event).
 * - N5: a message that arrived while nothing drained it is discoverable via INBOX; advancing the
 *   watermark (delivery) clears it.
 * - F4: cello_get_sealed_receipt splits the old sealed_receipt_not_found into four distinct reasons.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import { FileKeyProvider } from "@cello-protocol/crypto";
import type { Logger, DaemonConfig } from "../types.js";

const SID64 = (a: string) => a.repeat(64).slice(0, 64); // a 64-hex-char session id

describe("M8C-INBOX-1: cello_check_notifications + watermark + F4", () => {
  let tempDir: string;
  let logger: Logger;
  let handle: DaemonHandle | null;
  let clients: IpcClient[];

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    tempDir = await mkdtemp(join(tmpdir(), "cello-inbox-"));
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

  function seedReceived(agent: string, session: string, seqs: number[], direction: "received" | "sent" = "received") {
    const mgr = handle!.getSessionNodeManager();
    for (const seq of seqs) {
      mgr.recordTranscriptMessage(agent, session, seq, direction, new TextEncoder().encode(`m${seq}`), "corr");
    }
  }

  /**
   * DOD-AGENT-ID-JOINKEY-1: `sessions` is keyed by the STABLE `agent_id`, not the mutable
   * `agent_name`. Every caller here runs AFTER `setupWithAgents` + daemon start, so the named agent
   * already has a real `agents` row (imported from its flat-file key at startup) — resolve its id.
   */
  function insertSessionRow(agent: string, session: string) {
    const db = handle!.getSessionNodeManager().getDb()!;
    const agentRow = db
      .prepare("SELECT agent_id FROM agents WHERE agent_name = ? AND state != 'retired'")
      .get(agent) as { agent_id: string } | undefined;
    if (!agentRow) throw new Error(`test fixture bug: agent '${agent}' has no 'agents' row yet`);
    const now = Date.now();
    db.prepare(
      `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
       VALUES (?, ?, ?, 'active', ?, ?, 0, NULL)`,
    ).run(session, agentRow.agent_id, "cphex", now, now);
  }

  type R = Record<string, unknown>;
  const agentsOf = (r: R) => r["agents"] as Array<{ agent: string; pending_session_requests: Array<{ session_id: string }>; unread: Array<{ session_id: string; unread_count: number; last_seq: number }>; total_unread: number }>;

  // ─── N2 / N5: unread derives from transcript + watermark; delivery clears it ───
  it("N2/N5: received messages beyond the watermark are unread; advancing the watermark clears them", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_use_agent", { name: "alice" });

    const s = SID64("a");
    seedReceived("alice", s, [0, 1, 2]);

    let res = (await client.send("cello_check_notifications", { scope: "current" })) as R;
    let a = agentsOf(res).find((x) => x.agent === "alice")!;
    expect(a.unread).toEqual([{ session_id: s, unread_count: 3, last_seq: 2 }]);
    expect(a.total_unread).toBe(3);

    // Advance the watermark to seq 1 (as a delivery of msgs 0 and 1 would) → only seq 2 remains unread.
    handle.getSessionNodeManager().advanceLastDeliveredSeq("alice", s, 1);
    res = (await client.send("cello_check_notifications", { scope: "current" })) as R;
    a = agentsOf(res).find((x) => x.agent === "alice")!;
    expect(a.unread).toEqual([{ session_id: s, unread_count: 1, last_seq: 2 }]);

    // Deliver the rest → unread clears entirely.
    handle.getSessionNodeManager().advanceLastDeliveredSeq("alice", s, 2);
    res = (await client.send("cello_check_notifications", { scope: "current" })) as R;
    a = agentsOf(res).find((x) => x.agent === "alice")!;
    expect(a.unread).toEqual([]);
    expect(a.total_unread).toBe(0);
  });

  it("N2: SENT messages are never counted as unread", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_use_agent", { name: "alice" });

    const s = SID64("b");
    seedReceived("alice", s, [0, 1], "sent"); // my own sent messages
    const res = (await client.send("cello_check_notifications", { scope: "current" })) as R;
    expect(agentsOf(res).find((x) => x.agent === "alice")!.unread).toEqual([]);
  });

  // ─── N3: watermark is monotonic (what cello_receive advances on delivery) ───
  it("N3: advanceLastDeliveredSeq is monotonic — a lower seq never un-reads", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const mgr = handle.getSessionNodeManager();
    const s = SID64("c");
    mgr.advanceLastDeliveredSeq("alice", s, 5);
    mgr.advanceLastDeliveredSeq("alice", s, 2); // out-of-order / replay — must not lower
    expect(mgr.getLastDeliveredSeq("alice", s)).toBe(5);
  });

  // ─── N3 (coupling): a live cello_receive advances the watermark (delivery marks read) ───
  // Drives the real handleReceive → advanceLastDeliveredSeq path (not the primitive directly), so a
  // hollowed handleReceive that dropped the advance would leave unread stuck and fail here.
  it("N3: cello_receive advances the read watermark so the message stops being unread", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_use_agent", { name: "alice" });

    const s = SID64("e");
    insertSessionRow("alice", s);
    // Buffer a received message (also persists its transcript row) as the real inbound path would.
    await client.send("__test_buffer_received", { agentName: "alice", sessionId: s, seq: 0, content: "m0" });

    let res = (await client.send("cello_check_notifications", { scope: "current" })) as R;
    expect(agentsOf(res).find((x) => x.agent === "alice")!.total_unread).toBe(1);

    // A real delivery — this is the only production path that advances the watermark.
    const recv = (await client.send("cello_receive", { session_id: s, timeout_ms: 1000 })) as R;
    expect(recv["content"]).toBe("m0");

    res = (await client.send("cello_check_notifications", { scope: "current" })) as R;
    expect(agentsOf(res).find((x) => x.agent === "alice")!.total_unread).toBe(0); // delivery marked it read
  });

  // ─── N1: scope all labels every loaded agent ───
  it("N1: scope 'all' returns a labelled entry per loaded agent", async () => {
    const config = await setupWithAgents("alice", "bob");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    seedReceived("alice", SID64("a"), [0]);
    seedReceived("bob", SID64("b"), [0, 1]);

    const res = (await client.send("cello_check_notifications", { scope: "all" })) as R;
    const names = agentsOf(res).map((x) => x.agent).sort();
    expect(names).toEqual(["alice", "bob"]);
    expect(agentsOf(res).find((x) => x.agent === "bob")!.total_unread).toBe(2);
  });

  // ─── N1: scope current uses F18 sole-online; ambiguous → no_current_agent ───
  it("N1: scope current uses the sole-online agent when none selected; two online + none selected errors", async () => {
    const config = await setupWithAgents("alice", "bob");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    await client.send("cello_start_agent", { name: "alice" }); // sole online, not selected
    seedReceived("alice", SID64("a"), [0]);
    let res = (await client.send("cello_check_notifications", {})) as R; // default scope current
    expect(res["ok"]).toBe(true);
    expect(agentsOf(res)[0].agent).toBe("alice");

    await client.send("cello_start_agent", { name: "bob" }); // now two online, none selected
    res = (await client.send("cello_check_notifications", {})) as R;
    expect(res["reason"]).toBe("no_current_agent");
  });

  // A connection that CHOSE an agent, and had it stopped underneath, must not be silently
  // re-targeted at whoever else is online.
  //
  // The sole-online fallback above (N1) is a convenience for a caller that NEVER chose. It must not
  // apply to a caller whose choice was taken away: it asked for alice, alice was stopped, and the
  // next call would land on bob — reporting success, as a different identity. A lost intent is not
  // the same as no intent.
  it("N1b: a SELECTION that was stopped does not fall back to another online agent — it refuses", async () => {
    const config = await setupWithAgents("alice", "bob");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    await client.send("cello_start_agent", { name: "bob" });
    await client.send("cello_use_agent", { name: "alice" });   // an explicit choice (auto-starts alice)
    await client.send("cello_stop_agent", { name: "alice" });  // ...taken away. bob is now sole-online.

    // The dangerous outcome is ok:true carrying BOB's inbox.
    const res = (await client.send("cello_check_notifications", {})) as R;
    expect(res["reason"], "a stopped selection must not silently become another agent").toBe("no_current_agent");

    // ...and choosing again must restore normal service — the refusal is not a permanent state.
    await client.send("cello_use_agent", { name: "bob" });
    const after = (await client.send("cello_check_notifications", {})) as R;
    expect(after["ok"]).toBe(true);
    expect(agentsOf(after)[0].agent).toBe("bob");
  });

  // ─── N4: INBOX reads the pending queue non-destructively ───
  it("N4: check_notifications shows pending session requests WITHOUT draining them", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_use_agent", { name: "alice" });

    const s = SID64("d");
    await client.send("__test_enqueue_inbound_session", { agentName: "alice", sessionId: s, counterpartyPubkey: "cp" });

    const res = (await client.send("cello_check_notifications", { scope: "current" })) as R;
    const pending = agentsOf(res).find((x) => x.agent === "alice")!.pending_session_requests;
    expect(pending.map((p) => p.session_id)).toEqual([s]);

    // The event must still be there for cello_await_session to drain — INBOX only peeked.
    const await1 = (await client.send("cello_await_session", { timeout_ms: 500 })) as R;
    expect(await1["session_id"] ?? await1["sessionId"]).toBe(s);
  });

  // ─── F4: cello_get_sealed_receipt splits sealed_receipt_not_found into four reasons ───
  it("F4: get_sealed_receipt returns distinct reasons (too_short / unknown / wrong_agent / not_sealed_yet)", async () => {
    const config = await setupWithAgents("alice", "bob");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_use_agent", { name: "alice" });

    const aliceSession = SID64("a");
    const bobSession = SID64("b");
    insertSessionRow("alice", aliceSession);
    insertSessionRow("bob", bobSession);

    // not_sealed_yet — alice's own session, no seal certificate.
    const nsy = (await client.send("cello_get_sealed_receipt", { session_id: aliceSession })) as R;
    expect(nsy["reason"]).toBe("not_sealed_yet");

    // wrong_agent — the session belongs to bob, but alice is current.
    const wa = (await client.send("cello_get_sealed_receipt", { session_id: bobSession })) as R;
    expect(wa["reason"]).toBe("wrong_agent");

    // session_id_too_short — a strict prefix of alice's real session id (a truncated paste).
    const tooShort = (await client.send("cello_get_sealed_receipt", { session_id: aliceSession.slice(0, 16) })) as R;
    expect(tooShort["reason"]).toBe("session_id_too_short");

    // unknown_session — an id that matches nothing.
    const unknown = (await client.send("cello_get_sealed_receipt", { session_id: SID64("f") })) as R;
    expect(unknown["reason"]).toBe("unknown_session");
  });
});
