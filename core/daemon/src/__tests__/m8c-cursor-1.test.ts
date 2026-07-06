/**
 * CELLO-M8C-CURSOR-1 — per-connection, per-session read cursor (read-before-write gating)
 *
 * Clause coverage (M8C-BUILD-JOURNAL design note):
 * - C1: a fresh connection with unread history is refused cello_send with session_not_current +
 *   current_seq + last_read_seq + guidance, BEFORE any transmission attempt.
 * - C2: cello_get_transcript (covers both directions) advances the connection's cursor and
 *   unblocks the send.
 * - C3: a connection's OWN sent message auto-advances its OWN cursor (no self-block).
 * - C4 (the WhatsApp-group-chat model): two connections attending the SAME agent's SAME session —
 *   one sends, the other is blocked until it reads, including a message the FIRST connection
 *   authored (not just counterparty-received content).
 * - C5 (regression lock for the SINCESEQ gap): since_seq is received-only per its own spec, so it
 *   does NOT unblock a connection stuck behind a LOCAL (same-agent) sent message — only
 *   cello_get_transcript does. This proves why the gate's guidance points there.
 * - C6: the cursor is connection-scoped, in-memory — a fresh connection (e.g. after reconnect)
 *   starts over at -1, even though the agent/session already has history.
 * - C7 (reviewer HIGH finding, aa5928e2, fixed): the exact interleaving the original since_seq/
 *   live-drain "advance to max observed" logic got wrong — a LOCAL sent leaf followed by a
 *   counterparty-RECEIVED leaf at a higher sequence. Draining only the received leaf must NOT
 *   silently unblock a send that skips over the unread local-sent leaf.
 * - C8 (reviewer finding, per-session isolation): one connection attending TWO different sessions
 *   on the same agent — advancing the cursor on session A must not affect session B's gating.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { startDaemon } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import type { Logger, DaemonConfig } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";

class FakeNode implements Partial<CelloNode> {
  sent: Uint8Array[] = [];
  readonly #peerId = `fake-${Math.random().toString(36).slice(2)}`;
  async start(): Promise<void> {}
  async stop(): Promise<void> {}
  getPeerId(): string { return this.#peerId; }
  listenAddresses(): string[] { return ["/ip4/127.0.0.1/tcp/0"]; }
  async dial(_a: string): Promise<{ peerId: string }> { return { peerId: "remote" }; }
  async handle(_p: string, _h: unknown): Promise<void> {}
  getProtocols(): string[] { return []; }
  getConnections(): Array<{ peerId: string; encryption: string | undefined }> { return []; }
  onPeerConnect(_h: (p: string) => void): void {}
  onPeerDisconnect(_h: (p: string) => void): void {}
  getDialability(): { dialable: boolean; publicAddr: string | null } { return { dialable: false, publicAddr: null }; }
  onDialabilityChange(_l: (d: { dialable: boolean; publicAddr: string | null }) => void): () => void { return () => {}; }
  async newStream(_peer: string, _proto: string): Promise<Stream> {
    const sink = this.sent;
    return { send(d: Uint8Array) { sink.push(d); }, async close() {}, abort() {}, status: "open" } as unknown as Stream;
  }
}

class FixedFactory implements ISessionNodeFactory {
  constructor(private node: CelloNode) {}
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> { return this.node; }
}

describe("M8C-CURSOR-1: per-connection read cursor", () => {
  let tempDir: string;
  let handle: Awaited<ReturnType<typeof startDaemon>> | null;
  let clients: IpcClient[];

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-cursor-"));
    handle = null;
    clients = [];
  });

  afterEach(async () => {
    for (const c of clients) { try { c.close(); } catch { /* closed */ } }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
  });

  async function makeAgentDir(name: string): Promise<void> {
    const dir = join(tempDir, "agents", name);
    await mkdir(dir, { recursive: true });
    await FileKeyProvider.load(join(dir, "key"));
  }

  async function start(logger: Logger, node: CelloNode): Promise<Awaited<ReturnType<typeof startDaemon>>> {
    const config: DaemonConfig = {
      celloDir: tempDir, socketPath: join(tempDir, "daemon.sock"), lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16, version: "0.0.1-test", logger, sessionNodeFactory: new FixedFactory(node),
    };
    const h = await startDaemon(config);
    handle = h;
    return h;
  }

  async function connectAs(agent: string): Promise<IpcClient> {
    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    clients.push(client);
    await client.send("ipc.connect", { clientType: "test" });
    await client.send("cello_use_agent", { name: agent });
    return client;
  }

  const noopLogger: Logger = { debug() {}, info() {}, warn() {}, error() {} };

  /** Seed a RECEIVED message the same way the real inbound-content path does: append the tree
   *  leaf (bumps message_count) AND the readable transcript row, so record.message_count reflects
   *  it exactly like production. */
  function seedReceived(agent: string, sessionId: string, text: string): number {
    const snm = handle!.getSessionNodeManager();
    const { leafIndex } = snm.appendSessionLeaf(agent, sessionId, "msg", "aa".repeat(32), "seed");
    snm.recordTranscriptMessage(agent, sessionId, leafIndex, "received", new TextEncoder().encode(text), "seed");
    return leafIndex;
  }

  const SID = "cd".repeat(32);

  it("C1: a fresh connection with unread history is refused session_not_current with current_seq/last_read_seq/guidance", async () => {
    await makeAgentDir("alice");
    const h = await start(noopLogger, new FakeNode());
    await h.getSessionNodeManager().createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
    seedReceived("alice", SID, "hello from bob"); // message_count → 1, currentSeq → 0

    const client = await connectAs("alice");
    const res = (await client.send("cello_send", { session_id: SID, content: "reply" })) as Record<string, unknown>;
    expect(res).toMatchObject({ ok: false, reason: "session_not_current", current_seq: 0, last_read_seq: -1 });
    expect(String(res.guidance)).toContain("cello_get_transcript");
  });

  it("C2: cello_get_transcript advances the cursor and unblocks the send", async () => {
    await makeAgentDir("alice");
    const h = await start(noopLogger, new FakeNode());
    await h.getSessionNodeManager().createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
    seedReceived("alice", SID, "hello from bob");

    const client = await connectAs("alice");
    const blocked = (await client.send("cello_send", { session_id: SID, content: "reply" })) as Record<string, unknown>;
    expect(blocked.reason).toBe("session_not_current");

    await client.send("cello_get_transcript", { session_id: SID }); // catches up (max seq 0)

    const res = (await client.send("cello_send", { session_id: SID, content: "reply" })) as Record<string, unknown>;
    expect(res.ok).toBe(true);
    expect(typeof res.sequence_number).toBe("number");
  });

  it("C3: sending auto-advances the sender's OWN cursor (no self-block on the next send)", async () => {
    await makeAgentDir("alice");
    const h = await start(noopLogger, new FakeNode());
    await h.getSessionNodeManager().createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
    // Brand-new empty session: current_seq starts at -1, so the FIRST send needs no catch-up.

    const client = await connectAs("alice");
    const first = (await client.send("cello_send", { session_id: SID, content: "hi" })) as Record<string, unknown>;
    expect(first.ok).toBe(true);

    // A second send from the SAME connection must not be blocked by its own first message.
    const second = (await client.send("cello_send", { session_id: SID, content: "again" })) as Record<string, unknown>;
    expect(second.ok).toBe(true);
  });

  it("C4/C5 (WhatsApp-group-chat model + SINCESEQ-gap regression lock): a second connection on the SAME agent+session is blocked by the first connection's OWN sent message; since_seq (received-only) does NOT unblock it, only cello_get_transcript does", async () => {
    await makeAgentDir("alice");
    const h = await start(noopLogger, new FakeNode());
    await h.getSessionNodeManager().createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr");

    const connA = await connectAs("alice");
    const connB = await connectAs("alice"); // second attended connection, SAME agent

    const sendA = (await connA.send("cello_send", { session_id: SID, content: "from A" })) as Record<string, unknown>;
    expect(sendA.ok).toBe(true); // A's own send is never blocked

    // B has read nothing — A's message is a "sent" (not "received") row for this agent, so it is
    // invisible to B's since_seq batch by SINCESEQ's own received-only spec (the gap).
    const bBlocked = (await connB.send("cello_send", { session_id: SID, content: "from B" })) as Record<string, unknown>;
    expect(bBlocked).toMatchObject({ ok: false, reason: "session_not_current", current_seq: 0, last_read_seq: -1 });

    const sinceSeqAttempt = (await connB.send("cello_receive", { session_id: SID, since_seq: -1 })) as Record<string, unknown>;
    expect(sinceSeqAttempt.count).toBe(0); // regression lock: since_seq alone cannot see A's sent message

    const stillBlocked = (await connB.send("cello_send", { session_id: SID, content: "from B" })) as Record<string, unknown>;
    expect(stillBlocked.reason).toBe("session_not_current"); // since_seq did NOT unblock B

    await connB.send("cello_get_transcript", { session_id: SID }); // the correct catch-up path
    const bNowOk = (await connB.send("cello_send", { session_id: SID, content: "from B" })) as Record<string, unknown>;
    expect(bNowOk.ok).toBe(true);
  });

  it("C6: the cursor is connection-scoped — a fresh connection starts at -1 even with existing history", async () => {
    await makeAgentDir("alice");
    const h = await start(noopLogger, new FakeNode());
    await h.getSessionNodeManager().createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr");

    const conn1 = await connectAs("alice");
    const sent = (await conn1.send("cello_send", { session_id: SID, content: "hi" })) as Record<string, unknown>;
    expect(sent.ok).toBe(true);
    conn1.close();

    const conn2 = await connectAs("alice"); // brand-new connectionId, same agent+session
    const res = (await conn2.send("cello_send", { session_id: SID, content: "again" })) as Record<string, unknown>;
    expect(res).toMatchObject({ ok: false, reason: "session_not_current", current_seq: 0, last_read_seq: -1 });
  });

  function msgLeafHash(content: Uint8Array): Uint8Array {
    return new Uint8Array(createHash("sha256").update(new Uint8Array([0x00])).update(content).digest());
  }

  it("C7 (reviewer HIGH fix, live reproduction of the reported bypass): draining ONLY a later counterparty-received message must not silently unblock a send that skips an unread local-sent leaf", async () => {
    await makeAgentDir("alice");
    const h = await start(noopLogger, new FakeNode());
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr");

    const connA = await connectAs("alice");
    const connB = await connectAs("alice");

    // leaf 0: connA sends (a LOCAL sent message connB has not read).
    const sendA = (await connA.send("cello_send", { session_id: SID, content: "from A" })) as Record<string, unknown>;
    expect(sendA.ok).toBe(true);

    // leaf 1: counterparty content arrives (received), buffered for delivery.
    const inbound = new TextEncoder().encode("from counterparty");
    await snm.ingestReceivedContent("alice", SID, inbound, msgLeafHash(inbound), "corr-inbound");

    // connB drains ONLY the buffered received content (leaf 1) via live cello_receive — it has
    // still never read leaf 0 (connA's sent message).
    const recv = (await connB.send("cello_receive", { session_id: SID, timeout_ms: 500 })) as Record<string, unknown>;
    expect(recv.content).toBe("from counterparty");
    expect(recv.sequence_number).toBe(1);

    // The bug: the old "advance to max observed" logic would set connB's cursor to 1 (having
    // seen leaf 1), silently treating leaf 0 as read too. Fixed: connB must STILL be refused.
    const stillBlocked = (await connB.send("cello_send", { session_id: SID, content: "from B" })) as Record<string, unknown>;
    expect(stillBlocked).toMatchObject({ ok: false, reason: "session_not_current", current_seq: 1, last_read_seq: -1 });

    // Only cello_get_transcript (full bidirectional history) correctly closes the gap.
    await connB.send("cello_get_transcript", { session_id: SID });
    const nowOk = (await connB.send("cello_send", { session_id: SID, content: "from B" })) as Record<string, unknown>;
    expect(nowOk.ok).toBe(true);
  });

  it("C8 (reviewer finding, per-session isolation): one connection attending two different sessions — advancing one's cursor must not unblock the other", async () => {
    await makeAgentDir("alice");
    const h = await start(noopLogger, new FakeNode());
    const snm = h.getSessionNodeManager();
    const SID_A = "aa".repeat(32);
    const SID_B = "bb".repeat(32);
    await snm.createSessionNode(SID_A, "alice", "bobpubkeyhex", "bob-peer-id-a", "corr-a");
    await snm.createSessionNode(SID_B, "alice", "carolpubkeyhex", "carol-peer-id-b", "corr-b");

    // Attend FIRST (M8C-AWAY-1 is now live in this daemon too — seeding while unattended would
    // trigger its own auto-ack, adding an extra leaf this CURSOR-only test isn't about).
    const client = await connectAs("alice");

    // Seed unread history on BOTH sessions.
    const msgA = new TextEncoder().encode("on A");
    const msgB = new TextEncoder().encode("on B");
    await snm.ingestReceivedContent("alice", SID_A, msgA, msgLeafHash(msgA), "corr-a");
    await snm.ingestReceivedContent("alice", SID_B, msgB, msgLeafHash(msgB), "corr-b");

    // Catch up ONLY on session A.
    await client.send("cello_get_transcript", { session_id: SID_A });

    const sendA = (await client.send("cello_send", { session_id: SID_A, content: "reply A" })) as Record<string, unknown>;
    expect(sendA.ok).toBe(true); // A is caught up

    // A hollow Map<connectionId, number> (dropping the per-session dimension) would let this
    // through too, since it never read B's history — must still be refused.
    const sendB = (await client.send("cello_send", { session_id: SID_B, content: "reply B" })) as Record<string, unknown>;
    expect(sendB).toMatchObject({ ok: false, reason: "session_not_current", current_seq: 0, last_read_seq: -1 });
  });
});
