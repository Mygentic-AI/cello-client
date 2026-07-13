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
    // DOD-ONBOARD-HELP-1 §5: assert the SUBSTANCE, not the spelling. The daemon now renders the
    // remedy for the surface that asked (a CLI caller is told `cello transcript`, an MCP caller
    // `cello_transcript`), so pinning one spelling here would pin the wrong one for half the
    // callers. Both renderings are locked end-to-end in dod-onboard-help-1-vocabulary.test.ts.
    expect(String(res.guidance)).toMatch(/transcript/);
    expect(String(res.guidance)).toMatch(/unread/i);
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

  // ─── DOD-CURSOR-DURABLE-1 (2026-07-11, Andre's explicit go) — C4/C5/C6/C7 CHANGE ON PURPOSE ───
  //
  // These four clauses asserted that a connection is blocked by a message THIS AGENT SENT from a
  // DIFFERENT local connection. That is no longer true, and the change is deliberate, not a
  // regression. The gate now passes if EITHER the connection cursor is caught up (unchanged) OR the
  // agent has no unread RECEIVED messages (new, durable, persisted).
  //
  // WHY the old rule had to go: the cursor is in-memory and per-connection. A stateless client — the
  // `cello` CLI, a fresh process per command — always presents cursor -1, so it could never satisfy
  // it. Once the counterparty spoke, EVERY CLI send was refused forever, even though the agent had
  // demonstrably read the message. A bash agent could speak once and then never reply. The same bug
  // silently hit any RECONNECTING MCP client (fresh connectionId → cursor -1).
  //
  // The line the gate now draws, exactly:
  //   • unread COUNTERPARTY content still blocks — fully preserved, and now durable (C1, C2, C8,
  //     and the D-clauses below). This is the guarantee that matters: never reply to something
  //     nobody on your side has seen.
  //   • a message YOUR OWN AGENT sent from another window no longer blocks — RELAXED. The agent
  //     authored it; the daemon cannot referee which of an operator's own windows a human is
  //     looking at, and a socket is not a trust boundary. The principal is the agent.
  //
  // The clauses below are rewritten to lock the NEW boundary — including, explicitly, that the
  // counterparty half did NOT weaken.
  it("C4/C5 (rewritten, DOD-CURSOR-DURABLE-1): a second connection on the same agent is NO LONGER blocked by the first connection's own SENT message — but IS still blocked by unread COUNTERPARTY content", async () => {
    await makeAgentDir("alice");
    const h = await start(noopLogger, new FakeNode());
    await h.getSessionNodeManager().createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr");

    const connA = await connectAs("alice");
    const connB = await connectAs("alice"); // second attended connection, SAME agent

    const sendA = (await connA.send("cello_send", { session_id: SID, content: "from A" })) as Record<string, unknown>;
    expect(sendA.ok).toBe(true); // A's own send is never blocked

    // THE DELIBERATE CHANGE: B has read nothing, but the only thing it hasn't seen is a message THIS
    // AGENT sent. There is no unread counterparty content, so B may send. (Old behavior: refused.)
    const bNowAllowed = (await connB.send("cello_send", { session_id: SID, content: "from B" })) as Record<string, unknown>;
    expect(bNowAllowed.ok).toBe(true);

    // THE HALF THAT DID NOT WEAKEN: now the COUNTERPARTY speaks. Nobody on alice's side has read it.
    const inbound = new TextEncoder().encode("from bob");
    await h.getSessionNodeManager().ingestReceivedContent("alice", SID, inbound, msgLeafHash(inbound), "corr-in");

    const refused = (await connB.send("cello_send", { session_id: SID, content: "blind reply" })) as Record<string, unknown>;
    expect(refused).toMatchObject({ ok: false, reason: "session_not_current" });
    expect(refused.unread_received).toBe(1); // the gate names WHY: one unread counterparty message

    // And connA — which also never read bob — is refused too. Unread counterparty content blocks
    // EVERY connection on the agent, exactly as before.
    const refusedA = (await connA.send("cello_send", { session_id: SID, content: "also blind" })) as Record<string, unknown>;
    expect(refusedA).toMatchObject({ ok: false, reason: "session_not_current" });
  });

  it("C6 (rewritten, DOD-CURSOR-DURABLE-1): a fresh connection is no longer blocked by the agent's OWN prior send — this is the stateless-CLI path (a new process per command)", async () => {
    await makeAgentDir("alice");
    const h = await start(noopLogger, new FakeNode());
    await h.getSessionNodeManager().createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr");

    const conn1 = await connectAs("alice");
    const sent = (await conn1.send("cello_send", { session_id: SID, content: "hi" })) as Record<string, unknown>;
    expect(sent.ok).toBe(true);
    conn1.close();

    // Exactly what `cello send` does twice in a row: a brand-new connectionId, cursor -1, on a
    // session that already has history. The only unread leaf is this agent's OWN message.
    const conn2 = await connectAs("alice");
    const res = (await conn2.send("cello_send", { session_id: SID, content: "again" })) as Record<string, unknown>;
    expect(res.ok).toBe(true);
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

    // DOD-CURSOR-DURABLE-1 (rewritten): connB has now READ the counterparty's message (leaf 1), so
    // the durable clause is satisfied — there is no unread received content. The only leaf it has
    // not seen is leaf 0, which THIS AGENT sent. Under the per-agent rule that no longer blocks, so
    // the send is allowed. (Old behavior: refused, because the per-connection cursor was still -1.)
    //
    // The C7 hazard the original clause guarded — "advance to max observed silently marks an
    // earlier leaf read" — is still guarded where it matters: safeCursorAdvance/safeWatermarkAdvance
    // both refuse to vault past a gap, so an unread RECEIVED leaf can never be skipped. That is
    // proved by D3 below (a hole in the transcript keeps the counterparty message unread).
    const nowAllowed = (await connB.send("cello_send", { session_id: SID, content: "from B" })) as Record<string, unknown>;
    expect(nowAllowed.ok).toBe(true);
  });

  // ─── DOD-CURSOR-DURABLE-1 — the new durable clauses ────────────────────────────────────────
  describe("DOD-CURSOR-DURABLE-1: read-before-write survives the connection", () => {
    it("D1 (the fix): a FRESH connection may send once the AGENT has read the counterparty — the stateless-CLI case", async () => {
      await makeAgentDir("alice");
      const h = await start(noopLogger, new FakeNode());
      await h.getSessionNodeManager().createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
      seedReceived("alice", SID, "hello from bob");

      // Connection 1 = `cello receive`. It reads, advancing the PERSISTED watermark, then exits.
      const reader = await connectAs("alice");
      const got = (await reader.send("cello_receive", { session_id: SID, since_seq: -1 })) as Record<string, unknown>;
      expect(got.count).toBe(1);
      reader.close();

      // Connection 2 = `cello send`, a brand-new process. Its cursor is -1 and always will be.
      // Before this fix it was refused forever; now the agent's durable read unblocks it.
      const sender = await connectAs("alice");
      const res = (await sender.send("cello_send", { session_id: SID, content: "reply from bash" })) as Record<string, unknown>;
      expect(res.ok).toBe(true);
    });

    it("D2 (the guarantee HOLDS): unread counterparty content still refuses a fresh connection — the fix is not a bypass", async () => {
      await makeAgentDir("alice");
      const h = await start(noopLogger, new FakeNode());
      await h.getSessionNodeManager().createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
      seedReceived("alice", SID, "hello from bob"); // NOBODY reads it

      const sender = await connectAs("alice");
      const res = (await sender.send("cello_send", { session_id: SID, content: "blind reply" })) as Record<string, unknown>;
      expect(res).toMatchObject({ ok: false, reason: "session_not_current", unread_received: 1 });

      // ...and it stays refused across a reconnect. The block is durable, not an artifact of one socket.
      sender.close();
      const sender2 = await connectAs("alice");
      const again = (await sender2.send("cello_send", { session_id: SID, content: "still blind" })) as Record<string, unknown>;
      expect(again).toMatchObject({ ok: false, reason: "session_not_current" });
    });

    it("D3 (AC3 + hole safety): cello_get_transcript advances the PERSISTED watermark, and a gap in the transcript keeps later messages unread", async () => {
      await makeAgentDir("alice");
      const h = await start(noopLogger, new FakeNode());
      const snm = h.getSessionNodeManager();
      await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr");

      // Attend FIRST (as C8 does): seeding while unattended trips M8C-AWAY-1's auto-ack, which
      // appends its own SENT leaf and muddies the exact sequence numbers this clause is about.
      const attendant = await connectAs("alice");

      seedReceived("alice", SID, "bob 1"); // received leaf 0
      expect(snm.getLastDeliveredSeq("alice", SID)).toBe(-1); // nothing read yet

      // A fresh connection reads the TRANSCRIPT (not cello_receive) — the remedy the gate's guidance
      // names. Before AC3 this advanced only the dying connection cursor, so the next process was
      // still blocked and the documented remedy was a dead end for any stateless client.
      const reader = await connectAs("alice");
      await reader.send("cello_get_transcript", { session_id: SID });
      reader.close();
      expect(snm.getLastDeliveredSeq("alice", SID)).toBe(0); // PERSISTED — survives the socket
      expect(snm.getUnreadReceivedCount("alice", SID)).toBe(0);

      const sender = await connectAs("alice");
      const res = (await sender.send("cello_send", { session_id: SID, content: "reply" })) as Record<string, unknown>;
      expect(res.ok).toBe(true); // sent leaf (seq 2 after the reply)

      // Hole safety: append a leaf with NO transcript row (the shape an undecryptable/failed write
      // leaves), then a real received message BEYOND it. The contiguous walk must stop at the gap,
      // so the later counterparty message can never be silently marked read.
      snm.appendSessionLeaf("alice", SID, "msg", "bb".repeat(32), "hole"); // no transcript row
      const bob2Seq = seedReceived("alice", SID, "bob 2 (beyond the hole)");

      const reader2 = await connectAs("alice");
      await reader2.send("cello_get_transcript", { session_id: SID });
      // The walk may advance THROUGH rows it actually saw (the reply it sent), but it must STOP at
      // the hole — so the watermark never reaches bob 2, and bob 2 stays unread. That is the whole
      // point: a message the agent has not seen cannot be marked read by a gap.
      expect(snm.getLastDeliveredSeq("alice", SID)).toBeLessThan(bob2Seq);
      expect(snm.getUnreadReceivedCount("alice", SID)).toBeGreaterThan(0); // "bob 2" still unread

      // ...and because it is still unread, the gate still refuses the send. Hole safety is not
      // cosmetic — it is what stops the fix becoming a bypass.
      const refused = (await reader2.send("cello_send", { session_id: SID, content: "blind" })) as Record<string, unknown>;
      expect(refused).toMatchObject({ ok: false, reason: "session_not_current" });
      attendant.close();
    });

    it("D4 (the safety property): the long-lived single-connection path is UNCHANGED — read-then-send behaves exactly as before", async () => {
      await makeAgentDir("alice");
      const h = await start(noopLogger, new FakeNode());
      await h.getSessionNodeManager().createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
      seedReceived("alice", SID, "hello from bob");

      // This is the MCP shim's shape: ONE socket for the whole session. It is refused before reading
      // and allowed after — identical to pre-fix behavior, satisfied by the connection-cursor clause.
      const mcp = await connectAs("alice");
      const blocked = (await mcp.send("cello_send", { session_id: SID, content: "reply" })) as Record<string, unknown>;
      expect(blocked).toMatchObject({ ok: false, reason: "session_not_current", current_seq: 0, last_read_seq: -1 });

      await mcp.send("cello_get_transcript", { session_id: SID });
      const ok = (await mcp.send("cello_send", { session_id: SID, content: "reply" })) as Record<string, unknown>;
      expect(ok.ok).toBe(true);
    });
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

  // §1.5 — the read-before-write gate FAILS CLOSED when it cannot count.
  //
  // getUnreadReceivedCount answers one question for the send gate: "is there counterparty content
  // this agent has not read?" A 0 means "caught up" and UNBLOCKS a send. So every path that cannot
  // actually answer must return a POSITIVE count, never 0 — a 0 guessed from a broken DB silently
  // defeats the gate, which is the one thing the gate exists to prevent.
  //
  // This pins the reachable half of that contract. The other half (the query returning no row) is
  // unreachable — SELECT COUNT(*) with no GROUP BY always yields exactly one row — so it cannot be
  // driven from a test without inventing a DB seam that exists only for the test. It is still fixed,
  // because a fail-OPEN default sitting inside a gate documented as FAILS CLOSED is a defect whether
  // or not today's SQL happens to spare us. Both branches now answer the same way.
  it("§1.5: a gate that cannot count refuses the send — it never guesses 'caught up'", async () => {
    await makeAgentDir("alice");
    const h = await start(noopLogger, new FakeNode());
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr");

    const inbound = new TextEncoder().encode("unread counterparty content");
    await snm.ingestReceivedContent("alice", SID, inbound, msgLeafHash(inbound), "corr-inbound");
    expect(snm.getUnreadReceivedCount("alice", SID)).toBeGreaterThan(0);

    // Tear the DB out from under the gate. It can no longer count anything.
    await snm.gracefulShutdown();

    // It must STILL refuse — "I don't know" is not "you're caught up".
    expect(snm.getUnreadReceivedCount("alice", SID)).toBeGreaterThan(0);
  });

  // §1.9 — content ingested with NO relay witness must SAY SO.
  //
  // The relay is an independent attestation: it delivers B a (content_hash -> canonical sequence)
  // binding derived from the sender's own signed leaf. When B holds that witness, B can check the
  // content it received against a hash the sender committed to a THIRD PARTY. When B holds no
  // witness, the only hash B can compare against is the one riding in the same frame as the content
  // — i.e. B is checking the sender's claim against the sender's claim.
  //
  // We do NOT refuse unwitnessed content: the relay may legitimately be unreachable or merely slow,
  // and making the relay a hard precondition for READING mail would trade the redundancy invariant
  // away — a relay outage would render the inbox unreadable. That is the wrong trade.
  //
  // What we refuse is the SILENCE. An unwitnessed append is a materially weaker guarantee than a
  // witnessed one, and today the two are indistinguishable from the outside. It must be visible.
  it("§1.9: an append with no relay witness is announced, not silently treated as verified", async () => {
    const events: Array<{ event: string; ctx: Record<string, unknown> }> = [];
    const spyLogger: Logger = {
      debug() {}, info() {}, error() {},
      warn(event: string, ctx?: Record<string, unknown>) { events.push({ event, ctx: ctx ?? {} }); },
    };

    await makeAgentDir("alice");
    const h = await start(spyLogger, new FakeNode());
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr");

    // No recordWitnessedSequence() for this hash — the relay never witnessed it.
    const unwitnessed = new TextEncoder().encode("no relay witness for this one");
    await snm.ingestReceivedContent("alice", SID, unwitnessed, msgLeafHash(unwitnessed), "corr-unwitnessed");

    const warned = events.filter((e) => e.event === "session.content.unwitnessed");
    expect(warned, "an unwitnessed append must emit session.content.unwitnessed").toHaveLength(1);
    expect(warned[0].ctx).toMatchObject({ sessionId: SID, leafIndex: 0 });

    // ...and a WITNESSED append must NOT cry wolf, or the signal is worthless.
    const witnessed = new TextEncoder().encode("this one is witnessed");
    const hashHex = Buffer.from(msgLeafHash(witnessed)).toString("hex");
    snm.recordWitnessedSequence("alice", SID, hashHex, 1);
    await snm.ingestReceivedContent("alice", SID, witnessed, msgLeafHash(witnessed), "corr-witnessed");

    expect(events.filter((e) => e.event === "session.content.unwitnessed")).toHaveLength(1);
  });
});
