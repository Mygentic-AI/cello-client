/**
 * CELLO-M8C-SINCESEQ-1 — cello_receive({ since_seq }): stateless catch-up
 *
 * Clause coverage (M8C-BUILD-JOURNAL Entry 15):
 * - S1: since_seq returns a BATCH of received transcript messages with sequence > since_seq, ordered.
 * - S2: stateless + no replay race — reads the durable transcript, not the ephemeral buffer.
 * - S3: advances the read watermark to the max returned sequence (clears INBOX unread).
 * - S4: cello_receive WITHOUT since_seq is unchanged (no regression).
 * - received-only: the operator's own sent messages are not returned as catch-up.
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

describe("M8C-SINCESEQ-1: cello_receive since_seq catch-up", () => {
  let tempDir: string;
  let logger: Logger;
  let handle: DaemonHandle | null;
  let clients: IpcClient[];

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    tempDir = await mkdtemp(join(tmpdir(), "cello-sinceseq-"));
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

  /**
   * DOD-AGENT-ID-JOINKEY-1: `sessions` is keyed by the STABLE `agent_id`, not the mutable
   * `agent_name`. Every caller here runs AFTER `setupWithAgents` + daemon start, so the named agent
   * already has a real `agents` row (imported from its flat-file key at startup) — resolve its id.
   */
  function insertSessionRow(agent: string, session: string, counterparty: string) {
    const db = handle!.getSessionNodeManager().getDb()!;
    const agentRow = db
      .prepare("SELECT agent_id FROM agents WHERE agent_name = ? AND state != 'retired'")
      .get(agent) as { agent_id: string } | undefined;
    if (!agentRow) throw new Error(`test fixture bug: agent '${agent}' has no 'agents' row yet`);
    const now = Date.now();
    db.prepare(
      `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
       VALUES (?, ?, ?, 'active', ?, ?, 0, NULL)`,
    ).run(session, agentRow.agent_id, counterparty, now, now);
  }

  /**
   * A DOCUMENT leaf: it occupies a sequence number and writes no transcript row, which is exactly
   * what `document-frame-router.ts` does on purpose ("A document frame is NOT a transcript
   * message"). Inserted directly because the alternative is standing up a whole document exchange
   * to produce one row.
   */
  function seedLeaf(agent: string, session: string, leafIndex: number, kind: "msg" | "doc") {
    const db = handle!.getSessionNodeManager().getDb()!;
    const agentRow = db
      .prepare("SELECT agent_id FROM agents WHERE agent_name = ? AND state != 'retired'")
      .get(agent) as { agent_id: string };
    db.prepare(
      `INSERT INTO session_tree_leaves (agent_id, session_id, leaf_index, leaf_kind, leaf_hash_hex, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(agentRow.agent_id, session, leafIndex, kind, "aa".repeat(32), Date.now());
  }

  function seed(agent: string, session: string, seq: number, direction: "received" | "sent", text: string) {
    handle!.getSessionNodeManager().recordTranscriptMessage(agent, session, seq, direction, new TextEncoder().encode(text), "seed");
  }

  type R = Record<string, unknown>;

  it("S1/S2/S3: since_seq returns received messages beyond the cursor (ordered, content-bearing) and advances the watermark", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_use_agent", { name: "alice" });

    const s = "a".repeat(64);
    const from = "cafebabe";
    insertSessionRow("alice", s, from);
    // received 0,1,2,3,4 + one SENT (must be excluded from catch-up)
    for (const i of [0, 1, 2, 3, 4]) seed("alice", s, i, "received", `msg-${i}`);
    seed("alice", s, 5, "sent", "my own reply");

    const res = (await client.send("cello_receive", { session_id: s, since_seq: 2 })) as R;
    expect(res["ok"]).toBe(true);
    const msgs = res["messages"] as Array<{ sequence: number; content: string; from: string }>;
    // S1: only received seq > 2, ascending
    expect(msgs.map((m) => m.sequence)).toEqual([3, 4]);
    expect(msgs.map((m) => m.content)).toEqual(["msg-3", "msg-4"]);
    expect(msgs.every((m) => m.from === from)).toBe(true);
    expect(res["count"]).toBe(2);

    // S3: watermark advanced to 4 → INBOX unread cleared for this session
    const inbox = (await client.send("cello_check_notifications", { scope: "current" })) as R;
    const agents = inbox["agents"] as Array<{ agent: string; unread: Array<{ session_id: string }> }>;
    expect(agents[0].unread.find((u) => u.session_id === s)).toBeUndefined();
  });

  it("F8 (review): a HOLE INSIDE the delivered batch stops the watermark — a row nobody could read is not 'read'", async () => {
    // This path used to vault the watermark straight to the highest received sequence it delivered,
    // jumping anything in between. The leaf it jumps can be a transcript row that failed to
    // decrypt: readTranscript drops such a row from `messages`, but getUnreadReceivedCount still
    // counts it. So a message nobody could read was silently marked read, stopped counting as
    // unread, and cleared the send gate's second authority — the agent could then reply to a
    // conversation containing content it had never seen and could not see.
    //
    // Seq 2 is absent here, which is what a dropped/undecryptable row looks like to this code.
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_use_agent", { name: "alice" });

    const s = "d".repeat(64);
    insertSessionRow("alice", s, "cp");
    for (const i of [0, 1, 3]) seed("alice", s, i, "received", `m${i}`);

    const res = (await client.send("cello_receive", { session_id: s, since_seq: 0 })) as R;
    expect(res["ok"]).toBe(true);
    // Delivery is unchanged — the caller still RECEIVES everything readable. Only the claim about
    // what has been read is held back.
    expect((res["messages"] as Array<{ sequence: number }>).map((m) => m.sequence)).toEqual([1, 3]);

    // The watermark stopped at 1, so seq 3 is still outstanding and the session still reports unread.
    const inbox = (await client.send("cello_check_notifications", { scope: "current" })) as R;
    const agents = inbox["agents"] as Array<{ agent: string; unread: Array<{ session_id: string }> }>;
    expect(
      agents[0]?.unread.find((u) => u.session_id === s),
      "a gap below a delivered row must leave the session unread — not vaulted past",
    ).toBeDefined();
  });

  it("H1 (review): a SENT leaf in the range must NOT stop the watermark — reading everything clears unread", async () => {
    // The regression the first H1 fix introduced, and the reason this clause exists rather than a
    // comment. The walk was contiguous over the RECEIVED-only batch, and leaf indices are
    // contiguous across BOTH directions — so this agent's own reply, or a sibling connection's, is
    // a hole. Reading everything then left the session still reporting unread: the badge could not
    // be cleared, and a stateless CLI caller (fresh connection per command, so the cursor authority
    // can never help it) was refused forever through the very door the guidance points at.
    //
    // This is the M8D co-attendance shape: received, sibling's SENT, received.
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_use_agent", { name: "alice" });

    const s = "e".repeat(64);
    insertSessionRow("alice", s, "cp");
    seed("alice", s, 0, "received", "theirs");
    seed("alice", s, 1, "sent", "our reply from another window");
    seed("alice", s, 2, "received", "theirs again");

    const res = (await client.send("cello_receive", { session_id: s, since_seq: -1 })) as R;
    expect(res["ok"]).toBe(true);
    expect((res["messages"] as Array<{ sequence: number }>).map((m) => m.sequence)).toEqual([0, 2]);

    // Everything readable has been read, so nothing may still be reported unread.
    const inbox = (await client.send("cello_check_notifications", { scope: "current" })) as R;
    const agents = inbox["agents"] as Array<{ agent: string; unread: Array<{ session_id: string }> }> | undefined;
    expect(
      agents?.[0]?.unread.find((u) => u.session_id === s),
      "a SENT leaf is not an unread message — it must not pin the watermark",
    ).toBeUndefined();
  });

  it("S1: since_seq at the latest sequence returns an empty batch (not an error)", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_use_agent", { name: "alice" });

    const s = "b".repeat(64);
    insertSessionRow("alice", s, "cp");
    for (const i of [0, 1, 2]) seed("alice", s, i, "received", `m${i}`);

    const res = (await client.send("cello_receive", { session_id: s, since_seq: 2 })) as R;
    expect(res["ok"]).toBe(true);
    expect(res["count"]).toBe(0);
    expect(res["messages"]).toEqual([]);
  });

  // Boundary (reviewer): since_seq:0 is a VALID cursor and must batch (return seq > 0), NOT be
  // treated as falsy/absent. Pins that 0 !== undefined at this branch.
  it("since_seq:0 batches (returns sequence > 0), distinct from an absent since_seq", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_use_agent", { name: "alice" });

    const s = "d".repeat(64);
    insertSessionRow("alice", s, "cp");
    for (const i of [0, 1, 2]) seed("alice", s, i, "received", `m${i}`);

    const res = (await client.send("cello_receive", { session_id: s, since_seq: 0 })) as R;
    expect(res["ok"]).toBe(true);
    expect(res["since_seq"]).toBe(0); // 0 reached the batch branch (not the plain path)
    const msgs = res["messages"] as Array<{ sequence: number }>;
    expect(msgs.map((m) => m.sequence)).toEqual([1, 2]); // seq > 0 (msg 0 excluded)
  });

  // ─── S4, REWRITTEN BY DOD-COATTEND-1 (Tier 1), 2026-08-01 ───────────────────────────────────
  //
  // This clause used to assert that a plain receive must NOT return a transcript row that was never
  // in the live buffer. That was true of the destructive queue, and Tier 1 deliberately changed it:
  // delivery now reads the DURABLE RECORD against a per-connection bookmark, precisely so a message
  // is not lost when the buffer is drained by a sibling session or dies with a connection.
  //
  // So the clause is inverted rather than deleted — the transcript row IS now deliverable — and
  // what it still guards is the half that did not change: a plain receive returns ONE message in
  // the single-message shape, never the `since_seq` batch shape. Conflating those would break every
  // caller that switches on `messages` vs `content`.
  it("S4 (Tier 1): a plain receive DOES deliver a durable row, and still never returns the batch shape", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_use_agent", { name: "alice" });

    const s = "c".repeat(64);
    insertSessionRow("alice", s, "cp");
    seed("alice", s, 0, "received", "in transcript but not in the live buffer");

    const res = (await client.send("cello_receive", { session_id: s, timeout_ms: 200 })) as R;
    expect(res["ok"]).toBe(true);
    // The durable row is delivered — this is the Tier-1 change, and it is what stops a message
    // being lost when a sibling drains the buffer or the reading connection dies.
    expect(res["content"]).toBe("in transcript but not in the live buffer");
    // ...in the SINGLE-message shape. The since_seq batch shape is a different contract and callers
    // switch on it, so a plain receive must never return `messages`.
    expect(res).not.toHaveProperty("messages");
  });

  // ─── DOD-UNREAD-1 D4b (M8C-PHANTOM-SESSION-FIX-PLAN §4, reader for legacy residue) ──────────
  // Installs that predate D3/D4a carry received transcript rows with NO sessions row (the phantom
  // sessions' orphaned replies). getUnreadSummary counts them; cello_receive returned
  // session_not_found — permanently unread AND unreadable. The catch-up read must work from the
  // durable transcript alone; the badge clears only by ACTUAL delivery, never by hiding.
  describe("DOD-UNREAD-1 D4b: a transcript-only session (no sessions row) is readable via since_seq", () => {
    // The real residue shape: received rows exist (recordTranscriptMessage never required a
    // sessions row), the sessions table has nothing.
    function seedOrphan(agent: string, session: string, texts: string[]) {
      texts.forEach((t, i) => seed(agent, session, i, "received", t));
    }

    it("acceptance: unread counted → since_seq delivers with from:null → watermark advances → unread clears by DELIVERY", async () => {
      const config = await setupWithAgents("alice");
      handle = await startDaemon(config);
      const client = await connect(config.socketPath);
      await client.send("cello_use_agent", { name: "alice" });

      const s = "e".repeat(64);
      seedOrphan("alice", s, ["Dispatched.", "alice is currently away. Leave a message (send with [[WRAP]] to close) and it will be read when they return."]);

      // BEFORE the read: the badge shows the two messages (they are real — never hide them).
      const before = (await client.send("cello_check_notifications", { scope: "current" })) as R;
      const beforeAgents = before["agents"] as Array<{ unread: Array<{ session_id: string; unread_count: number }> }>;
      const beforeEntry = beforeAgents[0].unread.find((u) => u.session_id === s);
      expect(beforeEntry).toBeDefined();
      expect(beforeEntry!.unread_count).toBe(2);

      // The catch-up read works WITHOUT a sessions row, and attribution is null — never "unknown".
      const res = (await client.send("cello_receive", { session_id: s, since_seq: -1 })) as R;
      expect(res["ok"]).toBe(true);
      expect(res["count"]).toBe(2);
      const msgs = res["messages"] as Array<{ sequence: number; content: string; from: string | null }>;
      expect(msgs.map((m) => m.sequence)).toEqual([0, 1]);
      expect(msgs.map((m) => m.content)).toEqual(["Dispatched.", "alice is currently away. Leave a message (send with [[WRAP]] to close) and it will be read when they return."]);
      expect(msgs.every((m) => m.from === null)).toBe(true);

      // AFTER actual delivery: the badge clears — by the watermark, not by a JOIN that hides rows.
      const after = (await client.send("cello_check_notifications", { scope: "current" })) as R;
      const afterAgents = after["agents"] as Array<{ unread: Array<{ session_id: string }> }>;
      expect(afterAgents[0].unread.find((u) => u.session_id === s)).toBeUndefined();
    });

    it("plain receive on a transcript-only session → session_not_live with since_seq guidance — never session_not_found", async () => {
      const config = await setupWithAgents("alice");
      handle = await startDaemon(config);
      const client = await connect(config.socketPath);
      await client.send("cello_use_agent", { name: "alice" });

      const s = "f".repeat(64);
      seedOrphan("alice", s, ["stranded reply"]);

      const res = (await client.send("cello_receive", { session_id: s, timeout_ms: 200 })) as R;
      expect(res["ok"]).toBe(false);
      expect(res["reason"]).toBe("session_not_live"); // session_not_found would be a lie — the transcript exists
      expect(String(res["guidance"])).toMatch(/since_seq/);
    });

    it("regression: a session with NEITHER a sessions row NOR transcript rows is still session_not_found", async () => {
      const config = await setupWithAgents("alice");
      handle = await startDaemon(config);
      const client = await connect(config.socketPath);
      await client.send("cello_use_agent", { name: "alice" });

      const s = "9".repeat(64);
      const plain = (await client.send("cello_receive", { session_id: s, timeout_ms: 100 })) as R;
      expect(plain["ok"]).toBe(false);
      expect(plain["reason"]).toBe("session_not_found");
      const batch = (await client.send("cello_receive", { session_id: s, since_seq: -1 })) as R;
      expect(batch["ok"]).toBe(false);
      expect(batch["reason"]).toBe("session_not_found");
    });
  });
describe("DOD-DOC-SINCESEQ-1 — a document frame is not a hole in the catch-up walk", () => {
  it("advances PAST a document leaf, so a pair that co-edits can still catch up", async () => {
    // THE DEFECT, found live between two agents mid-conversation. A document frame takes a sequence
    // number and writes no transcript row, so from the transcript side it is indistinguishable from
    // a row that could never be read — and the contiguous walk treated it as unread and stopped.
    // Permanently: the hole never fills, so `since_seq` was broken for that pair FOREVER and the
    // send gate refused them while the guidance pointed at the tool they had just used.
    //
    // Not an edge case. The delivery worker REUSES an open session, so document traffic lands in
    // whatever conversation the two agents already have — any pair that talks and co-edits.
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_use_agent", { name: "alice" });

    const s = "e".repeat(64);
    insertSessionRow("alice", s, "cp");
    seed("alice", s, 0, "received", "m0");
    seed("alice", s, 1, "received", "m1");
    seed("alice", s, 3, "received", "m3");
    // The TREE, dense — leaf index IS the canonical sequence (that is what MSG-4's in-order gate
    // maintains), so the kind at index 2 is what tells the walk this slot was never a message.
    seedLeaf("alice", s, 0, "msg");
    seedLeaf("alice", s, 1, "msg");
    seedLeaf("alice", s, 2, "doc"); // a shared-document update — no transcript row, by design
    seedLeaf("alice", s, 3, "msg");

    const res = (await client.send("cello_receive", { session_id: s, since_seq: 1 })) as R;
    expect(res["ok"]).toBe(true);
    // Delivery was never the broken half — the readable message always came back.
    expect((res["messages"] as Array<{ sequence: number }>).map((m) => m.sequence)).toEqual([3]);

    // THE ASSERTION: unread is CLEARED. Before the fix the walk stopped at 2 and seq 3 stayed
    // unread forever, so this session never left the inbox and every send was refused.
    const inbox = (await client.send("cello_check_notifications", { scope: "current" })) as R;
    const agents = inbox["agents"] as Array<{ agent: string; unread: Array<{ session_id: string }> }>;
    expect(
      agents[0].unread.find((u) => u.session_id === s),
      "the document leaf still reads as an unread message",
    ).toBeUndefined();
  });

  it("STILL stops at a genuinely absent index — an unreadable row is not a document leaf", async () => {
    // The negative control, and the reason the fix keys on LEAF KIND rather than row-absence.
    // Absent-and-unreadable and absent-because-not-a-message look identical from the transcript, so
    // a fix that tested for a missing row would have relocated the bug instead of closing it.
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_use_agent", { name: "alice" });

    const s = "f".repeat(64);
    insertSessionRow("alice", s, "cp");
    seed("alice", s, 0, "received", "m0");
    // No leaf of any kind at 1 — a row nobody could read. It must still block.
    seed("alice", s, 2, "received", "m2");

    await client.send("cello_receive", { session_id: s, since_seq: 0 });
    const inbox = (await client.send("cello_check_notifications", { scope: "current" })) as R;
    const agents = inbox["agents"] as Array<{ agent: string; unread: Array<{ session_id: string }> }>;
    expect(
      agents[0].unread.find((u) => u.session_id === s),
      "an unreadable row was silently marked read",
    ).toBeDefined();
  });
});
});
