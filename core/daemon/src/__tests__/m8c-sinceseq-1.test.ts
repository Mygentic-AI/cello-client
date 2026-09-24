/**
 * CELLO-M8C-SINCESEQ-1 — what survives of since_seq catch-up.
 *
 * `since_seq` is REMOVED (2026-09-13): the plain cello_receive returns every unread message at once
 * and crosses holes. The batch/walk tests are deleted; the reference behaviour lives in
 * receive-all-unread.test.ts. Kept here: the transcript-only session (D4b) and the document-leaf
 * case, both re-driven through the plain read.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import type { Logger, DaemonConfig } from "../types.js";
import { provisionAgentIdentity } from "../testing.js";

describe("M8C-SINCESEQ-1: transcript-only and document-leaf reads", () => {
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
      await provisionAgentIdentity(tempDir, name);
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

  /** DOD-AGENT-ID-JOINKEY-1: `sessions` is keyed by the stable `agent_id`. */
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

  /** A DOCUMENT leaf: it occupies a sequence number and writes no transcript row, by design. */
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

  describe("DOD-UNREAD-1 D4b: a transcript-only session (no sessions row) is readable", () => {
    // The real residue shape: received rows exist, the sessions table has nothing.
    function seedOrphan(agent: string, session: string, texts: string[]) {
      texts.forEach((t, i) => seed(agent, session, i, "received", t));
    }

    it("acceptance: unread counted → receive delivers with from:null → unread clears by DELIVERY", async () => {
      const config = await setupWithAgents("alice");
      handle = await startDaemon(config);
      const client = await connect(config.socketPath);
      await client.send("cello_use_agent", { name: "alice" });

      const s = "e".repeat(64);
      const away = "alice is currently away. Leave a message (send with [[WRAP]] to close) and it will be read when they return.";
      seedOrphan("alice", s, ["Dispatched.", away]);

      const before = (await client.send("cello_check_notifications", { scope: "current" })) as R;
      const beforeAgents = before["agents"] as Array<{ unread: Array<{ session_id: string; unread_count: number }> }>;
      const beforeEntry = beforeAgents[0].unread.find((u) => u.session_id === s);
      expect(beforeEntry).toBeDefined();
      expect(beforeEntry!.unread_count).toBe(2);

      // Works WITHOUT a sessions row, returns immediately, and attribution is null — never "unknown".
      const res = (await client.send("cello_receive", { session_id: s })) as R;
      expect(res["ok"]).toBe(true);
      expect(res["count"]).toBe(2);
      const msgs = res["messages"] as Array<{ sequence: number; content: string; from: string | null }>;
      expect(msgs.map((m) => m.sequence)).toEqual([0, 1]);
      expect(msgs.map((m) => m.content)).toEqual(["Dispatched.", away]);
      expect(msgs.every((m) => m.from === null)).toBe(true);

      const after = (await client.send("cello_check_notifications", { scope: "current" })) as R;
      const afterAgents = after["agents"] as Array<{ unread: Array<{ session_id: string }> }>;
      expect(afterAgents[0].unread.find((u) => u.session_id === s)).toBeUndefined();
    });

    it("a second read on a transcript-only session with nothing unread → session_not_live, never session_not_found", async () => {
      const config = await setupWithAgents("alice");
      handle = await startDaemon(config);
      const client = await connect(config.socketPath);
      await client.send("cello_use_agent", { name: "alice" });

      const s = "f".repeat(64);
      seedOrphan("alice", s, ["stranded reply"]);

      const first = (await client.send("cello_receive", { session_id: s, timeout_ms: 200 })) as R;
      expect((first["messages"] as Array<{ content: string }>).map((m) => m.content)).toEqual(["stranded reply"]);
      const res = (await client.send("cello_receive", { session_id: s, timeout_ms: 200 })) as R;
      expect(res["ok"]).toBe(false);
      expect(res["reason"]).toBe("session_not_live"); // session_not_found would be a lie — the transcript exists
      expect(String(res["guidance"])).toMatch(/cello_transcript/);
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
    });
  });

  describe("DOD-DOC-SINCESEQ-1 — a document frame does not strand later messages", () => {
    it("reads PAST a document leaf and clears unread, so a pair that co-edits can still read", async () => {
      const config = await setupWithAgents("alice");
      handle = await startDaemon(config);
      const client = await connect(config.socketPath);
      await client.send("cello_use_agent", { name: "alice" });

      const s = "e".repeat(64);
      insertSessionRow("alice", s, "cp");
      seed("alice", s, 0, "received", "m0");
      seed("alice", s, 1, "received", "m1");
      seed("alice", s, 3, "received", "m3");
      seedLeaf("alice", s, 0, "msg");
      seedLeaf("alice", s, 1, "msg");
      seedLeaf("alice", s, 2, "doc"); // a shared-document update — no transcript row, by design
      seedLeaf("alice", s, 3, "msg");

      const res = (await client.send("cello_receive", { session_id: s, timeout_ms: 500 })) as R;
      expect(res["ok"]).toBe(true);
      expect((res["messages"] as Array<{ sequence: number }>).map((m) => m.sequence)).toEqual([0, 1, 3]);

      const inbox = (await client.send("cello_check_notifications", { scope: "current" })) as R;
      const agents = inbox["agents"] as Array<{ agent: string; unread: Array<{ session_id: string }> }>;
      expect(
        agents[0].unread.find((u) => u.session_id === s),
        "the document leaf still reads as an unread message",
      ).toBeUndefined();
    });
  });
});
