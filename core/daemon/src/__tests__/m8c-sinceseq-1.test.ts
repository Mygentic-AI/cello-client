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

  function insertSessionRow(agent: string, session: string, counterparty: string) {
    const db = handle!.getSessionNodeManager().getDb()!;
    const now = Date.now();
    db.prepare(
      `INSERT INTO sessions (session_id, agent_name, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
       VALUES (?, ?, ?, 'active', ?, ?, 0, NULL)`,
    ).run(session, agent, counterparty, now, now);
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

  it("S4: cello_receive WITHOUT since_seq is unchanged (drains live buffer / times out, no batch)", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_use_agent", { name: "alice" });

    const s = "c".repeat(64);
    insertSessionRow("alice", s, "cp");
    seed("alice", s, 0, "received", "in transcript but not in the live buffer");

    // No since_seq → the classic drain-or-timeout path: nothing buffered → a null-content timeout,
    // NOT the since_seq batch (the transcript row must NOT be returned by a plain receive).
    const res = (await client.send("cello_receive", { session_id: s, timeout_ms: 200 })) as R;
    expect(res["ok"]).toBe(true);
    expect(res).not.toHaveProperty("messages"); // no batch shape
    expect(res["content"]).toBeNull();
  });
});
