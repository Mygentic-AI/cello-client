/**
 * CELLO-M8C-MSGWAKE-1 — channel stage 2: per-message wake (cello_message doorbell)
 *
 * Drives the REAL inbound funnel (ingestReceivedContent → #appendVerifiedContent) so the callback
 * → dispatchCelloMessage → notification chain is proven against the actual producer, not a stub
 * (the WAKE reviewer's F2 flag: re-prove INV-CONTENTFREE against the real cello_message producer).
 *
 * Clause coverage (M8C-BUILD-JOURNAL Entry 14):
 * - M1: a verified inbound message fires a cello_message notification.
 * - M2: the frame carries session_id + from (senderPubkey) + type.
 * - M3 (INV-CONTENTFREE): no content/message/text/plaintext in the frame.
 * - routing: only connections where the affected agent is current receive it.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import { FileKeyProvider } from "@cello-protocol/crypto";
import type { Logger, DaemonConfig, IpcNotification } from "../types.js";

describe("M8C-MSGWAKE-1: cello_message doorbell on inbound content", () => {
  let tempDir: string;
  let logger: Logger;
  let handle: DaemonHandle | null;
  let clients: IpcClient[];

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    tempDir = await mkdtemp(join(tmpdir(), "cello-msgwake-"));
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

  function collect(client: IpcClient): IpcNotification[] {
    const buf: IpcNotification[] = [];
    client.onNotification((n) => buf.push(n));
    return buf;
  }

  function insertSessionRow(agent: string, session: string, counterparty: string) {
    const db = handle!.getSessionNodeManager().getDb()!;
    const now = Date.now();
    db.prepare(
      `INSERT INTO sessions (session_id, agent_name, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
       VALUES (?, ?, ?, 'active', ?, ?, 0, NULL)`,
    ).run(session, agent, counterparty, now, now);
  }

  // ingestReceivedContent verifies contentHash = sha256(0x00 || content) (domain-separated).
  const contentHash = (content: Uint8Array) =>
    new Uint8Array(createHash("sha256").update(new Uint8Array([0x00])).update(content).digest());

  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

  it("M1/M2/M3: a real inbound message fires a content-free cello_message doorbell to the current-agent connection only", async () => {
    const config = await setupWithAgents("alice", "bob");
    handle = await startDaemon(config);

    const clientA = await connect(config.socketPath); // will be current=alice
    const clientB = await connect(config.socketPath); // will be current=bob
    await clientA.send("cello_start_agent", { name: "alice" });
    await clientA.send("cello_use_agent", { name: "alice" });
    await clientB.send("cello_use_agent", { name: "bob" });

    const notifA = collect(clientA);
    const notifB = collect(clientB);

    const sessionId = "a".repeat(64);
    const senderPubkey = "cafebabe";
    insertSessionRow("alice", sessionId, senderPubkey);

    // Drive the REAL inbound funnel — this is what a live session content-frame does.
    const content = new TextEncoder().encode("hello from the peer");
    const result = handle.getSessionNodeManager().ingestReceivedContent(
      "alice", sessionId, content, contentHash(content), "corr-msg",
    );
    expect(result.ok).toBe(true); // sanity: the real funnel accepted the message

    await sleep(150);

    // M1: alice's connection got exactly one cello_message doorbell
    const msgsA = notifA.filter((n) => n.notification === "cello_message");
    expect(msgsA).toHaveLength(1);

    // M2: it carries type + from + session_id
    const data = msgsA[0].data as Record<string, unknown>;
    expect(data["type"]).toBe("cello_message");
    expect(data["from"]).toBe(senderPubkey);
    expect(data["session_id"]).toBe(sessionId);
    expect(data["agent"]).toBe("alice");

    // M3 (INV-CONTENTFREE): no message content on the doorbell
    expect(data).not.toHaveProperty("content");
    expect(data).not.toHaveProperty("message");
    expect(data).not.toHaveProperty("text");
    expect(data).not.toHaveProperty("plaintext");
    // and the plaintext bytes must not appear anywhere in the serialized frame
    expect(JSON.stringify(msgsA[0])).not.toContain("hello from the peer");

    // routing: bob's connection (different current agent) got NO cello_message
    expect(notifB.filter((n) => n.notification === "cello_message")).toHaveLength(0);
  });

  // M4 / M1 "recovered": HELD out-of-order content must wake ONCE, at RELEASE — not at hold time.
  // Locks the funnel placement: a doorbell fired in ingestReceivedContent BEFORE the hold gate would
  // wake here at hold (buffer not yet drainable) — this test would then see a wake too early.
  it("M4: held out-of-order content fires the doorbell once at RELEASE, not at hold", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_use_agent", { name: "alice" });
    const notif = collect(client);

    const mgr = handle.getSessionNodeManager();
    const s = "b".repeat(64);
    insertSessionRow("alice", s, "cp");

    // content_B is witnessed at canonical seq 1 (ahead of the empty tree's next-expected 0) → HELD.
    const contentB = new TextEncoder().encode("second message");
    const hashB = contentHash(contentB);
    mgr.recordWitnessedSequence("alice", s, Buffer.from(hashB).toString("hex"), 1);
    const heldRes = mgr.ingestReceivedContent("alice", s, contentB, hashB, "corr-B");
    expect((heldRes as { held?: boolean }).held).toBe(true); // held, not appended
    await sleep(120);
    expect(notif.filter((n) => n.notification === "cello_message")).toHaveLength(0); // NO wake at hold

    // content_A fills seq 0 → appends (1 wake) AND unblocks the held content_B (released → 1 wake).
    const contentA = new TextEncoder().encode("first message");
    mgr.ingestReceivedContent("alice", s, contentA, contentHash(contentA), "corr-A");
    await sleep(150);
    const msgs = notif.filter((n) => n.notification === "cello_message");
    expect(msgs).toHaveLength(2); // exactly one per real message (A + released B) — no premature/extra wake
  });

  // M1 dedup: a replay of an already-appended content hash must fire ZERO additional doorbells.
  // Locks the funnel placement: a doorbell fired before the dedup gate would wake twice here.
  it("M1: a deduplicated replay of the same content hash fires no extra doorbell", async () => {
    const config = await setupWithAgents("alice");
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_use_agent", { name: "alice" });
    const notif = collect(client);

    const mgr = handle.getSessionNodeManager();
    const s = "c".repeat(64);
    insertSessionRow("alice", s, "cp");

    const content = new TextEncoder().encode("delivered twice");
    const hash = contentHash(content);
    mgr.ingestReceivedContent("alice", s, content, hash, "first");  // appends → 1 wake
    const dupRes = mgr.ingestReceivedContent("alice", s, content, hash, "replay"); // same hash → dedup
    expect((dupRes as { appendedCount?: number }).appendedCount).toBe(0); // no new leaf
    await sleep(150);
    expect(notif.filter((n) => n.notification === "cello_message")).toHaveLength(1); // exactly one, not two
  });
});
