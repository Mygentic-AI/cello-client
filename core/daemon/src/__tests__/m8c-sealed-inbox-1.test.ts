/**
 * CELLO-M8C-SEALED-INBOX-1 — sealed sessions with unread do not pollute cello_inbox
 *
 * Clause coverage (DOD-SEALED-INBOX-1):
 * - T1: a sealed session with unread messages does NOT appear in `unread`; it appears in
 *   `sealed_unread` (with guidance).
 * - T2: after cello_dismiss, the session no longer appears in `sealed_unread`.
 * - T3: cello_dismiss on an active session returns `session_not_terminal`.
 * - T4: dismissed status survives an inbox re-check (read_at persists in the DB).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { startDaemon } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import type { DaemonConfig } from "../types.js";

describe("M8C-SEALED-INBOX-1: sealed sessions with unread messages", () => {
  let tempDir: string;
  let handle: Awaited<ReturnType<typeof startDaemon>> | null;
  let clients: IpcClient[];

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    tempDir = await mkdtemp(join(tmpdir(), "cello-sealed-inbox-"));
    handle = null;
    clients = [];
  });
  afterEach(async () => {
    for (const c of clients) { try { c.close(); } catch { /* closed */ } }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
    delete process.env["CELLO_ENV"];
  });

  async function makeAgentDir(name: string): Promise<void> {
    const dir = join(tempDir, "agents", name);
    await mkdir(dir, { recursive: true });
    await FileKeyProvider.load(join(dir, "key"));
  }

  async function start(): Promise<Awaited<ReturnType<typeof startDaemon>>> {
    const config: DaemonConfig = {
      celloDir: tempDir, socketPath: join(tempDir, "daemon.sock"), lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16, version: "0.0.1-test", logger: { debug() {}, info() {}, warn() {}, error() {} },
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

  it("T1: sealed session with unread appears in sealed_unread, NOT in unread", async () => {
    await makeAgentDir("alice");
    await start();
    const client = await connectAs("alice");
    const mgr = handle!.getSessionNodeManager();

    const sessionId = "ee".repeat(16);
    // Insert a sealed session row and a received transcript message above the watermark.
    await client.send("__test_insert_session_row", {
      agentName: "alice",
      sessionId,
      status: "sealed",
      counterpartyPubkey: "cphex",
    });
    mgr.recordTranscriptMessage("alice", sessionId, 0, "received", new TextEncoder().encode("hello"), "corr");

    const inbox = (await client.send("cello_check_notifications", { scope: "current" })) as {
      agents: Array<{
        unread: Array<{ session_id: string }>;
        sealed_unread?: Array<{ session_id: string }>;
        sealed_unread_guidance?: string;
        total_unread: number;
      }>;
    };
    const a = inbox.agents[0];
    expect(a.unread.find((u) => u.session_id === sessionId)).toBeUndefined(); // T1a
    expect(a.total_unread).toBe(0);
    expect(a.sealed_unread).toBeDefined(); // T1b
    expect(a.sealed_unread!.find((u) => u.session_id === sessionId)).toBeDefined();
    expect(typeof a.sealed_unread_guidance).toBe("string"); // guidance present
  });

  it("T2: after cello_dismiss, session no longer appears in sealed_unread", async () => {
    await makeAgentDir("alice");
    await start();
    const client = await connectAs("alice");
    const mgr = handle!.getSessionNodeManager();

    const sessionId = "ff".repeat(16);
    await client.send("__test_insert_session_row", {
      agentName: "alice",
      sessionId,
      status: "sealed",
      counterpartyPubkey: "cphex",
    });
    mgr.recordTranscriptMessage("alice", sessionId, 0, "received", new TextEncoder().encode("msg"), "corr");

    // Confirm it shows in sealed_unread before dismiss.
    const before = (await client.send("cello_check_notifications", { scope: "current" })) as {
      agents: Array<{ sealed_unread?: Array<{ session_id: string }> }>;
    };
    expect(before.agents[0].sealed_unread?.find((u) => u.session_id === sessionId)).toBeDefined();

    // Dismiss it.
    const dismissRes = (await client.send("cello_dismiss", { session_id: sessionId })) as { ok: boolean };
    expect(dismissRes.ok).toBe(true);

    // Should no longer appear.
    const after = (await client.send("cello_check_notifications", { scope: "current" })) as {
      agents: Array<{ sealed_unread?: Array<{ session_id: string }> }>;
    };
    expect(after.agents[0].sealed_unread?.find((u) => u.session_id === sessionId)).toBeUndefined();
  });

  it("T3: cello_dismiss on an active session returns session_not_terminal", async () => {
    await makeAgentDir("alice");
    await start();
    const client = await connectAs("alice");

    const sessionId = "11".repeat(16);
    await client.send("__test_insert_session_row", {
      agentName: "alice",
      sessionId,
      status: "active",
      counterpartyPubkey: "cphex",
    });

    const res = (await client.send("cello_dismiss", { session_id: sessionId })) as { ok: boolean; reason: string };
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("session_not_terminal");
  });

  it("T4: dismissed status persists — sealed_unread stays empty on re-check", async () => {
    await makeAgentDir("alice");
    await start();
    const client = await connectAs("alice");
    const mgr = handle!.getSessionNodeManager();

    const sessionId = "22".repeat(16);
    await client.send("__test_insert_session_row", {
      agentName: "alice",
      sessionId,
      status: "abandoned",
      counterpartyPubkey: "cphex",
    });
    mgr.recordTranscriptMessage("alice", sessionId, 0, "received", new TextEncoder().encode("msg"), "corr");

    await client.send("cello_dismiss", { session_id: sessionId });

    // Check twice to confirm read_at persisted.
    for (let i = 0; i < 2; i++) {
      const inbox = (await client.send("cello_check_notifications", { scope: "current" })) as {
        agents: Array<{ sealed_unread?: Array<{ session_id: string }> }>;
      };
      expect(inbox.agents[0].sealed_unread?.find((u) => u.session_id === sessionId)).toBeUndefined();
    }
  });
});
