/**
 * CELLO-M8C-TTL-1 — receiver-side session-request TTL
 *
 * Clause coverage (M8C-BUILD-JOURNAL design note):
 * - T1: a queued session request past INBOUND_SESSION_TTL_MS (24h default) is reaped — it no
 *   longer appears in cello_check_notifications' pending_session_requests, and cello_await_session
 *   never hands it back.
 * - T2: reaped requests are VISIBLE as expired in INBOX (expired_session_requests), not silently
 *   dropped.
 * - T3: a request younger than the TTL stays in pending_session_requests, unaffected.
 * - T4: reaping is lazy (on read), not a background timer — no reap, no side effect, until
 *   something actually reads the queue.
 * - T5: a non-expired entry whose session has reached a terminal DB status (sealed / abandoned /
 *   seal_interrupted_pending / interrupted) is silently dropped from pending — NOT moved to
 *   expired_session_requests.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway";
import { startDaemon, INBOUND_SESSION_TTL_MS } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import type { DaemonConfig } from "../types.js";

describe("M8C-TTL-1: session-request TTL", () => {
  let tempDir: string;
  let handle: Awaited<ReturnType<typeof startDaemon>> | null;
  let clients: IpcClient[];

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test"; // gates the __test_enqueue_inbound_session hook
    tempDir = await mkdtemp(join(tmpdir(), "cello-ttl-"));
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
    securityGateway: new PassthroughGatewayClient(),
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

  it("T1/T2: an expired request is reaped out of pending and surfaces in expired_session_requests", async () => {
    await makeAgentDir("alice");
    await start();
    const client = await connectAs("alice");

    const staleSid = "aa".repeat(16);
    await client.send("__test_enqueue_inbound_session", {
      agentName: "alice",
      sessionId: staleSid,
      counterpartyPubkey: "stalepubkeyhex",
      enqueuedAtOverride: Date.now() - INBOUND_SESSION_TTL_MS - 1000, // 1s past the TTL
    });

    const inbox = (await client.send("cello_check_notifications", { scope: "current" })) as {
      agents: Array<{
        pending_session_requests: Array<{ session_id: string }>;
        expired_session_requests: Array<{ session_id: string; from: string; expired_at: number }>;
      }>;
    };
    const { pending_session_requests, expired_session_requests } = inbox.agents[0];
    expect(pending_session_requests.find((p) => p.session_id === staleSid)).toBeUndefined(); // T1
    const expiredEntry = expired_session_requests.find((e) => e.session_id === staleSid);
    expect(expiredEntry).toBeDefined(); // T2 — visible, not silently dropped
    expect(expiredEntry?.from).toBe("stalepubkeyhex");
    expect(typeof expiredEntry?.expired_at).toBe("number");
  });

  it("T1: cello_await_session never hands back an expired entry (times out instead)", async () => {
    await makeAgentDir("alice");
    await start();
    const client = await connectAs("alice");

    const staleSid = "bb".repeat(16);
    await client.send("__test_enqueue_inbound_session", {
      agentName: "alice",
      sessionId: staleSid,
      counterpartyPubkey: "stalepubkeyhex",
      enqueuedAtOverride: Date.now() - INBOUND_SESSION_TTL_MS - 1000,
    });

    const res = (await client.send("cello_await_session", { timeout_ms: 200 })) as Record<string, unknown>;
    expect(res.type).not.toBe("new_session"); // reaped before it could be handed back — times out
  });

  it("T3: a request younger than the TTL stays pending, unaffected", async () => {
    await makeAgentDir("alice");
    await start();
    const client = await connectAs("alice");

    const freshSid = "cc".repeat(16);
    await client.send("__test_enqueue_inbound_session", {
      agentName: "alice",
      sessionId: freshSid,
      counterpartyPubkey: "freshpubkeyhex",
      enqueuedAtOverride: Date.now() - 1000, // 1s old — nowhere near the 24h TTL
    });

    const inbox = (await client.send("cello_check_notifications", { scope: "current" })) as {
      agents: Array<{ pending_session_requests: Array<{ session_id: string }>; expired_session_requests: unknown[] }>;
    };
    expect(inbox.agents[0].pending_session_requests.find((p) => p.session_id === freshSid)).toBeDefined();
    expect(inbox.agents[0].expired_session_requests).toHaveLength(0);
  });

  it.each(["sealed", "abandoned", "seal_interrupted_pending", "interrupted"] as const)(
    "T5: a non-expired entry with terminal DB status '%s' is silently dropped (not moved to expired)",
    async (terminalStatus) => {
      await makeAgentDir("alice");
      await start();
      const client = await connectAs("alice");

      const sessionId = "dd".repeat(16);
      // Enqueue a fresh (non-expired) inbound session request.
      await client.send("__test_enqueue_inbound_session", {
        agentName: "alice",
        sessionId,
        counterpartyPubkey: "terminatedpubkey",
        enqueuedAtOverride: Date.now() - 1000, // 1s old — well within TTL
      });
      // Seed a session DB row at the terminal status, as would happen after bilateral close.
      await client.send("__test_insert_session_row", {
        agentName: "alice",
        sessionId,
        status: terminalStatus,
        counterpartyPubkey: "terminatedpubkey",
      });

      const inbox = (await client.send("cello_check_notifications", { scope: "current" })) as {
        agents: Array<{
          pending_session_requests: Array<{ session_id: string }>;
          expired_session_requests: Array<{ session_id: string }>;
        }>;
      };
      const { pending_session_requests, expired_session_requests } = inbox.agents[0];
      // Terminal entries are silently dropped — not pending, not in expired list.
      expect(pending_session_requests.find((p) => p.session_id === sessionId)).toBeUndefined();
      expect(expired_session_requests.find((e) => e.session_id === sessionId)).toBeUndefined();
    },
  );

  // Reviewer HIGH finding (aed2d71f, D19): a whitelisted CONTACT-1 contact is exempt from
  // ABUSE-1's acceptance bounds, so they can push unlimited accepted sessions the operator never
  // claims — each becoming a permanent, unbounded expiredSessionRequests entry. Capped at 20.
  it("expired_session_requests is capped — does not grow unbounded past 20 per agent", async () => {
    await makeAgentDir("alice");
    await start();
    const client = await connectAs("alice");

    for (let i = 0; i < 25; i++) {
      await client.send("__test_enqueue_inbound_session", {
        agentName: "alice",
        sessionId: i.toString(16).padStart(32, "0"),
        counterpartyPubkey: `stranger-${i}`,
        enqueuedAtOverride: Date.now() - INBOUND_SESSION_TTL_MS - 1000,
      });
    }

    const inbox = (await client.send("cello_check_notifications", { scope: "current" })) as {
      agents: Array<{ expired_session_requests: unknown[] }>;
    };
    expect(inbox.agents[0].expired_session_requests.length).toBeLessThanOrEqual(20);
  });
});
