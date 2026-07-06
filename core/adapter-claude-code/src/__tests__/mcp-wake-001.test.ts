/**
 * CELLO-M8C-WAKE-001 — IpcProxy notification forwarding (channel stage 1, daemon→shim leg)
 *
 * DOD-WAKE-1 clause coverage (see M8C-BUILD-JOURNAL Entry 5):
 * - C2: notification frames are FORWARDED to a registered handler, not dropped.
 * - Falsify (a): the notification branch runs BEFORE response correlation and never touches
 *   #pending — a concurrent in-flight proxy.call still resolves while notifications interleave.
 * - Falsify (b): a notification is not mistaken for a response (no pending consumed).
 *
 * These are the daemon→shim leg. The shim→MCP-client leg (claude/channel capability + the
 * server.server.notification bridge over real stdio) is proven in the daemon-side integration
 * test, and the in-context hop in a live --channels session (LIVE-1).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, type Server } from "node:net";

describe("M8C-WAKE-001: IpcProxy forwards daemon notification frames", () => {
  let tempDir: string;
  let server: Server | null;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-wake001-"));
    server = null;
  });

  afterEach(async () => {
    if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
    await rm(tempDir, { recursive: true, force: true });
  });

  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

  it("C2: a { notification, data } frame is delivered to the registered onNotification handler", async () => {
    const { IpcProxy } = await import("../ipc-proxy.js");
    const socketPath = join(tempDir, "test.sock");

    const frame = {
      notification: "session_state_changed",
      data: {
        agent: "alice",
        type: "session_state_changed",
        agentName: "alice",
        sessionId: "sess-001",
        state: "created",
        counterpartyPubkey: "deadbeef",
      },
    };

    server = createServer((socket) => {
      // Push an unsolicited notification frame the instant the proxy connects.
      socket.write(JSON.stringify(frame) + "\n");
    });
    await new Promise<void>((resolve) => server!.listen(socketPath, resolve));

    const proxy = new IpcProxy(socketPath);
    const received: Array<Record<string, unknown>> = [];
    proxy.onNotification((f) => received.push(f));
    await proxy.connect();

    await sleep(100);
    proxy.close();

    expect(received).toHaveLength(1);
    expect(received[0]).toEqual(frame);
  });

  it("does NOT consume a pending request: a concurrent proxy.call still resolves while a notification interleaves", async () => {
    const { IpcProxy } = await import("../ipc-proxy.js");
    const socketPath = join(tempDir, "test.sock");

    server = createServer((socket) => {
      socket.on("data", (chunk: Buffer) => {
        const line = chunk.toString("utf-8").trim();
        if (!line) return;
        const req = JSON.parse(line) as { id: string; method: string };
        // Interleave: a server-initiated notification BEFORE the correlated response.
        socket.write(JSON.stringify({ notification: "agent_state_changed", data: { agent: "alice", type: "agent_state_changed", agentName: "alice", state: "online", reason: "started" } }) + "\n");
        socket.write(JSON.stringify({ id: req.id, result: { ok: true, echoed: req.method } }) + "\n");
      });
    });
    await new Promise<void>((resolve) => server!.listen(socketPath, resolve));

    const proxy = new IpcProxy(socketPath);
    const received: Array<Record<string, unknown>> = [];
    proxy.onNotification((f) => received.push(f));
    await proxy.connect();

    const result = (await proxy.call("cello_status", {})) as { ok: boolean; echoed: string };
    await sleep(50);
    proxy.close();

    // The response resolved correctly despite the interleaved notification…
    expect(result).toEqual({ ok: true, echoed: "cello_status" });
    // …and the notification was forwarded, not swallowed as a response.
    expect(received).toHaveLength(1);
    expect(received[0].notification).toBe("agent_state_changed");
  });

  it("INV-CONTENTFREE: forwarded frame carries no message content field", async () => {
    const { IpcProxy } = await import("../ipc-proxy.js");
    const socketPath = join(tempDir, "test.sock");

    const frame = {
      notification: "session_state_changed",
      data: { agent: "alice", type: "session_state_changed", agentName: "alice", sessionId: "s1", state: "created", counterpartyPubkey: "beef" },
    };
    server = createServer((socket) => { socket.write(JSON.stringify(frame) + "\n"); });
    await new Promise<void>((resolve) => server!.listen(socketPath, resolve));

    const proxy = new IpcProxy(socketPath);
    const received: Array<Record<string, unknown>> = [];
    proxy.onNotification((f) => received.push(f));
    await proxy.connect();
    await sleep(100);
    proxy.close();

    const data = received[0].data as Record<string, unknown>;
    expect(data).not.toHaveProperty("content");
    expect(data).not.toHaveProperty("message");
    expect(data).not.toHaveProperty("text");
    expect(data).not.toHaveProperty("plaintext");
  });
});
