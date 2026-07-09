/**
 * RECONNECT-001 — IpcProxy survives a daemon restart.
 *
 * The bug: a daemon restart closes the IPC socket, IpcProxy sets #dead, and EVERY subsequent
 * tool call returns `ipc_connection_lost` forever. The operator's cello_* tools silently
 * disappear with an error that names no remedy. Observed 5x in one day (2026-07-09), and it
 * orphans every connected agent simultaneously (Claude Code AND Hermes).
 *
 * Two things a naive "reopen the socket" fix gets wrong, both pinned below:
 *
 *  1. The daemon rebuilds per-connection state on restart. Reconnecting the socket alone leaves
 *     the connection with no registered clientType and no current agent — every tool then fails
 *     `no_current_agent` and notifications stop routing (the dispatcher keys on currentAgent).
 *     So the handshake (`ipc.connect`) AND the agent selection must be replayed.
 *
 *  2. In-flight requests must NEVER be replayed. `cello_send` is not idempotent; a silent retry
 *     double-sends a message. They must resolve as failures, and the caller retries explicitly.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, type Server, type Socket } from "node:net";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

interface FakeDaemon {
  server: Server;
  sockets: Socket[];
}

/** A fake daemon that records every method it receives and answers with `{ id, result }`. */
function fakeDaemon(
  socketPath: string,
  received: string[],
  opts: { answer?: boolean; onConnection?: (s: Socket) => void } = {},
): Promise<FakeDaemon> {
  const sockets: Socket[] = [];
  const server = createServer((socket) => {
    sockets.push(socket);
    opts.onConnection?.(socket);
    let buf = "";
    socket.on("data", (chunk: Buffer) => {
      buf += chunk.toString("utf-8");
      let idx: number;
      while ((idx = buf.indexOf("\n")) !== -1) {
        const line = buf.slice(0, idx);
        buf = buf.slice(idx + 1);
        if (!line.trim()) continue;
        const req = JSON.parse(line) as { id: string; method: string; params?: Record<string, unknown> };
        received.push(req.method);
        if (opts.answer === false) continue;
        const result =
          req.method === "cello_use_agent" ? { ok: true } : { ok: true, method: req.method };
        socket.write(JSON.stringify({ id: req.id, result }) + "\n");
      }
    });
    socket.on("error", () => {});
  });
  return new Promise((resolve) => server.listen(socketPath, () => resolve({ server, sockets })));
}

/**
 * Kill a daemon the way SIGTERM does. `server.close()` alone only stops NEW connections — the
 * established socket stays open, so the client never sees a close event. Existing sockets must be
 * destroyed for this to simulate a real daemon death.
 */
async function killDaemon(d: FakeDaemon, socketPath: string): Promise<void> {
  for (const s of d.sockets) s.destroy();
  await new Promise<void>((r) => d.server.close(() => r()));
  await rm(socketPath, { force: true });
}

describe("RECONNECT-001: IpcProxy auto-reconnects after a daemon restart", () => {
  let tempDir: string;
  let daemon: FakeDaemon | null;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-reconnect-"));
    daemon = null;
  });

  afterEach(async () => {
    if (daemon) {
      for (const s of daemon.sockets) s.destroy();
      await new Promise<void>((r) => daemon!.server.close(() => r()));
    }
    await rm(tempDir, { recursive: true, force: true });
  });

  it("recovers: a call succeeds after the daemon dies and comes back", async () => {
    const { IpcProxy } = await import("../ipc-proxy.js");
    const socketPath = join(tempDir, "d.sock");
    const received: string[] = [];

    daemon = await fakeDaemon(socketPath, received);
    const proxy = new IpcProxy(socketPath, { clientType: "mcp" });
    await proxy.connect();
    expect(await proxy.call("cello_status")).toMatchObject({ ok: true });

    await killDaemon(daemon, socketPath);
    daemon = await fakeDaemon(socketPath, received);

    // The very next tool call must succeed — no manual /mcp reconnect.
    expect(await proxy.call("cello_status")).toMatchObject({ ok: true });
    expect(proxy.isDead).toBe(false);
    proxy.close();
  }, 20_000);

  it("replays the handshake: the new connection receives ipc.connect again", async () => {
    const { IpcProxy } = await import("../ipc-proxy.js");
    const socketPath = join(tempDir, "d.sock");
    daemon = await fakeDaemon(socketPath, []);

    const proxy = new IpcProxy(socketPath, { clientType: "mcp" });
    await proxy.connect();
    await proxy.call("ipc.connect", { clientType: "mcp" });

    await killDaemon(daemon, socketPath);
    const second: string[] = [];
    daemon = await fakeDaemon(socketPath, second);
    await proxy.call("cello_status");

    // The daemon's fresh connection must be re-registered BEFORE the tool call lands.
    expect(second[0]).toBe("ipc.connect");
    proxy.close();
  }, 20_000);

  it("restores the current agent: cello_use_agent is replayed after reconnect", async () => {
    const { IpcProxy } = await import("../ipc-proxy.js");
    const socketPath = join(tempDir, "d.sock");
    daemon = await fakeDaemon(socketPath, []);

    const proxy = new IpcProxy(socketPath, { clientType: "mcp" });
    await proxy.connect();
    await proxy.call("ipc.connect", { clientType: "mcp" });
    await proxy.call("cello_use_agent", { name: "Ms_Chelly" });

    await killDaemon(daemon, socketPath);
    const second: string[] = [];
    daemon = await fakeDaemon(socketPath, second);
    await proxy.call("cello_status");

    // Without this, every tool returns no_current_agent and notifications never route.
    expect(second).toContain("cello_use_agent");
    expect(second.indexOf("ipc.connect")).toBeLessThan(second.indexOf("cello_use_agent"));
    expect(second.indexOf("cello_use_agent")).toBeLessThan(second.indexOf("cello_status"));
    proxy.close();
  }, 20_000);

  it("never replays an in-flight request (cello_send must not double-send)", async () => {
    const { IpcProxy } = await import("../ipc-proxy.js");
    const socketPath = join(tempDir, "d.sock");

    // A daemon that records cello_send but never answers it, then dies mid-flight.
    daemon = await fakeDaemon(socketPath, [], { answer: false });
    const proxy = new IpcProxy(socketPath, { clientType: "mcp" });
    await proxy.connect();

    const inflight = proxy.call("cello_send", { session_id: "s1", content: "hello" });
    await sleep(50);
    await killDaemon(daemon, socketPath);

    // The in-flight call resolves as a failure — it is NOT retried on the new connection.
    const result = (await inflight) as { ok: boolean; reason: string };
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("ipc_connection_lost");

    const second: string[] = [];
    daemon = await fakeDaemon(socketPath, second);
    await proxy.call("cello_status");
    expect(second).not.toContain("cello_send");
    proxy.close();
  }, 20_000);

  it("an explicit close() does NOT reconnect", async () => {
    const { IpcProxy } = await import("../ipc-proxy.js");
    const socketPath = join(tempDir, "d.sock");
    daemon = await fakeDaemon(socketPath, []);

    const proxy = new IpcProxy(socketPath, { clientType: "mcp" });
    await proxy.connect();
    proxy.close();
    await sleep(400);

    expect(proxy.isDead).toBe(true);
    const result = (await proxy.call("cello_status")) as { reason: string };
    expect(result.reason).toBe("ipc_connection_lost");
  }, 20_000);

  it("notifications resume after reconnect (the doorbell comes back)", async () => {
    const { IpcProxy } = await import("../ipc-proxy.js");
    const socketPath = join(tempDir, "d.sock");
    daemon = await fakeDaemon(socketPath, []);

    const proxy = new IpcProxy(socketPath, { clientType: "mcp" });
    await proxy.connect();

    const seen: string[] = [];
    proxy.onNotification((f) => seen.push(String(f["notification"])));

    await killDaemon(daemon, socketPath);

    // The new daemon answers the handshake AND pushes a doorbell on connect.
    daemon = await fakeDaemon(socketPath, [], {
      onConnection: (s) =>
        s.write(JSON.stringify({ notification: "cello_message", data: { from: "x" } }) + "\n"),
    });

    await proxy.call("cello_status"); // forces the reconnect to complete
    await sleep(100);
    expect(seen).toContain("cello_message");
    proxy.close();
  }, 20_000);

  it("the lost-connection guidance names the remedy", async () => {
    const { IpcProxy } = await import("../ipc-proxy.js");
    const proxy = new IpcProxy(join(tempDir, "nope.sock"), { clientType: "mcp" });
    proxy.close();
    const result = (await proxy.call("cello_status")) as { guidance: string };
    expect(result.guidance).toMatch(/reconnect|cello login|cello status/i);
  });

  it("a failed INITIAL connect rejects and starts no background reconnect loop", async () => {
    const { IpcProxy } = await import("../ipc-proxy.js");
    const socketPath = join(tempDir, "absent.sock");
    const proxy = new IpcProxy(socketPath, { clientType: "mcp" });

    await expect(proxy.connect()).rejects.toThrow();

    // If a loop had started, it would connect to a daemon that appears later. It must not.
    const received: string[] = [];
    daemon = await fakeDaemon(socketPath, received);
    await sleep(800);
    expect(received).toEqual([]);
    proxy.close();
  }, 20_000);
});
