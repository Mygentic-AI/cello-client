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

/**
 * Wait for a condition, up to `timeoutMs`.
 *
 * Replaces `await sleep(100)` before an assertion. A fixed sleep encodes a GUESS about how long the
 * machine takes, so it is simultaneously too slow locally and too fast on a loaded CI runner — where
 * "notifications resume after reconnect" failed with an EMPTY list on 2026-07-31 while passing on
 * every developer machine. This waits for the thing itself and still fails, bounded, if it never
 * happens: the assertion keeps all its teeth, only the arbitrary timing goes.
 */
async function waitFor(cond: () => boolean, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond() && Date.now() < deadline) await sleep(10);
}

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

  // ─── DOD-RELEASE-1: the replay must not resurrect a de-selection ───
  //
  // The cache above had a SET path and no CLEAR path, so every de-selection verb was silently undone
  // by the next reconnect. These are the two ways that hurt, and neither was covered.

  it("a released agent is NOT re-attended on reconnect", async () => {
    // Release to go away → socket drops → the shim replays cello_use_agent → isAttended() is true
    // again → the away message stops firing, with nothing in any log saying so. The exact bug
    // cello_stop_using_agent exists to fix, resurrected on a timer.
    const { IpcProxy } = await import("../ipc-proxy.js");
    const socketPath = join(tempDir, "d.sock");
    daemon = await fakeDaemon(socketPath, []);

    const proxy = new IpcProxy(socketPath, { clientType: "mcp" });
    await proxy.connect();
    await proxy.call("ipc.connect", { clientType: "mcp" });
    await proxy.call("cello_use_agent", { name: "Ms_Chelly" });
    await proxy.call("cello_stop_using_agent", {});

    await killDaemon(daemon, socketPath);
    const second: string[] = [];
    daemon = await fakeDaemon(socketPath, second);
    await proxy.call("cello_status");

    expect(second).not.toContain("cello_use_agent");
    expect(second).toContain("ipc.connect");
    proxy.close();
  }, 20_000);

  it("an agent taken OFFLINE is not silently auto-started by the reconnect replay", async () => {
    // cello_use_agent AUTO-STARTS an offline agent, so replaying it after a deliberate
    // set-agent-offline brings the agent back online and reachable with no signal — kill-switch
    // adjacent, and it contradicted parity-commands.ts's own claim that the MCP surface never does
    // this. (Pre-existing; found by the same review as the release case and fixed with it.)
    const { IpcProxy } = await import("../ipc-proxy.js");
    const socketPath = join(tempDir, "d.sock");
    daemon = await fakeDaemon(socketPath, []);

    const proxy = new IpcProxy(socketPath, { clientType: "mcp" });
    await proxy.connect();
    await proxy.call("ipc.connect", { clientType: "mcp" });
    await proxy.call("cello_use_agent", { name: "Ms_Chelly" });
    await proxy.call("cello_set_agent_offline", { name: "Ms_Chelly" });

    await killDaemon(daemon, socketPath);
    const second: string[] = [];
    daemon = await fakeDaemon(socketPath, second);
    await proxy.call("cello_status");

    expect(second).not.toContain("cello_use_agent");
    proxy.close();
  }, 20_000);

  it("taking a DIFFERENT agent offline leaves the current selection replayed", async () => {
    // The clear is conditional on the name matching. Without that guard, taking any unrelated agent
    // offline would drop routing for the agent this connection is actually driving.
    const { IpcProxy } = await import("../ipc-proxy.js");
    const socketPath = join(tempDir, "d.sock");
    daemon = await fakeDaemon(socketPath, []);

    const proxy = new IpcProxy(socketPath, { clientType: "mcp" });
    await proxy.connect();
    await proxy.call("ipc.connect", { clientType: "mcp" });
    await proxy.call("cello_use_agent", { name: "Ms_Chelly" });
    await proxy.call("cello_set_agent_offline", { name: "SomeoneElse" });

    await killDaemon(daemon, socketPath);
    const second: string[] = [];
    daemon = await fakeDaemon(socketPath, second);
    await proxy.call("cello_status");

    expect(second).toContain("cello_use_agent");
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
    await waitFor(() => seen.length > 0);
    expect(seen).toContain("cello_message");
    proxy.close();
  }, 20_000);

  // The daemon coming BACK had no announcement: `shutdown` is pushed by the dying daemon, and a
  // fresh one cannot push anything because it has never heard of this client. So the operator's
  // agent kept a ⚠️ "daemon stopped" notice with nothing to retract it. Only the shim knows both
  // halves — hence a reconnect hook rather than a daemon notification.
  it("fires onReconnect AFTER the replay — and never on the first connect", async () => {
    const { IpcProxy } = await import("../ipc-proxy.js");
    const socketPath = join(tempDir, "d.sock");
    daemon = await fakeDaemon(socketPath, []);

    const proxy = new IpcProxy(socketPath, { clientType: "mcp" });
    const agentAtFire: Array<string | null> = [];
    proxy.onReconnect(() => agentAtFire.push(proxy.currentAgent));

    await proxy.connect();
    await proxy.call("cello_use_agent", { name: "alice" });
    expect(agentAtFire, "the first connect is not a RE-connect — the caller already knows").toEqual([]);

    await killDaemon(daemon, socketPath);
    daemon = await fakeDaemon(socketPath, []);
    await proxy.call("cello_status"); // forces the reconnect to complete
    await waitFor(() => agentAtFire.length > 0);

    expect(agentAtFire.length, "a reconnect must announce exactly once").toBe(1);
    // Fired after the handshake replay, so the announcement is true when it arrives rather than
    // naming an agent that is still being restored.
    expect(agentAtFire[0]).toBe("alice");
    proxy.close();
  }, 20_000);

  it("a throwing onReconnect handler does not break the reconnect", async () => {
    const { IpcProxy } = await import("../ipc-proxy.js");
    const socketPath = join(tempDir, "d.sock");
    daemon = await fakeDaemon(socketPath, []);

    const proxy = new IpcProxy(socketPath, { clientType: "mcp" });
    await proxy.connect();
    proxy.onReconnect(() => { throw new Error("announcement blew up"); });

    await killDaemon(daemon, socketPath);
    daemon = await fakeDaemon(socketPath, []);

    // The connection is already good by the time the handler runs; losing it over a failed
    // announcement would be strictly worse than a missing doorbell.
    const result = await proxy.call("cello_status");
    expect(result).toBeDefined();
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
