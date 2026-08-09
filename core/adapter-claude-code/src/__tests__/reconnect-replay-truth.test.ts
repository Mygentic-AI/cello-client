/**
 * The shim must not announce an agent the daemon refused to give it back.
 *
 * OBSERVED LIVE, 2026-08-01, on Andre's own daemon. A session was told by the reconnect doorbell
 * *"the local daemon is back and you are acting as Miss_Chelly"*, and moments later:
 *
 *   cello_stop_using_agent → { ok: true, released: null,
 *                              guidance: "This connection was not attending any agent." }
 *   cello_agents           → Miss_Chelly { selected: false, attendance: 0 }
 *
 * Two surfaces, two answers, and the one the operator READ was the wrong one.
 *
 * ROOT CAUSE — not "the restart reset per-connection state" (the first hypothesis, which is a
 * description of the symptom). `#replayHandshake` calls `cello_use_agent` on reconnect and
 * **discards its result**. The `#currentAgent` cache is only ever cleared on an explicit
 * de-selection, so a REFUSED replay leaves the cache asserting an agent the daemon never attached.
 * `onReconnect` then builds its announcement from `proxy.currentAgent` — the cache, not the daemon —
 * so the claim is manufactured by the very component that failed to make it true.
 *
 * It fires exactly where it hurts: the replay is refused when the agent is not yet online at
 * reconnect time (a daemon that has just restarted is precisely that), and `cello_use_agent`
 * deliberately does NOT auto-start there.
 *
 * This is the same class as the two defects fixed earlier today — a MIRROR believed over the
 * SOURCE. The receptionist trusted a machine-wide file; `cello_inbox` trusted a dropped parameter;
 * this trusts a cache the daemon has contradicted.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, type Server, type Socket } from "node:net";
import { IpcProxy } from "../ipc-proxy.js";

/** A one-connection newline-delimited JSON IPC server whose replies the test dictates. */
function fakeDaemon(socketPath: string, reply: (method: string) => Record<string, unknown>): Promise<Server> {
  const live = new Set<Socket>();
  const server = createServer((sock: Socket) => {
    live.add(sock);
    sock.on("close", () => live.delete(sock));
    let buf = "";
    sock.on("data", (chunk: Buffer) => {
      buf += chunk.toString("utf8");
      let nl: number;
      while ((nl = buf.indexOf("\n")) !== -1) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (!line.trim()) continue;
        const req = JSON.parse(line) as { id?: string; method?: string };
        sock.write(JSON.stringify({ id: req.id, result: reply(req.method ?? "") }) + "\n");
      }
    });
    sock.on("error", () => { /* the test closes sockets abruptly on purpose */ });
  });
  // server.close() only stops ACCEPTING; an established socket survives it, so the proxy would
  // never see a drop and would never reconnect. Killing the live socket is what makes this a
  // daemon restart rather than a daemon that merely stopped listening.
  (server as Server & { destroyLive?: () => void }).destroyLive = () => { for (const s of live) s.destroy(); };
  return new Promise((resolve) => server.listen(socketPath, () => resolve(server)));
}

/** As above, but records every request so a test can assert on what the shim actually sent. */
function recordingDaemon(
  socketPath: string,
  seen: Array<{ method: string; params?: Record<string, unknown> }>,
  reply: (method: string) => Record<string, unknown>,
): Promise<Server> {
  const live = new Set<Socket>();
  const server = createServer((sock: Socket) => {
    live.add(sock);
    sock.on("close", () => live.delete(sock));
    let buf = "";
    sock.on("data", (chunk: Buffer) => {
      buf += chunk.toString("utf8");
      let nl: number;
      while ((nl = buf.indexOf("\n")) !== -1) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (!line.trim()) continue;
        const req = JSON.parse(line) as { id?: string; method?: string; params?: Record<string, unknown> };
        seen.push({ method: req.method ?? "", params: req.params });
        sock.write(JSON.stringify({ id: req.id, result: reply(req.method ?? "") }) + "\n");
      }
    });
    sock.on("error", () => { /* the test closes sockets abruptly on purpose */ });
  });
  (server as Server & { destroyLive?: () => void }).destroyLive = () => { for (const s of live) s.destroy(); };
  return new Promise((resolve) => server.listen(socketPath, () => resolve(server)));
}

const closeServer = (s: Server | null): Promise<void> => {
  if (!s) return Promise.resolve();
  (s as Server & { destroyLive?: () => void }).destroyLive?.();
  return new Promise((r) => s.close(() => r()));
};

describe("reconnect replay: the shim reports the DAEMON's agent, never its own cache", () => {
  let dir: string;
  let socketPath: string;
  let server: Server | null = null;
  let proxy: IpcProxy | null = null;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "cello-reconnect-"));
    socketPath = join(dir, "daemon.sock");
    server = null;
    proxy = null;
  });

  afterEach(async () => {
    proxy?.close();
    await closeServer(server);
    await rm(dir, { recursive: true, force: true });
  });

  it("R1: a REFUSED replay clears the cached agent — the shim stops claiming it", async () => {
    // Phase 1: a healthy daemon. The shim selects an agent and caches it for replay.
    server = await fakeDaemon(socketPath, () => ({ ok: true }));
    proxy = new IpcProxy(socketPath, { clientType: "mcp" });
    await proxy.connect();
    await proxy.call("ipc.connect", { clientType: "mcp" });
    await proxy.call("cello_use_agent", { name: "Miss_Chelly" });
    expect(proxy.currentAgent, "the cache is what makes replay possible at all").toBe("Miss_Chelly");

    // Phase 2: the daemon restarts and REFUSES the replay — the live case, because a daemon that
    // has just come up may not have the agent online yet, and cello_use_agent does not auto-start
    // on the replay path.
    await closeServer(server);
    const reconnected = new Promise<void>((resolve) => proxy!.onReconnect(() => resolve()));
    server = await fakeDaemon(socketPath, (method) =>
      method === "cello_use_agent"
        ? { ok: false, reason: "agent_start_failed", guidance: "not online" }
        : { ok: true },
    );
    await reconnected;

    // THE FIX: the daemon said no, so the shim must not go on claiming the agent. Before this,
    // the cache survived the refusal and every surface built from it lied.
    expect(proxy.currentAgent, "a refused replay must not leave the agent cached").toBeNull();
  });

  // ─── DOD-AGENT-SELECTION-UNWARRANTED-1 — making the switch attributable ───
  //
  // A connection changed identity twice on 2026-08-08/09 and neither could be attributed from any
  // log. Reading the code narrows it: `cello_use_agent` is the ONLY writer of a connection's current
  // agent (agent-handlers.ts:487 — every other site writes null), so no daemon-side fallback can
  // bind a connection. What the daemon cannot see is WHO called it: an operator's explicit
  // selection and the shim's reconnect replay arrive on the same handler, byte-identical.
  //
  // And the refusal path is silent. R1 above is correct behaviour — a refused replay must drop the
  // cache — but it drops it without a word anywhere, which is exactly the "my selection vanished"
  // report. The daemon logs no name for a switch that did not happen, and the shim logs nothing at
  // all. These two tests close that.

  it("R4: the replay identifies ITSELF, so a switch can be attributed to it rather than to the operator", async () => {
    const seen: Array<{ method: string; params?: Record<string, unknown> }> = [];
    server = await recordingDaemon(socketPath, seen, () => ({ ok: true }));
    proxy = new IpcProxy(socketPath, { clientType: "mcp" });
    await proxy.connect();
    await proxy.call("ipc.connect", { clientType: "mcp" });
    await proxy.call("cello_use_agent", { name: "Miss_Chelly" });

    // An operator's own call must NOT claim to be a replay, or the field is worthless.
    const explicit = seen.find((r) => r.method === "cello_use_agent");
    expect(explicit?.params?.["trigger"]).toBeUndefined();

    seen.length = 0;
    await closeServer(server);
    const reconnected = new Promise<void>((resolve) => proxy!.onReconnect(() => resolve()));
    server = await recordingDaemon(socketPath, seen, () => ({ ok: true }));
    await reconnected;

    const replayed = seen.find((r) => r.method === "cello_use_agent");
    expect(replayed, "the replay must happen at all").toBeDefined();
    expect(replayed!.params?.["trigger"]).toBe("replay");
  });

  it("R5: a refused replay SAYS SO — dropping a selection silently is the reported defect", async () => {
    const written: string[] = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = ((chunk: string | Uint8Array) => { written.push(String(chunk)); return true; }) as typeof process.stderr.write;
    try {
      server = await fakeDaemon(socketPath, () => ({ ok: true }));
      proxy = new IpcProxy(socketPath, { clientType: "mcp" });
      await proxy.connect();
      await proxy.call("ipc.connect", { clientType: "mcp" });
      await proxy.call("cello_use_agent", { name: "Miss_Chelly" });

      await closeServer(server);
      const reconnected = new Promise<void>((resolve) => proxy!.onReconnect(() => resolve()));
      server = await fakeDaemon(socketPath, (method) =>
        method === "cello_use_agent"
          ? { ok: false, reason: "agent_start_failed", guidance: "not online" }
          : { ok: true },
      );
      await reconnected;

      const all = written.join("");
      // The operator has to be able to tell "my selection was dropped, and why" from "the tools are
      // just broken". Name the agent and the daemon's own reason.
      expect(all).toContain("Miss_Chelly");
      expect(all).toContain("agent_start_failed");
    } finally {
      process.stderr.write = origWrite;
    }
  });

  it("R2 (the control): a SUCCESSFUL replay keeps the agent — reconnect must not lose routing", async () => {
    // The whole point of the cache is that routing survives a restart. Clearing it unconditionally
    // would 'fix' R1 by breaking the feature, so this pins the half that must not move.
    server = await fakeDaemon(socketPath, () => ({ ok: true }));
    proxy = new IpcProxy(socketPath, { clientType: "mcp" });
    await proxy.connect();
    await proxy.call("ipc.connect", { clientType: "mcp" });
    await proxy.call("cello_use_agent", { name: "Miss_Chelly" });

    await closeServer(server);
    const reconnected = new Promise<void>((resolve) => proxy!.onReconnect(() => resolve()));
    server = await fakeDaemon(socketPath, () => ({ ok: true }));
    await reconnected;

    expect(proxy.currentAgent).toBe("Miss_Chelly");
  });

  it("R3: `agent_already_current` on replay is SUCCESS, not a refusal", async () => {
    // The daemon answers ok:false / agent_already_current when the connection already holds it.
    // Treating every non-ok as a refusal would clear a cache that is in fact correct — the
    // over-strict direction of this same fix.
    server = await fakeDaemon(socketPath, () => ({ ok: true }));
    proxy = new IpcProxy(socketPath, { clientType: "mcp" });
    await proxy.connect();
    await proxy.call("ipc.connect", { clientType: "mcp" });
    await proxy.call("cello_use_agent", { name: "Miss_Chelly" });

    await closeServer(server);
    const reconnected = new Promise<void>((resolve) => proxy!.onReconnect(() => resolve()));
    server = await fakeDaemon(socketPath, (method) =>
      method === "cello_use_agent"
        ? { ok: false, reason: "agent_already_current" }
        : { ok: true },
    );
    await reconnected;

    expect(proxy.currentAgent).toBe("Miss_Chelly");
  });
});
