/**
 * M15D 001-DAEMON — the IPC server's half of "no message lost" and "the CLI always gets in":
 * - a refused connection is TOLD (`ipc_full`), never silently dropped;
 * - the last slots are reserved for `clientType: "cli"`;
 * - a reply's after-write step runs only when the write succeeded, and a failed write is logged;
 * - a closing socket aborts its in-flight requests;
 * - the envelope's `caller` reaches the handler untouched (the daemon decides whether to honour it).
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createConnection, type Socket } from "node:net";
import { createIpcServer, deferUntilWritten, type IpcHandler, type IpcServer } from "../ipc-server.js";
import type { Logger } from "../types.js";

describe("M15D ipc-server: slots, delivery, cancellation", () => {
  let tempDir: string;
  let socketPath: string;
  let events: Array<{ level: string; event: string; ctx: Record<string, unknown> }>;
  let logger: Logger;
  let server: IpcServer | undefined;
  const sockets: Socket[] = [];

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-m15d-ipc-"));
    socketPath = join(tempDir, "d.sock");
    events = [];
    const push = (level: string) => (event: string, ctx?: Record<string, unknown>) => { events.push({ level, event, ctx: ctx ?? {} }); };
    logger = { debug: push("debug"), info: push("info"), warn: push("warn"), error: push("error") };
  });

  afterEach(async () => {
    for (const s of sockets.splice(0)) s.destroy();
    await server?.stop();
    server = undefined;
    await rm(tempDir, { recursive: true, force: true });
  });

  function open(): Promise<Socket> {
    return new Promise((resolve, reject) => {
      const s = createConnection(socketPath);
      s.on("connect", () => { sockets.push(s); resolve(s); });
      s.on("error", reject);
    });
  }

  /** Everything the server writes until it closes the socket or `ms` passes. */
  function linesUntilClose(s: Socket, ms = 500): Promise<{ lines: Array<Record<string, unknown>>; closed: boolean }> {
    return new Promise((resolve) => {
      let buf = "";
      const done = (closed: boolean) => resolve({ lines: buf.split("\n").filter(Boolean).map((l) => JSON.parse(l) as Record<string, unknown>), closed });
      s.on("data", (c: Buffer) => { buf += c.toString("utf-8"); });
      s.on("close", () => done(true));
      setTimeout(() => done(false), ms);
    });
  }

  function request(s: Socket, req: Record<string, unknown>): Promise<Record<string, unknown>> {
    return new Promise((resolve) => {
      let buf = "";
      const onData = (c: Buffer) => {
        buf += c.toString("utf-8");
        const i = buf.indexOf("\n");
        if (i !== -1) { s.off("data", onData); resolve(JSON.parse(buf.slice(0, i)) as Record<string, unknown>); }
      };
      s.on("data", onData);
      s.write(JSON.stringify(req) + "\n");
    });
  }

  async function start(handlers: Map<string, IpcHandler>, maxConnections = 3, reservedForCli = 1): Promise<void> {
    server = createIpcServer({ socketPath, maxConnections, reservedForCli, logger }, handlers);
    await server.start();
  }

  it("a connection beyond the cap is told ipc_full before it is closed", async () => {
    await start(new Map(), 1, 0);
    await open();
    const extra = await open();
    const { lines, closed } = await linesUntilClose(extra);
    expect(closed).toBe(true);
    expect(lines[0]).toMatchObject({ error: { code: "ipc_full" } });
    expect(String((lines[0]!.error as Record<string, unknown>).guidance)).toMatch(/cello status/);
    expect(events.some((e) => e.event === "daemon.ipc.connection.limit.reached")).toBe(true);
  });

  it("the reserved slot refuses a non-CLI hello with ipc_full and admits a CLI hello and a no-hello CLI call", async () => {
    const handlers = new Map<string, IpcHandler>([
      ["ipc.connect", async () => ({ ok: true })],
      ["cello_status", async () => ({ ok: true, status: "up" })],
    ]);
    await start(handlers, 3, 1);
    await open();
    await open();

    const mcp = await open();
    const mcpOut = linesUntilClose(mcp);
    mcp.write(JSON.stringify({ id: "1", method: "ipc.connect", params: { clientType: "mcp" } }) + "\n");
    const { lines, closed } = await mcpOut;
    expect(closed).toBe(true);
    expect(lines[0]).toMatchObject({ id: "1", error: { code: "ipc_full" } });

    const cli = await open();
    expect(await request(cli, { id: "2", method: "ipc.connect", params: { clientType: "cli" } })).toMatchObject({ id: "2", result: { ok: true } });
    cli.destroy();
    await new Promise((r) => setTimeout(r, 50));

    const bare = await open();
    expect(await request(bare, { id: "3", method: "cello_status" })).toMatchObject({ id: "3", result: { status: "up" } });
  });

  it("after-write runs only once the reply is written; a reply to a closed socket logs daemon.ipc.write.failed and skips it", async () => {
    let committed = 0;
    let release: () => void = () => {};
    const gate = new Promise<void>((r) => { release = r; });
    const handlers = new Map<string, IpcHandler>([
      ["now", async () => deferUntilWritten({ ok: true }, () => { committed += 1; })],
      ["later", async () => { await gate; return deferUntilWritten({ ok: true }, () => { committed += 100; }); }],
    ]);
    await start(handlers, 4, 0);

    const s = await open();
    expect(await request(s, { id: "a", method: "now" })).toEqual({ id: "a", result: { ok: true } });
    await new Promise((r) => setTimeout(r, 20));
    expect(committed).toBe(1);

    const gone = await open();
    gone.write(JSON.stringify({ id: "b", method: "later" }) + "\n");
    await new Promise((r) => setTimeout(r, 20));
    gone.destroy();
    await new Promise((r) => setTimeout(r, 50));
    release();
    await new Promise((r) => setTimeout(r, 50));
    expect(committed).toBe(1);
    expect(events.some((e) => e.event === "daemon.ipc.write.failed" && e.ctx.method === "later")).toBe(true);
  });

  it("closing a socket aborts the signal its in-flight requests were given", async () => {
    let aborted: number | null = null;
    const startedAt = Date.now();
    const handlers = new Map<string, IpcHandler>([
      ["wait", (_p, _c, meta) => new Promise((resolve) => {
        meta.signal.addEventListener("abort", () => { aborted = Date.now() - startedAt; resolve({ ok: false }); });
        setTimeout(() => resolve({ ok: true }), 5000);
      })],
    ]);
    await start(handlers, 4, 0);
    const s = await open();
    s.write(JSON.stringify({ id: "w", method: "wait" }) + "\n");
    await new Promise((r) => setTimeout(r, 20));
    s.destroy();
    await new Promise((r) => setTimeout(r, 100));
    expect(aborted).not.toBeNull();
    expect(aborted!).toBeLessThan(1000);
  });

  it("passes the envelope's caller to the handler verbatim, and undefined when absent", async () => {
    const seen: unknown[] = [];
    const handlers = new Map<string, IpcHandler>([["who", async (_p, _c, meta) => { seen.push(meta.caller); return { ok: true }; }]]);
    await start(handlers, 4, 0);
    const s = await open();
    await request(s, { id: "1", method: "who", caller: { id: "oauth:x", label: "ChatGPT" } });
    await request(s, { id: "2", method: "who" });
    expect(seen).toEqual([{ id: "oauth:x", label: "ChatGPT" }, undefined]);
  });
});
