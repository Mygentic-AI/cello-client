/**
 * 082-HTTPMCP — the Streamable HTTP endpoint, end to end in-process: a REAL `startMcpHttpServer`
 * listening on a real port, the SDK's own HTTP client as the remote caller, and a fake daemon on a
 * real Unix socket (newline-delimited JSON, the IpcProxy wire). Nothing is stubbed between the
 * client and the daemon socket.
 */
import { describe, it, expect, afterEach } from "vitest";
import { createServer, type Server, type Socket } from "node:net";
import { mkdtemp, rm, writeFile, chmod } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { startMcpHttpServer, type McpHttpHandle } from "../http-server.js";
import { DEFAULT_DENIED_TOOLS } from "../tool-allowlist.js";
import { readTokenFile } from "../http-config.js";

const TOKEN = "t".repeat(40);
const A = "aa".repeat(32);
const B = "bb".repeat(32);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function waitFor(cond: () => boolean, ms = 5000) {
  const end = Date.now() + ms;
  while (!cond() && Date.now() < end) await sleep(10);
}

interface Rec { method: string; params: Record<string, unknown> | undefined; conn: number }
interface Fake {
  path: string;
  calls: Rec[];
  closedConns: Set<number>;
  connCount: () => number;
  roster: Array<{ name: string; pubkey: string; state: string }>;
  close(): Promise<void>;
}

async function fakeDaemon(dir: string): Promise<Fake> {
  const path = join(dir, "daemon.sock");
  const calls: Rec[] = [];
  const closedConns = new Set<number>();
  const sockets: Socket[] = [];
  const fake: Fake = {
    path, calls, closedConns,
    connCount: () => sockets.length,
    roster: [
      { name: "alice", pubkey: A, state: "online" },
      { name: "bob", pubkey: B, state: "online" },
    ],
    close: async () => { for (const s of sockets) s.destroy(); await new Promise<void>((r) => server.close(() => r())); },
  };
  const server: Server = createServer((socket) => {
    const conn = sockets.push(socket);
    let buf = "";
    socket.on("data", (c: Buffer) => {
      buf += c.toString("utf-8");
      let i: number;
      while ((i = buf.indexOf("\n")) !== -1) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1);
        if (!line.trim()) continue;
        const req = JSON.parse(line) as { id: string; method: string; params?: Record<string, unknown> };
        calls.push({ method: req.method, params: req.params, conn });
        const result = req.method === "cello_list_agents" ? { agents: fake.roster } : { ok: true, method: req.method };
        socket.write(JSON.stringify({ id: req.id, result }) + "\n");
      }
    });
    socket.on("close", () => closedConns.add(conn));
    socket.on("error", () => {});
  });
  await new Promise<void>((r) => server.listen(path, () => r()));
  return fake;
}

let dir: string;
let fake: Fake;
let handle: McpHttpHandle | undefined;
const clients: Client[] = [];
const transports = new Map<Client, StreamableHTTPClientTransport>();
let events: Array<{ event: string; ctx: Record<string, unknown> }>;

async function boot(over: Partial<Parameters<typeof startMcpHttpServer>[0]> = {}) {
  events = [];
  handle = await startMcpHttpServer({
    socketPath: fake.path, host: "127.0.0.1", port: 0, token: TOKEN, version: "0.0.0-test",
    log: (event, ctx) => events.push({ event, ctx: ctx ?? {} }),
    ...over,
  });
  return handle;
}

async function connect(token = TOKEN): Promise<Client> {
  const c = new Client({ name: "test", version: "0" });
  const t = new StreamableHTTPClientTransport(new URL(handle!.url), { requestInit: { headers: { Authorization: `Bearer ${token}` } } });
  await c.connect(t);
  clients.push(c);
  transports.set(c, t);
  return c;
}

const text = (r: unknown) => JSON.parse(((r as { content: Array<{ text: string }> }).content[0]!).text) as Record<string, unknown>;

afterEach(async () => {
  for (const c of clients.splice(0)) await c.close().catch(() => {});
  await handle?.close().catch(() => {});
  handle = undefined;
  await fake?.close().catch(() => {});
  await rm(dir, { recursive: true, force: true });
});

async function setup() {
  dir = await mkdtemp(join(tmpdir(), "httpmcp-"));
  fake = await fakeDaemon(dir);
}

const FIXTURES = join(import.meta.dirname, "fixtures");
type Snap = Array<{ name: string; description: string; inputSchema: unknown }>;
const pre = (f: string): Snap => JSON.parse(readFileSync(join(FIXTURES, f), "utf8"));
const norm = (t: Snap) => t.map((x) => ({ name: x.name, description: x.description, inputSchema: x.inputSchema })).sort((a, b) => a.name.localeCompare(b.name));

describe("082 parity with the stdio shim", () => {
  it("default config lists exactly the pre-refactor stdio tools minus DEFAULT_DENIED_TOOLS, identical name/description/schema", async () => {
    await setup(); await boot();
    const c = await connect();
    const got = norm((await c.listTools()).tools as unknown as Snap);
    const stdio = norm(pre("stdio-tools-list.pre-082.json"));
    const removed = stdio.filter((t) => !got.some((g) => g.name === t.name)).map((t) => t.name).sort();
    expect(removed).toEqual([...DEFAULT_DENIED_TOOLS].sort());
    expect(got).toEqual(stdio.filter((t) => !DEFAULT_DENIED_TOOLS.includes(t.name)));
  });
});

describe("082 tools allowlist over the wire", () => {
  it("a tools file limits tools/list to exactly its names", async () => {
    await setup(); await boot({ toolsFileText: "cello_agents\ncello_inbox\n" });
    const c = await connect();
    expect((await c.listTools()).tools.map((t) => t.name).sort()).toEqual(["cello_agents", "cello_inbox"]);
  });

  it("calling an excluded tool by name is refused tool_not_permitted, logged, and never reaches the daemon", async () => {
    await setup(); await boot({ toolsFileText: "cello_agents\n" });
    const c = await connect();
    const out = text(await c.callTool({ name: "cello_send", arguments: { cello_session_id: "s", content: "x", signal: "over" } }));
    expect(out["ok"]).toBe(false);
    expect(out["reason"]).toBe("tool_not_permitted");
    expect(fake.calls.map((x) => x.method)).not.toContain("cello_send");
    const ev = events.find((e) => e.event === "mcp.http.tool.refused");
    expect(ev?.ctx["tool"]).toBe("cello_send");
  });

  it("an allowed tool proxies with the caller's parameters unchanged", async () => {
    await setup(); await boot({ toolsFileText: "cello_contacts\n" });
    const c = await connect();
    await c.callTool({ name: "cello_contacts", arguments: {} });
    const seen = fake.calls.find((x) => x.method === "cello_contact_list");
    expect(seen?.params).toEqual({});
  });

  it("an unknown tool in the file, or an empty result, fails startup", async () => {
    await setup();
    await expect(boot({ toolsFileText: "cello_nope\n" })).rejects.toMatchObject({ reason: "unknown_tool" });
    await expect(boot({ toolsFileText: "# none\n" })).rejects.toMatchObject({ reason: "tools_empty" });
  });
});

describe("082 agents allowlist over the wire", () => {
  it("startup: empty list, unknown agent fail loud; the unknown one is named with the existing agents", async () => {
    await setup();
    await expect(boot({ agents: [] })).rejects.toMatchObject({ reason: "agents_empty" });
    await expect(boot({ agents: ["alice", "zed"] })).rejects.toMatchObject({
      reason: "agent_unknown", message: expect.stringMatching(/zed[\s\S]*alice[\s\S]*bob/),
    });
  });

  it("with --agents alice: bob is refused everywhere and the daemon never sees a bob call", async () => {
    await setup(); await boot({ agents: ["alice"] });
    const c = await connect();
    const use = text(await c.callTool({ name: "cello_use_agent", arguments: { name: "bob" } }));
    expect(use["reason"]).toBe("agent_not_permitted");
    const con = text(await c.callTool({ name: "cello_contacts", arguments: { agent: "bob" } }));
    expect(con["reason"]).toBe("agent_not_permitted");
    expect(fake.calls.map((x) => x.method)).not.toContain("cello_use_agent");
    expect(fake.calls.map((x) => x.method)).not.toContain("cello_contact_list");

    const ok = text(await c.callTool({ name: "cello_use_agent", arguments: { name: "alice" } }));
    expect(ok["ok"]).toBe(true);
    expect(fake.calls.find((x) => x.method === "cello_use_agent")?.params).toEqual({ name: "alice" });

    const list = text(await c.callTool({ name: "cello_agents", arguments: {} })) as { agents: Array<{ name: string }> };
    expect(list.agents.map((a) => a.name)).toEqual(["alice"]);
    expect(events.some((e) => e.event === "mcp.http.agent.refused")).toBe(true);
  });

  it("default (no --agents) serves every agent, including one created after start", async () => {
    await setup(); await boot();
    const c = await connect();
    fake.roster.push({ name: "dave", pubkey: "dd".repeat(32), state: "online" });
    const list = text(await c.callTool({ name: "cello_agents", arguments: {} })) as { agents: Array<{ name: string }> };
    expect(list.agents.map((a) => a.name).sort()).toEqual(["alice", "bob", "dave"]);
    const use = text(await c.callTool({ name: "cello_use_agent", arguments: { name: "dave" } }));
    expect(use["ok"]).toBe(true);
  });

  it("with --agents given and the daemon unreachable, startup fails rather than starting open", async () => {
    await setup();
    await expect(boot({ agents: ["alice"], socketPath: join(dir, "absent.sock") })).rejects.toMatchObject({ reason: "daemon_unreachable" });
  });
});

describe("082 sessions", () => {
  it("each MCP session gets its own daemon connection, released on close", async () => {
    await setup(); await boot();
    const c1 = await connect(); const c2 = await connect();
    await c1.callTool({ name: "cello_use_agent", arguments: { name: "alice" } });
    await c2.callTool({ name: "cello_use_agent", arguments: { name: "bob" } });
    const uses = fake.calls.filter((x) => x.method === "cello_use_agent");
    expect(uses.length).toBe(2);
    expect(uses[0]!.conn).not.toBe(uses[1]!.conn);
    const c1Conn = uses[0]!.conn;
    await transports.get(c1)!.terminateSession();
    await waitFor(() => fake.closedConns.has(c1Conn));
    expect(fake.closedConns.has(c1Conn)).toBe(true);
    expect(fake.closedConns.has(uses[1]!.conn)).toBe(false);
  });

  it("idle sessions are closed and release their daemon connection", async () => {
    await setup(); await boot({ idleTimeoutMs: 150 });
    const c = await connect();
    await c.callTool({ name: "cello_agents", arguments: {} });
    const conn = fake.calls.find((x) => x.method === "cello_list_agents")!.conn;
    await waitFor(() => fake.closedConns.has(conn));
    expect(fake.closedConns.has(conn)).toBe(true);
  });

  it("over --max-sessions a new initialize is refused 503, not queued", async () => {
    await setup(); await boot({ maxSessions: 1 });
    await connect();
    const res = await fetch(handle!.url, {
      method: "POST",
      headers: { Authorization: `Bearer ${TOKEN}`, "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "x", version: "0" } } }),
    });
    expect(res.status).toBe(503);
  });
});

describe("082 hardening", () => {
  it("no token / wrong token → 401 before the body is parsed (garbage body still 401, not 400)", async () => {
    await setup(); await boot();
    for (const auth of [undefined, "Bearer nope", "Basic abc"]) {
      const res = await fetch(handle!.url, {
        method: "POST",
        headers: { ...(auth ? { Authorization: auth } : {}), "content-type": "application/json", accept: "application/json, text/event-stream" },
        body: "{not json",
      });
      expect(res.status, String(auth)).toBe(401);
    }
    expect(events.some((e) => e.event === "mcp.http.auth.refused")).toBe(true);
    expect(JSON.stringify(events)).not.toContain(TOKEN);
  });

  it("GET without a token is refused too", async () => {
    await setup(); await boot();
    const res = await fetch(handle!.url, { method: "GET", headers: { accept: "text/event-stream" } });
    expect(res.status).toBe(401);
  });

  it("refuses to start with no token, or non-loopback without TLS", async () => {
    await setup();
    await expect(boot({ token: "" })).rejects.toMatchObject({ reason: "no_token" });
    await expect(boot({ host: "0.0.0.0" })).rejects.toMatchObject({ reason: "insecure_bind" });
  });

  it("a legal 1 MB cello_send body is accepted at the edge and reaches the daemon whole", async () => {
    await setup(); await boot();
    const c = await connect();
    await c.callTool({ name: "cello_use_agent", arguments: { name: "alice" } });
    const big = "x".repeat(1_000_000);
    await c.callTool({ name: "cello_send", arguments: { cello_session_id: "s1", content: big, signal: "over" } });
    const sent = fake.calls.find((x) => x.method === "cello_send");
    expect(sent, "cello_send reached the daemon").toBeDefined();
    expect(String(sent!.params!["content"]).length).toBe(1_000_000 + " [[OVER]]".length);
    expect(sent!.params!["session_id"]).toBe("s1");
  });

  it("the token file must be private: group/world-readable is refused; a private one is read and trimmed", async () => {
    dir = await mkdtemp(join(tmpdir(), "httpmcp-tok-"));
    fake = { close: async () => {} } as Fake;
    const p = join(dir, "token");
    await writeFile(p, `  ${TOKEN}\n`);
    await chmod(p, 0o644);
    expect(() => readTokenFile(p)).toThrow(/permission|readable|0600/i);
    await chmod(p, 0o600);
    expect(readTokenFile(p)).toBe(TOKEN);
  });
});
