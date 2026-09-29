/**
 * The CELLO MCP tools over Streamable HTTP, in front of the operator's OWN local daemon.
 *
 * An adapter, not a node: it holds a socket path and a bearer token, nothing else. Every MCP session
 * gets its own `McpServer` and its own `IpcProxy` because the daemon keeps the current agent per
 * connection. Two allowlists bound what a caller reaches — which tools are declared on the server
 * (an excluded tool does not exist on it) and which agents a tool argument may name (checked here,
 * before the daemon is called). The allowlists constrain THIS endpoint; any local process that can
 * open the daemon socket is unaffected.
 */

import { createServer as createHttp, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createServer as createHttps } from "node:https";
import { randomUUID, timingSafeEqual, createHash } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { IpcProxy } from "./ipc-proxy.js";
import { registerCelloTools } from "./cello-tools.js";
import { installDaemonGate } from "./daemon-gate.js";
import { forwardDaemonNotifications } from "./channel-forward.js";
import { logEvent, type LogFn } from "./shim-log.js";
import { McpHttpConfigError, isLoopbackHost } from "./http-config.js";
import { ToolsFileError, collectToolNames, filteringSink, resolveAllowedTools } from "./tool-allowlist.js";
import { AgentGuardError, guardProxy, makeNotificationPermit, resolvePermittedAgents } from "./agent-guard.js";

const MCP_PATH = "/mcp";
const MAX_BODY_BYTES = 5 * 1024 * 1024;

export interface McpHttpOptions {
  socketPath: string;
  host: string;
  port: number;
  token: string;
  version: string;
  /** Names or pubkeys. Undefined = serve every agent the daemon has. */
  agents?: string[];
  /** Contents of the tools file. Undefined = every tool except DEFAULT_DENIED_TOOLS. */
  toolsFileText?: string;
  tls?: { cert: string; key: string };
  maxSessions?: number;
  idleTimeoutMs?: number;
  log?: LogFn;
}

export interface McpHttpHandle {
  url: string;
  port: number;
  close(): Promise<void>;
}

interface Session {
  transport: StreamableHTTPServerTransport;
  server: McpServer;
  proxy: IpcProxy;
  idle: NodeJS.Timeout | undefined;
  closed: boolean;
}

const digest = (s: string) => createHash("sha256").update(s).digest();

function bearerOk(header: string | undefined, token: string): boolean {
  if (header === undefined || !header.startsWith("Bearer ")) return false;
  return timingSafeEqual(digest(header.slice("Bearer ".length)), digest(token));
}

function send(res: ServerResponse, status: number, body: Record<string, unknown>, headers: Record<string, string> = {}): void {
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(body));
}

async function readBody(req: IncomingMessage): Promise<string | "too_large"> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES) return "too_large";
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export async function startMcpHttpServer(opts: McpHttpOptions): Promise<McpHttpHandle> {
  const log: LogFn = opts.log ?? logEvent;
  const maxSessions = opts.maxSessions ?? 16;
  const idleTimeoutMs = opts.idleTimeoutMs ?? 900_000;

  if (opts.token === "") {
    throw new McpHttpConfigError("no_token", "no bearer token configured; pass --token-file or set CELLO_MCP_HTTP_TOKEN. An endpoint with no token would be open to anyone who can reach it.");
  }
  if (!isLoopbackHost(opts.host) && opts.tls === undefined) {
    throw new McpHttpConfigError("insecure_bind", `refusing to listen on ${opts.host} without TLS; pass --tls-cert/--tls-key, or bind to 127.0.0.1 and put your own TLS in front.`);
  }

  const allNames = collectToolNames();
  let allowed: Set<string>;
  try {
    allowed = resolveAllowedTools(allNames, opts.toolsFileText);
  } catch (e) {
    if (e instanceof ToolsFileError) {
      throw new McpHttpConfigError(e.reason === "empty_set" ? "tools_empty" : "unknown_tool", e.message);
    }
    throw e;
  }
  const excluded = new Set(allNames.filter((n) => !allowed.has(n)));

  let permitted: ReadonlySet<string> | "all" = "all";
  if (opts.agents !== undefined) {
    const probe = new IpcProxy(opts.socketPath, { clientType: "mcp" });
    try {
      await probe.connect();
      await probe.call("ipc.connect", { clientType: "mcp" });
      permitted = (await resolvePermittedAgents(probe, opts.agents)).permitted;
    } catch (e) {
      if (e instanceof AgentGuardError) throw new McpHttpConfigError(e.reason, e.message);
      throw new McpHttpConfigError("daemon_unreachable", `cannot reach the CELLO daemon at ${opts.socketPath} to check --agents: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      probe.close();
    }
  }

  const sessions = new Map<string, Session>();
  let starting = 0;

  const closeSession = (id: string | undefined, s: Session): void => {
    if (s.closed) return;
    s.closed = true;
    if (s.idle) clearTimeout(s.idle);
    if (id !== undefined) sessions.delete(id);
    s.proxy.close();
    s.server.close().catch((e: unknown) => log("mcp.http.session.close_failed", { sessionId: id, error: e instanceof Error ? e.message : String(e) }));
    log("mcp.http.session.closed", { sessionId: id });
  };

  const touch = (id: string, s: Session): void => {
    if (s.idle) clearTimeout(s.idle);
    s.idle = setTimeout(() => {
      log("mcp.http.session.idle_closed", { sessionId: id, idleTimeoutMs });
      void s.transport.close();
    }, idleTimeoutMs);
    s.idle.unref();
  };

  async function newSession(): Promise<Session> {
    const proxy = new IpcProxy(opts.socketPath, { clientType: "mcp" });
    try {
      return await buildSession(proxy);
    } catch (e) {
      proxy.close();
      throw e;
    }
  }

  async function buildSession(proxy: IpcProxy): Promise<Session> {
    await installDaemonGate(proxy, "cello-mcp-http");
    const guarded = guardProxy(proxy, permitted, log, () => proxy.currentAgent);
    const server = new McpServer(
      { name: "cello", version: opts.version },
      { capabilities: { experimental: { "claude/channel": {} } } },
    );
    registerCelloTools(filteringSink(server, allowed), guarded);
    const permit = permitted === "all" ? undefined : makeNotificationPermit(proxy, permitted, log);
    forwardDaemonNotifications(proxy, server, permit);

    let id: string | undefined;
    const session: Session = { transport: undefined as unknown as StreamableHTTPServerTransport, server, proxy, idle: undefined, closed: false };
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (sid) => {
        id = sid;
        sessions.set(sid, session);
        touch(sid, session);
        log("mcp.http.session.opened", { sessionId: sid, sessions: sessions.size });
      },
    });
    session.transport = transport;
    transport.onclose = () => closeSession(id, session);
    await server.connect(transport);

    const inner = transport.onmessage;
    transport.onmessage = (msg, extra) => {
      const m = msg as { id?: string | number; method?: string; params?: { name?: unknown } };
      if (m.method === "tools/call" && m.id !== undefined && typeof m.params?.name === "string" && excluded.has(m.params.name)) {
        log("mcp.http.tool.refused", { tool: m.params.name, sessionId: id });
        const refusal = {
          ok: false,
          reason: "tool_not_permitted",
          guidance: `${m.params.name} is not exposed by this endpoint; its operator excluded it at startup and it cannot be enabled from here. Use one of the tools listed by tools/list.`,
        };
        void transport.send(
          { jsonrpc: "2.0", id: m.id, result: { isError: true, content: [{ type: "text", text: JSON.stringify(refusal) }] } },
          { relatedRequestId: m.id },
        );
        return;
      }
      inner?.(msg, extra);
    };
    return session;
  }

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!bearerOk(req.headers["authorization"], opts.token)) {
      log("mcp.http.auth.refused", { method: req.method, remote: req.socket.remoteAddress });
      send(res, 401, { ok: false, reason: "unauthorized", guidance: "Send the endpoint's bearer token as `Authorization: Bearer <token>`." }, { "www-authenticate": "Bearer" });
      return;
    }
    if (new URL(req.url ?? "/", "http://x").pathname !== MCP_PATH) {
      send(res, 404, { ok: false, reason: "not_found", guidance: `The MCP endpoint is ${MCP_PATH}.` });
      return;
    }
    const sid = req.headers["mcp-session-id"];
    const sessionId = Array.isArray(sid) ? sid[0] : sid;

    if (req.method === "POST") {
      const raw = await readBody(req);
      if (raw === "too_large") {
        send(res, 413, { ok: false, reason: "body_too_large", guidance: `Request bodies are limited to ${MAX_BODY_BYTES} bytes.` });
        return;
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        send(res, 400, { ok: false, reason: "bad_json", guidance: "The request body is not valid JSON." });
        return;
      }
      if (sessionId !== undefined) {
        const s = sessions.get(sessionId);
        if (!s) {
          send(res, 404, { ok: false, reason: "unknown_session", guidance: "That MCP session has ended or never existed; send a new initialize request." });
          return;
        }
        touch(sessionId, s);
        await s.transport.handleRequest(req, res, parsed);
        return;
      }
      if (!isInitializeRequest(parsed)) {
        send(res, 400, { ok: false, reason: "no_session", guidance: "Start with an initialize request; later requests carry the Mcp-Session-Id it returns." });
        return;
      }
      if (sessions.size + starting >= maxSessions) {
        send(res, 503, { ok: false, reason: "too_many_sessions", guidance: `This endpoint allows ${maxSessions} concurrent sessions; close one or retry later.` });
        return;
      }
      starting++;
      try {
        const s = await newSession();
        await s.transport.handleRequest(req, res, parsed);
      } finally {
        starting--;
      }
      return;
    }

    if (req.method === "GET" || req.method === "DELETE") {
      const s = sessionId === undefined ? undefined : sessions.get(sessionId);
      if (!s || sessionId === undefined) {
        send(res, sessionId === undefined ? 400 : 404, { ok: false, reason: "no_session", guidance: "Send the Mcp-Session-Id returned by initialize." });
        return;
      }
      touch(sessionId, s);
      await s.transport.handleRequest(req, res);
      return;
    }
    send(res, 405, { ok: false, reason: "method_not_allowed", guidance: "Use POST, GET or DELETE." }, { allow: "POST, GET, DELETE" });
  }

  const listener = (req: IncomingMessage, res: ServerResponse): void => {
    handle(req, res).catch((err: unknown) => {
      log("mcp.http.request.failed", { error: err instanceof Error ? err.message : String(err) });
      if (!res.headersSent) send(res, 500, { ok: false, reason: "internal_error", guidance: "The endpoint failed handling this request; see its log." });
      else res.end();
    });
  };
  const httpServer: Server = opts.tls ? createHttps({ cert: opts.tls.cert, key: opts.tls.key }, listener) : createHttp(listener);

  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(opts.port, opts.host, () => resolve());
  });
  const addr = httpServer.address();
  const port = typeof addr === "object" && addr ? addr.port : opts.port;
  const url = `${opts.tls ? "https" : "http"}://${opts.host.includes(":") ? `[${opts.host}]` : opts.host}:${port}${MCP_PATH}`;
  log("mcp.http.listening", {
    url,
    tls: opts.tls !== undefined,
    agents: permitted === "all" ? "all" : permitted.size,
    toolsAllowed: allowed.size,
    toolsExcluded: excluded.size,
  });

  return {
    url,
    port,
    async close() {
      for (const [id, s] of [...sessions]) closeSession(id, s);
      httpServer.closeAllConnections();
      await new Promise<void>((r) => httpServer.close(() => r()));
    },
  };
}
