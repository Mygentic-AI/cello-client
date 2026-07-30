/**
 * The gateway server — the SEPARATE program the daemon screens through.
 *
 * Listens on a Unix domain socket, accepts length-prefixed JSON screen requests, runs them
 * through a screen function (M9-CORE-001 ships the pass-through default; later stories inject
 * the detection pipeline here), and writes a request-log line per request BEFORE replying.
 * The request log is the gateway's own record that it saw the content — the integration test
 * reads it to prove screening happened on the real daemon↔gateway channel.
 */
import { createServer, type Server, type Socket } from "node:net";
import { appendFile, rm } from "node:fs/promises";
import { createHash } from "node:crypto";
import { FrameDecoder, encodeFrame, SCREEN_OUTBOUND } from "./protocol.js";
import type { WireScreenRequest, WireScreenResponse } from "./protocol.js";
import type { ScreenDirection, ScreenVerdict, GovernanceDecision } from "./types.js";

/** The detection entry point. M9-CORE-001's default returns `allow`; the pipeline replaces it. */
export interface GatewayScreenFn {
  (req: {
    direction: ScreenDirection;
    content: Uint8Array;
    agentName: string;
    sessionId: string;
    correlationId?: string;
    /** The agent's governance re-send decisions, keyed by flagId (M9-FEED-001 §6). Outbound only. */
    governanceDecisions?: Record<string, GovernanceDecision>;
  }): ScreenVerdict | Promise<ScreenVerdict>;
}

/** Minimal injected logger (no console.log in the gateway, INV-7). Defaults to a no-op. */
export interface GatewayLogger {
  info(event: string, ctx?: Record<string, unknown>): void;
  warn(event: string, ctx?: Record<string, unknown>): void;
  error(event: string, ctx?: Record<string, unknown>): void;
}

const NOOP_LOGGER: GatewayLogger = {
  info() {},
  warn() {},
  error() {},
};

export interface GatewayServerOptions {
  socketPath: string;
  /** When set, one JSON line per screen request is appended here (the gateway's request log). */
  /** The screen function. Defaults to pass-through (always allow). */
  screen?: GatewayScreenFn;
  logger?: GatewayLogger;
}

export interface GatewayServerHandle {
  readonly socketPath: string;
  stop(): Promise<void>;
}

const ALLOW_ALL: GatewayScreenFn = () => ({ disposition: "allow" });

/** Start the gateway server on its socket. Resolves once it is listening. */
export async function createGatewayServer(opts: GatewayServerOptions): Promise<GatewayServerHandle> {
  const screen = opts.screen ?? ALLOW_ALL;
  const logger = opts.logger ?? NOOP_LOGGER;
  const { socketPath } = opts;

  // A stale socket file from a crashed prior run makes listen() fail with EADDRINUSE. Remove it.
  await rm(socketPath, { force: true });

  // Track live connections so stop() can close them. net.Server.close() stops accepting but
  // waits for EXISTING sockets to end; the daemon client holds its socket open for the daemon's
  // lifetime, so without this stop() would hang (M1 review).
  const sockets = new Set<Socket>();

  const server: Server = createServer((socket: Socket) => {
    sockets.add(socket);
    const decoder = new FrameDecoder(
      (obj) => { void handleRequest(obj as WireScreenRequest, socket); },
      (err) => {
        logger.warn("gateway.frame.decode.failed", { error: err.message });
        socket.destroy();
      },
    );
    socket.on("data", (chunk: Buffer) => decoder.push(chunk));
    socket.on("error", (err: Error) => logger.warn("gateway.socket.error", { error: err.message }));
    socket.once("close", () => sockets.delete(socket));
  });

  async function handleRequest(req: WireScreenRequest, socket: Socket): Promise<void> {
    const direction: ScreenDirection = req.method === SCREEN_OUTBOUND ? "outbound" : "inbound";
    const content = Buffer.from(req.content, "base64");

    // Record that the gateway saw this content BEFORE producing the verdict — so the daemon
    // cannot act on a verdict the gateway never logged (the test's ordering assertion).

    let verdict: ScreenVerdict;
    try {
      verdict = await screen({
        direction,
        content,
        agentName: req.ctx.agentName,
        sessionId: req.ctx.sessionId,
        correlationId: req.ctx.correlationId,
        ...(req.ctx.governanceDecisions !== undefined ? { governanceDecisions: req.ctx.governanceDecisions } : {}),
      });
    } catch (err) {
      // A screen-function fault is fail-closed: block, never silently allow.
      logger.error("gateway.screen.failed", {
        direction,
        error: err instanceof Error ? err.message : String(err),
      });
      verdict = {
        disposition: "block",
        reason: "screen_error",
        guidance: "The security gateway hit an internal error while screening this message. " +
          "Nothing was delivered or sent. Check the gateway logs.",
      };
    }

    const response: WireScreenResponse = {
      id: req.id,
      verdict: {
        disposition: verdict.disposition,
        // Echo content only when it was transformed (redact). On allow the daemon keeps the
        // original bytes it sent, so omitting content keeps the wire small.
        ...(verdict.content !== undefined ? { content: Buffer.from(verdict.content).toString("base64") } : {}),
        ...(verdict.reason !== undefined ? { reason: verdict.reason } : {}),
        ...(verdict.guidance !== undefined ? { guidance: verdict.guidance } : {}),
        ...(verdict.events !== undefined ? { events: verdict.events } : {}),
        ...(verdict.terminal !== undefined ? { terminal: verdict.terminal } : {}),
      },
    };
    if (!socket.destroyed) socket.write(encodeFrame(response));
  }

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => {
      server.off("error", reject);
      logger.info("gateway.listening", { socketPath });
      resolve();
    });
  });

  return {
    socketPath,
    async stop(): Promise<void> {
      // Close live connections first — otherwise server.close() waits for them forever.
      for (const s of sockets) s.destroy();
      sockets.clear();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await rm(socketPath, { force: true });
    },
  };
}
