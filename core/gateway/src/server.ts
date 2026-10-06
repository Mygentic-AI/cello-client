/**
 * The gateway server — the SEPARATE program the daemon screens through.
 *
 * Listens on a Unix domain socket, accepts length-prefixed JSON screen requests, runs them
 * through a screen function (M9-CORE-001 ships the pass-through default; later stories inject
 * the detection pipeline here), and replies with the verdict.
 *
 * PROOF THAT SCREENING HAPPENED lives in the ENCRYPTED record store, not here. This server used to
 * append a plaintext request-log line per request, and the integration tests read that file; it was
 * deleted because it duplicated the record store's audit trail outside SQLCipher (M8C
 * `DOD-CRYPTO-AT-REST-1`). The tests now read the record store, which is the stronger assertion.
 * The write-before-reply ORDERING that mattered is preserved where the records are actually written
 * — `bin/cello-gateway.ts` calls `recordOutcome` synchronously before returning the verdict, so the
 * daemon cannot act on a verdict the gateway never recorded, and a record-write throw becomes a
 * fail-closed `screen_error` block.
 */
import { createServer, connect, type Server, type Socket } from "node:net";
import { rm, stat } from "node:fs/promises";
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
    /** M16 031: the known public keys (lowercase 64-hex) the daemon recognised. Outbound only. */
    knownPublicKeys?: string[];
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
  /** The screen function. Defaults to pass-through (always allow). */
  screen?: GatewayScreenFn;
  logger?: GatewayLogger;
}

export interface GatewayServerHandle {
  readonly socketPath: string;
  stop(): Promise<void>;
}

const ALLOW_ALL: GatewayScreenFn = () => ({ disposition: "allow" });

/**
 * 084-GATEWAYSOCK: another gateway is already listening on THIS path. Distinct from a spawn or store
 * fault so the caller can leave the live gateway strictly alone rather than tear it down.
 */
export class GatewaySocketInUseError extends Error {
  readonly socketPath: string;
  constructor(socketPath: string) {
    super(`another gateway is already listening on ${socketPath}`);
    this.name = "GatewaySocketInUseError";
    this.socketPath = socketPath;
  }
}

/** How long the start-up probe waits to learn whether a live gateway holds the socket. */
const SOCKET_PROBE_TIMEOUT_MS = 1000;

/**
 * Is a gateway LIVE on `socketPath` right now, or is the file stale?
 *
 * We connect rather than trust the file's existence — a crashed prior run leaves a socket file with
 * nothing behind it. Connect succeeds → a live peer holds it (do not touch). `ECONNREFUSED`/`ENOENT`
 * → nothing is listening, the file is stale (safe to remove). Any other error is NOT a verdict: we
 * refuse to guess and let the caller fail naming the real cause.
 */
async function probeExistingSocket(socketPath: string, timeoutMs: number): Promise<"live" | "stale"> {
  return new Promise<"live" | "stale">((resolve, reject) => {
    const socket = connect(socketPath);
    let settled = false;
    const finish = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.removeAllListeners();
      socket.destroy();
      fn();
    };
    const timer = setTimeout(
      () => finish(() => reject(new Error(`timed out after ${timeoutMs}ms probing whether a gateway is live on ${socketPath}`))),
      timeoutMs,
    );
    socket.once("connect", () => finish(() => resolve("live")));
    socket.once("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "ECONNREFUSED" || err.code === "ENOENT") finish(() => resolve("stale"));
      else finish(() => reject(err));
    });
  });
}

import { dirname } from "node:path";
import { getGatewayIpcEndpoint } from "./ipc-endpoint.js";

/** Start the gateway server on its socket. Resolves once it is listening. */
export async function createGatewayServer(opts: GatewayServerOptions): Promise<GatewayServerHandle> {
  const screen = opts.screen ?? ALLOW_ALL;
  const logger = opts.logger ?? NOOP_LOGGER;
  const rawPath = opts.socketPath;
  const socketPath = process.platform === "win32" && !rawPath.startsWith("\\\\.\\pipe\\")
    ? getGatewayIpcEndpoint(dirname(rawPath))
    : rawPath;

  // 084-GATEWAYSOCK: never delete a socket another gateway is LIVE on. A stale file from a crashed
  // prior run makes listen() fail with EADDRINUSE and must be removed; a live peer's socket must be
  // left alone — deleting it is exactly the race a losing daemon's gateway used to run.
  //
  // This probe→rm→listen sequence is NOT atomic, and it does not need to be: another gateway could
  // in principle bind between the probe and the listen() below. What actually guarantees only one
  // gateway starts per CELLO_DIR at a time is Part B — the daemon takes its singleton lock BEFORE it
  // spawns any gateway, so two gateways for one directory never reach this point concurrently. This
  // probe only handles the steady-state case: a gateway that is already up is left untouched.
  const existing = await probeExistingSocket(socketPath, SOCKET_PROBE_TIMEOUT_MS);
  if (existing === "live") {
    logger.info("security.gateway.socket.in_use", { socketPath });
    throw new GatewaySocketInUseError(socketPath);
  }
  if (process.platform !== "win32") {
    await rm(socketPath, { force: true });
  }

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

    // The record-before-reply ordering is NOT enforced here — this server only routes to `screen`.
    // It is enforced by the injected screen fn in `bin/cello-gateway.ts`, which records the outcome
    // synchronously before returning. Stated rather than deleted because the constraint is real and
    // load-bearing; the plaintext log that used to implement it here is gone, not the requirement.
    let verdict: ScreenVerdict;
    try {
      verdict = await screen({
        direction,
        content,
        agentName: req.ctx.agentName,
        sessionId: req.ctx.sessionId,
        correlationId: req.ctx.correlationId,
        ...(req.ctx.governanceDecisions !== undefined ? { governanceDecisions: req.ctx.governanceDecisions } : {}),
        ...(req.ctx.knownPublicKeys !== undefined ? { knownPublicKeys: req.ctx.knownPublicKeys } : {}),
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
        ...(verdict.scan !== undefined ? { scan: verdict.scan } : {}),
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

  // 084-GATEWAYSOCK: identify the socket WE just created (inode + device), so stop() deletes only
  // this one. If a successor gateway replaces the file at this path while we run, its inode differs
  // and we must not unlink it. Best-effort: if we cannot stat our own socket, stop() leaves the path.
  let ownSocketId: { ino: number; dev: number } | undefined;
  try {
    const st = await stat(socketPath);
    ownSocketId = { ino: st.ino, dev: st.dev };
  } catch {
    ownSocketId = undefined;
  }

  const socketStillOurs = async (): Promise<boolean> => {
    if (!ownSocketId) return false;
    try {
      const st = await stat(socketPath);
      return st.ino === ownSocketId.ino && st.dev === ownSocketId.dev;
    } catch {
      return false;
    }
  };

  return {
    socketPath,
    async stop(): Promise<void> {
      // Close live connections first — otherwise server.close() waits for them forever.
      for (const s of sockets) s.destroy();
      sockets.clear();

      if (process.platform === "win32") {
        await new Promise<void>((resolve) => server.close(() => resolve()));
        return;
      }

      // Decide ownership BEFORE closing.
      if (await socketStillOurs()) {
        await new Promise<void>((resolve) => server.close(() => resolve()));
        await rm(socketPath, { force: true });
        return;
      }

      // NOT OURS: a different inode holds this path — a successor gateway has taken it over. Do NOT
      // call server.close(): libuv would unlink the bound path and delete the SUCCESSOR's socket,
      // which is the 084 bug over again. Do NOT touch the file either. We simply drop our listener by
      // letting the process exit — stop() runs only on the daemon's way out — and the kernel then
      // closes our fd WITHOUT unlinking, leaving the successor's socket exactly as it is. Part B (the
      // daemon takes its singleton lock BEFORE spawning a gateway) makes this branch unreachable in
      // production: a losing daemon never binds here at all. It survives only as defence.
      logger.info("security.gateway.socket.not_ours", { socketPath });
    },
  };
}
