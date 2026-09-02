/**
 * IPC server for the CELLO daemon.
 *
 * Pseudocode:
 * 1. createIpcServer(config, handlers):
 *    a. Create net.Server bound to Unix domain socket
 *    b. Set socket permissions to 0o600 (SI-001: owner-only access)
 *    c. On connection:
 *       - Check connectionCount < maxConnections (16)
 *       - If limit reached, send error frame and close
 *       - Otherwise, increment counter, assign connectionId
 *       - Log daemon.ipc.connected
 *       - Set up newline-delimited JSON parser on the socket
 *       - For each parsed request, dispatch to handler map
 *       - On close, decrement counter, log daemon.ipc.disconnected
 *    d. Return server handle with start() and stop() methods
 *
 * 2. IPC framing: JSON-newline-delimited
 *    - Each message is a single JSON object followed by \n
 *    - Requests: {id: string, method: string, params?: object}
 *    - Responses: {id: string, result: any} or {id: string, error: {code, message, guidance}}
 *
 * 3. Graceful shutdown:
 *    a. Stop accepting new connections
 *    b. Wait for in-flight requests to complete (with timeout)
 *    c. Send shutdown frame to all connected clients
 *    d. Close all connections
 *    e. Unlink socket file
 */

import { createServer, type Server, type Socket } from "node:net";
import { chmod, stat, unlink } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import type { Logger, IpcRequest, IpcResponse, IpcNotification } from "./types.js";
import { extractErrorMessage } from "./error-message.js";

/** Everything the server needs of a handler map: resolve a method name when a request arrives. */
export interface HandlerLookup {
  get(method: string): IpcHandler | undefined;
}

export type IpcHandler = (params: Record<string, unknown> | undefined, connectionId: string) => Promise<unknown>;

export interface IpcServerConfig {
  socketPath: string;
  maxConnections: number;
  logger: Logger;
}

/**
 * Returns context to MERGE into the single `daemon.ipc.disconnected` line — see the close handler.
 * Returning nothing is fine; a second log line from the handler is not (review F8).
 */
export type IpcDisconnectHandler = (connectionId: string) => Record<string, unknown> | void;

export interface IpcServer {
  start(): Promise<void>;
  stop(): Promise<void>;
  getConnectionCount(): number;
  onDisconnect(handler: IpcDisconnectHandler): void;
  /** Write a notification to a specific connection. Returns false on write failure. */
  sendNotification(connectionId: string, notification: IpcNotification): boolean;
  /** Return all active connection IDs. */
  getConnectionIds(): string[];
}

interface ActiveConnection {
  id: string;
  socket: Socket;
  inFlightCount: number;
  shutdownReason: string | null;
}

export function createIpcServer(
  config: IpcServerConfig,
  /**
   * Looked up per request, never enumerated. Typed as the lookup alone so the daemon can pass a
   * LATE-BINDING view over its handler map rather than a snapshot — a snapshot made registration
   * order load-bearing, and anything registered after the copy answered `method_not_found`.
   */
  handlers: HandlerLookup,
): IpcServer {
  const { socketPath, maxConnections, logger } = config;
  let server: Server | null = null;
  const connections = new Map<string, ActiveConnection>();
  let stopping = false;

  // DOD-DAEMON-CLEANUP-1 (AC2): the identity — not the path — of the socket THIS server created.
  // dev+ino is the only thing that survives another daemon rebinding the same path.
  let createdSocket: { dev: number; ino: number } | null = null;

  /**
   * What is sitting at socketPath right now?
   *   "ours"    — the socket this server created; we may remove it.
   *   "gone"    — nothing there; nothing to do.
   *   "foreign" — a DIFFERENT socket. Another daemon rebound the path. Hands off.
   *
   * The distinction is by inode, not by path. A path tells you a file exists; only the inode tells
   * you it is the same file you made.
   */
  async function socketOwnership(): Promise<"ours" | "gone" | "foreign"> {
    let current: { dev: number; ino: number };
    try {
      current = await stat(socketPath);
    } catch {
      // Nothing at the path (ENOENT is the only realistic case) — there is nothing to own.
      return "gone";
    }
    if (createdSocket === null) {
      // Unreachable: stop() returns early unless the server is listening, and a listening server has
      // been through start(), which sets this or throws. Say so rather than inventing an answer —
      // guessing here is what the whole unit is about.
      throw new Error("ipc server: socket identity unknown — stop() ran without a completed start()");
    }
    return current.dev === createdSocket.dev && current.ino === createdSocket.ino ? "ours" : "foreign";
  }
  let disconnectHandler: IpcDisconnectHandler | null = null;

  function handleConnection(socket: Socket): void {
    if (stopping) {
      socket.destroy();
      return;
    }

    if (connections.size >= maxConnections) {
      logger.warn("daemon.ipc.connection.limit.reached", {
        currentCount: connections.size,
        maxCount: maxConnections,
      });
      // Destroy immediately — the client has no pending requests to correlate
      // an error response against. Client's connectToDaemon() will reject with
      // a socket error, which is the correct signal.
      socket.destroy();
      return;
    }

    const connectionId = randomUUID();
    const conn: ActiveConnection = { id: connectionId, socket, inFlightCount: 0, shutdownReason: null };
    connections.set(connectionId, conn);

    logger.info("daemon.ipc.accepted", { connectionId });

    // CELLO-M7-MSG-001: the IPC buffer cap MUST exceed the application content cap
    // (MAX_CONTENT_BYTES = 1 MB) plus the JSON request envelope, or a max-size
    // cello_send message would trip this overflow and the connection would be killed
    // BEFORE cello_send's content_too_large check could run — turning a clean,
    // recoverable "content_too_large" into a fatal connection drop, and making even a
    // VALID 1 MB message unsendable. 4 MB matches the it-length-prefixed transport
    // default (IT_LENGTH_PREFIX_DEFAULT_MAX) so the IPC, app-cap, and transport layers
    // are coherent: content up to the 1 MB cap always traverses IPC, oversize content
    // reaches cello_send and is rejected with content_too_large, and only a payload
    // beyond the transport frame is a hard stop. Must stay in sync with the matching
    // constant in adapter-claude-code/src/ipc-proxy.ts.
    const MAX_BUFFER_SIZE = 4 * 1024 * 1024; // 4MB per connection (> 1MB content cap + envelope)
    let buffer = "";

    socket.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("utf-8");
      if (buffer.length > MAX_BUFFER_SIZE) {
        logger.warn("daemon.ipc.buffer.overflow", { connectionId, bufferSize: buffer.length });
        buffer = "";
        socket.removeAllListeners("data");
        socket.destroy();
        return;
      }
      let newlineIdx: number;
      while ((newlineIdx = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, newlineIdx);
        buffer = buffer.slice(newlineIdx + 1);
        if (line.trim().length === 0) continue;
        handleMessage(conn, line);
      }
    });

    socket.on("close", () => {
      connections.delete(connectionId);
      const reason = conn.shutdownReason || "client_closed";
      /**
       * ONE LINE, and the handler contributes to it — review F8.
       *
       * `DOD-M15-IPCVISIBLE-1` added a SECOND `daemon.ipc.disconnected` from the daemon's own
       * handler, carrying clientType and the attended agent. Two lines under one event name, with
       * disjoint fields and neither carrying the whole picture — and a naive count doubled, so a
       * shutdown with five clients emitted ten. For a unit whose entire subject is that the log is
       * readable, that is the wrong shape.
       *
       * The handler now RETURNS its context and it is merged here. `reason` lives on this side
       * because only the socket knows it.
       */
      const extra = disconnectHandler ? disconnectHandler(connectionId) : undefined;
      logger.info("daemon.ipc.disconnected", { connectionId, reason, ...(extra ?? {}) });
    });

    // Set shutdownReason so the 'close' handler (which always fires after 'error') logs it.
    // Do NOT call disconnectHandler or log here — 'close' fires immediately after 'error'.
    socket.on("error", (err: Error) => {
      conn.shutdownReason = err.message;
    });
  }

  function handleMessage(conn: ActiveConnection, line: string): void {
    let request: IpcRequest;
    try {
      request = JSON.parse(line) as IpcRequest;
    } catch {
      // Cannot recover the request ID from unparseable input.
      // Close the connection — client's pending promises will all reject
      // with "Connection closed", which correctly propagates the failure.
      logger.warn("daemon.ipc.parse.error", { connectionId: conn.id });
      conn.socket.destroy();
      return;
    }

    if (!request.id || !request.method) {
      // If id is missing/falsy, we can't correlate an error response.
      // Close the connection rather than sending an unmatchable frame.
      logger.warn("daemon.ipc.invalid.request", { connectionId: conn.id, hasId: !!request.id, hasMethod: !!request.method });
      conn.socket.destroy();
      return;
    }

    const handler = handlers.get(request.method);
    if (!handler) {
      const errorResp: IpcResponse = {
        id: request.id,
        error: {
          code: "method_not_found",
          message: `Unknown method: ${request.method}`,
          guidance: `Unknown IPC method '${request.method}'. Check that cello-mcp and the daemon are the same version. Run 'cello status' to verify the daemon is running.`,
        },
      };
      conn.socket.write(JSON.stringify(errorResp) + "\n");
      return;
    }

    conn.inFlightCount++;
    Promise.resolve(handler(request.params, conn.id))
      .then((result) => {
        try {
          // `DOD-M15-SELECTION-1`'s fallback notice used to be spread in HERE. It moved up into the
          // daemon's `renderedHandlers` wrapper: this point is downstream of `renderForSurface`, so
          // the notice's own guidance never got translated and a CLI operator was told to run
          // `cello_use_agent`, which is not a command. It also sits outside the request's async
          // context, which is what let a notice ride a concurrent call's response.
          const resp: IpcResponse = { id: request.id, result };
          conn.socket.write(JSON.stringify(resp) + "\n");
        } catch {
          // Socket closed before response could be written
        }
      })
      .catch((err: unknown) => {
        // extractErrorMessage, NOT String(err): handlers reject with structured plain objects as
        // well as Errors, and String() on a plain object yields the literal "[object Object]" —
        // the cause is destroyed at the point of reporting. The SAME extracted text goes to the
        // log, so a failure is diagnosable from the daemon log alone; the response's guidance
        // sends the reader there and is only true because of this log line.
        const message = extractErrorMessage(err);
        logger.error("daemon.ipc.request.failed", {
          connectionId: conn.id,
          method: request.method,
          requestId: request.id,
          error: message,
        });
        try {
          const resp: IpcResponse = {
            id: request.id,
            error: {
              code: "internal_error",
              message,
              guidance: "An unexpected error occurred. Check daemon logs for details.",
            },
          };
          conn.socket.write(JSON.stringify(resp) + "\n");
        } catch {
          // Socket closed before error could be written
        }
      })
      .finally(() => {
        conn.inFlightCount--;
      });
  }

  return {
    async start(): Promise<void> {
      // Remove stale socket file if it exists
      try {
        await unlink(socketPath);
      } catch (err: unknown) {
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
          throw err;
        }
      }

      server = createServer(handleConnection);

      await new Promise<void>((resolve, reject) => {
        server!.on("error", (err: Error) => {
          reject(err);
        });
        server!.listen(socketPath, () => {
          resolve();
        });
      });

      // SI-001: Set socket permissions to owner-only
      await chmod(socketPath, 0o600);

      // DOD-DAEMON-CLEANUP-1 (AC2): remember WHICH socket we created, by identity — not merely that
      // a file exists at this path. If another daemon later rebinds the path, its listen() replaces
      // the file with a different inode, and stop() must be able to tell the two apart so it does not
      // unlink a socket it does not own.
      //
      // No fallback here, deliberately. Swallowing this stat and leaving the identity unknown would
      // make stop() treat our OWN socket as foreign: it would then never close the server, so the
      // daemon would go on accepting IPC connections into a torn-down handler stack after stop()
      // returned, and would leave its socket behind. A daemon that cannot identify the socket it just
      // bound has no business coming up — and startup failure is already handled cleanly.
      const created = await stat(socketPath);
      createdSocket = { dev: created.dev, ino: created.ino };
    },

    async stop(): Promise<void> {
      stopping = true;
      if (!server) return;

      // Wait for in-flight requests to complete (max 5 seconds)
      const deadline = Date.now() + 5000;
      let totalInFlight = 0;
      while (Date.now() < deadline) {
        totalInFlight = 0;
        for (const conn of connections.values()) {
          totalInFlight += conn.inFlightCount;
        }
        if (totalInFlight === 0) break;
        await new Promise((r) => setTimeout(r, 50));
      }

      if (totalInFlight > 0) {
        logger.warn("daemon.ipc.shutdown.timeout", { abandonedRequests: totalInFlight });
      }

      // Send shutdown notification to all connected clients.
      // Uses IpcNotification shape — distinct from IpcResponse so clients
      // never confuse it with a response to their request.
      const shutdownNotification: IpcNotification = { notification: "shutdown" };
      const shutdownFrame = JSON.stringify(shutdownNotification) + "\n";
      for (const conn of connections.values()) {
        try {
          conn.shutdownReason = "daemon_shutdown";
          conn.socket.write(shutdownFrame);
          conn.socket.end();
        } catch {
          // Connection may already be closed
        }
      }

      // DOD-DAEMON-CLEANUP-1 (AC2): decide ownership BEFORE closing, because close() is itself a
      // blind unlink.
      //
      // Node's server.close() removes the unix socket path it bound — by PATH, with no check on what
      // is actually there now. If another daemon has since rebound this path, closing our server
      // deletes THEIR socket, and they are left alive, serving, and unreachable. Guarding our own
      // explicit unlink is not enough; the close would already have done the damage.
      const ownership = await socketOwnership();

      if (ownership === "foreign") {
        // We must not close: that would unlink the healthy daemon's socket out from under it. Drop
        // the handle from the event loop instead and let process exit reclaim the fd. The listening
        // socket is already inert — its path was taken from it, so nothing can reach it. Leaking an
        // unreachable fd for the last moments of a dying process is a trade we make happily against
        // disarming a live peer.
        logger.info("daemon.ipc.socket.not_ours", { socketPath, ourIno: createdSocket?.ino ?? null });
        server.unref();
      } else {
        await new Promise<void>((resolve) => {
          server!.close(() => resolve());
        });

        // close() normally unlinks the path for us. Re-check rather than assume: only remove the file
        // if it is STILL the socket we created. Between the close and here, the singleton lock is
        // still held (the daemon releases it after this returns), so no successor can have bound the
        // path — but the cost of re-checking is one stat, and the cost of being wrong is the bug this
        // whole unit exists to kill.
        if (await socketOwnership() === "ours") {
          try {
            await unlink(socketPath);
          } catch (err: unknown) {
            if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
              logger.warn("daemon.ipc.socket.unlink.failed", {
                socketPath,
                error: extractErrorMessage(err),
              });
            }
          }
        }
      }

      server = null;
    },

    getConnectionCount(): number {
      return connections.size;
    },

    onDisconnect(handler: IpcDisconnectHandler): void {
      disconnectHandler = handler;
    },

    sendNotification(connectionId: string, notification: IpcNotification): boolean {
      const conn = connections.get(connectionId);
      if (!conn) return false;
      try {
        const frame = JSON.stringify(notification) + "\n";
        return conn.socket.write(frame);
      } catch (err: unknown) {
        logger.debug("daemon.ipc.notification.write.failed", {
          connectionId,
          error: extractErrorMessage(err),
        });
        return false;
      }
    },

    getConnectionIds(): string[] {
      return Array.from(connections.keys());
    },
  };
}
