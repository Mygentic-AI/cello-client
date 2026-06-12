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
import { chmod, unlink } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import type { Logger, IpcRequest, IpcResponse, IpcNotification } from "./types.js";

export type IpcHandler = (params: Record<string, unknown> | undefined, connectionId: string) => Promise<unknown>;

export interface IpcServerConfig {
  socketPath: string;
  maxConnections: number;
  logger: Logger;
}

export type IpcDisconnectHandler = (connectionId: string) => void;

export interface IpcServer {
  start(): Promise<void>;
  stop(): Promise<void>;
  getConnectionCount(): number;
  onDisconnect(handler: IpcDisconnectHandler): void;
}

interface ActiveConnection {
  id: string;
  socket: Socket;
  inFlightCount: number;
  shutdownReason: string | null;
}

export function createIpcServer(
  config: IpcServerConfig,
  handlers: Map<string, IpcHandler>,
): IpcServer {
  const { socketPath, maxConnections, logger } = config;
  let server: Server | null = null;
  const connections = new Map<string, ActiveConnection>();
  let stopping = false;
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

    // clientType is logged as "cli" by default; ipc.connect handler can update it
    logger.info("daemon.ipc.connected", { connectionId, clientType: "cli" });

    const MAX_BUFFER_SIZE = 1024 * 1024; // 1MB per connection
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
      logger.info("daemon.ipc.disconnected", { connectionId, reason });
      if (disconnectHandler) disconnectHandler(connectionId);
    });

    socket.on("error", (err: Error) => {
      connections.delete(connectionId);
      logger.info("daemon.ipc.disconnected", { connectionId, reason: err.message });
      if (disconnectHandler) disconnectHandler(connectionId);
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
          guidance: "Available methods: status, shutdown",
        },
      };
      conn.socket.write(JSON.stringify(errorResp) + "\n");
      return;
    }

    conn.inFlightCount++;
    Promise.resolve(handler(request.params, conn.id))
      .then((result) => {
        try {
          const resp: IpcResponse = { id: request.id, result };
          conn.socket.write(JSON.stringify(resp) + "\n");
        } catch {
          // Socket closed before response could be written
        }
      })
      .catch((err: unknown) => {
        try {
          const resp: IpcResponse = {
            id: request.id,
            error: {
              code: "internal_error",
              message: err instanceof Error ? err.message : String(err),
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

      // Close server and remove socket
      await new Promise<void>((resolve) => {
        server!.close(() => resolve());
      });

      try {
        await unlink(socketPath);
      } catch (err: unknown) {
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
          logger.warn("daemon.ipc.socket.unlink.failed", {
            socketPath,
            error: err instanceof Error ? err.message : String(err),
          });
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
  };
}
