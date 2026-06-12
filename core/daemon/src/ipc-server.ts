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
import type { Logger, IpcRequest, IpcResponse } from "./types.js";
import { ErrorCodes } from "./types.js";

export type IpcHandler = (params: Record<string, unknown> | undefined) => Promise<unknown>;

export interface IpcServerConfig {
  socketPath: string;
  maxConnections: number;
  logger: Logger;
}

export interface IpcServer {
  start(): Promise<void>;
  stop(): Promise<void>;
  getConnectionCount(): number;
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
      const errorFrame: IpcResponse = {
        id: "system",
        error: {
          code: ErrorCodes.IPC_CONNECTION_LIMIT,
          message: `Maximum ${maxConnections} concurrent IPC connections reached`,
          guidance: "Wait for an existing connection to close before opening a new one.",
        },
      };
      socket.write(JSON.stringify(errorFrame) + "\n");
      socket.end();
      return;
    }

    const connectionId = randomUUID();
    const conn: ActiveConnection = { id: connectionId, socket, inFlightCount: 0, shutdownReason: null };
    connections.set(connectionId, conn);

    logger.info("daemon.ipc.connected", { connectionId, clientType: "cli" });

    const MAX_BUFFER_SIZE = 1024 * 1024; // 1MB per connection
    let buffer = "";

    socket.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("utf-8");
      if (buffer.length > MAX_BUFFER_SIZE) {
        const errorResp: IpcResponse = {
          id: "system",
          error: {
            code: "message_too_large",
            message: "IPC message exceeds 1MB limit",
            guidance: "IPC messages must be under 1MB. Check for malformed input.",
          },
        };
        try { conn.socket.write(JSON.stringify(errorResp) + "\n"); } catch { /* socket may be dead */ }
        conn.socket.end();
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
    });

    socket.on("error", (err: Error) => {
      connections.delete(connectionId);
      logger.info("daemon.ipc.disconnected", { connectionId, reason: err.message });
    });
  }

  function handleMessage(conn: ActiveConnection, line: string): void {
    let request: IpcRequest;
    try {
      request = JSON.parse(line) as IpcRequest;
    } catch {
      const errorResp: IpcResponse = {
        id: "unknown",
        error: {
          code: "parse_error",
          message: "Failed to parse IPC request as JSON",
          guidance: "Send a valid JSON object followed by a newline character.",
        },
      };
      conn.socket.write(JSON.stringify(errorResp) + "\n");
      return;
    }

    if (!request.id || !request.method) {
      const errorResp: IpcResponse = {
        id: request.id || "unknown",
        error: {
          code: "invalid_request",
          message: "Request must include 'id' and 'method' fields",
          guidance: "Format: {\"id\": \"<uuid>\", \"method\": \"<method_name>\", \"params\": {}}",
        },
      };
      conn.socket.write(JSON.stringify(errorResp) + "\n");
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
    Promise.resolve(handler(request.params))
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
      while (Date.now() < deadline) {
        let totalInFlight = 0;
        for (const conn of connections.values()) {
          totalInFlight += conn.inFlightCount;
        }
        if (totalInFlight === 0) break;
        await new Promise((r) => setTimeout(r, 50));
      }

      // Send shutdown frame to all connected clients
      const shutdownFrame = JSON.stringify({ id: "system", result: { type: "shutdown" } }) + "\n";
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
  };
}
