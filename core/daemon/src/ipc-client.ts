/**
 * IPC client for connecting to the CELLO daemon.
 *
 * Pseudocode:
 * 1. connectToDaemon(socketPath):
 *    a. Create net.Socket
 *    b. Connect to Unix domain socket
 *    c. Return IpcClient with send(method, params) → Promise<result>
 *
 * 2. send(method, params):
 *    a. Generate unique request ID
 *    b. Write JSON + newline to socket
 *    c. Wait for response with matching ID
 *    d. Return result or throw error
 */

import { createConnection, type Socket } from "node:net";
import { randomUUID } from "node:crypto";
import type { IpcRequest, IpcResponse, IpcResponseError, IpcNotification } from "./types.js";

export interface IpcClient {
  send(method: string, params?: Record<string, unknown>): Promise<unknown>;
  close(): void;
  onNotification(handler: (notification: IpcNotification) => void): void;
}

export class IpcError extends Error {
  readonly code: string;
  readonly guidance: string;

  constructor(code: string, message: string, guidance: string) {
    super(message);
    this.name = "IpcError";
    this.code = code;
    this.guidance = guidance;
  }
}

export interface IpcClientOptions {
  onFrameError?: (error: string) => void;
}

export function connectToDaemon(socketPath: string, opts?: IpcClientOptions): Promise<IpcClient> {
  return new Promise<IpcClient>((resolve, reject) => {
    const socket: Socket = createConnection(socketPath);
    const pending = new Map<string, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
    let buffer = "";
    let notificationHandler: ((notification: IpcNotification) => void) | null = null;

    const client: IpcClient = {
      send(method: string, params?: Record<string, unknown>): Promise<unknown> {
        return new Promise<unknown>((res, rej) => {
          if (socket.destroyed) {
            rej(new Error("Socket closed"));
            return;
          }
          const id = randomUUID();
          pending.set(id, { resolve: res, reject: rej });
          const request: IpcRequest = { id, method, params };
          socket.write(JSON.stringify(request) + "\n");
        });
      },

      close(): void {
        socket.end();
      },

      onNotification(handler: (notification: IpcNotification) => void): void {
        notificationHandler = handler;
      },
    };

    socket.on("connect", () => {
      resolve(client);
    });

    socket.on("error", (err: Error) => {
      reject(err);
      for (const [, p] of pending) {
        p.reject(err);
      }
      pending.clear();
    });

    socket.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("utf-8");
      let newlineIdx: number;
      while ((newlineIdx = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, newlineIdx);
        buffer = buffer.slice(newlineIdx + 1);
        if (line.trim().length === 0) continue;

        try {
          const frame = JSON.parse(line) as Record<string, unknown>;

          // Notifications have a "notification" field — they are server-initiated
          // and never correlate to a request.
          if ("notification" in frame) {
            if (notificationHandler) {
              notificationHandler(frame as unknown as IpcNotification);
            }
            continue;
          }

          // Regular response — correlate by id
          const response = frame as unknown as IpcResponse;
          const p = pending.get(response.id);
          if (p) {
            pending.delete(response.id);
            if ("error" in response) {
              const errResp = response as IpcResponseError;
              p.reject(new IpcError(errResp.error.code, errResp.error.message, errResp.error.guidance));
            } else {
              p.resolve(response.result);
            }
          }
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          if (opts?.onFrameError) {
            opts.onFrameError(msg);
          }
        }
      }
    });

    socket.on("close", () => {
      for (const [, p] of pending) {
        p.reject(new Error("Connection closed"));
      }
      pending.clear();
    });
  });
}
