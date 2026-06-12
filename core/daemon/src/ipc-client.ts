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
import type { IpcRequest, IpcResponse, IpcResponseError } from "./types.js";

export interface IpcClient {
  send(method: string, params?: Record<string, unknown>): Promise<unknown>;
  close(): void;
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

export function connectToDaemon(socketPath: string): Promise<IpcClient> {
  return new Promise<IpcClient>((resolve, reject) => {
    const socket: Socket = createConnection(socketPath);
    const pending = new Map<string, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
    let buffer = "";

    socket.on("connect", () => {
      resolve(client);
    });

    socket.on("error", (err: Error) => {
      reject(err);
      // Reject all pending requests
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
          const response = JSON.parse(line) as IpcResponse;
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
        } catch {
          // Malformed response — ignore
        }
      }
    });

    socket.on("close", () => {
      for (const [, p] of pending) {
        p.reject(new Error("Connection closed"));
      }
      pending.clear();
    });

    const client: IpcClient = {
      send(method: string, params?: Record<string, unknown>): Promise<unknown> {
        return new Promise<unknown>((res, rej) => {
          const id = randomUUID();
          pending.set(id, { resolve: res, reject: rej });
          const request: IpcRequest = { id, method, params };
          socket.write(JSON.stringify(request) + "\n");
        });
      },

      close(): void {
        socket.end();
      },
    };
  });
}
