/**
 * IPC Proxy — thin client for connecting cello-mcp to the daemon.
 *
 * Pseudocode:
 * 1. connect(socketPath):
 *    a. Create net.Socket via createConnection
 *    b. On 'connect' event → resolve
 *    c. On 'error' → reject with ENOENT/ECONNREFUSED
 *    d. Set up JSON-newline framing reader
 *
 * 2. call(method, params):
 *    a. If socket is dead → return ipc_connection_lost immediately
 *    b. Generate numeric request ID (incrementing counter)
 *    c. Write { id, method, params } + '\n' to socket
 *    d. Await matching response by id
 *    e. If JSON parse error on response → return ipc_deserialization_error
 *    f. If response has error → extract and return as { ok: false, ... }
 *    g. Otherwise return result
 *
 * 3. On socket close: set dead flag. All subsequent calls return ipc_connection_lost.
 */

import { createConnection, type Socket } from "node:net";

export interface IpcProxyResult {
  [key: string]: unknown;
}

const IPC_CONNECTION_LOST = {
  ok: false,
  reason: "ipc_connection_lost",
  guidance:
    "The connection to the CELLO daemon was lost. Restart this MCP server (close and reopen Claude Code) to reconnect. The daemon itself may still be running — run `cello status` in a terminal to check.",
};

const IPC_DESERIALIZATION_ERROR = {
  ok: false,
  reason: "ipc_deserialization_error",
  guidance:
    "The daemon sent a malformed response — this may be transient. Retry your operation. If the error persists, run `cello-mcp --version` and `cello status` to check for a version mismatch between cello-mcp and the running daemon.",
};

// CELLO-M7-MSG-001: must stay in sync with ipc-server.ts MAX_BUFFER_SIZE. Raised to
// 4 MB so a max-size (1 MB) cello_send content message + JSON envelope traverses IPC and
// reaches the daemon's content_too_large check, instead of tripping a fatal buffer
// overflow at the 1 MB content cap boundary.
const MAX_BUFFER_SIZE = 4 * 1024 * 1024; // 4MB — matches IPC server limit

export class IpcProxy {
  readonly #socketPath: string;
  #socket: Socket | null = null;
  #dead = false;
  #nextId = 1;
  #pending = new Map<string, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  #buffer = "";

  constructor(socketPath: string) {
    this.#socketPath = socketPath;
  }

  /**
   * Connect to the daemon IPC socket.
   * Throws if the socket doesn't exist (ENOENT) or daemon isn't listening (ECONNREFUSED).
   */
  connect(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const socket = createConnection(this.#socketPath);
      this.#socket = socket;

      socket.on("connect", () => {
        resolve();
      });

      socket.on("error", (err: Error) => {
        this.#dead = true;
        reject(err);
        // Reject all pending requests
        for (const [, p] of this.#pending) {
          p.reject(new Error("Connection closed"));
        }
        this.#pending.clear();
      });

      socket.on("data", (chunk: Buffer) => {
        this.#buffer += chunk.toString("utf-8");
        if (this.#buffer.length > MAX_BUFFER_SIZE) {
          this.#dead = true;
          socket.destroy();
          for (const [, p] of this.#pending) {
            p.resolve(IPC_CONNECTION_LOST);
          }
          this.#pending.clear();
          return;
        }
        this.#processBuffer();
      });

      socket.on("close", () => {
        this.#dead = true;
        // Reject all pending requests
        for (const [, p] of this.#pending) {
          p.reject(new Error("Connection closed"));
        }
        this.#pending.clear();
      });
    });
  }

  /**
   * Send an IPC request and await the response.
   * Returns the result directly if successful, or an error object with reason/guidance.
   */
  async call(method: string, params?: Record<string, unknown>): Promise<unknown> {
    if (!method || typeof method !== "string") {
      return { ok: false, reason: "invalid_method", guidance: "IPC method name must be a non-empty string." };
    }
    if (this.#dead) {
      return IPC_CONNECTION_LOST;
    }

    const id = String(this.#nextId++);

    return new Promise<unknown>((resolve) => {
      this.#pending.set(id, {
        resolve,
        reject: () => {
          // On socket close/error, return ipc_connection_lost
          resolve(IPC_CONNECTION_LOST);
        },
      });

      const frame = JSON.stringify({ id, method, params }) + "\n";
      try {
        this.#socket!.write(frame);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        process.stderr.write(`cello-mcp: IPC write failed: ${msg}\n`);
        this.#dead = true;
        this.#pending.delete(id);
        resolve(IPC_CONNECTION_LOST);
      }
    });
  }

  close(): void {
    if (this.#socket) {
      this.#socket.end();
      this.#socket = null;
    }
    this.#dead = true;
  }

  get isDead(): boolean {
    return this.#dead;
  }

  #processBuffer(): void {
    let newlineIdx: number;
    while ((newlineIdx = this.#buffer.indexOf("\n")) !== -1) {
      const line = this.#buffer.slice(0, newlineIdx);
      this.#buffer = this.#buffer.slice(newlineIdx + 1);
      if (line.trim().length === 0) continue;

      let frame: Record<string, unknown>;
      try {
        frame = JSON.parse(line) as Record<string, unknown>;
      } catch {
        // Malformed JSON — resolve the oldest pending request with deserialization error.
        // In production the daemon never sends malformed frames; this handles transient
        // corruption or version mismatch. We resolve the oldest pending because responses
        // arrive in order for the single-socket serial protocol.
        process.stderr.write(`cello-mcp: received malformed IPC frame (${line.length} bytes)\n`);
        const oldestEntry = this.#pending.entries().next();
        if (!oldestEntry.done) {
          const [oldestId, resolver] = oldestEntry.value;
          this.#pending.delete(oldestId);
          resolver.resolve(IPC_DESERIALIZATION_ERROR);
        }
        continue;
      }

      // Check for notification frames (server-initiated, no id)
      if ("notification" in frame) {
        // Notifications are not correlated to requests; skip for now
        continue;
      }

      // Regular response — correlate by id
      const responseId = frame.id as string;
      const pending = this.#pending.get(responseId);
      if (pending) {
        this.#pending.delete(responseId);
        if ("error" in frame) {
          const err = frame.error as { code: string; message: string; guidance: string };
          pending.resolve({
            ok: false,
            reason: err.code,
            message: err.message,
            guidance: err.guidance,
          });
        } else {
          pending.resolve(frame.result);
        }
      } else if (responseId) {
        process.stderr.write(`cello-mcp: orphaned IPC response for id=${responseId} (no pending request)\n`);
      }
    }
  }
}
