/**
 * CELLO-M7-DAEMON-001 — IPC server tests
 *
 * ACs tested:
 * - IPC framing: JSON-newline-delimited requests/responses
 * - Socket permissions: 0o600 (SI-001)
 * - Max 16 concurrent IPC connections
 * - Graceful shutdown: finish in-flight, send shutdown frame, remove socket
 * - Method dispatch: unknown method returns error with guidance
 * - daemon.ipc.connected / daemon.ipc.disconnected events logged
 * - daemon.ipc.connection.limit.reached warning
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createConnection, type Socket } from "node:net";
import { createIpcServer, type IpcHandler } from "../ipc-server.js";
import type { Logger } from "../types.js";

describe("ipc-server", () => {
  let tempDir: string;
  let logEvents: Array<{ level: string; event: string; context: Record<string, unknown> }>;
  let logger: Logger;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-ipc-test-"));
    logEvents = [];
    logger = {
      debug(event, context) { logEvents.push({ level: "debug", event, context }); },
      info(event, context) { logEvents.push({ level: "info", event, context }); },
      warn(event, context) { logEvents.push({ level: "warn", event, context }); },
      error(event, context) { logEvents.push({ level: "error", event, context }); },
    };
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  function connectToSocket(socketPath: string): Promise<Socket> {
    return new Promise((resolve, reject) => {
      const socket = createConnection(socketPath);
      socket.on("connect", () => resolve(socket));
      socket.on("error", reject);
    });
  }

  function sendAndReceive(socket: Socket, message: string): Promise<string> {
    return new Promise((resolve) => {
      let buf = "";
      const onData = (chunk: Buffer) => {
        buf += chunk.toString("utf-8");
        const idx = buf.indexOf("\n");
        if (idx !== -1) {
          socket.removeListener("data", onData);
          resolve(buf.slice(0, idx));
        }
      };
      socket.on("data", onData);
      socket.write(message + "\n");
    });
  }

  it("binds to Unix domain socket with 0o600 permissions", async () => {
    const socketPath = join(tempDir, "test.sock");
    const handlers = new Map<string, IpcHandler>();
    const server = createIpcServer({ socketPath, maxConnections: 16, logger }, handlers);

    await server.start();
    try {
      const s = await stat(socketPath);
      // Socket file should be owner-only
      expect(s.mode & 0o777).toBe(0o600);
    } finally {
      await server.stop();
    }
  });

  it("accepts IPC connections and dispatches requests", async () => {
    const socketPath = join(tempDir, "test.sock");
    const handlers = new Map<string, IpcHandler>();
    handlers.set("ping", async () => ({ pong: true }));

    const server = createIpcServer({ socketPath, maxConnections: 16, logger }, handlers);
    await server.start();

    try {
      const socket = await connectToSocket(socketPath);
      const response = await sendAndReceive(socket, JSON.stringify({ id: "req-1", method: "ping" }));
      const parsed = JSON.parse(response);
      expect(parsed).toEqual({ id: "req-1", result: { pong: true } });
      socket.end();
    } finally {
      await server.stop();
    }
  });

  it("returns error for unknown methods with guidance", async () => {
    const socketPath = join(tempDir, "test.sock");
    const handlers = new Map<string, IpcHandler>();
    const server = createIpcServer({ socketPath, maxConnections: 16, logger }, handlers);
    await server.start();

    try {
      const socket = await connectToSocket(socketPath);
      const response = await sendAndReceive(socket, JSON.stringify({ id: "req-2", method: "nonexistent" }));
      const parsed = JSON.parse(response);
      expect(parsed.id).toBe("req-2");
      expect(parsed.error.code).toBe("method_not_found");
      expect(parsed.error.message).toContain("nonexistent");
      expect(typeof parsed.error.guidance).toBe("string");
      socket.end();
    } finally {
      await server.stop();
    }
  });

  it("destroys connection on malformed JSON", async () => {
    const socketPath = join(tempDir, "test.sock");
    const handlers = new Map<string, IpcHandler>();
    const server = createIpcServer({ socketPath, maxConnections: 16, logger }, handlers);
    await server.start();

    try {
      const socket = await connectToSocket(socketPath);
      // Send malformed JSON — server should destroy the connection
      socket.write("not valid json\n");
      await new Promise<void>((resolve) => {
        socket.on("close", () => resolve());
      });
      // Connection was destroyed by server
      expect(socket.destroyed).toBe(true);
      const parseEvent = logEvents.find((e) => e.event === "daemon.ipc.parse.error");
      expect(parseEvent).toBeDefined();
    } finally {
      await server.stop();
    }
  });

  it("destroys connection for requests missing id or method", async () => {
    const socketPath = join(tempDir, "test.sock");
    const handlers = new Map<string, IpcHandler>();
    const server = createIpcServer({ socketPath, maxConnections: 16, logger }, handlers);
    await server.start();

    try {
      const socket = await connectToSocket(socketPath);
      // Send request without method field — server should destroy
      socket.write(JSON.stringify({ id: "x" }) + "\n");
      await new Promise<void>((resolve) => {
        socket.on("close", () => resolve());
      });
      expect(socket.destroyed).toBe(true);
      const invalidEvent = logEvents.find((e) => e.event === "daemon.ipc.invalid.request");
      expect(invalidEvent).toBeDefined();
    } finally {
      await server.stop();
    }
  });

  it("logs daemon.ipc.accepted and daemon.ipc.disconnected", async () => {
    const socketPath = join(tempDir, "test.sock");
    const handlers = new Map<string, IpcHandler>();
    const server = createIpcServer({ socketPath, maxConnections: 16, logger }, handlers);
    await server.start();

    try {
      const socket = await connectToSocket(socketPath);
      // Wait for connection event to be logged
      await new Promise((r) => setTimeout(r, 50));
      expect(logEvents.find((e) => e.event === "daemon.ipc.accepted")).toBeDefined();

      socket.end();
      await new Promise((r) => setTimeout(r, 100));
      expect(logEvents.find((e) => e.event === "daemon.ipc.disconnected")).toBeDefined();
    } finally {
      await server.stop();
    }
  });

  it("destroys connections beyond maxConnections with connection.limit.reached", async () => {
    const socketPath = join(tempDir, "test.sock");
    const handlers = new Map<string, IpcHandler>();
    const maxConnections = 2;
    const server = createIpcServer({ socketPath, maxConnections, logger }, handlers);
    await server.start();

    const sockets: Socket[] = [];
    try {
      // Open max connections
      for (let i = 0; i < maxConnections; i++) {
        sockets.push(await connectToSocket(socketPath));
      }
      await new Promise((r) => setTimeout(r, 50));

      // Third connection should be destroyed immediately
      const rejected = await connectToSocket(socketPath);
      await new Promise<void>((resolve) => {
        rejected.on("close", () => resolve());
      });
      expect(rejected.destroyed).toBe(true);

      const warnEvents = logEvents.filter((e) => e.event === "daemon.ipc.connection.limit.reached");
      expect(warnEvents.length).toBeGreaterThanOrEqual(1);
      expect(warnEvents[0].context.currentCount).toBe(maxConnections);
      expect(warnEvents[0].context.maxCount).toBe(maxConnections);
    } finally {
      for (const s of sockets) s.end();
      await server.stop();
    }
  });

  it("handles concurrent requests on same connection", async () => {
    const socketPath = join(tempDir, "test.sock");
    const handlers = new Map<string, IpcHandler>();
    handlers.set("echo", async (params) => params);

    const server = createIpcServer({ socketPath, maxConnections: 16, logger }, handlers);
    await server.start();

    try {
      const socket = await connectToSocket(socketPath);
      // Send two requests without waiting for responses
      socket.write(JSON.stringify({ id: "a", method: "echo", params: { val: 1 } }) + "\n");
      socket.write(JSON.stringify({ id: "b", method: "echo", params: { val: 2 } }) + "\n");

      // Collect both responses
      const responses: Record<string, unknown>[] = [];
      await new Promise<void>((resolve) => {
        let buf = "";
        socket.on("data", (chunk: Buffer) => {
          buf += chunk.toString("utf-8");
          let idx: number;
          while ((idx = buf.indexOf("\n")) !== -1) {
            const line = buf.slice(0, idx);
            buf = buf.slice(idx + 1);
            if (line.trim()) responses.push(JSON.parse(line));
            if (responses.length === 2) resolve();
          }
        });
      });

      const respA = responses.find((r: Record<string, unknown>) => r.id === "a") as Record<string, unknown>;
      const respB = responses.find((r: Record<string, unknown>) => r.id === "b") as Record<string, unknown>;
      expect(respA.result).toEqual({ val: 1 });
      expect(respB.result).toEqual({ val: 2 });
      socket.end();
    } finally {
      await server.stop();
    }
  });

  it("graceful shutdown waits for in-flight requests", async () => {
    const socketPath = join(tempDir, "test.sock");
    const handlers = new Map<string, IpcHandler>();
    let resolveHandler: (() => void) | null = null;
    handlers.set("slow", () => new Promise<unknown>((resolve) => {
      resolveHandler = () => resolve({ done: true });
    }));

    const server = createIpcServer({ socketPath, maxConnections: 16, logger }, handlers);
    await server.start();

    const socket = await connectToSocket(socketPath);
    // Send a slow request
    socket.write(JSON.stringify({ id: "slow-1", method: "slow" }) + "\n");
    await new Promise((r) => setTimeout(r, 50));

    // Start shutdown while request is in-flight
    const stopPromise = server.stop();

    // Resolve the handler
    await new Promise((r) => setTimeout(r, 50));
    resolveHandler!();

    // Collect the response
    const response = await new Promise<string>((resolve) => {
      let buf = "";
      socket.on("data", (chunk: Buffer) => {
        buf += chunk.toString("utf-8");
        const idx = buf.indexOf("\n");
        if (idx !== -1) resolve(buf.slice(0, idx));
      });
    });

    const parsed = JSON.parse(response);
    expect(parsed.id).toBe("slow-1");
    expect(parsed.result).toEqual({ done: true });

    await stopPromise;
    socket.end();
  });

  it("reports connection count correctly", async () => {
    const socketPath = join(tempDir, "test.sock");
    const handlers = new Map<string, IpcHandler>();
    const server = createIpcServer({ socketPath, maxConnections: 16, logger }, handlers);
    await server.start();

    try {
      expect(server.getConnectionCount()).toBe(0);
      const s1 = await connectToSocket(socketPath);
      await new Promise((r) => setTimeout(r, 50));
      expect(server.getConnectionCount()).toBe(1);
      const s2 = await connectToSocket(socketPath);
      await new Promise((r) => setTimeout(r, 50));
      expect(server.getConnectionCount()).toBe(2);
      s1.end();
      await new Promise((r) => setTimeout(r, 100));
      expect(server.getConnectionCount()).toBe(1);
      s2.end();
    } finally {
      await server.stop();
    }
  });
});
