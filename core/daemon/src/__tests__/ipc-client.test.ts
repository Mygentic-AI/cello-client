/**
 * CELLO-M7-DAEMON-001 — IPC client tests
 *
 * ACs tested:
 * - Client connects to Unix domain socket
 * - send(method, params) returns result for successful calls
 * - IpcError thrown on error responses (with code, message, guidance)
 * - Connection failure throws
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createIpcServer, type IpcHandler } from "../ipc-server.js";
import { connectToDaemon, IpcError } from "../ipc-client.js";
import type { Logger } from "../types.js";

describe("ipc-client", () => {
  let tempDir: string;
  let logger: Logger;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-client-test-"));
    logger = { info: () => {}, warn: () => {}, error: () => {} };
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("connects and sends a request successfully", async () => {
    const socketPath = join(tempDir, "test.sock");
    const handlers = new Map<string, IpcHandler>();
    handlers.set("greet", async (params) => ({ hello: params?.name || "world" }));
    const server = createIpcServer({ socketPath, maxConnections: 16, logger }, handlers);
    await server.start();

    try {
      const client = await connectToDaemon(socketPath);
      const result = await client.send("greet", { name: "cello" });
      expect(result).toEqual({ hello: "cello" });
      client.close();
    } finally {
      await server.stop();
    }
  });

  it("throws IpcError on error response", async () => {
    const socketPath = join(tempDir, "test.sock");
    const handlers = new Map<string, IpcHandler>();
    // No "unknown" method registered, so it returns method_not_found
    const server = createIpcServer({ socketPath, maxConnections: 16, logger }, handlers);
    await server.start();

    try {
      const client = await connectToDaemon(socketPath);
      await expect(client.send("unknown")).rejects.toThrow(IpcError);
      try {
        await client.send("unknown");
      } catch (err: unknown) {
        const ipcErr = err as IpcError;
        expect(ipcErr.code).toBe("method_not_found");
        expect(typeof ipcErr.guidance).toBe("string");
      }
      client.close();
    } finally {
      await server.stop();
    }
  });

  it("rejects when socket does not exist", async () => {
    const socketPath = join(tempDir, "nonexistent.sock");
    await expect(connectToDaemon(socketPath)).rejects.toThrow();
  });

  it("handles multiple sequential requests on same connection", async () => {
    const socketPath = join(tempDir, "test.sock");
    const handlers = new Map<string, IpcHandler>();
    let counter = 0;
    handlers.set("inc", async () => ({ value: ++counter }));
    const server = createIpcServer({ socketPath, maxConnections: 16, logger }, handlers);
    await server.start();

    try {
      const client = await connectToDaemon(socketPath);
      const r1 = await client.send("inc");
      const r2 = await client.send("inc");
      const r3 = await client.send("inc");
      expect(r1).toEqual({ value: 1 });
      expect(r2).toEqual({ value: 2 });
      expect(r3).toEqual({ value: 3 });
      client.close();
    } finally {
      await server.stop();
    }
  });
});
