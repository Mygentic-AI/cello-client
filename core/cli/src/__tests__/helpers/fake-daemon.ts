/**
 * A fake daemon for CLI tests: a socket that answers the methods it is given, records every
 * request it receives, and a lock file pointing at it so the CLI finds it. `requests` starts
 * `undefined` and is set on the first request, so a test can assert the CLI never reached it.
 */
import { createServer, type Server } from "node:net";
import { join } from "node:path";
import { acquireLock } from "@cello-protocol/daemon";

export interface FakeDaemon {
  /** Every request received, in order; `undefined` until the first one arrives. */
  requests: Array<{ method: string; params?: Record<string, unknown> }> | undefined;
  close(): Promise<void>;
}

export async function startFakeDaemon(
  celloDir: string,
  answers: Record<string, unknown>,
): Promise<FakeDaemon> {
  const socketPath = join(celloDir, "fake-daemon.sock");
  const fake: FakeDaemon = { requests: undefined, close: async () => {} };
  const server: Server = createServer((socket) => {
    let buffer = "";
    socket.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("utf-8");
      let newline = buffer.indexOf("\n");
      while (newline !== -1) {
        const line = buffer.slice(0, newline).trim();
        buffer = buffer.slice(newline + 1);
        newline = buffer.indexOf("\n");
        if (!line) continue;
        const req = JSON.parse(line) as { id: string | number; method: string; params?: Record<string, unknown> };
        (fake.requests ??= []).push({ method: req.method, ...(req.params ? { params: req.params } : {}) });
        if (req.method in answers) socket.write(JSON.stringify({ id: req.id, result: answers[req.method] }) + "\n");
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(socketPath, resolve));
  await acquireLock(join(celloDir, "daemon.lock"), { pid: process.pid, socketPath, version: "0.0.1-test" });
  fake.close = () => new Promise<void>((resolve) => server.close(() => resolve()));
  return fake;
}
