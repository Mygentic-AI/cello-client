/**
 * CELLO-M7-PERSIST-002 (AC-009 / DEC-4): the write-allow-list guard.
 *
 * After a daemon lifecycle (start → create agent → start agent → restart), the ONLY files that may
 * exist under CELLO_DIR are: the SQLCipher DB (+ its WAL/SHM + a one-time migration .bak), the
 * SQLCipher key file, daemon.lock, daemon.log, and daemon.sock. No flat-file STATE — no
 * agents/<name>/key, no *.json identity files, no transcript-key — may appear. This guard fails CI
 * if a future change writes client state to a flat file ("everything in the database", DEC-4).
 *
 * (Registration + sessions are exercised by the live J-PERSIST journey; this in-process guard covers
 * the identity + lifecycle write paths without a live directory.)
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readdir } from "node:fs/promises";
import { join, relative } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway";
import { startDaemon, type DaemonHandle, type DaemonConfig } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import type { Logger } from "../types.js";

function makeLogger(): Logger {
  return { debug() {}, info() {}, warn() {}, error() {} };
}

let tempDir = "";
let handle: DaemonHandle | null = null;
const clients: IpcClient[] = [];

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "persist002-allow-"));
});
afterEach(async () => {
  for (const c of clients) { try { c.close(); } catch { /* ignore */ } }
  clients.length = 0;
  if (handle) { await handle.stop(); handle = null; }
  await rm(tempDir, { recursive: true, force: true });
});

function makeConfig(): DaemonConfig {
  return {
      securityGateway: new PassthroughGatewayClient(),
      securityGateway: new PassthroughGatewayClient(),
    celloDir: tempDir,
    socketPath: join(tempDir, "daemon.sock"),
    lockFilePath: join(tempDir, "daemon.lock"),
    maxConnections: 16,
    version: "0.0.1-test",
    logger: makeLogger(),
  };
}

async function connect(socketPath: string): Promise<IpcClient> {
  const client = await connectToDaemon(socketPath);
  clients.push(client);
  await client.send("ipc.connect", { clientType: "mcp" });
  return client;
}

/** Every file (relative path) under dir, recursively. */
async function listFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  async function walk(d: string): Promise<void> {
    for (const e of await readdir(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) await walk(p);
      else out.push(relative(dir, p));
    }
  }
  await walk(dir);
  return out;
}

// The ONLY paths the daemon may write under CELLO_DIR (DEC-4).
const ALLOW = [
  /^sessions\.db$/,
  /^sessions\.db-wal$/,
  /^sessions\.db-shm$/,
  /^sessions\.db\.key$/,
  /^sessions\.db\.pre-sqlcipher\.bak$/, // one-time migration backup
  /^daemon\.lock$/,
  /^daemon\.log$/,
  /^daemon\.sock$/,
  // DOD-SINGLE-DAEMON-1: the file the kernel takes the singleton lock on. Same category as
  // daemon.lock and daemon.sock — process infrastructure, not state. It holds NO rows and never
  // will (SQLite is only the vehicle for a portable fcntl lock), so it carries nothing that could
  // want encrypting.
  /^daemon\.singleton$/,
];

describe("PERSIST-002 AC-009 — write-allow-list guard (DEC-4)", () => {
  it("a full lifecycle writes ONLY the DB, key, lock, log, and socket — no flat-file state", async () => {
    const config = makeConfig();
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    // Exercise the identity + lifecycle write paths.
    await client.send("cello_create_agent", { name: "alice" });
    await client.send("cello_create_agent", { name: "bob" });
    await client.send("cello_start_agent", { name: "alice" });
    await client.send("cello_use_agent", { name: "alice" });
    client.close();
    clients.length = 0;
    await handle.stop();

    // Restart (exercises migration-no-op + reload-from-DB write paths).
    handle = await startDaemon(makeConfig());
    const client2 = await connect(makeConfig().socketPath);
    await client2.send("cello_start_agent", { name: "alice" });
    client2.close();
    clients.length = 0;
    await handle.stop();
    handle = null;

    const files = await listFiles(tempDir);
    const offenders = files.filter((f) => !ALLOW.some((re) => re.test(f)));
    expect(offenders, `unexpected flat-file writes under CELLO_DIR: ${offenders.join(", ")}`).toEqual([]);

    // Teeth: the guard actually saw the DB + key (so it's not vacuously passing on an empty dir).
    expect(files).toContain("sessions.db");
    expect(files).toContain("sessions.db.key");
    // And specifically NONE of the pre-story flat-file identity artifacts exist.
    expect(files.some((f) => f.endsWith("/key") || f === "key")).toBe(false);
    expect(files.some((f) => f.endsWith(".json"))).toBe(false);
    expect(files.some((f) => f.endsWith(".transcript-key"))).toBe(false);
  });
});
