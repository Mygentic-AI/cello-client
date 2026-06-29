/**
 * CELLO-M7-SESSION (cello_list_sessions) — session discovery surface.
 *
 * Until now an operator/agent could read a transcript or a sealed receipt by
 * session_id (cello_get_transcript / cello_get_sealed_receipt), but had no way
 * to DISCOVER the session ids in the first place — cello_list_sessions returned
 * `not_implemented`. Multiple guidance strings ("See cello_list_sessions",
 * "Check cello_list_sessions for sealed sessions") pointed at that dead end.
 *
 * Specification (SPARC Phase S):
 *
 * LIST-1 Unit (SessionNodeManager.getSessionsForAgent): returns every persisted
 *   session for the named agent regardless of status (active, interrupted,
 *   sealed, seal_interrupted_pending), and excludes other agents' sessions.
 *   Empty array for an agent with no sessions.
 *
 * LIST-2 Integration: cello_list_sessions with no current agent returns
 *   { ok:false, reason:"no_current_agent" } with a guidance field.
 *
 * LIST-3 Integration: cello_list_sessions returns the CURRENT agent's sessions
 *   only — active, interrupted AND sealed — each entry carrying sessionId,
 *   agentName, counterpartyPubkey, status, messageCount, createdAt (ISO),
 *   updatedAt (ISO), interruptedAt (ISO|null). Other agents' sessions are
 *   excluded. Ordered most-recently-updated first.
 *
 * LIST-4 Integration: cello_list_sessions returns { ok:true, sessions:[] } for a
 *   current agent that has no sessions (always an array, never undefined).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { SessionNodeManager } from "../session-node-manager.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import { startDaemon } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Logger, DaemonConfig, DaemonHandle } from "../types.js";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeLogger(): { logger: Logger; events: Array<{ level: string; event: string; context: Record<string, unknown> }> } {
  const events: Array<{ level: string; event: string; context: Record<string, unknown> }> = [];
  const logger: Logger = {
    debug(event, context) { events.push({ level: "debug", event, context }); },
    info(event, context) { events.push({ level: "info", event, context }); },
    warn(event, context) { events.push({ level: "warn", event, context }); },
    error(event, context) { events.push({ level: "error", event, context }); },
  };
  return { logger, events };
}

/** Loopback fake node — start_agent's standing receiver can come up without a network. */
class FakeCelloNode {
  readonly peerId = `fake-peer-${Math.random().toString(36).slice(2)}`;
  readonly addrs = ["/ip4/127.0.0.1/tcp/9999"];
  async start(): Promise<void> {}
  async stop(): Promise<void> {}
  getPeerId(): string { return this.peerId; }
  listenAddresses(): string[] { return this.addrs; }
  async dial(_ma: string): Promise<{ peerId: string }> { return { peerId: "remote" }; }
  async handle(_p: string, _h: unknown): Promise<void> {}
  async newStream(_p: string, _pid: string): Promise<unknown> { return {}; }
  getProtocols(): string[] { return []; }
  getConnections(): Array<{ peerId: string; encryption: string | undefined }> { return []; }
  hasDirectConnectionTo(_peerId: string): boolean { return false; }
  onPeerConnect(_h: (_p: string) => void): void {}
  onPeerDisconnect(_h: (_p: string) => void): void {}
  getDialability(): { dialable: boolean; publicAddr: string | null } { return { dialable: false, publicAddr: null }; }
  onDialabilityChange(_l: (d: { dialable: boolean; publicAddr: string | null }) => void): () => void { return () => {}; }
  get keyProvider() { return { getPublicKey: async () => new Uint8Array(32), sign: async (m: Uint8Array) => m }; }
}

class StubNodeFactory implements ISessionNodeFactory {
  async createNode(_config: SessionNodeConfig): Promise<CelloNode> {
    return new FakeCelloNode() as unknown as CelloNode;
  }
}

/**
 * M7 sessions table mirroring production: composite PRIMARY KEY (agent_name,
 * session_id) — the DOD-LOOP-1 shape, so the pre-created table is identical to
 * what the daemon's `initialize()` CREATE TABLE IF NOT EXISTS would build. The
 * message_count / interrupted_at columns (added by ALTER in production) are
 * inlined here for the test inserts; the daemon's idempotent ALTERs no-op on them.
 */
function createSessionsTable(db: DaemonDatabase): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      session_id TEXT NOT NULL,
      agent_name TEXT NOT NULL,
      counterparty_pubkey TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      message_count INTEGER NOT NULL DEFAULT 0,
      interrupted_at TEXT,
      PRIMARY KEY (agent_name, session_id)
    )
  `);
}

function insertRow(
  db: DaemonDatabase,
  opts: {
    sessionId: string;
    agentName: string;
    counterpartyPubkey: string;
    status: string;
    messageCount?: number;
    createdAt?: number;
    updatedAt?: number;
    interruptedAt?: string | null;
  },
): void {
  const now = Date.now();
  db.prepare(
    `INSERT OR REPLACE INTO sessions
       (session_id, agent_name, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    opts.sessionId,
    opts.agentName,
    opts.counterpartyPubkey,
    opts.status,
    opts.createdAt ?? now,
    opts.updatedAt ?? now,
    opts.messageCount ?? 0,
    opts.interruptedAt ?? null,
  );
}

// ─── LIST-1: SessionNodeManager.getSessionsForAgent (unit) ─────────────────────

describe("cello_list_sessions: SessionNodeManager.getSessionsForAgent", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-list-mgr-"));
  });
  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("LIST-1: returns the agent's sessions across every status, excludes other agents", async () => {
    const { logger } = makeLogger();
    const dbPath = join(tempDir, "sessions.db");
    const mgr = new SessionNodeManager({ factory: new StubNodeFactory(), logger, dbPath });
    await mgr.initialize();
    const db = mgr.getDb();

    insertRow(db, { sessionId: "a1".padEnd(64, "0"), agentName: "alice", counterpartyPubkey: "cpA", status: "active", messageCount: 2 });
    insertRow(db, { sessionId: "a2".padEnd(64, "0"), agentName: "alice", counterpartyPubkey: "cpB", status: "interrupted", messageCount: 5, interruptedAt: "2026-06-20T00:00:00.000Z" });
    insertRow(db, { sessionId: "a3".padEnd(64, "0"), agentName: "alice", counterpartyPubkey: "cpC", status: "sealed", messageCount: 4 });
    insertRow(db, { sessionId: "b1".padEnd(64, "0"), agentName: "bob", counterpartyPubkey: "cpD", status: "active", messageCount: 9 });

    const aliceSessions = mgr.getSessionsForAgent("alice");
    expect(aliceSessions).toHaveLength(3);
    const statuses = aliceSessions.map((s) => s.status).sort();
    expect(statuses).toEqual(["active", "interrupted", "sealed"]);
    expect(aliceSessions.every((s) => s.agent_name === "alice")).toBe(true);
  });

  it("LIST-1: returns an empty array for an agent with no sessions", async () => {
    const { logger } = makeLogger();
    const dbPath = join(tempDir, "sessions.db");
    const mgr = new SessionNodeManager({ factory: new StubNodeFactory(), logger, dbPath });
    await mgr.initialize();
    expect(mgr.getSessionsForAgent("ghost")).toEqual([]);
  });
});

// ─── LIST-2/3/4: cello_list_sessions handler (integration) ─────────────────────

describe("cello_list_sessions: MCP handler", () => {
  let tempDir: string;
  let handle: DaemonHandle | null;
  let clients: IpcClient[];

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-list-handler-"));
    handle = null;
    clients = [];
  });

  afterEach(async () => {
    for (const c of clients) { try { c.close(); } catch { /* closed */ } }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
  });

  async function setupAgent(name: string): Promise<void> {
    const agentDir = join(tempDir, "agents", name);
    await mkdir(agentDir, { recursive: true });
    await FileKeyProvider.load(join(agentDir, "key"));
  }

  function makeConfig(): DaemonConfig {
    const { logger } = makeLogger();
    return {
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
    };
  }

  async function connect(socketPath: string): Promise<IpcClient> {
    const client = await connectToDaemon(socketPath);
    clients.push(client);
    await client.send("ipc.connect", { clientType: "mcp" });
    return client;
  }

  it("LIST-2: returns no_current_agent (with guidance) when no agent is set", async () => {
    await setupAgent("alice");
    const config = makeConfig();
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    const res = await client.send("cello_list_sessions") as { ok: boolean; reason: string; guidance: string };
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("no_current_agent");
    expect(typeof res.guidance).toBe("string");
    expect(res.guidance.length).toBeGreaterThan(0);
  });

  it("LIST-3: filter (open default / closed / failed / all) + limit, scoped to the current agent", async () => {
    // Pre-populate the sessions DB before the daemon opens it (matches SESSION-001 AC-006 pattern).
    const db = openTestDb(join(tempDir, "sessions.db"));
    createSessionsTable(db);
    const t0 = Date.now() - 30_000;
    // aa: active (reconciled to interrupted-with-messages at startup) → category OPEN
    insertRow(db, { sessionId: "aa".padEnd(64, "1"), agentName: "alice", counterpartyPubkey: "cpActive", status: "active", messageCount: 2, createdAt: t0, updatedAt: t0 + 1000 });
    // bb: interrupted WITH messages → resumable → OPEN
    insertRow(db, { sessionId: "bb".padEnd(64, "2"), agentName: "alice", counterpartyPubkey: "cpIntr", status: "interrupted", messageCount: 5, createdAt: t0, updatedAt: t0 + 3000, interruptedAt: new Date(t0 + 3000).toISOString() });
    // cc: sealed → CLOSED
    insertRow(db, { sessionId: "cc".padEnd(64, "3"), agentName: "alice", counterpartyPubkey: "cpSealed", status: "sealed", messageCount: 4, createdAt: t0, updatedAt: t0 + 2000 });
    // ee: interrupted with ZERO messages → a failed init → FAILED (must not show by default)
    insertRow(db, { sessionId: "ee".padEnd(64, "5"), agentName: "alice", counterpartyPubkey: "cpFailed", status: "interrupted", messageCount: 0, createdAt: t0, updatedAt: t0 + 500, interruptedAt: new Date(t0 + 500).toISOString() });
    // dd: another agent's — always excluded from alice's per-agent list
    insertRow(db, { sessionId: "dd".padEnd(64, "4"), agentName: "bob", counterpartyPubkey: "cpBob", status: "active", messageCount: 9, createdAt: t0, updatedAt: t0 + 9000 });
    db.close();

    await setupAgent("alice");
    const config = makeConfig();
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_start_agent", { name: "alice" });
    await client.send("cello_use_agent", { name: "alice" });

    type Entry = { sessionId: string; counterpartyPubkey: string; status: string; category: string; messageCount: number; interruptedAt: string | null };
    type Res = { ok: boolean; filter: string; limit: number; totalMatched: number; sessions: Entry[] };
    const cp = (r: Res) => r.sessions.map((s) => s.counterpartyPubkey).sort();

    // DEFAULT = open: the active(→resumable) + the interrupted-with-messages. NOT sealed, NOT the
    // failed 0-message init, NOT bob's.
    const def = await client.send("cello_list_sessions") as Res;
    expect(def.ok).toBe(true);
    expect(def.filter).toBe("open");
    expect(cp(def)).toEqual(["cpActive", "cpIntr"].sort());
    expect(def.sessions.every((s) => s.category === "open")).toBe(true);
    // newest-updated first
    const ms = def.sessions.map((s) => Date.parse(s.updatedAt as unknown as string));
    expect(ms).toEqual([...ms].sort((a, b) => b - a));

    // failed: ONLY the 0-message interrupted init.
    const failed = await client.send("cello_list_sessions", { filter: "failed" }) as Res;
    expect(cp(failed)).toEqual(["cpFailed"]);
    expect(failed.sessions[0].category).toBe("failed");

    // closed: ONLY the sealed one.
    const closed = await client.send("cello_list_sessions", { filter: "closed" }) as Res;
    expect(cp(closed)).toEqual(["cpSealed"]);
    expect(closed.sessions[0].category).toBe("closed");

    // all: every one of alice's four, bob's still excluded.
    const all = await client.send("cello_list_sessions", { filter: "all" }) as Res;
    expect(cp(all)).toEqual(["cpActive", "cpFailed", "cpIntr", "cpSealed"].sort());
    expect(all.sessions.some((s) => s.counterpartyPubkey === "cpBob")).toBe(false);
    expect(all.totalMatched).toBe(4);

    // limit: caps the returned rows but reports the true match count.
    const limited = await client.send("cello_list_sessions", { filter: "all", limit: 2 }) as Res;
    expect(limited.sessions.length).toBe(2);
    expect(limited.totalMatched).toBe(4);
  });

  it("LIST-4: returns an empty sessions array for a current agent with no sessions", async () => {
    await setupAgent("alice");
    const config = makeConfig();
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);
    await client.send("cello_start_agent", { name: "alice" });
    await client.send("cello_use_agent", { name: "alice" });

    const res = await client.send("cello_list_sessions") as { ok: boolean; sessions: unknown[] };
    expect(res.ok).toBe(true);
    expect(Array.isArray(res.sessions)).toBe(true);
    expect(res.sessions).toHaveLength(0);
  });
});
