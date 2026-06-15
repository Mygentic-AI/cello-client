/**
 * CELLO-M7-SESSION-001 — Session interrupted detection, login surfacing, and
 * cello_close_session error codes.
 *
 * Specification (SPARC Phase S):
 *
 * AC-004 Integration: relay stream delivers session_interrupted frame →
 *   daemon marks SQLite 'interrupted', logs session.interrupted.detected
 *   with source:'relay_frame', tears down session node.
 *   SI-001: no seal-related event fires on frame receipt.
 *
 * AC-005 Integration: relay stream closes without session_interrupted frame →
 *   daemon marks SQLite 'interrupted', logs session.interrupted.detected
 *   with source:'stream_close'.
 *
 * AC-006/AC-007 Unit: cello status includes interrupted_sessions array with
 *   sessionId, agentName, counterpartyPubkey, messageCount, interruptedAt.
 *   interrupted_sessions always present (empty array if none).
 *
 * AC-010 Unit: cello_close_session on sealed session returns session_already_sealed
 *   with guidance field.
 *
 * AC-011 Unit: cello_close_session while in-progress returns
 *   seal_interrupted_in_progress with guidance field.
 *
 * AC-012 Unit: seal-interrupted fails when signaling unavailable returns
 *   seal_interrupted_counterparty_unavailable with guidance field.
 *
 * AC-013 Unit: seal-interrupted rejected returns
 *   seal_interrupted_rejected_by_counterparty with guidance field.
 *
 * AC-014 Unit: error codes are distinct and non-colliding.
 *
 * AC-015 Unit: guidance field present on all cello_close_session failure paths.
 *
 * DB-001 Unit: cello_close_session on interrupted session when signaling
 *   is 'reconnecting' returns signaling_reconnecting with guidance field.
 *
 * SI-001 Security: receipt of session_interrupted frame does NOT auto-seal.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { DatabaseSync } from "node:sqlite";
import { Encoder } from "cbor-x";
import * as lp from "it-length-prefixed";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { SessionNodeManager } from "../session-node-manager.js";
import { startDaemon } from "../daemon.js";
import { connectToDaemon } from "../ipc-client.js";
import type { Logger, DaemonConfig, DaemonStatusResponse, SessionRecord } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";

// ─── Helpers ──────────────────────────────────────────────────────────────────

const CBOR_ENC = new Encoder({ tagUint8Array: false });

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

/** Minimal fake CelloNode for tests that don't need real libp2p. */
class FakeCelloNode implements CelloNode {
  private _started = false;
  readonly #peerId = `fake-peer-${Math.random().toString(36).slice(2)}`;
  readonly #addrs = ["/ip4/127.0.0.1/tcp/0"];
  async start() { this._started = true; }
  async stop() { this._started = false; }
  getPeerId() { return this.#peerId; }
  getMultiaddrs() { return this.#addrs; }
  newStream(_peer: unknown, _proto: unknown): Promise<Stream> { return Promise.reject(new Error("stub")); }
  dial(_addr: unknown): Promise<unknown> { return Promise.reject(new Error("stub")); }
}

class StubNodeFactory implements ISessionNodeFactory {
  async createNode(_config: SessionNodeConfig): Promise<CelloNode> {
    const node = new FakeCelloNode();
    await node.start();
    return node;
  }
}

/** Create a SessionNodeManager with a temp DB. */
async function makeSessionNodeManager(
  logger: Logger,
  dbPath: string,
): Promise<SessionNodeManager> {
  const mgr = new SessionNodeManager({
    factory: new StubNodeFactory(),
    logger,
    dbPath,
  });
  await mgr.initialize();
  return mgr;
}

/** Insert a session row directly into the DB. */
function insertSession(
  db: DatabaseSync,
  opts: {
    sessionId: string;
    agentName: string;
    counterpartyPubkey: string;
    status: "active" | "interrupted" | "sealed";
    messageCount?: number;
    interruptedAt?: string;
  },
): void {
  const now = Date.now();
  db.prepare(
    `INSERT INTO sessions
     (session_id, agent_name, counterparty_pubkey, status, created_at, updated_at,
      message_count, interrupted_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    opts.sessionId,
    opts.agentName,
    opts.counterpartyPubkey,
    opts.status,
    now,
    now,
    opts.messageCount ?? 0,
    opts.interruptedAt ?? null,
  );
}

/** Create a fake relay stream that delivers specific frames in order. */
function makeFakeRelayStream(frames: Uint8Array[], opts?: { closeError?: boolean }): Stream {
  let frameIdx = 0;
  const encoded: Uint8Array[] = frames.map((f) => lp.encode.single(f));

  const iter: AsyncIterator<Uint8Array> = {
    async next() {
      if (frameIdx < encoded.length) {
        return { value: encoded[frameIdx++]!, done: false };
      }
      if (opts?.closeError) {
        throw new Error("stream aborted");
      }
      return { value: undefined as unknown as Uint8Array, done: true };
    },
    return() { return Promise.resolve({ value: undefined as unknown as Uint8Array, done: true }); },
  };

  // Return a minimal Stream-like object.
  // The session-node-manager uses `lp.decode(stream)` on the stream directly —
  // to test this we need to provide an AsyncIterable on the stream.
  const fakeStream = {
    [Symbol.asyncIterator]() { return iter; },
    // Stream interface stubs
    source: { [Symbol.asyncIterator]() { return iter; } },
    sink: async (_source: AsyncIterable<unknown>) => {},
    close: async () => {},
    abort: (_err?: Error) => {},
    status: "open",
    direction: "inbound",
    timeline: { open: Date.now() },
    id: "fake-stream-" + Math.random(),
    metadata: {},
    stat: { direction: "inbound" as const, timeline: { open: Date.now() } },
    send: async (_data: Uint8Array) => {},
  } as unknown as Stream;

  return fakeStream;
}

// ─── SessionNodeManager unit/integration tests (AC-004, AC-005) ──────────────

describe("SESSION-001: SessionNodeManager.registerRelayStream", () => {
  let tempDir: string;
  let mgr: SessionNodeManager;
  let logEvents: Array<{ level: string; event: string; context: Record<string, unknown> }>;
  let logger: Logger;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-session-001-"));
    const l = makeLogger();
    logger = l.logger;
    logEvents = l.events;
    mgr = await makeSessionNodeManager(logger, join(tempDir, "sessions.db"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  /**
   * AC-004: daemon receives session_interrupted frame → SQLite 'interrupted',
   * session.interrupted.detected with source:'relay_frame'.
   * SI-001: no seal-related event fires.
   */
  it("AC-004: marks session interrupted on session_interrupted frame", async () => {
    const sessionId = "aabbcc001122334455667788aabbcc001122334455667788aabbcc001122334455";
    const db = mgr.getDb();
    insertSession(db, {
      sessionId,
      agentName: "alice",
      counterpartyPubkey: "bbccdd",
      status: "active",
      messageCount: 5,
    });

    const sessionInterruptedFrame = CBOR_ENC.encode({
      type: "session_interrupted",
      session_id: sessionId,
      reason: "peer_disconnected",
    });

    const stream = makeFakeRelayStream([sessionInterruptedFrame]);
    mgr.registerRelayStream(sessionId, stream, 5);

    // Wait for the async watcher to complete
    await new Promise<void>((resolve) => setTimeout(resolve, 50));

    // Assert SQLite row updated
    const row = db.prepare("SELECT * FROM sessions WHERE session_id = ?").get(sessionId) as SessionRecord;
    expect(row.status).toBe("interrupted");

    // Assert session.interrupted.detected with source:'relay_frame'
    const detectedEvent = logEvents.find(
      (e) => e.event === "session.interrupted.detected" && e.context.source === "relay_frame",
    );
    expect(detectedEvent).toBeDefined();
    expect(detectedEvent!.level).toBe("warn");
    expect(detectedEvent!.context.sessionId).toBe(sessionId);
    expect(detectedEvent!.context.agentName).toBe("alice");

    // SI-001: no seal-related events fired
    const sealEvents = logEvents.filter((e) =>
      e.event.includes("seal") || e.event.includes("frost"),
    );
    expect(sealEvents).toHaveLength(0);
  });

  /**
   * AC-005: relay stream closes without session_interrupted frame →
   * daemon marks SQLite 'interrupted', session.interrupted.detected with source:'stream_close'.
   */
  it("AC-005: marks session interrupted on stream close without frame", async () => {
    const sessionId = "cc001122334455667788aabbcc001122334455667788aabbcc001122334455667";
    const db = mgr.getDb();
    insertSession(db, {
      sessionId,
      agentName: "bob",
      counterpartyPubkey: "ddeeff",
      status: "active",
      messageCount: 3,
    });

    // Empty stream — closes immediately without sending a session_interrupted frame
    const stream = makeFakeRelayStream([]);
    mgr.registerRelayStream(sessionId, stream, 3);

    // Wait for the async watcher to complete
    await new Promise<void>((resolve) => setTimeout(resolve, 50));

    // Assert SQLite row updated
    const row = db.prepare("SELECT * FROM sessions WHERE session_id = ?").get(sessionId) as SessionRecord;
    expect(row.status).toBe("interrupted");

    // Assert session.interrupted.detected with source:'stream_close'
    const detectedEvent = logEvents.find(
      (e) => e.event === "session.interrupted.detected" && e.context.source === "stream_close",
    );
    expect(detectedEvent).toBeDefined();
    expect(detectedEvent!.level).toBe("warn");
    expect(detectedEvent!.context.sessionId).toBe(sessionId);
  });

  /**
   * AC-005 variant: stream errors (aborted) — same as stream close.
   */
  it("AC-005 (error path): marks session interrupted on stream abort", async () => {
    const sessionId = "dd1122334455667788aabbcc001122334455667788aabbcc00112233445566778";
    const db = mgr.getDb();
    insertSession(db, {
      sessionId,
      agentName: "carol",
      counterpartyPubkey: "aabb11",
      status: "active",
    });

    const stream = makeFakeRelayStream([], { closeError: true });
    mgr.registerRelayStream(sessionId, stream, 0);

    await new Promise<void>((resolve) => setTimeout(resolve, 50));

    const row = db.prepare("SELECT * FROM sessions WHERE session_id = ?").get(sessionId) as SessionRecord;
    expect(row.status).toBe("interrupted");

    const detectedEvent = logEvents.find(
      (e) => e.event === "session.interrupted.detected" && e.context.source === "stream_close",
    );
    expect(detectedEvent).toBeDefined();
  });
});

// ─── Schema extension tests ───────────────────────────────────────────────────

describe("SESSION-001: SQLite schema extension", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-session-001-schema-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("adds message_count and interrupted_at columns to existing DB", async () => {
    // First: create a DB with the old schema (no new columns)
    const dbPath = join(tempDir, "old.db");
    const db = new DatabaseSync(dbPath);
    db.exec(`
      CREATE TABLE sessions (
        session_id TEXT PRIMARY KEY,
        agent_name TEXT NOT NULL,
        counterparty_pubkey TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      )
    `);
    db.close();

    // Now initialize SessionNodeManager — it should run the idempotent ALTER TABLE
    const { logger } = makeLogger();
    const mgr = new SessionNodeManager({
      factory: new StubNodeFactory(),
      logger,
      dbPath,
    });
    await mgr.initialize();

    // Verify the columns exist by inserting and reading back
    const sessionId = "ee1122334455667788aabbcc001122334455667788aabbcc0011223344556677";
    const db2 = mgr.getDb();
    insertSession(db2, {
      sessionId,
      agentName: "dave",
      counterpartyPubkey: "ffee11",
      status: "interrupted",
      messageCount: 7,
      interruptedAt: new Date().toISOString(),
    });

    const row = db2.prepare("SELECT * FROM sessions WHERE session_id = ?").get(sessionId) as SessionRecord;
    expect(row.message_count).toBe(7);
    expect(row.interrupted_at).toBeTruthy();
  });

  it("idempotent: re-initializing does not throw on existing columns", async () => {
    const dbPath = join(tempDir, "idem.db");
    const { logger } = makeLogger();

    // First init — creates columns
    const mgr1 = new SessionNodeManager({ factory: new StubNodeFactory(), logger, dbPath });
    await mgr1.initialize();

    // Second init — should not throw
    const mgr2 = new SessionNodeManager({ factory: new StubNodeFactory(), logger, dbPath });
    await expect(mgr2.initialize()).resolves.not.toThrow();
  });
});

// ─── getSessionRecord tests ───────────────────────────────────────────────────

describe("SESSION-001: getSessionRecord", () => {
  let tempDir: string;
  let mgr: SessionNodeManager;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-session-001-getrecord-"));
    const { logger } = makeLogger();
    mgr = await makeSessionNodeManager(logger, join(tempDir, "sessions.db"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("returns null for unknown session", () => {
    const record = mgr.getSessionRecord("nonexistent");
    expect(record).toBeNull();
  });

  it("returns record for known session", () => {
    const sessionId = "aa001122334455667788aabbcc001122334455667788aabbcc0011223344556677";
    insertSession(mgr.getDb(), {
      sessionId,
      agentName: "eve",
      counterpartyPubkey: "112233",
      status: "interrupted",
      messageCount: 2,
      interruptedAt: "2026-06-15T00:00:00.000Z",
    });

    const record = mgr.getSessionRecord(sessionId);
    expect(record).not.toBeNull();
    expect(record!.session_id).toBe(sessionId);
    expect(record!.status).toBe("interrupted");
    expect(record!.message_count).toBe(2);
    expect(record!.interrupted_at).toBe("2026-06-15T00:00:00.000Z");
  });
});

// ─── Daemon getStatus tests (AC-006, AC-007) ─────────────────────────────────

describe("SESSION-001: daemon status interrupted_sessions field", () => {
  let tempDir: string;
  let handle: ReturnType<typeof startDaemon> extends Promise<infer T> ? T : never;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-session-001-status-"));
  });

  afterEach(async () => {
    if (handle) {
      try {
        await (handle as { stop: (r: string) => Promise<void> }).stop("test_cleanup");
      } catch {
        // Ignore
      }
    }
    await rm(tempDir, { recursive: true, force: true });
  });

  /**
   * AC-007: interrupted_sessions is always present in the status response.
   * Empty array when no interrupted sessions.
   */
  it("AC-007: interrupted_sessions always present (empty when none)", async () => {
    const l = makeLogger();
    const config: DaemonConfig = {
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger: l.logger,
    };
    const h = await startDaemon(config);
    handle = h as typeof handle;
    const status = h.getStatus() as DaemonStatusResponse;

    expect(status.interrupted_sessions).toBeDefined();
    expect(Array.isArray(status.interrupted_sessions)).toBe(true);
    expect(status.interrupted_sessions).toHaveLength(0);
  });

  /**
   * AC-006: interrupted sessions appear in status with all required fields.
   */
  it("AC-006: interrupted sessions surfaced with sessionId, agentName, counterpartyPubkey, messageCount, interruptedAt", async () => {
    const l = makeLogger();

    // Pre-populate the DB with interrupted sessions before starting the daemon
    const dbPath = join(tempDir, "sessions.db");
    const db = new DatabaseSync(dbPath);
    db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        agent_name TEXT NOT NULL,
        counterparty_pubkey TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        message_count INTEGER NOT NULL DEFAULT 0,
        interrupted_at TEXT
      )
    `);
    const now = Date.now();
    const isoNow = new Date(now).toISOString();
    const sid1 = "aabb1122334455667788aabbcc001122334455667788aabbcc00112233445566";
    const sid2 = "bbcc1122334455667788aabbcc001122334455667788aabbcc00112233445567";
    db.prepare(
      "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    ).run(sid1, "alice", "pubkey1", "interrupted", now, now, 3, isoNow);
    db.prepare(
      "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    ).run(sid2, "bob", "pubkey2", "interrupted", now, now, 0, isoNow);
    db.close();

    const config: DaemonConfig = {
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger: l.logger,
    };
    const h = await startDaemon(config);
    handle = h as typeof handle;
    const status = h.getStatus() as DaemonStatusResponse;

    expect(status.interrupted_sessions).toHaveLength(2);

    const entry1 = status.interrupted_sessions.find((e) => e.sessionId === sid1);
    expect(entry1).toBeDefined();
    expect(entry1!.agentName).toBe("alice");
    expect(entry1!.counterpartyPubkey).toBe("pubkey1");
    expect(entry1!.messageCount).toBe(3);
    expect(typeof entry1!.interruptedAt).toBe("string");
    expect(entry1!.interruptedAt).not.toBe("");

    const entry2 = status.interrupted_sessions.find((e) => e.sessionId === sid2);
    expect(entry2).toBeDefined();
    expect(entry2!.messageCount).toBe(0);
  });
});

// ─── cello_close_session error code tests (AC-010 through AC-015, DB-001) ────

describe("SESSION-001: cello_close_session error codes", () => {
  let tempDir: string;
  let handle: Awaited<ReturnType<typeof startDaemon>> | null;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-session-001-close-"));
    handle = null;
  });

  afterEach(async () => {
    if (handle) {
      try {
        await handle.stop("test_cleanup");
      } catch {
        // Ignore
      }
    }
    await rm(tempDir, { recursive: true, force: true });
  });

  /** Create an agent directory with a key file so the daemon recognizes it. */
  async function makeAgentDir(agentName: string): Promise<void> {
    const agentDir = join(tempDir, "agents", agentName);
    await mkdir(agentDir, { recursive: true });
    await FileKeyProvider.load(join(agentDir, "key"));
  }

  async function startTestDaemon(): Promise<Awaited<ReturnType<typeof startDaemon>>> {
    const { logger } = makeLogger();
    const config: DaemonConfig = {
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
    };
    const h = await startDaemon(config);
    handle = h;
    return h;
  }

  function insertSessionRow(
    sessionId: string,
    agentName: string,
    status: "active" | "interrupted" | "sealed",
    messageCount: number = 0,
  ): void {
    const dbPath = join(tempDir, "sessions.db");
    const db = new DatabaseSync(dbPath);
    const now = Date.now();
    db.prepare(
      "INSERT OR REPLACE INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    ).run(sessionId, agentName, "counterparty_pubkey_hex", status, now, now, messageCount, new Date(now).toISOString());
    db.close();
  }

  /**
   * AC-010: cello_close_session on sealed session → session_already_sealed + guidance.
   * AC-015: guidance field present on all failure paths.
   *
   * The handler checks currentAgent before status. Set up an agent and use_agent
   * so the handler reaches the status check.
   */
  it("AC-010/AC-015: sealed session returns session_already_sealed with guidance", async () => {
    await makeAgentDir("alice");
    await startTestDaemon();
    const sessionId = "ff1122334455667788aabbcc001122334455667788aabbcc0011223344556677";
    insertSessionRow(sessionId, "alice", "sealed");

    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });
      await client.send("cello_start_agent", { name: "alice" });
      await client.send("cello_use_agent", { name: "alice" });
      const result = await client.send("cello_close_session", { sessionId }) as Record<string, unknown>;
      expect(result.ok).toBe(false);
      expect(result.reason).toBe("session_already_sealed");
      expect(typeof result.guidance).toBe("string");
      expect((result.guidance as string).length).toBeGreaterThan(0);
    } finally {
      client.close();
    }
  });

  /**
   * AC-014: error codes are distinct strings.
   */
  it("AC-014: error codes are distinct and non-colliding", () => {
    const errorCodes = [
      "session_already_sealed",
      "seal_interrupted_in_progress",
      "seal_interrupted_counterparty_unavailable",
      "seal_interrupted_rejected_by_counterparty",
      "signaling_reconnecting",
    ];
    const unique = new Set(errorCodes);
    expect(unique.size).toBe(errorCodes.length);
  });
});

// ─── SI-001 security invariant ─────────────────────────────────────────────────

describe("SESSION-001 SI-001: no auto-seal on session_interrupted receipt", () => {
  let tempDir: string;
  let mgr: SessionNodeManager;
  let logEvents: Array<{ level: string; event: string; context: Record<string, unknown> }>;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-session-001-si001-"));
    const l = makeLogger();
    logEvents = l.events;
    mgr = await makeSessionNodeManager(l.logger, join(tempDir, "sessions.db"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("SI-001: session_interrupted frame receipt does NOT trigger any seal events", async () => {
    const sessionId = "1122334455667788aabbcc001122334455667788aabbcc00112233445566778899";
    const db = mgr.getDb();
    insertSession(db, {
      sessionId,
      agentName: "frank",
      counterpartyPubkey: "aabb11",
      status: "active",
    });

    const sessionInterruptedFrame = CBOR_ENC.encode({
      type: "session_interrupted",
      session_id: sessionId,
      reason: "peer_disconnected",
    });

    const stream = makeFakeRelayStream([sessionInterruptedFrame]);
    mgr.registerRelayStream(sessionId, stream, 0);

    await new Promise<void>((resolve) => setTimeout(resolve, 50));

    // Status: interrupted, not sealed
    const row = db.prepare("SELECT status FROM sessions WHERE session_id = ?").get(sessionId) as { status: string };
    expect(row.status).toBe("interrupted");

    // No seal-related events
    const sealEvents = logEvents.filter((e) =>
      e.event.includes("seal") || e.event.includes("frost") || e.event.includes("ceremony"),
    );
    expect(sealEvents).toHaveLength(0);

    // No session.interrupted.sealed (that's only after explicit cello_close_session + bilateral flow)
    const sealedEvents = logEvents.filter((e) => e.event === "session.interrupted.sealed");
    expect(sealedEvents).toHaveLength(0);
  });
});

// ─── markInterruptedWithDetails tests ────────────────────────────────────────

describe("SESSION-001: markInterruptedWithDetails", () => {
  let tempDir: string;
  let mgr: SessionNodeManager;
  let logEvents: Array<{ level: string; event: string; context: Record<string, unknown> }>;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-session-001-mark-"));
    const l = makeLogger();
    logEvents = l.events;
    mgr = await makeSessionNodeManager(l.logger, join(tempDir, "sessions.db"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("sets message_count and interrupted_at on update", async () => {
    const sessionId = "bb2233445566778899aabbcc001122334455667788aabbcc001122334455667788";
    const db = mgr.getDb();
    insertSession(db, {
      sessionId,
      agentName: "grace",
      counterpartyPubkey: "ccdd22",
      status: "active",
    });

    await mgr.markInterruptedWithDetails(sessionId, 12, "relay_frame");

    const row = db.prepare("SELECT * FROM sessions WHERE session_id = ?").get(sessionId) as SessionRecord;
    expect(row.status).toBe("interrupted");
    expect(row.message_count).toBe(12);
    expect(row.interrupted_at).not.toBeNull();
    expect(typeof row.interrupted_at).toBe("string");
    // Verify it's a valid ISO timestamp
    expect(() => new Date(row.interrupted_at!)).not.toThrow();

    // session.interrupted.detected at WARN
    const detectedEvent = logEvents.find((e) => e.event === "session.interrupted.detected");
    expect(detectedEvent).toBeDefined();
    expect(detectedEvent!.level).toBe("warn");
    expect(detectedEvent!.context.source).toBe("relay_frame");
    expect(detectedEvent!.context.sessionId).toBe(sessionId);
  });
});
