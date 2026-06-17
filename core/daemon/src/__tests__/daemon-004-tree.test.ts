/**
 * CELLO-M7-DAEMON-004 — SessionNodeManager: daemon-owned tree persistence,
 * restart survival, content send (dead-stream contract), and content ingest.
 *
 * Specification (SPARC Phase S):
 *
 * AC-002 (mechanism, at the manager layer): appendSessionLeaf advances the
 *   persisted per-session tree; getSessionTreeRootHex reflects every appended leaf.
 *   session.tree.appended fires once per leaf with sessionId, leafIndex, newRootHex.
 *
 * AC-007: the per-session tree is persisted to SQLite. A fresh SessionNodeManager
 *   opened on the same DB reconstructs the tree with the same leaves and the same
 *   root — the transcript survives the daemon restart boundary.
 *
 * AC-005 (mechanism): sendContent over a DEAD session stream (newStream rejects)
 *   returns a named, diagnosable failure — never a silent success. It does NOT
 *   mutate the tree (no desync).
 *
 * AC-001 receive half (mechanism): ingestReceivedContent cross-checks the content
 *   against its hash, appends the verified leaf to the daemon-owned tree, buffers
 *   the content for cello_receive, and fires session.content.received. A hash
 *   MISMATCH (genuine tamper) is rejected: no append, no buffer, warn event.
 *
 * Crypto refs: RFC 6962 §2.1, FIPS 180-4.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import * as lp from "it-length-prefixed";
import { decode as cborDecode } from "cbor-x";
import { SessionNodeManager } from "../session-node-manager.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { Logger } from "../types.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";

interface LogEvent { level: string; event: string; context: Record<string, unknown> }

function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const logger: Logger = {
    debug(event, context) { events.push({ level: "debug", event, context }); },
    info(event, context) { events.push({ level: "info", event, context }); },
    warn(event, context) { events.push({ level: "warn", event, context }); },
    error(event, context) { events.push({ level: "error", event, context }); },
  };
  return { logger, events };
}

function msgLeafHash(content: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(new Uint8Array([0x00])).update(content).digest());
}

/** A configurable fake node: newStream either rejects (dead) or returns a capturing stream. */
class ConfigurableFakeNode implements Partial<CelloNode> {
  sent: Uint8Array[] = [];
  constructor(private opts: { newStreamFails?: boolean } = {}) {}
  readonly #peerId = `fake-${Math.random().toString(36).slice(2)}`;
  async start(): Promise<void> {}
  async stop(): Promise<void> {}
  getPeerId(): string { return this.#peerId; }
  listenAddresses(): string[] { return ["/ip4/127.0.0.1/tcp/0"]; }
  async dial(_addr: string): Promise<{ peerId: string }> { return { peerId: "remote" }; }
  async handle(_p: string, _h: unknown): Promise<void> {}
  getProtocols(): string[] { return []; }
  getConnections(): Array<{ peerId: string; encryption: string | undefined }> { return []; }
  onPeerConnect(_h: (p: string) => void): void {}
  onPeerDisconnect(_h: (p: string) => void): void {}
  async newStream(_peer: string, _proto: string): Promise<Stream> {
    if (this.opts.newStreamFails) throw new Error("connection_lost: stream dead");
    const sink = this.sent;
    const stream = {
      send(data: Uint8Array) { sink.push(data); },
      async close() {},
      abort() {},
      status: "open",
    } as unknown as Stream;
    return stream;
  }
}

class ControlledFactory implements ISessionNodeFactory {
  constructor(private node: CelloNode) {}
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> { return this.node; }
}

/**
 * A loopback node: the content-stream handler registered via handle() is invoked
 * with whatever newStream().send() delivers, so a sendContent on this node is
 * cross-checked + ingested by the SAME manager's content handler. This exercises
 * the real lp-framed CBOR content_frame encode → decode path (including the
 * correlationId field), without a second OS process — used only to verify the
 * in-process mechanism (the cross-PROCESS gate is E2E-001 under CELLO_E2E_LIVE).
 */
class LoopbackFakeNode implements Partial<CelloNode> {
  #handler: ((stream: Stream) => void) | null = null;
  readonly #peerId = `lb-${Math.random().toString(36).slice(2)}`;
  async start(): Promise<void> {}
  async stop(): Promise<void> {}
  getPeerId(): string { return this.#peerId; }
  listenAddresses(): string[] { return ["/ip4/127.0.0.1/tcp/0"]; }
  async dial(_addr: string): Promise<{ peerId: string }> { return { peerId: "remote" }; }
  async handle(_p: string, h: (stream: Stream) => void): Promise<void> { this.#handler = h; }
  getProtocols(): string[] { return []; }
  getConnections(): Array<{ peerId: string; encryption: string | undefined }> { return []; }
  onPeerConnect(_h: (p: string) => void): void {}
  onPeerDisconnect(_h: (p: string) => void): void {}
  async newStream(_peer: string, _proto: string): Promise<Stream> {
    const handler = this.#handler;
    const stream = {
      send(data: unknown) {
        const chunks = [data];
        const inbound = {
          [Symbol.asyncIterator]() {
            let i = 0;
            return {
              next(): Promise<IteratorResult<unknown>> {
                return i < chunks.length
                  ? Promise.resolve({ value: chunks[i++], done: false })
                  : Promise.resolve({ value: undefined, done: true });
              },
            };
          },
        } as unknown as Stream;
        if (handler) handler(inbound);
      },
      async close() {},
      abort() {},
      status: "open",
    } as unknown as Stream;
    return stream;
  }
}

async function makeManager(logger: Logger, dbPath: string, node: CelloNode): Promise<SessionNodeManager> {
  const mgr = new SessionNodeManager({ factory: new ControlledFactory(node), logger, dbPath });
  await mgr.initialize();
  return mgr;
}

describe("DAEMON-004: SessionNodeManager tree persistence", () => {
  let tempDir: string;
  let logger: Logger;
  let events: LogEvent[];

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-d004-tree-"));
    const l = makeLogger();
    logger = l.logger;
    events = l.events;
  });
  afterEach(async () => { await rm(tempDir, { recursive: true, force: true }); });

  it("AC-002: appendSessionLeaf advances the root and fires session.tree.appended per leaf", async () => {
    const mgr = await makeManager(logger, join(tempDir, "s.db"), new ConfigurableFakeNode());
    const sid = "a".repeat(64);
    const empty = mgr.getSessionTreeRootHex(sid);

    const h1 = Buffer.from(msgLeafHash(new TextEncoder().encode("one"))).toString("hex");
    const r1 = mgr.appendSessionLeaf(sid, "msg", h1, "corr-1");
    expect(r1.leafIndex).toBe(0);
    expect(r1.newRootHex).not.toBe(empty);
    expect(mgr.getSessionTreeRootHex(sid)).toBe(r1.newRootHex);

    const h2 = Buffer.from(msgLeafHash(new TextEncoder().encode("two"))).toString("hex");
    const r2 = mgr.appendSessionLeaf(sid, "msg", h2, "corr-1");
    expect(r2.leafIndex).toBe(1);

    const appended = events.filter((e) => e.event === "session.tree.appended");
    expect(appended).toHaveLength(2);
    expect(appended[0].context.sessionId).toBe(sid);
    expect(appended[0].context.leafIndex).toBe(0);
    expect(appended[0].context.newRootHex).toBe(r1.newRootHex);
    expect(appended[1].context.leafIndex).toBe(1);
  });

  it("AC-007: the tree survives a restart — a fresh manager on the same DB reloads the same root", async () => {
    const dbPath = join(tempDir, "restart.db");
    const sid = "b".repeat(64);
    const mgr1 = await makeManager(logger, dbPath, new ConfigurableFakeNode());
    for (const c of ["m1", "m2", "m3"]) {
      mgr1.appendSessionLeaf(sid, "msg", Buffer.from(msgLeafHash(new TextEncoder().encode(c))).toString("hex"));
    }
    const rootBefore = mgr1.getSessionTreeRootHex(sid);
    const sizeBefore = mgr1.getSessionTree(sid).size();

    // Simulate a restart: a brand-new manager instance over the same DB file.
    const mgr2 = await makeManager(makeLogger().logger, dbPath, new ConfigurableFakeNode());
    expect(mgr2.getSessionTree(sid).size()).toBe(sizeBefore);
    expect(mgr2.getSessionTreeRootHex(sid)).toBe(rootBefore);
  });

  it("AC-002: two managers fed the SAME ordered leaves report the SAME root", async () => {
    const mgrA = await makeManager(logger, join(tempDir, "A.db"), new ConfigurableFakeNode());
    const mgrB = await makeManager(makeLogger().logger, join(tempDir, "B.db"), new ConfigurableFakeNode());
    const sid = "c".repeat(64);
    for (const c of ["x", "y", "z", "w"]) {
      const h = Buffer.from(msgLeafHash(new TextEncoder().encode(c))).toString("hex");
      mgrA.appendSessionLeaf(sid, "msg", h);
      mgrB.appendSessionLeaf(sid, "msg", h);
    }
    expect(mgrA.getSessionTreeRootHex(sid)).toBe(mgrB.getSessionTreeRootHex(sid));
  });
});

describe("DAEMON-004: SessionNodeManager content send/receive", () => {
  let tempDir: string;
  let logger: Logger;
  let events: LogEvent[];
  const sid = "d".repeat(64);

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-d004-content-"));
    const l = makeLogger();
    logger = l.logger;
    events = l.events;
  });
  afterEach(async () => { await rm(tempDir, { recursive: true, force: true }); });

  it("AC-001 send: sendContent over a live stream sends a content_frame and reports ok", async () => {
    const node = new ConfigurableFakeNode();
    const mgr = await makeManager(logger, join(tempDir, "s.db"), node);
    await mgr.createSessionNode(sid, "alice", "bobpubkey", "bob-peer-id", "corr-1");
    const content = new TextEncoder().encode("hello");
    const contentHash = msgLeafHash(content);
    const res = await mgr.sendContent(sid, content, contentHash);
    expect(res.ok).toBe(true);
    expect(node.sent.length).toBe(1);
  });

  it("AC-005: sendContent over a DEAD stream returns a named failure and does NOT mutate the tree", async () => {
    const node = new ConfigurableFakeNode({ newStreamFails: true });
    const mgr = await makeManager(logger, join(tempDir, "s.db"), node);
    await mgr.createSessionNode(sid, "alice", "bobpubkey", "bob-peer-id", "corr-1");
    const rootBefore = mgr.getSessionTreeRootHex(sid);
    const content = new TextEncoder().encode("hello");
    const res = await mgr.sendContent(sid, content, msgLeafHash(content));
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(typeof res.reason).toBe("string");
      expect(res.reason.length).toBeGreaterThan(0);
      // error.message is extracted — never [object Object]
      expect(res.error).not.toContain("[object Object]");
      expect(res.error).toContain("stream dead");
    }
    // No tree mutation on a failed send.
    expect(mgr.getSessionTreeRootHex(sid)).toBe(rootBefore);
  });

  it("finding #2: appendSessionLeaf keeps sessions.message_count synced to the tree size", async () => {
    const mgr = await makeManager(logger, join(tempDir, "s.db"), new ConfigurableFakeNode());
    await mgr.createSessionNode(sid, "alice", "bobpubkey", "bob-peer-id", "corr-1");
    expect(mgr.getSessionRecord(sid)!.message_count ?? 0).toBe(0);

    // A sent leaf advances message_count.
    mgr.appendSessionLeaf(sid, "msg", Buffer.from(msgLeafHash(new TextEncoder().encode("a"))).toString("hex"));
    expect(mgr.getSessionRecord(sid)!.message_count).toBe(1);

    // A received leaf (via ingest) also advances it — column tracks the tree, so a
    // post-active-messaging seal binds the real transcript length, not 0.
    const content = new TextEncoder().encode("b");
    mgr.ingestReceivedContent(sid, content, msgLeafHash(content));
    expect(mgr.getSessionRecord(sid)!.message_count).toBe(2);
    expect(mgr.getSessionTree(sid).size()).toBe(2);
  });

  it("AC-001 receive: ingestReceivedContent cross-checks, appends the leaf, buffers, fires session.content.received", async () => {
    const mgr = await makeManager(logger, join(tempDir, "s.db"), new ConfigurableFakeNode());
    await mgr.createSessionNode(sid, "alice", "bobpubkey", "bob-peer-id", "corr-1");
    const content = new TextEncoder().encode("from-bob");
    const contentHash = msgLeafHash(content);
    const rootBefore = mgr.getSessionTreeRootHex(sid);

    const res = mgr.ingestReceivedContent(sid, content, contentHash);
    expect(res.ok).toBe(true);
    expect(mgr.getSessionTreeRootHex(sid)).not.toBe(rootBefore);

    const recvEvent = events.find((e) => e.event === "session.content.received");
    expect(recvEvent).toBeDefined();
    expect(recvEvent!.context.sessionId).toBe(sid);
    expect(recvEvent!.context.senderPubkey).toBe("bobpubkey");

    const buffered = mgr.takeReceivedContent(sid);
    expect(buffered).not.toBeNull();
    expect(Buffer.from(buffered!.contentHex, "hex").toString()).toBe("from-bob");
    // FIFO drained
    expect(mgr.takeReceivedContent(sid)).toBeNull();
  });

  it("AC-001 receive (tamper): a content_hash MISMATCH is rejected — no append, no buffer, warn event", async () => {
    const mgr = await makeManager(logger, join(tempDir, "s.db"), new ConfigurableFakeNode());
    await mgr.createSessionNode(sid, "alice", "bobpubkey", "bob-peer-id", "corr-1");
    const content = new TextEncoder().encode("real");
    const wrongHash = msgLeafHash(new TextEncoder().encode("tampered"));
    const rootBefore = mgr.getSessionTreeRootHex(sid);

    const res = mgr.ingestReceivedContent(sid, content, wrongHash);
    expect(res.ok).toBe(false);
    expect(mgr.getSessionTreeRootHex(sid)).toBe(rootBefore);
    expect(mgr.takeReceivedContent(sid)).toBeNull();
    const failEvent = events.find((e) => e.event === "session.content.cross_check.failed");
    expect(failEvent).toBeDefined();
    expect(failEvent!.level).toBe("warn");
  });

  // ── AC-001 finding: correlationId must be SHARED across the send/receive boundary ──
  it("AC-001 correlationId: sendContent stamps correlation_id into the content_frame", async () => {
    const node = new ConfigurableFakeNode();
    const mgr = await makeManager(logger, join(tempDir, "s.db"), node);
    await mgr.createSessionNode(sid, "alice", "bobpubkey", "bob-peer-id", "corr-1");
    const content = new TextEncoder().encode("hello");
    const correlationId = "flow-abc-123";
    const res = await mgr.sendContent(sid, content, msgLeafHash(content), correlationId);
    expect(res.ok).toBe(true);
    expect(node.sent.length).toBe(1);

    // Decode the lp-framed CBOR content_frame and assert the correlationId rode along.
    const sentChunk = node.sent[0];
    async function* source(): AsyncGenerator<Uint8Array> { yield sentChunk; }
    let frame: Record<string, unknown> | undefined;
    for await (const msg of lp.decode(source())) {
      const bytes = (msg as { subarray(): Uint8Array }).subarray();
      frame = cborDecode(bytes) as Record<string, unknown>;
      break;
    }
    expect(frame).toBeDefined();
    expect(frame!["type"]).toBe("content_frame");
    expect(frame!["correlation_id"]).toBe(correlationId);
  });

  it("AC-001 correlationId: ingestReceivedContent threads correlationId into received + appended events", () => {
    const mgr = new SessionNodeManager({ factory: new ControlledFactory(new ConfigurableFakeNode()), logger, dbPath: join(tempDir, "ci.db") });
    // initialize() is async but ingest does not require the standing receiver; run after init.
    return mgr.initialize().then(async () => {
      await mgr.createSessionNode(sid, "alice", "bobpubkey", "bob-peer-id", "corr-1");
      const content = new TextEncoder().encode("from-bob");
      const correlationId = "flow-xyz-789";
      mgr.ingestReceivedContent(sid, content, msgLeafHash(content), correlationId);
      const recv = events.find((e) => e.event === "session.content.received");
      expect(recv).toBeDefined();
      expect(recv!.context.correlationId).toBe(correlationId);
      const appended = events.find((e) => e.event === "session.tree.appended");
      expect(appended).toBeDefined();
      expect(appended!.context.correlationId).toBe(correlationId);
    });
  });

  it("AC-001 correlationId (round-trip): content sent over the stream is ingested with the SAME correlationId", async () => {
    const node = new LoopbackFakeNode();
    const mgr = await makeManager(logger, join(tempDir, "lb.db"), node as unknown as CelloNode);
    await mgr.createSessionNode(sid, "alice", "bobpubkey", "bob-peer-id", "corr-1");
    const content = new TextEncoder().encode("loopback-hi");
    const correlationId = "flow-roundtrip-1";
    const res = await mgr.sendContent(sid, content, msgLeafHash(content), correlationId);
    expect(res.ok).toBe(true);
    // The loopback delivers synchronously into the handler, which ingests async — drain.
    await new Promise((r) => setImmediate(r));

    const recv = events.find((e) => e.event === "session.content.received");
    expect(recv).toBeDefined();
    // The receiver shares the sender's correlationId — extracted from the frame, not minted.
    expect(recv!.context.correlationId).toBe(correlationId);
    const buffered = mgr.takeReceivedContent(sid);
    expect(buffered).not.toBeNull();
    expect(Buffer.from(buffered!.contentHex, "hex").toString()).toBe("loopback-hi");
  });

  // ── medium finding: in-memory tree + received-content maps must be evicted on teardown ──
  it("eviction: destroySessionNode clears the buffered received content (no plaintext retention)", async () => {
    const mgr = await makeManager(logger, join(tempDir, "ev.db"), new ConfigurableFakeNode());
    await mgr.createSessionNode(sid, "alice", "bobpubkey", "bob-peer-id", "corr-1");
    const content = new TextEncoder().encode("secret-payload");
    mgr.ingestReceivedContent(sid, content, msgLeafHash(content));
    const persistedRoot = mgr.getSessionTreeRootHex(sid);

    await mgr.destroySessionNode(sid, "sealed");

    // The in-memory plaintext buffer is gone after teardown.
    expect(mgr.takeReceivedContent(sid)).toBeNull();
    // But the durable transcript is intact — the tree reloads from SQLite with the
    // same root, proving eviction dropped only the in-memory cache, not durable state.
    expect(mgr.getSessionTreeRootHex(sid)).toBe(persistedRoot);
  });
});
