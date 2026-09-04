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

import { SESSION_CONTENT_ENCRYPTION_V1 } from "../content-encryption-status.js";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import * as lp from "it-length-prefixed";
import { decode as cborDecode } from "cbor-x";
// DOD-M15-FRAME-1 (review F6): the PRODUCTION encoder, imported rather than reconstructed. A local
// `new Encoder({ tagUint8Array: false })` got the byte fields right and still differed — `useRecords`
// defaults to true, so its frames went out as cbor-x record structures where production emits plain
// CBOR maps. Harmless here, and exactly the drift a hand-rolled copy invites. Importing the real one
// means the question cannot recur.
import { encodeCbor, buildStructure2, encodeStructure2 } from "@cello-protocol/protocol-types";
import { generateKeypair, sealSessionContent } from "@cello-protocol/crypto";
import { encodeStructure1 } from "@cello-protocol/protocol-types";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager } from "../session-node-manager.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { Logger } from "../types.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";
import { seedAgents, wireAgentKeyProviders } from "./helpers/seed-agents.js";

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
  getDialability(): { dialable: boolean; publicAddr: string | null } { return { dialable: false, publicAddr: null }; }
  onDialabilityChange(_l: (d: { dialable: boolean; publicAddr: string | null }) => void): () => void { return () => {}; }
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
  /**
   * DOD-M15-FRAME-1: the handler takes the SECOND argument the real transport passes.
   *
   * `CelloNode.handle` is `(stream, remotePeerId)` — `node.ts` supplies
   * `connection?.remotePeer?.toString()`, the Noise-authenticated transport identity. This fake
   * declared a single-argument handler, so every frame it delivered arrived with `remotePeerId`
   * undefined. That was invisible while nothing checked it; the content protocol now pins every
   * frame to the session's counterparty, and an absent identity is refused rather than waved
   * through — so the fake has to deliver what the real transport delivers, or it is testing a
   * transport that does not exist.
   */
  #handler: ((stream: Stream, remotePeerId?: string) => void) | null = null;
  readonly #peerId = `lb-${Math.random().toString(36).slice(2)}`;
  /** The peer id inbound frames are delivered as — the counterparty this session was created with. */
  deliverAs = "bob-peer-id";
  async start(): Promise<void> {}
  async stop(): Promise<void> {}
  getPeerId(): string { return this.#peerId; }
  listenAddresses(): string[] { return ["/ip4/127.0.0.1/tcp/0"]; }
  async dial(_addr: string): Promise<{ peerId: string }> { return { peerId: "remote" }; }
  async handle(_p: string, h: (stream: Stream, remotePeerId?: string) => void): Promise<void> { this.#handler = h; }
  getProtocols(): string[] { return []; }
  getConnections(): Array<{ peerId: string; encryption: string | undefined }> { return []; }
  onPeerConnect(_h: (p: string) => void): void {}
  onPeerDisconnect(_h: (p: string) => void): void {}
  getDialability(): { dialable: boolean; publicAddr: string | null } { return { dialable: false, publicAddr: null }; }
  onDialabilityChange(_l: (d: { dialable: boolean; publicAddr: string | null }) => void): () => void { return () => {}; }
  /**
   * DOD-M15-FRAME-1: deliver a HAND-BUILT frame straight to the registered handler.
   *
   * `sendContent` always populates `session_id`, so it can never produce the omission case an
   * attacker constructs by hand — and that case is exactly what the old `&&` check let through.
   * Testing it needs a way to put arbitrary bytes on the wire as a chosen peer.
   */
  deliverFrame(frame: Record<string, unknown>, fromPeerId: string): void {
    const handler = this.#handler;
    if (!handler) return;
    const chunks = [lp.encode.single(encodeCbor(frame))];
    const inbound = {
      [Symbol.asyncIterator]() {
        let i = 0;
        return { next(): Promise<IteratorResult<unknown>> {
          return i < chunks.length
            ? Promise.resolve({ value: chunks[i++], done: false })
            : Promise.resolve({ value: undefined, done: true });
        } };
      },
    } as unknown as Stream;
    handler(inbound, fromPeerId);
  }

  async newStream(_peer: string, _proto: string): Promise<Stream> {
    const handler = this.#handler;
    const deliverAs = this.deliverAs;
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
        if (handler) handler(inbound, deliverAs);
      },
      async close() {},
      abort() {},
      status: "open",
    } as unknown as Stream;
    return stream;
  }
}

async function makeManager(logger: Logger, dbPath: string, node: CelloNode): Promise<SessionNodeManager> {
  const mgr = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new ControlledFactory(node), logger, dbPath });
  await mgr.initialize();
  // DOD-AGENT-ID-JOINKEY-1: every test in this file drives the manager as "alice" — production
  // always has an `agents` row before a session exists, so seed one here rather than at every call site.
  await seedAgents(mgr.getDb(), ["alice"]);
  // DOD-M15-AUTHORSHIP-ABSENT-1: and production always has the key providers too. Without them the
  // manager cannot sign the Structure 1 that now rides on every content frame, so every send here
  // would be exercising the refusal path instead of the behaviour the test is named for.
  await wireAgentKeyProviders(mgr, mgr.getDb());
  return mgr;
}

/** Alice's own K_local pubkey, hex — what a counterparty on the other end of a LOOPBACK is. */
function alicePubkeyHex(mgr: SessionNodeManager): string {
  return (mgr.getDb()
    .prepare("SELECT k_local_pubkey FROM agents WHERE agent_name = ?")
    .get("alice") as { k_local_pubkey: string }).k_local_pubkey;
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
    const empty = mgr.getSessionTreeRootHex("alice", sid);

    const h1 = Buffer.from(msgLeafHash(new TextEncoder().encode("one"))).toString("hex");
    const r1 = mgr.appendSessionLeaf("alice", sid, "msg", h1, "corr-1");
    expect(r1.leafIndex).toBe(0);
    expect(r1.newRootHex).not.toBe(empty);
    expect(mgr.getSessionTreeRootHex("alice", sid)).toBe(r1.newRootHex);

    const h2 = Buffer.from(msgLeafHash(new TextEncoder().encode("two"))).toString("hex");
    const r2 = mgr.appendSessionLeaf("alice", sid, "msg", h2, "corr-1");
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
      mgr1.appendSessionLeaf("alice", sid, "msg", Buffer.from(msgLeafHash(new TextEncoder().encode(c))).toString("hex"));
    }
    const rootBefore = mgr1.getSessionTreeRootHex("alice", sid);
    const sizeBefore = mgr1.getSessionTree("alice", sid).size();

    // Simulate a restart: a brand-new manager instance over the same DB file.
    const mgr2 = await makeManager(makeLogger().logger, dbPath, new ConfigurableFakeNode());
    expect(mgr2.getSessionTree("alice", sid).size()).toBe(sizeBefore);
    expect(mgr2.getSessionTreeRootHex("alice", sid)).toBe(rootBefore);
  });

  it("AC-002: two managers fed the SAME ordered leaves report the SAME root", async () => {
    const mgrA = await makeManager(logger, join(tempDir, "A.db"), new ConfigurableFakeNode());
    const mgrB = await makeManager(makeLogger().logger, join(tempDir, "B.db"), new ConfigurableFakeNode());
    const sid = "c".repeat(64);
    for (const c of ["x", "y", "z", "w"]) {
      const h = Buffer.from(msgLeafHash(new TextEncoder().encode(c))).toString("hex");
      mgrA.appendSessionLeaf("alice", sid, "msg", h);
      mgrB.appendSessionLeaf("alice", sid, "msg", h);
    }
    expect(mgrA.getSessionTreeRootHex("alice", sid)).toBe(mgrB.getSessionTreeRootHex("alice", sid));
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
    // 007-CRYPTO: the state a completed key exchange leaves — a live send needs an agreed key.
    mgr.setSessionContentKeyForTest("alice", sid, new Uint8Array(32).fill(0x7e));
    const content = new TextEncoder().encode("hello");
    const contentHash = msgLeafHash(content);
    const res = await mgr.sendContent("alice", sid, content, contentHash);
    expect(res.ok).toBe(true);
    expect(node.sent.length).toBe(1);
  });

  it("AC-005: sendContent over a DEAD stream returns a named failure and does NOT mutate the tree", async () => {
    const node = new ConfigurableFakeNode({ newStreamFails: true });
    const mgr = await makeManager(logger, join(tempDir, "s.db"), node);
    await mgr.createSessionNode(sid, "alice", "bobpubkey", "bob-peer-id", "corr-1");
    // 007-CRYPTO: the state a completed key exchange leaves — a live send needs an agreed key.
    mgr.setSessionContentKeyForTest("alice", sid, new Uint8Array(32).fill(0x7e));
    const rootBefore = mgr.getSessionTreeRootHex("alice", sid);
    const content = new TextEncoder().encode("hello");
    const res = await mgr.sendContent("alice", sid, content, msgLeafHash(content));
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(typeof res.reason).toBe("string");
      expect(res.reason.length).toBeGreaterThan(0);
      // error.message is extracted — never [object Object]
      expect(res.error).not.toContain("[object Object]");
      expect(res.error).toContain("stream dead");
    }
    // No tree mutation on a failed send.
    expect(mgr.getSessionTreeRootHex("alice", sid)).toBe(rootBefore);
  });

  it("finding #2: appendSessionLeaf keeps sessions.message_count synced to the tree size", async () => {
    const mgr = await makeManager(logger, join(tempDir, "s.db"), new ConfigurableFakeNode());
    await mgr.createSessionNode(sid, "alice", "bobpubkey", "bob-peer-id", "corr-1");
    // 007-CRYPTO: the state a completed key exchange leaves — a live send needs an agreed key.
    mgr.setSessionContentKeyForTest("alice", sid, new Uint8Array(32).fill(0x7e));
    expect(mgr.getSessionRecord("alice", sid)!.message_count ?? 0).toBe(0);

    // A sent leaf advances message_count.
    mgr.appendSessionLeaf("alice", sid, "msg", Buffer.from(msgLeafHash(new TextEncoder().encode("a"))).toString("hex"));
    expect(mgr.getSessionRecord("alice", sid)!.message_count).toBe(1);

    // A received leaf (via ingest) also advances it — column tracks the tree, so a
    // post-active-messaging seal binds the real transcript length, not 0.
    const content = new TextEncoder().encode("b");
    await mgr.ingestReceivedContent("alice", sid, content, msgLeafHash(content));
    expect(mgr.getSessionRecord("alice", sid)!.message_count).toBe(2);
    expect(mgr.getSessionTree("alice", sid).size()).toBe(2);
  });

  it("AC-001 receive: ingestReceivedContent cross-checks, appends the leaf, buffers, fires session.content.received", async () => {
    const mgr = await makeManager(logger, join(tempDir, "s.db"), new ConfigurableFakeNode());
    await mgr.createSessionNode(sid, "alice", "bobpubkey", "bob-peer-id", "corr-1");
    // 007-CRYPTO: the state a completed key exchange leaves — a live send needs an agreed key.
    mgr.setSessionContentKeyForTest("alice", sid, new Uint8Array(32).fill(0x7e));
    const content = new TextEncoder().encode("from-bob");
    const contentHash = msgLeafHash(content);
    const rootBefore = mgr.getSessionTreeRootHex("alice", sid);

    const res = await mgr.ingestReceivedContent("alice", sid, content, contentHash);
    expect(res.ok).toBe(true);
    expect(mgr.getSessionTreeRootHex("alice", sid)).not.toBe(rootBefore);

    const recvEvent = events.find((e) => e.event === "session.content.received");
    expect(recvEvent).toBeDefined();
    expect(recvEvent!.context.sessionId).toBe(sid);
    expect(recvEvent!.context.senderPubkey).toBe("bobpubkey");

    const buffered = mgr.takeReceivedContent("alice", sid);
    expect(buffered).not.toBeNull();
    expect(Buffer.from(buffered!.contentHex, "hex").toString()).toBe("from-bob");
    // FIFO drained
    expect(mgr.takeReceivedContent("alice", sid)).toBeNull();
  });

  it("AC-001 receive (tamper): a content_hash MISMATCH is rejected — no append, no buffer, warn event", async () => {
    const mgr = await makeManager(logger, join(tempDir, "s.db"), new ConfigurableFakeNode());
    await mgr.createSessionNode(sid, "alice", "bobpubkey", "bob-peer-id", "corr-1");
    // 007-CRYPTO: the state a completed key exchange leaves — a live send needs an agreed key.
    mgr.setSessionContentKeyForTest("alice", sid, new Uint8Array(32).fill(0x7e));
    const content = new TextEncoder().encode("real");
    const wrongHash = msgLeafHash(new TextEncoder().encode("tampered"));
    const rootBefore = mgr.getSessionTreeRootHex("alice", sid);

    const res = await mgr.ingestReceivedContent("alice", sid, content, wrongHash);
    expect(res.ok).toBe(false);
    expect(mgr.getSessionTreeRootHex("alice", sid)).toBe(rootBefore);
    expect(mgr.takeReceivedContent("alice", sid)).toBeNull();
    const failEvent = events.find((e) => e.event === "session.content.cross_check.failed");
    expect(failEvent).toBeDefined();
    expect(failEvent!.level).toBe("warn");
  });

  // ── AC-001 finding: correlationId must be SHARED across the send/receive boundary ──
  it("AC-001 correlationId: sendContent stamps correlation_id into the content_frame", async () => {
    const node = new ConfigurableFakeNode();
    const mgr = await makeManager(logger, join(tempDir, "s.db"), node);
    await mgr.createSessionNode(sid, "alice", "bobpubkey", "bob-peer-id", "corr-1");
    // 007-CRYPTO: the state a completed key exchange leaves — a live send needs an agreed key.
    mgr.setSessionContentKeyForTest("alice", sid, new Uint8Array(32).fill(0x7e));
    const content = new TextEncoder().encode("hello");
    const correlationId = "flow-abc-123";
    const res = await mgr.sendContent("alice", sid, content, msgLeafHash(content), correlationId);
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
    const mgr = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new ControlledFactory(new ConfigurableFakeNode()), logger, dbPath: join(tempDir, "ci.db") });
    // initialize() is async but ingest does not require the standing receiver; run after init.
    return mgr.initialize().then(async () => {
      await seedAgents(mgr.getDb(), ["alice"]);
      await mgr.createSessionNode(sid, "alice", "bobpubkey", "bob-peer-id", "corr-1");
      // 007-CRYPTO: the state a completed key exchange leaves — a live send needs an agreed key.
      mgr.setSessionContentKeyForTest("alice", sid, new Uint8Array(32).fill(0x7e));
      const content = new TextEncoder().encode("from-bob");
      const correlationId = "flow-xyz-789";
      await mgr.ingestReceivedContent("alice", sid, content, msgLeafHash(content), correlationId);
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
    /**
     * DOD-M15-AUTHORSHIP-ABSENT-1: ON A LOOPBACK, ALICE IS HER OWN COUNTERPARTY.
     *
     * The frame is now signed by the sending agent's identity key and the receiver checks the signer
     * against `counterparty_pubkey`. With the placeholder `"bobpubkey"` here, this loopback would be
     * a session whose counterparty is nobody — the receiving half would correctly refuse a message
     * from a signer it has no record of, and the test would be measuring that instead of the
     * round trip it is named for.
     */
    await mgr.createSessionNode(sid, "alice", alicePubkeyHex(mgr), "bob-peer-id", "corr-1");
    // 007-CRYPTO: the state a completed key exchange leaves — a live send needs an agreed key.
    mgr.setSessionContentKeyForTest("alice", sid, new Uint8Array(32).fill(0x7e));
    const content = new TextEncoder().encode("loopback-hi");
    const correlationId = "flow-roundtrip-1";
    const res = await mgr.sendContent("alice", sid, content, msgLeafHash(content), correlationId);
    expect(res.ok).toBe(true);
    // The loopback delivers synchronously into the handler, which ingests async — drain.
    await new Promise((r) => setImmediate(r));

    const recv = events.find((e) => e.event === "session.content.received");
    expect(recv).toBeDefined();
    // The receiver shares the sender's correlationId — extracted from the frame, not minted.
    expect(recv!.context.correlationId).toBe(correlationId);
    const buffered = mgr.takeReceivedContent("alice", sid);
    expect(buffered).not.toBeNull();
    expect(Buffer.from(buffered!.contentHex, "hex").toString()).toBe("loopback-hi");
  });

  /**
   * DOD-M15-FRAME-1 — the injection path, refused.
   *
   * Walked as the sequence an operator would live through: a stranger reaches the standing
   * receiver's open port, the encrypted handshake completes (proving they hold *some* key, not that
   * they are anyone known), they hold the connection through promotion, and then speak the content
   * protocol. Every frame below is one an attacker can actually construct — the point is that none
   * of them lands in the transcript.
   */
  describe("DOD-M15-FRAME-1: a stranger cannot put words in the counterparty's mouth", () => {
    it("refuses a content frame from a peer that is not this session's counterparty", async () => {
      const node = new LoopbackFakeNode();
      const mgr = await makeManager(logger, join(tempDir, "inject.db"), node as unknown as CelloNode);
      await mgr.createSessionNode(sid, "alice", "bobpubkey", "bob-peer-id", "corr-1");
      // 007-CRYPTO: the state a completed key exchange leaves — a live send needs an agreed key.
      mgr.setSessionContentKeyForTest("alice", sid, new Uint8Array(32).fill(0x7e));

      // The frame is otherwise perfectly well-formed. Only the sender is wrong.
      node.deliverAs = "stranger-peer-id";
      const content = new TextEncoder().encode("a message alice never received");
      await mgr.sendContent("alice", sid, content, msgLeafHash(content), "corr-x");
      await new Promise((r) => setImmediate(r));

      expect(events.find((e) => e.event === "session.content.received"), "nothing may be ingested").toBeUndefined();
      expect(events.find((e) => e.event === "session.tree.appended"), "and nothing may reach the tree").toBeUndefined();
      const refused = events.find((e) => e.event === "session.content.peer_mismatch");
      expect(refused).toBeDefined();
      expect(refused!.context.frameType).toBe("content_frame");
      // The transcript is the artifact this protocol exists to produce. A stranger's text in it,
      // filed as the counterparty's, is the one thing it must never contain.
      expect(mgr.readTranscript("alice", sid).messages.filter((m) => m.direction === "received")).toHaveLength(0);
    });

    it("refuses a frame that OMITS session_id — absence is not agreement", async () => {
      /**
       * The omission bypass, and the reason clause 3 is separate from clause 1. The old check read
       * `typeof x === "string" && x !== sessionId`, so it fired only when the field was PRESENT and
       * wrong. An attacker evading a mismatch check does not send a wrong value — it sends none.
       * Driven through the real handler with a hand-built frame, because `sendContent` always sets
       * the field and could never produce this.
       */
      const node = new LoopbackFakeNode();
      const mgr = await makeManager(logger, join(tempDir, "omit.db"), node as unknown as CelloNode);
      await mgr.createSessionNode(sid, "alice", "bobpubkey", "bob-peer-id", "corr-1");
      // 007-CRYPTO: the state a completed key exchange leaves — a live send needs an agreed key.
      mgr.setSessionContentKeyForTest("alice", sid, new Uint8Array(32).fill(0x7e));

      const content = new TextEncoder().encode("no session id on this one");
      // Correct sender, correct everything — except the field simply is not there.
      node.deliverFrame({ type: "content_frame", content_bytes: sealSessionContent(new Uint8Array(32).fill(0x7e), content), content_encryption: SESSION_CONTENT_ENCRYPTION_V1, content_hash: msgLeafHash(content) }, "bob-peer-id");
      await new Promise((r) => setImmediate(r));

      expect(events.find((e) => e.event === "session.content.received")).toBeUndefined();
      const refused = events.find((e) => e.event === "session.content.session_mismatch");
      expect(refused).toBeDefined();
      expect(refused!.context.claimedSessionId).toBe("(absent)");
    });

    /**
     * DOD-M15-FRAME-1 (review: the freeze had NO coverage and survived deletion with a green suite).
     *
     * The existing ordering tests all drive `recordOrderingRecord` — the PARK path, which by design
     * discards `fatal` — so they assert the pre-fix behaviour and pass either way. These go through
     * the LIVE path: a real `content_frame` carrying a real ordering record, delivered by a peer
     * that passes the transport gate. That distinction is the whole point: in the session-open MITM
     * the substituted party IS the peer we dialled, so the transport gate cannot see it and the
     * signer comparison is what shows the substitution.
     */
    const kpRecord = async (
      kp: ReturnType<typeof generateKeypair>,
      content: Uint8Array,
      seq: number,
      opts: { corruptSig?: boolean } = {},
    ) => {
      const pubkey = await kp.getPublicKey();
      const contentHash = msgLeafHash(content);
      const structure1Cbor = encodeStructure1({
        contentHash,
        senderPubkey: pubkey,
        sessionId: new Uint8Array(16),
        lastSeenSeq: 0,
        timestamp: 1_700_000_000_000,
      });
      let sig = await kp.sign(structure1Cbor);
      if (opts.corruptSig) { sig = new Uint8Array(sig); sig[0] ^= 0xff; }
      const built = buildStructure2(seq, pubkey, contentHash, sig, new Uint8Array(32));
      if (!built.ok) throw new Error("buildStructure2 failed");
      // DOD-M15-AUTHORSHIP-ABSENT-1: the signature rides on the FRAME as well, which is where the
      // receiver now checks authorship from. Same bytes the relay commits at Structure 2 index 3 —
      // a real sender puts one value in both places, so a fixture that used two would be testing a
      // sender nobody ships.
      return { structure1Cbor, structure2Cbor: encodeStructure2(built.structure2), contentHash, senderSignature: sig };
    };

    const sessionWithCounterparty = async (kp: ReturnType<typeof generateKeypair>, db: string) => {
      const node = new LoopbackFakeNode();
      const mgr = await makeManager(logger, join(tempDir, db), node as unknown as CelloNode);
      const cpHex = Buffer.from(await kp.getPublicKey()).toString("hex");
      await mgr.createSessionNode(sid, "alice", cpHex, "bob-peer-id", "corr-1");
      // 007-CRYPTO: the state a completed key exchange leaves — a live send needs an agreed key.
      mgr.setSessionContentKeyForTest("alice", sid, new Uint8Array(32).fill(0x7e));
      return { node, mgr };
    };

    it("FREEZES the session when the ordering record is signed by a NON-counterparty key", async () => {
      // The session-open MITM, at the one place it shows. M holds the session peer id we dialled —
      // so the transport gate passes — but signs the leaf with M's own key, not B's.
      const counterparty = generateKeypair();
      const attacker = generateKeypair();
      const { node, mgr } = await sessionWithCounterparty(counterparty, "mitm.db");

      const content = new TextEncoder().encode("a message B never wrote");
      const rec = await kpRecord(attacker, content, 1);
      node.deliverFrame({
        type: "content_frame", session_id: sid,
        content_bytes: sealSessionContent(new Uint8Array(32).fill(0x7e), content), content_encryption: SESSION_CONTENT_ENCRYPTION_V1, content_hash: rec.contentHash,
        structure1_cbor: rec.structure1Cbor, sender_signature: rec.senderSignature, structure2_cbor: rec.structure2Cbor,
      }, "bob-peer-id");
      await new Promise((r) => setTimeout(r, 30));

      /**
       * DOD-M15-AUTHORSHIP-ABSENT-1: the event moved with the check. It used to be
       * `session.content.ordering.wrong_signer`, because the signer was only ever checked while
       * reading the relay's ordering record; the frame's own signature is checked first now, and
       * says so under its own name. The relay-record event still exists and still fires for a
       * Structure 2 whose committed signature disagrees with the frame — a different fault.
       */
      const refuted = events.find((e) => e.event === "session.content.authorship.refuted");
      expect(refuted).toBeDefined();
      expect(refuted!.context.reason).toBe("signer_not_counterparty");
      expect(events.find((e) => e.event === "session.content.identity.frozen"), "the check must ACT, not just fire").toBeDefined();
      expect(events.find((e) => e.event === "session.content.received"), "nothing may be ingested").toBeUndefined();
      expect(mgr.readTranscript("alice", sid).messages.filter((m) => m.direction === "received")).toHaveLength(0);
    });

    it("FREEZES on a bad signature too — a supplied proof that fails is not an absent one", async () => {
      const counterparty = generateKeypair();
      const { node, mgr } = await sessionWithCounterparty(counterparty, "badsig-live.db");

      const content = new TextEncoder().encode("forged");
      const rec = await kpRecord(counterparty, content, 1, { corruptSig: true });
      node.deliverFrame({
        type: "content_frame", session_id: sid,
        content_bytes: sealSessionContent(new Uint8Array(32).fill(0x7e), content), content_encryption: SESSION_CONTENT_ENCRYPTION_V1, content_hash: rec.contentHash,
        structure1_cbor: rec.structure1Cbor, sender_signature: rec.senderSignature, structure2_cbor: rec.structure2Cbor,
      }, "bob-peer-id");
      await new Promise((r) => setTimeout(r, 30));

      expect(events.find((e) => e.event === "session.content.identity.frozen")).toBeDefined();
      expect(mgr.getSessionTree("alice", sid).size()).toBe(0);
    });

    it("a frozen session is NOT revived by a read — the freeze must not undo itself", async () => {
      /**
       * The freeze tears the node down, and a teardown writes `interrupted` — which is the REVIVABLE
       * status. Before this was pinned, the operator's very next read rebuilt the session behind a
       * gater allowing the same peer and logged it as a success, so a security decision reversed
       * itself silently while the log said no further content would be accepted.
       */
      const counterparty = generateKeypair();
      const attacker = generateKeypair();
      const { node, mgr } = await sessionWithCounterparty(counterparty, "frozen-revive.db");

      const content = new TextEncoder().encode("mitm");
      const rec = await kpRecord(attacker, content, 1);
      node.deliverFrame({
        type: "content_frame", session_id: sid,
        content_bytes: sealSessionContent(new Uint8Array(32).fill(0x7e), content), content_encryption: SESSION_CONTENT_ENCRYPTION_V1, content_hash: rec.contentHash,
        structure1_cbor: rec.structure1Cbor, sender_signature: rec.senderSignature, structure2_cbor: rec.structure2Cbor,
      }, "bob-peer-id");
      await new Promise((r) => setTimeout(r, 30));
      expect(events.find((e) => e.event === "session.content.identity.frozen"), "precondition").toBeDefined();

      const revived = await mgr.reviveSessionNode("alice", sid, "corr-revive");
      expect(revived.ok, "a frozen session must not come back on a read").toBe(false);
      expect(revived.ok === false && revived.reason).toBe("session_frozen_identity_failure");
      // Invariant 4: the refusal names what remains open, and does not send them to a dead end.
      expect(revived.ok === false && String(revived.guidance)).toMatch(/cello_transcript/);
      expect(revived.ok === false && String(revived.guidance)).toMatch(/cello_close_session/);
      /**
       * THE EXPLANATION ITSELF, not just the affordances — `DOD-M15-SEALWIRE-1` part A, review F6.
       *
       * `#frozenSessions` became a Map so a second kind of freeze (a salt disagreement) could carry
       * its own words instead of borrowing these. That moved this guidance from a literal inside
       * `reviveSessionNode` to a parameter supplied by the freezing site — and nothing asserted it
       * afterwards. Blanking it left every test green while the operator got a refusal that opened
       * mid-sentence with no reason in it at all.
       *
       * Both halves are pinned because both are load-bearing: WHAT was observed, and the explicit
       * refusal to conclude who did it.
       */
      expect(
        revived.ok === false && String(revived.guidance),
        "the identity refusal must still say what was observed",
      ).toMatch(/counterparty's key/);
      expect(
        revived.ok === false && String(revived.guidance),
        "and must still decline to conclude it was them — the signal cannot tell impersonation from our own fallback",
      ).toMatch(/Cause undetermined/);
    });

    it("does NOT freeze when the counterparty cannot be resolved — 'could not tell' is not 'refuted'", async () => {
      /**
       * The false-positive guard, and the branch with the widest blast radius if it were wrong.
       * `counterparty_unknown` means we cannot prove the signer either way; refusing there would
       * strand sessions whose record we merely failed to read, rather than sessions under attack.
       */
      const kp = generateKeypair();
      const node = new LoopbackFakeNode();
      const mgr = await makeManager(logger, join(tempDir, "cp-unknown.db"), node as unknown as CelloNode);
      // Session created with an EMPTY counterparty pubkey — resolvable session, unresolvable signer.
      await mgr.createSessionNode(sid, "alice", "", "bob-peer-id", "corr-1");
      // 007-CRYPTO: the state a completed key exchange leaves — a live send needs an agreed key.
      mgr.setSessionContentKeyForTest("alice", sid, new Uint8Array(32).fill(0x7e));

      const content = new TextEncoder().encode("unverifiable but not refuted");
      const rec = await kpRecord(kp, content, 1);
      node.deliverFrame({
        type: "content_frame", session_id: sid,
        content_bytes: sealSessionContent(new Uint8Array(32).fill(0x7e), content), content_encryption: SESSION_CONTENT_ENCRYPTION_V1, content_hash: rec.contentHash,
        structure1_cbor: rec.structure1Cbor, sender_signature: rec.senderSignature, structure2_cbor: rec.structure2Cbor,
      }, "bob-peer-id");
      await new Promise((r) => setTimeout(r, 30));

      expect(events.find((e) => e.event === "session.content.ordering.wrong_signer"), "the check still runs").toBeDefined();
      expect(events.find((e) => e.event === "session.content.identity.frozen"), "an unprovable signer must NOT freeze").toBeUndefined();
      /**
       * MEASURED, not assumed: the sequence is `ordering.wrong_signer` → `content.sender_unresolved`.
       * The content does not ingest here — but that is the ingest path's OWN pre-existing guard
       * refusing to attribute a message it cannot resolve a sender for, not this unit's freeze. The
       * distinction is the whole point of the test: an unprovable signer must not be escalated into
       * a session-ending decision by the code this unit added.
       *
       * It also means `counterparty_unknown` is barely reachable on the live path — a real session
       * always carries a counterparty pubkey, and without one the ingest guard fires first. The soft
       * branch is kept anyway, because a gate that depends on another guard running first is a gate
       * with a hidden precondition.
       */
      expect(events.find((e) => e.event === "session.content.sender_unresolved")).toBeDefined();
    });

    it("a frame with NO RELAY RECORD but a real signature still ingests — position is soft, identity is not", async () => {
      /**
       * ⚠️ **THIS TEST USED TO ASSERT THE DEFECT `DOD-M15-AUTHORSHIP-ABSENT-1` FIXED.** It was
       * called *"a frame with NO ordering record still ingests, and SAYS it was unverified"*, and it
       * pinned exactly that: a frame carrying nothing checkable was delivered, with a log line
       * admitting nobody had checked who wrote it. Rewritten rather than deleted, because the half
       * it was protecting is real and a careless fix breaks it.
       *
       * The half that survives: refusing on an absent RELAY record would make the relay a
       * precondition for reading mail. So a message whose sender could not reach a relay still
       * lands — its POSITION falls back to the witness stream — and it lands with its author proven,
       * because the signature travels on the frame beside the bytes it signs.
       *
       * The half that is gone: "ingests and says it was unverified". A message nobody can be held to
       * is refused now, which is the case below.
       */
      const counterparty = generateKeypair();
      const { node, mgr } = await sessionWithCounterparty(counterparty, "no-record.db");

      const content = new TextEncoder().encode("no relay record, still signed");
      const rec = await kpRecord(counterparty, content, 1);
      node.deliverFrame({
        type: "content_frame", session_id: sid,
        content_bytes: sealSessionContent(new Uint8Array(32).fill(0x7e), content), content_encryption: SESSION_CONTENT_ENCRYPTION_V1, content_hash: rec.contentHash,
        // Structure 1 and its signature — and deliberately NO `structure2_cbor`.
        structure1_cbor: rec.structure1Cbor, sender_signature: rec.senderSignature,
      }, "bob-peer-id");
      await new Promise((r) => setTimeout(r, 30));

      expect(events.find((e) => e.event === "session.content.received"), "relay-degraded delivery must still work").toBeDefined();
      expect(events.find((e) => e.event === "session.content.identity.frozen"), "and it is not an identity fault").toBeUndefined();
      const absent = events.find((e) => e.event === "session.content.ordering.absent");
      expect(absent, "the POSITION is what is unknown, and the log says so").toBeDefined();
      expect(String(absent!.context.impact)).toMatch(/POSITION/);
      expect(mgr.readTranscript("alice", sid).messages.filter((m) => m.direction === "received")).toHaveLength(1);
    });

    it("a frame with NO PROOF AT ALL is refused — the passport case", async () => {
      /**
       * The other half of the same measurement, and the reason the test above is not enough on its
       * own: identical bytes, one field gone. A frame that supplies nothing checkable used to be
       * ingested and attributed to the counterparty; it is refused now, by name, and the operator
       * is told rather than watching the conversation go quiet.
       */
      const counterparty = generateKeypair();
      const { node, mgr } = await sessionWithCounterparty(counterparty, "no-proof.db");

      const content = new TextEncoder().encode("who wrote this? nobody can say");
      node.deliverFrame({
        type: "content_frame", session_id: sid,
        content_bytes: sealSessionContent(new Uint8Array(32).fill(0x7e), content), content_encryption: SESSION_CONTENT_ENCRYPTION_V1, content_hash: msgLeafHash(content),
      }, "bob-peer-id");
      await new Promise((r) => setTimeout(r, 30));

      expect(events.find((e) => e.event === "session.content.received"), "nothing unattributable may be ingested").toBeUndefined();
      expect(events.find((e) => e.event === "session.content.identity.frozen"), "and a refusal is not a freeze").toBeUndefined();
      const refused = events.find((e) => e.event === "session.content.refused" && e.context.reason === "authorship_proof_absent");
      expect(refused, "refused BY NAME").toBeDefined();
      expect(mgr.readTranscript("alice", sid).messages.filter((m) => m.direction === "received")).toHaveLength(0);
    });

    it("a legitimate frame from the real counterparty is untouched — no new false positive", async () => {
      // The gate must not be the thing that breaks messaging. Same fixture, correct sender.
      const node = new LoopbackFakeNode();
      const mgr = await makeManager(logger, join(tempDir, "ok.db"), node as unknown as CelloNode);
      // On a loopback the sender IS the counterparty — see the round-trip test above.
      await mgr.createSessionNode(sid, "alice", alicePubkeyHex(mgr), "bob-peer-id", "corr-1");
      // 007-CRYPTO: the state a completed key exchange leaves — a live send needs an agreed key.
      mgr.setSessionContentKeyForTest("alice", sid, new Uint8Array(32).fill(0x7e));

      const content = new TextEncoder().encode("a real message");
      await mgr.sendContent("alice", sid, content, msgLeafHash(content), "corr-ok");
      await new Promise((r) => setImmediate(r));

      expect(events.find((e) => e.event === "session.content.received")).toBeDefined();
      expect(events.find((e) => e.event === "session.content.peer_mismatch")).toBeUndefined();
      expect(events.find((e) => e.event === "session.content.session_mismatch")).toBeUndefined();
    });
  });

  // ── medium finding: in-memory tree + received-content maps must be evicted on teardown ──
  it("eviction: destroySessionNode clears the buffered received content (no plaintext retention)", async () => {
    const mgr = await makeManager(logger, join(tempDir, "ev.db"), new ConfigurableFakeNode());
    await mgr.createSessionNode(sid, "alice", "bobpubkey", "bob-peer-id", "corr-1");
    // 007-CRYPTO: the state a completed key exchange leaves — a live send needs an agreed key.
    mgr.setSessionContentKeyForTest("alice", sid, new Uint8Array(32).fill(0x7e));
    const content = new TextEncoder().encode("secret-payload");
    await mgr.ingestReceivedContent("alice", sid, content, msgLeafHash(content));
    const persistedRoot = mgr.getSessionTreeRootHex("alice", sid);

    await mgr.destroySessionNode("alice", sid, "sealed");

    // The in-memory plaintext buffer is gone after teardown.
    expect(mgr.takeReceivedContent("alice", sid)).toBeNull();
    // But the durable transcript is intact — the tree reloads from SQLite with the
    // same root, proving eviction dropped only the in-memory cache, not durable state.
    expect(mgr.getSessionTreeRootHex("alice", sid)).toBe(persistedRoot);
  });

  // ── round-2 finding #5: a frozen session must not let late inbound content mutate
  //    the committed tree. Once the bilateral seal commitment advances the session
  //    out of 'active', ingestReceivedContent must reject — otherwise a frame that
  //    arrives after the SEAL leaf was signed would diverge the transcript from the
  //    root that was just committed (and that a later FROST notarization attests).
  it("finding #5: ingestReceivedContent rejects late content once the session is frozen (not active)", async () => {
    const mgr = await makeManager(logger, join(tempDir, "s.db"), new ConfigurableFakeNode());
    await mgr.createSessionNode(sid, "alice", "bobpubkey", "bob-peer-id", "corr-1");
    // 007-CRYPTO: the state a completed key exchange leaves — a live send needs an agreed key.
    mgr.setSessionContentKeyForTest("alice", sid, new Uint8Array(32).fill(0x7e));

    // One leaf arrives while active — accepted, then drained.
    const c1 = new TextEncoder().encode("m1");
    expect((await mgr.ingestReceivedContent("alice", sid, c1, msgLeafHash(c1))).ok).toBe(true);
    expect(mgr.getSessionTree("alice", sid).size()).toBe(1);
    expect(mgr.takeReceivedContent("alice", sid)).not.toBeNull();

    // Freeze: the seal commitment advances the session out of 'active'.
    mgr.persistSealInterruptedCommitment({ agentName: "alice",
      sessionId: sid, role: "initiator", ownLeaf: {}, counterpartyLeaf: {},
      merkleRoot: mgr.getSessionTreeRootHex("alice", sid), nonce: "n1",
    });
    expect(mgr.getSessionRecord("alice", sid)!.status).toBe("seal_interrupted_pending");
    const rootAfterCommit = mgr.getSessionTreeRootHex("alice", sid);

    // A late inbound frame MUST be rejected — the frozen tree is not mutated.
    const c2 = new TextEncoder().encode("late-frame");
    const res = await mgr.ingestReceivedContent("alice", sid, c2, msgLeafHash(c2));
    expect(res.ok).toBe(false);
    expect(mgr.getSessionTree("alice", sid).size()).toBe(1);
    expect(mgr.getSessionTreeRootHex("alice", sid)).toBe(rootAfterCommit);
    // No content buffered from the rejected frame.
    expect(mgr.takeReceivedContent("alice", sid)).toBeNull();
  });

  // ── round-2 finding #7: message_count must track the daemon-owned tree across an
  //    interrupt, not a stale registration value (default 0). Both seal flows prefer
  //    tree.size(), but the column must not be left inconsistent with the tree.
  it("finding #7: markInterruptedWithDetails keeps message_count synced to the daemon-owned tree, not a stale value", async () => {
    const mgr = await makeManager(logger, join(tempDir, "s.db"), new ConfigurableFakeNode());
    await mgr.createSessionNode(sid, "alice", "bobpubkey", "bob-peer-id", "corr-1");
    // 007-CRYPTO: the state a completed key exchange leaves — a live send needs an agreed key.
    mgr.setSessionContentKeyForTest("alice", sid, new Uint8Array(32).fill(0x7e));
    for (const m of ["a", "b", "c"]) {
      mgr.appendSessionLeaf("alice", sid, "msg", Buffer.from(msgLeafHash(new TextEncoder().encode(m))).toString("hex"));
    }
    expect(mgr.getSessionTree("alice", sid).size()).toBe(3);

    // Interrupt with a STALE registration count of 0 (the registerRelayStream default).
    await mgr.markInterruptedWithDetails("alice", sid, 0, "stream_close");

    // message_count reflects the daemon-owned tree (3), not the stale 0.
    expect(mgr.getSessionRecord("alice", sid)!.message_count).toBe(3);
  });
});
