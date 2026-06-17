/**
 * CELLO-M7-DAEMON-004 — IPC-level: cello_send / cello_receive / active-session
 * seal through the real composition root.
 *
 * Specification (SPARC Phase S):
 *
 * AC-005 (integration): cello_send over a DEAD session stream (killed at the L7
 *   transport boundary — newStream rejects) returns a distinct, diagnosable
 *   outcome with a guidance field and fires session.content.send.failed with
 *   sessionId, recipientPubkey, reason, errorMessage (never [object Object]).
 *   The session remains usable. DB-001: the content is preserved in the durable
 *   retry_queue rather than dropped.
 *
 * AC-006 (integration): cello_send is reachable through the real IPC socket and
 *   routes to a SessionNodeManager session (NOT not_implemented). The send/tree
 *   capability is instantiated by the composition root.
 *
 * AC-003 (integration): cello_close_session on an ACTIVE session does NOT return
 *   not_implemented; it builds a SEAL leaf over the daemon's OWN tree root and
 *   fires session.seal.initiated with rootHex == the daemon's tree root,
 *   role:'initiator'.
 *
 * SI-001 (integration): a caller-supplied merkleRoot param is IGNORED — the seal
 *   is initiated over the daemon's own tree root, never the caller value.
 *
 * SI-003 (integration): the SEAL leaf in the seal_request is signed by the
 *   closing party's OWN key (signerPubkey == initiator); no counterparty
 *   signature is synthesized by the initiator.
 *
 * DB-002 (integration): cello_close_session on an active session while signaling
 *   is reconnecting returns signaling_reconnecting and does NOT fire
 *   session.seal.initiated (no partial seal).
 *
 * cello_send happy path + cello_receive (integration): a live stream send
 *   appends to the daemon-owned tree (session.tree.appended + session.content.sent)
 *   and returns { ok:true, sequence_number }; cello_receive returns ingested content.
 *
 * Crypto refs: Ed25519 RFC 8032, RFC 6962 §2.1.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { FileKeyProvider, verify as ed25519Verify } from "@cello-protocol/crypto";
import { startDaemon } from "../daemon.js";
import { connectToDaemon } from "../ipc-client.js";
import type { Logger, DaemonConfig } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { ConnectResult, SignalingStream, CelloNode } from "@cello-protocol/transport";
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

class FakeNode implements Partial<CelloNode> {
  sent: Uint8Array[] = [];
  constructor(private opts: { newStreamFails?: boolean } = {}) {}
  readonly #peerId = `fake-${Math.random().toString(36).slice(2)}`;
  async start(): Promise<void> {}
  async stop(): Promise<void> {}
  getPeerId(): string { return this.#peerId; }
  listenAddresses(): string[] { return ["/ip4/127.0.0.1/tcp/0"]; }
  async dial(_a: string): Promise<{ peerId: string }> { return { peerId: "remote" }; }
  async handle(_p: string, _h: unknown): Promise<void> {}
  getProtocols(): string[] { return []; }
  getConnections(): Array<{ peerId: string; encryption: string | undefined }> { return []; }
  onPeerConnect(_h: (p: string) => void): void {}
  onPeerDisconnect(_h: (p: string) => void): void {}
  async newStream(_peer: string, _proto: string): Promise<Stream> {
    if (this.opts.newStreamFails) throw new Error("connection_lost: counterparty stream dead");
    const sink = this.sent;
    return { send(d: Uint8Array) { sink.push(d); }, async close() {}, abort() {}, status: "open" } as unknown as Stream;
  }
}

class FixedFactory implements ISessionNodeFactory {
  constructor(private node: CelloNode) {}
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> { return this.node; }
}

/** Capturing signaling stream: records frames sent by the daemon. */
function makeCapturingSignaling(captured: Record<string, unknown>[]): () => Promise<ConnectResult> {
  const stream: SignalingStream = {
    send: async (frame: unknown) => { captured.push(frame as Record<string, unknown>); },
    onMessage: (_h: (frame: unknown) => void) => {},
    close: () => {},
  };
  return async () => ({ stream, directoryNodeId: "fake-dir", manifestVersion: 1 });
}

describe("DAEMON-004 IPC: cello_send / cello_receive / active seal", () => {
  let tempDir: string;
  let handle: Awaited<ReturnType<typeof startDaemon>> | null;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-d004-ipc-"));
    handle = null;
  });
  afterEach(async () => {
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* ignore */ } }
    await rm(tempDir, { recursive: true, force: true });
  });

  async function makeAgentDir(name: string): Promise<string> {
    const dir = join(tempDir, "agents", name);
    await mkdir(dir, { recursive: true });
    const kp = await FileKeyProvider.load(join(dir, "key"));
    return Buffer.from(await kp.getPublicKey()).toString("hex");
  }

  async function start(opts: {
    logger: Logger;
    node: CelloNode;
    signalingConnect?: () => Promise<ConnectResult>;
  }): Promise<Awaited<ReturnType<typeof startDaemon>>> {
    const config: DaemonConfig = {
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger: opts.logger,
      sessionNodeFactory: new FixedFactory(opts.node),
      signalingConnect: opts.signalingConnect,
    };
    const h = await startDaemon(config);
    handle = h;
    return h;
  }

  const SID = "ab".repeat(32);

  it("AC-006 + happy path: cello_send routes to the SessionNodeManager, advances the daemon tree, returns sequence_number", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("alice");
    const node = new FakeNode();
    const h = await start({ logger, node });
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr");

    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });
      await client.send("cello_start_agent", { name: "alice" });
      await client.send("cello_use_agent", { name: "alice" });
      const res = await client.send("cello_send", { sessionId: SID, content: "hello" }) as Record<string, unknown>;
      expect(res.reason).not.toBe("not_implemented");
      expect(res.ok).toBe(true);
      expect(typeof res.sequence_number).toBe("number");
    } finally { client.close(); }

    // content_frame was sent over the (fake) session stream.
    expect(node.sent.length).toBe(1);
    // Tree advanced + events fired.
    expect(snm.getSessionTree(SID).size()).toBe(1);
    expect(events.find((e) => e.event === "session.content.sent")).toBeDefined();
    expect(events.find((e) => e.event === "session.tree.appended")).toBeDefined();
  });

  it("AC-005 + DB-001: cello_send over a DEAD stream returns a named failure, fires session.content.send.failed, queues the leaf, session stays usable", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("alice");
    const node = new FakeNode({ newStreamFails: true });
    const h = await start({ logger, node });
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr");

    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });
      await client.send("cello_start_agent", { name: "alice" });
      await client.send("cello_use_agent", { name: "alice" });
      const res = await client.send("cello_send", { sessionId: SID, content: "hello" }) as Record<string, unknown>;
      expect(res.ok).toBe(false);
      expect(res.reason).not.toBe("not_implemented");
      expect(typeof res.reason).toBe("string");
      expect((res.reason as string).length).toBeGreaterThan(0);
      expect(typeof res.guidance).toBe("string");
      // session still usable — a second send still reaches the send path (same failure, not desync)
      const res2 = await client.send("cello_send", { sessionId: SID, content: "again" }) as Record<string, unknown>;
      expect(res2.ok).toBe(false);
      expect(res2.reason).not.toBe("session_desynchronized");
    } finally { client.close(); }

    const failEvent = events.find((e) => e.event === "session.content.send.failed");
    expect(failEvent).toBeDefined();
    expect(failEvent!.level).toBe("warn");
    expect(failEvent!.context.sessionId).toBe(SID);
    expect(failEvent!.context.recipientPubkey).toBe("bobpubkeyhex");
    expect(typeof failEvent!.context.reason).toBe("string");
    expect(String(failEvent!.context.errorMessage)).not.toContain("[object Object]");
    expect(String(failEvent!.context.errorMessage)).toContain("stream dead");

    // DB-001: the content was preserved in the durable retry_queue (not dropped).
    expect(h.getStatus().retryQueueDepth).toBeGreaterThanOrEqual(1);
    // Tree NOT advanced on a failed send.
    expect(snm.getSessionTree(SID).size()).toBe(0);
  });

  it("AC-001 receive: cello_receive returns content ingested into the daemon buffer", async () => {
    const { logger } = makeLogger();
    await makeAgentDir("alice");
    const node = new FakeNode();
    const h = await start({ logger, node });
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
    const content = new TextEncoder().encode("from-bob");
    snm.ingestReceivedContent(SID, content, msgLeafHash(content));

    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });
      await client.send("cello_start_agent", { name: "alice" });
      await client.send("cello_use_agent", { name: "alice" });
      const res = await client.send("cello_receive", { sessionId: SID }) as Record<string, unknown>;
      expect(res.reason).not.toBe("not_implemented");
      expect(res.ok).toBe(true);
      expect(res.content).toBe("from-bob");
    } finally { client.close(); }
  });

  it("AC-003 + SI-001 + SI-003: active close initiates a seal over the daemon's OWN root, ignoring a caller merkleRoot", async () => {
    const { logger, events } = makeLogger();
    const alicePubkey = await makeAgentDir("alice");
    const node = new FakeNode();
    const captured: Record<string, unknown>[] = [];
    const h = await start({ logger, node, signalingConnect: makeCapturingSignaling(captured) });
    await new Promise((r) => setTimeout(r, 50)); // let signaling connect
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
    // Append two message leaves so the tree has a non-empty, real root.
    snm.appendSessionLeaf(SID, "msg", Buffer.from(msgLeafHash(new TextEncoder().encode("m1"))).toString("hex"));
    snm.appendSessionLeaf(SID, "msg", Buffer.from(msgLeafHash(new TextEncoder().encode("m2"))).toString("hex"));
    const ownRoot = snm.getSessionTreeRootHex(SID);

    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });
      await client.send("cello_start_agent", { name: "alice" });
      await client.send("cello_use_agent", { name: "alice" });
      // SI-001: supply a bogus caller merkleRoot — it MUST be ignored.
      const res = await client.send("cello_close_session", { sessionId: SID, merkleRoot: "ff".repeat(32) }) as Record<string, unknown>;
      expect(res.reason).not.toBe("not_implemented");
      expect(res.ok).toBe(true);
    } finally { client.close(); }

    // AC-003: session.seal.initiated with rootHex == daemon's OWN tree root.
    const initiated = events.find((e) => e.event === "session.seal.initiated");
    expect(initiated).toBeDefined();
    expect(initiated!.level).toBe("info");
    expect(initiated!.context.sessionId).toBe(SID);
    expect(initiated!.context.role).toBe("initiator");
    // SI-001: the root signed is the daemon's own root, NOT the caller's "ff...".
    expect(initiated!.context.rootHex).toBe(ownRoot);
    expect(initiated!.context.rootHex).not.toBe("ff".repeat(32));

    // SI-003: the SEAL leaf submitted is signed by the closing party's own key.
    const sealReq = captured.find((f) => f.type === "seal_request");
    expect(sealReq).toBeDefined();
    const leaf = sealReq!.sealLeaf as Record<string, unknown>;
    expect(leaf.signerPubkey).toBe(alicePubkey);
    // The submitted frame carries no counterparty signature — the initiator never produces it.
    expect(sealReq!.counterpartySignature).toBeUndefined();
    // And the initiator's own SEAL leaf signature verifies under the initiator key.
    const canonical = JSON.stringify({
      type: leaf.type, sessionId: leaf.sessionId, merkleRoot: leaf.merkleRoot,
      leafCount: leaf.leafCount, timestamp: leaf.timestamp, signerPubkey: leaf.signerPubkey,
    });
    const ok = ed25519Verify(
      new Uint8Array(Buffer.from(alicePubkey, "hex")),
      new TextEncoder().encode(canonical),
      new Uint8Array(Buffer.from(leaf.signature as string, "hex")),
    );
    expect(ok).toBe(true);
  });

  it("DB-002: active close while signaling reconnecting returns signaling_reconnecting and does NOT initiate a seal", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("alice");
    const node = new FakeNode();
    // No signalingConnect → SignalingManager stays 'reconnecting'.
    const h = await start({ logger, node });
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
    snm.appendSessionLeaf(SID, "msg", Buffer.from(msgLeafHash(new TextEncoder().encode("m1"))).toString("hex"));

    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });
      await client.send("cello_start_agent", { name: "alice" });
      await client.send("cello_use_agent", { name: "alice" });
      const res = await client.send("cello_close_session", { sessionId: SID }) as Record<string, unknown>;
      expect(res.ok).toBe(false);
      expect(res.reason).toBe("signaling_reconnecting");
      expect(typeof res.guidance).toBe("string");
    } finally { client.close(); }

    // No partial seal initiated.
    expect(events.find((e) => e.event === "session.seal.initiated")).toBeUndefined();
  });
});
