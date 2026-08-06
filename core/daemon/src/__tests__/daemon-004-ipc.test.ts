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
import { FileKeyProvider, generateKeypair, verify as ed25519Verify, docLeafHash, rejectLeafHash } from "@cello-protocol/crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
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
  stopped = false;
  constructor(private opts: { newStreamFails?: boolean } = {}) {}
  readonly #peerId = `fake-${Math.random().toString(36).slice(2)}`;
  async start(): Promise<void> {}
  async stop(): Promise<void> { this.stopped = true; }
  getPeerId(): string { return this.#peerId; }
  listenAddresses(): string[] { return ["/ip4/127.0.0.1/tcp/0"]; }
  async dial(_a: string): Promise<{ peerId: string }> { return { peerId: "remote" }; }
  async handle(_p: string, _h: unknown): Promise<void> {}
  getProtocols(): string[] { return []; }
  getConnections(): Array<{ peerId: string; encryption: string | undefined }> { return []; }
  onPeerConnect(_h: (p: string) => void): void {}
  onPeerDisconnect(_h: (p: string) => void): void {}
  getDialability(): { dialable: boolean; publicAddr: string | null } { return { dialable: false, publicAddr: null }; }
  onDialabilityChange(_l: (d: { dialable: boolean; publicAddr: string | null }) => void): () => void { return () => {}; }
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

/** Canonical SEAL-INTERRUPTED leaf bytes — MUST match daemon.ts exactly. */
function canonicalLeafBytes(leaf: {
  type: string; sessionId: string; leafCount: number;
  merkleRootAtInterruption: string; timestamp: number; signerPubkey: string;
}): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({
    type: leaf.type, sessionId: leaf.sessionId, leafCount: leaf.leafCount,
    merkleRootAtInterruption: leaf.merkleRootAtInterruption, timestamp: leaf.timestamp,
    signerPubkey: leaf.signerPubkey,
  }));
}

/** Build a real K_local-signed SEAL-INTERRUPTED leaf using a real keypair. */
async function signLeaf(
  kp: KeyProvider,
  opts: { sessionId: string; leafCount: number; merkleRootAtInterruption: string; signerPubkeyHex: string },
): Promise<Record<string, unknown>> {
  const partial = {
    type: "SEAL_INTERRUPTED", sessionId: opts.sessionId, leafCount: opts.leafCount,
    merkleRootAtInterruption: opts.merkleRootAtInterruption, timestamp: Date.now(),
    signerPubkey: opts.signerPubkeyHex,
  };
  const sig = await kp.sign(canonicalLeafBytes(partial));
  return { ...partial, signature: Buffer.from(sig).toString("hex") };
}

/**
 * Signaling stream that records sent frames AND plays the counterparty: on a
 * `seal_interrupted_request` it co-signs a SEAL-INTERRUPTED ack leaf with the
 * counterparty key (over whatever root + leafCount the initiator sent) and
 * delivers the ack back. Mirrors the SESSION-001 initiator-flow test stub.
 */
function makeRespondingSignaling(
  captured: Record<string, unknown>[],
  cpKp: KeyProvider,
  cpPubkeyHex: string,
  ackDelayMs = 0,
): () => Promise<ConnectResult> {
  let inbound: ((frame: unknown) => void) | null = null;
  const stream: SignalingStream = {
    send: async (frame: unknown) => {
      const f = frame as Record<string, unknown>;
      captured.push(f);
      if (f.type === "seal_interrupted_request") {
        const leaf = await signLeaf(cpKp, {
          sessionId: f.sessionId as string,
          leafCount: f.leafCountAtInterruption as number,
          merkleRootAtInterruption: f.merkleRootAtInterruption as string,
          signerPubkeyHex: cpPubkeyHex,
        });
        const deliver = () => inbound?.({
          type: "seal_interrupted_ack",
          sessionId: f.sessionId,
          initiatorPubkey: f.initiatorPubkey,
          nonce: f.nonce,
          sealInterruptedLeaf: leaf,
        });
        // ackDelayMs > 0 keeps the initiator flow in-progress long enough to make
        // the concurrency guard (finding #4) observable; 0 → next-tick (default).
        if (ackDelayMs > 0) setTimeout(deliver, ackDelayMs);
        else setImmediate(deliver);
      }
    },
    onMessage: (h: (frame: unknown) => void) => { inbound = h; },
    close: () => {},
  };
  return async () => ({ stream, directoryNodeId: "fake-dir", manifestVersion: 1 });
}

/**
 * Signaling stub that captures outbound frames AND lets the test inject an inbound
 * frame (via injectRef.inject). Used to drive the bilateral RESPONDER path
 * (handleInboundSealInterruptedRequest) directly — finding #6 / SI-001.
 */
function makeInjectableSignaling(
  captured: Record<string, unknown>[],
  injectRef: { inject?: (frame: unknown) => void },
): () => Promise<ConnectResult> {
  let inbound: ((frame: unknown) => void) | null = null;
  const stream: SignalingStream = {
    send: async (frame: unknown) => { captured.push(frame as Record<string, unknown>); },
    onMessage: (h: (frame: unknown) => void) => { inbound = h; },
    close: () => {},
  };
  injectRef.inject = (frame: unknown) => inbound?.(frame);
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
    securityGateway: new PassthroughGatewayClient(),
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
      const res = await client.send("cello_send", { session_id: SID, content: "hello" }) as Record<string, unknown>;
      expect(res.reason).not.toBe("not_implemented");
      expect(res.ok).toBe(true);
      expect(typeof res.sequence_number).toBe("number");
    } finally { client.close(); }

    // content_frame was sent over the (fake) session stream.
    expect(node.sent.length).toBe(1);
    // Tree advanced + events fired.
    expect(snm.getSessionTree("alice", SID).size()).toBe(1);
    expect(events.find((e) => e.event === "session.content.sent")).toBeDefined();
    expect(events.find((e) => e.event === "session.tree.appended")).toBeDefined();
  });

  // ─── round-2 BLOCKING regression: production proxy param contract ───────────
  // The only shipped producer of these IPC calls is cello-mcp.ts, which forwards
  // the public MCP tool fields VERBATIM through IpcProxy.call (ipc-proxy.ts:128 →
  // JSON.stringify({ id, method, params })). connectToDaemon().send (ipc-client.ts:60)
  // is the byte-identical passthrough — neither side rewrites keys. So sending the
  // snake_case public field `session_id` here reproduces the exact wire frame the
  // shipped binary emits. Before this fix the daemon read camelCase `params.sessionId`,
  // so EVERY real cello_send/cello_receive/cello_close_session returned missing_params.
  // This test fails closed if the daemon ever drifts back to camelCase.
  it("production param contract: cello_send/receive/close_session accept snake_case session_id (the shipped proxy shape) and reject camelCase sessionId", async () => {
    const { logger } = makeLogger();
    await makeAgentDir("alice");
    // Real counterparty keypair so the active close can complete the bilateral ack.
    const cpKp = generateKeypair();
    const cpPubkeyHex = Buffer.from(await cpKp.getPublicKey()).toString("hex");
    const node = new FakeNode();
    const captured: Record<string, unknown>[] = [];
    const h = await start({ logger, node, signalingConnect: makeRespondingSignaling(captured, cpKp, cpPubkeyHex) });
    await new Promise((r) => setTimeout(r, 50)); // let signaling connect
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID, "alice", cpPubkeyHex, "bob-peer-id", "corr");
    // Buffer one inbound message so cello_receive has something to return.
    const inbound = new TextEncoder().encode("from-bob");
    await snm.ingestReceivedContent("alice", SID, inbound, msgLeafHash(inbound));

    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });
      await client.send("cello_start_agent", { name: "alice" });
      await client.send("cello_use_agent", { name: "alice" });

      // M8C-CURSOR-1: read-before-write — a message was buffered (ingestReceivedContent, above)
      // before this connection ever attached, so cello_send would now correctly be refused
      // session_not_current until it's read. Read it first (the real operator flow), THEN send —
      // this also lets the existing recvOk assertions below move earlier without losing coverage.
      const recvOk = await client.send("cello_receive", { session_id: SID }) as Record<string, unknown>;
      expect(recvOk.ok).toBe(true);
      expect(recvOk.content).toBe("from-bob");
      // M8C-AWAY-1: the agent was unattended when the message above was ingested, so the daemon
      // ALSO auto-acked it (a real, correct cross-unit interaction) — cello_get_transcript catches
      // up on that too (cello_receive only drains the received-content buffer, not the auto-ack).
      await client.send("cello_get_transcript", { session_id: SID });

      // ── snake_case (the real proxy shape) → works ──
      const sendOk = await client.send("cello_send", { session_id: SID, content: "hello" }) as Record<string, unknown>;
      expect(sendOk.ok).toBe(true);
      expect(sendOk.reason).toBeUndefined();

      // ── camelCase (the pre-fix bug shape) → rejected as missing_params, NOT silently accepted ──
      const sendCamel = await client.send("cello_send", { sessionId: SID, content: "hello" }) as Record<string, unknown>;
      expect(sendCamel.ok).toBe(false);
      expect(sendCamel.reason).toBe("missing_params");
      const recvCamel = await client.send("cello_receive", { sessionId: SID }) as Record<string, unknown>;
      expect(recvCamel.ok).toBe(false);
      expect(recvCamel.reason).toBe("missing_params");
      const closeCamel = await client.send("cello_close_session", { sessionId: SID }) as Record<string, unknown>;
      expect(closeCamel.ok).toBe(false);
      expect(closeCamel.reason).toBe("missing_params");

      // ── snake_case close on the active session → seal_interrupted_pending (matches persisted row) ──
      const closeOk = await client.send("cello_close_session", { session_id: SID }) as Record<string, unknown>;
      expect(closeOk.ok).toBe(true);
      expect(closeOk.status).toBe("seal_interrupted_pending");
    } finally { client.close(); }
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
      const res = await client.send("cello_send", { session_id: SID, content: "hello" }) as Record<string, unknown>;
      expect(res.ok).toBe(false);
      expect(res.reason).not.toBe("not_implemented");
      expect(typeof res.reason).toBe("string");
      expect((res.reason as string).length).toBeGreaterThan(0);
      expect(typeof res.guidance).toBe("string");
      // session still usable — a second send still reaches the send path (same failure, not desync)
      const res2 = await client.send("cello_send", { session_id: SID, content: "again" }) as Record<string, unknown>;
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
    expect(snm.getSessionTree("alice", SID).size()).toBe(0);
  });

  it("AC-001 receive: cello_receive returns content ingested into the daemon buffer", async () => {
    const { logger } = makeLogger();
    await makeAgentDir("alice");
    const node = new FakeNode();
    const h = await start({ logger, node });
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
    const content = new TextEncoder().encode("from-bob");
    await snm.ingestReceivedContent("alice", SID, content, msgLeafHash(content));

    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });
      await client.send("cello_start_agent", { name: "alice" });
      await client.send("cello_use_agent", { name: "alice" });
      const res = await client.send("cello_receive", { session_id: SID }) as Record<string, unknown>;
      expect(res.reason).not.toBe("not_implemented");
      expect(res.ok).toBe(true);
      expect(res.content).toBe("from-bob");
    } finally { client.close(); }
  });

  it("AC-003 + SI-001 + SI-003: active close initiates a bilateral seal over the daemon's OWN root, ignoring a caller merkleRoot, and awaits the counterparty's own-signed ack", async () => {
    const { logger, events } = makeLogger();
    const alicePubkey = await makeAgentDir("alice");
    // Real counterparty keypair so its ack leaf carries a verifiable signature.
    const cpKp = generateKeypair();
    const cpPubkeyHex = Buffer.from(await cpKp.getPublicKey()).toString("hex");
    const node = new FakeNode();
    const captured: Record<string, unknown>[] = [];
    const h = await start({ logger, node, signalingConnect: makeRespondingSignaling(captured, cpKp, cpPubkeyHex) });
    await new Promise((r) => setTimeout(r, 50)); // let signaling connect
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID, "alice", cpPubkeyHex, "bob-peer-id", "corr");
    // Append two message leaves so the tree has a non-empty, real root.
    snm.appendSessionLeaf("alice", SID, "msg", Buffer.from(msgLeafHash(new TextEncoder().encode("m1"))).toString("hex"));
    snm.appendSessionLeaf("alice", SID, "msg", Buffer.from(msgLeafHash(new TextEncoder().encode("m2"))).toString("hex"));
    const ownRoot = snm.getSessionTreeRootHex("alice", SID);

    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });
      await client.send("cello_start_agent", { name: "alice" });
      await client.send("cello_use_agent", { name: "alice" });
      // SI-001: supply a bogus caller merkleRoot — it MUST be ignored.
      const res = await client.send("cello_close_session", { session_id: SID, merkleRoot: "ff".repeat(32) }) as Record<string, unknown>;
      expect(res.reason).not.toBe("not_implemented");
      expect(res.ok).toBe(true);
      expect(res.status).toBe("seal_interrupted_pending");
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

    // Finding #1: the daemon sends the WIRED seal_interrupted_request (the only
    // frame the directory routes), NOT an unwired seal_request. It binds the
    // daemon's OWN root + size (SI-001), never the caller's "ff..." value.
    const sealReq = captured.find((f) => f.type === "seal_interrupted_request");
    expect(sealReq).toBeDefined();
    expect(captured.find((f) => f.type === "seal_request")).toBeUndefined();
    expect(sealReq!.merkleRootAtInterruption).toBe(ownRoot);
    expect(sealReq!.merkleRootAtInterruption).not.toBe("ff".repeat(32));
    expect(sealReq!.leafCountAtInterruption).toBe(2);
    expect(sealReq!.initiatorPubkey).toBe(alicePubkey);
    // The request frame carries no counterparty signature — the initiator never produces it.
    expect(sealReq!.sealInterruptedLeaf).toBeUndefined();
    expect(sealReq!.counterpartySignature).toBeUndefined();

    // SI-003: the persisted bilateral commitment has BOTH leaves signed by their
    // OWN owners — alice's own leaf by alice, the counterparty leaf by the
    // counterparty's own key (never synthesized by the initiator).
    const art = snm.getSealInterruptedArtifacts("alice", SID);
    expect(art).not.toBeNull();
    expect(art!.role).toBe("initiator");
    expect(art!.merkleRoot).toBe(ownRoot);
    const ownLeaf = art!.ownLeaf as Record<string, unknown>;
    const cpLeaf = art!.counterpartyLeaf as Record<string, unknown>;
    expect(ownLeaf.signerPubkey).toBe(alicePubkey);
    expect(cpLeaf.signerPubkey).toBe(cpPubkeyHex);
    // The counterparty's ack leaf verifies under the COUNTERPARTY's key (SI-003).
    const cpOk = ed25519Verify(
      new Uint8Array(Buffer.from(cpPubkeyHex, "hex")),
      canonicalLeafBytes(cpLeaf as { type: string; sessionId: string; leafCount: number; merkleRootAtInterruption: string; timestamp: number; signerPubkey: string }),
      new Uint8Array(Buffer.from(cpLeaf.signature as string, "hex")),
    );
    expect(cpOk).toBe(true);
    // alice's own leaf verifies under alice's key.
    const ownOk = ed25519Verify(
      new Uint8Array(Buffer.from(alicePubkey, "hex")),
      canonicalLeafBytes(ownLeaf as { type: string; sessionId: string; leafCount: number; merkleRootAtInterruption: string; timestamp: number; signerPubkey: string }),
      new Uint8Array(Buffer.from(ownLeaf.signature as string, "hex")),
    );
    expect(ownOk).toBe(true);
  });

  it("AC-007: after SIGKILL+restart, cello_close_session seals over the RELOADED daemon-owned root (not message_count / caller root)", async () => {
    const { logger } = makeLogger();
    const alicePubkey = await makeAgentDir("alice");
    const cpKp = generateKeypair();
    const cpPubkeyHex = Buffer.from(await cpKp.getPublicKey()).toString("hex");

    // ── Daemon 1: build a transcript of 3 leaves, then "crash" (stop). ──
    const node1 = new FakeNode();
    const h1 = await start({ logger, node: node1 });
    const snm1 = h1.getSessionNodeManager();
    await snm1.createSessionNode(SID, "alice", cpPubkeyHex, "bob-peer-id", "corr");
    for (const m of ["m1", "m2", "m3"]) {
      snm1.appendSessionLeaf("alice", SID, "msg", Buffer.from(msgLeafHash(new TextEncoder().encode(m))).toString("hex"));
    }
    const rootBeforeCrash = snm1.getSessionTreeRootHex("alice", SID);
    expect(snm1.getSessionTree("alice", SID).size()).toBe(3);
    await h1.stop("simulated_sigkill");
    handle = null;

    // ── Daemon 2: restart over the SAME celloDir. initialize() forces the
    //    active session → interrupted; the tree reloads from session_tree_leaves. ──
    const captured: Record<string, unknown>[] = [];
    const node2 = new FakeNode();
    const h2 = await start({ logger, node: node2, signalingConnect: makeRespondingSignaling(captured, cpKp, cpPubkeyHex) });
    await new Promise((r) => setTimeout(r, 50));
    const snm2 = h2.getSessionNodeManager();
    // Transcript survived the restart boundary.
    expect(snm2.getSessionTree("alice", SID).size()).toBe(3);
    expect(snm2.getSessionTreeRootHex("alice", SID)).toBe(rootBeforeCrash);

    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });
      await client.send("cello_start_agent", { name: "alice" });
      await client.send("cello_use_agent", { name: "alice" });
      // SI-001: a bogus caller root must be ignored — the reloaded tree root wins.
      const res = await client.send("cello_close_session", { session_id: SID, merkleRootAtInterruption: "ff".repeat(32) }) as Record<string, unknown>;
      expect(res.ok).toBe(true);
      expect(res.status).toBe("seal_interrupted_pending");
    } finally { client.close(); }

    // The seal request bound the RELOADED root + size — not message_count=0, not "ff...".
    const sealReq = captured.find((f) => f.type === "seal_interrupted_request");
    expect(sealReq).toBeDefined();
    expect(sealReq!.merkleRootAtInterruption).toBe(rootBeforeCrash);
    expect(sealReq!.merkleRootAtInterruption).not.toBe("ff".repeat(32));
    expect(sealReq!.leafCountAtInterruption).toBe(3);
    expect(sealReq!.initiatorPubkey).toBe(alicePubkey);

    // The persisted commitment seals over the reloaded root.
    const art = snm2.getSealInterruptedArtifacts("alice", SID);
    expect(art).not.toBeNull();
    expect(art!.merkleRoot).toBe(rootBeforeCrash);
  });

  // DOD-DOC-LEAF-1 (review): the reload path itself, not just the mapper function. Before this
  // unit, #loadTreeFromDb read `leaf_kind === "ctrl" ? "ctrl" : "msg"` — a stored document leaf
  // came back labeled "msg" after any restart, which inflates the content-leaf count that the
  // sealed receipt reports. This test is red under that coercion.
  it("DOD-DOC-LEAF-1: doc and reject leaf kinds survive a restart reload — never relabeled 'msg'", async () => {
    const { logger } = makeLogger();
    await makeAgentDir("alice");
    const cpKp = generateKeypair();
    const cpPubkeyHex = Buffer.from(await cpKp.getPublicKey()).toString("hex");

    const h1 = await start({ logger, node: new FakeNode() });
    const snm1 = h1.getSessionNodeManager();
    await snm1.createSessionNode(SID, "alice", cpPubkeyHex, "bob-peer-id", "corr");
    snm1.appendSessionLeaf("alice", SID, "msg", Buffer.from(msgLeafHash(new TextEncoder().encode("m1"))).toString("hex"));
    snm1.appendSessionLeaf("alice", SID, "doc", Buffer.from(docLeafHash(new TextEncoder().encode("update"))).toString("hex"));
    snm1.appendSessionLeaf("alice", SID, "reject", Buffer.from(rejectLeafHash(new TextEncoder().encode("rejected"))).toString("hex"));
    const rootBefore = snm1.getSessionTreeRootHex("alice", SID);
    await h1.stop("simulated_sigkill");
    handle = null;

    const h2 = await start({ logger, node: new FakeNode(), signalingConnect: makeRespondingSignaling([], cpKp, cpPubkeyHex) });
    await new Promise((r) => setTimeout(r, 50));
    const reloaded = h2.getSessionNodeManager().getSessionTree("alice", SID);

    expect(reloaded.leaves().map((l) => l.kind)).toEqual(["msg", "doc", "reject"]);
    // The root is identical either way — the stored hash carries its own domain — so the kind
    // label is what the content count depends on, and exactly one leaf is content.
    expect(reloaded.rootHex()).toBe(rootBefore);
    expect(reloaded.leaves().filter((l) => l.kind === "msg").length).toBe(1);
  });

  it("finding #4: two concurrent active cello_close_session calls — only one initiates a seal; the other is rejected seal_interrupted_in_progress", async () => {
    const { logger } = makeLogger();
    await makeAgentDir("alice");
    const cpKp = generateKeypair();
    const cpPubkeyHex = Buffer.from(await cpKp.getPublicKey()).toString("hex");
    const node = new FakeNode();
    const captured: Record<string, unknown>[] = [];
    // Delay the ack so the FIRST close is still in-progress when the SECOND arrives.
    const h = await start({ logger, node, signalingConnect: makeRespondingSignaling(captured, cpKp, cpPubkeyHex, 120) });
    await new Promise((r) => setTimeout(r, 50));
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID, "alice", cpPubkeyHex, "bob-peer-id", "corr");
    snm.appendSessionLeaf("alice", SID, "msg", Buffer.from(msgLeafHash(new TextEncoder().encode("m1"))).toString("hex"));

    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });
      await client.send("cello_start_agent", { name: "alice" });
      await client.send("cello_use_agent", { name: "alice" });
      const [r1, r2] = await Promise.all([
        client.send("cello_close_session", { session_id: SID }),
        client.send("cello_close_session", { session_id: SID }),
      ]) as Record<string, unknown>[];
      const results = [r1, r2];
      const inProgress = results.filter((r) => r.reason === "seal_interrupted_in_progress");
      const initiated = results.filter((r) => r.ok === true && r.status === "seal_interrupted_pending");
      // Exactly one initiates the seal; the other is rejected by the concurrency guard.
      expect(inProgress).toHaveLength(1);
      expect(initiated).toHaveLength(1);
    } finally { client.close(); }

    // Only ONE seal_interrupted_request was sent — no double seal.
    expect(captured.filter((f) => f.type === "seal_interrupted_request")).toHaveLength(1);
  });

  it("finding #5: after an active seal initiates, the session node is torn down (no leaked libp2p node, content handler retired)", async () => {
    const { logger } = makeLogger();
    await makeAgentDir("alice");
    const cpKp = generateKeypair();
    const cpPubkeyHex = Buffer.from(await cpKp.getPublicKey()).toString("hex");
    const node = new FakeNode();
    const captured: Record<string, unknown>[] = [];
    const h = await start({ logger, node, signalingConnect: makeRespondingSignaling(captured, cpKp, cpPubkeyHex) });
    await new Promise((r) => setTimeout(r, 50));
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID, "alice", cpPubkeyHex, "bob-peer-id", "corr");
    snm.appendSessionLeaf("alice", SID, "msg", Buffer.from(msgLeafHash(new TextEncoder().encode("m1"))).toString("hex"));
    expect(node.stopped).toBe(false);

    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });
      await client.send("cello_start_agent", { name: "alice" });
      await client.send("cello_use_agent", { name: "alice" });
      const res = await client.send("cello_close_session", { session_id: SID }) as Record<string, unknown>;
      expect(res.ok).toBe(true);
    } finally { client.close(); }

    // The session's libp2p node was stopped — no leak per active close.
    expect(node.stopped).toBe(true);
    // The durable transcript survives teardown (tree reloads from SQLite).
    expect(snm.getSessionTree("alice", SID).size()).toBe(1);
  });

  it("finding #6 (SI-001 responder): an active-session responder co-signs its OWN tree root, never the initiator-supplied root", async () => {
    const { logger } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const node = new FakeNode();
    const captured: Record<string, unknown>[] = [];
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start({ logger, node, signalingConnect: makeInjectableSignaling(captured, injectRef) });
    await new Promise((r) => setTimeout(r, 50));
    const snm = h.getSessionNodeManager();
    const initiatorPubkey = "cd".repeat(32);
    // Bob has an ACTIVE session with no content yet — his own tree is empty.
    await snm.createSessionNode(SID, "bob", initiatorPubkey, "alice-peer-id", "corr");
    const bobOwnRoot = snm.getSessionTreeRootHex("bob", SID); // canonical empty-tree root

    // The initiator sends a BOGUS merkleRoot. SI-001: Bob must co-sign his OWN root.
    injectRef.inject!({
      type: "seal_interrupted_request",
      sessionId: SID,
      initiatorPubkey,
      counterpartyPubkey: bobPubkey,
      leafCountAtInterruption: 0,
      merkleRootAtInterruption: "ff".repeat(32),
      nonce: "nonce-r6",
    });
    await new Promise((r) => setTimeout(r, 80));

    const ack = captured.find((f) => f.type === "seal_interrupted_ack") as Record<string, unknown> | undefined;
    expect(ack).toBeDefined();
    const leaf = ack!.sealInterruptedLeaf as Record<string, unknown>;
    // SI-001: Bob signed his OWN empty-tree root, NOT the initiator-supplied "ff..".
    expect(leaf.merkleRootAtInterruption).toBe(bobOwnRoot);
    expect(leaf.merkleRootAtInterruption).not.toBe("ff".repeat(32));
    expect(leaf.signerPubkey).toBe(bobPubkey);
  });

  it("DB-002: active close while signaling reconnecting returns signaling_reconnecting and does NOT initiate a seal", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("alice");
    const node = new FakeNode();
    // No signalingConnect → SignalingManager stays 'reconnecting'.
    const h = await start({ logger, node });
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
    snm.appendSessionLeaf("alice", SID, "msg", Buffer.from(msgLeafHash(new TextEncoder().encode("m1"))).toString("hex"));

    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });
      await client.send("cello_start_agent", { name: "alice" });
      await client.send("cello_use_agent", { name: "alice" });
      const res = await client.send("cello_close_session", { session_id: SID }) as Record<string, unknown>;
      expect(res.ok).toBe(false);
      expect(res.reason).toBe("signaling_reconnecting");
      expect(typeof res.guidance).toBe("string");
    } finally { client.close(); }

    // No partial seal initiated.
    expect(events.find((e) => e.event === "session.seal.initiated")).toBeUndefined();
  });

  // ─── F1-a/a2/b/c — blocking receive + seal terminal answer ──────────────────

  it("F1-a: cello_receive BLOCKS up to timeout_ms and returns content that arrives AFTER the call begins", async () => {
    const { logger } = makeLogger();
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

      // Buffer is empty when the receive begins; content lands ~40ms later.
      const content = new TextEncoder().encode("delayed-hello");
      const recvPromise = client.send("cello_receive", { session_id: SID, timeout_ms: 2000 }) as Promise<Record<string, unknown>>;
      setTimeout(() => { void snm.ingestReceivedContent("alice", SID, content, msgLeafHash(content)); }, 40);

      const res = await recvPromise;
      expect(res.ok).toBe(true);
      expect(res.content).toBe("delayed-hello");
    } finally { client.close(); }
  });

  it("F1-a: cello_receive returns { ok:true, content:null } on timeout when nothing arrives", async () => {
    const { logger } = makeLogger();
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
      const res = await client.send("cello_receive", { session_id: SID, timeout_ms: 60 }) as Record<string, unknown>;
      expect(res.ok).toBe(true);
      expect(res.content).toBeNull();
    } finally { client.close(); }
  });

  it("DOD-ONBOARD-HELP-1: cello_receive_session is DELETED — the handler is GONE, not stubbed", async () => {
    // It used to be a literal alias: `handlers.set("cello_receive_session", handleReceive)` — the SAME
    // handler object as cello_receive. Its help claimed an "accept/join" step CELLO does not have
    // (inbound sessions are auto-accepted by the standing receiver), so it was a command that did
    // nothing distinct and described itself falsely. Andre ruled: delete it outright — no alias, no
    // deprecated shim, NO DEAD HANDLER left behind.
    //
    // This test is the inversion of the one it replaces (which asserted the alias was live). A
    // deletion that no test can see is a deletion that grows back.
    const { logger } = makeLogger();
    await makeAgentDir("alice");
    const node = new FakeNode();
    await start({ logger, node });

    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });
      await expect(
        client.send("cello_receive_session", { session_id: SID, timeout_ms: 500 }),
      ).rejects.toThrow(/method_not_found|Unknown method/i);
    } finally { client.close(); }
  });

  it("F1-b/c: a seal that evicts UNREAD content sets a session_sealed terminal marker (with unread_count) and logs session.receive.buffer.evicted", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("alice");
    const node = new FakeNode();
    const h = await start({ logger, node });
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr");

    // One inbound message is buffered but NEVER read (mirrors the live final-message race).
    const inbound = new TextEncoder().encode("unread-final-message");
    await snm.ingestReceivedContent("alice", SID, inbound, msgLeafHash(inbound));

    // Seal teardown evicts the unread buffer.
    await snm.destroySessionNode("alice", SID, "sealed");

    // F1-c: the silent drop is now diagnosable.
    const evicted = events.find((e) => e.event === "session.receive.buffer.evicted");
    expect(evicted).toBeDefined();
    expect(evicted!.context.unreadCount).toBe(1);
    expect(evicted!.context.sessionId).toBe(SID);

    // F1-b: a receive after seal returns the terminal answer instead of hanging or 404ing.
    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });
      await client.send("cello_start_agent", { name: "alice" });
      await client.send("cello_use_agent", { name: "alice" });
      const res = await client.send("cello_receive", { session_id: SID, timeout_ms: 500 }) as Record<string, unknown>;
      expect(res.ok).toBe(true);
      expect(res.type).toBe("session_sealed");
      expect(res.unread_count).toBe(1);
      expect(typeof res.guidance).toBe("string");
    } finally { client.close(); }
  });

  it("DOD-TERMINAL-WAKE-1: the sealed answer SURVIVES a daemon restart — an unread message must not come back as live work", async () => {
    // Observed live 2026-08-05 on Miss_Chelly_H: three sessions sealed in the morning re-fired as
    // wakes six to eight hours later, and one carried a `[[STANDBY EST:15m]]` directive the agent
    // obeyed — standing by on a conversation that had ended, against a counterparty whose daemon
    // held no record of the session. An agent acting on an expired instruction is a correctness
    // failure, and it is self-concealing: the agent reports a perfectly coherent status.
    //
    // The trigger is a RESTART. `#sessionTerminal` is an in-memory Map populated only by
    // destroySessionNode; the session row on disk still says 'sealed', but after a restart the map
    // is empty, peekTerminalMarker answers null, and the durable-record read below it happily
    // delivers the old message as if it had just arrived.
    const { logger } = makeLogger();
    await makeAgentDir("alice");
    const node = new FakeNode();
    const h1 = await start({ logger, node });
    const snm = h1.getSessionNodeManager();
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr");

    const inbound = new TextEncoder().encode("[[STANDBY EST:15m]] hold for my next message");
    await snm.ingestReceivedContent("alice", SID, inbound, msgLeafHash(inbound));
    await snm.destroySessionNode("alice", SID, "sealed");

    // The restart is the whole point: same celloDir, so the sealed row persists and the marker does not.
    await h1.stop("test_restart");
    const { logger: logger2 } = makeLogger();
    await start({ logger: logger2, node: new FakeNode() });

    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });
      await client.send("cello_start_agent", { name: "alice" });
      await client.send("cello_use_agent", { name: "alice" });
      const res = await client.send("cello_receive", { session_id: SID, timeout_ms: 500 }) as Record<string, unknown>;

      // The message must NOT be delivered as live content.
      expect(res.content).toBeUndefined();
      expect(res.type).toBe("session_sealed");
      expect(res.unread_count).toBe(1);
      // It is still on the record — the seal attests what each side actually consumed, so the
      // message stays honestly unread. It just stops ringing the bell. (The surface vocabulary
      // renders the tool name for the caller's surface, hence the loose match on the stem.)
      expect(String(res.guidance)).toMatch(/transcript/);
    } finally { client.close(); }
  });
});
