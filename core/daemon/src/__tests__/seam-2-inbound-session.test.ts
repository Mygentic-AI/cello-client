/**
 * Seam 2 — inbound session establishment (counterparty side), in-process.
 *
 * Traces the connection point that was broken before this seam: the directory
 * PUSHES a FROST-signed SessionAssignment to the counterparty (B) over B's
 * directory signaling stream as an unsolicited `session_assignment` frame, but
 * the daemon routed only registration + seal-interrupted inbound frames — there
 * was no path from that frame to a live inbound session, and cello_await_session
 * was a `not_implemented` stub.
 *
 * This verifies the wired seam end-to-end IN PROCESS with a stub (injectable)
 * signaling stream and a fake session node:
 *
 *   inbound session_assignment frame
 *     → resolve participant_b → local agent
 *     → SessionNodeManager.acceptSession (standing receiver handed off, bound to A)
 *     → session-core has an ACTIVE session row (queryable)
 *     → inbound event enqueued
 *     → cello_await_session returns { type: "new_session", session_id, counterparty_pubkey, genesis_prev_root }
 *
 * No infra, no relay, no real directory — the directory's push is injected as a
 * trusted frame. The FROST signature verification of the assignment is the
 * SESSION-004 re-home (deferred); this seam asserts that deferral is logged loudly
 * (session.inbound.assignment.unverified), never silent.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FileKeyProvider } from "@cello-protocol/crypto";
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

// Minimal fake session node — the standing receiver and any session node the
// factory hands out. AutoNAT methods are required by NodeAutoNatService.
class FakeNode implements Partial<CelloNode> {
  stopped = false;
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
    const sink: Uint8Array[] = [];
    return { send(d: Uint8Array) { sink.push(d); }, async close() {}, abort() {}, status: "open" } as unknown as Stream;
  }
}

class FixedFactory implements ISessionNodeFactory {
  constructor(private node: CelloNode) {}
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> { return this.node; }
}

/**
 * Signaling stub that records outbound frames AND lets the test inject an inbound
 * frame (via injectRef.inject) — the directory's push channel.
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

describe("Seam 2: inbound session_assignment → acceptSession → cello_await_session", () => {
  let tempDir: string;
  let handle: Awaited<ReturnType<typeof startDaemon>> | null;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-seam2-"));
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
    signalingConnect: () => Promise<ConnectResult>;
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

  // session_id is 16 bytes per the protocol; the daemon hex-encodes it.
  const SID_BYTES = Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 1));
  const SID_HEX = Buffer.from(SID_BYTES).toString("hex");

  /** Build a directory-pushed session_assignment frame addressed to participant_b. */
  function assignmentFrame(opts: {
    sessionId: Uint8Array;
    initiatorPubkeyHex: string;   // participant_a (our counterparty)
    counterpartyPubkeyHex: string; // participant_b (the local agent)
    initiatorPeerId: string;
  }): Record<string, unknown> {
    return {
      type: "session_assignment",
      assignment: {
        session_id: opts.sessionId,
        participant_a: { pubkey: Buffer.from(opts.initiatorPubkeyHex, "hex") },
        participant_b: { pubkey: Buffer.from(opts.counterpartyPubkeyHex, "hex") },
        initiator_session_peer_id: opts.initiatorPeerId,
        signature_type: "frost",
      },
    };
  }

  it("turns a pushed session_assignment into an active inbound session that cello_await_session returns", async () => {
    const { logger, events } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const node = new FakeNode();
    const captured: Record<string, unknown>[] = [];
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start({ logger, node, signalingConnect: makeInjectableSignaling(captured, injectRef) });
    await new Promise((r) => setTimeout(r, 50)); // let signaling connect + standing receiver come up

    const snm = h.getSessionNodeManager();
    const initiatorPubkey = "cd".repeat(32);

    // The directory pushes the assignment to bob (participant_b).
    injectRef.inject!(assignmentFrame({
      sessionId: SID_BYTES,
      initiatorPubkeyHex: initiatorPubkey,
      counterpartyPubkeyHex: bobPubkey,
      initiatorPeerId: "alice-session-peer-id",
    }));
    await new Promise((r) => setTimeout(r, 80)); // async inbound handler

    // (1) Session-core observable: bob now has an ACTIVE session row bound to alice.
    const record = snm.getSessionRecord(SID_HEX);
    expect(record).not.toBeNull();
    expect(record!.status).toBe("active");
    expect(record!.agent_name).toBe("bob");
    expect(record!.counterparty_pubkey).toBe(initiatorPubkey);

    // (2) The deferred FROST-verification gap is logged loudly (never silent).
    expect(events.find((e) => e.event === "session.inbound.assignment.unverified")).toBeDefined();
    expect(events.find((e) => e.event === "session.inbound.accepted")).toBeDefined();

    // (3) cello_await_session returns the queued inbound session for bob's connection.
    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });
      await client.send("cello_start_agent", { name: "bob" });
      await client.send("cello_use_agent", { name: "bob" });
      const res = await client.send("cello_await_session", { timeout_ms: 1000 }) as Record<string, unknown>;
      expect(res.type).toBe("new_session");
      expect(res.session_id).toBe(SID_HEX);
      expect(res.counterparty_pubkey).toBe(initiatorPubkey);
      expect(typeof res.genesis_prev_root).toBe("string");
    } finally { client.close(); }
  });

  it("blocks cello_await_session until a session_assignment arrives, then returns it", async () => {
    const { logger } = makeLogger();
    const bobPubkey = await makeAgentDir("bob");
    const node = new FakeNode();
    const captured: Record<string, unknown>[] = [];
    const injectRef: { inject?: (frame: unknown) => void } = {};
    await start({ logger, node, signalingConnect: makeInjectableSignaling(captured, injectRef) });
    await new Promise((r) => setTimeout(r, 50));

    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });
      await client.send("cello_start_agent", { name: "bob" });
      await client.send("cello_use_agent", { name: "bob" });

      // Start the blocking await BEFORE any assignment exists.
      const awaitP = client.send("cello_await_session", { timeout_ms: 2000 }) as Promise<Record<string, unknown>>;
      await new Promise((r) => setTimeout(r, 40)); // ensure the waiter is registered

      const initiatorPubkey = "ab".repeat(32);
      injectRef.inject!(assignmentFrame({
        sessionId: SID_BYTES,
        initiatorPubkeyHex: initiatorPubkey,
        counterpartyPubkeyHex: bobPubkey,
        initiatorPeerId: "alice-session-peer-id",
      }));

      const res = await awaitP;
      expect(res.type).toBe("new_session");
      expect(res.session_id).toBe(SID_HEX);
      expect(res.counterparty_pubkey).toBe(initiatorPubkey);
    } finally { client.close(); }
  });

  it("ignores a session_assignment not addressed to any local agent (no session, no enqueue)", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("bob");
    const node = new FakeNode();
    const captured: Record<string, unknown>[] = [];
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start({ logger, node, signalingConnect: makeInjectableSignaling(captured, injectRef) });
    await new Promise((r) => setTimeout(r, 50));

    // participant_b is some OTHER pubkey, not bob.
    injectRef.inject!(assignmentFrame({
      sessionId: SID_BYTES,
      initiatorPubkeyHex: "cd".repeat(32),
      counterpartyPubkeyHex: "ee".repeat(32), // not a local agent
      initiatorPeerId: "alice-session-peer-id",
    }));
    await new Promise((r) => setTimeout(r, 80));

    expect(h.getSessionNodeManager().getSessionRecord(SID_HEX)).toBeNull();
    expect(events.find((e) => e.event === "session.inbound.not_local")).toBeDefined();
    expect(events.find((e) => e.event === "session.inbound.accepted")).toBeUndefined();
  });

  it("ignores a malformed session_assignment frame (no assignment payload) without throwing", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("bob");
    const node = new FakeNode();
    const captured: Record<string, unknown>[] = [];
    const injectRef: { inject?: (frame: unknown) => void } = {};
    const h = await start({ logger, node, signalingConnect: makeInjectableSignaling(captured, injectRef) });
    await new Promise((r) => setTimeout(r, 50));

    injectRef.inject!({ type: "session_assignment" }); // no `assignment`
    await new Promise((r) => setTimeout(r, 50));

    expect(h.getSessionNodeManager().getSessionRecord(SID_HEX)).toBeNull();
    expect(events.find((e) => e.event === "session.inbound.accepted")).toBeUndefined();
  });
});
