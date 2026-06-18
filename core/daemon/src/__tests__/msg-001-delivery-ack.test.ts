/**
 * CELLO-M7-MSG-001 — delivery ACK / TTF (send + receive), re-homed onto the daemon.
 *
 * AC-001 (round-trip): after the receiver durably ingests a content frame AND its
 *   content_hash cross-check succeeds, it emits an unsigned `persisted` delivery ACK
 *   back over the session channel; the sender resolves its awaiting-ACK timer and
 *   fires content.delivery.acked. The ACK carries no signature. Verified across two
 *   independent SessionNodeManagers whose nodes are cross-wired so the ACK travels
 *   the real CBOR→lp-frame→decode→handler path (NOT an internal method injection).
 *   The cross-PROCESS variant is the milestone-close live two-daemon smoke.
 * AC-002 (persisted-only): a `received`-level ACK does NOT resolve the timer or fire
 *   content.delivery.acked — the protocol acts on `persisted` ONLY; only the
 *   `persisted` ACK clears it.
 *
 * No signature anywhere on the ACK (SI-004): authentication is the session channel.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import * as lp from "it-length-prefixed";
import { Encoder } from "cbor-x";
import { SessionNodeManager } from "../session-node-manager.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { Logger } from "../types.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";

const CBOR_ENC = new Encoder({ tagUint8Array: false });

interface LogEvent { level: string; event: string; context: Record<string, unknown> }
function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const logger: Logger = {
    debug(event, context) { events.push({ level: "debug", event, context: context ?? {} }); },
    info(event, context) { events.push({ level: "info", event, context: context ?? {} }); },
    warn(event, context) { events.push({ level: "warn", event, context: context ?? {} }); },
    error(event, context) { events.push({ level: "error", event, context: context ?? {} }); },
  };
  return { logger, events };
}

function msgLeafHash(content: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(new Uint8Array([0x00])).update(content).digest());
}

/** A sink that can receive a frame on its registered content handler. */
interface FrameSink { invokeHandler(data: unknown): void }

/**
 * A node whose newStream().send() delivers the framed bytes to its PEER's registered
 * content handler — so two of these, cross-wired, exercise the full content_frame +
 * delivery-ACK round-trip through the real lp/CBOR decode + handler dispatch path.
 */
class WiredNode implements Partial<CelloNode>, FrameSink {
  #handler: ((stream: Stream) => void) | null = null;
  peer: FrameSink | null = null;
  readonly #peerId = `wired-${Math.random().toString(36).slice(2)}`;
  async start(): Promise<void> {}
  async stop(): Promise<void> {}
  getPeerId(): string { return this.#peerId; }
  listenAddresses(): string[] { return ["/ip4/127.0.0.1/tcp/0"]; }
  async dial(_a: string): Promise<{ peerId: string }> { return { peerId: "remote" }; }
  async handle(_p: string, h: (stream: Stream) => void): Promise<void> { this.#handler = h; }
  getProtocols(): string[] { return []; }
  getConnections(): Array<{ peerId: string; encryption: string | undefined }> { return []; }
  onPeerConnect(_h: (p: string) => void): void {}
  onPeerDisconnect(_h: (p: string) => void): void {}
  getDialability(): { dialable: boolean; publicAddr: string | null } { return { dialable: false, publicAddr: null }; }
  onDialabilityChange(_l: (d: { dialable: boolean; publicAddr: string | null }) => void): () => void { return () => {}; }
  invokeHandler(data: unknown): void {
    const h = this.#handler;
    if (!h) return;
    const chunks = [data];
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
    h(inbound);
  }
  async newStream(_peer: string, _proto: string): Promise<Stream> {
    const peer = this.peer;
    return { send(data: unknown) { peer?.invokeHandler(data); }, async close() {}, abort() {}, status: "open" } as unknown as Stream;
  }
}

class ControlledFactory implements ISessionNodeFactory {
  constructor(private node: CelloNode) {}
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> { return this.node; }
}

async function makeManager(logger: Logger, dbPath: string, node: CelloNode, contentTtfMs = 60_000): Promise<SessionNodeManager> {
  const mgr = new SessionNodeManager({ factory: new ControlledFactory(node), logger, dbPath, contentTtfMs });
  await mgr.initialize();
  return mgr;
}

async function waitFor(pred: () => boolean, timeoutMs = 2000): Promise<boolean> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (pred()) return true;
    await new Promise((r) => setTimeout(r, 5));
  }
  return pred();
}

describe("MSG-001: delivery ACK / TTF (daemon)", () => {
  let tempDir: string;
  let managers: SessionNodeManager[] = [];

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-msg001-ack-"));
    managers = [];
  });
  afterEach(async () => {
    for (const m of managers) { try { await m.gracefulShutdown(); } catch { /* ignore */ } }
    await rm(tempDir, { recursive: true, force: true });
  });

  const SID = "ef".repeat(32);

  it("AC-001: receiver auto-ACKs after ingest; sender resolves and fires content.delivery.acked (no signature, no park)", async () => {
    const nodeA = new WiredNode();
    const nodeB = new WiredNode();
    nodeA.peer = nodeB; // A's sends reach B's handler
    nodeB.peer = nodeA; // B's ACK reaches A's handler

    const a = makeLogger();
    const b = makeLogger();
    const mgrA = await makeManager(a.logger, join(tempDir, "a.db"), nodeA);
    const mgrB = await makeManager(b.logger, join(tempDir, "b.db"), nodeB);
    managers.push(mgrA, mgrB);

    await mgrA.createSessionNode(SID, "alice", "bobpk", nodeB.getPeerId(), "corr-a");
    await mgrB.createSessionNode(SID, "bob", "alicepk", nodeA.getPeerId(), "corr-b");

    const content = new TextEncoder().encode("hello over the wire");
    const hash = msgLeafHash(content);
    const res = await mgrA.sendContent(SID, content, hash, "corr-a");
    expect(res.ok).toBe(true);

    // The receiver ingested it (buffered for cello_receive).
    expect(await waitFor(() => mgrB.takeReceivedContent(SID) !== null)).toBe(true);

    // The sender observably transitioned from awaiting → acked over a real ACK frame.
    expect(await waitFor(() => a.events.some((e) => e.event === "content.delivery.acked"))).toBe(true);
    const acked = a.events.find((e) => e.event === "content.delivery.acked");
    expect(acked?.context.contentHash).toBe(Buffer.from(hash).toString("hex"));
    expect(acked?.context.level).toBe("persisted");
    expect(acked?.context.correlationId).toBe("corr-a");
    // The ACK carries no signature anywhere in the flow (SI-004).
    expect(JSON.stringify(a.events)).not.toContain("signature");
    // No park / TTF-expiry happened (the ACK arrived well within the 60s TTF).
    expect(a.events.some((e) => e.event === "content.delivery.ttf_expired")).toBe(false);
  });

  it("AC-002: a `received`-level ACK leaves the timer armed; only `persisted` resolves it", async () => {
    const nodeA = new WiredNode();
    const sink: FrameSink = { invokeHandler() { /* swallow A's content; no auto-ACK */ } };
    nodeA.peer = sink;

    const a = makeLogger();
    const mgrA = await makeManager(a.logger, join(tempDir, "a2.db"), nodeA);
    managers.push(mgrA);
    await mgrA.createSessionNode(SID, "alice", "bobpk", "bob-peer", "corr-a");

    const content = new TextEncoder().encode("level test");
    const hash = msgLeafHash(content);
    const res = await mgrA.sendContent(SID, content, hash, "corr-a");
    expect(res.ok).toBe(true);

    const ackFrame = (level: string): unknown =>
      lp.encode.single(CBOR_ENC.encode({ type: "content_delivery_ack", session_id: SID, content_hash: hash, level }));

    // A `received` ACK must NOT resolve the awaiting entry.
    nodeA.invokeHandler(ackFrame("received"));
    await new Promise((r) => setTimeout(r, 30));
    expect(a.events.some((e) => e.event === "content.delivery.acked")).toBe(false);

    // The `persisted` ACK resolves it.
    nodeA.invokeHandler(ackFrame("persisted"));
    expect(await waitFor(() => a.events.some((e) => e.event === "content.delivery.acked"))).toBe(true);
    const acked = a.events.find((e) => e.event === "content.delivery.acked");
    expect(acked?.context.level).toBe("persisted");
    expect(acked?.context.contentHash).toBe(Buffer.from(hash).toString("hex"));
  });
});
