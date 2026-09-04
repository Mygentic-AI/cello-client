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
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager } from "../session-node-manager.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import { seedAgentKeys, wireAgentKeyProviders } from "./helpers/seed-agents.js";
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
// DOD-M15-FRAME-1: the sender's peer id rides with the frame, because the real transport delivers
// it — `node.ts` hands the handler `connection?.remotePeer?.toString()`, the Noise-authenticated
// identity. The content protocol now pins every frame to the session's counterparty, so a fake that
// delivers frames from nobody is testing a transport that does not exist.
interface FrameSink { invokeHandler(data: unknown, fromPeerId: string): void }

/**
 * A node whose newStream().send() delivers the framed bytes to its PEER's registered
 * content handler — so two of these, cross-wired, exercise the full content_frame +
 * delivery-ACK round-trip through the real lp/CBOR decode + handler dispatch path.
 */
class WiredNode implements Partial<CelloNode>, FrameSink {
  #handler: ((stream: Stream, remotePeerId?: string) => void) | null = null;
  peer: FrameSink | null = null;
  readonly #peerId = `wired-${Math.random().toString(36).slice(2)}`;
  async start(): Promise<void> {}
  async stop(): Promise<void> {}
  getPeerId(): string { return this.#peerId; }
  listenAddresses(): string[] { return ["/ip4/127.0.0.1/tcp/0"]; }
  async dial(_a: string): Promise<{ peerId: string }> { return { peerId: "remote" }; }
  async handle(_p: string, h: (stream: Stream, remotePeerId?: string) => void): Promise<void> { this.#handler = h; }
  getProtocols(): string[] { return []; }
  getConnections(): Array<{ peerId: string; encryption: string | undefined }> { return []; }
  onPeerConnect(_h: (p: string) => void): void {}
  onPeerDisconnect(_h: (p: string) => void): void {}
  getDialability(): { dialable: boolean; publicAddr: string | null } { return { dialable: false, publicAddr: null }; }
  onDialabilityChange(_l: (d: { dialable: boolean; publicAddr: string | null }) => void): () => void { return () => {}; }
  invokeHandler(data: unknown, fromPeerId: string): void {
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
    h(inbound, fromPeerId);
  }
  async newStream(_peer: string, _proto: string): Promise<Stream> {
    const peer = this.peer;
    // The RECEIVER sees the SENDER's peer id, which is what the transport binds and what the
    // session's `counterpartySessionPeerId` was set to when the pair was cross-wired.
    const fromPeerId = this.getPeerId();
    return { send(data: unknown) { peer?.invokeHandler(data, fromPeerId); }, async close() {}, abort() {}, status: "open" } as unknown as Stream;
  }
}

class ControlledFactory implements ISessionNodeFactory {
  constructor(private node: CelloNode) {}
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> { return this.node; }
}

async function makeManager(logger: Logger, dbPath: string, node: CelloNode, contentTtfMs = 60_000): Promise<SessionNodeManager> {
  const mgr = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new ControlledFactory(node), logger, dbPath, contentTtfMs });
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
    // Production always has these rows: the daemon creates an agent long before it has a session.
    /**
     * DOD-M15-AUTHORSHIP-ABSENT-1: the counterparty keys are the REAL ones. They were `"bobpk"` and
     * `"alicepk"` — placeholders for identities nothing checked. Every content frame now carries the
     * sender's signature over its own Structure 1, and the receiver matches the signer against
     * `counterparty_pubkey`; against a placeholder, alice signing with alice's key is a stranger and
     * B refuses her message before it can ever be ACKed.
     */
    const alicePub = (await seedAgentKeys(mgrA.getDb(), ["alice"])).get("alice")!.pubkeyHex;
    const bobPub = (await seedAgentKeys(mgrB.getDb(), ["bob"])).get("bob")!.pubkeyHex;
    // And production always wires the key providers — without them A cannot sign what it sends.
    await wireAgentKeyProviders(mgrA, mgrA.getDb());
    await wireAgentKeyProviders(mgrB, mgrB.getDb());

    await mgrA.createSessionNode(SID, "alice", bobPub, nodeB.getPeerId(), "corr-a");
    // 007-CRYPTO: the state a completed key exchange leaves — a live send needs an agreed key.
    mgrA.setSessionContentKeyForTest("alice", SID, new Uint8Array(32).fill(0x7e));
    await mgrB.createSessionNode(SID, "bob", alicePub, nodeA.getPeerId(), "corr-b");
    // 007-CRYPTO: the state a completed key exchange leaves — a live send needs an agreed key.
    mgrB.setSessionContentKeyForTest("bob", SID, new Uint8Array(32).fill(0x7e));

    const content = new TextEncoder().encode("hello over the wire");
    const hash = msgLeafHash(content);
    const res = await mgrA.sendContent("alice", SID, content, hash, "corr-a");
    expect(res.ok).toBe(true);

    // The receiver ingested it (buffered for cello_receive).
    expect(await waitFor(() => mgrB.takeReceivedContent("bob", SID) !== null)).toBe(true);

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
    await seedAgentKeys(mgrA.getDb(), ["alice"]);
    await wireAgentKeyProviders(mgrA, mgrA.getDb());
    await mgrA.createSessionNode(SID, "alice", "bobpk", "bob-peer", "corr-a");
    // 007-CRYPTO: the state a completed key exchange leaves — a live send needs an agreed key.
    mgrA.setSessionContentKeyForTest("alice", SID, new Uint8Array(32).fill(0x7e));

    const content = new TextEncoder().encode("level test");
    const hash = msgLeafHash(content);
    const res = await mgrA.sendContent("alice", SID, content, hash, "corr-a");
    expect(res.ok).toBe(true);

    const ackFrame = (level: string): unknown =>
      lp.encode.single(CBOR_ENC.encode({ type: "content_delivery_ack", session_id: SID, content_hash: hash, level }));

    // A `received` ACK must NOT resolve the awaiting entry.
    nodeA.invokeHandler(ackFrame("received"), "bob-peer");
    await new Promise((r) => setTimeout(r, 30));
    expect(a.events.some((e) => e.event === "content.delivery.acked")).toBe(false);

    /**
     * DOD-M15-FRAME-1: a `persisted` ACK from ANYONE ELSE must not resolve it either.
     *
     * This handler had no sender check and no session check at all — a shape test and a string
     * compare. A stranger holding a pre-positioned connection to the standing receiver could forge
     * one and cancel the park-on-undelivered timer, so the operator's message would silently vanish
     * while every local surface reported it delivered. Asserted BEFORE the legitimate ACK below, so
     * a regression cannot be masked by the real one arriving afterwards.
     */
    nodeA.invokeHandler(ackFrame("persisted"), "stranger-peer");
    await new Promise((r) => setTimeout(r, 30));
    expect(
      a.events.some((e) => e.event === "content.delivery.acked"),
      "a forged ACK from a non-counterparty must not resolve the delivery timer",
    ).toBe(false);
    expect(a.events.some((e) => e.event === "session.content.peer_mismatch")).toBe(true);

    // The `persisted` ACK from the real counterparty resolves it.
    nodeA.invokeHandler(ackFrame("persisted"), "bob-peer");
    expect(await waitFor(() => a.events.some((e) => e.event === "content.delivery.acked"))).toBe(true);
    const acked = a.events.find((e) => e.event === "content.delivery.acked");
    expect(acked?.context.level).toBe("persisted");
    expect(acked?.context.contentHash).toBe(Buffer.from(hash).toString("hex"));
  });
});
