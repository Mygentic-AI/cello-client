/**
 * Seam 3 — two-session-core content round-trip over REAL local libp2p, in-process.
 *
 * The first time content flows daemon-to-daemon through real session nodes, composing
 * all three prior seams end to end:
 *
 *   A.createSessionNode (seam 1a)  → N_A, gated to B's standing receiver
 *   A.connectToCounterparty (1b)   → N_A dials B's standing receiver (N_A holds the link)
 *   B.acceptSession (seam 2 core)  → B's standing receiver handed off + gated to N_A,
 *                                    content handler registered
 *   A.sendContent                  → content_frame over the live N_A ↔ B connection
 *   B.#handleContentStream         → cross-check + tree append + buffer + delivery-ACK
 *   A.#handleContentStream         → content_delivery_ack resolves A's awaiting-ACK
 *
 * This is the load-bearing transport seam: real Noise/yamux over loopback TCP, two
 * independent SessionNodeManager instances (two session cores), no FakeNode. The
 * daemon-level cello_send→SNM routing and the seam-2 signaling→acceptSession wiring are
 * proven in their own suites; this proves the live two-node round trip those depend on.
 *
 * No infra, no relay, no directory — B's standing-receiver coordinates (what a local
 * SessionNegotiator would advertise) are read directly via getStandingReceiverInfo().
 * The delivery-ACK rides BACK over the same muxed connection N_A opened (B never dials A).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { createNode } from "@cello-protocol/transport";
import { generateKeypair } from "@cello-protocol/crypto";
import { SessionNodeManager } from "../session-node-manager.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { Logger } from "../types.js";
import type { CelloNode } from "@cello-protocol/transport";

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

/**
 * Factory that creates real libp2p nodes on loopback TCP, honoring the session gater
 * AND forwarding nodeType so each node's dcutr/config matches production
 * (createSessionNode → 'session', standing receiver → 'standing_receiver') — review L3.
 */
class RealNodeFactory implements ISessionNodeFactory {
  async createNode(config: SessionNodeConfig): Promise<CelloNode> {
    return createNode({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      connectionGater: config.connectionGater,
      nodeType: config.nodeType,
    });
  }
}

/** RFC 6962 §2.1 leaf hash for a message content leaf — MUST match ingest's cross-check. */
function msgLeafHash(content: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(new Uint8Array([0x00])).update(content).digest());
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function pollFor<T>(fn: () => T | null | undefined | false, tries = 160, stepMs = 25): Promise<T | null> {
  for (let i = 0; i < tries; i++) {
    const v = fn();
    if (v) return v as T;
    await wait(stepMs);
  }
  return null;
}

describe("Seam 3: two-session-core content round-trip over real libp2p", () => {
  let tempDir: string;
  const managers: SessionNodeManager[] = [];

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-seam3-"));
    managers.length = 0;
  });
  afterEach(async () => {
    for (const m of managers) { try { await m.gracefulShutdown(); } catch { /* already down */ } }
    managers.length = 0;
    await rm(tempDir, { recursive: true, force: true });
  });

  function makeManager(): { manager: SessionNodeManager; events: LogEvent[] } {
    const { logger, events } = makeLogger();
    const dbPath = join(tempDir, `snm-${Math.random().toString(36).slice(2)}.db`);
    const manager = new SessionNodeManager({ factory: new RealNodeFactory(), logger, dbPath });
    managers.push(manager);
    return { manager, events };
  }

  const SID = "33".repeat(16);
  const A_PUB = "aa".repeat(32);
  const B_PUB = "bb".repeat(32);

  it("A→B content is ingested + tree-appended + delivery-ACKed, resolving A's awaiting-ACK", async () => {
    const A = makeManager();
    const B = makeManager();
    await A.manager.initialize();
    await B.manager.initialize();
    // DOD-LOOP-1: bob comes online → his per-agent standing receiver is created.
    await B.manager.ensureStandingReceiverForAgent("bob");

    // B advertises bob's standing receiver coordinates (what a local negotiator reads).
    const bInfo = B.manager.getStandingReceiverInfo("bob");
    expect(bInfo).not.toBeNull();

    // A: create N_A (gated to B's standing receiver) and dial it through N_A (seam 1a/1b).
    const created = await A.manager.createSessionNode(SID, "alice", B_PUB, bInfo!.peerId, "corr-A");
    expect(created.ok).toBe(true);
    if (!created.ok) return;
    const connected = await A.manager.connectToCounterparty(SID, bInfo!.addrs);
    expect(connected.ok).toBe(true);

    // B: accept the inbound session (seam 2 core) — hands off the standing receiver gated
    // to N_A and registers B's content handler. MUST happen before A sends.
    const accepted = await B.manager.acceptSession(SID, "bob", A_PUB, created.peerId, "corr-B");
    expect(accepted.ok).toBe(true);

    // A: send content over the live N_A ↔ B connection.
    const text = "hello over real libp2p";
    const content = new TextEncoder().encode(text);
    const hash = msgLeafHash(content);
    const sent = await A.manager.sendContent(SID, content, hash, "corr-A");
    expect(sent.ok).toBe(true);

    // B: the content arrives, cross-checks, appends to B's daemon-owned tree, and buffers.
    const received = await pollFor(() => B.manager.takeReceivedContent(SID));
    expect(received).not.toBeNull();
    expect(Buffer.from(received!.contentHex, "hex").toString()).toBe(text);
    expect(received!.sequenceNumber).toBe(0);
    expect(B.manager.getSessionTree(SID).size()).toBe(1);
    expect(B.events.find((e) => e.event === "session.content.received")).toBeDefined();

    // A: the delivery-ACK round-trips back over the same muxed connection and resolves the
    // awaiting-ACK (content.delivery.acked at level 'persisted'), so NO TTF park fires.
    const acked = await pollFor(() => A.events.find((e) => e.event === "content.delivery.acked"));
    expect(acked).not.toBeNull();
    expect(acked!.context["level"]).toBe("persisted");
    expect(A.events.find((e) => e.event === "content.delivery.ttf_expired")).toBeUndefined();
    expect(A.events.find((e) => e.event === "content.park.backstop.failed")).toBeUndefined();
  }, 30_000);

  it("a hash-mismatched (tampered) frame is rejected: no tree append, no buffer, no delivery-ACK", async () => {
    const A = makeManager();
    const B = makeManager();
    await A.manager.initialize();
    await B.manager.initialize();
    await B.manager.ensureStandingReceiverForAgent("bob");

    const bInfo = B.manager.getStandingReceiverInfo("bob");
    expect(bInfo).not.toBeNull();
    const created = await A.manager.createSessionNode(SID, "alice", B_PUB, bInfo!.peerId, "corr-A");
    expect(created.ok).toBe(true);
    if (!created.ok) return;
    const connected = await A.manager.connectToCounterparty(SID, bInfo!.addrs);
    expect(connected.ok).toBe(true);
    const accepted = await B.manager.acceptSession(SID, "bob", A_PUB, created.peerId, "corr-B");
    expect(accepted.ok).toBe(true);

    // Send content under a hash that does NOT match it (wire tamper of a single frame).
    const content = new TextEncoder().encode("genuine content");
    const wrongHash = msgLeafHash(new TextEncoder().encode("different content"));
    const sent = await A.manager.sendContent(SID, content, wrongHash, "corr-A");
    expect(sent.ok).toBe(true);

    // B rejects on cross-check: no buffered content, empty tree, and the cross-check warns.
    const rejected = await pollFor(() => B.events.find((e) => e.event === "session.content.cross_check.failed"));
    expect(rejected).not.toBeNull();
    expect(rejected!.context["reason"]).toBe("content_hash_mismatch");
    expect(B.manager.takeReceivedContent(SID)).toBeNull();
    expect(B.manager.getSessionTree(SID).size()).toBe(0);

    // And A never gets an ACK (no delivery for tampered content) — its awaiting-ACK stays
    // armed (it is the TTF/recovery path's job, not this seam's, to drain it).
    await wait(150);
    expect(A.events.find((e) => e.event === "content.delivery.acked")).toBeUndefined();
  }, 30_000);
});
