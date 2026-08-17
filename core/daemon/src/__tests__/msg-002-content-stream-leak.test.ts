/**
 * DOD-M12B-ACK-1 — a conversation must not die on its 33rd frame.
 *
 * Every content frame and every delivery ACK opens a fresh `/cello/content/1.0.0` stream on the
 * one muxed connection the session holds. libp2p caps INBOUND streams per protocol per connection
 * at DEFAULT_MAX_INBOUND_STREAMS = 32 (nothing in this codebase passes `maxInboundStreams`), and
 * it enforces the cap AFTER multistream-select has already answered. So the sender's `newStream`
 * resolves normally and the very next `stream.send(...)` throws
 * `Cannot write to a stream that is closed` — the error that produced 115 failures on one live
 * daemon in 3.5 hours (M12B Entry 10), 89 of them ordinary messages parking instead of delivering.
 *
 * Measured on that daemon: EXACTLY 32 successful outbound content streams preceded the first
 * failure, on both affected sessions. The cap is never released because the receiving handler
 * reads one frame and returns without closing the stream, so a half-closed stream sits in
 * `connection.streams` for the life of the connection and the session never recovers.
 *
 * This test rides the seam-3 harness (real Noise/yamux over loopback TCP, two independent
 * SessionNodeManager instances) because the defect lives in libp2p's per-connection accounting —
 * a FakeNode cannot express it.
 *
 * Revert test: restore the missing `stream.close()` in `#handleContentStream` to a bare `return`
 * and this fails at frame 33 with `Cannot write to a stream that is closed`.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { createNode } from "@cello-protocol/transport";
import { generateKeypair } from "@cello-protocol/crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager } from "../session-node-manager.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import { seedAgents } from "./helpers/seed-agents.js";
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

async function pollFor<T>(fn: () => T | null | undefined | false, tries = 200, stepMs = 25): Promise<T | null> {
  for (let i = 0; i < tries; i++) {
    const v = fn();
    if (v) return v as T;
    await wait(stepMs);
  }
  return null;
}

describe("DOD-M12B-ACK-1: content streams are not leaked at the receiver", () => {
  let tempDir: string;
  const managers: SessionNodeManager[] = [];

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-msg002-"));
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
    const manager = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new RealNodeFactory(), logger, dbPath });
    managers.push(manager);
    return { manager, events };
  }

  const SID = "44".repeat(16);
  const A_PUB = "aa".repeat(32);
  const B_PUB = "bb".repeat(32);

  // 40 > the 32-stream cap by a clear margin, in BOTH directions: 40 content frames A→B and the
  // 40 delivery ACKs B→A. A cap released only on one side would still fail this.
  const MESSAGE_COUNT = 40;

  it("delivers 40 messages on one session — the 33rd does not die on a closed stream", async () => {
    const A = makeManager();
    const B = makeManager();
    await A.manager.initialize();
    await B.manager.initialize();
    await seedAgents(A.manager.getDb(), ["alice"]);
    await seedAgents(B.manager.getDb(), ["bob"]);
    await B.manager.ensureStandingReceiverForAgent("bob");

    const bInfo = B.manager.getStandingReceiverInfo("bob");
    expect(bInfo).not.toBeNull();

    const created = await A.manager.createSessionNode(SID, "alice", B_PUB, bInfo!.peerId, "corr-A");
    expect(created.ok).toBe(true);
    if (!created.ok) return;
    const connected = await A.manager.connectToCounterparty("alice", SID, bInfo!.addrs);
    expect(connected.ok).toBe(true);
    const accepted = await B.manager.acceptSession(SID, "bob", A_PUB, created.peerId, "corr-B");
    expect(accepted.ok).toBe(true);

    const received: string[] = [];
    for (let i = 0; i < MESSAGE_COUNT; i++) {
      const text = `message ${i}`;
      const content = new TextEncoder().encode(text);
      const sent = await A.manager.sendContent("alice", SID, content, msgLeafHash(content), `corr-A-${i}`);
      // `delivered` is the field that separates "went to the peer" from "parked for later". A park
      // here is the defect: there is no relay in this harness, so a parked frame is a lost one.
      expect(sent.ok, `send ${i} refused`).toBe(true);
      const drained = await pollFor(() => B.manager.takeReceivedContent("bob", SID));
      expect(drained, `message ${i} never arrived at B`).not.toBeNull();
      received.push(Buffer.from(drained!.contentHex, "hex").toString());
    }

    // Every message, in order, once.
    expect(received).toEqual(Array.from({ length: MESSAGE_COUNT }, (_, i) => `message ${i}`));
    expect(B.manager.getSessionTree("bob", SID).size()).toBe(MESSAGE_COUNT);

    // The two live symptoms, named directly: no direct send fell back to a park, and every ACK
    // made it home. Asserting on the counts (not merely "some acked") is what catches a fix that
    // repairs one direction and leaks the other.
    const sendFailures = A.events.filter((e) => e.event === "session.content.direct.send.failed");
    expect(sendFailures.map((e) => String(e.context["error"]))).toEqual([]);
    const ackFailures = B.events.filter((e) => e.event === "content.delivery.ack.send.failed");
    expect(ackFailures.map((e) => String(e.context["error"]))).toEqual([]);

    const acked = await pollFor(
      () => A.events.filter((e) => e.event === "content.delivery.acked").length === MESSAGE_COUNT || null,
    );
    expect(acked, `only ${A.events.filter((e) => e.event === "content.delivery.acked").length} of ${MESSAGE_COUNT} ACKs came back`).not.toBeNull();
  }, 120_000);
});
