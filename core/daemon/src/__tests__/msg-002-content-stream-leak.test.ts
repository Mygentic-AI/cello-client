import { LEAF_KIND_MSG } from "../session-relay-client.js";
/**
 * DOD-M12B-ACK-1 — a conversation must not die on its 33rd frame.
 *
 * Every content frame and every delivery ACK opens a fresh `/cello/content/1.0.0` stream on the
 * one muxed connection the session holds. libp2p caps INBOUND streams per protocol per connection
 * and enforces that cap AFTER multistream-select has already answered, so the sender's `newStream`
 * resolves normally and the very next `stream.send(...)` throws
 * `Cannot write to a stream that is closed` — the error that produced 115 failures on one live
 * daemon in 3.5 hours (M12B Entry 10), 89 of them ordinary messages parking instead of delivering.
 *
 * Measured on that daemon against libp2p's registrar default of 32: EXACTLY 32 successful outbound
 * content streams preceded the first failure, on both affected sessions. The slot was never
 * released because the receiving handler read one frame and returned without closing the stream,
 * so a half-closed stream sat in `connection.streams` for the life of the connection.
 *
 * This test rides the seam-3 harness (real Noise/yamux over loopback TCP, two independent
 * SessionNodeManager instances) because the defect lives in libp2p's per-connection accounting —
 * a FakeNode cannot express it.
 *
 * THE LAST ASSERTION IS THE LOAD-BEARING ONE. Delivering 40 messages proves only that 40 fit —
 * which a raised cap over a live leak would also satisfy. Counting the streams still open after
 * the run is what proves the slot came back.
 *
 * Revert test: turn `#handleContentStream`'s `finally` back into a bare `return` and this fails —
 * at frame 33 under libp2p's default cap, and on the stream census under the raised one.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createNode } from "@cello-protocol/transport";
import { generateKeypair, msgLeafHash } from "@cello-protocol/crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager } from "../session-node-manager.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import { seedAgentKeys, wireAgentKeyProviders } from "./helpers/seed-agents.js";
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
  /**
   * DOD-M15-AUTHORSHIP-ABSENT-1: THE COUNTERPARTY KEYS ARE THE REAL ONES NOW.
   *
   * They were `"aa".repeat(32)` / `"bb".repeat(32)` — placeholders standing in for identities
   * nothing checked. Every content frame carries the sender's signature over its own Structure 1
   * and the receiver matches the signer against `counterparty_pubkey`; against a placeholder, alice
   * signing with alice's own key is a stranger and her message is refused. Seeded per test, since
   * each builds its own managers with their own agent rows.
   */

  // 40 > the 32-stream cap by a clear margin, in BOTH directions: 40 content frames A→B and the
  // 40 delivery ACKs B→A. A cap released only on one side would still fail this.
  const MESSAGE_COUNT = 40;

  it("delivers 40 messages on one session — the 33rd does not die on a closed stream", async () => {
    const A = makeManager();
    const B = makeManager();
    await A.manager.initialize();
    await B.manager.initialize();
    const A_PUB = (await seedAgentKeys(A.manager.getDb(), ["alice"])).get("alice")!.pubkeyHex;
    const B_PUB = (await seedAgentKeys(B.manager.getDb(), ["bob"])).get("bob")!.pubkeyHex;
    // Production always wires the key providers too — without them A cannot sign what it sends.
    await wireAgentKeyProviders(A.manager, A.manager.getDb());
    await wireAgentKeyProviders(B.manager, B.manager.getDb());
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
    /**
     * ⚠️ **THE CONTENT KEY IS THE REAL ONE HERE, NOT A SEEDED CONSTANT** —
     * `DOD-M15-AUTHORSHIP-ABSENT-1`.
     *
     * Both ends used to be handed `0x7e…`, because a FakeNode counterparty can never complete the
     * ephemeral key exchange. This file's transport is REAL, and the identity keys wired above were
     * the last thing that exchange was missing — so it completes on its own now, moments after the
     * seed would have been written, and overwrites it on whichever side finishes last. Two ends
     * sealing under different keys is `decrypt_failed` on every message.
     *
     * So the seed is gone and the test waits for the agreement it was standing in for.
     */
    expect(await pollFor(() => A.events.find((e) => e.event === "session.key.agreed")), "A must hold an agreed content key before it can send").not.toBeNull();
    expect(await pollFor(() => B.events.find((e) => e.event === "session.key.agreed")), "and B must hold the same one before it can open the message").not.toBeNull();

    const received: string[] = [];
    for (let i = 0; i < MESSAGE_COUNT; i++) {
      const text = `message ${i}`;
      const content = new TextEncoder().encode(text);
      const sent = await A.manager.sendContent("alice", SID, content, msgLeafHash(content), `corr-A-${i}`, LEAF_KIND_MSG);
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

    // THE SLOT WAS RELEASED — not merely "40 happened to fit".
    //
    // Without this, an implementation that keeps the leak and simply raises the cap passes
    // everything above and dies at message 513 instead of 33. Counting live streams is the only
    // assertion that distinguishes "we closed what we opened" from "we bought more room".
    // A small allowance, not zero: the last ACK's stream may still be retiring when we look.
    const census = await pollFor(() => {
      const c = A.manager.countSessionContentStreams("alice", SID);
      return c && c.inbound <= 2 && c.outbound <= 2 ? c : null;
    });
    expect(
      census,
      `content streams never drained: ${JSON.stringify(A.manager.countSessionContentStreams("alice", SID))} after ${MESSAGE_COUNT} messages`,
    ).not.toBeNull();
  }, 120_000);
});
