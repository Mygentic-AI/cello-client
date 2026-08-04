/**
 * DOD-RELAY-KEEPALIVE-1 (review F2) — a relay link dropping must not declare the COUNTERPARTY dead.
 *
 * `#wireSessionLiveness` acted on every peer event the session node saw, justified by a comment
 * saying the gater restricts that node to the counterparty. That stopped being true when session
 * nodes started dialing the relay as their Structure-2 witness (`#connectSessionRelay`): the gater
 * allows those peers outbound, so a relay disconnect drove `counterparty_liveness` to 'gone' — at
 * WARN, feeding the unilateral-seal gate — while the counterparty was alive and well.
 *
 * It is the same event this whole unit exists to stop: during the 2026-08-04 incident the relay
 * link churned every 60-90 seconds, so every churn produced a false counterparty-death verdict.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager } from "../session-node-manager.js";
import { ProductionSessionNodeFactory } from "../daemon.js";
import type { Logger } from "../types.js";
import { seedAgents } from "./helpers/seed-agents.js";
import { createNode } from "@cello-protocol/transport";
import type { CelloNode } from "@cello-protocol/transport";
import { generateKeypair } from "@cello-protocol/crypto";

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function waitUntil(fn: () => boolean, timeoutMs: number, everyMs = 50): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fn()) return true;
    await wait(everyMs);
  }
  return fn();
}

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

describe("F2: session liveness is a statement about the COUNTERPARTY, not about the relay", () => {
  let tempDir = "";
  let manager: SessionNodeManager;
  let events: LogEvent[];

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-liveness-peer-"));
    process.env["CELLO_LISTEN_ADDR"] = "/ip4/127.0.0.1/tcp/0";
    const made = makeLogger();
    events = made.events;
    manager = new SessionNodeManager({
      securityGateway: new PassthroughGatewayClient(),
      factory: new ProductionSessionNodeFactory(),
      logger: made.logger,
      dbPath: join(tempDir, "sessions.db"),
      standingReceiverRetryDelaysMs: [],
    });
    await manager.initialize();
    await seedAgents(manager.getDb(), ["alice"]);
  });

  afterEach(async () => {
    await manager.gracefulShutdown();
    delete process.env["CELLO_LISTEN_ADDR"];
    await rm(tempDir, { recursive: true, force: true });
  });

  /**
   * A REAL relay leg and a REAL counterparty. The point of the finding is that the session node
   * holds connections to both, so the test must too — a hand-fired event could not have caught it.
   */
  async function startPeerNode(): Promise<{ node: CelloNode; peerId: string; addr: string }> {
    const node = await createNode({ keyProvider: generateKeypair(), listenAddresses: ["/ip4/127.0.0.1/tcp/0"] });
    await node.start();
    const addr = node.listenAddresses().find((a) => a.includes("/p2p/"));
    if (!addr) throw new Error("peer node has no addressed multiaddr");
    return { node, peerId: node.getPeerId(), addr };
  }

  it("a RELAY link dropping leaves counterparty liveness alone — it is not a counterparty death", async () => {
    const relay = await startPeerNode();
    const counterparty = await startPeerNode();
    const sessionId = randomUUID().replaceAll("-", "");
    try {
      const created = await manager.createSessionNode(
        sessionId, "alice", "cc".repeat(32), counterparty.peerId, randomUUID(), false,
        {
          relayPeerId: relay.peerId,
          relayAddrs: [relay.addr],
          keyProvider: generateKeypair(),
          senderPubkey: new Uint8Array(32),
          sessionIdBytes: Buffer.from(sessionId, "hex"),
        },
      );
      expect(created.ok).toBe(true);

      // The counterparty is up and connected — liveness is 'alive' and honestly so.
      await manager.connectToCounterparty("alice", sessionId, [counterparty.addr]);
      const alive = await waitUntil(() => manager.getSessionLiveness("alice", sessionId) === "alive", 10_000);
      expect(alive).toBe(true);
      events.length = 0;

      // THE CHURN. The relay dies; the counterparty does not move.
      await relay.node.stop();
      await wait(1_500);

      expect(
        manager.getSessionLiveness("alice", sessionId),
        "the relay dropping says nothing about whether the counterparty is alive",
      ).toBe("alive");
      expect(
        events.some((e) => e.event === "session.liveness.changed" && e.context["liveness"] === "gone"),
        "no counterparty-death WARN may be emitted for a relay disconnect",
      ).toBe(false);
    } finally {
      await counterparty.node.stop();
      await relay.node.stop().catch(() => { /* already stopped */ });
    }
  }, 40_000);

  it("the COUNTERPARTY going away still drives 'gone' — the detector is preserved, not disabled", async () => {
    const counterparty = await startPeerNode();
    const sessionId = randomUUID().replaceAll("-", "");
    try {
      const created = await manager.createSessionNode(
        sessionId, "alice", "cc".repeat(32), counterparty.peerId, randomUUID(),
      );
      expect(created.ok).toBe(true);
      await manager.connectToCounterparty("alice", sessionId, [counterparty.addr]);
      const alive = await waitUntil(() => manager.getSessionLiveness("alice", sessionId) === "alive", 10_000);
      expect(alive).toBe(true);

      await counterparty.node.stop();

      const gone = await waitUntil(() => manager.getSessionLiveness("alice", sessionId) === "gone", 10_000);
      expect(gone, "a counterparty that leaves must still be detected — filtering must not silence it").toBe(true);
      const warn = events.find((e) => e.event === "session.liveness.changed" && e.context["liveness"] === "gone");
      expect(warn).toBeDefined();
      expect(warn!.level).toBe("warn");
    } finally {
      await counterparty.node.stop().catch(() => { /* already stopped */ });
    }
  }, 40_000);
});
