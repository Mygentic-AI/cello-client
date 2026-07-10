/**
 * M8B F14 / FINDING-2 (Brief 2) — the standing receiver must reliably RE-ARM.
 *
 * Root cause under test (live EC2 evidence, 2026-07-02): on a fixed-port deployment
 * (CELLO_LISTEN_ADDR pins the SR port) the consumed receiver keeps the port while it
 * lives on as the session node, so the immediate re-arm after acceptSession fails with
 * EADDRINUSE. Nothing ever retried:
 *   - #ensureStandingReceiver left no entry on failure and was never re-invoked,
 *   - destroySessionNode (the moment the port frees) did not re-arm,
 *   - the inbound accept path only POLLED readiness — it never kicked creation.
 * After one failed create the agent was deaf forever.
 *
 * Contract pinned here (manager level):
 *  1. destroySessionNode re-arms: after a failed post-consume re-arm, tearing down the
 *     handed-off session node re-creates the standing receiver, and a later accept succeeds.
 *  2. #ensureStandingReceiver retries with bounded backoff on create failure.
 *  3. When every attempt fails for an agent that wants a receiver, a LOUD terminal event
 *     (`session.standing_receiver.dead`, error level) fires — distinct from the per-attempt
 *     `session.node.create.failed`.
 *  4. Regression (L1): cello_stop_agent during an in-flight ensure still tears down cleanly
 *     (tombstone semantics preserved — the retry loop must also honor it).
 *
 * The daemon-level half (ensure-on-demand in the inbound accept path + per-agent
 * standing_receiver_ready in status) is pinned in standing-receiver-inbound.test.ts.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { SessionNodeManager } from "../session-node-manager.js";
import type { Logger } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { CelloNode } from "@cello-protocol/transport";
import { createNode } from "@cello-protocol/transport";
import { generateKeypair } from "@cello-protocol/crypto";
import { seedAgents } from "./helpers/seed-agents.js";

function makeLogger(): { logger: Logger; events: Array<{ level: string; event: string; context: Record<string, unknown> }> } {
  const events: Array<{ level: string; event: string; context: Record<string, unknown> }> = [];
  const logger: Logger = {
    debug(event, context) { events.push({ level: "debug", event, context }); },
    info(event, context) { events.push({ level: "info", event, context }); },
    warn(event, context) { events.push({ level: "warn", event, context }); },
    error(event, context) { events.push({ level: "error", event, context }); },
  };
  return { logger, events };
}

/** Real libp2p nodes, with the ability to FAIL the next N creates (the EADDRINUSE shape). */
class FlakyNodeFactory implements ISessionNodeFactory {
  failNext = 0;
  createAttempts = 0;
  async createNode(config: SessionNodeConfig): Promise<CelloNode> {
    this.createAttempts++;
    if (this.failNext > 0) {
      this.failNext--;
      throw new Error("listen EADDRINUSE: address already in use 0.0.0.0:4001");
    }
    return createNode({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      connectionGater: config.connectionGater,
      nodeType: config.nodeType,
    });
  }
}

/** Factory whose next create PARKS until released (for the in-flight-stop regression). */
class ParkingNodeFactory implements ISessionNodeFactory {
  #release: (() => void) | null = null;
  readonly created: CelloNode[] = [];
  release(): void { this.#release?.(); this.#release = null; }
  async createNode(config: SessionNodeConfig): Promise<CelloNode> {
    await new Promise<void>((r) => { this.#release = r; });
    const node = await createNode({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      connectionGater: config.connectionGater,
      nodeType: config.nodeType,
    });
    this.created.push(node);
    return node;
  }
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function waitUntil(fn: () => boolean, timeoutMs: number, everyMs = 25): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fn()) return true;
    await wait(everyMs);
  }
  return fn();
}

describe("M8B F14: standing receiver re-arm", () => {
  let tempDir = "";

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-sr-rearm-"));
  });
  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  function makeManager(factory: ISessionNodeFactory, retryDelaysMs?: number[]) {
    const { logger, events } = makeLogger();
    const dbPath = join(tempDir, `sessions-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
    const manager = new SessionNodeManager({
      factory,
      logger,
      dbPath,
      // Brief-2 fix 3: injectable bounded-backoff schedule (default 1s/5s/15s in production).
      standingReceiverRetryDelaysMs: retryDelaysMs,
    });
    return { manager, events };
  }

  it("destroySessionNode re-arms the standing receiver after a failed post-consume re-arm, and a later accept succeeds", async () => {
    const factory = new FlakyNodeFactory();
    // No retry schedule — isolates the TEARDOWN re-arm path from the retry path.
    const { manager } = makeManager(factory, []);
    await manager.initialize();
    // DOD-AGENT-ID-JOINKEY-1: every test in this file drives the manager as "bob" — production
    // always has an `agents` row before a session exists.
    await seedAgents(manager.getDb(), ["bob"]);
    try {
      await manager.ensureStandingReceiverForAgent("bob");
      expect(manager.getStandingReceiverReady("bob")).toBe(true);

      // The fixed-port shape: the consumed receiver keeps the port, so the immediate
      // post-consume re-arm fails once (EADDRINUSE).
      factory.failNext = 1;
      const accepted = await manager.acceptSession("f14-s1", "bob", "aa".repeat(32), "initiator-peer", "corr-f14-1");
      expect(accepted.ok).toBe(true);
      await wait(150); // let the failed immediate re-arm settle
      expect(manager.getStandingReceiverReady("bob")).toBe(false); // agent is deaf

      // The port frees the moment the handed-off node is torn down — the natural re-arm point.
      await manager.destroySessionNode("bob", "f14-s1", "sealed");
      const rearmed = await waitUntil(() => manager.getStandingReceiverReady("bob"), 5_000);
      expect(rearmed, "teardown must re-arm the standing receiver (F14)").toBe(true);

      // And the agent can accept inbound again.
      const accepted2 = await manager.acceptSession("f14-s2", "bob", "aa".repeat(32), "initiator-peer-2", "corr-f14-2");
      expect(accepted2.ok).toBe(true);
    } finally {
      await manager.gracefulShutdown();
    }
  }, 20_000);

  it("relay-detected interruption (markInterruptedWithDetails) also re-arms — the third teardown path frees the port too", async () => {
    const factory = new FlakyNodeFactory();
    const { manager } = makeManager(factory, []);
    await manager.initialize();
    // DOD-AGENT-ID-JOINKEY-1: every test in this file drives the manager as "bob" — production
    // always has an `agents` row before a session exists.
    await seedAgents(manager.getDb(), ["bob"]);
    try {
      await manager.ensureStandingReceiverForAgent("bob");
      factory.failNext = 1;
      const accepted = await manager.acceptSession("f14-s3", "bob", "aa".repeat(32), "initiator-peer", "corr-f14-3");
      expect(accepted.ok).toBe(true);
      await wait(150);
      expect(manager.getStandingReceiverReady("bob")).toBe(false); // deaf

      // The session ends via a relay-detected interruption (network blip / counterparty
      // crash), NOT an explicit seal/close — this teardown also frees the fixed port.
      await manager.markInterruptedWithDetails("bob", "f14-s3", 0, "stream_close");
      const rearmed = await waitUntil(() => manager.getStandingReceiverReady("bob"), 5_000);
      expect(rearmed, "the interruption teardown must re-arm the standing receiver").toBe(true);
    } finally {
      await manager.gracefulShutdown();
    }
  }, 20_000);

  it("ensure retries with bounded backoff: transient create failures recover without any teardown", async () => {
    const factory = new FlakyNodeFactory();
    const { manager, events } = makeManager(factory, [30, 30]);
    await manager.initialize();
    // DOD-AGENT-ID-JOINKEY-1: every test in this file drives the manager as "bob" — production
    // always has an `agents` row before a session exists.
    await seedAgents(manager.getDb(), ["bob"]);
    try {
      factory.failNext = 2; // attempts 1+2 fail, attempt 3 succeeds
      await manager.ensureStandingReceiverForAgent("bob");
      expect(manager.getStandingReceiverReady("bob"), "bounded retry must recover a transient failure").toBe(true);
      const failed = events.filter((e) => e.event === "session.node.create.failed");
      expect(failed.length).toBe(2);
    } finally {
      await manager.gracefulShutdown();
    }
  }, 20_000);

  it("all attempts failing → LOUD session.standing_receiver.dead terminal event (error level)", async () => {
    const factory = new FlakyNodeFactory();
    const { manager, events } = makeManager(factory, [10, 10]);
    await manager.initialize();
    // DOD-AGENT-ID-JOINKEY-1: every test in this file drives the manager as "bob" — production
    // always has an `agents` row before a session exists.
    await seedAgents(manager.getDb(), ["bob"]);
    try {
      factory.failNext = 100; // every attempt fails
      await manager.ensureStandingReceiverForAgent("bob");
      expect(manager.getStandingReceiverReady("bob")).toBe(false);
      const perAttempt = events.filter((e) => e.event === "session.node.create.failed");
      expect(perAttempt.length).toBe(3); // initial + 2 retries
      const dead = events.filter((e) => e.event === "session.standing_receiver.dead");
      expect(dead.length, "an ONLINE agent with no receiver after retries must fail LOUD").toBe(1);
      expect(dead[0].level).toBe("error");
      expect(dead[0].context.agentName).toBe("bob");
      expect(String(dead[0].context.reason)).toMatch(/EADDRINUSE/);
    } finally {
      await manager.gracefulShutdown();
    }
  }, 20_000);

  it("regression (L1): stop_agent during an in-flight ensure still tears down cleanly", async () => {
    const factory = new ParkingNodeFactory();
    const { manager } = makeManager(factory, [50]);
    await manager.initialize();
    // DOD-AGENT-ID-JOINKEY-1: every test in this file drives the manager as "bob" — production
    // always has an `agents` row before a session exists.
    await seedAgents(manager.getDb(), ["bob"]);
    try {
      const ensureP = manager.ensureStandingReceiverForAgent("bob"); // parks on createNode
      await wait(50);
      await manager.removeStandingReceiverForAgent("bob"); // leaves the L1 tombstone
      factory.release();
      await ensureP;
      // The fresh node must NOT be installed for the now-offline agent.
      expect(manager.getStandingReceiverReady("bob")).toBe(false);
    } finally {
      await manager.gracefulShutdown();
    }
  }, 20_000);
});
