/**
 * DOD-PARK-DRAIN-1 — parked store-and-forward content reaches a RUNNING daemon.
 *
 * The defect (2026-08-04, first cross-machine conversation): store-and-forward worked in every
 * part except its trigger. Content parks when the RELAY stream drops; the only live drain trigger
 * was hooked to DIRECTORY SIGNALING reconnecting — a different connection that stayed up while the
 * relay churned seven times. So a parked message sat until a human restarted the receiving daemon,
 * which is the one path (agent start) that reliably drains.
 *
 * Pinned here:
 *  A1 — the drain fires on the FIRST standing-receiver install.
 *  A2 — it fires again on the watchdog REBUILD after the relay link dies. This is the defect:
 *       parking and rebuilding are the same event, so the drain has to ride the rebuild. Proven
 *       against a real in-process relay that is killed mid-life — a deliberately flapping link.
 *  A3 — it fires on the auth_ok rebuild (setDirectoryRelayEndpoints).
 *  A4 — a slow periodic backstop fires with no rebuild at all, so no future missed trigger can
 *       strand content indefinitely.
 *  A5 — a throwing drain hook costs the drain, never the standing receiver.
 *  B  — the signaling-reconnect path chains ensure→drain instead of racing them (the race lost
 *       102 times in one log: `standing_receiver_unavailable`).
 *  C  — the daemon composition root actually wires the hook, and its failures name their cause
 *       rather than logging "[object Object]".
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { FileKeyProvider, generateKeypair } from "@cello-protocol/crypto";
import { createNode } from "@cello-protocol/transport";
import type { CelloNode } from "@cello-protocol/transport";
import { SessionNodeManager } from "../session-node-manager.js";
import { ProductionSessionNodeFactory, startDaemon, type DaemonHandle } from "../daemon.js";
import { createReconnectDrain } from "../reconnect-drain.js";
import type { DaemonConfig, Logger } from "../types.js";
import { seedAgents } from "./helpers/seed-agents.js";

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

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function waitUntil(fn: () => boolean, timeoutMs: number, everyMs = 50): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fn()) return true;
    await wait(everyMs);
  }
  return fn();
}

/** An in-process HOP relay — a service node (nodeType undefined keeps the relay service). */
async function startHopRelay(): Promise<{ node: CelloNode; peerId: string; addr: string }> {
  const node = await createNode({ keyProvider: generateKeypair(), listenAddresses: ["/ip4/127.0.0.1/tcp/0"] });
  await node.start();
  const addr = node.listenAddresses().find((a) => a.includes("/p2p/"));
  if (!addr) throw new Error("relay node has no addressed multiaddr");
  return { node, peerId: node.getPeerId(), addr };
}

describe("A: the parked-content drain rides the standing receiver's life-cycle", () => {
  let tempDir = "";
  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-park-drain-"));
    process.env["CELLO_LISTEN_ADDR"] = "/ip4/127.0.0.1/tcp/0"; // keep test nodes off real interfaces
  });
  afterEach(async () => {
    delete process.env["CELLO_LISTEN_ADDR"];
    await rm(tempDir, { recursive: true, force: true });
  });

  async function makeManager(opts?: { watchdogMs?: number; backstopMs?: number }) {
    const { logger, events } = makeLogger();
    const dbPath = join(tempDir, `sessions-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
    const manager = new SessionNodeManager({
      securityGateway: new PassthroughGatewayClient(),
      factory: new ProductionSessionNodeFactory(),
      logger,
      dbPath,
      standingReceiverRetryDelaysMs: [],
      standingReceiverReservationTimeoutMs: 2_000,
      ...(opts?.watchdogMs !== undefined ? { standingReceiverWatchdogIntervalMs: opts.watchdogMs } : {}),
      ...(opts?.backstopMs !== undefined ? { parkedDrainBackstopMs: opts.backstopMs } : {}),
    });
    await manager.initialize();
    const drains: Array<{ agentName: string; reason: string }> = [];
    manager.setParkedDrainHook((agentName, reason) => { drains.push({ agentName, reason }); });
    return { manager, events, drains };
  }

  async function seedRelayEndpoint(manager: SessionNodeManager, agent: string, relayPeerId: string, relayAddr: string): Promise<void> {
    const db = manager.getDb();
    const ids = await seedAgents(db, [agent]);
    const now = Date.now();
    db.prepare(
      `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, relay_peer_id, relay_addrs)
       VALUES (?, ?, ?, 'sealed', ?, ?, 0, ?, ?)`,
    ).run(randomUUID().replaceAll("-", ""), ids.get(agent)!, "cc".repeat(32), now, now, relayPeerId, JSON.stringify([relayAddr]));
  }

  it("A1: the first standing-receiver install drains the agent's parked mailbox", async () => {
    const { manager, drains } = await makeManager();
    try {
      await seedAgents(manager.getDb(), ["alice"]);
      await manager.ensureStandingReceiverForAgent("alice");
      expect(drains).toEqual([{ agentName: "alice", reason: "standing_receiver_ready" }]);
    } finally {
      await manager.gracefulShutdown();
    }
  }, 20_000);

  it("A2: a relay link that DIES mid-life drains again on the watchdog rebuild — no daemon restart", async () => {
    const relay = await startHopRelay();
    const { manager, events, drains } = await makeManager({ watchdogMs: 250 });
    try {
      await seedRelayEndpoint(manager, "alice", relay.peerId, relay.addr);
      await manager.ensureStandingReceiverForAgent("alice");
      const reserved = await waitUntil(() => {
        const info = manager.getStandingReceiverInfo("alice");
        return info !== null && info.addrs.some((a) => a.includes("/p2p-circuit"));
      }, 10_000);
      expect(reserved).toBe(true);
      expect(drains.length).toBe(1);

      // THE FLAP. The relay dies the way it did in production — the client keeps running, and the
      // content it could not deliver is sitting parked on the other side of this link.
      await relay.node.stop();

      const rebuilt = await waitUntil(() => drains.length >= 2, 15_000);
      expect(rebuilt, "the watchdog rebuild must drain — this is the trigger the defect was missing").toBe(true);
      expect(drains[1]).toEqual({ agentName: "alice", reason: "standing_receiver_ready" });
      expect(events.some((e) => e.event === "session.standing_receiver.reservation.lost")).toBe(true);
    } finally {
      await manager.gracefulShutdown();
      await relay.node.stop().catch(() => { /* already stopped */ });
    }
  }, 40_000);

  it("A3: the auth_ok rebuild (directory relay endpoints arriving late) drains too", async () => {
    const relay = await startHopRelay();
    const { manager, drains } = await makeManager();
    try {
      await seedAgents(manager.getDb(), ["alice"]);
      await manager.ensureStandingReceiverForAgent("alice"); // comes up with no reservation
      expect(drains.length).toBe(1);

      manager.setDirectoryRelayEndpoints("alice", [{ relayPeerId: relay.peerId, relayAddrs: [relay.addr] }]);
      const rebuilt = await waitUntil(() => drains.length >= 2, 15_000);
      expect(rebuilt).toBe(true);
    } finally {
      await manager.gracefulShutdown();
      await relay.node.stop();
    }
  }, 40_000);

  it("A4: a slow periodic backstop drains a steady receiver, so a missed trigger cannot strand content forever", async () => {
    const { manager, drains } = await makeManager({ watchdogMs: 100, backstopMs: 300 });
    try {
      await seedAgents(manager.getDb(), ["alice"]);
      await manager.ensureStandingReceiverForAgent("alice");
      const backstopped = await waitUntil(() => drains.some((d) => d.reason === "periodic_backstop"), 10_000);
      expect(backstopped).toBe(true);
      expect(drains.filter((d) => d.reason === "periodic_backstop").every((d) => d.agentName === "alice")).toBe(true);
    } finally {
      await manager.gracefulShutdown();
    }
  }, 20_000);

  it("A5: a THROWING drain hook costs the drain, never the standing receiver", async () => {
    const { logger, events } = makeLogger();
    const dbPath = join(tempDir, `sessions-throw-${Date.now()}.db`);
    const manager = new SessionNodeManager({
      securityGateway: new PassthroughGatewayClient(),
      factory: new ProductionSessionNodeFactory(),
      logger,
      dbPath,
      standingReceiverRetryDelaysMs: [],
    });
    await manager.initialize();
    manager.setParkedDrainHook(() => { throw new Error("drain exploded"); });
    try {
      await seedAgents(manager.getDb(), ["alice"]);
      await manager.ensureStandingReceiverForAgent("alice");
      expect(manager.getStandingReceiverInfo("alice")).not.toBeNull();
      const failed = events.find((e) => e.event === "content.recover.drain.hook.failed");
      expect(failed).toBeDefined();
      expect(String(failed!.context["error"])).toContain("drain exploded");
    } finally {
      await manager.gracefulShutdown();
    }
  }, 20_000);
});

describe("B: the signaling-reconnect drain chains ensure→drain instead of racing it", () => {
  it("B1: the drain runs only AFTER the standing-receiver ensure has resolved", async () => {
    const order: string[] = [];
    let releaseEnsure = (): void => {};
    const ensureGate = new Promise<void>((r) => { releaseEnsure = r; });
    const { logger } = makeLogger();

    const onConnected = createReconnectDrain({
      logger,
      isAgentOnline: () => true,
      ensureStandingReceiver: async (agentName) => {
        order.push(`ensure:start:${agentName}`);
        await ensureGate;
        order.push(`ensure:done:${agentName}`);
      },
      drainParked: async (agentName) => { order.push(`drain:${agentName}`); },
    });

    onConnected("alice");
    await wait(20);
    expect(order, "the drain must not start while the ensure is still in flight").toEqual(["ensure:start:alice"]);

    releaseEnsure();
    await waitUntil(() => order.includes("drain:alice"), 2_000);
    expect(order).toEqual(["ensure:start:alice", "ensure:done:alice", "drain:alice"]);
  });

  it("B2: an ensure that rejects names its cause and does not run a drain that cannot work", async () => {
    const { logger, events } = makeLogger();
    let drained = false;
    const onConnected = createReconnectDrain({
      logger,
      isAgentOnline: () => true,
      // The transport rejects with structured plain objects, not Errors — String() on one of these
      // is the "[object Object]" that made 102 real failures undiagnosable.
      ensureStandingReceiver: async () => { throw { reason: "port_in_use", message: "EADDRINUSE 41000" }; },
      drainParked: async () => { drained = true; },
    });

    onConnected("alice");
    await waitUntil(() => events.some((e) => e.event === "session.standing_receiver.reregister.failed"), 2_000);
    const failed = events.find((e) => e.event === "session.standing_receiver.reregister.failed");
    expect(failed).toBeDefined();
    expect(String(failed!.context["error"])).toBe("EADDRINUSE 41000");
    expect(String(failed!.context["error"])).not.toContain("[object Object]");
    expect(drained).toBe(false);
  });

  it("B3: an agent that is not online gets neither a receiver nor a drain", async () => {
    const { logger } = makeLogger();
    let ensured = false;
    let drained = false;
    const onConnected = createReconnectDrain({
      logger,
      isAgentOnline: () => false,
      ensureStandingReceiver: async () => { ensured = true; },
      drainParked: async () => { drained = true; },
    });
    onConnected("alice");
    await wait(50);
    expect(ensured).toBe(false);
    expect(drained).toBe(false);
  });

  it("B4: a drain that rejects is logged with its cause, never swallowed and never '[object Object]'", async () => {
    const { logger, events } = makeLogger();
    const onConnected = createReconnectDrain({
      logger,
      isAgentOnline: () => true,
      ensureStandingReceiver: async () => {},
      drainParked: async () => { throw { reason: "relay_unreachable", message: "dial failed" }; },
    });
    onConnected("alice");
    await waitUntil(() => events.some((e) => e.event === "content.recover.auto.failed"), 2_000);
    const failed = events.find((e) => e.event === "content.recover.auto.failed");
    expect(failed).toBeDefined();
    expect(String(failed!.context["error"] ?? failed!.context["reason"])).toBe("dial failed");
  });
});

describe("C: the daemon composition root wires the drain to the standing receiver", () => {
  let tempDir = "";
  let handle: DaemonHandle | null = null;
  let logger: Logger;
  let logEvents: LogEvent[];

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-park-drain-daemon-"));
    process.env["CELLO_LISTEN_ADDR"] = "/ip4/127.0.0.1/tcp/0";
    const made = makeLogger();
    logger = made.logger;
    logEvents = made.events;
    handle = null;
  });
  afterEach(async () => {
    delete process.env["CELLO_LISTEN_ADDR"];
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* already stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
  });

  function makeConfig(overrides?: Partial<DaemonConfig>): DaemonConfig {
    return {
      securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
      ...overrides,
    };
  }

  it("C1: a standing-receiver rebuild inside a RUNNING daemon drains the mailbox, and the failure names its cause", async () => {
    const relay = await startHopRelay();
    await mkdir(join(tempDir, "agents", "alice"), { recursive: true });
    await FileKeyProvider.load(join(tempDir, "agents", "alice", "key"));

    handle = await startDaemon(makeConfig());
    const manager = handle.getSessionNodeManager();

    // A session on this relay is what makes the agent's mailbox worth draining — autoRecoverForAgent
    // reads its relay set from session history.
    const db = manager.getDb();
    const ids = await seedAgents(db, ["alice"]);
    const now = Date.now();
    db.prepare(
      `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, relay_peer_id, relay_addrs)
       VALUES (?, ?, ?, 'interrupted', ?, ?, 0, ?, ?)`,
    ).run(randomUUID().replaceAll("-", ""), ids.get("alice")!, "cc".repeat(32), now, now, relay.peerId, JSON.stringify([relay.addr]));

    await manager.ensureStandingReceiverForAgent("alice");
    const drainedOnce = await waitUntil(
      () => logEvents.some((e) => e.event === "content.recover.auto.completed" && e.context["agentName"] === "alice"),
      15_000,
    );
    expect(drainedOnce, "the daemon must wire the standing-receiver drain hook — no consumer, no ship").toBe(true);

    // The relay is a bare libp2p node: it does not speak /cello/content-park, so the pull fails.
    // That failure is the one that logged "[object Object]" for 102 occurrences in the incident log.
    const failure = logEvents.find(
      (e) => e.event === "content.recover.auto.failed" || e.event === "content.recover.auto.relay_failed",
    );
    if (failure) {
      const rendered = JSON.stringify(failure.context);
      expect(rendered, "a drain failure must name its cause").not.toContain("[object Object]");
    }
  }, 60_000);
});
