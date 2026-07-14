/**
 * DOD-NAT-REACHABILITY-1 parts 2+3 (daemon) — the standing receiver takes
 * circuit-relay reservations, binds routable, and the gaters admit the relays.
 *
 * The defect: a CELLO agent on a normal machine could not RECEIVE a session.
 * The standing receiver listened on loopback unless CELLO_LISTEN_ADDR was
 * hand-set, and no node ever listened on /p2p/<relay>/p2p-circuit, so a NAT'd
 * agent had no dialable address of any kind. The app-level mailbox absorbed the
 * failed dials, which is why it presented as "slow" instead of "unreachable".
 *
 * Pinned here:
 *  R1 — SessionConnectionGater outbound allowance is a SET: the session node
 *       must dial the assigned witness relay AND the counterparty's reservation
 *       relay(s), which are independent.
 *  R2 — ProductionSessionNodeFactory: standing receiver defaults to a ROUTABLE
 *       listen (/ip4/0.0.0.0/tcp/0), CELLO_LISTEN_ADDR still overrides, and
 *       ephemeral session nodes stay on loopback.
 *  R3 — the factory forwards circuitRelayListenAddrs so the receiver reserves
 *       with the relay (circuit addr appears in listenAddresses()).
 *  R4 — SessionNodeManager wires persisted relay endpoints (sessions rows) into
 *       the standing receiver's reservation set.
 *  R5 — a DEAD relay endpoint must not kill the receiver: it installs TCP-only
 *       and logs the degradation loudly (this is the sovereign-redundancy
 *       invariant — one dead relay must never mean "deaf agent").
 *  R6 — the initiator's connectToCounterparty can dial a /p2p-circuit address:
 *       the gater admits the relay embedded in the FROST-signed assignment addr.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { SessionNodeManager } from "../session-node-manager.js";
import { SessionConnectionGater } from "../session-connection-gater.js";
import { ProductionSessionNodeFactory } from "../daemon.js";
import type { Logger } from "../types.js";
import type { CelloNode } from "@cello-protocol/transport";
import { createNode } from "@cello-protocol/transport";
import { generateKeypair } from "@cello-protocol/crypto";
import { seedAgents } from "./helpers/seed-agents.js";

function makeLogger(): { logger: Logger; events: Array<{ level: string; event: string; context: Record<string, unknown> }> } {
  const events: Array<{ level: string; event: string; context: Record<string, unknown> }> = [];
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

/** A syntactically valid (but unreachable) libp2p peer id for dead-relay tests. */
const DEAD_RELAY_PEER_ID = "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aU76ZgUriHhKust";

describe("R1: SessionConnectionGater outbound allowance is a set", () => {
  it("two setAllowedOutboundPeer calls both stay allowed; inbound allowlist is untouched", () => {
    const { logger, events } = makeLogger();
    const gater = new SessionConnectionGater({ sessionId: "s1", allowedPeerId: "COUNTERPARTY", logger });
    gater.setAllowedOutboundPeer("RELAY_WITNESS");
    gater.setAllowedOutboundPeer("RESERVATION_RELAY");

    const asPeer = (s: string) => ({ toString: () => s }) as unknown as Parameters<typeof gater.denyOutboundEncryptedConnection>[0];
    const maConn = {} as Parameters<typeof gater.denyOutboundEncryptedConnection>[1];

    expect(gater.denyOutboundEncryptedConnection(asPeer("RELAY_WITNESS"), maConn)).toBe(false);
    expect(gater.denyOutboundEncryptedConnection(asPeer("RESERVATION_RELAY"), maConn)).toBe(false);
    expect(gater.denyOutboundEncryptedConnection(asPeer("COUNTERPARTY"), maConn)).toBe(false);
    expect(gater.denyOutboundEncryptedConnection(asPeer("STRANGER"), maConn)).toBe(true);
    // Inbound: outbound allowances must NOT widen the inbound gate (INV-5).
    expect(gater.denyInboundEncryptedConnection(asPeer("RESERVATION_RELAY"), maConn)).toBe(true);
    expect(gater.denyInboundEncryptedConnection(asPeer("COUNTERPARTY"), maConn)).toBe(false);
    expect(events.some((e) => e.event === "session.node.connection.rejected")).toBe(true);
  });
});

describe("R2: ProductionSessionNodeFactory listen defaults", () => {
  const savedListen = process.env["CELLO_LISTEN_ADDR"];
  const savedAnnounce = process.env["CELLO_ANNOUNCE_ADDRS"];
  afterEach(() => {
    if (savedListen === undefined) delete process.env["CELLO_LISTEN_ADDR"];
    else process.env["CELLO_LISTEN_ADDR"] = savedListen;
    if (savedAnnounce === undefined) delete process.env["CELLO_ANNOUNCE_ADDRS"];
    else process.env["CELLO_ANNOUNCE_ADDRS"] = savedAnnounce;
  });

  it("standing receiver binds ROUTABLE by default — not loopback-only", async () => {
    delete process.env["CELLO_LISTEN_ADDR"];
    const factory = new ProductionSessionNodeFactory();
    const node = await factory.createNode({ sessionId: "sr-test", nodeType: "standing_receiver" });
    await node.start();
    try {
      const addrs = node.listenAddresses();
      // 0.0.0.0 enumerates every interface — loopback appears, but it must not be ALL there is.
      expect(addrs.length).toBeGreaterThan(0);
      expect(addrs.some((a) => a.startsWith("/ip4/") && !a.startsWith("/ip4/127."))).toBe(true);
    } finally {
      await node.stop();
    }
  });

  it("CELLO_LISTEN_ADDR still overrides the standing receiver listen address", async () => {
    process.env["CELLO_LISTEN_ADDR"] = "/ip4/127.0.0.1/tcp/0";
    const factory = new ProductionSessionNodeFactory();
    const node = await factory.createNode({ sessionId: "sr-env", nodeType: "standing_receiver" });
    await node.start();
    try {
      expect(node.listenAddresses().every((a) => !a.startsWith("/ip4/") || a.startsWith("/ip4/127."))).toBe(true);
    } finally {
      await node.stop();
    }
  });

  it("ephemeral session nodes stay on loopback — they dial OUT and need no inbound reachability", async () => {
    delete process.env["CELLO_LISTEN_ADDR"];
    const factory = new ProductionSessionNodeFactory();
    const node = await factory.createNode({ sessionId: "sess-test", nodeType: "session" });
    await node.start();
    try {
      expect(node.listenAddresses().every((a) => !a.startsWith("/ip4/") || a.startsWith("/ip4/127."))).toBe(true);
    } finally {
      await node.stop();
    }
  });
});

describe("R3: the factory forwards circuit-relay listen addresses", () => {
  it("a standing receiver created with circuitRelayListenAddrs reserves with the relay", async () => {
    const relay = await startHopRelay();
    process.env["CELLO_LISTEN_ADDR"] = "/ip4/127.0.0.1/tcp/0";
    try {
      const factory = new ProductionSessionNodeFactory();
      const node = await factory.createNode({
        sessionId: "sr-circuit",
        nodeType: "standing_receiver",
        circuitRelayListenAddrs: [`${relay.addr}/p2p-circuit`],
      });
      await node.start();
      try {
        const ok = await waitUntil(() => node.listenAddresses().some((a) => a.includes("/p2p-circuit")), 10_000);
        expect(ok).toBe(true);
      } finally {
        await node.stop();
      }
    } finally {
      delete process.env["CELLO_LISTEN_ADDR"];
      await relay.node.stop();
    }
  }, 20_000);
});

describe("R4+R5+R6: SessionNodeManager reservation wiring", () => {
  let tempDir = "";
  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-nat-resv-"));
    process.env["CELLO_LISTEN_ADDR"] = "/ip4/127.0.0.1/tcp/0"; // keep test nodes off real interfaces
  });
  afterEach(async () => {
    delete process.env["CELLO_LISTEN_ADDR"];
    await rm(tempDir, { recursive: true, force: true });
  });

  async function makeManager() {
    const { logger, events } = makeLogger();
    const dbPath = join(tempDir, `sessions-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
    const manager = new SessionNodeManager({ factory: new ProductionSessionNodeFactory(), logger, dbPath });
    await manager.initialize();
    return { manager, events };
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

  it("R4: persisted relay endpoints become reservations — the receiver advertises a /p2p-circuit addr", async () => {
    const relay = await startHopRelay();
    const { manager, events } = await makeManager();
    try {
      await seedRelayEndpoint(manager, "alice", relay.peerId, relay.addr);
      await manager.ensureStandingReceiverForAgent("alice");
      const ok = await waitUntil(() => {
        const info = manager.getStandingReceiverInfo("alice");
        return info !== null && info.addrs.some((a) => a.includes("/p2p-circuit"));
      }, 10_000);
      expect(ok).toBe(true);
      expect(events.some((e) => e.event === "session.standing_receiver.reachability")).toBe(true);
      // The reservation settles INSIDE node.start() (the circuit listener awaits
      // openConnection + reserve), so the healthy path must never fire the
      // degradation warn — pins the timing against future libp2p upgrades.
      expect(events.some((e) => e.event === "session.standing_receiver.reservation.none")).toBe(false);
    } finally {
      await manager.gracefulShutdown();
      await relay.node.stop();
    }
  }, 20_000);

  it("R5: a dead relay endpoint degrades LOUDLY but does not kill the receiver", async () => {
    const { manager, events } = await makeManager();
    try {
      await seedRelayEndpoint(manager, "alice", DEAD_RELAY_PEER_ID, "/ip4/127.0.0.1/tcp/59987");
      await manager.ensureStandingReceiverForAgent("alice");
      const info = manager.getStandingReceiverInfo("alice");
      expect(info).not.toBeNull();
      expect(info!.addrs.length).toBeGreaterThan(0);
      expect(info!.addrs.every((a) => !a.includes("/p2p-circuit"))).toBe(true);
      expect(events.some((e) => e.event === "session.standing_receiver.reservation.none" && e.level === "warn")).toBe(true);
    } finally {
      await manager.gracefulShutdown();
    }
  }, 20_000);

  it("R6: the initiator dials a /p2p-circuit counterparty address — the embedded relay is admitted outbound", async () => {
    const relay = await startHopRelay();
    // The "counterparty": a receiver reserved with the relay (plain transport node, open gater).
    const receiver = await createNode({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0", `${relay.addr}/p2p-circuit`],
      nodeType: "standing_receiver",
    });
    await receiver.start();
    const { manager } = await makeManager();
    try {
      const circuitOk = await waitUntil(() => receiver.listenAddresses().some((a) => a.includes("/p2p-circuit")), 10_000);
      expect(circuitOk).toBe(true);
      const circuitAddr = receiver.listenAddresses().find((a) => a.includes("/p2p-circuit"))!;

      const db = manager.getDb();
      await seedAgents(db, ["alice"]);
      const sessionId = randomUUID().replaceAll("-", "");
      const created = await manager.createSessionNode(sessionId, "alice", "dd".repeat(32), receiver.getPeerId(), randomUUID());
      expect(created.ok).toBe(true);

      const res = await manager.connectToCounterparty("alice", sessionId, [circuitAddr]);
      expect(res).toEqual({ ok: true });
    } finally {
      await manager.gracefulShutdown();
      await receiver.stop();
      await relay.node.stop();
    }
  }, 30_000);
});

describe("R7+R8: directory-provided relay endpoints (Phase 2 client half)", () => {
  let tempDir = "";
  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-nat-dirteps-"));
    process.env["CELLO_LISTEN_ADDR"] = "/ip4/127.0.0.1/tcp/0";
  });
  afterEach(async () => {
    delete process.env["CELLO_LISTEN_ADDR"];
    await rm(tempDir, { recursive: true, force: true });
  });

  async function makeManager() {
    const { logger, events } = makeLogger();
    const dbPath = join(tempDir, `sessions-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
    const manager = new SessionNodeManager({ factory: new ProductionSessionNodeFactory(), logger, dbPath });
    await manager.initialize();
    return { manager, events };
  }

  it("R7: endpoints set BEFORE ensure — a fresh agent with no session history still reserves", async () => {
    const relay = await startHopRelay();
    const { manager } = await makeManager();
    try {
      await seedAgents(manager.getDb(), ["alice"]); // agent exists; NO sessions rows
      manager.setDirectoryRelayEndpoints("alice", [{ relayPeerId: relay.peerId, relayAddrs: [relay.addr] }]);
      await manager.ensureStandingReceiverForAgent("alice");
      const ok = await waitUntil(() => {
        const info = manager.getStandingReceiverInfo("alice");
        return info !== null && info.addrs.some((a) => a.includes("/p2p-circuit"));
      }, 10_000);
      expect(ok).toBe(true);
    } finally {
      await manager.gracefulShutdown();
      await relay.node.stop();
    }
  }, 20_000);

  it("R8: endpoints arriving AFTER a deaf ensure rebuild the receiver (agent-online races auth_ok)", async () => {
    const relay = await startHopRelay();
    const { manager, events } = await makeManager();
    try {
      await seedAgents(manager.getDb(), ["alice"]);
      await manager.ensureStandingReceiverForAgent("alice"); // no endpoints known yet → deaf to NAT'd initiators
      const before = manager.getStandingReceiverInfo("alice");
      expect(before).not.toBeNull();
      expect(before!.addrs.every((a) => !a.includes("/p2p-circuit"))).toBe(true);

      manager.setDirectoryRelayEndpoints("alice", [{ relayPeerId: relay.peerId, relayAddrs: [relay.addr] }]);
      const ok = await waitUntil(() => {
        const info = manager.getStandingReceiverInfo("alice");
        return info !== null && info.addrs.some((a) => a.includes("/p2p-circuit"));
      }, 10_000);
      expect(ok).toBe(true);
      expect(events.some((e) => e.event === "session.standing_receiver.reservation.rebuild")).toBe(true);
    } finally {
      await manager.gracefulShutdown();
      await relay.node.stop();
    }
  }, 20_000);

  it("R8b: endpoints arriving when the receiver ALREADY has a reservation do NOT rebuild it", async () => {
    const relay = await startHopRelay();
    const { manager, events } = await makeManager();
    try {
      await seedAgents(manager.getDb(), ["alice"]);
      manager.setDirectoryRelayEndpoints("alice", [{ relayPeerId: relay.peerId, relayAddrs: [relay.addr] }]);
      await manager.ensureStandingReceiverForAgent("alice");
      await waitUntil(() => {
        const info = manager.getStandingReceiverInfo("alice");
        return info !== null && info.addrs.some((a) => a.includes("/p2p-circuit"));
      }, 10_000);
      const peerBefore = manager.getStandingReceiverInfo("alice")!.peerId;

      manager.setDirectoryRelayEndpoints("alice", [{ relayPeerId: relay.peerId, relayAddrs: [relay.addr] }]);
      await wait(300);
      expect(manager.getStandingReceiverInfo("alice")!.peerId).toBe(peerBefore);
      expect(events.some((e) => e.event === "session.standing_receiver.reservation.rebuild")).toBe(false);
    } finally {
      await manager.gracefulShutdown();
      await relay.node.stop();
    }
  }, 20_000);
});
