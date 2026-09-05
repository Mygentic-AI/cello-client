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
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
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
    const manager = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new ProductionSessionNodeFactory(), logger, dbPath });
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
      // 032-RELAYSPREAD part 1 — the reachability event names the two facts separately.
      // `reservationsRequested` was `reservations.addrs.length`: the size of the CANDIDATE list,
      // logged under a name that reads as a count of asks. That one field is why "the client
      // already requests a reservation with every relay it knows" survived an audit.
      const reach = events.find((e) => e.event === "session.standing_receiver.reachability");
      expect(reach).toBeDefined();
      expect(reach!.context).not.toHaveProperty("reservationsRequested");
      expect(reach!.context.relaysOffered).toBe(1);
      expect(reach!.context.reservationsHeld).toBe(1);
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
      const none = events.find((e) => e.event === "session.standing_receiver.reservation.none");
      expect(none).toBeDefined();
      expect(none!.level).toBe("warn");
      // Offered one, held none. The two numbers DIVERGE here, which is the whole point of splitting
      // the field: under the old name this event said "1" and a reader could not tell whether that
      // meant one relay asked or one reservation obtained.
      expect(none!.context).not.toHaveProperty("reservationsRequested");
      expect(none!.context.relaysOffered).toBe(1);
      expect(none!.context.reservationsHeld).toBe(0);
    } finally {
      await manager.gracefulShutdown();
    }
  }, 20_000);

  it("R5b: offered TWO relays with one dead — relaysOffered is 2 and reservationsHeld is 1", async () => {
    // THE DISCRIMINATING CASE, and the reason R4 alone is not enough: R4 offers one relay and holds
    // one, so `reservationsHeld: reservations.addrs.length` — the exact bug being renamed away —
    // passes it. Here the two numbers cannot both be right, so only a count of what actually
    // GRANTED survives. Order-independent: whichever candidate is tried first, one relay grants.
    const relay = await startHopRelay();
    const { manager, events } = await makeManager();
    try {
      await seedRelayEndpoint(manager, "alice", relay.peerId, relay.addr);
      await seedRelayEndpoint(manager, "alice", DEAD_RELAY_PEER_ID, "/ip4/127.0.0.1/tcp/59987");
      await manager.ensureStandingReceiverForAgent("alice");
      const ok = await waitUntil(() => {
        const info = manager.getStandingReceiverInfo("alice");
        return info !== null && info.addrs.some((a) => a.includes("/p2p-circuit"));
      }, 15_000);
      expect(ok).toBe(true);
      const reach = events.find((e) => e.event === "session.standing_receiver.reachability");
      expect(reach).toBeDefined();
      expect(reach!.context.relaysOffered).toBe(2);
      expect(reach!.context.reservationsHeld).toBe(1);
    } finally {
      await manager.gracefulShutdown();
      await relay.node.stop();
    }
  }, 30_000);

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
    const manager = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new ProductionSessionNodeFactory(), logger, dbPath });
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

// ─── Review round 3: a hostile/misconfigured directory must not kill the receiver ──

describe("R9+R10: directory-supplied endpoints are untrusted input", () => {
  let tempDir = "";
  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-nat-untrusted-"));
    process.env["CELLO_LISTEN_ADDR"] = "/ip4/127.0.0.1/tcp/0";
  });
  afterEach(async () => {
    delete process.env["CELLO_LISTEN_ADDR"];
    await rm(tempDir, { recursive: true, force: true });
  });

  async function makeManager() {
    const { logger, events } = makeLogger();
    const dbPath = join(tempDir, `sessions-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
    const manager = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new ProductionSessionNodeFactory(), logger, dbPath });
    await manager.initialize();
    return { manager, events };
  }

  it("R9: a NON-MULTIADDR relay endpoint (a wss:// URL) is dropped — the receiver still comes up", async () => {
    // The blocking defect: the directory used to fabricate `[r.endpoint]` (a wss:// URL)
    // for a relay with no multiaddrs. Fed into libp2p's LISTEN set it throws at node
    // construction — every create attempt fails and the agent ends up with NO standing
    // receiver: deaf to ALL inbound, including the direct path that worked before.
    // A bad endpoint must cost one relay, never the receiver.
    const { manager, events } = await makeManager();
    try {
      await seedAgents(manager.getDb(), ["alice"]);
      manager.setDirectoryRelayEndpoints("alice", [
        { relayPeerId: DEAD_RELAY_PEER_ID, relayAddrs: ["wss://relay.example.com"] },
      ]);
      await manager.ensureStandingReceiverForAgent("alice");

      const info = manager.getStandingReceiverInfo("alice");
      expect(info).not.toBeNull();                       // the receiver LIVES
      expect(info!.addrs.length).toBeGreaterThan(0);     // and is dialable directly
      expect(events.some((e) => e.event === "session.standing_receiver.relay_endpoint.invalid" && e.level === "warn")).toBe(true);
      expect(events.some((e) => e.event === "session.standing_receiver.dead")).toBe(false);
    } finally {
      await manager.gracefulShutdown();
    }
  }, 20_000);

  it("R10: an agent stopped DURING a rebuild is not resurrected — a stopped agent stays dark", async () => {
    const relay = await startHopRelay();
    const { manager } = await makeManager();
    try {
      await seedAgents(manager.getDb(), ["alice"]);
      await manager.ensureStandingReceiverForAgent("alice"); // up, no reservation → deaf
      expect(manager.getStandingReceiverInfo("alice")).not.toBeNull();

      // Endpoints arrive → rebuild starts. The agent goes offline while it is in flight.
      manager.setDirectoryRelayEndpoints("alice", [{ relayPeerId: relay.peerId, relayAddrs: [relay.addr] }]);
      await manager.removeStandingReceiverForAgent("alice");

      // The rebuild must observe the cleared want-flag and NOT stand a receiver back up
      // for an agent that asked to go dark (it would accept inbound sessions offline).
      await wait(1_500);
      expect(manager.getStandingReceiverInfo("alice")).toBeNull();
    } finally {
      await manager.gracefulShutdown();
      await relay.node.stop();
    }
  }, 20_000);
});

// ─── R11: THE LIVE REGRESSION — creation must never be gated on relay reachability ──
//
// Found in production, not in a test: the directory handed out THREE relays; one did
// not answer from this network; libp2p's circuit listener awaits a live connection to
// each relay before start() resolves and has NO timeout of its own — so start() hung
// forever. No created event, no failure, no retry, no alarm. Every agent on the daemon
// ended up with NO standing receiver: deaf to ALL inbound, including the direct path
// that worked before reservations existed. Strictly worse than the NAT defect itself.

describe("R11: an unreachable relay must NOT prevent the standing receiver from coming up", () => {
  let tempDir = "";
  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-nat-hang-"));
    process.env["CELLO_LISTEN_ADDR"] = "/ip4/127.0.0.1/tcp/0";
  });
  afterEach(async () => {
    delete process.env["CELLO_LISTEN_ADDR"];
    await rm(tempDir, { recursive: true, force: true });
  });

  /** A factory whose circuit-listen node NEVER finishes starting — the live failure. */
  class HangingCircuitFactory extends ProductionSessionNodeFactory {
    override async createNode(config: Parameters<ProductionSessionNodeFactory["createNode"]>[0]) {
      const node = await super.createNode({ ...config, circuitRelayListenAddrs: undefined });
      if (config.circuitRelayListenAddrs && config.circuitRelayListenAddrs.length > 0) {
        // Mimic libp2p: start() parks forever waiting on a relay that never answers.
        return { ...node, start: () => new Promise<void>(() => {}) } as typeof node;
      }
      return node;
    }
  }

  it("R11a: an UNREACHABLE relay is rejected — the receiver still comes up", async () => {
    const { logger, events } = makeLogger();
    const manager = new SessionNodeManager({
      securityGateway: new PassthroughGatewayClient(),
      factory: new ProductionSessionNodeFactory(),
      logger,
      dbPath: join(tempDir, "sessions-a.db"),
      });
    await manager.initialize();
    try {
      await seedAgents(manager.getDb(), ["alice"]);
      manager.setDirectoryRelayEndpoints("alice", [
        { relayPeerId: DEAD_RELAY_PEER_ID, relayAddrs: ["/ip4/127.0.0.1/tcp/59986"] },
      ]);

      await manager.ensureStandingReceiverForAgent("alice");

      // THE ASSERTION THAT MATTERS: the agent HAS a receiver. It is reachable.
      const info = manager.getStandingReceiverInfo("alice");
      expect(info).not.toBeNull();
      expect(info!.addrs.length).toBeGreaterThan(0);
      // The relay was rejected — unreachable, out of slots, or too slow. All three are
      // "do not listen on this relay", and all three are logged with a named reason.
      expect(events.some((e) => e.event === "session.standing_receiver.relay.rejected" && e.level === "warn")).toBe(true);
      expect(events.some((e) => e.event === "session.standing_receiver.dead")).toBe(false);
    } finally {
      await manager.gracefulShutdown();
    }
  }, 20_000);

  it("R11b: a relay whose RESERVATION never completes is abandoned on the deadline → receiver still comes up, loudly degraded", async () => {
    // The relay is dialable, so a dial-only probe would wave it through. The probe
    // attempts the REAL reservation, so it catches the hang here — on a throwaway
    // node — instead of on the standing receiver, where it would leave the agent deaf.
    const relay = await startHopRelay();
    const { logger, events } = makeLogger();
    const manager = new SessionNodeManager({
      securityGateway: new PassthroughGatewayClient(),
      factory: new HangingCircuitFactory(),
      logger,
      dbPath: join(tempDir, "sessions-b.db"),
      standingReceiverReservationTimeoutMs: 400,
      });
    await manager.initialize();
    try {
      await seedAgents(manager.getDb(), ["alice"]);
      manager.setDirectoryRelayEndpoints("alice", [
        { relayPeerId: relay.peerId, relayAddrs: [relay.addr] }, // dialable, but the reservation hangs
      ]);

      await manager.ensureStandingReceiverForAgent("alice");

      // THE ASSERTION THAT MATTERS: the agent HAS a receiver.
      const info = manager.getStandingReceiverInfo("alice");
      expect(info).not.toBeNull();
      expect(info!.addrs.length).toBeGreaterThan(0);
      expect(events.some((e) => e.event === "session.standing_receiver.relay.rejected" && e.level === "warn")).toBe(true);
      expect(events.some((e) => e.event === "session.standing_receiver.dead")).toBe(false);
    } finally {
      await manager.gracefulShutdown();
      await relay.node.stop();
    }
  }, 25_000);

  it("R11c: a HEALTHY relay still reserves — the probe must not cost the good path", async () => {
    const relay = await startHopRelay();
    const { logger } = makeLogger();
    const manager = new SessionNodeManager({
      securityGateway: new PassthroughGatewayClient(),
      factory: new ProductionSessionNodeFactory(),
      logger,
      dbPath: join(tempDir, "sessions-c.db"),
    });
    await manager.initialize();
    try {
      await seedAgents(manager.getDb(), ["alice"]);
      // One dead relay AND one healthy one: the dead must not cost the healthy its
      // reservation (live, exactly this left 3 of 4 agents with none).
      manager.setDirectoryRelayEndpoints("alice", [
        { relayPeerId: DEAD_RELAY_PEER_ID, relayAddrs: ["/ip4/127.0.0.1/tcp/59986"] },
        { relayPeerId: relay.peerId, relayAddrs: [relay.addr] },
      ]);

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
  }, 25_000);
});

// ─── W: the reservation WATCHDOG — a silently lost reservation must be noticed ──
//
// libp2p refreshes a circuit reservation before it expires. If the relay has died,
// the refresh fails and the /p2p-circuit address simply VANISHES. Nothing throws.
// The receiver is still up and still directly dialable, so it looks perfectly
// healthy — while no NAT'd peer can reach the agent at all. That is the silent
// loss of inbound this whole story exists to kill; it cannot be left to chance.

describe("W: a standing receiver that LOSES its reservation gets another one", () => {
  let tempDir = "";
  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-nat-watchdog-"));
    process.env["CELLO_LISTEN_ADDR"] = "/ip4/127.0.0.1/tcp/0";
  });
  afterEach(async () => {
    delete process.env["CELLO_LISTEN_ADDR"];
    await rm(tempDir, { recursive: true, force: true });
  });

  function makeManager(dbName: string) {
    const { logger, events } = makeLogger();
    const manager = new SessionNodeManager({
      securityGateway: new PassthroughGatewayClient(),
      factory: new ProductionSessionNodeFactory(),
      logger,
      dbPath: join(tempDir, dbName),
      standingReceiverWatchdogIntervalMs: 250,
    });
    return { manager, events };
  }

  it("W1: the relay dies → the circuit address vanishes → the watchdog re-picks a live relay and the agent is reachable again", async () => {
    const dying = await startHopRelay();
    const survivor = await startHopRelay();
    const { manager, events } = makeManager("w1.db");
    await manager.initialize();
    try {
      await seedAgents(manager.getDb(), ["alice"]);
      // The dying relay is FIRST, so it is the one selected.
      manager.setDirectoryRelayEndpoints("alice", [
        { relayPeerId: dying.peerId, relayAddrs: [dying.addr] },
        { relayPeerId: survivor.peerId, relayAddrs: [survivor.addr] },
      ]);
      await manager.ensureStandingReceiverForAgent("alice");
      expect(
        await waitUntil(() => {
          const i = manager.getStandingReceiverInfo("alice");
          return i !== null && i.addrs.some((a) => a.includes("/p2p-circuit"));
        }, 10_000),
      ).toBe(true);

      const peerBefore = manager.getStandingReceiverInfo("alice")!.peerId;

      // The relay dies. NOTE: libp2p does NOT drop the /p2p-circuit address here — it
      // keeps it until the reservation's own refresh, hours away. So "still advertising
      // a circuit address" proves nothing, and a test that only checked for one would
      // pass while the agent was unreachable. The watchdog must DETECT the loss.
      await dying.node.stop();

      const detected = await waitUntil(
        () => events.some((e) => e.event === "session.standing_receiver.reservation.lost" && e.level === "warn"),
        20_000,
      );
      expect(detected).toBe(true);

      // …and having detected it, re-probe (the dead relay now fails), pick the
      // survivor, and rebuild — WITHOUT anyone asking. A NEW node, holding a real
      // reservation with the relay that is still alive.
      const recovered = await waitUntil(() => {
        const i = manager.getStandingReceiverInfo("alice");
        return i !== null && i.peerId !== peerBefore && i.addrs.some((a) => a.includes("/p2p-circuit"));
      }, 20_000);
      expect(recovered).toBe(true);
    } finally {
      await manager.gracefulShutdown();
      await survivor.node.stop();
      try { await dying.node.stop(); } catch { /* already stopped */ }
    }
  }, 40_000);

  it("W2: a receiver that NEVER had a reservation is not rebuilt on a timer — no thrash against relays we know refuse", async () => {
    const { manager, events } = makeManager("w2.db");
    await manager.initialize();
    try {
      await seedAgents(manager.getDb(), ["alice"]);
      manager.setDirectoryRelayEndpoints("alice", [
        { relayPeerId: DEAD_RELAY_PEER_ID, relayAddrs: ["/ip4/127.0.0.1/tcp/59985"] },
      ]);
      await manager.ensureStandingReceiverForAgent("alice");
      const peerBefore = manager.getStandingReceiverInfo("alice")!.peerId;

      await wait(1_200); // several watchdog ticks
      // Still up, still the SAME node — degraded (and already loud), never thrashing.
      expect(manager.getStandingReceiverInfo("alice")!.peerId).toBe(peerBefore);
      expect(events.some((e) => e.event === "session.standing_receiver.reservation.lost")).toBe(false);
    } finally {
      await manager.gracefulShutdown();
    }
  }, 25_000);

  it("W3: the watchdog never resurrects a receiver for an agent that went offline", async () => {
    const relay = await startHopRelay();
    const { manager } = makeManager("w3.db");
    await manager.initialize();
    try {
      await seedAgents(manager.getDb(), ["alice"]);
      manager.setDirectoryRelayEndpoints("alice", [{ relayPeerId: relay.peerId, relayAddrs: [relay.addr] }]);
      await manager.ensureStandingReceiverForAgent("alice");
      await waitUntil(() => {
        const i = manager.getStandingReceiverInfo("alice");
        return i !== null && i.addrs.some((a) => a.includes("/p2p-circuit"));
      }, 10_000);

      await manager.removeStandingReceiverForAgent("alice"); // agent goes dark
      await relay.node.stop();                                // and the relay dies

      await wait(1_500); // several ticks
      expect(manager.getStandingReceiverInfo("alice")).toBeNull();
    } finally {
      await manager.gracefulShutdown();
      try { await relay.node.stop(); } catch { /* already stopped */ }
    }
  }, 30_000);
});
