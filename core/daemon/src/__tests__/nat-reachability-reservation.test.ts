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
 *  R3 — a receiver that asks (listenOnCircuit) reserves with the relay, and the
 *       circuit addr appears in listenAddresses(). 056-SLOTDEAD moved the ask out
 *       of node construction; the property being pinned is unchanged.
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

/**
 * ⚠️ **THIS USED TO BE "the factory forwards circuit-relay listen addresses" — 056-SLOTDEAD.**
 * The property is the same and it is the one that matters: a standing receiver ends up announcing a
 * real circuit through a real relay. Only the MECHANISM moved. A node was once BUILT carrying the
 * relay's address (`circuitRelayListenAddrs`), so the reservation was a side effect of `start()`;
 * it now starts on TCP and asks afterwards, through `listenOnCircuit`, so that the ask can happen
 * when a session needs it rather than at login. Deleting the test with the field would have deleted
 * the only live proof that a reservation is obtainable at all.
 */
describe("R3: a standing receiver takes a circuit reservation on demand", () => {
  it("listenOnCircuit reserves with the relay and the node announces the circuit", async () => {
    const relay = await startHopRelay();
    process.env["CELLO_LISTEN_ADDR"] = "/ip4/127.0.0.1/tcp/0";
    try {
      const factory = new ProductionSessionNodeFactory();
      const node = await factory.createNode({
        sessionId: "sr-circuit",
        nodeType: "standing_receiver",
      });
      await node.start();
      await node.listenOnCircuit(`${relay.addr}/p2p-circuit`);
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
      /**
       * ⚠️ **THE TITLE'S "AT LOGIN" IS GONE — 055-ONDEMAND — AND THE REST OF IT IS NOT.**
       *
       * A persisted relay endpoint no longer BECOMES a reservation when the agent comes up: an idle
       * agent holds zero, which is the whole capacity change. What survives, and is what this test
       * was really protecting, is that a persisted endpoint is what the agent reserves ON when it
       * needs to, and that a healthy relay produces a real circuit address rather than a node that
       * merely looks started.
       */
      expect(
        manager.getStandingReceiverInfo("alice")?.addrs.some((a) => a.includes("/p2p-circuit")),
        "an idle agent holds NO circuit — the login walk is gone",
      ).toBe(false);

      await manager.takeReservationForSession("alice", `${relay.addr}/p2p-circuit`, "test-corr");

      const ok = await waitUntil(() => {
        const info = manager.getStandingReceiverInfo("alice");
        return info !== null && info.addrs.some((a) => a.includes("/p2p-circuit"));
      }, 10_000);
      expect(ok, "and the ask on that endpoint yields a real, announced circuit address").toBe(true);
      expect(
        manager.getStandingReceiverRelayIds("alice"),
        "recorded as ONE relay, deduped — the number the watchdog and cello_status read",
      ).toEqual([relay.peerId]);
      // The healthy path must never fire the degradation warn — pins the timing against future
      // libp2p upgrades.
      expect(events.some((e) => e.event === "session.standing_receiver.reservation.none")).toBe(false);
    } finally {
      await manager.gracefulShutdown();
      await relay.node.stop();
    }
  }, 20_000);

  it("R5: a dead relay degrades LOUDLY at the moment it costs something, and never kills the receiver", async () => {
    /**
     * ⚠️ **REWRITTEN FOR 055-ONDEMAND, AND THE "LOUDLY" MOVED RATHER THAN GOING AWAY.**
     *
     * This used to assert `reservation.none` at WARN when the login walk failed. Nothing is asked at
     * login now, so that warn was removed: firing it on every healthy login would make an alarm that
     * means "nobody can dial this agent" wrong every single time.
     *
     * The loudness belongs where the failure costs someone something — the ask itself. That is what
     * is asserted here: a dead relay makes the ask fail, says so with a named reason on the surface
     * `cello_status` reads, and leaves the receiver up on its TCP floor.
     */
    const { manager, events } = await makeManager();
    try {
      await seedRelayEndpoint(manager, "alice", DEAD_RELAY_PEER_ID, "/ip4/127.0.0.1/tcp/59987");
      await manager.ensureStandingReceiverForAgent("alice");

      const took = await manager.takeReservationForSession(
        "alice", `/ip4/127.0.0.1/tcp/59987/p2p/${DEAD_RELAY_PEER_ID}/p2p-circuit`, "test-corr",
      );

      expect(took, "a dead relay grants nothing, and the caller is told so rather than left to guess").toBe(false);
      const info = manager.getStandingReceiverInfo("alice");
      expect(info, "the receiver is still up — a bad relay must never cost the agent its front door").not.toBeNull();
      expect(info!.addrs.length).toBeGreaterThan(0);
      expect(info!.addrs.every((a) => !a.includes("/p2p-circuit"))).toBe(true);
      const rejected = events.find((e) => e.event === "session.standing_receiver.relay.rejected");
      expect(rejected, "the refusal is reported, with a cause").toBeDefined();
      expect(rejected!.level).toBe("warn");
      expect(
        rejected!.context.reason,
        "and it names the RELAY being unreachable, not a generic failure — the operator has to know " +
          "which of the three (capacity, network, latency) they are looking at",
      ).toBe("relay_unreachable");
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
      /**
       * ⚠️ **THE COUNTING HALF OF THIS TEST IS GONE WITH THE LOGIN WALK (055-ONDEMAND); THE
       * SECURITY HALF BELOW IS WHY THE TEST SURVIVES, AND IT MATTERS MORE NOW.**
       *
       * It used to assert `relaysOffered: 2, reservationsHeld: 1` from the walk's reachability
       * event. Nothing is offered or held at login any more. What is unchanged — and is now the
       * whole point — is that being NAMED buys no foothold: under on-demand the directory names the
       * relay, so "named by the directory" and "granted us a slot" are further apart than ever.
       *
       * One relay grants, one is dead. Both were asked; only one is admitted inbound.
       */
      expect(
        await manager.takeReservationForSession("alice", `${relay.addr}/p2p-circuit`, "test-corr"),
        "the healthy relay grants",
      ).toBe(true);
      expect(
        await manager.takeReservationForSession(
          "alice", `/ip4/127.0.0.1/tcp/59987/p2p/${DEAD_RELAY_PEER_ID}/p2p-circuit`, "test-corr",
        ),
        "the dead one does not",
      ).toBe(false);
      expect(
        manager.getStandingReceiverRelayIds("alice"),
        "and only the one that granted is recorded as held",
      ).toEqual([relay.peerId]);
      void events;

      /**
       * ⚠️ THE WIRING, WHICH IS THE SECURITY-SENSITIVE HALF AND WAS THE HOLLOW ONE.
       *
       * Two tests in `dod-m15-assign-1-receiver-gate.test.ts` prove the gater's SET SEMANTICS by
       * handing a gater a list directly — and nothing was going to get those wrong. They say
       * nothing about the one line that matters, which is what the MANAGER hands it. Swap that
       * argument for `reservations.relayPeerIds` — the DIRECTORY-supplied candidate list — and every
       * one of those tests still passes while the receiver ships the exact hole the bound exists to
       * close: a compromised directory names a relay, never grants a reservation, and dials in
       * behind the gate.
       *
       * This fixture is the one that can tell them apart, because one relay granted and the other
       * only ever appeared in the candidate list.
       */
      expect(
        manager.isRelayCarvedOutInbound("alice", relay.peerId),
        "the relay that GRANTED is admitted inbound — it answers the AutoNAT probes we start",
      ).toBe(true);
      expect(
        manager.isRelayCarvedOutInbound("alice", DEAD_RELAY_PEER_ID),
        "the relay that was OFFERED and never granted is refused inbound: being named by the " +
          "directory must not buy a foothold, which is precisely what handing the gater the " +
          "candidate list instead of the held list would do",
      ).toBe(false);
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

  /**
   * ⚠️ **R7, R8 AND R8b ARE REPLACED BY THIS ONE — 055-ONDEMAND, and the reason is that their
   * SUBJECT was deleted, not that they were wrong.**
   *
   * All three were about the same machinery: directory relay endpoints ARRIVING caused the receiver
   * to be rebuilt so it could reserve with them. R7 asserted a fresh agent reserved once endpoints
   * were known; R8 that endpoints arriving late triggered the rebuild; R8b that endpoints arriving
   * when one was already held did NOT. That rebuild-to-reserve path exists only because reservations
   * were acquired at login, and nothing is acquired at login now.
   *
   * What survives is worth keeping, and both halves are here:
   *   - endpoints are USABLE whenever they arrive — before the receiver exists or after it — which
   *     is what R7 and R8 were really protecting; and
   *   - their arrival does NOT churn the receiver, which is R8b's property and matters more now,
   *     because a rebuild would discard reservations a LIVE SESSION is depending on.
   */
  it("★★★ directory endpoints are usable whenever they arrive, and their arrival never churns the receiver", async () => {
    const relay = await startHopRelay();
    const { manager, events } = await makeManager();
    try {
      await seedAgents(manager.getDb(), ["alice"]); // agent exists; NO sessions rows
      await manager.ensureStandingReceiverForAgent("alice"); // endpoints not known yet
      const before = manager.getStandingReceiverInfo("alice");
      expect(before, "the receiver comes up regardless — a relay it has not heard of is not a blocker").not.toBeNull();
      expect(
        before!.addrs.every((a) => !a.includes("/p2p-circuit")),
        "and it holds nothing: an idle agent occupies no relay slot, which is the whole unit",
      ).toBe(true);

      // The endpoints arrive LATE, the case R8 was written for.
      manager.setDirectoryRelayEndpoints("alice", [{ relayPeerId: relay.peerId, relayAddrs: [relay.addr] }]);
      await wait(300);

      expect(
        manager.getStandingReceiverInfo("alice")!.peerId,
        "⚠️ NO CHURN. Endpoints arriving must not rebuild the receiver — under on-demand a rebuild " +
          "would throw away circuits a LIVE session is depending on, and its counterparty would " +
          "silently lose the route it was given.",
      ).toBe(before!.peerId);
      expect(events.some((e) => e.event === "session.standing_receiver.reservation.rebuild")).toBe(false);

      // And they are usable the moment an offer needs them — whenever they turned up.
      expect(
        await manager.takeReservationForSession("alice", `${relay.addr}/p2p-circuit`, "test-corr"),
        "a late-arriving endpoint is a usable endpoint",
      ).toBe(true);
      expect(manager.getStandingReceiverRelayIds("alice")).toEqual([relay.peerId]);
    } finally {
      await manager.gracefulShutdown();
      await relay.node.stop();
    }
  }, 30_000);
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

  /**
   * A factory whose RESERVATION never completes — the live failure.
   *
   * ⚠️ DOD-M15-RELAYPROVE-ORDER-1 MOVED WHERE A RESERVATION IS ASKED FOR, so this fixture hangs in
   * two places rather than one. It used to hang only `start()`, because a circuit address in the
   * constructor made start() the moment libp2p asked. The walk now builds probes with NO circuit
   * address and asks afterwards through `listenOnCircuit` — so hanging start() alone models a
   * reservation that completes instantly, and the deadline this test is about is never reached.
   *
   * Both are kept: `listenOnCircuit` is the probe's ask, and `start()` is still the installed
   * receiver's, since it is built from the addresses the walk collected.
   */
  class HangingCircuitFactory extends ProductionSessionNodeFactory {
    override async createNode(config: Parameters<ProductionSessionNodeFactory["createNode"]>[0]) {
      const node = await super.createNode({ ...config, circuitRelayListenAddrs: undefined });
      /**
       * ⚠️ ASSIGNED, NOT SPREAD. `{...node, start}` copies own enumerable properties only, and
       * `CelloNode`'s methods live on the PROTOTYPE — so the spread returned an object with no
       * `listenAddresses`, no `stop`, no `getConnections`. That was invisible while `start()` hung
       * forever, because nothing else was ever called on it. The probe below DOES get called, and
       * the spread turned "the reservation hangs" into "every method is missing".
       */
      const hang = (): Promise<void> => new Promise<void>(() => {});
      if (config.circuitRelayListenAddrs && config.circuitRelayListenAddrs.length > 0) {
        // Mimic libp2p: start() parks forever waiting on a relay that never answers.
        (node as unknown as { start: () => Promise<void> }).start = hang;
        return node;
      }
      // The probe. It starts fine — it is only TCP — and parks on the ask.
      (node as unknown as { listenOnCircuit: () => Promise<void> }).listenOnCircuit = hang;
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
      // 055-ONDEMAND: nothing is asked at login. The ask this test is about happens when an offer
      // arrives, on the relay the directory named — the same seam the offer handler uses.
      await manager.takeReservationForSession("alice", `/ip4/127.0.0.1/tcp/59986/p2p/${DEAD_RELAY_PEER_ID}/p2p-circuit`, "test-corr");

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
      // 055-ONDEMAND: nothing is asked at login. The ask this test is about happens when an offer
      // arrives, on the relay the directory named — the same seam the offer handler uses.
      await manager.takeReservationForSession("alice", `${relay.addr}/p2p-circuit`, "test-corr");

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
      // 055-ONDEMAND: nothing is asked at login. The ask this test is about happens when an offer
      // arrives, on the relay the directory named — the same seam the offer handler uses.
      await manager.takeReservationForSession("alice", `/ip4/127.0.0.1/tcp/59986/p2p/${DEAD_RELAY_PEER_ID}/p2p-circuit`, "test-corr");
      await manager.takeReservationForSession("alice", `${relay.addr}/p2p-circuit`, "test-corr");

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

  function makeManager(dbName: string, opts: { respreadEveryMs?: number } = {}) {
    const { logger, events } = makeLogger();
    const manager = new SessionNodeManager({
      securityGateway: new PassthroughGatewayClient(),
      factory: new ProductionSessionNodeFactory(),
      logger,
      dbPath: join(tempDir, dbName),
      standingReceiverWatchdogIntervalMs: 250,
      // The re-spread rides this clock deliberately — a reservation is scarce, so a decayed agent
      // re-asks on the reservation retry interval and not on the watchdog's grid. Five minutes in
      // production; a test that waited that out would just be a test nobody runs.
      ...(opts.respreadEveryMs !== undefined ? { standingReceiverReservationRetryMs: opts.respreadEveryMs } : {}),
    });
    return { manager, events };
  }

  /**
   * ⚠️ **W1, W1b AND W1c ARE REPLACED — 055-ONDEMAND DELETED THEIR SUBJECT, WHICH WAS THE SPREAD.**
   *
   * ⚠️ **FIVE went, not three — review MEDIUM-7.** W2 and W3 also went; W3 is restored above,
   * because its subject (`agentsWantingReceiver`) is still live and was left uncovered. W2 is
   * subsumed by the idle test below.
   *
   * All three were about a receiver MAINTAINING a set of login-time reservations: two relays grant
   * and one dies (do not rebuild), the last one dies (do rebuild), and an idle agent holding fewer
   * than it was offered takes the rest ("no ratchet"). Every one of those describes an agent that
   * holds slots while nobody is calling it, which is exactly what this unit removes: demand was
   * `agents × relays` because of that behaviour.
   *
   * The property that replaces them is the INVERSE, and it is the one that protects the fleet: the
   * watchdog must leave an idle agent alone. Getting this wrong would not look like a broken agent —
   * it would look like every idle agent in the fleet quietly asking relays for slots the design says
   * they must not hold, which is the same exhaustion the old spread caused, wearing a new name.
   *
   * A live session that LOSES its circuit still gets it back; that path has its own coverage in
   * `msg-018-reservation-retry.test.ts`, where the budget and backoff are asserted with it.
   */
  it("★★★ W3: the watchdog never resurrects a receiver for an agent that went offline", async () => {
    /**
     * ⚠️ **RESTORED — review MEDIUM-7.** Five tests were deleted from this block and the replacement
     * comment accounted for three. W2 is fairly subsumed by the idle test below; **W3 is not.** It
     * guards `if (!this.#ctx.agentsWantingReceiver.has(agentName)) continue;`, which is still there
     * and now had no coverage.
     *
     * The property is untouched by 055-ONDEMAND and matters as much as ever: an agent the operator
     * took offline must STAY offline. Resurrecting a receiver for it would put an agent back on the
     * network after they asked for it to go dark — the one direction a kill switch must never fail.
     */
    const relay = await startHopRelay();
    const { manager } = makeManager("w3.db");
    await manager.initialize();
    try {
      await seedAgents(manager.getDb(), ["alice"]);
      manager.setDirectoryRelayEndpoints("alice", [{ relayPeerId: relay.peerId, relayAddrs: [relay.addr] }]);
      await manager.ensureStandingReceiverForAgent("alice");
      // 055-ONDEMAND: an idle agent holds nothing, so take one — the state this test is about is an
      // agent that was REACHABLE and then went dark, not one that never was.
      await manager.takeReservationForSession("alice", `${relay.addr}/p2p-circuit`, "test-corr");
      await waitUntil(() => {
        const i = manager.getStandingReceiverInfo("alice");
        return i !== null && i.addrs.some((a) => a.includes("/p2p-circuit"));
      }, 10_000);

      await manager.removeStandingReceiverForAgent("alice"); // agent goes dark
      await relay.node.stop();                                // and the relay dies

      await wait(1_500); // several ticks
      expect(
        manager.getStandingReceiverInfo("alice"),
        "an agent the operator took offline must stay offline — a resurrected receiver puts them " +
          "back on the network after they asked to go dark",
      ).toBeNull();
    } finally {
      await manager.gracefulShutdown();
      try { await relay.node.stop(); } catch { /* already stopped */ }
    }
  }, 30_000);

  it("★★★ the watchdog leaves an IDLE agent alone — no asks for slots it must not hold", async () => {
    const relay = await startHopRelay();
    const { manager, events } = makeManager("sessions-idle-untouched.db", { respreadEveryMs: 100 });
    try {
      await manager.initialize();
      await seedAgents(manager.getDb(), ["alice"]);
      manager.setDirectoryRelayEndpoints("alice", [{ relayPeerId: relay.peerId, relayAddrs: [relay.addr] }]);
      await manager.ensureStandingReceiverForAgent("alice");
      const peerBefore = manager.getStandingReceiverInfo("alice")?.peerId;
      expect(peerBefore, "precondition: a receiver exists").toBeTruthy();

      // Several watchdog ticks with a relay available and NO session wanting it.
      await wait(1_500);

      expect(
        manager.getStandingReceiverRelayIds("alice"),
        "an idle agent holds nothing, and the watchdog does not go and get some",
      ).toEqual([]);
      expect(
        manager.getStandingReceiverInfo("alice")?.peerId,
        "and it is not churned — a rebuild would cost the agent its identity for no gain",
      ).toBe(peerBefore);
      expect(
        events.filter((e) => e.event === "session.standing_receiver.reservation.retry"),
        "no retry ladder for an agent that wants nothing",
      ).toEqual([]);
      expect(
        events.filter((e) => e.event === "session.standing_receiver.reservation.rebuild"),
        "and no rebuild",
      ).toEqual([]);
    } finally {
      await manager.gracefulShutdown();
      await relay.node.stop();
    }
  }, 30_000);
});
