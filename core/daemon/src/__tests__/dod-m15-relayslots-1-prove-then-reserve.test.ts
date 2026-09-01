/**
 * DOD-M15-RELAYSLOTS-1 (client half) — **ASK, BE REFUSED, PROVE, ASK AGAIN.**
 *
 * The relay now refuses a circuit reservation from any peer that has not shown, over CELLO's own
 * auth stream, that it belongs to a registered agent. That gate is the whole of this order — three
 * earlier designs tried to guess from a peer id alone which caller looked like an attacker, and a
 * botnet walks through guesses.
 *
 * The cost lands here. A reservation taken on the SAME connection as the proof yields a slot with
 * no dialable address (libp2p announces circuit addresses only for reservations its own discovery
 * made), so a receiver has to build, be refused, prove itself, drop the connection, and rebuild on
 * the same transport identity. `#startReceiverNode` and `#buildRevivedNode` both run that loop.
 *
 * ─── Why this file exists ─────────────────────────────────────────────────────────────────────
 *
 * The review's blunt finding: delete the whole two-attempt loop, restoring the previous code
 * exactly, and NOTHING went red. The central mechanism of the client half had no test at all, and
 * the paths that tell a person why their agent is unreachable were never exercised. Every test here
 * is written so that removing the thing it names reddens it.
 *
 * The scripted relay below models the gate itself: it grants only to a peer id that has proved.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { SessionNodeManager, type ISessionNodeFactory, type SessionNodeConfig } from "../session-node-manager.js";
import { FakeNode } from "./helpers/two-connection-fixture.js";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { seedAgents } from "./helpers/seed-agents.js";
import type { AgentRelayClient, RelayAuthRefusal } from "../session-relay-client.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Logger } from "../types.js";

const COUNTERPARTY_PEER = "12D3KooWFakeCounterpartyPeerIdForTestingOnly000000000000";
const RELAY_A = "12D3KooWRelayAAAA0000000000000000000000000000";
const RELAY_B = "12D3KooWRelayBBBB0000000000000000000000000000";
const CIRCUIT_A = `/ip4/10.0.0.1/tcp/4001/p2p/${RELAY_A}/p2p-circuit`;
const CIRCUIT_B = `/ip4/10.0.0.2/tcp/4001/p2p/${RELAY_B}/p2p-circuit`;

/**
 * The relay's gate, in the small: a peer id gets a circuit address only once it has proved itself.
 *
 * Shared by the node factory (which decides what `listenAddresses()` reports) and the relay-client
 * stub (which records the proof), because in production they are the same relay.
 */
class ScriptedRelay {
  readonly proven = new Set<string>();
  /** Refusal to answer the NEXT proof with, per relay peer id. Absent means the proof succeeds. */
  readonly refusals = new Map<string, RelayAuthRefusal>();
  readonly proofAttempts: Array<{ relayPeerId: string; peerId: string }> = [];
  grants(peerId: string): boolean { return this.proven.has(peerId); }
}

class GatedNode extends FakeNode {
  started = false;
  stopped = false;
  readonly #id: string;
  constructor(
    seed: Uint8Array | undefined,
    private readonly relay: ScriptedRelay,
    private readonly circuit: string | undefined,
  ) {
    super();
    this.#id = seed ? `12D3KooW${createHash("sha256").update(seed).digest("hex").slice(0, 40)}` : "random";
  }
  override getPeerId(): string { return this.#id; }
  override async start(): Promise<void> { this.started = true; }
  override async stop(): Promise<void> { if (this.started) this.stopped = true; }
  override listenAddresses(): string[] {
    // THE GATE. A circuit address appears only for a peer id the relay has a proof for — which is
    // exactly what the relay's `denyInboundRelayReservation` decides, and why the first ask fails.
    return this.started && this.circuit !== undefined && this.relay.grants(this.#id)
      ? [this.circuit, "/ip4/127.0.0.1/tcp/1"]
      : ["/ip4/127.0.0.1/tcp/1"];
  }
}

class GatedFactory implements ISessionNodeFactory {
  readonly asks: Array<{ circuits: string[]; nodeType: string | undefined; peerId: string }> = [];
  readonly built: GatedNode[] = [];
  constructor(private readonly relay: ScriptedRelay) {}
  async createNode(config: SessionNodeConfig): Promise<CelloNode> {
    const circuit = config.circuitRelayListenAddrs?.[0];
    const node = new GatedNode(config.transportPrivateKey, this.relay, circuit);
    this.asks.push({ circuits: config.circuitRelayListenAddrs ?? [], nodeType: config.nodeType, peerId: node.getPeerId() });
    this.built.push(node);
    return node as unknown as CelloNode;
  }
}

/** The relay-auth half: records the proof the way the real relay does, or refuses with a cause. */
function relayClientStub(relay: ScriptedRelay, relayPeerId: string): AgentRelayClient {
  let lastRefusal: RelayAuthRefusal | null = null;
  return {
    async proveReservation(node: CelloNode): Promise<boolean> {
      relay.proofAttempts.push({ relayPeerId, peerId: node.getPeerId() });
      const refusal = relay.refusals.get(relayPeerId);
      if (refusal) { lastRefusal = refusal; return false; }
      relay.proven.add(node.getPeerId());
      lastRefusal = null;
      return true;
    },
    getLastAuthRefusal(): RelayAuthRefusal | null { return lastRefusal; },
    close(): void { /* nothing held */ },
  } as unknown as AgentRelayClient;
}

const silent: Logger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };
let tempDir: string;
let mgr: SessionNodeManager | undefined;

async function makeManager(relay: ScriptedRelay, factory: GatedFactory): Promise<SessionNodeManager> {
  const m = new SessionNodeManager({
    securityGateway: new PassthroughGatewayClient(),
    factory,
    logger: silent,
    dbPath: join(tempDir, "sessions.db"),
  });
  await m.initialize();
  await seedAgents(m.getDb(), ["alice"]);
  m.setDirectoryRelayEndpoints("alice", [
    { relayPeerId: RELAY_A, relayAddrs: [`/ip4/10.0.0.1/tcp/4001/p2p/${RELAY_A}`] },
    { relayPeerId: RELAY_B, relayAddrs: [`/ip4/10.0.0.2/tcp/4001/p2p/${RELAY_B}`] },
  ]);
  m.setDetachedRelayClientBuilder((_agent, relayPeerId) => relayClientStub(relay, relayPeerId));
  return m;
}

beforeEach(async () => { tempDir = await mkdtemp(join(tmpdir(), "cello-slots-prove-")); });
afterEach(async () => {
  await mgr?.gracefulShutdown();
  mgr = undefined;
  await rm(tempDir, { recursive: true, force: true });
});

describe("DOD-M15-RELAYSLOTS-1: the receiver proves itself and gets its slot", () => {
  it("★★★ refused on the first ask, granted on the second — SAME transport identity", async () => {
    const relay = new ScriptedRelay();
    const factory = new GatedFactory(relay);
    mgr = await makeManager(relay, factory);

    await mgr.ensureStandingReceiverForAgent("alice");
    const node = mgr.getStandingReceiverNode("alice");

    expect(
      node?.listenAddresses().some((a) => a.includes("/p2p-circuit")),
      "delete the two-attempt loop and this is false: the relay refuses every unproven peer, so " +
        "the receiver comes up with no circuit address and the agent is reachable by nobody.",
    ).toBe(true);

    const asks = factory.asks.filter((a) => a.circuits.length > 0);
    expect(asks.length, "exactly two asks: refused, then granted").toBe(2);
    expect(
      asks.map((a) => a.circuits[0]),
      "both asks go to the SAME relay — the second is a retry, not a walk to the next candidate",
    ).toEqual([CIRCUIT_A, CIRCUIT_A]);
    expect(
      asks[0]?.peerId,
      "⚠️ THE SAME PEER ID BOTH TIMES. The relay remembers the proof against a transport identity, " +
        "so a retry on a fresh identity would be refused exactly like the first ask — the seed is " +
        "reused for precisely this reason.",
    ).toBe(asks[1]?.peerId);
    expect(relay.proofAttempts).toHaveLength(1);
    expect(relay.proofAttempts[0]?.peerId).toBe(asks[0]?.peerId);
  }, 30_000);

  it("★★★ a refusal about THIS AGENT reaches cello_status, and stops the fleet walk", async () => {
    const relay = new ScriptedRelay();
    // `slot_cap_exceeded` is per AGENT, so every relay in the pool answers identically.
    const refusal: RelayAuthRefusal = {
      reason: "slot_cap_exceeded",
      advice: "close some sessions — this agent holds 32 of 32 relay slots",
      tryAnotherRelay: false,
      slotsHeld: 32,
      slotCap: 32,
    };
    relay.refusals.set(RELAY_A, refusal);
    relay.refusals.set(RELAY_B, refusal);
    const factory = new GatedFactory(relay);
    mgr = await makeManager(relay, factory);

    await mgr.ensureStandingReceiverForAgent("alice");

    const surfaced = mgr.getStandingReceiverRefusal("alice");
    expect(
      surfaced?.reason,
      "the relay computed the cause, the count and the next step and put them on the wire. Dropped " +
        "here, cello_status shows an agent that is online and reachable by nobody, with no cause " +
        "anywhere a person will look.",
    ).toBe("slot_cap_exceeded");
    expect(surfaced?.slotsHeld).toBe(32);
    expect(surfaced?.slotCap).toBe(32);
    expect(surfaced?.relayPeerId).toBe(RELAY_A);

    expect(
      relay.proofAttempts.map((p) => p.relayPeerId),
      "and it must STOP. This refusal is about the agent, not the relay, so walking the pool costs " +
        "a node build and two dials per relay to reach the same answer — and makes one client-side " +
        "fault read as a fleet-wide outage.",
    ).toEqual([RELAY_A]);
  }, 30_000);

  it("★★★ a refusal about THIS RELAY quarantines it and moves to the next", async () => {
    const relay = new ScriptedRelay();
    // A relay with no directory key configured is broken; another one will work right now.
    relay.refusals.set(RELAY_A, {
      reason: "online_token_no_directory_key",
      advice: "this relay has no directory key configured and cannot verify anyone — try another",
      tryAnotherRelay: true,
    });
    const factory = new GatedFactory(relay);
    mgr = await makeManager(relay, factory);

    await mgr.ensureStandingReceiverForAgent("alice");

    expect(
      relay.proofAttempts.map((p) => p.relayPeerId),
      "a relay-side fault is the one case where the next relay genuinely helps — and A is asked " +
        "ONCE, because the retry exists only to use a proof that landed, and this one did not",
    ).toEqual([RELAY_A, RELAY_B]);
    expect(
      factory.asks.filter((a) => a.circuits[0] === CIRCUIT_A).length,
      "one node build for A, not two: retrying a relay that refused the proof spends a build and a " +
        "dial to be refused identically",
    ).toBe(1);
    expect(
      mgr.isRelayQuarantined("alice", RELAY_A),
      "and it must not be asked first again on the next rebuild — otherwise a misconfigured relay " +
        "is retried forever for the life of the process.",
    ).toBe(true);
    expect(mgr.getStandingReceiverNode("alice")?.listenAddresses().some((a) => a.includes("/p2p-circuit"))).toBe(true);
    expect(factory.asks.filter((a) => a.circuits[0] === CIRCUIT_B && a.nodeType === "standing_receiver").length)
      .toBeGreaterThan(0);
  }, 30_000);

  it("★★★ a REVIVED session proves itself too, or it comes back dialable by nobody", async () => {
    const relay = new ScriptedRelay();
    const factory = new GatedFactory(relay);
    mgr = await makeManager(relay, factory);

    const sid = "93".repeat(32);
    await mgr.ensureStandingReceiverForAgent("alice");
    const opened = await mgr.createSessionNode(sid, "alice", "bb".repeat(32), COUNTERPARTY_PEER, "corr", true);
    expect(opened.ok, JSON.stringify(opened)).toBe(true);
    await mgr.destroySessionNode("alice", sid, "interrupted");

    /**
     * ⚠️ THE PROOF HAS AGED OUT. The relay remembers a proof for two minutes; a revival happens
     * whenever the person comes back, which is essentially never inside that window. Clearing it is
     * what makes this test model a real revival rather than one that happens to run seconds after
     * the receiver proved.
     */
    relay.proven.clear();
    const proofsBefore = relay.proofAttempts.length;

    const revived = await mgr.reviveSessionNode("alice", sid);
    expect(revived.ok, JSON.stringify(revived)).toBe(true);

    expect(
      relay.proofAttempts.length,
      "without a prove step the revival is refused by every candidate and lands on the plain floor: " +
        "the session is alive and active and the counterparty cannot dial it, so every message in " +
        "both directions is forced through the relay park route.",
    ).toBeGreaterThan(proofsBefore);

    const revivedAsks = factory.asks.filter((a) => a.nodeType === "session" && a.circuits.length > 0);
    const granted = factory.built.filter(
      (n) => n.listenAddresses().some((a) => a.includes("/p2p-circuit")),
    );
    expect(revivedAsks.length, "one refused ask, one granted, on one relay").toBe(2);
    expect(granted.length, "the revived session ends up holding a real circuit address").toBeGreaterThan(0);
  }, 30_000);
});
