/**
 * DOD-M15-RELAYSLOTS-1 (client half) — **PROVE FIRST, THEN ASK ONCE.**
 *
 * The relay refuses a circuit reservation from any peer that has not shown, over CELLO's own auth
 * stream, that it belongs to a registered agent. That gate is the whole of the original order —
 * three earlier designs tried to guess from a peer id alone which caller looked like an attacker,
 * and a botnet walks through guesses.
 *
 * ─── ⚠️ THIS FILE'S ORIGINAL PREMISE WAS FALSIFIED — kept, corrected, not deleted ──────────────
 *
 * It read: *"A reservation taken on the SAME connection as the proof yields a slot with no dialable
 * address (libp2p announces circuit addresses only for reservations its own discovery made), so a
 * receiver has to build, be refused, prove itself, drop the connection, and rebuild on the same
 * transport identity."* Every test below was written to that shape.
 *
 * **The second clause is false, and it was measured** (spike 2, 2026-09-08, live against the
 * Virginia relay on libp2p 3.3.11 / circuit-relay-v2 4.2.13; script kept in the M15 tools
 * directory). Asking libp2p's OWN transport manager to listen on the circuit after the proof makes
 * the reservation libp2p's own — so it announces the address exactly as it does for one its
 * discovery made. What the original claim actually described was taking the slot by hand, over a
 * raw HOP stream, which is a different act.
 *
 * The correction it is kept for: **libp2p opened no new connection** for that reservation. Its
 * store calls `openConnection(peerId)` without `force`, which returns the already-open connection —
 * the one the proof was made on — and the relay sets `slot.provenForReservation` per CONNECTION at
 * auth time. So the first ask succeeds, and `DOD-M15-RELAYPROVE-ORDER-1` removes the ask-refuse-
 * rebuild dance rather than surviving it. `#startReceiverNode` and `#buildRevivedNode` both changed.
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
  /**
   * Every `proveReservation`, tagged with whether the proving node already held a circuit address.
   *
   * ⚠️ TWO DIFFERENT PROOFS REACH THIS, and conflating them made two assertions here wrong before
   * the distinction existed. `#proveToRelay` proves a node that has just been REFUSED, so it holds
   * no circuit address — that is the gate proof, and the subject of this file. Once a receiver
   * holds a reservation, `#authenticateStandingReceiver` proves again over the delivery path, which
   * is pre-existing behaviour and correct. Only the first kind is counted below.
   */
  readonly proofAttempts: Array<{ relayPeerId: string; peerId: string; hadCircuit: boolean; nodeType: string | undefined }> = [];
  /** The proofs made to GET a reservation, in order. */
  gateProofs(): Array<{ relayPeerId: string; peerId: string; nodeType: string | undefined }> {
    return this.proofAttempts.filter((a) => !a.hadCircuit);
  }
  grants(peerId: string): boolean { return this.proven.has(peerId); }
  /** When set, every node's reservation ask throws a CLIENT-side fault (see `GatedNode`). */
  askThrows = false;
  /** When set, every proof fails on TRANSPORT — false with no refusal, i.e. no verdict was reached. */
  proofTransportFails = false;
  /** How many circuit addresses each relay announces. Real relays announce several; see `GatedNode`. */
  addressesPerRelay = 1;

  /**
   * DOD-M15-RELAYPROVE-ORDER-1 — **an ORDERED log, because the defect is an ORDER.**
   *
   * Counting proofs and counting reservations cannot express "the proof came first, on this node,
   * and nothing tore it down in between" — and that sentence is the whole property. Each entry
   * carries the NODE OBJECT, not its peer id: a receiver reuses one seed across every relay, so
   * peer id cannot tell "the node that proved" from "a different node built on the same identity",
   * which is exactly the rebuild this order removes.
   */
  readonly timeline: Array<{ kind: "prove" | "listen" | "stop"; node: object; relayPeerId?: string; hadCircuit?: boolean }> = [];
  /**
   * The proofs made to GET a reservation, in timeline order.
   *
   * ⚠️ FILTERED THE SAME WAY `gateProofs()` IS, and for the same reason: once a receiver holds a
   * reservation, `#authenticateStandingReceiver` proves AGAIN over the delivery path. That is
   * pre-existing, correct, and not this order's subject — counting it here made "one proof per
   * relay" read as three on a two-relay pool.
   */
  gateProofTimeline(): Array<{ kind: string; node: object; relayPeerId?: string }> {
    return this.timeline.filter((e) => e.kind === "prove" && e.hadCircuit === false);
  }
  /** Index into `timeline` of the first entry matching, or -1. */
  firstIndex(kind: "prove" | "listen" | "stop", node: object): number {
    return this.timeline.findIndex((e) => e.kind === kind && e.node === node);
  }
}

class GatedNode extends FakeNode {
  started = false;
  stopped = false;
  readonly #id: string;
  constructor(
    seed: Uint8Array | undefined,
    private readonly relay: ScriptedRelay,
    private readonly circuit: string | undefined,
    /**
     * ⚠️ CARRIED SO A PROOF CAN BE ATTRIBUTED. A revived session reuses the receiver's transport
     * seed — that is what a handoff IS — so peer id cannot tell the two apart, and an assertion
     * that merely counts proofs is satisfied by the RECEIVER rebuilding. That is not a hypothetical:
     * deleting the revival's prove step left the count assertion green, because clearing the
     * relay's memory also strips the receiver's circuit address and its watchdog rebuilds.
     */
    readonly nodeType: string | undefined,
  ) {
    super();
    this.#id = seed ? `12D3KooW${createHash("sha256").update(seed).digest("hex").slice(0, 40)}` : "random";
  }
  override getPeerId(): string { return this.#id; }
  override async start(): Promise<void> { this.started = true; }
  override async stop(): Promise<void> {
    if (this.started) this.stopped = true;
    this.relay.timeline.push({ kind: "stop", node: this });
  }

  /**
   * Circuits this node took AFTER start, by asking. Separate from the constructor's `circuit`
   * because they are different acts: the constructor's is libp2p asking on its own at start (the
   * ordering that gets refused), this one is the caller asking once the proof has landed.
   */
  readonly takenCircuits: string[] = [];

  /**
   * DOD-M15-RELAYPROVE-ORDER-1 — the relay's gate, applied at the moment of the ask.
   *
   * Grants only if the relay holds a proof for this peer id, which is what
   * `denyInboundRelayReservation` decides. It does NOT throw when refused: a relay at its slot cap
   * completes the handshake and grants nothing, and the code under test must not read a resolved
   * `listen()` as a reservation — `listenAddresses()` is the only proof. A fixture that threw here
   * would let a caller pass by catching nothing.
   */
  override async listenOnCircuit(circuitAddr: string): Promise<void> {
    this.relay.timeline.push({ kind: "listen", node: this, relayPeerId: /\/p2p\/([^/]+)\/p2p-circuit/.exec(circuitAddr)?.[1] });
    /**
     * ⚠️ ONE RELAY ANNOUNCES SEVERAL ADDRESSES, and the fixture has to say so or it cannot see the
     * defect this models. libp2p builds one circuit address per LISTEN ADDRESS the relay holds, so
     * a two-relay pool routinely yields ten `/p2p-circuit` entries. Measured live 2026-09-10: the
     * receiver reported `relaysOffered: 2, reservationsHeld: 10`.
     */
    if (this.relay.addressesPerRelay > 1 && this.started && this.relay.grants(this.#id)) {
      for (let extra = 1; extra < this.relay.addressesPerRelay; extra++) {
        this.takenCircuits.push(circuitAddr.replace("/tcp/4001", `/tcp/${4001 + extra}`));
      }
    }
    /**
     * The CLIENT-SIDE fault: this node cannot take a reservation at all — libp2p renamed
     * `components.transportManager`, say. It throws SYNCHRONOUSLY, which is what the real
     * `listenOnCircuit` does and what the containment has to survive.
     */
    if (this.relay.askThrows) {
      throw { reason: "transport_manager_unavailable", message: "libp2p exposes no components.transportManager.listen" };
    }
    if (this.started && this.relay.grants(this.#id)) this.takenCircuits.push(circuitAddr);
  }

  override listenAddresses(): string[] {
    // THE GATE. A circuit address appears only for a peer id the relay has a proof for — which is
    // exactly what the relay's `denyInboundRelayReservation` decides.
    const atStart = this.started && this.circuit !== undefined && this.relay.grants(this.#id) ? [this.circuit] : [];
    return [...atStart, ...(this.started ? this.takenCircuits : []), "/ip4/127.0.0.1/tcp/1"];
  }
}

class GatedFactory implements ISessionNodeFactory {
  readonly asks: Array<{ circuits: string[]; nodeType: string | undefined; peerId: string }> = [];
  readonly built: GatedNode[] = [];
  constructor(private readonly relay: ScriptedRelay) {}
  async createNode(config: SessionNodeConfig): Promise<CelloNode> {
    const circuit = config.circuitRelayListenAddrs?.[0];
    const node = new GatedNode(config.transportPrivateKey, this.relay, circuit, config.nodeType);
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
      /**
       * ⚠️ THE DISCRIMINATOR CHANGED WITH 054-SRSPLIT, and the old one silently stopped working.
       *
       * It was *"did this node hold ANY circuit address?"* — true only of a delivery proof, back
       * when each relay got its own throwaway probe node. There is ONE node now, so after the first
       * relay grants it holds a circuit and every later GATE proof looked like a delivery proof and
       * was filtered out. The count then read 1 on a two-relay pool.
       *
       * The question that survives the change is per RELAY: had THIS relay already granted us a
       * circuit when we proved to it?
       */
      relay.timeline.push({
        kind: "prove",
        node,
        relayPeerId,
        hadCircuit: node.listenAddresses().some((a) => a.includes(`/p2p/${relayPeerId}/p2p-circuit`)),
      });
      relay.proofAttempts.push({
        relayPeerId,
        peerId: node.getPeerId(),
        hadCircuit: node.listenAddresses().some((a) => a.includes(`/p2p/${relayPeerId}/p2p-circuit`)),
        nodeType: (node as unknown as GatedNode).nodeType,
      });
      /**
       * ⚠️ THE NO-VERDICT SHAPE, and it is NOT the same as a refusal — review HIGH-1.
       *
       * `proveReservation` returns false with `getLastAuthRefusal()` NULL when the proof failed for
       * a TRANSPORT reason: a failed dial, a reset stream, a dead muxer. The relay said nothing.
       * `#proveReservationOnce` clears the refusal at its head precisely so this case leaves none
       * behind, and the production log calls it `no_relay_verdict`. This is the dominant real case,
       * and it used to be labelled `refused_try_another_relay` one layer up.
       */
      if (relay.proofTransportFails) { lastRefusal = null; return false; }
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

async function makeManager(
  relay: ScriptedRelay,
  factory: GatedFactory,
  /**
   * Non-breaking `opts`, per the fixture rule. `noRelayClient` models a daemon whose proof path is
   * unavailable — no builder wired — which is one of the ways `proveToRelay` reaches no verdict.
   * `logger` lets a case read the refusal reasons the walk emits.
   */
  opts: { noRelayClient?: boolean; logger?: Logger } = {},
): Promise<SessionNodeManager> {
  const m = new SessionNodeManager({
    securityGateway: new PassthroughGatewayClient(),
    factory,
    logger: opts.logger ?? silent,
    dbPath: join(tempDir, "sessions.db"),
  });
  await m.initialize();
  await seedAgents(m.getDb(), ["alice"]);
  m.setDirectoryRelayEndpoints("alice", [
    { relayPeerId: RELAY_A, relayAddrs: [`/ip4/10.0.0.1/tcp/4001/p2p/${RELAY_A}`] },
    { relayPeerId: RELAY_B, relayAddrs: [`/ip4/10.0.0.2/tcp/4001/p2p/${RELAY_B}`] },
  ]);
  // `undefined` is what a daemon with no relay client wired actually hands back, and it is the
  // production shape of "the proof could not even be attempted".
  m.setDetachedRelayClientBuilder((_agent, relayPeerId) =>
    opts.noRelayClient === true ? undefined : relayClientStub(relay, relayPeerId),
  );
  return m;
}

beforeEach(async () => { tempDir = await mkdtemp(join(tmpdir(), "cello-slots-prove-")); });
afterEach(async () => {
  await mgr?.gracefulShutdown();
  mgr = undefined;
  await rm(tempDir, { recursive: true, force: true });
});

describe("DOD-M15-RELAYSLOTS-1: the receiver proves itself and gets its slot", () => {
  it("★★★ granted on the FIRST ask, because the proof went first — DOD-M15-RELAYPROVE-ORDER-1", async () => {
    const relay = new ScriptedRelay();
    const factory = new GatedFactory(relay);
    mgr = await makeManager(relay, factory);

    await mgr.ensureStandingReceiverForAgent("alice");
    const node = mgr.getStandingReceiverNode("alice");

    expect(
      node?.listenAddresses().some((a) => a.includes("/p2p-circuit")),
      "the relay refuses every unproven peer, so a receiver that never proves comes up with no " +
        "circuit address and the agent is reachable by nobody.",
    ).toBe(true);

    /**
     * ⚠️ THE ASSERTION THAT CARRIES THIS ORDER, and it is about what was NOT done.
     *
     * A probe node built with a circuit address in its listen set is libp2p asking the relay before
     * anything has proved — the refusal that costs the connection the proof rides on. The walk must
     * now build probes with NO circuit listen address and ask afterwards, so the count of
     * constructor-time circuit asks during the walk is ZERO.
     *
     * Restore `circuitRelayListenAddrs: [circuitAddr]` on the probe and this fails immediately,
     * which is the revert test for the whole change.
     */
    /**
     * ⚠️ THIS COUNT WENT FROM ONE TO ZERO WITH 054-SRSPLIT, and the direction is the point.
     *
     * Unit 1 removed the constructor-time ask from the PROBES and left it on the installed
     * receiver, which then depended on the relay remembering a proof for two minutes. There are no
     * probes now and no rebuild: one node starts on TCP and takes each reservation in place, so
     * **nothing is ever built carrying a circuit address**. Restore either the probes or the
     * rebuild and this fails.
     */
    expect(
      factory.asks.filter((a) => a.circuits.length > 0).length,
      "no node is built asking for a reservation — the ask happens on a node that is already " +
        "running and has already proved itself",
    ).toBe(0);
    expect(
      factory.built.filter((n) => n.nodeType === "standing_receiver").length,
      "and ONE node serves the whole walk, where the old shape built one per relay plus a final",
    ).toBe(1);
    expect(
      mgr.getStandingReceiverNode("alice")?.listenAddresses().filter((a) => a.includes("/p2p-circuit")).sort(),
      "that one node ends up listening on EVERY granted circuit",
    ).toEqual([CIRCUIT_A, CIRCUIT_B]);

    // The walk still visits both relays (032-RELAYSPREAD) and still does it on ONE identity.
    expect(
      relay.gateProofs().map((p) => p.relayPeerId),
      "the walk must CONTINUE past the first grant — one reservation is one relay away from unreachable",
    ).toEqual([RELAY_A, RELAY_B]);
    expect(
      new Set(factory.asks.map((a) => a.peerId)).size,
      "ONE identity across every relay: an agent is dialable at ONE peer id through any of its circuits",
    ).toBe(1);

    /**
     * ONE ASK PER RELAY. The old shape asked A twice — refused, then granted after the proof. Two
     * asks per relay is the cost this order removes, and counting them is how a silent regression
     * back to the dance would be caught.
     */
    const listensPerRelay = relay.timeline.filter((e) => e.kind === "listen");
    expect(
      listensPerRelay.map((e) => e.relayPeerId),
      "one reservation ask per relay, in walk order",
    ).toEqual([RELAY_A, RELAY_B]);
  }, 30_000);

  it("★★★ the proof and the reservation happen on the SAME node, with no teardown between them", async () => {
    /**
     * ⚠️ THE TEETH, and the reason the assertion above is not enough.
     *
     * "A reservation appeared" is satisfied by the OLD code too — it also ends with a receiver
     * holding a circuit address. The property that is actually new is that the ask rides the
     * connection the proof was made on, and in production that is guaranteed by one measured fact:
     * libp2p's reservation store calls `openConnection(peerId)` without `force`, so it reuses the
     * open connection instead of dialling. **That only holds if nothing closed it in between.**
     *
     * So this asserts the node OBJECT, not the peer id — the receiver reuses one seed across every
     * relay, so peer id cannot distinguish "the node that proved" from "a rebuild on the same
     * identity", which is exactly what the old dance did.
     */
    const relay = new ScriptedRelay();
    const factory = new GatedFactory(relay);
    mgr = await makeManager(relay, factory);

    await mgr.ensureStandingReceiverForAgent("alice");

    const proofs = relay.gateProofTimeline();
    expect(proofs.length, "one gate proof per relay in the pool").toBe(2);

    for (const proof of proofs) {
      const provedAt = relay.timeline.indexOf(proof);
      /**
       * ⚠️ MATCHED PER RELAY, NOT PER NODE — 054-SRSPLIT. There is ONE node now, so "the first
       * listen by this node" is relay A's ask even when we are checking relay B, and the ordering
       * assertion silently compared the wrong pair. The node identity is still asserted (the ask
       * must be BY the proving node), it is just no longer sufficient on its own to say WHICH ask.
       */
      const askedAt = relay.timeline.findIndex(
        (e) => e.kind === "listen" && e.node === proof.node && e.relayPeerId === proof.relayPeerId,
      );
      const stoppedAt = relay.firstIndex("stop", proof.node);

      expect(
        askedAt,
        `relay ${proof.relayPeerId}: the node that proved must be the node that asks — a rebuild in ` +
          "between is the refused-first-ask dance wearing different clothes",
      ).toBeGreaterThan(-1);
      expect(askedAt, `relay ${proof.relayPeerId}: the proof must come BEFORE the ask`).toBeGreaterThan(provedAt);
      expect(
        stoppedAt === -1 || stoppedAt > askedAt,
        `relay ${proof.relayPeerId}: the proving node must still be up when it asks — stopping it ` +
          "closes the connection the relay marked proven, and the reservation is refused",
      ).toBe(true);
    }
  }, 30_000);

  it("★★★ a proof that reached NO VERDICT still asks — a refusal declines, silence does not", async () => {
    /**
     * ⚠️ REVIEW HIGH-1. The clause: `unavailable` (no relay verdict was obtained — no client wired,
     * or the relay unreachable) must NOT decline the candidate, because **not every relay gates
     * reservations**. One that never asks for a proof grants on the first ask, and refusing to ask
     * because OUR proof path was unavailable would lose the ability to reserve with it at all.
     *
     * This is the clause that had no test, and it is why the review found the boundary was drawn in
     * the wrong place: `proveToRelay` was returning `refused_try_another_relay` for a proof that
     * failed on transport, so the ask this asserts never happened.
     *
     * The relay here grants without any proof, which is exactly what an ungated relay does.
     */
    const relay = new ScriptedRelay();
    const factory = new GatedFactory(relay);
    // An UNGATED relay: it grants whoever asks, having been told nothing.
    relay.proven.add("*");
    const originalGrants = relay.grants.bind(relay);
    relay.grants = (): boolean => true;
    mgr = await makeManager(relay, factory, { noRelayClient: true });

    await mgr.ensureStandingReceiverForAgent("alice");

    expect(
      relay.timeline.filter((e) => e.kind === "listen").map((e) => e.relayPeerId),
      "with no proof path available the walk must still ASK every relay — treating silence as a " +
        "refusal makes this client unable to reserve with an ungated relay at all",
    ).toEqual([RELAY_A, RELAY_B]);
    expect(
      mgr.getStandingReceiverNode("alice")?.listenAddresses().some((a) => a.includes("/p2p-circuit")),
      "and the reservation it was granted is held",
    ).toBe(true);
    expect(relay.gateProofs(), "no proof could be made — that is the premise, not a side effect").toHaveLength(0);
    relay.grants = originalGrants;
  }, 30_000);

  it("★★★ a proof that FAILED ON TRANSPORT is no verdict either — and it is the case that actually happens", async () => {
    /**
     * ⚠️ REVIEW HIGH-1, AND THIS IS THE VARIANT THAT MATTERS. The case above ("no relay client
     * wired") already returned `unavailable` before the review. The DOMINANT real case did not: a
     * proof whose dial failed or whose stream was reset returns `false` with NO refusal recorded —
     * `#proveReservationOnce` clears the refusal at its head precisely so a transport failure leaves
     * no verdict behind — and `proveToRelay` labelled that `refused_try_another_relay` anyway.
     *
     * Under that label the ask never happened, so a relay whose proof stream got reset was recorded
     * as having refused this agent's proof, and an UNGATED relay that would have granted was never
     * asked. The producer now says `unavailable`, which is what its own log line already said.
     */
    const relay = new ScriptedRelay();
    relay.proofTransportFails = true;
    const factory = new GatedFactory(relay);
    // Ungated: it grants whoever asks. The point is that we never find out unless we ask.
    const originalGrants = relay.grants.bind(relay);
    relay.grants = (): boolean => true;
    mgr = await makeManager(relay, factory);

    await mgr.ensureStandingReceiverForAgent("alice");

    expect(
      relay.gateProofs().length,
      "the proof was ATTEMPTED — this is a transport failure, not an absent proof path",
    ).toBeGreaterThan(0);
    expect(
      relay.timeline.filter((e) => e.kind === "listen").map((e) => e.relayPeerId),
      "a proof that reached no verdict must not decline the candidate: the relay refused nothing, " +
        "and one that does not gate reservations would have granted",
    ).toEqual([RELAY_A, RELAY_B]);
    relay.grants = originalGrants;
  }, 30_000);

  it("★★★ a fault of OURS is not reported in the relay's vocabulary", async () => {
    /**
     * ⚠️ REVIEW HIGH-2, and the failure it prevents is a wild goose chase rather than a broken
     * session. `listenOnCircuit` throws `transport_manager_unavailable` when libp2p renames
     * `components.transportManager`. The generic decline infers its reason from the relay
     * connection — which is open and irrelevant, because the ask never left this process — and so
     * reported `relay_granted_no_reservation` on EVERY relay in the pool. In this daemon's own
     * taxonomy that string means *"relay CAPACITY, a trustless-cello problem"*, so a client-side API
     * change would send an operator into the relay fleet while the real cause survived only as an
     * `error` field on a warn line nothing surfaces.
     */
    const relay = new ScriptedRelay();
    relay.askThrows = true;
    const factory = new GatedFactory(relay);
    const events: Array<{ event: string; ctx: Record<string, unknown> }> = [];
    const capture = (event: string, ctx?: Record<string, unknown>): void => { events.push({ event, ctx: ctx ?? {} }); };
    mgr = await makeManager(relay, factory, {
      logger: { debug: capture, info: capture, warn: capture, error: capture },
    });

    await mgr.ensureStandingReceiverForAgent("alice");

    const rejected = events.filter((e) => e.event === "session.standing_receiver.relay.rejected");
    expect(rejected.length, "every relay in the pool is declined — the fault is ours, not theirs").toBeGreaterThan(0);
    for (const r of rejected) {
      expect(
        r.ctx["reason"],
        "the transport named this fault; re-deriving it from the relay connection turns a client-side " +
          "API change into a fleet-wide capacity outage",
      ).toBe("transport_manager_unavailable");
    }
    expect(
      mgr.getStandingReceiverReady("alice"),
      "and the agent still gets a receiver on the plain TCP floor — a client fault must degrade " +
        "reachability, not remove the receiver",
    ).toBe(true);
  }, 30_000);

  it("★★★ reservationsHeld counts RELAYS, not announced addresses", async () => {
    /**
     * ⚠️ A LIVE-MEASURED REGRESSION, not a hypothetical. Rewriting the walk (054-SRSPLIT) replaced a
     * deduping count with `listenAddresses().filter(isCircuit).length`, and the receiver reported
     * `relaysOffered: 2, reservationsHeld: 10` against the real GCP relays.
     *
     * It is not cosmetic. The watchdog and `cello_status` read this number to decide whether an
     * agent has LOST reachability, and a count that can exceed the number of relays offered cannot
     * answer that question — it makes a healthy agent and a churning one look the same.
     */
    const relay = new ScriptedRelay();
    relay.addressesPerRelay = 5; // what a relay with five listen addresses actually announces
    const factory = new GatedFactory(relay);
    const events: Array<{ event: string; ctx: Record<string, unknown> }> = [];
    const capture = (event: string, ctx?: Record<string, unknown>): void => { events.push({ event, ctx: ctx ?? {} }); };
    mgr = await makeManager(relay, factory, {
      logger: { debug: capture, info: capture, warn: capture, error: capture },
    });

    await mgr.ensureStandingReceiverForAgent("alice");

    const reachEvents = events.filter((e) => e.event === "session.standing_receiver.reachability");
    const reach = reachEvents.at(-1);
    expect(reach, "the receiver must report its reachability").toBeDefined();
    expect(
      reach?.ctx["reservationsHeld"],
      "two relays granted, so two reservations are held — however many addresses each announces",
    ).toBe(2);
    expect(
      Number(reach?.ctx["reservationsHeld"]),
      "and it can never exceed what was offered, which is the property that makes it answerable",
    ).toBeLessThanOrEqual(Number(reach?.ctx["relaysOffered"]));
    /**
     * ⚠️ ONE EMISSION PER RECEIVER BUILD — review MEDIUM-7, and this assertion is why the test above
     * is not hollow. 054-SRSPLIT added a second `reachability` emission inside `#startReceiverNode`
     * while the caller already emitted one. `.at(-1)` then read the CALLER's event, which counts
     * correctly, so a wrong count in the inner one was invisible: mutating the inner count left this
     * test green. `reservation.none` is also the event MSG-018 counted 481 of to justify a retry,
     * and doubling it breaks any comparison against that baseline.
     */
    expect(reachEvents.length, "the receiver reports its reachability ONCE per build").toBe(1);
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
      relay.gateProofs().map((p) => p.relayPeerId),
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
      relay.gateProofs().map((p) => p.relayPeerId),
      "a relay-side fault is the one case where the next relay genuinely helps — and A is asked " +
        "ONCE, because the retry exists only to use a proof that landed, and this one did not",
    ).toEqual([RELAY_A, RELAY_B]);
    /**
     * ⚠️ THIS ASSERTION MOVED WITH THE BEHAVIOUR (DOD-M15-RELAYPROVE-ORDER-1). It used to count
     * NODE BUILDS carrying relay A's circuit address and require exactly one — "retrying a relay
     * that refused the proof spends a build and a dial to be refused identically". Probes no
     * longer carry a circuit address at all, so that count is now zero for every relay and the old
     * form would pass for a walk that asked A ten times.
     *
     * The property is unchanged and is now stated where it actually lives: **relay A is never
     * asked for a reservation.** Its proof was refused, so the ask that follows a proof never
     * happens — and asking anyway is precisely the wasted dial the original assertion guarded.
     */
    expect(
      relay.timeline.filter((e) => e.kind === "listen" && e.relayPeerId === RELAY_A).length,
      "a relay that refused the proof is never asked for a reservation — the ask is what the proof " +
        "is a precondition for",
    ).toBe(0);
    expect(
      relay.timeline.filter((e) => e.kind === "listen" && e.relayPeerId === RELAY_B).length,
      "and the relay that DID take the proof is asked exactly once",
    ).toBe(1);
    expect(
      mgr.isRelayQuarantined("alice", RELAY_A),
      "and it must not be asked first again on the next rebuild — otherwise a misconfigured relay " +
        "is retried forever for the life of the process.",
    ).toBe(true);
    expect(mgr.getStandingReceiverNode("alice")?.listenAddresses().some((a) => a.includes("/p2p-circuit"))).toBe(true);
    // 054-SRSPLIT: the walk reaching relay B is visible as the ASK to B, not as a node built for it.
    expect(
      relay.timeline.filter((e) => e.kind === "listen" && e.relayPeerId === RELAY_B).length,
      "the walk moved on and actually asked B — 'it proved to B' without 'it asked B' is a proof " +
        "spent for nothing",
    ).toBe(1);
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
    const asksBefore = factory.asks.length;

    const revived = await mgr.reviveSessionNode("alice", sid);
    expect(revived.ok, JSON.stringify(revived)).toBe(true);

    /**
     * ⚠️ FILTERED TO THE SESSION NODE, and the filter is the assertion. Counting proofs alone is
     * green with the revival's prove step DELETED — clearing the relay's memory also strips the
     * receiver's circuit address, its watchdog rebuilds, and the receiver's own gate proof makes
     * the count go up. Measured: that mutant passed before this filter existed.
     */
    expect(
      relay.gateProofs().filter((p) => p.nodeType === "session"),
      "without a prove step the revival is refused by every candidate and lands on the plain floor: " +
        "the session is alive and active and the counterparty cannot dial it, so every message in " +
        "both directions is forced through the relay park route.",
    ).toHaveLength(1);

    /**
     * ⚠️ MOVED WITH THE BEHAVIOUR (DOD-M15-RELAYPROVE-ORDER-1). This used to require exactly TWO
     * node builds carrying a circuit address — "one refused ask, one granted, on one relay". The
     * revival now proves on a node built with no circuit address and asks once, so the
     * constructor-time count is zero and the ask is counted where it now happens.
     */
    expect(
      factory.asks.slice(asksBefore).filter((a) => a.nodeType === "session" && a.circuits.length > 0).length,
      "a revived session no longer asks before it has proved — nothing is built holding a circuit " +
        "address it has not earned",
    ).toBe(0);
    const revivedListens = relay.timeline
      .filter((e) => e.kind === "listen")
      .filter((e) => (e.node as unknown as GatedNode).nodeType === "session");
    expect(revivedListens.length, "one ask, on one relay, after the proof").toBe(1);
    expect(
      factory.built.filter(
        (n) => n.nodeType === "session" && n.listenAddresses().some((a) => a.includes("/p2p-circuit")),
      ).length,
      "the REVIVED SESSION ends up holding a real circuit address — not merely some node somewhere",
    ).toBeGreaterThan(0);
  }, 30_000);
});
