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
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
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
  /** Relay peer ids this agent told us it was finished with. */
  readonly released: string[] = [];
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
  /**
   * 056-SLOTDEAD review F5 — did this node ever ASK? The replacement for the deleted `asks` record,
   * and it observes the node rather than the config it was built from: a circuit announced without
   * this ever having been true is a constructor-time reservation, which is the thing that must
   * never come back.
   */
  #asked = false;
  hasAsked(): boolean { return this.#asked; }

  override async listenOnCircuit(circuitAddr: string): Promise<void> {
    this.#asked = true;
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

  /**
   * ⚠️ **A GRANTED RESERVATION IMPLIES A LIVE CONNECTION TO THE RELAY**, and a fixture that says
   * otherwise makes the watchdog read every held reservation as LOST on its next tick — rebuilding
   * the receiver forever. That is the fixture lying, not the code churning; `msg-018`'s
   * `ReservationNode` carries the same note for the same reason.
   *
   * OUTBOUND, because a reservation is this node dialling the relay and holding that open.
   */
  override getConnections(): Array<{
    id: string;
    peerId: string;
    encryption: string | undefined;
    status: string;
    direction: "inbound" | "outbound";
    openedAt: number;
    streamCount: number;
  }> {
    return this.listenAddresses()
      .map((a) => /\/p2p\/([^/]+)\/p2p-circuit/.exec(a)?.[1])
      .filter((id): id is string => id !== undefined)
      .map((peerId) => ({
        id: `conn-${peerId}`, peerId, encryption: "noise", status: "open",
        direction: "outbound" as const, openedAt: 0, streamCount: 0,
      }));
  }

  override listenAddresses(): string[] {
    // THE GATE. A circuit address appears only for a peer id the relay has a proof for — which is
    // exactly what the relay's `denyInboundRelayReservation` decides.
    const atStart = this.started && this.circuit !== undefined && this.relay.grants(this.#id) ? [this.circuit] : [];
    return [...atStart, ...(this.started ? this.takenCircuits : []), "/ip4/127.0.0.1/tcp/1"];
  }
}

class GatedFactory implements ISessionNodeFactory {
  readonly built: GatedNode[] = [];
  constructor(private readonly relay: ScriptedRelay) {}
  /**
   * ⚠️ **`asks` IS GONE, AND SO IS THE `circuit` IT WAS BUILT FROM — 056-SLOTDEAD, review F5.**
   *
   * This recorded `config.circuitRelayListenAddrs`, the field that made a node ask a relay for a
   * slot at construction, so a test could assert nothing is ever built that way. 055-ONDEMAND
   * deleted the field. `tsconfig.json` excludes `src/__tests__`, so reading it here was not a type
   * error — it was silently `undefined`, every recorded `circuits` was `[]`, and the assertion
   * counting them was vacuous. It read as the revert test for the whole change and could not fail.
   *
   * **The property it guarded is now enforced by the type system instead, which is strictly
   * stronger.** There is no field to pass, so no caller can build a node carrying a circuit
   * address; re-introducing one is a change to `SessionNodeConfig`, not a slip. What still has
   * teeth is the node's own state, asserted below: a node announces a circuit only after it has
   * asked and been granted, never at construction.
   */
  async createNode(config: SessionNodeConfig): Promise<CelloNode> {
    const node = new GatedNode(config.transportPrivateKey, this.relay, undefined, config.nodeType);
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
    // 055-ONDEMAND — the relay's own record of being told a slot is free. Asserting on THIS rather
    // than on our local addresses is the difference between "we stopped advertising" and "the slot
    // is back in the table", and only the second is what the story is about.
    async releaseReservation(): Promise<boolean> { relay.released.push(relayPeerId); return true; },
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
  opts: { noRelayClient?: boolean; logger?: Logger; watchdogMs?: number; reservationRetryMs?: number } = {},
): Promise<SessionNodeManager> {
  const m = new SessionNodeManager({
    securityGateway: new PassthroughGatewayClient(),
    factory,
    logger: opts.logger ?? silent,
    dbPath: join(tempDir, "sessions.db"),
    // 056-SLOTDEAD: a fast watchdog so a tick actually lands inside the window under test.
    ...(opts.watchdogMs !== undefined ? { standingReceiverWatchdogIntervalMs: opts.watchdogMs } : {}),
    /**
     * 056-SLOTDEAD review F12 — **THE RESPREAD CLOCK, AND WITHOUT IT THE TEST BELOW PROVED
     * NOTHING.** `srLastRespreadAt` is stamped when the receiver is BUILT and only re-stamped when
     * a respread fires, so the guard `now - last < srReservationRetryMs` blocks a receiver younger
     * than the interval — which, at the default five minutes, is every receiver a test builds.
     * Leaving it at the default made the revert test green with the respread RESTORED, which is how
     * a live defect got recorded as inert. A tiny interval reproduces the production case: an agent
     * that has been logged in longer than the interval, which is every real agent.
     */
    ...(opts.reservationRetryMs !== undefined ? { standingReceiverReservationRetryMs: opts.reservationRetryMs } : {}),
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

/**
 * 055-ONDEMAND — **THE TRIGGER MOVED, SO THE FIXTURE MOVED WITH IT.**
 *
 * These tests used to call `ensureStandingReceiverForAgent` and watch the login WALK visit every
 * relay. There is no walk: an idle agent holds nothing, and a reservation is taken when an offer
 * arrives, on the relay the directory named. So the receiver comes up and then this asks for the
 * relays the test is about — which is exactly what the offer path does, through the same seam.
 *
 * ⚠️ The properties below did NOT move. Prove-before-ask, one node, the client-fault vocabulary and
 * the refusal reaching `cello_status` are all still true and still asserted; what changed is who
 * decides which relay, and that is now the directory rather than a walk.
 */
async function bringUpAndReserve(m: SessionNodeManager, relays: readonly string[] = [CIRCUIT_A, CIRCUIT_B]): Promise<boolean[]> {
  await m.ensureStandingReceiverForAgent("alice");
  const took: boolean[] = [];
  for (const circuitAddr of relays) {
    took.push(await m.takeReservationForSession("alice", circuitAddr, "test-corr"));
    // An agent-level refusal reproduces on every relay, so the offer path would not ask a second.
    if (m.getStandingReceiverRefusal("alice")?.tryAnotherRelay === false) break;
  }
  return took;
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

    await bringUpAndReserve(mgr);
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
    /**
     * ⚠️ **THIS COUNTED A FIELD THAT NO LONGER EXISTS, SO IT COULD NOT FAIL — 056-SLOTDEAD, F5.**
     * It was `factory.asks.filter((a) => a.circuits.length > 0).length === 0`, and `circuits` came
     * from the deleted `circuitRelayListenAddrs`, so every entry was `[]`. The claim above it —
     * "restore either the probes or the rebuild and this fails" — had stopped being true.
     *
     * The replacement observes the node instead of the config, which is what the property was
     * always about: a node that has been BUILT but has not yet asked announces no circuit. A
     * constructor-time ask would put one there, and this would go red.
     */
    expect(
      factory.built.filter((n) => n.listenAddresses().some((a) => a.includes("/p2p-circuit"))
        && !n.hasAsked()).length,
      "no node announces a circuit it never asked for — the ask happens on a node that is already " +
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
    // 056-SLOTDEAD F5: read off the nodes actually built, not the deleted `asks` record. Same claim.
    expect(
      new Set(factory.built.map((n) => n.getPeerId())).size,
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

    await bringUpAndReserve(mgr);

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

    await bringUpAndReserve(mgr);

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

    await bringUpAndReserve(mgr);

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

    await bringUpAndReserve(mgr);

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

    await bringUpAndReserve(mgr);

    /**
     * ⚠️ THE SUBJECT MOVED WITH 055-ONDEMAND. The count used to be reported at login, by the walk.
     * Nothing is held at login now, so the number that matters is the receiver's own record of what
     * it holds — `relayPeerIds`, which is what the reservation WATCHDOG compares against to decide a
     * reservation was lost and what `cello_status` reports as reachability.
     *
     * Getting it wrong is not cosmetic in either place: a count that can exceed the number of relays
     * makes a healthy agent and a churning one look identical.
     */
    expect(
      mgr.getStandingReceiverRelayIds("alice"),
      "two relays granted, so two relays are recorded — however many addresses each announces",
    ).toEqual([RELAY_A, RELAY_B]);
    /**
     * ⚠️ ONE EMISSION PER RECEIVER BUILD — review MEDIUM-7, and this assertion is why the test above
     * is not hollow. 054-SRSPLIT added a second `reachability` emission inside `#startReceiverNode`
     * while the caller already emitted one. `.at(-1)` then read the CALLER's event, which counts
     * correctly, so a wrong count in the inner one was invisible: mutating the inner count left this
     * test green. `reservation.none` is also the event MSG-018 counted 481 of to justify a retry,
     * and doubling it breaks any comparison against that baseline.
     */
    /**
     * ONE emission per build — kept from 054-SRSPLIT review MEDIUM-7, where a duplicate
     * `reachability` line made a count test read the wrong copy of the event and go green against a
     * defect. The event now reports zero held at login (055-ONDEMAND), and it must still be one line.
     */
    expect(
      events.filter((e) => e.event === "session.standing_receiver.reachability").length,
      "the receiver reports its reachability ONCE per build",
    ).toBe(1);
  }, 30_000);

  it("★★★ an offer that goes QUIET gives its slot back — DOD-M15-OFFER-EXPIRY-1, relocated", async () => {
    /**
     * ⚠️ **THE STORY PREDICTED THIS EXACT DEFECT AND NAMED THIS UNIT AS ITS OWNER.**
     *
     * Units 2 and 3 removed the permanently-open door `OFFER-EXPIRY-1` wanted a timer on — and the
     * defect moved somewhere more expensive rather than going away. The responder reserves the
     * moment an offer arrives; an initiator that never dials leaves a slot held on a SHARED relay
     * until its TTL, two hours by default. "Released at seal" cannot cover it, because there is no
     * seal.
     *
     * ⚠️ AND THE BUDGET IS THE POINT: it is NOT the directory's 2-second accept clock. The accept
     * only starts the ceremony — the assignment still has to be FROST-signed and delivered before
     * either side builds a session. Releasing on 2 s would take the slot out from under a session
     * that was about to begin.
     */
    vi.useFakeTimers();
    try {
      const relay = new ScriptedRelay();
      const factory = new GatedFactory(relay);
      const evs: Array<{ event: string }> = [];
      const cap = (event: string): void => { evs.push({ event }); };
      mgr = await makeManager(relay, factory, { logger: { debug: cap, info: cap, warn: cap, error: cap } });
      await mgr.ensureStandingReceiverForAgent("alice");

      const sessionIdHex = "ab".repeat(16);
      await mgr.takeReservationForSession("alice", CIRCUIT_A, "corr", sessionIdHex);
      expect(
        mgr.getStandingReceiverRelayIds("alice"),
        "precondition: the offer took a slot, which is what makes it abandonable",
      ).toEqual([RELAY_A]);

      // The ceremony is still plausibly running here — nothing may be released yet.
      await vi.advanceTimersByTimeAsync(30_000);
      expect(
        evs.some((e) => e.event === "session.reservation.offer_abandoned"),
        "⚠️ NOT released at 30s. A FROST-signed assignment still has to reach both parties; " +
          "releasing inside that window breaks sessions that were about to start.",
      ).toBe(false);

      // Past the grace, with no session ever created for that id.
      await vi.advanceTimersByTimeAsync(40_000);
      await vi.runOnlyPendingTimersAsync();

      expect(
        evs.some((e) => e.event === "session.reservation.offer_abandoned"),
        "the slot is given back rather than held for the relay's two-hour TTL",
      ).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  }, 30_000);

  it("★★★ an offer that BECOMES a session keeps its slot — the release must not fire under a live session", async () => {
    /**
     * The other half, and the one that decides whether the timer above is safe to ship. A release
     * that fired on a healthy session would be far worse than the leak it prevents: the
     * counterparty holds a route that stops working mid-conversation, and nothing says why.
     */
    vi.useFakeTimers();
    try {
      const relay = new ScriptedRelay();
      const factory = new GatedFactory(relay);
      mgr = await makeManager(relay, factory);
      await mgr.ensureStandingReceiverForAgent("alice");

      const sessionIdHex = "cd".repeat(16);
      await mgr.takeReservationForSession("alice", CIRCUIT_A, "corr", sessionIdHex);
      const created = await mgr.createSessionNode(sessionIdHex, "alice", "bb".repeat(32), COUNTERPARTY_PEER, "corr", true);
      expect(created.ok, JSON.stringify(created)).toBe(true);

      await vi.advanceTimersByTimeAsync(120_000);
      await vi.runOnlyPendingTimersAsync();

      /**
       * ⚠️ READ THROUGH `cello_status`, NOT THE RECEIVER. The circuit lives on the SESSION's node —
       * the receiver was promoted into it and replaced — so checking the receiver reports a fault
       * on a perfectly healthy conversation. That is exactly the defect the reachability read had
       * before this unit fixed it, and asserting through the operator's own surface is what stops
       * it coming back.
       */
      expect(
        mgr.getStandingReceiverReachability("alice"),
        "a live session keeps the circuit its counterparty was told to dial, and the operator's " +
          "surface says so",
      ).toBe("reserved");
    } finally {
      vi.useRealTimers();
    }
  }, 30_000);

  it("★★★ TWO live sessions, one seals: the other keeps its circuit — the order's mandated test", async () => {
    /**
     * ⚠️ **THE ORDER SAID THIS TEST MUST EXIST BEFORE THE CODE, AND IT DID NOT.** Review HIGH-5. Its
     * absence is why the release half shipped in a state where it could never run: nothing in the
     * suite went red when `releaseSessionReservation` returned without doing anything.
     *
     * ⚠️ AND THE ANSWER IT PINS IS NOT THE ONE THE ORDER EXPECTED. The order feared that sealing one
     * session would clear the other's refresh timers, because libp2p shares a `reservationStore`
     * across listeners — so it prescribed a recompute. That store is shared **within one node**, and
     * each live session owns its OWN node. Sealing one cannot touch another's. The recompute was
     * aimed at an object that does not exist, and re-deriving it removed a whole class of drift
     * rather than managing it.
     */
    const relay = new ScriptedRelay();
    const factory = new GatedFactory(relay);
    mgr = await makeManager(relay, factory);
    await mgr.ensureStandingReceiverForAgent("alice");

    const sidA = "11".repeat(16);
    await mgr.takeReservationForSession("alice", CIRCUIT_A, "corrA", sidA);
    const openedA = await mgr.createSessionNode(sidA, "alice", "aa".repeat(32), COUNTERPARTY_PEER, "corrA", true);
    expect(openedA.ok, JSON.stringify(openedA)).toBe(true);

    await mgr.ensureStandingReceiverForAgent("alice");
    const sidB = "22".repeat(16);
    await mgr.takeReservationForSession("alice", CIRCUIT_B, "corrB", sidB);
    const openedB = await mgr.createSessionNode(sidB, "alice", "bb".repeat(32), COUNTERPARTY_PEER, "corrB", true);
    expect(openedB.ok, JSON.stringify(openedB)).toBe(true);

    const nodeB = mgr.getSessionNodeForTest("alice", sidB);
    const bHeldBefore = (nodeB?.listenAddresses() ?? []).filter((a) => a.includes("/p2p-circuit")).length;
    expect(bHeldBefore, "precondition: session B holds a circuit, or this measures nothing").toBeGreaterThan(0);

    await mgr.destroySessionNode("alice", sidA, "sealed");

    expect(
      (nodeB?.listenAddresses() ?? []).filter((a) => a.includes("/p2p-circuit")).length,
      "⚠️ session B still announces its circuit. Sealing A must not cost B the route its " +
        "counterparty was told to dial — a live session losing inbound with no event is the worst " +
        "shape this unit could ship.",
    ).toBe(bHeldBefore);
    expect(
      mgr.getStandingReceiverReachability("alice"),
      "and the operator's surface still says the agent is reachable",
    ).toBe("reserved");
  }, 30_000);

  it("★★★ the seal TELLS the relay — the only thing that actually frees a slot", async () => {
    /**
     * Review HIGH-1/HIGH-2: the release used to look the node up by agent name, which after the
     * promotion is the fresh EMPTY receiver — so it read zero circuits and returned having told the
     * relay nothing, while logging success. And it only ran on `retireSessionNode`, which is the
     * CLOSER's path; the responder, which is the party that reserved, tears down through
     * `destroySessionNode`.
     *
     * Both are asserted here, on the responder's path, through the relay's own record of being told.
     */
    const relay = new ScriptedRelay();
    const factory = new GatedFactory(relay);
    mgr = await makeManager(relay, factory);
    await mgr.ensureStandingReceiverForAgent("alice");

    const sid = "33".repeat(16);
    await mgr.takeReservationForSession("alice", CIRCUIT_A, "corr", sid);
    const opened = await mgr.createSessionNode(sid, "alice", "aa".repeat(32), COUNTERPARTY_PEER, "corr", true);
    expect(opened.ok, JSON.stringify(opened)).toBe(true);
    expect(relay.released, "precondition: nothing released yet").toEqual([]);

    await mgr.destroySessionNode("alice", sid, "sealed");

    expect(
      relay.released,
      "the relay is TOLD. Closing a listener sends it nothing and its own reaper waits on pressure, " +
        "so without this the slot is held for its full TTL — two hours — after the session ended.",
    ).toEqual([RELAY_A]);
  }, 30_000);

  it("★★★ an offer's reservation survives a watchdog tick taken BEFORE the session exists", async () => {
    /**
     * ⚠️ **THE DEFECT 055-ONDEMAND LEFT BEHIND — 056-SLOTDEAD (A), AND THE CLOCK IS THE WHOLE TEST.**
     *
     * `#respreadIfDecayed` existed to top up an IDLE agent's login-time spread. Its guards were
     * written for a world where the standing receiver held reservations, and unit 3 created a state
     * that passes every one of them:
     *
     *   - `relayPeerIds.length === 0`?  No — the offer just took one.
     *   - in `activeNodes`?             No — the assignment has not arrived, so no session yet.
     *   - `held >= offered`?            No — one held, two offered.
     *   - respread clock due?           Yes, for any agent logged in longer than the interval.
     *
     * A watchdog tick in that window REBUILDS the receiver, discarding the reservation the offer
     * just took — and the accept then advertises a circuit that no longer exists. The counterparty
     * is handed a route to nothing, and nothing anywhere says so.
     *
     * ⚠️ **THE FOURTH GUARD IS WHY THIS FILE PREVIOUSLY LIED, review F12.** The first version of
     * this test said the clock is due because `srLastRespreadAt` is 0 on the first offer. It is not
     * 0 — it is stamped when the receiver is BUILT — so at the default five-minute interval the
     * guard blocked, the revert test stayed GREEN with the respread restored, and a live defect was
     * written down as inert. `reservationRetryMs: 1` is not a convenience here: it is the only way
     * to reproduce the production state, which is an agent that logged in more than five minutes
     * ago. That describes every real agent and no test receiver.
     *
     * Not a race: a reachable state, and the four guards are the whole argument.
     */
    const relay = new ScriptedRelay();
    const factory = new GatedFactory(relay);
    mgr = await makeManager(relay, factory, { watchdogMs: 60, reservationRetryMs: 1 });
    await mgr.ensureStandingReceiverForAgent("alice");

    // The offer reserves. The session does NOT exist yet — the assignment is still in flight.
    await mgr.takeReservationForSession("alice", CIRCUIT_A, "corr", "ef".repeat(16));
    const peerBefore = mgr.getStandingReceiverInfo("alice")?.peerId;
    expect(mgr.getStandingReceiverRelayIds("alice"), "precondition: the offer took a slot").toEqual([RELAY_A]);

    // Several watchdog ticks land in the window between the reserve and the session.
    await new Promise((r) => setTimeout(r, 500));

    expect(
      mgr.getStandingReceiverInfo("alice")?.peerId,
      "the receiver must NOT be rebuilt while an offer's reservation is in flight — a rebuild " +
        "discards it, and the accept then advertises a circuit that does not exist",
    ).toBe(peerBefore);
    expect(
      mgr.getStandingReceiverRelayIds("alice"),
      "and the reservation is still held",
    ).toEqual([RELAY_A]);
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

    await bringUpAndReserve(mgr);

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

    await bringUpAndReserve(mgr);

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
    await bringUpAndReserve(mgr);
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
    const builtBefore = factory.built.length;

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
     * revival now proves on a node built with no circuit address and asks once.
     *
     * ⚠️ AND IT COUNTED A DELETED FIELD, so it could not fail — 056-SLOTDEAD, review F5. It read
     * `a.circuits.length > 0` off `circuitRelayListenAddrs`, which 055-ONDEMAND removed; every
     * entry was `[]` and the zero was arithmetic, not evidence. Asserted on the node now: a revived
     * session node that announces a circuit without ever having asked is the defect.
     */
    expect(
      factory.built.slice(builtBefore)
        .filter((n) => n.nodeType === "session"
          && n.listenAddresses().some((a) => a.includes("/p2p-circuit"))
          && !n.hasAsked()).length,
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
