/**
 * DOD-M15-RELAYPROVE-ORDER-1 — **TAKING A RESERVATION AFTER START, ON THE CONNECTION WE PROVED ON.**
 *
 * The daemon's walk used to hand a circuit address to `createNode`, which made libp2p ask the relay
 * for a reservation the instant the node started — before any CELLO code had presented the
 * directory-signed online token. The relay refuses an unproven peer, and libp2p answers a refused
 * reservation by restarting its connection manager and closing every connection, including the one
 * carrying the proof. `listenOnCircuit` is the seam that lets the caller put the proof first.
 *
 * ⚠️ WHAT THIS FILE CAN AND CANNOT MEASURE. The reservation itself is exercised end to end against
 * a live relay in `#startReceiverNode`'s own suite and by the spine journeys. What lives HERE is the
 * part with no other home: the three refusals, and that a granted reservation is ANNOUNCED. The
 * third is the one the whole redesign turned on — a reservation nobody can dial through is a slot
 * spent for nothing, and the objection this order had to kill was that a reservation taken outside
 * libp2p's own discovery yields no dialable address.
 */
import { describe, it, expect, afterEach } from "vitest";
import { createNode } from "../node.js";
import { generateKeypair } from "@cello-protocol/crypto";
import type { CelloNode } from "../types.js";

describe("DOD-M15-RELAYPROVE-ORDER-1: listenOnCircuit", () => {
  const nodes: CelloNode[] = [];
  afterEach(async () => {
    for (const n of nodes.splice(0)) { try { await n.stop(); } catch { /* cleanup */ } }
  });

  async function plainNode(): Promise<CelloNode> {
    const node = await createNode({ keyProvider: generateKeypair(), listenAddresses: ["/ip4/127.0.0.1/tcp/0"] });
    nodes.push(node);
    return node;
  }

  it("★★★ a reservation taken AFTER start is ANNOUNCED — the objection this order had to kill", async () => {
    /**
     * The recorded objection, in `session-relay.ts`'s own words: *"taking the reservation by hand
     * yields no dialable address, because libp2p only announces addresses for reservations its own
     * discovery made."* True of a slot taken over a raw HOP stream; false here, because this asks
     * libp2p's OWN transport manager and the reservation is therefore libp2p's own.
     *
     * A slot that is held and not announced is the worst of both: it consumes the scarce resource
     * this whole story exists to conserve and buys no reachability. Asserting the ADDRESS rather
     * than "listen() resolved" is what separates them — `listen()` resolves either way.
     */
    const relay = await createNode({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      relayServer: { enabled: true, reservations: { maxReservations: 64, applyDefaultLimit: false } },
    });
    nodes.push(relay);
    await relay.start();
    const relayAddr = relay.listenAddresses().find((a) => a.includes("/tcp/"));
    expect(relayAddr, "the relay must be listening for this test to mean anything").toBeDefined();

    const client = await plainNode();
    await client.start();
    expect(
      client.listenAddresses().some((a) => a.includes("/p2p-circuit")),
      "no circuit address before the ask — the node was built with none",
    ).toBe(false);

    // The ordering under test: connect FIRST, then ask on that connection.
    await client.dial(relayAddr!);
    await client.listenOnCircuit(`${relayAddr!}/p2p-circuit`);

    expect(
      client.listenAddresses().filter((a) => a.includes("/p2p-circuit")),
      "the reservation must yield a DIALABLE address, not merely a held slot",
    ).not.toHaveLength(0);
  }, 30_000);

  it("refuses a non-circuit address by name, rather than listening on it", async () => {
    // A direct listen address belongs in createNode, where start() can still fail loudly on a bad
    // bind. Accepting one here would add a second, quieter way to open a listener.
    const node = await plainNode();
    await node.start();
    await expect(node.listenOnCircuit("/ip4/127.0.0.1/tcp/4001")).rejects.toMatchObject({
      reason: "not_a_circuit_address",
    });
  }, 20_000);

  it("refuses a substring match — `p2p-circuit` must be a SEGMENT", async () => {
    /**
     * `includes("/p2p-circuit")` is the tempting test and it is wrong twice over: the marker sits
     * in the MIDDLE of a full circuit address, and a substring match also accepts an address whose
     * host or peer id merely contains the text. This asserts the guard reads segments.
     */
    const node = await plainNode();
    await node.start();
    await expect(node.listenOnCircuit("/dns4/p2p-circuit.example.com/tcp/4001")).rejects.toMatchObject({
      reason: "not_a_circuit_address",
    });
  }, 20_000);

  it("refuses on a node that has not started — and says which, rather than reporting a relay fault", async () => {
    // Asking before start is a caller ordering error. It must not surface as something about the
    // relay, which is where an operator would then go looking.
    const node = await plainNode();
    await expect(node.listenOnCircuit("/ip4/127.0.0.1/tcp/4001/p2p-circuit")).rejects.toMatchObject({
      reason: "node_stopped",
    });
  }, 20_000);
});

describe("054-SRSPLIT: releaseAllCircuits — giving reservations back", () => {
  const nodes: CelloNode[] = [];
  afterEach(async () => {
    for (const n of nodes.splice(0)) { try { await n.stop(); } catch { /* cleanup */ } }
  });

  it("★★★ a released circuit stops being announced — AND the relay still holds the slot", async () => {
    /**
     * ⚠️ **BOTH HALVES OF THIS ASSERTION ARE THE POINT, AND THE SECOND IS THE SURPRISING ONE.**
     *
     * Closing the local listener runs `reservationStore.cancelReservations()`, whose entire body is
     * `clearTimeout` on each entry and `this.reservations.clear()`. It sends the relay NOTHING, and
     * circuit-relay-v2 has no unreserve message. The relay's server frees a reservation only when
     * its TTL aborts — two hours by default — and has no disconnect listener.
     *
     * So `releaseAllCircuits` is the LOCAL half: it stops us advertising a route we can no longer be
     * reached on. **It does not free capacity**, and the second assertion pins that so nobody later
     * reads this method as a release and builds "released at seal" on top of it. The verb that
     * frees the slot lives on `/cello/relay/1.0.0` (054-SRSPLIT part A2), in the relay.
     */
    const relay = await createNode({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      relayServer: { enabled: true, reservations: { maxReservations: 64, applyDefaultLimit: false } },
    });
    nodes.push(relay);
    await relay.start();
    const relayAddr = relay.listenAddresses().find((a) => a.includes("/tcp/"));
    expect(relayAddr, "the relay must be listening for this test to mean anything").toBeDefined();

    const client = await createNode({ keyProvider: generateKeypair(), listenAddresses: ["/ip4/127.0.0.1/tcp/0"] });
    nodes.push(client);
    await client.start();
    await client.dial(relayAddr!);
    await client.listenOnCircuit(`${relayAddr!}/p2p-circuit`);
    expect(
      client.listenAddresses().some((a) => a.includes("/p2p-circuit")),
      "precondition: a reservation must be HELD before releasing it can mean anything",
    ).toBe(true);

    const released = await client.releaseAllCircuits();

    expect(released, "it reports having held one").toBe(true);
    expect(
      client.listenAddresses().some((a) => a.includes("/p2p-circuit")),
      "we stop advertising an address we can no longer be reached on — otherwise a counterparty is " +
        "handed a route to a circuit that will refuse them",
    ).toBe(false);
    expect(
      relay.releaseRelayReservation(client.getPeerId()),
      "⚠️ TRUE MEANS THE RELAY STILL HELD IT. That is not a bug in releaseAllCircuits — it is the reason " +
        "the relay needs a release VERB. If this ever goes false, libp2p has started telling the " +
        "relay, and the verb can go.",
    ).toBe(true);
  }, 30_000);

  it("releasing a circuit that was never held is a named no-op, not a throw", async () => {
    // The seal path will call this whether or not a reservation was ever taken — an offer that went
    // quiet never took one. Throwing there would turn a tidy-up into a failed seal.
    const node = await createNode({ keyProvider: generateKeypair(), listenAddresses: ["/ip4/127.0.0.1/tcp/0"] });
    nodes.push(node);
    await node.start();
    await expect(node.releaseAllCircuits()).resolves.toBe(false);
  }, 20_000);

  it("★★★ releasing gives back EVERY circuit, and the caller must not expect otherwise", async () => {
    /**
     * ⚠️ THE ASSERTION THAT KEEPS THE NAME HONEST — review HIGH-2, which this method's first version
     * got wrong in the most expensive way available.
     *
     * It took ONE address and closed the listener announcing it. Measured in
     * `@libp2p/circuit-relay-v2@4.2.5`: every listener shares ONE `reservationStore`, and
     * `listener.close()` calls `cancelReservations()` — `clearTimeout` over every entry, then
     * `reservations.clear()`. So closing relay A's listener cleared the refresh timers for B and C
     * while their listeners kept announcing their addresses. The agent went on advertising circuits
     * nobody would renew: routes that die at the relay's TTL while `cello status` still reads
     * `reserved`.
     *
     * A one-circuit fixture cannot see that — which is why the original test passed. Two relays can.
     */
    const relays = await Promise.all([0, 1].map(async () => {
      const r = await createNode({
        keyProvider: generateKeypair(),
        listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
        relayServer: { enabled: true, reservations: { maxReservations: 64, applyDefaultLimit: false } },
      });
      nodes.push(r);
      await r.start();
      return r.listenAddresses().find((a) => a.includes("/tcp/"))!;
    }));

    const client = await createNode({ keyProvider: generateKeypair(), listenAddresses: ["/ip4/127.0.0.1/tcp/0"] });
    nodes.push(client);
    await client.start();
    for (const relayAddr of relays) {
      await client.dial(relayAddr);
      await client.listenOnCircuit(`${relayAddr}/p2p-circuit`);
    }
    expect(
      new Set(client.listenAddresses()
        .filter((a) => a.split("/").includes("p2p-circuit"))
        .map((a) => /\/p2p\/([^/]+)\/p2p-circuit/.exec(a)?.[1])).size,
      "precondition: two relays must actually be held, or this measures nothing",
    ).toBe(2);

    await client.releaseAllCircuits();

    expect(
      client.listenAddresses().filter((a) => a.split("/").includes("p2p-circuit")),
      "NOTHING is left announced. Leaving one advertised while its refresh timer has been cleared " +
        "is the silent failure: it reads as reachable until the relay's TTL runs out.",
    ).toEqual([]);
  }, 40_000);
});
