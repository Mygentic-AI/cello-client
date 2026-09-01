/**
 * DOD-M15-RELAYSLOTS-1 — **HANGING A PEER UP DOES NOT FREE ITS RESERVATION.**
 *
 * This is the measurement the relay's whole reclaim story rests on, and until now nothing checked
 * it. Every path the relay has for reclaiming a slot — the grace-window revoke for an unproven
 * holder, the reaper under pressure, and the unproven-budget eviction — ends in `hangUp`. All three
 * were freeing the relay's own bookkeeping and nothing else.
 *
 * Verified against `@libp2p/circuit-relay-v2@4.2.3` before writing this: the server's
 * `removeReservation` is called from exactly one place — the catch when writing the reservation
 * confirmation frame fails — and there is no connection-close or disconnect listener anywhere in
 * its server directory. `reservationTtl` is not set by CELLO, so it defaults to two hours.
 *
 * What that meant in practice: a relay could evict a flood, watch its own counters fall, report
 * itself well under capacity — and still be holding those reservations against libp2p's 4096 limit
 * for two hours. An attacker could keep reserving into that gap and take the table while every
 * counter the relay owns said it was fine.
 *
 * The first assertion below is the defect. The second is the fix.
 */
import { describe, it, expect, afterEach } from "vitest";
import { createNode } from "../node.js";
import { generateKeypair } from "@cello-protocol/crypto";
import type { CelloNode } from "../types.js";

describe("DOD-M15-RELAYSLOTS-1: a relay can actually give a reservation back", () => {
  const nodes: CelloNode[] = [];
  afterEach(async () => {
    for (const n of nodes.splice(0)) { try { await n.stop(); } catch { /* cleanup */ } }
  });

  async function relayAndClient(): Promise<{ relay: CelloNode; client: CelloNode; relayAddr: string }> {
    const relay = await createNode({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      // The relay server is configured under `relayServer`, and enabling it is what makes this node
      // hold reservations at all.
      relayServer: { enabled: true, reservations: { maxReservations: 64, applyDefaultLimit: false } },
    });
    nodes.push(relay);
    await relay.start();
    const relayAddr = relay.listenAddresses().find((a) => a.includes("/p2p/"));
    if (!relayAddr) throw new Error("relay has no addressed multiaddr");

    const client = await createNode({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0", `${relayAddr}/p2p-circuit`],
      nodeType: "standing_receiver",
    });
    nodes.push(client);
    await client.start();

    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline && !client.listenAddresses().some((a) => a.includes("/p2p-circuit"))) {
      await new Promise((r) => setTimeout(r, 50));
    }
    expect(
      client.listenAddresses().some((a) => a.includes("/p2p-circuit")),
      "precondition: the client must actually hold a reservation, or this test measures nothing",
    ).toBe(true);
    return { relay, client, relayAddr };
  }

  it("★★★ hangUp leaves the reservation in place — the assumption three reclaim paths were built on", async () => {
    const { relay, client } = await relayAndClient();
    const clientPeerId = client.getPeerId();

    await relay.hangUp(clientPeerId);
    // The connection is gone; give libp2p a moment in case anything reacts to the close.
    await new Promise((r) => setTimeout(r, 500));

    expect(
      relay.releaseRelayReservation(clientPeerId),
      "returning true here means the reservation was STILL HELD after the hangup — which is the " +
        "defect. If this ever returns false, libp2p has started releasing reservations on " +
        "disconnect and this whole method can go.",
    ).toBe(true);
  }, 40_000);

  it("★★★ releaseRelayReservation actually gives it back, and is idempotent", async () => {
    const { relay, client } = await relayAndClient();
    const clientPeerId = client.getPeerId();

    expect(relay.releaseRelayReservation(clientPeerId), "held, then released").toBe(true);
    expect(
      relay.releaseRelayReservation(clientPeerId),
      "a second call must be a no-op — every reclaim path may reach this, and some reach it twice",
    ).toBe(false);
  }, 40_000);

  it("is a no-op on a node with no relay service, rather than throwing", async () => {
    const { client } = await relayAndClient();
    expect(
      client.releaseRelayReservation(client.getPeerId()),
      "every client node runs this code path via the shared type; it must not throw on one that " +
        "holds no reservations to give back.",
    ).toBe(false);
  }, 40_000);

  it("refuses a malformed peer id by name rather than letting a parse error read as a relay fault", async () => {
    const { relay } = await relayAndClient();
    expect(relay.releaseRelayReservation("not-a-peer-id")).toBe(false);
  }, 40_000);
});
