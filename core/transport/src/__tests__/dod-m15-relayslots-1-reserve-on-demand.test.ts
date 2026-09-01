/**
 * DOD-M15-RELAYSLOTS-1 — **AUTHENTICATE, THEN RESERVE.** The ordering that turns the relay's token
 * check from a heuristic into a gate.
 *
 * ─── Why this exists ──────────────────────────────────────────────────────────────────────────
 *
 * A circuit reservation is normally taken automatically at node construction, from the
 * `/p2p-circuit` entry in `listenAddresses`. That happens before the client has told the relay
 * anything about itself, so the relay must answer knowing only a peer id — which is free to
 * generate. That single ordering is why a machine with no registered agent could hold slots at all,
 * and why every attempt to bound it afterwards was a guess about who looked bad rather than a check
 * for who was allowed. A botnet walks through guesses.
 *
 * `reserveRelaySlot` breaks the ordering: build the node with NO circuit address, dial, prove
 * yourself, and only then ask for the slot. What this file proves is the half the relay depends on —
 * that a node really can come up without a reservation and take one later, on demand.
 */
import { describe, it, expect, afterEach } from "vitest";
import { createNode } from "../node.js";
import { generateKeypair } from "@cello-protocol/crypto";
import type { CelloNode } from "../types.js";

describe("DOD-M15-RELAYSLOTS-1: a client can reserve AFTER proving itself, not before", () => {
  const nodes: CelloNode[] = [];
  afterEach(async () => {
    for (const n of nodes.splice(0)) { try { await n.stop(); } catch { /* cleanup */ } }
  });

  async function relay(): Promise<{ node: CelloNode; addr: string; peerId: string }> {
    const node = await createNode({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      relayServer: { enabled: true, reservations: { maxReservations: 64, applyDefaultLimit: false } },
    });
    nodes.push(node);
    await node.start();
    const addr = node.listenAddresses().find((a) => a.includes("/p2p/"));
    if (!addr) throw new Error("relay has no addressed multiaddr");
    return { node, addr, peerId: node.getPeerId() };
  }

  /** A client built WITHOUT a circuit listen address — so it takes no reservation on its own. */
  async function client(): Promise<CelloNode> {
    const node = await createNode({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      nodeType: "standing_receiver",
    });
    nodes.push(node);
    await node.start();
    return node;
  }

  it("★★★ comes up with NO reservation, then takes one on demand", async () => {
    const r = await relay();
    const c = await client();

    expect(
      c.listenAddresses().some((a) => a.includes("/p2p-circuit")),
      "precondition: it must NOT have reserved on its own, or the ordering was never broken",
    ).toBe(false);
    expect(r.node.releaseRelayReservation(c.getPeerId()), "and the relay holds nothing for it").toBe(false);

    await c.dial(r.addr);
    // In production the CELLO auth happens here, between the dial and the reservation. That is the
    // entire point of the ordering; this file proves the transport half of it.
    expect(await c.reserveRelaySlot(r.peerId), "the on-demand reservation must succeed").toBe(true);

    expect(
      r.node.releaseRelayReservation(c.getPeerId()),
      "the relay is now holding a real reservation for this client — taken AFTER the connection " +
        "existed, which is what lets the relay refuse a stranger at the door instead of granting " +
        "first and regretting it.",
    ).toBe(true);
  }, 40_000);

  it("is idempotent — asking twice does not consume a second slot", async () => {
    const r = await relay();
    const c = await client();
    await c.dial(r.addr);

    expect(await c.reserveRelaySlot(r.peerId)).toBe(true);
    expect(await c.reserveRelaySlot(r.peerId), "already held, so this is a no-op").toBe(true);
    // One reservation, so one release empties it.
    expect(r.node.releaseRelayReservation(c.getPeerId())).toBe(true);
    expect(r.node.releaseRelayReservation(c.getPeerId())).toBe(false);
  }, 40_000);

  it("reports failure rather than throwing when there is no connection to reserve over", async () => {
    const r = await relay();
    const c = await client();
    // Never dialled. libp2p will not reserve without a non-relayed connection.
    expect(
      await c.reserveRelaySlot(r.peerId),
      "a caller deciding whether to try another relay needs an answer, not an exception",
    ).toBe(false);
  }, 40_000);

  it("reports failure on a malformed relay peer id", async () => {
    const c = await client();
    expect(await c.reserveRelaySlot("not-a-peer-id")).toBe(false);
  }, 40_000);
});
