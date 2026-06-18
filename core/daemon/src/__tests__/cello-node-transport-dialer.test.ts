/**
 * CELLO-M7-TRANSPORT-001 — cello-node-transport-dialer.test.ts (review C1(b))
 *
 * The real TransportDialer over a CelloNode + relay registry. These tests pin the
 * dial operations the TransportSelector composes:
 *   - dialDirect: first-success-wins, throws when every address fails, honours the
 *     per-attempt timeout.
 *   - dialRelay: dials the circuit address.
 *   - relayCircuitAddr: built from the daemon's relay registry (AC-006), throws
 *     when no relay is registered.
 *   - attemptDcutr: resolves when a direct connection appears, throws on timeout
 *     (non-fatal — SI-003).
 */

import { describe, it, expect } from "vitest";
import { CelloNodeTransportDialer, type RelayEndpoint } from "../cello-node-transport-dialer.js";
import type { SessionAssignment } from "@cello-protocol/protocol-types";
import type { CelloNode } from "@cello-protocol/transport";

// ─── Fake CelloNode ───────────────────────────────────────────────────────────

interface FakeNodeOpts {
  dialImpl?: (addr: string) => Promise<{ peerId: string }>;
  directConnections?: Set<string>;
}

class FakeCelloNode {
  dialed: string[] = [];
  #dialImpl: (addr: string) => Promise<{ peerId: string }>;
  #direct: Set<string>;
  constructor(opts: FakeNodeOpts = {}) {
    this.#dialImpl = opts.dialImpl ?? (async () => ({ peerId: "12D3KooWok" }));
    this.#direct = opts.directConnections ?? new Set();
  }
  async dial(addr: string): Promise<{ peerId: string }> {
    this.dialed.push(addr);
    return this.#dialImpl(addr);
  }
  hasDirectConnectionTo(peerId: string): boolean {
    return this.#direct.has(peerId);
  }
  markDirect(peerId: string): void {
    this.#direct.add(peerId);
  }
}

function asNode(fake: FakeCelloNode): CelloNode {
  return fake as unknown as CelloNode;
}

function makeAssignment(): SessionAssignment {
  return {
    session_id: new Uint8Array(16).fill(9),
    participant_a: { pubkey: new Uint8Array(32).fill(1), peer_id: "12D3KooWA", multiaddrs: [] },
    participant_b: { pubkey: new Uint8Array(32).fill(2), peer_id: "12D3KooWB", multiaddrs: [] },
    relay_endpoint: { peer_id: "12D3KooWRelay", multiaddrs: ["/ip4/198.51.100.9/tcp/4001"] },
    directory_endpoint: { peer_id: "12D3KooWDir", multiaddrs: ["/ip4/203.0.113.1/tcp/4001"] },
    session_timestamp: 1_700_000_000_000,
    directory_pubkey: new Uint8Array(32).fill(3),
    directory_signature: new Uint8Array(64).fill(4),
    signature_type: "frost",
    signer_pubkey: new Uint8Array(32).fill(5),
    counterparty_session_peer_id: "12D3KooWCounter",
    counterparty_session_addrs: ["/ip4/203.0.113.50/tcp/4001/p2p/12D3KooWCounter"],
    transport_mode: "direct",
  };
}

const REGISTRY: RelayEndpoint = { peerId: "12D3KooWRelay", multiaddrs: ["/ip4/198.51.100.9/tcp/4001"] };

describe("CelloNodeTransportDialer.dialDirect", () => {
  it("succeeds on the first dialable address", async () => {
    const node = new FakeCelloNode();
    const dialer = new CelloNodeTransportDialer({ node: asNode(node), relayRegistry: () => REGISTRY });
    await dialer.dialDirect("12D3KooWCounter", ["/ip4/203.0.113.50/tcp/4001", "/ip4/203.0.113.51/tcp/4001"], 5000);
    expect(node.dialed).toEqual(["/ip4/203.0.113.50/tcp/4001"]); // first-success-wins
  });

  it("tries every address and throws when all fail", async () => {
    const node = new FakeCelloNode({ dialImpl: async (a) => { throw new Error(`refused ${a}`); } });
    const dialer = new CelloNodeTransportDialer({ node: asNode(node), relayRegistry: () => REGISTRY });
    await expect(
      dialer.dialDirect("12D3KooWCounter", ["/ip4/203.0.113.50/tcp/4001", "/ip4/203.0.113.51/tcp/4001"], 5000),
    ).rejects.toThrow(/refused/);
    expect(node.dialed).toHaveLength(2);
  });

  it("throws on a per-address timeout", async () => {
    const node = new FakeCelloNode({ dialImpl: () => new Promise(() => { /* never resolves */ }) });
    const dialer = new CelloNodeTransportDialer({ node: asNode(node), relayRegistry: () => REGISTRY });
    await expect(dialer.dialDirect("12D3KooWCounter", ["/ip4/203.0.113.50/tcp/4001"], 50)).rejects.toThrow(/timed out/);
  });

  it("throws when given no addresses", async () => {
    const node = new FakeCelloNode();
    const dialer = new CelloNodeTransportDialer({ node: asNode(node), relayRegistry: () => REGISTRY });
    await expect(dialer.dialDirect("12D3KooWCounter", [], 5000)).rejects.toThrow(/no direct addresses/);
  });
});

describe("CelloNodeTransportDialer.relayCircuitAddr / dialRelay", () => {
  it("builds the circuit address from the relay registry (AC-006)", () => {
    const node = new FakeCelloNode();
    const dialer = new CelloNodeTransportDialer({ node: asNode(node), relayRegistry: () => REGISTRY });
    const addr = dialer.relayCircuitAddr(makeAssignment());
    expect(addr).toBe("/ip4/198.51.100.9/tcp/4001/p2p/12D3KooWRelay/p2p-circuit/p2p/12D3KooWCounter");
  });

  it("throws when no relay endpoint is registered", () => {
    const node = new FakeCelloNode();
    const dialer = new CelloNodeTransportDialer({ node: asNode(node), relayRegistry: () => null });
    expect(() => dialer.relayCircuitAddr(makeAssignment())).toThrow(/no relay endpoint/);
  });

  it("dialRelay dials the circuit address", async () => {
    const node = new FakeCelloNode();
    const dialer = new CelloNodeTransportDialer({ node: asNode(node), relayRegistry: () => REGISTRY });
    const circuit = dialer.relayCircuitAddr(makeAssignment());
    await dialer.dialRelay(circuit, "12D3KooWCounter");
    expect(node.dialed).toEqual([circuit]);
  });
});

describe("CelloNodeTransportDialer.attemptDcutr", () => {
  it("resolves when a direct connection appears", async () => {
    const node = new FakeCelloNode();
    const dialer = new CelloNodeTransportDialer({
      node: asNode(node),
      relayRegistry: () => REGISTRY,
      dcutrObserveTimeoutMs: 1000,
      dcutrPollIntervalMs: 10,
    });
    // Simulate libp2p's dcutr upgrade landing shortly after the call.
    setTimeout(() => node.markDirect("12D3KooWCounter"), 30);
    await expect(dialer.attemptDcutr("12D3KooWCounter")).resolves.toBeUndefined();
  });

  it("throws when no direct connection appears within the window (non-fatal upstream)", async () => {
    const node = new FakeCelloNode();
    const dialer = new CelloNodeTransportDialer({
      node: asNode(node),
      relayRegistry: () => REGISTRY,
      dcutrObserveTimeoutMs: 60,
      dcutrPollIntervalMs: 10,
    });
    await expect(dialer.attemptDcutr("12D3KooWCounter")).rejects.toThrow(/dcutr did not establish/);
  });
});
