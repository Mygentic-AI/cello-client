/**
 * DOD-NAT-REACHABILITY-1: nat-reachability.test.ts
 *
 * Inbound sessions were impossible for a NAT'd node: the standing receiver never
 * took a circuit-relay reservation, dcutr was excluded from the one node that
 * needs it (the INBOUND peer starts the upgrade — @libp2p/dcutr registers with
 * `direction !== 'inbound' → return`), and CELLO's protocols could not run over
 * the limited relayed connection a default relay hands out.
 *
 * These tests pin the transport-layer half of the fix:
 *   T1 — dcutr is present on EVERY node type, including standing_receiver.
 *   T2 — HOP relay service is gated: client nodes (session / standing_receiver)
 *        no longer advertise themselves as relays; service nodes still do, and
 *        relayServer options pass through for the real relay.
 *   T3 — the full reservation mechanics, in-process: a receiver listens on
 *        /p2p/<relay>/p2p-circuit, takes a reservation, a dialer reaches it
 *        THROUGH the relay, and a CELLO protocol stream works over the LIMITED
 *        relayed connection (default relay limits stay on in this test — this is
 *        exactly the hostile-network fallback the fix must protect).
 *
 * Run: pnpm --filter @cello-protocol/transport run test
 */

import {
  setupV3Tests,
  createTestScope,
  waitFor,
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
} from "@claude-flow/testing";
import { networkInterfaces } from "node:os";
import * as lp from "it-length-prefixed";
import { generateKeypair } from "@cello-protocol/crypto";
import { createNode, buildConfiguredHosts } from "../node.js";
import { CIRCUIT_RELAY_V2_HOP_PROTOCOL_ID } from "../protocols.js";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { CelloNode } from "../types.js";

setupV3Tests();

const DCUTR_PROTOCOL_ID = "/libp2p/dcutr";
const TEST_PROTOCOL_ID = "/cello/nat-test/1.0.0";

function makeKeyProvider(): KeyProvider {
  const inner = generateKeypair();
  return {
    getPublicKey: () => Promise.resolve(inner.getPublicKey()),
    sign: (data: Uint8Array) => Promise.resolve(inner.sign(data)),
  };
}

async function startNode(opts: Partial<Parameters<typeof createNode>[0]> = {}): Promise<CelloNode> {
  const node = await createNode({
    keyProvider: makeKeyProvider(),
    listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
    ...opts,
  });
  await node.start();
  return node;
}

// ─── T1: dcutr on every node type ────────────────────────────────────────────

describe("T1: dcutr is present on every node type (the inbound peer starts the upgrade)", () => {
  let scope = createTestScope();
  beforeEach(() => { scope = createTestScope(); });
  afterEach(() => scope.run(async () => {}));

  it("standing_receiver advertises /libp2p/dcutr — it is the node that MUST run it", async () => {
    const node = await startNode({ nodeType: "standing_receiver" });
    scope.addCleanup(async () => { try { await node.stop(); } catch { /* cleanup */ } });
    expect(node.getProtocols()).toContain(DCUTR_PROTOCOL_ID);
  });

  it("session node advertises /libp2p/dcutr (unchanged)", async () => {
    const node = await startNode({ nodeType: "session" });
    scope.addCleanup(async () => { try { await node.stop(); } catch { /* cleanup */ } });
    expect(node.getProtocols()).toContain(DCUTR_PROTOCOL_ID);
  });
});

// ─── T2: HOP relay service is gated by role ──────────────────────────────────

describe("T2: circuitRelayServer (HOP) is a service-node capability, not a client default", () => {
  let scope = createTestScope();
  beforeEach(() => { scope = createTestScope(); });
  afterEach(() => scope.run(async () => {}));

  it("standing_receiver does NOT advertise HOP — a NAT'd laptop is not a relay", async () => {
    const node = await startNode({ nodeType: "standing_receiver" });
    scope.addCleanup(async () => { try { await node.stop(); } catch { /* cleanup */ } });
    expect(node.getProtocols()).not.toContain(CIRCUIT_RELAY_V2_HOP_PROTOCOL_ID);
  });

  it("session node does NOT advertise HOP", async () => {
    const node = await startNode({ nodeType: "session" });
    scope.addCleanup(async () => { try { await node.stop(); } catch { /* cleanup */ } });
    expect(node.getProtocols()).not.toContain(CIRCUIT_RELAY_V2_HOP_PROTOCOL_ID);
  });

  it("service node (no nodeType — directory, relay) still advertises HOP: deployed-relay compatibility", async () => {
    const node = await startNode();
    scope.addCleanup(async () => { try { await node.stop(); } catch { /* cleanup */ } });
    expect(node.getProtocols()).toContain(CIRCUIT_RELAY_V2_HOP_PROTOCOL_ID);
  });

  it("relayServer options pass through — a client type with relayServer.enabled advertises HOP", async () => {
    const node = await startNode({
      nodeType: "standing_receiver",
      relayServer: { enabled: true },
    });
    scope.addCleanup(async () => { try { await node.stop(); } catch { /* cleanup */ } });
    expect(node.getProtocols()).toContain(CIRCUIT_RELAY_V2_HOP_PROTOCOL_ID);
  });

  it("relayServer.reservations reaches circuitRelayServer — maxReservations: 1 rejects the second reserver", async () => {
    // Phase 2's deployed relay depends on exactly this passthrough to lift the
    // libp2p defaults (15 reservations, 2-min/128-KiB limits). Prove the options
    // object lands: with maxReservations: 1, the first receiver reserves and the
    // second is refused. Reverting the passthrough (default 15) turns this red.
    const relay = await startNode({ relayServer: { enabled: true, reservations: { maxReservations: 1 } } });
    scope.addCleanup(async () => { try { await relay.stop(); } catch { /* cleanup */ } });
    const relayAddr = relay.listenAddresses().find((a) => a.includes("/p2p/"))!;

    const first = await startNode({
      nodeType: "standing_receiver",
      listenAddresses: ["/ip4/127.0.0.1/tcp/0", `${relayAddr}/p2p-circuit`],
    });
    scope.addCleanup(async () => { try { await first.stop(); } catch { /* cleanup */ } });
    await waitFor(() => first.listenAddresses().some((a) => a.includes("/p2p-circuit")), {
      timeout: 10_000,
      message: "first receiver never obtained its reservation",
    });

    const second = await startNode({
      nodeType: "standing_receiver",
      listenAddresses: ["/ip4/127.0.0.1/tcp/0", `${relayAddr}/p2p-circuit`],
    });
    scope.addCleanup(async () => { try { await second.stop(); } catch { /* cleanup */ } });
    await new Promise((r) => setTimeout(r, 3_000));
    expect(second.listenAddresses().some((a) => a.includes("/p2p-circuit"))).toBe(false);
  }, 25_000);
});

// ─── T3: reservation → relayed dial → CELLO stream over the LIMITED connection ─

describe("T3: circuit-relay reservation and a CELLO stream over the limited relayed connection", () => {
  let scope = createTestScope();
  beforeEach(() => { scope = createTestScope(); });
  afterEach(() => scope.run(async () => {}));

  async function relayedPair(): Promise<{ relay: CelloNode; receiver: CelloNode; dialer: CelloNode; circuitAddr: string }> {
    // The relay: a service node with HOP on and DEFAULT limits — deliberately the
    // deployed-relay configuration, so this test proves the limited-connection path.
    const relay = await startNode();
    scope.addCleanup(async () => { try { await relay.stop(); } catch { /* cleanup */ } });
    const relayAddr = relay.listenAddresses().find((a) => a.includes("/p2p/"));
    expect(relayAddr).toBeDefined();

    // The receiver: a standing_receiver listening on the relay's circuit address.
    // This IS the fix — the listen entry is what takes the reservation.
    const receiver = await startNode({
      nodeType: "standing_receiver",
      listenAddresses: ["/ip4/127.0.0.1/tcp/0", `${relayAddr}/p2p-circuit`],
    });
    scope.addCleanup(async () => { try { await receiver.stop(); } catch { /* cleanup */ } });

    // The reservation materialises as a /p2p-circuit entry in listenAddresses().
    await waitFor(() => receiver.listenAddresses().some((a) => a.includes("/p2p-circuit")), {
      timeout: 10_000,
      message: "receiver never obtained a circuit-relay reservation",
    });
    const circuitAddr = receiver.listenAddresses().find((a) => a.includes("/p2p-circuit"))!;

    const dialer = await startNode({ nodeType: "session" });
    scope.addCleanup(async () => { try { await dialer.stop(); } catch { /* cleanup */ } });
    return { relay, receiver, dialer, circuitAddr };
  }

  it("receiver reserves with the relay and is dialable at its /p2p-circuit address", async () => {
    const { receiver, dialer, circuitAddr } = await relayedPair();
    const { peerId } = await dialer.dial(circuitAddr);
    expect(peerId).toBe(receiver.getPeerId());
  }, 20_000);

  it("a CELLO protocol stream works over the limited relayed connection, both directions", async () => {
    const { receiver, dialer, circuitAddr } = await relayedPair();

    // Receiver handles a protocol — the handler must run on a LIMITED connection,
    // because a punch-failed session lives on one.
    const echoed: string[] = [];
    await receiver.handle(TEST_PROTOCOL_ID, (stream) => {
      void (async () => {
        for await (const chunk of lp.decode(stream)) {
          const raw = (chunk as unknown as { slice(): Uint8Array }).slice();
          echoed.push(Buffer.from(raw).toString("utf8"));
          stream.send(lp.encode.single(raw));
        }
      })();
    });

    await dialer.dial(circuitAddr);
    const stream = await dialer.newStream(receiver.getPeerId(), TEST_PROTOCOL_ID);
    stream.send(lp.encode.single(Buffer.from("over-the-relay", "utf8")));

    let reply = "";
    for await (const chunk of lp.decode(stream as unknown as AsyncIterable<Uint8Array>)) {
      const raw = (chunk as unknown as { slice(): Uint8Array }).slice();
      reply = Buffer.from(raw).toString("utf8");
      break;
    }
    expect(echoed).toContain("over-the-relay");
    expect(reply).toBe("over-the-relay");
  }, 20_000);

  it("hasDirectConnectionTo stays false for a relayed-only connection (dcutr observability contract)", async () => {
    const { receiver, dialer, circuitAddr } = await relayedPair();
    await dialer.dial(circuitAddr);
    // Loopback addrs are not punch candidates, so no upgrade happens in-process:
    // the relayed connection must be classified as NOT direct.
    expect(dialer.hasDirectConnectionTo(receiver.getPeerId())).toBe(false);
  }, 20_000);
});

// ─── T4: plain nodes are unaffected by the circuit-listen machinery ───────────

describe("T4: circuit listen addresses do not break plain nodes", () => {
  let scope = createTestScope();
  beforeEach(() => { scope = createTestScope(); });
  afterEach(() => scope.run(async () => {}));

  it("a standing_receiver with only a TCP listen addr still starts and reports addresses", async () => {
    const node = await startNode({ nodeType: "standing_receiver" });
    scope.addCleanup(async () => { try { await node.stop(); } catch { /* cleanup */ } });
    expect(node.listenAddresses().length).toBeGreaterThan(0);
    expect(node.listenAddresses().every((a) => !a.includes("/p2p-circuit"))).toBe(true);
  });

  it("buildConfiguredHosts does NOT expand a wildcard to interface addresses — that would mute a genuinely public host", () => {
    // A tempting 'fix' under the 0.0.0.0 default is to add every local interface
    // address to configuredHosts (so a firewalled public IP can't read dialable).
    // It is wrong: libp2p only surfaces VERIFIED addresses, and a public transport
    // address stays unverified until AutoNAT confirms it — the firewalled host never
    // offers one. Expanding here would instead suppress the address of a genuinely
    // reachable public host AFTER AutoNAT confirmed it, pinning it to dialable:false
    // forever and forcing it onto a relay it does not need. Keep the set literal.
    const hosts = buildConfiguredHosts(["/ip4/0.0.0.0/tcp/0"]);
    expect(hosts).toEqual(new Set(["0.0.0.0"]));
    const nonLoopbackIfaceAddrs = Object.values(networkInterfaces())
      .flatMap((i) => i ?? [])
      .filter((a) => a.family === "IPv4" && !a.internal)
      .map((a) => a.address);
    for (const addr of nonLoopbackIfaceAddrs) {
      expect(hosts.has(addr)).toBe(false);
    }
    // Announce addrs ARE configured (the EC2/EIP case) and stay excluded.
    expect(buildConfiguredHosts(["/ip4/0.0.0.0/tcp/4001"], ["/ip4/203.0.113.7/tcp/4001"]))
      .toEqual(new Set(["0.0.0.0", "203.0.113.7"]));
  });

  it("0.0.0.0 listen does NOT make interface addresses count as dialable — configured is not confirmed", async () => {
    // Review F1: the wildcard expands to real interface addrs in getMultiaddrs().
    // Without wildcard→interface expansion in configuredHosts, a firewalled
    // public-IP host would read dialable:true with zero AutoNAT dial-back and
    // its advertised address would suppress the working relay circuit address.
    const node = await startNode({
      nodeType: "standing_receiver",
      listenAddresses: ["/ip4/0.0.0.0/tcp/0"],
    });
    scope.addCleanup(async () => { try { await node.stop(); } catch { /* cleanup */ } });
    // Interface (non-loopback) addrs are present — the raw material for the false positive…
    expect(node.listenAddresses().some((a) => a.startsWith("/ip4/") && !a.startsWith("/ip4/127."))).toBe(true);
    // …but none of them is AutoNAT-confirmed, so dialability must stay false.
    const d = node.getDialability();
    expect(d.dialable).toBe(false);
    expect(d.publicAddr).toBeNull();
  }, 15_000);

  it("a dead relay in the listen set does not kill the node — TCP survives, no circuit addr", async () => {
    const node = await startNode({
      nodeType: "standing_receiver",
      listenAddresses: [
        "/ip4/127.0.0.1/tcp/0",
        "/ip4/127.0.0.1/tcp/59991/p2p/12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aU76ZgUriHhKust/p2p-circuit",
      ],
    });
    scope.addCleanup(async () => { try { await node.stop(); } catch { /* cleanup */ } });
    const addrs = node.listenAddresses();
    expect(addrs.length).toBeGreaterThan(0);
    expect(addrs.every((a) => !a.includes("/p2p-circuit"))).toBe(true);
  }, 15_000);
});
