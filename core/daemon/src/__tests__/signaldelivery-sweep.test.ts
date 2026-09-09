/**
 * 043-SIGNALDELIVERY C2 (daemon half) — collect from every node, not just the one we happen to be on.
 *
 * The portal now delivers a signal to the node that holds the agent, and a directory pushes it down
 * a live stream. Neither helps a signal that was parked at a node this daemon is not connected to:
 * `pickup_queue` is deliberately node-local and does NOT replicate, so nothing brings it to us. The
 * only thing that collects it is a stream authenticating AT that node, because the drain runs on
 * auth.
 *
 * Until C1 that was impossible; now it is merely incidental — it happens if you happen to start a
 * session with someone on that node. This makes it deterministic.
 */
import { describe, it, expect, vi } from "vitest";
import { createTrustSignalSweep } from "../trust-signal-sweep.js";

const noop = () => {};
const silent = { debug: noop, info: noop, warn: noop, error: noop } as never;

interface FakeConn {
  handlers: ((f: Record<string, unknown>) => void)[];
  stopped: boolean;
}

/**
 * One visiting connection per node. `completeOn` decides which nodes send the terminal frame; the
 * rest stay silent, which is what a slow or wedged node looks like from here.
 */
function harness(opts: { nodes: string[]; completeOn?: string[]; unreachable?: string[] } = { nodes: [] }) {
  const conns = new Map<string, FakeConn>();
  const openVisitingConnection = vi.fn((_agent: string, _kp: unknown, _pub: string, _ep: unknown, _corr: string, nodeId: string) => {
    if (opts.unreachable?.includes(nodeId)) throw new Error(`dial failed: ${nodeId}`);
    const conn: FakeConn = { handlers: [], stopped: false };
    conns.set(nodeId, conn);
    const mgr = {
      registerInboundHandler(h: (f: Record<string, unknown>) => void) {
        conn.handlers.push(h);
        // A node that completes answers as soon as anyone starts listening.
        if (opts.completeOn?.includes(nodeId)) {
          queueMicrotask(() => h({ type: "trust_signal_drain_complete", count: 0 }));
        }
      },
    };
    return { mgr, stop: async () => { conn.stopped = true; } };
  });
  return { conns, openVisitingConnection };
}

const ROSTER = (ids: string[]) =>
  ids.map((nodeId) => ({ nodeId, pubkey: "p", peerId: "pid", multiaddr: "/m" }));

describe("043-SIGNALDELIVERY C2 — background collection sweep", () => {
  it("visits every node EXCEPT the one already connected", async () => {
    // The home stream drains inline on its own auth. Re-visiting it would open a second
    // authenticated connection to a node we are already on, for nothing.
    const h = harness({ nodes: [], completeOn: ["b", "c"] });
    const sweep = createTrustSignalSweep({
      logger: silent,
      resolveConsortiumRoster: async () => ROSTER(["a", "b", "c"]),
      openVisitingConnection: h.openVisitingConnection as never,
      ceilingMs: 500,
    });

    const result = await sweep("alice", {} as never, "a".repeat(64), "a");
    expect(h.openVisitingConnection.mock.calls.map((c) => c[5]).sort()).toEqual(["b", "c"]);
    expect(result.visited.sort()).toEqual(["b", "c"]);
    expect(result.unreachable).toEqual([]);
  });

  it("closes a connection as soon as the node says the drain is finished", async () => {
    const h = harness({ nodes: [], completeOn: ["b"] });
    const sweep = createTrustSignalSweep({
      logger: silent,
      resolveConsortiumRoster: async () => ROSTER(["a", "b"]),
      openVisitingConnection: h.openVisitingConnection as never,
      // A ceiling long enough that reaching it would fail the test rather than pass it slowly.
      ceilingMs: 10_000,
    });
    const started = Date.now();
    await sweep("alice", {} as never, "a".repeat(64), "a");
    expect(Date.now() - started).toBeLessThan(2_000);
    expect(h.conns.get("b")?.stopped).toBe(true);
  });

  it("gives up on a silent node at the ceiling rather than hanging forever", async () => {
    const h = harness({ nodes: [], completeOn: [] });
    const sweep = createTrustSignalSweep({
      logger: silent,
      resolveConsortiumRoster: async () => ROSTER(["a", "b"]),
      openVisitingConnection: h.openVisitingConnection as never,
      ceilingMs: 50,
    });
    const result = await sweep("alice", {} as never, "a".repeat(64), "a");
    expect(h.conns.get("b")?.stopped).toBe(true);
    // Reached its ceiling without a terminal frame: we do not know we got everything, so the node
    // is reported as incomplete rather than as swept clean.
    expect(result.incomplete).toEqual(["b"]);
  });

  it("names a node it could not reach — never reports it as nothing waiting", async () => {
    // Collapsing a dial failure into an empty result lets ONE down node manufacture a false
    // negative: the operator is told there is nothing to collect when nobody looked.
    const h = harness({ nodes: [], completeOn: ["b"], unreachable: ["c"] });
    const sweep = createTrustSignalSweep({
      logger: silent,
      resolveConsortiumRoster: async () => ROSTER(["a", "b", "c"]),
      openVisitingConnection: h.openVisitingConnection as never,
      ceilingMs: 500,
    });
    const result = await sweep("alice", {} as never, "a".repeat(64), "a");
    expect(result.unreachable).toEqual(["c"]);
    expect(result.visited).toEqual(["b"]);
  });

  it("one node being down does not stop the others being swept", async () => {
    const h = harness({ nodes: [], completeOn: ["b", "d"], unreachable: ["c"] });
    const sweep = createTrustSignalSweep({
      logger: silent,
      resolveConsortiumRoster: async () => ROSTER(["a", "b", "c", "d"]),
      openVisitingConnection: h.openVisitingConnection as never,
      ceilingMs: 500,
    });
    const result = await sweep("alice", {} as never, "a".repeat(64), "a");
    expect(result.visited.sort()).toEqual(["b", "d"]);
    expect(result.unreachable).toEqual(["c"]);
  });

  it("does nothing when the roster cannot be resolved, and says so", async () => {
    // No hardcoded node list anywhere in this path — the fleet is going to five. An unresolvable
    // roster means we do not know who to ask, which is not the same as nobody having anything.
    const h = harness({ nodes: [] });
    const sweep = createTrustSignalSweep({
      logger: silent,
      resolveConsortiumRoster: async () => null,
      openVisitingConnection: h.openVisitingConnection as never,
      ceilingMs: 500,
    });
    const result = await sweep("alice", {} as never, "a".repeat(64), "a");
    expect(h.openVisitingConnection).not.toHaveBeenCalled();
    expect(result.rosterUnavailable).toBe(true);
  });

  it("sweeps a FOUR-node manifest without a code change", async () => {
    const h = harness({ nodes: [], completeOn: ["b", "c", "d"] });
    const sweep = createTrustSignalSweep({
      logger: silent,
      resolveConsortiumRoster: async () => ROSTER(["a", "b", "c", "d"]),
      openVisitingConnection: h.openVisitingConnection as never,
      ceilingMs: 500,
    });
    const result = await sweep("alice", {} as never, "a".repeat(64), "a");
    expect(result.visited.sort()).toEqual(["b", "c", "d"]);
  });
});

/**
 * The wiring half. A sweep that works in isolation and is never triggered is the same defect this
 * whole order is about — a correct mechanism production does not call. Asserted through the real
 * `createSignalingWiring`, by driving the manager's onConnected the way the transport does.
 */
describe("043-SIGNALDELIVERY C2 — the sweep is actually triggered on connect", () => {
  it("runs in the background when a home stream connects", async () => {
    const transport = await import("@cello-protocol/transport");
    let onConnected: (() => void) | undefined;
    const fakeMgr = {
      registerInboundHandler() {}, stop: async () => {}, send: async () => {},
      sendRaw: async () => {}, onStatusChange: () => {}, start: async () => {}, status: "connected",
    };
    vi.spyOn(transport, "SignalingManager").mockImplementation((opts: never) => {
      onConnected = (opts as unknown as { onConnected?: () => void }).onConnected;
      return fakeMgr as never;
    });

    const { createSignalingWiring } = await import("../signaling-wiring.js");
    const sweep = vi.fn(async () => ({}));
    const nop = () => {};
    const wiring = createSignalingWiring({
      getSweepTrustSignals: () => sweep,
      getHandleTrustSignalPickup: () => async () => {},
      logger: { debug: nop, info: nop, warn: nop, error: nop },
      loadedAgents: new Map(), keyProviders: new Map(), perAgentSignaling: new Map(),
      sessionNodeManager: { getSetting: () => undefined, hasDatabase: () => false } as never,
      getPersistence: () => ({}) as never,
      resolveConsortiumRoster: async () => [],
      getFailoverEndpoint: () => ({ url: "http://d", peerId: "p", multiaddr: "/m" }),
      failoverEndpointResolver: {} as never, directoryEndpointResolver: {} as never,
      challengeVerifier: {} as never, registerSealListeners: () => () => {},
      getWirePerAgentSessionInbound: () => () => {},
      onSignalingConnected: nop, verifiedManifestVersion: 1,
      sealFailures: {} as never,
      submissionRetries: { onSignalingConnected: nop } as never,
      noSharedDirectoryNode: true, sharedSignaling: undefined,
    } as never);

    (wiring as unknown as { getAgentSignaling: (n: string, k: unknown, p: string) => unknown })
      .getAgentSignaling("alice", {} as never, "a".repeat(64));

    expect(typeof onConnected).toBe("function");
    // THE REVERT TEST: delete the sweep call from onConnected and this stays at zero — which is
    // the state before this unit, where signals parked elsewhere were collected only by accident.
    onConnected?.();
    expect(sweep).toHaveBeenCalledOnce();
    expect(sweep.mock.calls[0][0]).toBe("alice");
  });
});
