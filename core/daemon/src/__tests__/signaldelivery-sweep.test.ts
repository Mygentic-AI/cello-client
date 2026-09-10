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
function harness(opts: { nodes: string[]; completeOn?: string[]; unreachable?: string[]; neverConnects?: string[] } = { nodes: [] }) {
  const conns = new Map<string, FakeConn>();
  const openVisitingConnection = vi.fn((_agent: string, _kp: unknown, _pub: string, _ep: unknown, _corr: string, nodeId: string) => {
    if (opts.unreachable?.includes(nodeId)) throw new Error(`dial failed: ${nodeId}`);
    const conn: FakeConn = { handlers: [], stopped: false };
    conns.set(nodeId, conn);
    const mgr = {
      status: opts.neverConnects?.includes(nodeId) ? "reconnecting" : "connected",
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

  it("a sweep that never finishes does not starve the other reconnect work", async () => {
    // WHAT THIS CAN AND CANNOT PROVE, stated because the first version of this test proved nothing.
    // The transport calls `onConnected` fire-and-forget (`this._onConnected?.()`, typed `() => void`,
    // return ignored), so "the sweep does not delay stream auth" is guaranteed by the transport's
    // own contract and CANNOT be violated from here — asserting it was unfalsifiable.
    //
    // What IS falsifiable is the ordering inside the callback: awaiting the sweep before the
    // submission retry would mean a wedged sweep silently stops sealed submissions being re-sent,
    // and nothing would say so. That is the real risk and it is what this holds.
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
    const nop = () => {};
    const retried = vi.fn();
    const wiring = createSignalingWiring({
      // Never settles.
      getSweepTrustSignals: () => () => new Promise(() => {}),
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
      submissionRetries: { onSignalingConnected: retried } as never,
      noSharedDirectoryNode: true, sharedSignaling: undefined,
    } as never);

    (wiring as unknown as { getAgentSignaling: (n: string, k: unknown, p: string) => unknown })
      .getAgentSignaling("alice", {} as never, "a".repeat(64));

    onConnected?.();
    // Reverting to `await sweep(...)` placed before this call leaves it at zero, forever.
    expect(retried).toHaveBeenCalledWith("alice");
  });
});

describe("043-SIGNALDELIVERY C2 — review fixes", () => {
  it("names a DECLARED node that never resolved, which is the only way a dead node shows up", async () => {
    // The roster is already the REACHABLE SUBSET — a node whose /bootstrap probe failed is dropped
    // before the sweep sees it. Without asking for the unresolved list, a dead node appeared in no
    // bucket at all and the sweep reported "visited 2, unreachable 0" on a three-node fleet: the
    // operator told nothing was waiting when nobody looked.
    const h = harness({ nodes: [], completeOn: ["b"] });
    const sweep = createTrustSignalSweep({
      logger: silent,
      resolveConsortiumRoster: async () => ROSTER(["a", "b"]),
      getUnresolvedNodes: () => [{ nodeId: "c", reason: "probe_timeout" }],
      openVisitingConnection: h.openVisitingConnection as never,
      ceilingMs: 200,
    });
    const result = await sweep("alice", {} as never, "a".repeat(64), "a");
    expect(result.visited).toEqual(["b"]);
    expect(result.unreachable).toEqual(["c"]);
  });

  it("calls a node that never connected UNREACHABLE, not incomplete", async () => {
    // openVisitingConnection connects asynchronously and does not throw on a dial failure, so this
    // node sits out the full ceiling. Filing it as "answered but never finished" names the
    // directory's drain for what is a transport failure — an exit-point label an operator would act
    // on, sending them to the wrong system.
    const h = harness({ nodes: [], completeOn: [], neverConnects: ["b"] });
    const sweep = createTrustSignalSweep({
      logger: silent,
      resolveConsortiumRoster: async () => ROSTER(["a", "b"]),
      openVisitingConnection: h.openVisitingConnection as never,
      ceilingMs: 20,
    });
    const result = await sweep("alice", {} as never, "a".repeat(64), "a");
    expect(result.unreachable).toEqual(["b"]);
    expect(result.incomplete).toEqual([]);
  });

  it("closes the connection even when registering the handler throws", async () => {
    // A throw between opening and closing leaves an AUTHENTICATED visiting stream open, and the
    // directory drains its durable notification queue down any such stream — the bug this
    // connection type has already caused once.
    let stopped = false;
    const sweep = createTrustSignalSweep({
      logger: silent,
      resolveConsortiumRoster: async () => ROSTER(["a", "b"]),
      openVisitingConnection: (() => ({
        mgr: { status: "connected", registerInboundHandler: () => { throw new Error("wiring blew up"); } },
        stop: async () => { stopped = true; },
      })) as never,
      ceilingMs: 50,
    });
    await sweep("alice", {} as never, "a".repeat(64), "a").catch(() => {});
    expect(stopped).toBe(true);
  });

  it("does not run a second sweep for an agent while one is in flight", async () => {
    // onConnected fires on every reconnect. A flapping stream would otherwise stack sweeps, each
    // holding N authenticated visiting streams and re-triggering every node's drain — load arriving
    // exactly when the network is already struggling.
    const h = harness({ nodes: [], completeOn: [] });
    const sweep = createTrustSignalSweep({
      logger: silent,
      resolveConsortiumRoster: async () => ROSTER(["a", "b"]),
      openVisitingConnection: h.openVisitingConnection as never,
      ceilingMs: 100,
    });
    const [first, second] = await Promise.all([
      sweep("alice", {} as never, "a".repeat(64), "a"),
      sweep("alice", {} as never, "a".repeat(64), "a"),
    ]);
    const opened = h.openVisitingConnection.mock.calls.length;
    expect(opened).toBe(1);
    // The one that was turned away says nothing was swept rather than claiming a clean result.
    expect(first.incomplete.length + second.incomplete.length).toBe(1);
  });
});

describe("048-SWEEPTICK — a steady-state problem is stated once, not every five minutes", () => {
  it("WARNS a node's first bad sweep and DEBUGS the identical repeat, while the RESULT is unchanged", async () => {
    /**
     * This module was written for a once-per-connection cadence. Since 048 it runs every five
     * minutes for the life of the daemon, so a node that is delisted but still declared in the
     * manifest went from two warns a day to roughly 1,150 — and the next incident is found by
     * grepping `daemon.log`. A warning that fires on a steady state has stopped being a signal.
     *
     * What must NOT change is the answer: the buckets the caller receives are identical either way.
     * Demoting a log line is not the same as deciding a node is fine, and that is the whole risk in
     * this change.
     */
    const warns: string[] = [];
    const debugs: string[] = [];
    const logger = {
      info: () => {}, error: () => {},
      warn: (event: string) => { warns.push(event); },
      debug: (event: string) => { debugs.push(event); },
    } as never;
    const h = harness({ nodes: ["a"], completeOn: ["a"] });
    const sweep = createTrustSignalSweep({
      logger,
      resolveConsortiumRoster: async () => ROSTER(["a"]),
      openVisitingConnection: h.openVisitingConnection as never,
      getUnresolvedNodes: () => [{ nodeId: "dead", reason: "bootstrap probe failed" }],
      ceilingMs: 100,
    });

    const first = await sweep("alice", {} as never, "a".repeat(64));
    expect(warns.filter((e) => e === "trust_signal.sweep.node_unreachable"), "first time: warn").toHaveLength(1);

    warns.length = 0; debugs.length = 0;
    const second = await sweep("alice", {} as never, "a".repeat(64));
    expect(warns, "same problem five minutes later: nothing at warn").toHaveLength(0);
    expect(debugs.filter((e) => e === "trust_signal.sweep.node_unreachable"), "still recorded, at debug").toHaveLength(1);

    // THE ANSWER IS THE SAME. The dead node is still reported unreachable to the caller on both
    // runs — the quieting is about the log, never about the verdict.
    expect(first.unreachable, "first").toEqual(["dead"]);
    expect(second.unreachable, "second — a quieter log is not a cleaner result").toEqual(["dead"]);
  });

  it("warns AGAIN when the problem set changes", async () => {
    // The dedup keys on the problem set, so a node going bad after a clean run must still shout.
    const warns: string[] = [];
    const logger = {
      info: () => {}, error: () => {}, debug: () => {},
      warn: (event: string) => { warns.push(event); },
    } as never;
    const h = harness({ nodes: ["a"], completeOn: ["a"] });
    let dead: { nodeId: string; reason: string }[] = [];
    const sweep = createTrustSignalSweep({
      logger,
      resolveConsortiumRoster: async () => ROSTER(["a"]),
      openVisitingConnection: h.openVisitingConnection as never,
      getUnresolvedNodes: () => dead,
      ceilingMs: 100,
    });

    await sweep("alice", {} as never, "a".repeat(64));          // clean
    expect(warns).toHaveLength(0);
    dead = [{ nodeId: "b", reason: "gone" }];
    await sweep("alice", {} as never, "a".repeat(64));          // newly bad
    expect(warns.filter((e) => e === "trust_signal.sweep.node_unreachable"), "a change still shouts").toHaveLength(1);
  });
});
