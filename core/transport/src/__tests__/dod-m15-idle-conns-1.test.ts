/**
 * DOD-M15-IDLE-CONNS-1 — a connection that authenticates to nothing does not live forever.
 *
 * ─── WHAT THE DoD LINE SAID, AND WHAT FALSIFICATION FOUND (→ Entry S3) ─────────────────────────
 *
 * The line describes "a stranger dials the standing receiver (which accepts everyone by design)".
 * That has not been true since `DOD-M15-ASSIGN-1`: `session-connection-gater.ts` refuses every
 * inbound dial while `#allowedPeerId` is null, and an offer narrows the gate to ONE peer before
 * this side advertises its address. A stranger cannot hold a connection at all.
 *
 * Inbound flooding is bounded too — by defaults NOBODY CHOSE. Measured in libp2p@3.3.2
 * (`connection-manager/constants*.js`), because the line says do not guess:
 *
 *     maxConnections 300 · inboundConnectionThreshold 5 · maxIncomingPendingConnections 10
 *     inboundUpgradeTimeout 10_000ms
 *
 * `createNode` passes NO `connectionManager` block, so all four are inherited. That is the real
 * defect in this half: a libp2p minor bump silently re-prices the entire posture and nothing here
 * goes red.
 *
 * What genuinely remains is an ADMITTED peer — one an offer already named — that connects and
 * opens no stream, forever, because nothing reaps it.
 *
 * ─── WHY THESE TESTS ARE SHAPED THE WAY THEY ARE ───────────────────────────────────────────────
 *
 * The hollow shape here is easy to write and useless: assert "an idle connection was closed" and
 * the test passes with a reaper that also kills the relay reservation — which costs the agent its
 * inbound reachability, the one property this milestone must not trade away. So I3 exists only to
 * be the thing I4 cannot pass by accident.
 *
 * And the wiring seam is tested from BOTH sides, because four consecutive units in this milestone
 * shipped a green module with nothing proving the daemon called it: I1/I2 pin the policy object,
 * I5 proves a REAL node with a REAL connection actually reaps.
 */
import { describe, it, expect, afterEach } from "vitest";
import { generateKeypair } from "@cello-protocol/crypto";
import {
  createNode,
  resolveConnectionLimits,
  selectIdleConnections,
  IDLE_CONNECTION_GRACE_MS,
  DECLARED_MAX_CONNECTIONS,
  DECLARED_INBOUND_CONNECTION_THRESHOLD,
  DECLARED_MAX_INCOMING_PENDING,
  DECLARED_INBOUND_UPGRADE_TIMEOUT_MS,
} from "../node.js";
import type { CelloNode } from "../types.js";

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function waitUntil(fn: () => boolean, timeoutMs: number, everyMs = 50): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fn()) return true;
    await wait(everyMs);
  }
  return fn();
}

const started: CelloNode[] = [];
afterEach(async () => {
  await Promise.all(started.splice(0).map((n) => n.stop().catch(() => undefined)));
});
async function start(opts: Parameters<typeof createNode>[0]): Promise<CelloNode> {
  const n = await createNode(opts);
  await n.start();
  started.push(n);
  return n;
}

describe("I1: the connection posture is DECLARED, not inherited", () => {
  it("resolves every inbound knob to a value this repo names", () => {
    // The point is not the numbers — it is that they exist HERE. Before this unit `createNode`
    // passed no connectionManager block at all, so a libp2p upgrade could change any of them and
    // no test in this repo would notice. These four are the ones an unauthenticated peer can spend.
    const limits = resolveConnectionLimits({});
    expect(limits.maxConnections).toBe(DECLARED_MAX_CONNECTIONS);
    expect(limits.inboundConnectionThreshold).toBe(DECLARED_INBOUND_CONNECTION_THRESHOLD);
    expect(limits.maxIncomingPendingConnections).toBe(DECLARED_MAX_INCOMING_PENDING);
    expect(limits.inboundUpgradeTimeout).toBe(DECLARED_INBOUND_UPGRADE_TIMEOUT_MS);
  });

  it("lets a caller override a limit without silently dropping the others", () => {
    // A relay carries far more connections than an operator's laptop, so the override has to work
    // — and an override that returned ONLY the overridden key would re-inherit the rest, which is
    // the defect this unit exists to remove, reintroduced by the fix for it.
    const limits = resolveConnectionLimits({ connectionLimits: { maxConnections: 2000 } });
    expect(limits.maxConnections).toBe(2000);
    expect(limits.inboundConnectionThreshold).toBe(DECLARED_INBOUND_CONNECTION_THRESHOLD);
    expect(limits.maxIncomingPendingConnections).toBe(DECLARED_MAX_INCOMING_PENDING);
  });
});

describe("I2: the node reports the SAME policy object libp2p was given", () => {
  it("does not let the reported policy drift from the configured one", async () => {
    // Copied deliberately from resolveConnectionMonitorConfig's comment: "what libp2p is configured
    // with is what the node reports, by construction rather than by two call sites agreeing."
    // Asserting equality of two independently-built objects would pass while they drift.
    const node = await start({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      nodeType: "session",
      connectionLimits: { maxConnections: 42 },
    });
    expect(node.getConnectionLimits().maxConnections).toBe(42);
  });
});

describe("I2b: the declared limits actually REACH libp2p", () => {
  /**
   * WRITTEN BECAUSE MUTATION TESTING CAUGHT ITS ABSENCE. Deleting `connectionManager:
   * connectionLimits` from the `createLibp2p` call left all eleven other tests green — I2 asserts
   * the NODE reports the policy, which is true of a node that never handed it to anybody. The
   * entire claim of this half of the unit ("declared, not inherited") had no test behind it, and
   * that is the fifth consecutive unit in this milestone to ship a module nothing proved was
   * called.
   *
   * So this asserts the OUTCOME, not the shadow: set maxConnections to 1, dial in twice, and watch
   * libp2p enforce it. If the block stops being passed, the limit reverts to 300 and both
   * connections survive.
   */
  it("enforces inboundConnectionThreshold — proving libp2p got the block, not just that we kept a copy", async () => {
    /**
     * `inboundConnectionThreshold` is the right knob to prove this on: it is the one an
     * unauthenticated peer spends directly, and it is enforced at ACCEPT time
     * (`connection-manager/index.js` — `inboundConnectionRateLimiter.consume(host)` → refuse),
     * before the Noise handshake, so the outcome is a dial that fails rather than a connection
     * that is later cleaned up.
     *
     * NOT `maxConnections`: pruning there runs through `safelyCloseConnectionIfUnused`, and a
     * just-opened connection is still carrying identify, so a low cap does not deterministically
     * shed a fresh connection. My first version of this test assumed it did, went red at baseline
     * and GREEN under the mutation — an assertion that measured libp2p's pruning policy rather
     * than whether our block arrived.
     */
    const listener = await start({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      nodeType: "session",
      connectionLimits: { inboundConnectionThreshold: 1 },
    });
    const addr = listener.listenAddresses().find((a) => a.includes("/p2p/"));
    if (!addr) throw new Error("listener has no addressed multiaddr");

    const dialOnce = async (): Promise<boolean> => {
      const dialer = await start({
        keyProvider: generateKeypair(),
        listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
        nodeType: "session",
      });
      try {
        await dialer.dial(addr);
        return true;
      } catch {
        return false;
      }
    };

    // First inbound from 127.0.0.1 consumes the single point the threshold allows.
    expect(await dialOnce(), "the first inbound dial should be admitted").toBe(true);
    // Everything else from the same host inside the window is refused before Noise. With the block
    // unpassed the threshold reverts to libp2p's 5 and all of these are admitted.
    const laterAdmitted = [await dialOnce(), await dialOnce(), await dialOnce()].filter(Boolean).length;
    expect(
      laterAdmitted,
      `inboundConnectionThreshold: 1 was not enforced — ${laterAdmitted} of 3 further dials from ` +
        `the same host were admitted, so the connectionManager block never reached libp2p`,
    ).toBe(0);
  });
});

describe("I3: a connection carries what a reaper needs to judge it", () => {
  it("reports direction, open time and live stream count per connection", async () => {
    const listener = await start({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      nodeType: "session",
    });
    const dialer = await start({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      nodeType: "session",
    });
    const addr = listener.listenAddresses().find((a) => a.includes("/p2p/"));
    if (!addr) throw new Error("listener has no addressed multiaddr");
    await dialer.dial(addr);
    await waitUntil(() => listener.getConnections().length > 0, 5000);

    const [inbound] = listener.getConnections();
    expect(inbound, "listener saw no connection").toBeDefined();
    // Named values, not "it did not fail" — the shadow assertion this milestone keeps catching.
    expect(inbound!.direction).toBe("inbound");
    expect(typeof inbound!.openedAt).toBe("number");
    expect(inbound!.openedAt).toBeGreaterThan(0);
    expect(inbound!.streamCount).toBe(0);

    const [outbound] = dialer.getConnections();
    expect(outbound!.direction).toBe("outbound");
  });
});

describe("I4: the reaper closes a silent peer and SPARES the ones reachability depends on", () => {
  const base = { id: "c1", direction: "inbound" as const, streamCount: 0, openedAt: 0 };
  /** Default: nothing has ever spoken. Tests that care override it. */
  const neverSpoke = () => false;

  it("selects an inbound connection that has opened no stream past the grace period", () => {
    const now = 60_000;
    const picked = selectIdleConnections({
      connections: [{ ...base, id: "c-silent", peerId: "silent", openedAt: now - IDLE_CONNECTION_GRACE_MS - 1 }],
      now,
      isSpared: () => false,
      hasEverCarriedStream: neverSpoke,
    });
    expect(picked).toEqual(["silent"]);
  });

  it("does NOT select a connection that is carrying a stream, however old", () => {
    const now = 10_000_000;
    const picked = selectIdleConnections({
      connections: [{ ...base, id: "c-busy", peerId: "busy", openedAt: 0, streamCount: 1 }],
      now,
      isSpared: () => false,
      hasEverCarriedStream: neverSpoke,
    });
    expect(picked).toEqual([]);
  });

  it("does NOT select a connection still inside the grace period", () => {
    const now = 60_000;
    const picked = selectIdleConnections({
      connections: [{ ...base, id: "c-new", peerId: "new", openedAt: now - IDLE_CONNECTION_GRACE_MS + 1 }],
      now,
      isSpared: () => false,
      hasEverCarriedStream: neverSpoke,
    });
    expect(picked).toEqual([]);
  });

  /**
   * THE CLAUSE THIS UNIT IS MOST LIKELY TO GET WRONG (C5, and the hollow-test guard).
   *
   * A relay reservation connection is idle BY NATURE — it carries no stream between refreshes,
   * which is precisely the shape the reaper hunts. Reaping it costs the agent every NAT'd inbound
   * session it would otherwise have received, and the operator sees "nobody can reach me" with no
   * error anywhere. A reaper that passes the three tests above and fails this one is worse than no
   * reaper at all, because it trades the property this milestone is forbidden to trade.
   */
  it("does NOT select a spared peer — the relay we hold a reservation with", () => {
    const now = 10_000_000;
    const picked = selectIdleConnections({
      connections: [
        { ...base, id: "c-relay", peerId: "relay", openedAt: 0 },
        { ...base, id: "c-stranger", peerId: "stranger", openedAt: 0 },
      ],
      now,
      isSpared: (p) => p === "relay",
      hasEverCarriedStream: neverSpoke,
    });
    expect(picked).toEqual(["stranger"]);
  });

  it("does NOT select OUTBOUND connections — this node chose those", () => {
    // Outbound is an errand this agent started (content-park deposit, restart-seal submit). Reaping
    // it would cancel our own work to bound someone else's, and the gater already makes the same
    // inbound/outbound distinction for the same reason.
    const now = 10_000_000;
    const picked = selectIdleConnections({
      connections: [{ ...base, id: "c-errand", peerId: "errand", direction: "outbound", openedAt: 0 }],
      now,
      isSpared: () => false,
      hasEverCarriedStream: neverSpoke,
    });
    expect(picked).toEqual([]);
  });
});

describe("I4b: a connection that HAS spoken is never a candidate again", () => {
  /**
   * THE TEST WHOSE ABSENCE LET THE DEFECT THROUGH, and review found it by RUNNING the reaper: with
   * a 1000ms grace and a stream exchanged every 400ms, the connection was hung up at t≈1200ms and
   * the next send failed with `No open connection to peer`.
   *
   * The cause was that the predicate compared `now - openedAt` and ANDed it with "zero streams at
   * this instant". CELLO content streams are per-message and ephemeral — one stream per frame — so
   * a busy session sits at zero streams almost all of the time. The old I5 test hid this by holding
   * ONE stream open for the entire window, which is the shape no real session ever has.
   */
  const base = { id: "c1", direction: "inbound" as const, streamCount: 0, openedAt: 0 };

  it("spares a connection that carried a stream earlier and is quiet NOW", () => {
    const picked = selectIdleConnections({
      connections: [{ ...base, id: "c-chatty", peerId: "counterparty" }],
      now: 10_000_000,
      isSpared: () => false,
      // It spoke once, at some point. That is the whole question.
      hasEverCarriedStream: (id) => id === "c-chatty",
    });
    expect(picked, "a connection that has spoken was reaped for being quiet").toEqual([]);
  });

  it("still reaps a sibling connection to the SAME peer that never spoke", () => {
    // The bit is per CONNECTION, not per peer — otherwise one live connection would shelter any
    // number of dead ones opened by the same peer.
    const picked = selectIdleConnections({
      connections: [
        { ...base, id: "c-spoke", peerId: "p" },
        { ...base, id: "c-silent", peerId: "p" },
      ],
      now: 10_000_000,
      isSpared: () => false,
      hasEverCarriedStream: (id) => id === "c-spoke",
    });
    expect(picked).toEqual(["p"]);
  });

  it("returns each peer once even when several of its connections qualify", () => {
    // `hangUp` is peer-scoped, so duplicates would hang the same peer up twice and double-count in
    // whatever the caller reports.
    const picked = selectIdleConnections({
      connections: [
        { ...base, id: "a", peerId: "p" },
        { ...base, id: "b", peerId: "p" },
      ],
      now: 10_000_000,
      isSpared: () => false,
      hasEverCarriedStream: () => false,
    });
    expect(picked).toEqual(["p"]);
  });

  it("reaps exactly AT the grace boundary, not one tick later", () => {
    // The boundary tests either side used GRACE ± 1, so flipping `>=` to `>` survived both.
    const now = 1_000_000;
    const picked = selectIdleConnections({
      connections: [{ ...base, id: "c-exact", peerId: "p", openedAt: now - IDLE_CONNECTION_GRACE_MS }],
      now,
      isSpared: () => false,
      hasEverCarriedStream: () => false,
    });
    expect(picked).toEqual(["p"]);
  });
});

describe("I5: the reaper is WIRED — a real node closes a real idle connection", () => {
  /**
   * The seam four consecutive units in this milestone got wrong: a green policy module with
   * nothing proving the node calls it. I4 tests the judgement; this tests that anything runs it.
   * Delete the sweep's scheduling and I4 stays green while this goes red.
   */
  it("drops an inbound connection that never opens a stream", async () => {
    const listener = await start({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      nodeType: "session",
      idleConnectionReaper: { graceMs: 300, sweepIntervalMs: 100 },
    });
    const dialer = await start({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      nodeType: "session",
    });
    const addr = listener.listenAddresses().find((a) => a.includes("/p2p/"));
    if (!addr) throw new Error("listener has no addressed multiaddr");
    await dialer.dial(addr);
    expect(await waitUntil(() => listener.getConnections().length > 0, 5000)).toBe(true);

    const closed = await waitUntil(() => listener.getConnections().length === 0, 5000);
    expect(closed, "the idle inbound connection was never reaped").toBe(true);
  });

  it("leaves a connection alone that carried a stream and then went QUIET — the real session shape", async () => {
    /**
     * THE PROBE REVIEW RAN, AS A TEST. This is what a CELLO conversation actually looks like: a
     * stream per message, opened and closed, with silence in between. The previous version of this
     * suite only covered a stream held open for the whole window — a shape no session ever has —
     * and the reaper hung up a live conversation at t≈1200ms with a 1000ms grace.
     *
     * Reverting the `hasEverCarriedStream` clause turns this red while every other test stays
     * green, which is precisely the coverage that was missing.
     */
    const PROTO = "/cello/idle-quiet/1.0.0";
    const listener = await start({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      nodeType: "session",
      idleConnectionReaper: { graceMs: 300, sweepIntervalMs: 100 },
    });
    await listener.handle(PROTO, async () => {});
    const dialer = await start({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      nodeType: "session",
    });
    const addr = listener.listenAddresses().find((a) => a.includes("/p2p/"));
    if (!addr) throw new Error("listener has no addressed multiaddr");
    const peerId = (await dialer.dial(addr)).peerId;

    // One message, then close it — exactly what `newStream` does per frame.
    const stream = await dialer.newStream(peerId, PROTO);
    await stream.close();
    expect(await waitUntil(() => listener.getConnections().length > 0, 5000)).toBe(true);

    // Now go quiet for well past the grace, with many sweeps in between.
    await wait(1500);
    expect(
      listener.getConnections().length,
      "a connection that had already carried a stream was reaped for going quiet — this is the " +
        "defect that killed a live conversation",
    ).toBeGreaterThan(0);
  });

  it("tells somebody when it reaps — the guard is heard", async () => {
    // Invariant 2: a hang-up nobody hears is indistinguishable from the thing not happening, and
    // the operator is left reading `no_connection` with nothing naming the local timer.
    const seen: Array<{ peerId: string; reason: string }> = [];
    const listener = await start({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      nodeType: "session",
      idleConnectionReaper: {
        graceMs: 300,
        sweepIntervalMs: 100,
        onReaped: (e) => { seen.push({ peerId: e.peerId, reason: e.reason }); },
      },
    });
    const dialer = await start({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      nodeType: "session",
    });
    const addr = listener.listenAddresses().find((a) => a.includes("/p2p/"));
    if (!addr) throw new Error("listener has no addressed multiaddr");
    await dialer.dial(addr);

    expect(await waitUntil(() => seen.length > 0, 5000), "nothing was told about the reap").toBe(true);
    // Name the value — "it was called" is the shadow.
    expect(seen[0]!.reason).toBe("never_carried_a_stream");
    expect(seen[0]!.peerId).toBe(dialer.getPeerId());
  });

  it("reports the connection census every sweep — the count the DoD asks for", async () => {
    // C4. Exposing the CAPS without the COUNT would be a capability nothing reads.
    const counts: Array<{ total: number; inbound: number; neverSpoke: number }> = [];
    const listener = await start({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      nodeType: "session",
      idleConnectionReaper: {
        graceMs: 60_000, // long, so nothing is reaped while we watch
        sweepIntervalMs: 100,
        onObserved: (c) => { counts.push({ total: c.total, inbound: c.inbound, neverSpoke: c.neverSpoke }); },
      },
    });
    const dialer = await start({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      nodeType: "session",
    });
    const addr = listener.listenAddresses().find((a) => a.includes("/p2p/"));
    if (!addr) throw new Error("listener has no addressed multiaddr");
    await dialer.dial(addr);

    expect(await waitUntil(() => counts.some((c) => c.inbound === 1), 5000)).toBe(true);
    const observed = counts.find((c) => c.inbound === 1)!;
    expect(observed.total).toBeGreaterThanOrEqual(1);
    expect(observed.neverSpoke).toBe(1);
  });

  it("stops sweeping once the node is stopped", async () => {
    // A timer that outlives its node keeps a "stopped" daemon working, and — per the unhandled
    // rejection route — can take the process down from a node nobody is using.
    const seen: string[] = [];
    const listener = await start({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      nodeType: "session",
      idleConnectionReaper: {
        graceMs: 50,
        sweepIntervalMs: 50,
        onObserved: () => { seen.push("swept"); },
      },
    });
    await waitUntil(() => seen.length > 0, 3000);
    await listener.stop();
    const after = seen.length;
    await wait(400); // several sweep intervals
    expect(seen.length, "the sweep kept running after stop()").toBe(after);
  });

  it("leaves a connection alone while a stream is open on it", async () => {
    // The other half of the same wiring: a reaper that closes everything also passes the test
    // above. This is what stops "it reaped" from meaning "it reaps indiscriminately".
    const PROTO = "/cello/idle-test/1.0.0";
    const listener = await start({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      nodeType: "session",
      idleConnectionReaper: { graceMs: 300, sweepIntervalMs: 100 },
    });
    await listener.handle(PROTO, async () => {
      // Hold the stream open for the duration of the assertion window.
      await wait(3000);
    });
    const dialer = await start({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      nodeType: "session",
    });
    const addr = listener.listenAddresses().find((a) => a.includes("/p2p/"));
    if (!addr) throw new Error("listener has no addressed multiaddr");
    const peerId = (await dialer.dial(addr)).peerId;
    await dialer.newStream(peerId, PROTO);
    expect(await waitUntil(() => listener.getConnections().length > 0, 5000)).toBe(true);

    await wait(1200); // well past graceMs with several sweeps in between
    expect(
      listener.getConnections().length,
      "a connection carrying a live stream was reaped",
    ).toBeGreaterThan(0);
  });
});
