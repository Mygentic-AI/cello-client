/**
 * DOD-RELAY-KEEPALIVE-1 (client half) — libp2p's own connection monitor must stop killing
 * healthy WAN links.
 *
 * THE ATTRIBUTION, established statically before any code was written (libp2p 3.3.2):
 *  - `ConnectionMonitor` is constructed on EVERY node unless explicitly disabled
 *    (libp2p/dist/src/libp2p.js:108 — `if (init.connectionMonitor?.enabled !== false)`).
 *  - It pings every connection every 10s (DEFAULT_PING_INTERVAL_MS) under an AdaptiveTimeout
 *    whose floor is 5s (@libp2p/utils DEFAULT_MIN_TIMEOUT).
 *  - `abortConnectionOnPingFailure` defaults to TRUE, so ONE ping that misses that deadline
 *    calls `conn.abort(err)` on the whole connection (connection-monitor.js).
 *  - A missing ping PROTOCOL is tolerated (`UnsupportedProtocolError` counts as alive — and no
 *    CELLO node registers a ping responder, so that is the normal outcome). A ping that is merely
 *    SLOW is fatal.
 *
 * WHAT THESE TESTS DO AND DO NOT ESTABLISH (corrected after review):
 *
 * K0 pins that Node's message for a timed-out AbortSignal is "The operation was aborted due to
 * timeout". That is a property of the RUNTIME, shared by every AbortSignal.timeout in the tree —
 * libp2p alone has ~10 on the relay path (registrar, upgrader, connection negotiate/close,
 * dial-queue, connection-pruner) plus circuit-relay-v2's listen/reservation/hop timeouts. So it
 * pins the wording, NOT which subsystem produced the incident's copies of it. It passes before and
 * after this change and is not coverage of it.
 *
 * K1 is real coverage: it proves `pingTimeoutMinMs` actually reaches libp2p's monitor under the
 * right nested key, by making the deadline unmeetable and watching a HEALTHY loopback connection
 * die. Rename the option and this goes red while everything else stays green.
 *
 * K2 is the relay-side policy: `abortConnectionOnPingFailure: false` keeps that same doomed link
 * up. K3 pins the default policy, and K4 pins the part production actually ships — that a node
 * built with NO options gets the 30s floor rather than libp2p's 5s.
 */
import { describe, it, expect } from "vitest";
import { generateKeypair } from "@cello-protocol/crypto";
import { createNode, resolveConnectionMonitorConfig, WAN_PING_TIMEOUT_FLOOR_MS } from "../node.js";
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

/** A doomed ping deadline: 1ms is shorter than any real round trip, so EVERY ping fails. */
const DOOMED_PING = { pingIntervalMs: 100, pingTimeoutMinMs: 1 };

async function startPair(monitorOpts: {
  pingIntervalMs: number;
  pingTimeoutMinMs: number;
  abortConnectionOnPingFailure?: boolean;
}): Promise<{ dialer: CelloNode; listener: CelloNode; listenerAddr: string }> {
  const listener = await createNode({
    keyProvider: generateKeypair(),
    listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
    nodeType: "session",
  });
  await listener.start();
  const dialer = await createNode({
    keyProvider: generateKeypair(),
    listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
    nodeType: "session",
    keepAliveIntervalMs: monitorOpts.pingIntervalMs,
    connectionMonitor: {
      pingTimeoutMinMs: monitorOpts.pingTimeoutMinMs,
      ...(monitorOpts.abortConnectionOnPingFailure !== undefined
        ? { abortConnectionOnPingFailure: monitorOpts.abortConnectionOnPingFailure }
        : {}),
    },
  });
  await dialer.start();
  const listenerAddr = listener.listenAddresses().find((a) => a.includes("/p2p/"));
  if (!listenerAddr) throw new Error("listener has no addressed multiaddr");
  return { dialer, listener, listenerAddr };
}

describe("K0: what the incident's error STRING does and does not tell us", () => {
  it("pins the wording AbortSignal.timeout produces on this Node runtime — shared by ~10 call sites", async () => {
    // NOT the last link in an attribution chain — a review corrected that overstatement. The
    // monitor aborts with whatever its AbortSignal.timeout produced, and the daemon logged that
    // text verbatim as `session.relay.reader.ended` (2,061 times in launch-triage, untraced) — but
    // so would a dial, upgrade, negotiation, hop or reservation timeout. This pins the WORDING, so
    // that if a Node upgrade changes it, the incident logs stop matching anything and we know.
    const signal = AbortSignal.timeout(1);
    const err = await new Promise<Error>((resolve) => {
      signal.addEventListener("abort", () => { resolve(signal.reason as Error); });
    });
    expect(err.message).toBe("The operation was aborted due to timeout");
  });

});

describe("K1: pingTimeoutMinMs really reaches libp2p — a doomed deadline kills a healthy link", () => {
  it("a ping deadline no round trip can meet tears down a healthy loopback connection", async () => {
    const { dialer, listener, listenerAddr } = await startPair(DOOMED_PING);
    try {
      let disconnected = false;
      dialer.onPeerDisconnect(() => { disconnected = true; });
      await dialer.dial(listenerAddr);
      expect(dialer.hasDirectConnectionTo(listener.getPeerId())).toBe(true);

      // Nothing is wrong with this connection. Both nodes are up, on loopback, in one process.
      const died = await waitUntil(() => disconnected, 10_000);
      expect(died, "stock libp2p kills a healthy link when the ping misses its deadline").toBe(true);
      expect(dialer.hasDirectConnectionTo(listener.getPeerId())).toBe(false);
    } finally {
      await dialer.stop();
      await listener.stop();
    }
  }, 30_000);
});

describe("K2: abortConnectionOnPingFailure:false keeps the link up (the fix)", () => {
  it("the same doomed ping deadline no longer costs the connection", async () => {
    const { dialer, listener, listenerAddr } = await startPair({ ...DOOMED_PING, abortConnectionOnPingFailure: false });
    try {
      let disconnected = false;
      dialer.onPeerDisconnect(() => { disconnected = true; });
      await dialer.dial(listenerAddr);
      expect(dialer.hasDirectConnectionTo(listener.getPeerId())).toBe(true);

      // Long enough for ~30 failed pings at the 100ms interval. Every one of them would have
      // aborted the connection under the default policy (K1 kills it in well under a second).
      await wait(3_000);
      expect(disconnected, "a slow ping must not sever a healthy link").toBe(false);
      expect(dialer.hasDirectConnectionTo(listener.getPeerId())).toBe(true);
    } finally {
      await dialer.stop();
      await listener.stop();
    }
  }, 30_000);
});

describe("K3: the default connection-monitor policy", () => {
  it("replaces libp2p's 5s AdaptiveTimeout floor with a WAN-safe floor", () => {
    expect(WAN_PING_TIMEOUT_FLOOR_MS).toBeGreaterThanOrEqual(30_000);
    const cfg = resolveConnectionMonitorConfig({});
    expect(cfg.pingTimeout?.minTimeout).toBe(WAN_PING_TIMEOUT_FLOOR_MS);
  });

  it("leaves the ABORT on by default — session-peer liveness ('gone') depends on it", () => {
    const cfg = resolveConnectionMonitorConfig({});
    expect(cfg.abortConnectionOnPingFailure).not.toBe(false);
  });

  it("keepAliveIntervalMs still drives the ping interval, and omitting it leaves libp2p's default", () => {
    expect(resolveConnectionMonitorConfig({ keepAliveIntervalMs: 250 }).pingInterval).toBe(250);
    expect(resolveConnectionMonitorConfig({}).pingInterval).toBeUndefined();
  });

  it("an explicit override wins over the default policy — both fields", () => {
    const cfg = resolveConnectionMonitorConfig({
      connectionMonitor: { abortConnectionOnPingFailure: false, pingTimeoutMinMs: 90_000 },
    });
    expect(cfg.abortConnectionOnPingFailure).toBe(false);
    expect(cfg.pingTimeout?.minTimeout).toBe(90_000);
  });

  it("the monitor is never disabled — the ping traffic IS the keepalive against network reapers", () => {
    // Asserted by ABSENCE. libp2p switches the monitor off with `enabled: false`, so the policy
    // never emitting that key at all is the guarantee — stronger than the old
    // `expect(cfg.enabled).not.toBe(false)`, which passed on a field nothing produced.
    expect("enabled" in resolveConnectionMonitorConfig({})).toBe(false);
    expect(
      "enabled" in resolveConnectionMonitorConfig({ connectionMonitor: { abortConnectionOnPingFailure: false } }),
    ).toBe(false);
  });
});

describe("K4: the policy production actually ships reaches libp2p", () => {
  it("a node created with NO options runs the 30s floor, not libp2p's 5s", async () => {
    // K3 proves the policy FUNCTION returns the right literal; K1 proves an injected value is
    // plumbed through. Neither covered the case every production node is in — no options at all.
    // A review found that gap. The node reports the very object handed to createLibp2p, so this
    // cannot drift from what libp2p was configured with.
    const node = await createNode({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      nodeType: "session",
    });
    try {
      const policy = node.getConnectionMonitorPolicy();
      expect(policy.pingTimeout?.minTimeout).toBe(WAN_PING_TIMEOUT_FLOOR_MS);
      expect(policy.pingTimeout?.minTimeout).toBeGreaterThan(5_000); // libp2p's LAN floor
      expect(policy.abortConnectionOnPingFailure).toBe(true);        // liveness preserved
    } finally {
      await node.stop();
    }
  }, 20_000);

  it("the relay's policy — abort off, pings still on — survives the same round trip", async () => {
    const node = await createNode({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      connectionMonitor: { abortConnectionOnPingFailure: false },
    });
    try {
      const policy = node.getConnectionMonitorPolicy();
      expect(policy.abortConnectionOnPingFailure).toBe(false);
      expect("enabled" in policy, "never disabled — the pings ARE the keepalive").toBe(false);
      expect(policy.pingTimeout?.minTimeout).toBe(WAN_PING_TIMEOUT_FLOOR_MS);
    } finally {
      await node.stop();
    }
  }, 20_000);
});
