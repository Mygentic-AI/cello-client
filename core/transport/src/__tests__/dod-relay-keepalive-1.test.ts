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
 * K1 pins that mechanism end to end, and pins the ERROR STRING it produces —
 * "The operation was aborted due to timeout" — which is the string in the 2026-08-04 relay reader
 * errors and in the 2,061 untraced launch-triage errors. K1 is a CHARACTERIZATION test of stock
 * libp2p, so it passes before and after the fix; that is its job. It is evidence for the
 * attribution, not a test of our change.
 *
 * K2 is the fix: the same doomed configuration with `abortConnectionOnPingFailure: false` keeps
 * the connection. K3 pins the POLICY — a WAN-safe ping-timeout floor replacing libp2p's 5s
 * AdaptiveTimeout floor, with the abort left ON by default so that session-peer liveness
 * (counterparty_liveness → 'gone') keeps working.
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

describe("K1: stock libp2p aborts a HEALTHY connection on one slow ping (the defect)", () => {
  it("the string the incident logs carry IS what a timed-out abort signal produces on this runtime", async () => {
    // The last link in the attribution chain. The monitor aborts with the error its
    // AbortSignal.timeout produced, and the daemon logged that error verbatim as
    // `session.relay.reader.ended` — 2,061 times in launch-triage, untraced. If a Node upgrade
    // ever changes this wording, the log-to-mechanism link is broken and this test says so.
    const signal = AbortSignal.timeout(1);
    const err = await new Promise<Error>((resolve) => {
      signal.addEventListener("abort", () => { resolve(signal.reason as Error); });
    });
    expect(err.message).toBe("The operation was aborted due to timeout");
  });

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
    expect(resolveConnectionMonitorConfig({}).enabled).not.toBe(false);
    expect(
      resolveConnectionMonitorConfig({ connectionMonitor: { abortConnectionOnPingFailure: false } }).enabled,
    ).not.toBe(false);
  });
});
