/**
 * CELLO-M8C-RELAYWAKE-1 — check relay on wakeup (transport-level: SignalingManager.onConnected)
 *
 * Clause coverage (M8C-BUILD-JOURNAL design note): the daemon-level wiring (autoRecoverForAgent
 * triggered on EVERY signaling connect, not just agent-start) is proven by these three properties
 * of the underlying mechanism it depends on:
 * - R1: onConnected fires on the FIRST successful connect.
 * - R2: onConnected fires AGAIN on a genuine RECONNECT after a dropped stream — this is the actual
 *   new behavior RELAYWAKE-1 adds (before this unit, nothing re-checked relays after the first
 *   agent-start; a signaling drop+reconnect while the agent stayed loaded found nothing new).
 * - R3: a throwing onConnected callback never breaks the signaling connection it's observing
 *   (best-effort, matches the design note's explicit requirement).
 */

import { describe, it, expect } from "vitest";
import { SignalingManager, type SignalingStream, type ConnectResult } from "../signaling-manager.js";

// Return type INFERRED: the literal carries a `debug` the SignalingLogger type does not declare, and
// annotating it away would be claiming a shape this object does not have.
function makeLogger() {
  const warnings: Array<{ event: string; context: Record<string, unknown> }> = [];
  return {
    warnings,
    debug() {}, info() {},
    warn(event: string, context: Record<string, unknown>) { warnings.push({ event, context }); },
    error() {},
  };
}

function makeStream(): SignalingStream {
  return {
    send: async () => {},
    onMessage: () => {},
    close: () => {},
  };
}

describe("M8C-RELAYWAKE-1: SignalingManager.onConnected", () => {
  it("R1: fires on the first successful connect", async () => {
    const logger = makeLogger();
    let calls = 0;
    const connect = async (): Promise<ConnectResult> => ({ stream: makeStream(), directoryNodeId: "node1", manifestVersion: 1 });
    const mgr = new SignalingManager({ connect, logger, onConnected: () => { calls++; } });
    await new Promise((r) => setTimeout(r, 30));
    expect(calls).toBeGreaterThanOrEqual(1);
    await mgr.stop();
  });

  it("R2: fires AGAIN on a genuine reconnect after a dropped stream (the actual new behavior)", async () => {
    const logger = makeLogger();
    let calls = 0;
    let attempt = 0;
    const connect = async (): Promise<ConnectResult> => {
      attempt++;
      return { stream: makeStream(), directoryNodeId: `node${attempt}`, manifestVersion: 1 };
    };
    // A real drop, not a simulated one: the fake stream never answers the manager's heartbeat
    // ping (its onMessage handler is a no-op), so the heartbeat TIMEOUT fires for real —
    // declareStreamDead → the manager's own reconnectLoop reconnects on its own, exactly the
    // "was offline, signaling reconnected" scenario RELAYWAKE-1 exists for. Short intervals so
    // the test doesn't wait real seconds.
    const mgr = new SignalingManager({
      connect,
      logger,
      onConnected: () => { calls++; },
      heartbeatIntervalMs: 15,
      heartbeatTimeoutMs: 15,
      initialBackoffMs: 5,
      maxBackoffMs: 20,
    });
    expect(calls).toBe(0); // nothing yet — connect() hasn't resolved

    // Wait through several heartbeat-timeout + reconnect + backoff cycles (short intervals, so
    // multiple genuine reconnects happen well within this window).
    await new Promise((r) => setTimeout(r, 150));
    expect(calls).toBeGreaterThanOrEqual(2); // the FIRST connect, plus at least one real reconnect
    expect(attempt).toBeGreaterThanOrEqual(2); // connect() was genuinely called more than once
    await mgr.stop();
  });

  it("R3: a throwing onConnected callback never breaks the connection (logged, not fatal)", async () => {
    const logger = makeLogger();
    const connect = async (): Promise<ConnectResult> => ({ stream: makeStream(), directoryNodeId: "node1", manifestVersion: 1 });
    const mgr = new SignalingManager({
      connect,
      logger,
      onConnected: () => { throw new Error("boom"); },
    });
    await new Promise((r) => setTimeout(r, 30));
    expect(mgr.status).toBe("connected"); // the throw did not break the connection
    expect(logger.warnings.find((w) => w.event === "signaling.on_connected.callback_failed")).toBeDefined();
    await mgr.stop();
  });
});
