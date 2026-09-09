/**
 * 043-SIGNALDELIVERY C — every authenticated stream must handle a trust-signal pickup.
 *
 * ─── THE BUG THIS FILE EXISTS TO STOP COMING BACK ──────────────────────────────────────────────
 *
 * A directory drains its pickup queue down ANY stream that authenticates, including a VISITING
 * connection opened to broker a cross-node session. The daemon registered the
 * `trust_signal_pickup` handler only on the agent's own per-agent manager, so a visited node
 * dutifully pushed its pickups and the daemon dropped every frame on the floor. Nothing was lost —
 * the directory deletes on ACK, not on send — but the frames were re-sent and re-dropped on every
 * visit, silently, and the operator's wallet stayed empty.
 *
 * `outbound-sessions.ts` already states the rule in its own header — "Anything a home stream must
 * handle, a visiting stream must handle too" — and `registerSealListeners` exists because the seal
 * frames hit this exact failure first. This is the same bug, one frame type later.
 */
import { describe, it, expect, vi } from "vitest";
import { createPickupListenerRegistrar } from "../trust-signal-pickup-listener.js";

type Handler = (frame: Record<string, unknown>) => void;

/** The only part of SignalingManager this touches. */
function fakeManager() {
  const handlers: Handler[] = [];
  return {
    handlers,
    registerInboundHandler(h: Handler) { handlers.push(h); },
    deliver(frame: Record<string, unknown>) { for (const h of handlers) h(frame); },
  };
}

const KP = {} as never;

describe("043-SIGNALDELIVERY C — pickup listener registrar", () => {
  it("routes a trust_signal_pickup frame to the handler", async () => {
    const handle = vi.fn(async () => {});
    const register = createPickupListenerRegistrar(() => handle);
    const mgr = fakeManager();

    register(mgr as never, "alice", KP);
    mgr.deliver({ type: "trust_signal_pickup", id: "p1" });

    expect(handle).toHaveBeenCalledOnce();
    const [frame, , signaling, agentName] = handle.mock.calls[0] as unknown as [
      Record<string, unknown>, unknown, unknown, string,
    ];
    expect(frame["id"]).toBe("p1");
    expect(agentName).toBe("alice");
    // The ACK goes back down the SAME stream the pickup arrived on. Acking down the home stream
    // for a frame that arrived on a visiting one would leave the visited node's row unacked
    // forever — re-sent on every visit, which is today's bug wearing a different hat.
    expect(signaling).toBe(mgr);
  });

  it("ignores every other frame type", async () => {
    const handle = vi.fn(async () => {});
    const register = createPickupListenerRegistrar(() => handle);
    const mgr = fakeManager();

    register(mgr as never, "alice", KP);
    for (const type of ["seal_verified", "session_sealed", "register_success", "auth_ok"]) {
      mgr.deliver({ type });
    }
    expect(handle).not.toHaveBeenCalled();
  });

  it("passes the agent's OWN key provider, because only k_local can open the seal", async () => {
    // The daemon is the only party that can open a sealed pickup (SI-001). A registrar that closed
    // over the wrong agent's key would fail every hash check and reject signals that were fine.
    const handle = vi.fn(async () => {});
    const register = createPickupListenerRegistrar(() => handle);
    const mgr = fakeManager();
    const kp = { marker: "alice-kp" } as never;

    register(mgr as never, "alice", kp);
    mgr.deliver({ type: "trust_signal_pickup", id: "p1" });

    expect(handle.mock.calls[0][1]).toBe(kp);
  });

  it("resolves the handler LATE, so wiring order cannot leave it unregistered", async () => {
    // The daemon builds the signaling wiring before the inbound-session handlers exist. Capturing
    // the handler at registration time would bind whatever was there at boot — which for this
    // frame type is nothing at all.
    let current: ((...a: unknown[]) => Promise<void>) | undefined;
    const register = createPickupListenerRegistrar(() => current as never);
    const mgr = fakeManager();
    register(mgr as never, "alice", KP);

    const late = vi.fn(async () => {});
    current = late as never;
    mgr.deliver({ type: "trust_signal_pickup", id: "p1" });

    expect(late).toHaveBeenCalledOnce();
  });
});

/**
 * The wiring half. The registrar being correct proves nothing about whether the VISITING connection
 * uses it — and that gap is the entire defect: a correct handler that production never registers.
 *
 * This repo has hit that seam repeatedly (see `dod-m15-idle-conns-1-wiring.test.ts`, which lists
 * four consecutive units where a green module had nothing showing production called it). So the
 * assertion is made against `openVisitingConnection`'s real return value: build it, hand its manager
 * a pickup frame, and require the handler to fire.
 */
describe("043-SIGNALDELIVERY C — the VISITING connection registers it", () => {
  it("routes a pickup frame arriving on a visiting stream", async () => {
    const { createOutboundSessions } = await import("../outbound-sessions.js");

    const registered: ((frame: Record<string, unknown>) => void)[] = [];
    const fakeMgr = {
      registerInboundHandler(h: (f: Record<string, unknown>) => void) { registered.push(h); },
      stop: async () => {},
      send: async () => {},
    };
    // Replace only the manager the visiting path constructs; everything else is the real module.
    const transport = await import("@cello-protocol/transport");
    vi.spyOn(transport, "SignalingManager").mockImplementation(() => fakeMgr as never);

    const handle = vi.fn(async () => {});
    const registerPickupListener = createPickupListenerRegistrar(() => handle);
    const noop = () => {};
    const silent = { debug: noop, info: noop, warn: noop, error: noop } as never;

    // Only the deps openVisitingConnection actually reaches on the path to registering listeners.
    // Everything else is left off deliberately: stubbing the whole surface would make this a test
    // of the stub, and the point is that the REAL function registers the REAL listener.
    const outbound = createOutboundSessions({
      logger: silent,
      registerPickupListener,
      registerSealListeners: () => () => {},
      getPersistence: () => ({}) as never,
      sessionNodeManager: { verifyCertifiedRoot: () => false } as never,
      challengeVerifier: {} as never,
      getManifestVersion: () => 1,
      getFailoverEndpoint: () => ({ url: "http://dir", peerId: "p", multiaddr: "/m" }),
      resolveConsortiumRoster: async () => [],
      recordSealFailure: () => {},
    } as never);

    const visiting = (outbound as unknown as {
      openVisitingConnection: (
        agentName: string, kp: unknown, pub: string, endpoint: unknown, corr: string, nodeId: string,
      ) => { mgr: unknown };
    }).openVisitingConnection(
      "alice", {} as never, "a".repeat(64), { url: "http://dir", peerId: "p", multiaddr: "/m" }, "corr", "us-east1",
    );
    expect(visiting.mgr).toBe(fakeMgr);

    // THE REVERT TEST: delete `registerPickupListener(...)` from openVisitingConnection and no
    // handler here responds to the frame — which is exactly today's behaviour, the directory
    // pushing pickups at a stream that drops them.
    for (const h of registered) h({ type: "trust_signal_pickup", id: "p1" });
    expect(handle).toHaveBeenCalledOnce();
  });
});
