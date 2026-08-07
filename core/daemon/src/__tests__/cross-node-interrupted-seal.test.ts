/**
 * Closing an INTERRUPTED session across nodes must dial the broker, exactly as an ACTIVE close does.
 *
 * ─── The failure this pins ──────────────────────────────────────────────────────────────────────
 * The directory routes a signaling frame by looking up a stream IT holds. An agent's daemon holds
 * its stream to its OWN home node, so when two agents are homed on different nodes the lookup
 * misses and the frame is dropped — the node logs "target offline" and returns NOTHING to the
 * sender, which then times out believing the counterparty is unreachable. Symmetrically, in both
 * directions, with neither side wrong from where it stands.
 *
 * Cross-node reach is achieved by the CLIENT dialling the far node — directories never forward to
 * each other (`M12-BUILD-JOURNAL`: "directory→directory forwarding — new cross-node channel, does
 * not exist"). The close handler already does this for ACTIVE sessions, with a comment naming this
 * exact failure. That block was gated on `record.status === "active"`, and the interrupted branch —
 * which sends the same seal frames — never got it.
 *
 * Measured live 2026-08-07: CELLO_Coder_1 homed on gcp-euw1, Miss_Chelly_H on gcp-usc1, a
 * seal-interrupted exchange timing out in both directions while a session (which does dial) worked
 * alongside it.
 *
 * ─── Why it survived from 2026-06-15 to now ─────────────────────────────────────────────────────
 * Every test in the suite puts both agents on one machine, which puts them on one directory — the
 * single arrangement in which this cannot occur. A green suite meant "works when they are
 * neighbours". `two-node-seal.spine.test.ts` is the end-to-end guard; this is the unit-level one.
 */

import { describe, it, expect, vi } from "vitest";
import { registerCloseSessionHandler } from "../close-session-handler.js";
import type { Logger } from "@cello-protocol/interfaces";

const silent: Logger = { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} } as unknown as Logger;

const AGENT = "agent-a";
const SESSION = "ab".repeat(16);
const BROKER = "gcp-usc1";

function harness(opts: {
  /** The session's status — the condition the reconnect used to be gated on. */
  status: "interrupted" | "active";
  /** Whether this session was brokered by another node. Absent → same-node, no dial expected. */
  brokeredBy?: string;
  /** Whether the visiting connection comes up within the wait. */
  connects?: boolean;
}) {
  const handlers = new Map<string, (p: Record<string, unknown>, c: string) => Promise<unknown>>();
  const stop = vi.fn(async () => {});
  const openVisitingConnection = vi.fn(() => ({ mgr: {}, stop }));

  const crossNodeBrokerBySession = new Map<string, string>();
  if (opts.brokeredBy) crossNodeBrokerBySession.set(`${AGENT}:${SESSION}`, opts.brokeredBy);

  const sessionNodeManager = {
    getSessionRecord: () => ({ agent_name: AGENT, agent_id: "aid", session_id: SESSION, status: opts.status }),
    submitSealLeaf: async () => ({ ok: false as const, reason: "unused" }),
    getSealCertificate: () => null,
    resolveAgentId: () => "aid",
    setSessionName: () => {},
    sealReadiness: () => ({ ready: true, treeSize: 1, highWaterSeq: 0, heldCount: 0, missingLeaves: 0 }),
  };

  registerCloseSessionHandler({
    handlers,
    logger: silent,
    sessionNodeManager,
    getConnState: () => ({ currentAgent: AGENT }),
    resolveCurrentAgent: () => AGENT,
    NO_CURRENT_AGENT_RESPONSE: { ok: false, reason: "no_current_agent" },
    getKeyProvider: () => ({ getPublicKey: async () => new Uint8Array(32) }),
    signalingFor: () => ({ status: "connected" }),
    sendOver: async () => ({ ok: true }),
    waitForSignalingConnected: async () => opts.connects !== false,
    openVisitingConnection,
    crossNodeBrokerBySession,
    sealKey: (a: string, s: string) => `${a}:${s}`,
    sealInterruptedInProgress: new Set<string>(),
    pendingSealWaiters: new Map(),
    pendingUnilateralWaiters: new Map(),
    resolveConsortiumRoster: async () => [
      { nodeId: BROKER, peerId: "12D3KooWBroker", multiaddr: "/ip4/10.10.1.25/tcp/4000" },
    ],
    handleSealInterruptedFlow: async () => ({ ok: true, sealed_root: "ff".repeat(32) }),
    handleActiveSealFlow: async () => ({ ok: false, reason: "unused" }),
  } as never);

  return { close: handlers.get("cello_close_session")!, openVisitingConnection, stop };
}

describe("closing an interrupted session that was brokered by another node", () => {
  it("DIALS THE BROKER before sealing, instead of asking over the home stream", async () => {
    // The regression this file exists for. Without the dial the seal frames are pushed by the
    // broker to a stream it does not hold, and the close times out with "counterparty unavailable"
    // for a counterparty that is online and waiting.
    const { close, openVisitingConnection } = harness({ status: "interrupted", brokeredBy: BROKER });

    await close({ session_id: SESSION }, "conn-1");

    expect(openVisitingConnection).toHaveBeenCalledTimes(1);
    // The LAST argument is the broker node id — dialling any other node reproduces the bug.
    const args = openVisitingConnection.mock.calls[0] as unknown as unknown[];
    expect(args[args.length - 1]).toBe(BROKER);
  });

  it("RELEASES the transient connection afterwards", async () => {
    // It is transient by design. Leaking one per interrupted close would accumulate a connection
    // to every node an operator has ever been brokered through.
    const { close, stop } = harness({ status: "interrupted", brokeredBy: BROKER });

    await close({ session_id: SESSION }, "conn-1");

    expect(stop).toHaveBeenCalled();
  });

  it("does NOT dial for a same-node interrupted session", async () => {
    // THE SCOPE ASSERTION. Without it, "always dial" passes the test above while adding a 10-second
    // wait and a redundant connection to every ordinary same-node close.
    const { close, openVisitingConnection } = harness({ status: "interrupted" });

    await close({ session_id: SESSION }, "conn-1");

    expect(openVisitingConnection).not.toHaveBeenCalled();
  });

  it("still seals when the broker cannot be reached, rather than refusing the close", async () => {
    // An unreachable broker is the pre-fix behaviour, not a new failure: proceed on the home stream
    // and let the seal time out honestly. Refusing here would turn a degraded path into a dead one.
    const { close, stop } = harness({ status: "interrupted", brokeredBy: BROKER, connects: false });

    const res = (await close({ session_id: SESSION }, "conn-1")) as { ok: boolean };

    expect(res.ok).toBe(true);
    // The half-open connection is still torn down.
    expect(stop).toHaveBeenCalled();
  });

  it("keeps dialling for ACTIVE sessions — the behaviour that already worked", async () => {
    // Parity guard. The fix moves shared code out of the active branch; if that extraction breaks
    // the active path, the flow that DOES work today regresses silently.
    const { close, openVisitingConnection } = harness({ status: "active", brokeredBy: BROKER });

    await close({ session_id: SESSION }, "conn-1");

    expect(openVisitingConnection).toHaveBeenCalledTimes(1);
  });
});

const COUNTERPARTY = "cc".repeat(32);

function discoveryHarness(opts: {
  /** What the directory says about the counterparty's whereabouts. */
  discovery: { kind: "result"; state: "online" | "offline" | "unknown_agent"; owningNodeIds: string[] } | { kind: "timeout" };
  /** This agent's own home node — a match means no dial is needed. */
  homeNodeId: string | null;
  /** Populate the in-memory map, i.e. simulate NOT having restarted. */
  brokeredBy?: string;
  /** When true the FIRST home-stream attempt succeeds, so nothing should be looked up at all. */
  firstAttemptSucceeds?: boolean;
}) {
  const handlers = new Map<string, (p: Record<string, unknown>, c: string) => Promise<unknown>>();
  const stop = vi.fn(async () => {});
  const openVisitingConnection = vi.fn(() => ({ mgr: {}, stop }));
  const runDiscoveryLookup = vi.fn(async () => opts.discovery);
  let sealAttempts = 0;

  const crossNodeBrokerBySession = new Map<string, string>();
  if (opts.brokeredBy) crossNodeBrokerBySession.set(`${AGENT}:${SESSION}`, opts.brokeredBy);

  registerCloseSessionHandler({
    handlers,
    logger: silent,
    sessionNodeManager: {
      getSessionRecord: () => ({
        agent_name: AGENT, agent_id: "aid", session_id: SESSION,
        status: "interrupted", counterparty_pubkey: COUNTERPARTY,
      }),
      submitSealLeaf: async () => ({ ok: false as const, reason: "unused" }),
      getSealCertificate: () => null,
      resolveAgentId: () => "aid",
      setSessionName: () => {},
      sealReadiness: () => ({ ready: true, treeSize: 1, highWaterSeq: 0, heldCount: 0, missingLeaves: 0 }),
    },
    getConnState: () => ({ currentAgent: AGENT }),
    resolveCurrentAgent: () => AGENT,
    NO_CURRENT_AGENT_RESPONSE: { ok: false, reason: "no_current_agent" },
    getKeyProvider: () => ({ getPublicKey: async () => new Uint8Array(32) }),
    signalingFor: () => ({ status: "connected", currentDirectoryNodeId: opts.homeNodeId }),
    sendOver: async () => ({ ok: true }),
    waitForSignalingConnected: async () => true,
    openVisitingConnection,
    runDiscoveryLookup,
    crossNodeBrokerBySession,
    sealKey: (a: string, s: string) => `${a}:${s}`,
    sealInterruptedInProgress: new Set<string>(),
    pendingSealWaiters: new Map(),
    pendingUnilateralWaiters: new Map(),
    resolveConsortiumRoster: async () => [
      { nodeId: BROKER, peerId: "12D3KooWBroker", multiaddr: "/ip4/10.10.1.25/tcp/4000" },
    ],
    // The home-stream attempt fails the way the real one does after a restart; the retry (which
    // only happens once a broker connection is open) succeeds.
    handleSealInterruptedFlow: async () => {
      sealAttempts += 1;
      if (opts.firstAttemptSucceeds || sealAttempts > 1) return { ok: true, sealed_root: "ff".repeat(32) };
      return { ok: false, reason: "seal_interrupted_counterparty_unavailable" };
    },
    handleActiveSealFlow: async () => ({ ok: false, reason: "unused" }),
  } as never);

  return { close: handlers.get("cello_close_session")!, openVisitingConnection, runDiscoveryLookup, stop, attempts: () => sealAttempts };
}

/**
 * THE BROKER MAP DOES NOT SURVIVE THE RESTART THAT CREATES THE CONDITION.
 *
 * `crossNodeBrokerBySession` is an in-memory Map populated while a session is being brokered. A
 * daemon restart empties it — and a daemon restart is precisely what flips a live session to
 * `interrupted`. So on the interrupted path the map is essentially ALWAYS empty, and gating the
 * dial on it alone means the dial never happens for the case it was added for.
 *
 * Shipped as daemon 0.0.140 and proved insufficient against the real stranded sessions the same
 * hour: the close still returned `seal_interrupted_counterparty_unavailable`. The unit tests above
 * passed because they HAND the map to the code — the fixture supplied the very state a restart
 * destroys.
 *
 * The fix is not to persist the broker. The node that brokered the session hours ago need not be
 * where the counterparty lives now; agents re-home. What matters at seal time is where the
 * counterparty is NOW, which the directory can answer from replicated presence — so the fallback is
 * a discovery lookup, classified by the SAME `classifyOnlineResult` the outbound path uses.
 */
describe("closing an interrupted session after a restart, with no broker in memory", () => {
  it("LOOKS UP the counterparty and dials their CURRENT node when memory is empty", async () => {
    // The real stranded case: restarted daemon, nothing in the map, counterparty on another node.
    const h = discoveryHarness({
      discovery: { kind: "result", state: "online", owningNodeIds: [BROKER] },
      homeNodeId: "gcp-euw1",
    });

    await h.close({ session_id: SESSION }, "conn-1");

    expect(h.runDiscoveryLookup).toHaveBeenCalledTimes(1);
    expect(h.openVisitingConnection).toHaveBeenCalledTimes(1);
    const args = h.openVisitingConnection.mock.calls[0] as unknown as unknown[];
    expect(args[args.length - 1]).toBe(BROKER);
  });

  it("does NOT dial when the counterparty is on OUR node", async () => {
    // Same-node needs no visiting connection; dialling would add a redundant one to every close.
    const h = discoveryHarness({
      discovery: { kind: "result", state: "online", owningNodeIds: ["gcp-euw1"] },
      homeNodeId: "gcp-euw1",
    });

    await h.close({ session_id: SESSION }, "conn-1");

    expect(h.openVisitingConnection).not.toHaveBeenCalled();
  });

  it("prefers the in-memory broker and NEVER looks up when it IS known", async () => {
    // The fast path must stay fast: within one process lifetime the answer is already known, and a
    // discovery round-trip would be pure latency in front of the seal waiter.
    const h = discoveryHarness({
      discovery: { kind: "result", state: "online", owningNodeIds: ["gcp-use1"] },
      homeNodeId: "gcp-euw1",
      brokeredBy: BROKER,
    });

    await h.close({ session_id: SESSION }, "conn-1");

    expect(h.runDiscoveryLookup).not.toHaveBeenCalled();
    const args = h.openVisitingConnection.mock.calls[0] as unknown as unknown[];
    expect(args[args.length - 1]).toBe(BROKER);
  });

  it("does not dial when the lookup times out, and never invents a success", async () => {
    // A failed lookup leaves us exactly where the pre-fix code was: the home-stream attempt already
    // failed, and that real reason is what the operator gets. Reporting ok here would be worse than
    // the bug — a close that claims a seal it never obtained.
    const h = discoveryHarness({ discovery: { kind: "timeout" }, homeNodeId: "gcp-euw1" });

    const res = (await h.close({ session_id: SESSION }, "conn-1")) as { ok: boolean; reason?: string };

    expect(h.openVisitingConnection).not.toHaveBeenCalled();
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("seal_interrupted_counterparty_unavailable");
  });

  it("does NOT dial when the counterparty is reported OFFLINE", async () => {
    // Offline is a real answer, not a routing problem. Dialling their node cannot conjure a stream.
    const h = discoveryHarness({
      discovery: { kind: "result", state: "offline", owningNodeIds: [BROKER] },
      homeNodeId: "gcp-euw1",
    });

    await h.close({ session_id: SESSION }, "conn-1");

    expect(h.openVisitingConnection).not.toHaveBeenCalled();
  });
});

/**
 * THE LOOKUP MUST NOT SIT IN FRONT OF THE SEAL.
 *
 * The first shape of this fix ran the discovery BEFORE the seal attempt. That delayed registration
 * of the seal waiter by up to the lookup timeout, and a bilateral seal arriving promptly was then
 * missed entirely — a correctness regression strictly worse than the latency, caught by the
 * unilateral-escalation suite whose close registers its waiter within ~100ms.
 *
 * So discovery is a REPAIR, not a pre-flight: the close goes out on the home stream first and only
 * the one failure that discovery can fix triggers a lookup and a retry.
 */
describe("the discovery lookup is a repair, never a pre-flight", () => {
  it("does NOT look anything up when the home-stream attempt succeeds", async () => {
    const h = discoveryHarness({
      discovery: { kind: "result", state: "online", owningNodeIds: [BROKER] },
      homeNodeId: "gcp-euw1",
      firstAttemptSucceeds: true,
    });

    const res = (await h.close({ session_id: SESSION }, "conn-1")) as { ok: boolean };

    expect(res.ok).toBe(true);
    expect(h.runDiscoveryLookup, "a successful close must cost no lookup").not.toHaveBeenCalled();
    expect(h.openVisitingConnection).not.toHaveBeenCalled();
    expect(h.attempts()).toBe(1);
  });

  it("retries the seal ONCE after dialling, and reports the retry's success", async () => {
    const h = discoveryHarness({
      discovery: { kind: "result", state: "online", owningNodeIds: [BROKER] },
      homeNodeId: "gcp-euw1",
    });

    const res = (await h.close({ session_id: SESSION }, "conn-1")) as { ok: boolean; sealed_root?: string };

    expect(h.attempts(), "one attempt on the home stream, one after the dial").toBe(2);
    expect(res.ok).toBe(true);
    expect(res.sealed_root).toMatch(/^[0-9a-f]{64}$/);
  });

  it("returns the ORIGINAL failure when there is nowhere to dial", async () => {
    // No second attempt, and the operator sees the real reason rather than a manufactured one.
    const h = discoveryHarness({ discovery: { kind: "timeout" }, homeNodeId: "gcp-euw1" });

    const res = (await h.close({ session_id: SESSION }, "conn-1")) as { ok: boolean; reason?: string };

    expect(h.attempts()).toBe(1);
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("seal_interrupted_counterparty_unavailable");
  });
});
