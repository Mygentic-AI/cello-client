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
