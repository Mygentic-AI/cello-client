/**
 * M12-P14 — refuse to seal a chain this side already knows is short.
 *
 * Measured 2026-08-05 across two machines. The initiator asked to seal-interrupt holding 2 leaves;
 * the responder held 3 and refused with `leaf_count_mismatch`. That refusal is CORRECT — a seal is a
 * bilateral signature over the same conversation, and no one may sign a transcript that omits a
 * message the other side recorded. It is also TERMINAL: there is no backfill request in the
 * protocol, so the session's only remaining exit was `force: true`, which is terminal and produces
 * NO notarized receipt. Both sessions ended that way.
 *
 * The prevention is local and needs no network call: the relay is the ordering authority and the
 * daemon already records its high-water canonical sequence, plus any content held behind a gap.
 * Either signal above our own frontier proves a leaf exists that we have not appended. Until now
 * nothing read either at close time — `#highWaterSeq`'s own comment said it was "reserved … NOT yet
 * consumed by the gate".
 */
import { describe, it, expect } from "vitest";
import { registerCloseSessionHandler } from "../close-session-handler.js";

const AGENT = "alice";
const SESSION = "cd".repeat(32);

type Readiness = ReturnType<typeof readiness>;
function readiness(over: Partial<{ ready: boolean; treeSize: number; highWaterSeq: number; heldCount: number; missingLeaves: number }> = {}) {
  return { ready: true, treeSize: 2, highWaterSeq: 1, heldCount: 0, missingLeaves: 0, ...over };
}

function harness(sealReady: Readiness, status = "interrupted") {
  const handlers = new Map<string, (p: Record<string, unknown>, c: string) => Promise<unknown>>();
  const events: Array<{ event: string; context: Record<string, unknown> }> = [];
  let sealFlowCalls = 0;
  let abandoned = 0;

  const sessionNodeManager = {
    getSessionRecord: () => ({ agent_name: AGENT, agent_id: "aid", session_id: SESSION, status }),
    sealReadiness: () => sealReady,
    abandonSession: async () => { abandoned += 1; return true; },
    submitSealLeaf: async () => ({ ok: false as const, reason: "relay_unavailable" }),
    getSealCertificate: () => undefined,
    resolveAgentId: () => "aid",
    setSessionName: () => {},
  };

  registerCloseSessionHandler({
    handlers,
    logger: {
      debug() {}, info(e, c) { events.push({ event: e, context: c ?? {} }); },
      warn(e, c) { events.push({ event: e, context: c ?? {} }); }, error() {},
    },
    sessionNodeManager: sessionNodeManager as never,
    getConnState: () => ({ currentAgent: AGENT }) as never,
    resolveCurrentAgent: () => AGENT,
    NO_CURRENT_AGENT_RESPONSE: { ok: false, reason: "no_current_agent" },
    sealInterruptedInProgress: new Set<string>(),
    sealKey: (a: string, s: string) => `${a}:${s}`,
    signalingFor: () => ({ status: "connected" }) as never,
    handleSealInterruptedFlow: async () => { sealFlowCalls += 1; return { ok: true, status: "sealed" }; },
    handleActiveSealFlow: async () => { sealFlowCalls += 1; return { ok: true, status: "sealed" }; },
    pendingSealWaiters: new Map(),
    logger2: undefined,
  } as never);

  const close = handlers.get("cello_close_session")!;
  return { close, events, sealFlow: () => sealFlowCalls, abandons: () => abandoned };
}

describe("M12-P14: a close will not seal a chain it knows is incomplete", () => {
  it("refuses when the relay has witnessed a sequence beyond our own frontier", async () => {
    // The exact 2026-08-05 shape: we hold 2, the relay witnessed 3 (high-water index 2).
    const h = harness(readiness({ ready: false, treeSize: 2, highWaterSeq: 2, missingLeaves: 1 }));
    const res = await h.close({ session_id: SESSION }, "conn") as Record<string, unknown>;

    expect(res.ok).toBe(false);
    expect(res.reason).toBe("session_incomplete");
    expect(res.missing_leaves).toBe(1);
    // The seal must NOT be attempted — asking produces a leaf_count_mismatch, and that refusal is
    // terminal. Refusing here costs a retry; asking costs the receipt permanently.
    expect(h.sealFlow(), "no seal may be requested for a chain we know is short").toBe(0);
    // And it must be visible: this was silent when it cost two sessions.
    expect(h.events.find((e) => e.event === "session.seal.blocked_incomplete")).toBeDefined();
  });

  it("refuses when content is HELD behind a gap — we have the message and cannot append it yet", async () => {
    // Distinct from the high-water case: here the content arrived and verified, but it sits behind a
    // missing sequence. Sealing would sign a chain we are actively holding messages out of.
    const h = harness(readiness({ ready: false, heldCount: 2, missingLeaves: 0 }));
    const res = await h.close({ session_id: SESSION }, "conn") as Record<string, unknown>;

    expect(res.ok).toBe(false);
    expect(res.held_messages).toBe(2);
    expect(String(res.guidance)).toMatch(/waiting behind a gap/);
    expect(h.sealFlow()).toBe(0);
  });

  it("the guidance names the receipt consequence, not just the refusal", async () => {
    // An operator who reads "cannot seal" and reaches straight for force: true converts a
    // recoverable wait into the terminal, receipt-less outcome this gate exists to prevent. The
    // wording has to make the cost of force explicit and offer the cheaper action first.
    const h = harness(readiness({ ready: false, treeSize: 2, highWaterSeq: 2, missingLeaves: 1 }));
    const res = await h.close({ session_id: SESSION }, "conn") as Record<string, unknown>;
    const g = String(res.guidance);

    expect(g).toMatch(/no notarized receipt/);
    expect(g).toMatch(/wait a moment and close again/);
  });

  it("a COMPLETE chain seals exactly as before — the gate is additive, not a new failure mode", async () => {
    const h = harness(readiness());
    const res = await h.close({ session_id: SESSION }, "conn") as Record<string, unknown>;

    expect(res.ok).toBe(true);
    expect(h.sealFlow(), "the seal flow must still run untouched").toBe(1);
    expect(h.events.find((e) => e.event === "session.seal.blocked_incomplete")).toBeUndefined();
  });

  it("force:true is NEVER gated — the operator's escape hatch must not depend on a complete chain", async () => {
    // Force exists precisely for a session that cannot be sealed. Gating it would strand the very
    // sessions the escape hatch is for, with no way out at all.
    const h = harness(readiness({ ready: false, treeSize: 2, highWaterSeq: 9, missingLeaves: 8 }));
    const res = await h.close({ session_id: SESSION, force: true }, "conn") as Record<string, unknown>;

    expect(res.ok).toBe(true);
    expect(res.status).toBe("abandoned");
    expect(h.abandons()).toBe(1);
  });
});
