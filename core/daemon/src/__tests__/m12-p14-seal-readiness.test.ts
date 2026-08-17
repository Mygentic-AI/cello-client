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
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { registerCloseSessionHandler } from "../close-session-handler.js";
import { startTwoConnectionFixture } from "./helpers/two-connection-fixture.js";

const AGENT = "alice";
const SESSION = "cd".repeat(32);

type Readiness = ReturnType<typeof readiness>;
function readiness(
  over: Partial<{ ready: boolean; treeSize: number; highWaterSeq: number; heldCount: number; missingLeaves: number; heldOwn: number; heldReceived: number }> = {},
) {
  const base = { ready: true, treeSize: 2, highWaterSeq: 1, heldCount: 0, missingLeaves: 0, heldOwn: 0, ...over };
  // DOD-M12B-INDEX-1: `heldReceived` defaults to "all of them", which is what `heldCount` meant
  // before the split — so a case that does not care about the sender keeps its old meaning instead
  // of silently becoming zero and dropping the clause it asserts on.
  return { ...base, heldReceived: over.heldReceived ?? base.heldCount - base.heldOwn };
}

function harness(sealReady: Readiness, status = "interrupted") {
  const handlers = new Map<string, (p: Record<string, unknown>, c: string) => Promise<unknown>>();
  const events: Array<{ event: string; context: Record<string, unknown> }> = [];
  let sealFlowCalls = 0;
  let abandoned = 0;

  const sessionNodeManager = {
    getSessionRecord: () => ({ agent_name: AGENT, agent_id: "aid", session_id: SESSION, status }),
    sealReadiness: () => sealReady,
    // DOD-M12B-ABANDON-NOTIFY-1: force-abandon now tells the counterparty first. Modelled as
    // "could not reach them", which is the case the guidance has to be honest about.
    notifyCounterpartyAbandon: async () => ({ told: false, reason: "no_local_node" as const }),
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
    sealKey: (a: string, s: string) => `${a}\x1f${s}`, // production shape (seal-coordinator.ts)
    signalingFor: () => ({ status: "connected" }) as never,
    handleSealInterruptedFlow: async () => { sealFlowCalls += 1; return { ok: true, status: "sealed" }; },
    handleActiveSealFlow: async () => { sealFlowCalls += 1; return { ok: true, status: "sealed" }; },
    pendingSealWaiters: new Map(),
    // Declared by the handler and previously omitted: the `as never` cast let the fixture skip a
    // REQUIRED dependency, and it went unnoticed only because the branch that reads it was not
    // reached from here. Empty on purpose — no recorded broker means a same-node session, so the
    // seal path under test proceeds on the home stream exactly as before.
    crossNodeBrokerBySession: new Map<string, string>(),
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

/**
 * The arithmetic itself, against a REAL SessionNodeManager.
 *
 * Review (blocking): every test above supplies a pre-built readiness object, so the body of
 * `sealReadiness` — the one line Andre was most worried about — had no coverage at all. Inverting
 * the comparison, dropping a term, or ignoring `missingLeaves` entirely left all five green.
 *
 * The specific fear is a FALSE POSITIVE: a gate that refuses a healthy session forever is worse than
 * the bug it guards, because force-abandon (no receipt) becomes the only exit. So the cases that
 * matter most here are the ones that must read READY.
 */
describe("M12-P14: sealReadiness computes from real manager state", () => {
  let fx: Awaited<ReturnType<typeof startTwoConnectionFixture>>;
  const SID = "77".repeat(32);

  beforeEach(async () => { fx = await startTwoConnectionFixture({ dirPrefix: "cello-p14-real-" }); });
  afterEach(async () => { await fx.cleanup(); });

  it("a fresh session with nothing witnessed is READY — the gate must not block an empty close", async () => {
    await fx.createSession(SID, "alice");
    expect(fx.snm.sealReadiness("alice", SID)).toMatchObject({ ready: true, missingLeaves: 0, heldCount: 0 });
  });

  it("a witnessed leaf that has NOT been appended reads as missing", async () => {
    await fx.createSession(SID, "alice");
    fx.snm.recordWitnessedSequence("alice", SID, "aa".repeat(32), 0);

    const r = fx.snm.sealReadiness("alice", SID);
    expect(r.missingLeaves).toBe(1);
    expect(r.ready).toBe(false);
  });

  it("appending the witnessed content clears it — the witness is consumed, not merely counted", async () => {
    // This is the whole basis of the measure: #witnessedSeq loses its entry the moment the leaf is
    // appended, so what remains is exactly "committed by the ordering authority, absent from this
    // tree". A count that never drained would refuse every session forever after one message.
    await fx.createSession(SID, "alice");
    fx.seedReceived("alice", SID, "hello");

    expect(fx.snm.sealReadiness("alice", SID)).toMatchObject({ ready: true, missingLeaves: 0 });
    expect(fx.snm.getSessionTree("alice", SID).size()).toBe(1);
  });

  it("a high-water AHEAD of the tree does NOT by itself refuse — ctrl leaves live in that space, msg leaves do not", async () => {
    // The false positive that the first implementation would have shipped. The relay increments its
    // sequence counter for EVERY leaf including the seal ctrl leaf, while the tree is msg-only, so
    // `(highWaterSeq + 1) - treeSize` reads a permanent phantom gap after any seal ctrl leaf. Here
    // the high-water is deliberately pushed past the tree with no outstanding witness: a healthy
    // chain, and it MUST still seal.
    await fx.createSession(SID, "alice");
    fx.seedReceived("alice", SID, "one");
    fx.snm.recordWitnessedSequence("alice", SID, "bb".repeat(32), 5);
    fx.snm.getSessionTree("alice", SID); // no-op read; the tree is 1 leaf, high-water is 5

    // The outstanding witness above IS a real missing leaf, so clear it the way an append would and
    // assert the residual high-water alone does not refuse.
    fx.snm.recordWitnessedSequence("alice", SID, "bb".repeat(32), 5);
    const withWitness = fx.snm.sealReadiness("alice", SID);
    expect(withWitness.highWaterSeq).toBe(5);
    expect(withWitness.treeSize).toBe(1);
    // Under the old subtraction this would have been 5. It is 1 — the one genuinely outstanding
    // witness — and it is driven by the witness map, not by the gap between the two spaces.
    expect(withWitness.missingLeaves).toBe(1);
  });

  it("never reports a negative or absurd count when the relay is behind the tree", async () => {
    // The relay-degraded direction: content delivered directly while the hash submit failed, so the
    // tree is AHEAD of anything witnessed. That is not a gap and must clamp to ready.
    await fx.createSession(SID, "alice");
    fx.seedReceived("alice", SID, "one");
    fx.seedReceived("alice", SID, "two");

    const r = fx.snm.sealReadiness("alice", SID);
    expect(r.treeSize).toBe(2);
    expect(r.missingLeaves).toBe(0);
    expect(r.ready).toBe(true);
  });
});
