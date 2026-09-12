/**
 * DOD-M15-SEALPRECOND-1 — a conversation cannot be signed off while it is still being written down.
 *
 * Measured 2026-09-11, session `e7dd3f43…`, both daemon logs. The relay ordered this side's
 * in-flight leaf at 16:13:28.438; the close signed the root at 16:13:28.790 holding two leaves; the
 * third leaf was appended at 16:13:28.804. Both directories refused the signature as
 * `merkle_root_mismatch` and the receipt was lost permanently — on BOTH sides, because the
 * counterparty had already locked its own copy and quarantined the message that arrived after.
 *
 * NOT A RACE, and the tests here are written so no delay can make them pass. The close path DID
 * consult `sealReadiness` and `sealReadiness` answered `ready: true` honestly: its three terms
 * (`missingLeaves`, `heldCount`, `diverged`) all describe the counterparty's leaves or a permanent
 * parting, and none of them has any term for THIS side's own leaf that the relay has ordered and
 * the tree has not yet placed. That leaf is what these tests make visible.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { registerCloseSessionHandler } from "../close-session-handler.js";
import { startTwoConnectionFixture } from "./helpers/two-connection-fixture.js";

const AGENT = "alice";
const SESSION = "cd".repeat(32);
const HASH = "ab".repeat(32);

type ReadinessShape = {
  ready: boolean; treeSize: number; highWaterSeq: number; heldCount: number; missingLeaves: number;
  heldOwn: number; heldReceived: number; diverged: boolean; ownLeavesOrdered: number;
};

function readiness(over: Partial<ReadinessShape> = {}): ReadinessShape {
  return {
    ready: true, treeSize: 2, highWaterSeq: 1, heldCount: 0, missingLeaves: 0,
    heldOwn: 0, heldReceived: 0, diverged: false, ownLeavesOrdered: 0, ...over,
  };
}

/**
 * The close handler with a readiness source the test drives.
 *
 * `readNext` is called on EVERY `sealReadiness()` — that is what lets a test model the real
 * sequence: unsettled at the moment the operator closes, settled a few milliseconds later when the
 * send's own continuation places the leaf. A harness that returned one frozen object could not tell
 * a gate that waits from a gate that refuses.
 */
function harness(readNext: () => ReadinessShape, status = "active") {
  const handlers = new Map<string, (p: Record<string, unknown>, c: string) => Promise<unknown>>();
  const events: Array<{ event: string; context: Record<string, unknown> }> = [];
  let sealFlowCalls = 0;
  let readinessReads = 0;

  const sessionNodeManager = {
    getSessionRecord: () => ({ agent_name: AGENT, agent_id: "aid", session_id: SESSION, status }),
    sealReadiness: () => { readinessReads += 1; return readNext(); },
    notifyCounterpartyAbandon: async () => ({ told: false, reason: "no_local_node" as const }),
    abandonSession: async () => true,
    submitSealLeaf: async () => ({ ok: false as const, reason: "relay_unavailable" }),
    getSealCertificate: () => undefined,
    resolveAgentId: () => "aid",
    setSessionName: () => {},
  };

  registerCloseSessionHandler({
    handlers,
    sealFailures: { record: () => {}, clear: () => {} },
    logger: {
      debug() {}, info(e, c) { events.push({ event: e, context: c ?? {} }); },
      warn(e, c) { events.push({ event: e, context: c ?? {} }); }, error() {},
    },
    sessionNodeManager: sessionNodeManager as never,
    getConnState: () => ({ currentAgent: AGENT }) as never,
    resolveCurrentAgent: () => AGENT,
    NO_CURRENT_AGENT_RESPONSE: { ok: false, reason: "no_current_agent" },
    sealInterruptedInProgress: new Set<string>(),
    sealKey: (a: string, s: string) => `${a}\x1f${s}`,
    signalingFor: () => ({ status: "connected" }) as never,
    handleSealInterruptedFlow: async () => { sealFlowCalls += 1; return { ok: true, status: "sealed" }; },
    handleActiveSealFlow: async () => { sealFlowCalls += 1; return { ok: true, status: "sealed" }; },
    pendingSealWaiters: new Map(),
    crossNodeBrokerBySession: new Map<string, string>(),
    logger2: undefined,
  } as never);

  return {
    close: handlers.get("cello_close_session")!,
    events,
    sealFlow: () => sealFlowCalls,
    reads: () => readinessReads,
  };
}

describe("DOD-M15-SEALPRECOND-1: the close waits for its own record to settle", () => {
  it("does not sign while the relay has ordered a leaf this tree has not placed", async () => {
    // The 2026-09-11 shape, frozen: the leaf never lands, so the bound expires. The seal must not
    // be requested at all — a signature over a short tree is refused by the directory and the
    // receipt is gone for good, which is strictly worse than making the operator close again.
    const h = harness(() => readiness({ ready: false, ownLeavesOrdered: 1 }));
    const res = await h.close({ session_id: SESSION }, "conn") as Record<string, unknown>;

    expect(res.ok).toBe(false);
    expect(h.sealFlow(), "no root may be signed while a leaf of ours is unplaced").toBe(0);
  });

  it("declines in terms of THIS side's own record, never the counterparty's", async () => {
    // 065-SEALREASON: a refusal that names the wrong party sends two operators to argue with each
    // other about a condition neither of them caused. `session_incomplete` says the counterparty
    // has not sent something; that is a different condition and it must not be borrowed here.
    const h = harness(() => readiness({ ready: false, ownLeavesOrdered: 1 }));
    const res = await h.close({ session_id: SESSION }, "conn") as Record<string, unknown>;

    expect(res.reason).toBe("session_record_settling");
    const g = String(res.guidance);
    expect(g, "the operator is told nothing was signed").toMatch(/no signature|not signed|nothing was signed/i);
    expect(g, "and told to close again — the condition clears on its own").toMatch(/close/i);
    expect(g).not.toMatch(/counterparty (has|had) not|waiting on an earlier message|leaf_count_mismatch|merkle_root_mismatch/i);
    expect(res.reason).not.toBe("session_incomplete");
    expect(String(res.reason)).not.toMatch(/merkle_root_mismatch/);
    // Visible in the log, with the counter that caused it. Silence is how the first one cost a
    // receipt with nobody able to say why.
    const blocked = h.events.find((e) => e.event === "session.seal.blocked_settling");
    expect(blocked).toBeDefined();
    expect(blocked!.context.ownLeavesOrdered).toBe(1);
  });

  it("WAITS: a leaf that lands mid-close is sealed, not refused", async () => {
    // Done When 1. The real sequence — unsettled when the operator closes, placed milliseconds
    // later — must end in a seal. An in-flight send resolves in 14ms; handing the operator a
    // failure for that would trade a lost receipt for a pointless refusal.
    let reads = 0;
    const h = harness(() => (++reads >= 3 ? readiness() : readiness({ ready: false, ownLeavesOrdered: 1 })));
    const res = await h.close({ session_id: SESSION }, "conn") as Record<string, unknown>;

    expect(res.ok, `refused after ${reads} readiness reads`).toBe(true);
    expect(h.sealFlow(), "the seal runs once the tree is level").toBe(1);
  });

  it("the wait is on the CONDITION, not the clock — it returns as soon as the leaf lands", async () => {
    // The anti-sleep assertion. A fixed delay would take the full bound whatever the state does;
    // this must re-read the condition and proceed on it. Two reads minimum (unsettled, settled) and
    // well inside the bound.
    let reads = 0;
    const h = harness(() => (++reads >= 2 ? readiness() : readiness({ ready: false, ownLeavesOrdered: 1 })));
    const started = Date.now();
    const res = await h.close({ session_id: SESSION }, "conn") as Record<string, unknown>;

    expect(res.ok).toBe(true);
    expect(h.reads(), "the condition is re-read, not slept through").toBeGreaterThan(1);
    expect(Date.now() - started, "it must not serve out the whole bound").toBeLessThan(1_000);
  });

  it("a healthy close is untouched — no new false positive, no added latency", async () => {
    // The fear this codebase states plainly: a gate that blocks a healthy session is worse than the
    // bug it guards, because force-abandon (no receipt) becomes the only exit.
    const h = harness(() => readiness());
    const started = Date.now();
    const res = await h.close({ session_id: SESSION }, "conn") as Record<string, unknown>;

    expect(res.ok).toBe(true);
    expect(h.sealFlow()).toBe(1);
    expect(Date.now() - started).toBeLessThan(500);
  });

  it("a DIVERGED record still gets its own permanent answer — the settling wait must not preempt it", async () => {
    // Divergence never resolves, so waiting on it would delay a permanent answer and then report a
    // transient one. DOD-M15-DIVERGE-1 exists because substituting a transient explanation for a
    // permanent condition sends the operator into a retry loop that ends at force-abandon.
    const h = harness(() => readiness({ ready: false, diverged: true, ownLeavesOrdered: 1 }));
    const res = await h.close({ session_id: SESSION }, "conn") as Record<string, unknown>;

    expect(res.reason).toBe("session_record_diverged");
    expect(h.sealFlow()).toBe(0);
  });

  it("force-abandon is never gated by it — the escape hatch must always return", async () => {
    const h = harness(() => readiness({ ready: false, ownLeavesOrdered: 1 }));
    const res = await h.close({ session_id: SESSION, force: true }, "conn") as Record<string, unknown>;

    expect(res.ok).toBe(true);
    expect(res.status).toBe("abandoned");
  });
});

describe("DOD-M15-SEALPRECOND-1: sealReadiness counts our own ordered-but-unplaced leaf", () => {
  let fx: Awaited<ReturnType<typeof startTwoConnectionFixture>>;
  const SID = "77".repeat(32);

  beforeEach(async () => { fx = await startTwoConnectionFixture({ dirPrefix: "cello-sealprecond-" }); });
  afterEach(async () => { await fx.cleanup(); });

  it("the relay ordering our leaf makes the session NOT ready until the tree places it", async () => {
    // The counter the gate was missing. `missingLeaves` cannot see this: the witness map gains an
    // entry only for leaves NOT authored by us (`relayLeafHandler`), so our own ordered leaf leaves
    // every existing term at zero.
    await fx.createSession(SID, "alice");

    fx.snm.noteOwnLeafOrdered("alice", SID, HASH, 0);
    const pending = fx.snm.sealReadiness("alice", SID);
    expect(pending.missingLeaves, "the existing counters genuinely cannot see it — that is the defect").toBe(0);
    expect(pending.heldCount).toBe(0);
    expect(pending.diverged).toBe(false);
    expect(pending.ownLeavesOrdered).toBe(1);
    expect(pending.ready, "and yet it must NOT be ready").toBe(false);

    const placed = fx.snm.placeOwnLeaf("alice", SID, HASH, new TextEncoder().encode("hi"), 0, undefined, "msg", undefined);
    expect(placed).toMatchObject({ placed: true });
    expect(fx.snm.sealReadiness("alice", SID)).toMatchObject({ ownLeavesOrdered: 0, ready: true });
  });

  it("a HELD own leaf clears the marker — it is then counted as held, never as both", async () => {
    // Placement resolves the marker whatever the outcome. A leaf held behind a gap is already
    // refused by `heldOwn`; counting it twice would report one message as two conditions and make
    // the guidance contradict itself.
    await fx.createSession(SID, "alice");
    fx.snm.noteOwnLeafOrdered("alice", SID, HASH, 4);
    const held = fx.snm.placeOwnLeaf("alice", SID, HASH, new TextEncoder().encode("ahead"), 4, undefined, "msg", undefined);
    expect(held).toMatchObject({ placed: false });

    const r = fx.snm.sealReadiness("alice", SID);
    expect(r.ownLeavesOrdered, "resolved by the placement, held by the hold").toBe(0);
    expect(r.heldOwn).toBe(1);
    expect(r.ready).toBe(false);
  });

  it("the status surface says the record is settling, not `blocked` with nothing behind it", async () => {
    // Folding a new term into `ready` drops the session into `sealReadinessView`'s `!ready` branch,
    // which reports `blocked` with awaitingArrival and heldBehindGap both ZERO — an answer that
    // describes nothing and points the operator at the counterparty. Same trap DOD-M15-DIVERGE-1
    // hit; same fix, read it first.
    await fx.createSession(SID, "alice");
    fx.snm.noteOwnLeafOrdered("alice", SID, HASH, 0);

    expect(fx.snm.sealReadinessView("alice", SID)).toEqual({
      state: "unknown",
      reason: "own_send_settling",
    });
  });

  it("a real send through the daemon leaves no marker behind once it has placed its leaf", async () => {
    // The marker must be resolved by the ordinary path, or every session becomes permanently
    // unsealable after its first message — a false positive far worse than the defect.
    await fx.createSession(SID, "alice");
    fx.seedSent("alice", SID, "one");
    fx.seedReceived("alice", SID, "two");

    expect(fx.snm.sealReadiness("alice", SID)).toMatchObject({ ownLeavesOrdered: 0, ready: true });
  });
});
