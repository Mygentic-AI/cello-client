/**
 * M12-P15, blocker — an INTERRUPTED session cannot submit a seal leaf at all.
 *
 * The first P15 attempt (49b67d5, reverted) routed a rejection into `submitSealLeaf` and was INERT:
 * that method requires an `#activeNodes` entry, and every producer of `status='interrupted'` deletes
 * it (`markInterruptedWithDetails`, `destroySessionNode(...,"interrupted")`, and the shutdown/boot
 * blanket UPDATEs which run when no node exists at all). `handleSealInterruptedFlow` is ONLY
 * reachable when the status is `interrupted`, so the submit returned `session_node_unavailable` on
 * 100% of reachable calls. The unit test passed only because the manager was hand-stubbed to return
 * a value the real object cannot produce there.
 *
 * The daemon already solves exactly this shape for content: `startupParkFn` acts on a session with
 * no in-memory node using the PERSISTED relay endpoint (`relay_peer_id` / `relay_addrs`, columns
 * that exist for precisely this reason) plus the owning agent's standing receiver. `submitLeaf`
 * takes (node, sessionId, contentHash, leafKind) explicitly — nothing about it needs a per-session
 * node. So the guard is the defect, not the architecture.
 *
 * These tests pin the GUARD, not the relay round trip: a unit test cannot reach a real relay, but it
 * CAN prove the call is no longer refused before it ever tries, and that a genuinely missing
 * precondition is named for what it is instead of being reported as a missing node.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { startTwoConnectionFixture } from "./helpers/two-connection-fixture.js";

describe("M12-P15 blocker: an interrupted session can reach the relay to seal", () => {
  let fx: Awaited<ReturnType<typeof startTwoConnectionFixture>>;
  const SID = "e5".repeat(32);

  beforeEach(async () => { fx = await startTwoConnectionFixture({ dirPrefix: "cello-p15-" }); });
  afterEach(async () => { await fx.cleanup(); });

  it("does not refuse with session_node_unavailable once the node is gone — that guard is what made the fix inert", async () => {
    await fx.createSession(SID, "alice");
    // Drive the REAL producer of the interrupted status, not a raw UPDATE: this is the transition
    // that deletes #activeNodes, and it is the one the measured incident went through.
    await fx.snm.markInterruptedWithDetails("alice", SID, "test");

    const res = await fx.snm.submitSealLeaf("alice", SID, "corr");
    expect(res.ok).toBe(false); // no relay in a unit test — the POINT is which reason comes back
    expect(
      (res as { reason: string }).reason,
      "the node guard must no longer be the answer for an interrupted session",
    ).not.toBe("session_node_unavailable");
  });

  it("names a MISSING persisted relay endpoint for what it is", async () => {
    // A session that never had a relay has nothing to seal through, and that must read as its own
    // cause. Reporting it as a missing node sends the next investigation at the session lifecycle
    // instead of at the endpoint — the error-substitution shape this milestone keeps paying for.
    await fx.createSession(SID, "alice"); // created with no relay opts
    await fx.snm.markInterruptedWithDetails("alice", SID, "test");

    const res = await fx.snm.submitSealLeaf("alice", SID, "corr") as { ok: false; reason: string };
    expect(res.reason).toBe("no_persisted_relay_endpoint");
  });

  it("an ACTIVE session is completely unaffected — the in-memory node still wins", async () => {
    // Regression lock: the detached path is a FALLBACK. If it ever takes precedence, a live session
    // would seal through a rebuilt client instead of its own registered one.
    await fx.createSession(SID, "alice");
    const res = await fx.snm.submitSealLeaf("alice", SID, "corr") as { ok: false; reason: string };
    // Still no relay configured in the fixture, but it must fail on the ACTIVE path's own guard.
    expect(res.reason).toBe("relay_unavailable");
  });
});
