/**
 * DOD-M12B-INTERRUPTED-ESCALATE-1 — an interrupted session must be able to obtain a RECEIPT.
 *
 * Found 2026-08-17 by the review of DOD-M12B-RESTART-SEAL-1. `cello_close_session` on an
 * `interrupted` session takes a branch **every exit returns from**, so the `if (record.status ===
 * "active")` block below it — the only place the unilateral escalation lived — was structurally
 * unreachable. The interrupted branch's success type is literally
 * `{ ok: true; status: "seal_interrupted_pending" }`, and the handler says so itself:
 *
 *   "THE BILATERAL COMMITMENT IS NOT THE SEAL… an interrupted session reached a mutually signed
 *    record that nobody was ever asked to notarize."
 *
 * The responder confirms it: `inbound-seal-request.ts` persists its commitment, acks, and never
 * submits a seal leaf. The relay notarizes only once BOTH parties have posted, so one side's leaf
 * can never be enough — waiting for the relay round was waiting for something that cannot happen.
 *
 * **Measured cost: 26 sessions sat in `seal_interrupted_pending` for up to 10.5 days**, and
 * `cello_close_session` refuses that status by name, so there was no way out at all. This is Andre's
 * "most of the time we can't even close them", stated in code.
 *
 * WHAT MUST NOT BREAK — the trust decision. A unilateral seal notarizes OUR reported root with the
 * counterparty absent. That is legitimate when they agreed (the commitment landed) or when they
 * never answered. It is NOT legitimate after they actively REFUSED: a rejection means the two trees
 * disagree, and notarizing over a stated objection is the one thing a trust layer must not do.
 *
 * Revert test: drop the escalation call and the first case fails — no `seal_unilateral` frame is
 * ever sent and the close returns a commitment instead of a receipt.
 */
import { describe, it, expect, vi } from "vitest";
import { registerCloseSessionHandler } from "../close-session-handler.js";
import type { Logger } from "../types.js";

const AGENT = "alice";
const SESSION = "7a".repeat(32);
const ROOT = "ab".repeat(32);
const SEALED_ROOT = "cd".repeat(32);

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

function harness(opts: {
  /** What the bilateral commitment exchange did. */
  flow: { ok: true; sessionId: string; status: string } | { ok: false; reason: string; guidance: string };
  /** What the directory answers the `seal_unilateral` request with. Absent → never answers. */
  directory?: { ok: true; sealedRootHex: string } | { ok: false; reason: string; remainingSeconds?: number };
}) {
  const handlers = new Map<string, (p: Record<string, unknown>, c: string) => Promise<unknown>>();
  const sentFrames: Array<Record<string, unknown>> = [];
  const pendingUnilateralWaiters = new Map<string, (r: unknown) => void>();

  const sendOver = vi.fn(async (_agent: string, frame: Record<string, unknown>) => {
    sentFrames.push(frame);
    // Stand in for the directory: answer the moment the request goes out.
    if (frame["type"] === "seal_unilateral" && opts.directory) {
      const resolve = pendingUnilateralWaiters.get(SESSION);
      if (resolve) queueMicrotask(() => resolve(opts.directory));
    }
    return { ok: true };
  });

  registerCloseSessionHandler({
    handlers,
    logger: silent,
    sessionNodeManager: {
      getSessionRecord: () => ({ agent_name: AGENT, agent_id: "aid", session_id: SESSION, status: "interrupted" }),
      submitSealLeaf: async () => ({ ok: true as const, sequenceNumber: 4, reportedRootHex: ROOT }),
      getSealCarry: () => [],
      getSealCertificate: () => null,
      resolveAgentId: () => "aid",
      setSessionName: () => {},
      sealReadiness: () => ({ ready: true, treeSize: 1, highWaterSeq: 0, heldCount: 0, missingLeaves: 0 }),
    },
    getConnState: () => ({ currentAgent: AGENT }),
    resolveCurrentAgent: () => AGENT,
    NO_CURRENT_AGENT_RESPONSE: { ok: false, reason: "no_current_agent" },
    getKeyProvider: () => ({ getPublicKey: async () => new Uint8Array(32) }),
    signalingFor: () => ({ status: "connected" }),
    sendOver,
    waitForSignalingConnected: async () => true,
    openVisitingConnection: () => ({ mgr: {}, stop: async () => {} }),
    crossNodeBrokerBySession: new Map<string, string>(),
    sealKey: (a: string, s: string) => `${a}:${s}`,
    sealInterruptedInProgress: new Set<string>(),
    pendingSealWaiters: new Map(),
    pendingUnilateralWaiters,
    resolveConsortiumRoster: async () => [],
    unilateralTimeoutMs: 50,
    handleSealInterruptedFlow: async () => opts.flow,
    handleActiveSealFlow: async () => ({ ok: false, reason: "unused" }),
  } as never);

  return {
    close: handlers.get("cello_close_session")!,
    sentFrames,
    unilateralFrames: () => sentFrames.filter((f) => f["type"] === "seal_unilateral"),
  };
}

describe("DOD-M12B-INTERRUPTED-ESCALATE-1: an interrupted close can earn a receipt", () => {
  it("escalates to a unilateral seal and returns a REAL receipt, not a commitment", async () => {
    const h = harness({
      flow: { ok: true, sessionId: SESSION, status: "seal_interrupted_pending" },
      directory: { ok: true, sealedRootHex: SEALED_ROOT },
    });

    const res = (await h.close({ session_id: SESSION }, "conn-1")) as {
      ok: boolean; sealed_root?: string; seal_type?: string; status?: string;
    };

    expect(
      h.unilateralFrames().length,
      "the interrupted branch must ASK the directory to notarize — before this unit it never could",
    ).toBe(1);
    expect(res.ok).toBe(true);
    expect(res.sealed_root, "a receipt, not a mutually signed record nobody notarized").toBe(SEALED_ROOT);
    expect(res.seal_type).toBe("unilateral");
    expect(res.status, "it must no longer answer with the stuck status").not.toBe("seal_interrupted_pending");
  });

  it("carries the directory's countdown as a NUMBER when the grace has not elapsed", async () => {
    // The field DOD-M12B-RESTART-SEAL-1's resolver consumes. Before this unit it was produced only
    // inside the active branch, which an interrupted session can never enter — so its one named
    // consumer could never reach it.
    const h = harness({
      flow: { ok: true, sessionId: SESSION, status: "seal_interrupted_pending" },
      directory: { ok: false, reason: "seal_unilateral_too_early", remainingSeconds: 420 },
    });

    const res = (await h.close({ session_id: SESSION }, "conn-1")) as {
      ok: boolean; retry_after_seconds?: number; seal_receipt?: string; seal_pending_reason?: string;
    };

    expect(res.retry_after_seconds, "a caller that can wait must not have to parse a sentence").toBe(420);
    expect(res.seal_pending_reason).toBe("seal_counterparty_pending");
    // The commitment STANDS. Turning a succeeded commitment into a reported failure is what sends
    // an operator to force:true, which permanently forfeits the half they still hold.
    expect(res.ok, "a successful commitment must never be reported as a failure").toBe(true);
    expect(res.seal_receipt, "but it must not imply a receipt it does not have").toBe("outstanding");
  });

  it("NEVER escalates after the counterparty REFUSED — that would notarize over their objection", async () => {
    // A rejection means the two trees disagree (leaf_count_mismatch, a diverging index). However
    // stuck the session is, signing our own root against their stated objection is not an option.
    const h = harness({
      flow: { ok: false, reason: "seal_interrupted_rejected_by_counterparty", guidance: "" },
      directory: { ok: true, sealedRootHex: SEALED_ROOT },
    });

    const res = (await h.close({ session_id: SESSION }, "conn-1")) as { ok: boolean; sealed_root?: string };

    expect(h.unilateralFrames().length, "no notarization may be requested over a refusal").toBe(0);
    expect(res.ok).toBe(false);
    expect(res.sealed_root).toBeUndefined();
  });

  it("DOES escalate when the counterparty never answered — that is what a unilateral seal is FOR", async () => {
    // The measured majority case for a restart-orphaned session: the other daemon is not running.
    // Refusing to escalate here would leave exactly the sessions this work exists to resolve stuck.
    const h = harness({
      flow: { ok: false, reason: "seal_interrupted_counterparty_unavailable", guidance: "" },
      directory: { ok: true, sealedRootHex: SEALED_ROOT },
    });

    const res = (await h.close({ session_id: SESSION }, "conn-1")) as { ok: boolean; sealed_root?: string };

    expect(h.unilateralFrames().length, "an absent counterparty is the unilateral seal's whole purpose").toBe(1);
    expect(res.sealed_root).toBe(SEALED_ROOT);
  });

  it("a directory that never answers leaves the commitment intact, and says a receipt is outstanding", async () => {
    // The largest measured failure — `seal_unilateral_timeout`, 50 occurrences. It must not destroy
    // the commitment, and it must not be reported as a receipt.
    const h = harness({
      flow: { ok: true, sessionId: SESSION, status: "seal_interrupted_pending" },
      // No `directory` — nothing ever resolves the waiter.
    });

    const res = (await h.close({ session_id: SESSION }, "conn-1")) as {
      ok: boolean; seal_receipt?: string; seal_pending_reason?: string; sealed_root?: string;
    };

    expect(res.ok, "the commitment survives a silent directory").toBe(true);
    expect(res.seal_pending_reason).toBe("seal_unilateral_timeout");
    expect(res.seal_receipt).toBe("outstanding");
    expect(res.sealed_root, "and no receipt may be claimed").toBeUndefined();
  });
});
