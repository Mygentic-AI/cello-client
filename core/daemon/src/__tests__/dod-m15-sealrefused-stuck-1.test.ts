/**
 * DOD-M15-SEALREFUSED-STUCK-1 — a seal the directory REFUSED must stop reporting itself as running.
 *
 * Measured on session `dab46e16` (2026-09-08): the directory refused at 09:17:13.834 with
 * `seal_parties_disagree`; this side began waiting for the counterparty at 09:17:22.018, 8.2s
 * LATER, so the verdict was consumed with no waiter listening. The wait polled five times, gave up
 * at 09:28:52 with `seal_unilateral_timeout` — which OVERWROTE the true reason — and
 * `cello_sealed_receipt` answered `seal_in_progress` for hours.
 */
import { describe, it, expect } from "vitest";
import { SealFailureStore, describeSealFailed } from "../seal-failure-store.js";

const A = "alice";
const S = "dab46e16b038ec810578bc68dbaae613";
const T = "2026-09-08T09:17:13.834Z";

describe("DOD-M15-SEALREFUSED-STUCK-1: a directory refusal is a verdict, not a symptom", () => {
  it("★★★ a later timeout does NOT overwrite the refusal — the operator is not sent to chase the counterparty", () => {
    const store = new SealFailureStore();
    store.record(A, S, "seal_parties_disagree", T, "refused");
    // Eleven minutes later, the escalation that never learned of the refusal gives up.
    store.record(A, S, "seal_unilateral_timeout", "2026-09-08T09:28:52.077Z", "unresolved");

    const failure = store.get(A, S);
    expect(failure?.reason, "the reason the DIRECTORY gave is the one that survives").toBe("seal_parties_disagree");
    expect(failure?.kind).toBe("refused");
    expect(
      failure?.reason,
      "seal_unilateral_timeout says the counterparty never closed — the one party who did nothing wrong",
    ).not.toBe("seal_unilateral_timeout");
  });

  it("★★★ an ordinary dead ceremony has NO precedence — a later reason replaces it as before", () => {
    /**
     * THE CONTROL. The guard must bite ONLY for a reason the directory gave. If it applied to every
     * failure, the first transient local fault of a session would pin its reason for the life of the
     * daemon and every later, truer cause would be dropped.
     */
    const store = new SealFailureStore();
    expect(store.isFromDirectory(A, S), "no failure at all").toBe(false);
    store.record(A, S, "seal_ceremony_threw", T, "threw");
    store.record(A, S, "seal_unilateral_timeout", "2026-09-08T09:28:52.077Z", "unresolved");
    expect(store.get(A, S)?.reason, "an ordinary failure is freely superseded").toBe("seal_unilateral_timeout");
    expect(store.isFromDirectory(A, S)).toBe(false);
  });

  it("★★ a re-close still clears a refusal — the marker must not outlive a fresh ceremony", () => {
    const store = new SealFailureStore();
    store.record(A, S, "seal_parties_disagree", T, "refused");
    store.clear(A, S);
    expect(store.isFromDirectory(A, S)).toBe(false);
    expect(store.get(A, S)).toBeUndefined();
    // And a fresh ceremony's own failure lands normally afterwards.
    store.record(A, S, "seal_unilateral_timeout", T, "unresolved");
    expect(store.get(A, S)?.reason).toBe("seal_unilateral_timeout");
  });

  it("★★★ the refusal gets its OWN guidance — waiting for the counterparty is the wrong next move", () => {
    const store = new SealFailureStore();
    store.record(A, S, "seal_parties_disagree", T, "refused");
    const answer = describeSealFailed({ sessionId: S, failure: store.get(A, S)! }) as Record<string, string>;

    expect(answer["seal_status"], "not 'unresolved' — that word invites waiting").toBe("refused");
    expect(answer["seal_failure_reason"]).toBe("seal_parties_disagree");
    expect(answer["guidance"], "it must say the DIRECTORY refused, not that something is pending").toMatch(/REFUSED/);
    expect(
      answer["guidance"],
      "and it must point at the transcripts, which is where the disagreement actually is",
    ).toMatch(/cello_transcript/);
    expect(
      answer["guidance"],
      "the unresolved wording tells them the other side has not closed yet — wrong party, wrong action",
    ).not.toMatch(/has not closed yet/);
    /**
     * ⚠️ REVIEW HIGH-1, AND THIS IS THE ASSERTION THAT MATTERS MOST IN THIS FILE.
     *
     * A refused BILATERAL seal falls through to a SOLO seal that can still produce a receipt
     * (`close-session-handler.ts` → `session.seal.refused.escalating` → `escalateToUnilateralSeal`).
     * The first draft of this guidance said "no signature exists and none will be produced for it"
     * and offered `{ force: true }` on that basis — an operator who believed it would have
     * PERMANENTLY forfeited the receipt the escalation was still earning. Worse than the defect
     * this unit was opened for.
     */
    expect(answer["guidance"], "a solo seal may still produce a receipt — say so").toMatch(/SOLO seal/);
    expect(answer["guidance"], "and never invite the one irreversible action").toMatch(/Do NOT use \{ force: true \}/);
    expect(answer["guidance"], "it must not claim no receipt can exist").not.toMatch(/none will be produced/);
  });
});
