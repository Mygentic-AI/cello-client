/**
 * DOD-M15-CLOSEWAIT-1 — a close answers the caller before eleven minutes elapse.
 *
 * ─── What an operator lives through today ──────────────────────────────────────────────────────
 *
 * They run `cello_close_session`. The command freezes. Measured 2026-08-17: seal leaf submitted at
 * 16:48:55, ceremony completed at 17:00:01 — **11 minutes 6 seconds of a dead terminal.**
 *
 * It is working the whole time. It has submitted its SEAL leaf, and it is waiting for the
 * counterparty to close too; if they never do, it escalates to a unilateral seal and produces a real
 * notarized receipt. But nobody watching a frozen command believes that. One operator concluded it
 * was broken and force-abandoned **seventeen sessions** — and force-abandon forfeits the exact
 * receipt the wait was earning.
 *
 * `DOD-M12B-CLOSE-SILENT-WAIT-1` already fixed the half that could be fixed without touching the
 * contract: the wait now announces itself in the log. This is the other half.
 *
 * ─── The contract, decided before the code (Decisions Carried #4) ──────────────────────────────
 *
 * **ANSWER ON COMMITMENT, NOT ON NOTARIZATION.** The close returns as soon as the SEAL leaf is
 * durably submitted. The bilateral wait and the unilateral escalation continue in the background;
 * the receipt is collected with `cello_get_sealed_receipt`.
 *
 * Nothing about WHAT is signed, by whom, or in what order changes — the same escalation produces the
 * same receipt from the same leaf. Only the IPC response stops waiting for it.
 *
 * ─── The counterbalance, named before the code ─────────────────────────────────────────────────
 *
 * Answering early must not let an operator believe a COMMITTED session is a SEALED one. That is the
 * failure this change could introduce, and it would be worse than the wait: an operator who thinks
 * they hold a receipt and does not is in a worse position than one who is merely kept waiting. So
 * the response says committed-not-notarized, names the verb that fetches the receipt, and the
 * session keeps reading as sealing until it genuinely is not.
 *
 * ─── Why this is plumbing and not a rebuild ────────────────────────────────────────────────────
 *
 * Both safety nets already existed, which is what made this the least-reversing option:
 *   - `cello_get_sealed_receipt` already returns the same certificate.
 *   - `RestartSealResolver` (`DOD-M12B-RESTART-SEAL-1`) already resolves `seal_interrupted_pending`
 *     on boot — a seal commitment nobody asked the directory to notarize — so a daemon that dies
 *     during the background wait finishes on its next start rather than orphaning the session.
 */

import { describe, it, expect } from "vitest";
import { CLOSE_COMMITTED_GUIDANCE, describeSealCommitted } from "../close-commitment.js";

describe("DOD-M15-CLOSEWAIT-1: the committed answer cannot be mistaken for a sealed one", () => {
  it("★ it does NOT report ok-with-a-root — there is no root yet", () => {
    /**
     * The counterbalance, first. The tempting shape is `{ ok: true }` with the session gone from the
     * list, because that is what a close "looks like" — and it would be a lie that costs an operator
     * their receipt, since they would never call `cello_get_sealed_receipt`.
     */
    const r = describeSealCommitted({ sessionId: "abc123", deadlineMs: 660_000 });
    expect(r["sealed_root"], "there is no notarized root at commitment time, so there must be no field claiming one").toBeUndefined();
    expect(r["sealed"], "and nothing may report the session as sealed").toBeUndefined();
  });

  it("★ it states the status as COMMITTED, in a word that is not 'closed'", () => {
    const r = describeSealCommitted({ sessionId: "abc123", deadlineMs: 660_000 });
    expect(r["ok"]).toBe(true);
    expect(r["seal_status"]).toBe("committed");
  });

  it("★ the guidance names the verb that fetches the receipt", () => {
    /**
     * Invariant 4 — an agent-facing response carries the affordance. Without the verb, "committed"
     * is a status an agent can do nothing with, and the receipt is never collected.
     */
    const r = describeSealCommitted({ sessionId: "abc123", deadlineMs: 660_000 });
    expect(String(r["guidance"])).toContain("cello_sealed_receipt");
    expect(
      String(r["guidance"]),
      "and it must NOT name the internal IPC method — the handler is registered as " +
        "cello_get_sealed_receipt, but the TOOL an agent can call is cello_sealed_receipt, and " +
        "prose naming the wrong one hands the operator a dead command (the vocabulary audit caught " +
        "exactly this here)",
    ).not.toMatch(/cello_get_sealed_receipt/);
  });

  it("★ it says the receipt is NOT yet available, and roughly when to look", () => {
    const g = String(describeSealCommitted({ sessionId: "abc", deadlineMs: 660_000 })["guidance"]);
    expect(g, "an agent that polls immediately and finds nothing must not read that as failure").toMatch(/not yet/i);
    expect(g, "and the outer bound has to be a NUMBER, not 'shortly'").toMatch(/11 minutes/);
  });

  it("★ it warns against force-abandon, which is what the 11-minute freeze actually caused", () => {
    /**
     * Seventeen sessions were lost that way. The wait no longer blocks, so the panic that produced
     * those force-abandons should not recur — but an operator who does not see an immediate receipt
     * may still reach for `force: true`, and that still forfeits it.
     */
    const g = String(describeSealCommitted({ sessionId: "abc", deadlineMs: 660_000 })["guidance"]);
    expect(g).toMatch(/force/i);
    expect(g, "and it must say what forcing COSTS, not merely that it exists").toMatch(/forfeit|lose|destroy/i);
  });

  it("the deadline is rendered from the actual configured timeout, not hardcoded prose", () => {
    // An operator who shortened CELLO_SEAL_BILATERAL_TIMEOUT_MS must not be told "11 minutes".
    const g = String(describeSealCommitted({ sessionId: "abc", deadlineMs: 120_000 })["guidance"]);
    expect(g).toMatch(/2 minutes/);
    expect(g).not.toMatch(/11 minutes/);
  });

  it("the session id is echoed, so the receipt can actually be fetched", () => {
    const r = describeSealCommitted({ sessionId: "deadbeef", deadlineMs: 660_000 });
    expect(r["session_id"]).toBe("deadbeef");
    expect(String(r["guidance"]), "and the id appears in the instruction itself").toContain("deadbeef");
  });

  it("CLOSE_COMMITTED_GUIDANCE is one definition, not a second copy", () => {
    /**
     * The shape this milestone keeps finding: a string duplicated at two call sites, one of which is
     * later reworded, and the two surfaces quietly disagree. One exported builder, used everywhere.
     */
    expect(typeof CLOSE_COMMITTED_GUIDANCE).toBe("function");
    expect(CLOSE_COMMITTED_GUIDANCE({ sessionId: "x", deadlineMs: 660_000 })).toBe(
      String(describeSealCommitted({ sessionId: "x", deadlineMs: 660_000 })["guidance"]),
    );
  });
});
