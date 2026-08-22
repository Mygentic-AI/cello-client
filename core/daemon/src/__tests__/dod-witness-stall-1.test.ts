/**
 * DOD-WITNESS-STALL-1 (launch triage item 1) — a send the relay will NEVER witness must not report
 * success.
 *
 * ── WHAT HAPPENS TO AN OPERATOR ──────────────────────────────────────────────────────────────────
 *
 * They hold a long working conversation. Every message sends, every message arrives, nothing warns.
 * Then they close it and there is no receipt, and there can never be one — the record stopped
 * growing hours earlier. The work is already done by the time it announces itself.
 *
 * Measured 2026-08-09 on a live session: **12 messages held, 6 witnessed, frozen 68 minutes** across
 * 8 further messages, every one reporting `delivered: true` — including the messages being used to
 * discuss the problem.
 *
 * ── THE MECHANISM, from the relay's own log ──────────────────────────────────────────────────────
 *
 * The session opened while BOTH agents were unattended, so both away-responders fired. The away flow
 * ends a session, so each side submitted a SEAL ctrl leaf — the relay log shows ctrl at sequence 5
 * and ctrl at sequence 7, three seconds after creation. **Two distinct-sender ctrl leaves are
 * exactly what triggers the relay's seal**, so the certificate was built and delivered at 01:13:36.
 *
 * From that moment the relay considers the session terminal and witnesses nothing more. Both daemons
 * still show it `active` — the seal completion is pushed with no pull twin, so neither side learned
 * (launch triage item 13). The operators came back and had a full conversation on a session the
 * relay had already closed.
 *
 * ── WHY THE DAEMON DID NOT NOTICE, WHICH IS THE PART THIS FIXES ──────────────────────────────────
 *
 * It DID notice. `sendContent` submits the leaf hash, gets back `session_sealed`, logs
 * `session.relay.hash.submit.failed` — and continues, because that path treats every relay miss as a
 * transient best-effort degradation:
 *
 *     "Best-effort: a relay miss degrades to local-only sequencing."
 *
 * That is right for a relay that is briefly unreachable: the content is real, the peer gets it, and
 * the sequence is recovered later. It is WRONG for `session_sealed`, which is terminal — there is no
 * later. The distinction between "not witnessed yet" and "will never be witnessed" was collapsed,
 * and the daemon reported the second as though it were the first.
 *
 * ── THE RULE ─────────────────────────────────────────────────────────────────────────────────────
 *
 * A terminal refusal fails the send LOUDLY. The message is not delivered, because delivering content
 * that cannot enter the record is what produces a conversation nobody can prove. A transient refusal
 * keeps its existing best-effort behaviour, because that case genuinely recovers.
 */

import { describe, it, expect } from "vitest";
import { TERMINAL_RELAY_REFUSALS, isTerminalRelayRefusal } from "../session-relay-client.js";

describe("a relay refusal that can never resolve is not treated as a hiccup", () => {
  it("names the terminal refusals, and they are the ones that mean 'this session is over'", () => {
    // Enumerated rather than pattern-matched: a substring rule like `reason.includes("sealed")`
    // would silently absorb a future reason nobody has thought about, which is how the original
    // collapse happened.
    expect([...TERMINAL_RELAY_REFUSALS].sort()).toEqual([
      "seal_refused",
      "session_not_found",
      "session_sealed",
    ]);
  });

  it("`seal_refused` is terminal — a directory READ the seal and rejected it", () => {
    /**
     * `DOD-M15-TERMINAL-REASON-1` split the relay's catch-all `session_sealed` into named causes,
     * and this set was one of THREE keyed on the old literal. The rename alone made a terminal
     * refusal non-terminal here — reopening the 68-minute defect this file exists to prevent, by
     * changing a string rather than by touching any logic.
     *
     * That is why the set above is asserted EXACTLY: a new relay reason that nobody adds here is
     * silently treated as transient, and "transient" means the conversation keeps running against a
     * chain that has stopped growing.
     */
    expect(isTerminalRelayRefusal("seal_refused")).toBe(true);
  });

  it("`seal_in_progress` is NOT terminal — a seal in flight may still succeed", () => {
    // The counterexample, and it matters more since DOD-M15-TRANSPORT-TERMINAL-1: a session can
    // now leave `sealing` and return to `active`. Retiring on this would kill a conversation that
    // is about to seal normally.
    expect(isTerminalRelayRefusal("seal_in_progress")).toBe(false);
  });

  it("`session_sealed` is terminal — the relay has closed the session and will never witness again", () => {
    expect(isTerminalRelayRefusal("session_sealed")).toBe(true);
  });

  it("`session_not_found` is terminal — the relay has dropped it and nothing can be added", () => {
    expect(isTerminalRelayRefusal("session_not_found")).toBe(true);
  });

  it("a transient refusal is NOT terminal, so an unreachable relay still degrades gracefully", () => {
    // The guard against over-correcting. If everything became terminal, a brief relay blip would
    // start failing sends that recover on their own — trading a silent failure for a loud false one.
    for (const r of ["relay_unavailable", "timeout", "connection_lost", "no_response", ""]) {
      expect(isTerminalRelayRefusal(r), `'${r}' must stay recoverable`).toBe(false);
    }
  });
});

/**
 * THE BEHAVIOUR — that `sendContent` actually refuses on a terminal reason — is asserted end to end
 * in `packages/e2e-tests/src/spine/j-witness-stall.spine.test.ts`, against two real daemons and a
 * real relay, because that is the only place the relay can genuinely be made to answer
 * `session_sealed`.
 *
 * No fixture is constructed here for it. A mock that returns `session_sealed` and asserts the caller
 * saw it would be testing the mock: the seam it would stub is the exact seam that was wrong.
 */
