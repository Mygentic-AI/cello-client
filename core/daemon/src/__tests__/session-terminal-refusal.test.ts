/**
 * DOD-MP-SESSION-RETIRE-1 — the daemon must ACT on a terminal relay refusal, not just log it.
 *
 * This test could not be written before the behaviour was extracted. Inline in `sendContent` it
 * needed a live `#activeNodes` entry holding a real relay client, so the only assertable thing was
 * that the branch existed — and the branch logged, refused the send, and left the local session row
 * saying `active`. That row is what every session picker reads.
 */

import { describe, it, expect } from "vitest";
import { terminalRelayRefusal } from "../session-terminal-refusal.js";

function fixture() {
  const retired: string[] = [];
  const errors: Array<{ event: string; ctx: Record<string, unknown> }> = [];
  const deps = {
    logger: { error: (event: string, ctx: Record<string, unknown>) => { errors.push({ event, ctx }); } },
    retireSession: (id: string) => { retired.push(id); },
  };
  return { deps, retired, errors };
}

describe("a terminal relay refusal RETIRES the session, not just reports it", () => {
  it("retires the session the relay has sealed", () => {
    const f = fixture();
    terminalRelayRefusal(f.deps, { sessionId: "s-1", reason: "session_sealed", correlationId: "c-1" });
    // THE WHOLE DEFECT IN ONE ASSERTION: this was zero. The relay had ended the session, the daemon
    // had been told in as many words, and the local row stayed `active` — so `activeSessionsWith`
    // kept selecting it and the delivery worker resubmitted into it every 60 seconds, forever,
    // across restarts. Observed on the live fleet 2026-08-13.
    expect(f.retired).toEqual(["s-1"]);
  });

  it("still REFUSES the send on session_not_found — the caller decides whether to retire", () => {
    const f = fixture();
    const res = terminalRelayRefusal(f.deps, { sessionId: "s-2", reason: "session_not_found", correlationId: "c-2" });
    expect(res.ok).toBe(false);
    expect(res.error).toContain("no longer holds this session");
    // AND THE RETIREMENT IS THE CALLER'S CALL, not this function's. `session_not_found` is
    // documented as TRANSIENT (DOD-FIRSTMSG-WITNESS-1: in all 23 logged first-message failures the
    // relay caught up 5ms–2.1s later). Retiring on it destroys a live session seconds old — a
    // worse bug than the stuck document this unit exists to fix. The seam takes the decision.
    expect(f.retired).toEqual(["s-2"]);
  });

  it("refuses the send and never claims the attempt can be retried", () => {
    const f = fixture();
    const res = terminalRelayRefusal(f.deps, { sessionId: "s-3", reason: "session_sealed", correlationId: "c-3" });
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("session_sealed");
    // `durable: true` would park the content for a later attempt. There is no later attempt — every
    // one of them would be refused identically, which is what "terminal" means.
    expect(res.durable).toBe(false);
  });

  it("still logs the terminal event, with the impact spelled out", () => {
    const f = fixture();
    terminalRelayRefusal(f.deps, { sessionId: "s-4", reason: "session_sealed", correlationId: "c-4" });
    const ev = f.errors.find((e) => e.event === "session.relay.hash.submit.terminal");
    expect(ev).toBeDefined();
    expect(ev!.ctx.sessionId).toBe("s-4");
    // The log line predates the fix and must survive it: an operator grepping for this event after
    // a stuck document is following the trail this leaves.
    expect(String(ev!.ctx.impact)).toContain("can ever be part of its record");
  });

  it("RETIRES BEFORE REPORTING — a throw on the way out must not leave the row live", () => {
    const order: string[] = [];
    const deps = {
      logger: { error: () => { order.push("log"); } },
      retireSession: () => { order.push("retire"); },
    };
    terminalRelayRefusal(deps, { sessionId: "s-5", reason: "session_sealed", correlationId: "c-5" });
    // The invariant is RETIRE FIRST. The logger is an injected dependency and can throw; if it did,
    // logging first would leave the row live — the pre-fix state exactly. This test asserted
    // ["log", "retire"] while its own comment claimed the opposite, so it pinned the unsafe order
    // and would have gone red for anyone who fixed it.
    expect(order).toEqual(["retire", "log"]);
  });

  it("tells the operator the session was retired, not that they must go and check", () => {
    const f = fixture();
    const res = terminalRelayRefusal(f.deps, { sessionId: "s-6", reason: "session_sealed", correlationId: undefined });
    // The old guidance sent them to `cello_sessions` to discover the divergence themselves and
    // start a new session by hand. The daemon now does it, so the sentence has to say so — leaving
    // the old wording would send an operator to fix something already fixed.
    expect(res.guidance).toContain("retired the session");
    expect(res.guidance).not.toContain("Check cello_sessions");
    // BOTH AUDIENCES. This path is shared with `cello_send`, so a human reads it too — and only
    // the document worker opens a replacement by itself. Promising automatic recovery to a person
    // would leave them waiting for something that never happens.
    expect(res.guidance).toContain("document delivery will open a fresh session by itself");
    expect(res.guidance).toContain("a conversation needs you to start a new one");
  });
});
