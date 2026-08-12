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

  it("retires on session_not_found too — the relay no longer holds it either way", () => {
    const f = fixture();
    const res = terminalRelayRefusal(f.deps, { sessionId: "s-2", reason: "session_not_found", correlationId: "c-2" });
    expect(f.retired).toEqual(["s-2"]);
    expect(res.error).toContain("no longer holds this session");
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
    // Ordering is the guarantee: the row is corrected before anything that could fail. Reversed,
    // a daemon could report a refusal it had not acted on — which is the pre-fix state exactly.
    expect(order).toEqual(["log", "retire"]);
  });

  it("tells the operator the session was retired, not that they must go and check", () => {
    const f = fixture();
    const res = terminalRelayRefusal(f.deps, { sessionId: "s-6", reason: "session_sealed", correlationId: undefined });
    // The old guidance sent them to `cello_sessions` to discover the divergence themselves and
    // start a new session by hand. The daemon now does it, so the sentence has to say so — leaving
    // the old wording would send an operator to fix something already fixed.
    expect(res.guidance).toContain("retired the session");
    expect(res.guidance).toContain("next send will start a fresh one");
    expect(res.guidance).not.toContain("Check cello_sessions");
  });
});
