/**
 * DOD-M12B-DISPATCH-GUIDANCE-1 — a successful send must not read as a failure.
 *
 * OBSERVED LIVE 2026-08-18, and it is the clearest UX defect the whole live test produced. A send on
 * a revived session came back:
 *
 *   { ok: true, delivered: false, reason: "dispatched_to_relay",
 *     guidance: "…It will be delivered the next time the counterparty's daemon reconnects…" }
 *
 * That message arrived on the counterparty's side in **8 seconds**, with the doorbell firing. The
 * sending agent read the response and correctly reported that nothing had changed — because it is
 * BYTE-IDENTICAL to the response returned when the same send took THREE MINUTES, before the revived
 * session reconnected its relay.
 *
 * Two separate faults in one string:
 *
 * 1. **It cannot distinguish success from the failure it replaced.** The rational next move for
 *    anyone reading it is to send again, which duplicates a message that was never lost — the exact
 *    outcome the earlier "it is lost. Send it again." guidance produced, arrived at from the other
 *    direction.
 * 2. **It asserts a cause it does not know.** The counterparty's daemon is usually up the whole
 *    time. This path is taken because the two SESSION NODES hold no direct connection — a different
 *    fact about a different party.
 *
 * `delivered: false` is accurate and stays: it means "not over a direct link". What changes is that
 * the guidance now says so, instead of implying the message is waiting on someone else's outage.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const SRC = readFileSync(join(import.meta.dirname, "..", "session-content-handlers.ts"), "utf-8");

/** The guidance string attached to the `dispatched_to_relay` response, comments stripped. */
function dispatchGuidance(): string {
  const code = SRC.replace(/\/\*[\s\S]*?\*\//g, "");
  const at = code.indexOf('reason: "dispatched_to_relay"');
  expect(at, "the dispatched_to_relay response moved — this test must follow it").toBeGreaterThan(-1);
  return code.slice(at, at + 1400);
}

describe("DOD-M12B-DISPATCH-GUIDANCE-1: relay dispatch reads as the success it is", () => {
  it("does not blame the counterparty's daemon for a path we chose", () => {
    // The counterparty's daemon is typically up throughout. Naming it sends the operator to look at
    // the wrong machine, and tells them to wait for an event that has already happened.
    expect(
      dispatchGuidance().includes("daemon reconnects"),
      "this asserts a cause the daemon cannot know and points at the wrong party",
    ).toBe(false);
  });

  it("says the message is on its way, in words a sender can act on", () => {
    const g = dispatchGuidance();
    expect(g.includes("Sent."), "lead with what happened, not with what did not").toBe(true);
    expect(
      g.includes("seconds"),
      "a sender needs the expected timescale — without it there is no way to tell this from the " +
      "three-minute case it used to be",
    ).toBe(true);
  });

  it("tells the sender NOT to re-send — the duplicate is the real cost", () => {
    // Both failure modes today converge on the same operator behaviour: send it again. One produced
    // duplicates of a message that was lost, the other of a message that arrived in 8 seconds.
    expect(
      dispatchGuidance().includes("duplicate"),
      "without this the rational response to `delivered: false` is to re-send",
    ).toBe(true);
  });

  it("explains that delivered:false is about the PATH, not about failure", () => {
    expect(
      dispatchGuidance().includes("delivered: false"),
      "the field that reads as failure has to be explained where it is returned, not in docs",
    ).toBe(true);
  });
});
