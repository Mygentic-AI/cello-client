/**
 * M16 005 review H1 — the client half: a directory refusal over a CHANNEL reaches the operator as
 * what it is.
 *
 * The directory refuses to broker a session naming a broadcast channel (`channel_participant`), and
 * refuses when it cannot check (`channel_check_failed`). `sessionRequestErrorReason` keeps an
 * allowlist, and an unlisted reason falls to `directory_unreachable`. Without these entries, a caller
 * who tried to reach a channel was sent to debug their network.
 */
import { describe, it, expect } from "vitest";
import { sessionRequestErrorReason, sessionRequestErrorGuidance } from "../session-assignment-parser.js";

describe("M16: channel refusals survive the daemon's reason mapper", () => {
  it("channel_participant is preserved, never collapsed to directory_unreachable", () => {
    expect(sessionRequestErrorReason({ type: "session_request_error", reason: "channel_participant" })).toBe("channel_participant");
  });

  it("channel_check_failed is preserved as its own reason", () => {
    expect(sessionRequestErrorReason({ type: "session_request_error", reason: "channel_check_failed" })).toBe("channel_check_failed");
  });

  it("the guidance for a channel says it is a channel and names the admin agent, not the network", () => {
    const g = sessionRequestErrorGuidance("channel_participant");
    expect(g).toMatch(/broadcast channel/);
    expect(g).toMatch(/admin/);
    expect(g).not.toMatch(/registered and online/);
  });

  it("the guidance for a failed check says the directory could not check, and to retry", () => {
    const g = sessionRequestErrorGuidance("channel_check_failed");
    expect(g).toMatch(/could not check/);
    expect(g).toMatch(/[Rr]etry/);
  });

  it("every other reason keeps the existing guidance", () => {
    expect(sessionRequestErrorGuidance("target_offline")).toBe(
      "The directory refused the session request (target_offline). Ensure the counterparty is registered and online.",
    );
  });
});
