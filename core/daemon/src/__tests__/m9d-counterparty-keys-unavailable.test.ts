/**
 * M9D 002-PQKEYS — the client half of `counterparty_keys_unavailable`.
 *
 * The directory refuses to broker a session when either profile lacks a post-quantum key or its v2
 * binding — after V68 that can only mean replication has not delivered the row to the node that
 * answered. `sessionRequestErrorReason` keeps an allowlist and an unlisted reason falls to
 * `directory_unreachable`, which would send the operator to debug their network for a profile that
 * has simply not reached one node yet.
 */
import { describe, it, expect } from "vitest";
import { sessionRequestErrorReason, sessionRequestErrorGuidance } from "../session-assignment-parser.js";

describe("M9D: counterparty_keys_unavailable survives the daemon's reason mapper", () => {
  it("is preserved, never collapsed to directory_unreachable", () => {
    expect(sessionRequestErrorReason({ type: "session_request_error", reason: "counterparty_keys_unavailable" }))
      .toBe("counterparty_keys_unavailable");
  });

  it("the guidance names the cause (a profile not yet replicated) and the remedy (retry / another node)", () => {
    const g = sessionRequestErrorGuidance("counterparty_keys_unavailable");
    expect(g).toMatch(/post-quantum/);
    expect(g).toMatch(/[Rr]etry/);
    expect(g).not.toMatch(/registered and online/);
  });
});
