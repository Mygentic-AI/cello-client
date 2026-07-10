/**
 * DOD-DIR-FAILCLOSED-1 (D2), daemon half of the cross-repo contract.
 *
 * The directory now FAILS CLOSED when the target never accepts the session_offer: instead of
 * FROST-signing an assignment with an empty counterparty endpoint (the phantom session's origin),
 * it returns `session_request_error{reason: "counterparty_did_not_accept"}`.
 *
 * `sessionRequestErrorReason` is the LIVE consumer of that frame (daemon.ts's session negotiator).
 * It keeps its own allowlist, and an unlisted reason falls through to `directory_unreachable` — so
 * the operator is told the DIRECTORY was unreachable when the directory was fine and the
 * COUNTERPARTY simply did not accept. That points diagnosis at the wrong subsystem, which is the
 * precise failure mode the debugging discipline exists to prevent. The reason must survive.
 *
 * The daemon suite is green either way, so this test is the only thing that pins the contract on
 * this side of the repo split.
 */
import { describe, it, expect } from "vitest";
import { sessionRequestErrorReason } from "../session-assignment-parser.js";

describe("DOD-DIR-FAILCLOSED-1: the directory's fail-closed reason survives the daemon's mapper", () => {
  it("counterparty_did_not_accept is preserved — never collapsed to directory_unreachable", () => {
    const reason = sessionRequestErrorReason({ type: "session_request_error", reason: "counterparty_did_not_accept" });
    expect(reason).toBe("counterparty_did_not_accept");
    expect(reason).not.toBe("directory_unreachable");
  });

  it("the guidance an operator sees names the counterparty, not the directory", () => {
    // Mirrors daemon.ts's negotiator: `The directory refused the session request (${reason})`.
    // With the collapse, that sentence read "(directory_unreachable)" — a lie about which
    // subsystem failed. The reason string is the only variable part, so pinning it pins the text.
    expect(sessionRequestErrorReason({ reason: "counterparty_did_not_accept" })).toContain("counterparty");
  });

  it("regression: every previously-known reason still maps to itself", () => {
    const known = [
      "target_offline", "relay_unavailable", "frost_signer_not_configured", "directory_below_threshold",
      "ceremony_timeout", "ceremony_exhausted", "ceremony_conflict", "not_registered", "peer_not_registered",
      "no_connection", "connection_id_required", "session_request_missing_peer_id", "agent_revoked", "agent_suspended",
    ];
    for (const r of known) expect(sessionRequestErrorReason({ reason: r })).toBe(r);
  });

  it("regression: an unknown reason still falls back to directory_unreachable (the fallback is right — just not for known reasons)", () => {
    expect(sessionRequestErrorReason({ reason: "some_future_reason" })).toBe("directory_unreachable");
    expect(sessionRequestErrorReason({})).toBe("directory_unreachable");
  });
});
