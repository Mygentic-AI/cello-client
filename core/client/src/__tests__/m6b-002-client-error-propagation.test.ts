/**
 * CELLO-M6B-002: FROST ceremony error propagation — client tests
 *
 * Specification:
 *   AC-005: client.ts maps ceremony_timeout wire reason to InitiateSessionResult
 *   AC-006: client.ts maps ceremony_exhausted wire reason to InitiateSessionResult
 *   AC-007: types.ts includes new reasons in InitiateSessionResult union
 *
 * DOD-LEGACY-MCP-1 (2026-07-12): AC-009 and AC-010 lived here too. They asserted the *message text*
 * of the `cello_initiate_session` tool handler inside `mcp-server.ts` — the legacy in-process MCP
 * server, now deleted. They drove it through InMemoryTransport with a stub CelloClient, so the only
 * code they constrained was that dead handler's string formatting. Their subject is gone, so they
 * are gone.
 *
 * Everything below survives untouched: it tests `mapSessionRequestErrorFrame` in the LIVE
 * `client.ts` and the `InitiateSessionResult` union in the LIVE `types.ts`, and never needed the
 * MCP server at all. This file was the worked example in the deletion plan for exactly this reason
 * — a file-level "it imports the dead server, delete it" would have destroyed real coverage.
 */

import { describe, it, expect } from "vitest";
import { mapSessionRequestErrorFrame } from "../client.js";
import type { InitiateSessionResult } from "../types.js";

describe("CELLO-M6B-002: Client-side error propagation", () => {
  // ─── AC-005: client.ts ceremony_timeout mapping ──────────────────────────────
  // Tests the RUNTIME behavior of mapSessionRequestErrorFrame (extracted from
  // initiateSession). If lines 5394-5395 of client.ts were deleted or typo'd,
  // this test fails — unlike a pure compile-time type assertion.

  it("AC-005: mapSessionRequestErrorFrame maps ceremony_timeout wire reason to InitiateSessionResult", () => {
    const frame = { type: "session_request_error", reason: "ceremony_timeout" };
    const result = mapSessionRequestErrorFrame(frame);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("ceremony_timeout");
      // Must NOT map to any existing reason
      expect(result.reason).not.toBe("directory_below_threshold");
      expect(result.reason).not.toBe("directory_unreachable");
    }
  });

  // ─── AC-006: client.ts ceremony_exhausted mapping ────────────────────────────

  it("AC-006: mapSessionRequestErrorFrame maps ceremony_exhausted wire reason to InitiateSessionResult", () => {
    const frame = { type: "session_request_error", reason: "ceremony_exhausted" };
    const result = mapSessionRequestErrorFrame(frame);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("ceremony_exhausted");
      // Must NOT map to any existing reason
      expect(result.reason).not.toBe("directory_below_threshold");
      expect(result.reason).not.toBe("directory_unreachable");
    }
  });

  // ─── AC-007: types.ts union completeness ─────────────────────────────────────

  it("AC-007: InitiateSessionResult type allows ceremony_timeout and ceremony_exhausted", () => {
    // Compile-time check that both new reasons are valid members of InitiateSessionResult
    const timeout: InitiateSessionResult = { ok: false, reason: "ceremony_timeout" };
    const exhausted: InitiateSessionResult = { ok: false, reason: "ceremony_exhausted" };
    const existing: InitiateSessionResult = { ok: false, reason: "directory_below_threshold" };

    expect(timeout.ok).toBe(false);
    expect(exhausted.ok).toBe(false);
    expect(existing.ok).toBe(false);
  });

  // ─── AC-005/AC-006 companion: existing reasons still map correctly ───────────

  it("AC-005/AC-006: mapSessionRequestErrorFrame preserves all pre-existing reasons", () => {
    const cases: Array<[string, string]> = [
      ["target_offline", "target_offline"],
      ["relay_unavailable", "relay_unavailable"],
      ["frost_signer_not_configured", "frost_signer_not_configured"],
      ["directory_below_threshold", "directory_below_threshold"],
      ["ceremony_conflict", "ceremony_conflict"],
      ["no_connection", "no_connection"],
      ["unknown_future_reason", "directory_unreachable"],
    ];
    for (const [wireReason, expectedReason] of cases) {
      const result = mapSessionRequestErrorFrame({ type: "session_request_error", reason: wireReason });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe(expectedReason);
      }
    }
  });
});

// ─── DOD-DIR-FAILCLOSED-1 (D2) cross-repo: the fail-closed reason must SURVIVE the mapper ───
//
// The directory now fails closed with session_request_error{counterparty_did_not_accept} instead
// of FROST-signing an endpoint-less assignment. But every mapper keeps its OWN allowlist, and an
// unlisted reason falls through to `directory_unreachable` — telling the operator the DIRECTORY
// was unreachable when the directory was fine and the COUNTERPARTY simply never accepted. That
// names the wrong subsystem, which is exactly what the debugging discipline forbids.
// `agent_revoked` / `agent_suspended` were already being swallowed the same way.
describe("DOD-DIR-FAILCLOSED-1: distinct directory reasons are not collapsed to directory_unreachable", () => {
  it("counterparty_did_not_accept survives the mapper (the counterparty refused — the directory is fine)", () => {
    const result = mapSessionRequestErrorFrame({ type: "session_request_error", reason: "counterparty_did_not_accept" });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("counterparty_did_not_accept");
      expect(result.reason).not.toBe("directory_unreachable");
    }
  });

  it("agent_revoked and agent_suspended survive the mapper (pre-existing collapse, same defect)", () => {
    for (const reason of ["agent_revoked", "agent_suspended"] as const) {
      const result = mapSessionRequestErrorFrame({ type: "session_request_error", reason });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toBe(reason);
    }
  });

  it("a genuinely unknown reason still falls back to directory_unreachable (the fallback is correct — just not for known reasons)", () => {
    const result = mapSessionRequestErrorFrame({ type: "session_request_error", reason: "some_future_reason" });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("directory_unreachable");
  });
});
