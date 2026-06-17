/**
 * CELLO-M7-SESSION-003 — liveness→attestation mapping (AC-006, AC-011)
 *
 * AC-006: the mapping used by the unilateral-seal path maps each liveness value:
 *   'gone' → ABSENT; 'alive' → DELIVERED; 'unknown' → DELIVERED (fail-safe).
 *   It NEVER returns CLEAN or FLAGGED, and NEVER returns ABSENT for any input
 *   other than a positive 'gone'.
 * AC-011: the DELIVERED attestation is never promotable to Active/CLEAN/FLAGGED
 *   by a liveness signal — the mapping's codomain is exactly {DELIVERED, ABSENT}.
 *
 * Pure function — no external state; no CELLO_E2E_LIVE guard.
 */
import { describe, it, expect } from "vitest";
import { livenessToAttestation } from "../session-liveness.js";

describe("livenessToAttestation (AC-006 / AC-011)", () => {
  it("maps 'gone' → ABSENT", () => {
    expect(livenessToAttestation("gone")).toBe("ABSENT");
  });

  it("maps 'alive' → DELIVERED", () => {
    expect(livenessToAttestation("alive")).toBe("DELIVERED");
  });

  it("maps 'unknown' → DELIVERED (fail-safe)", () => {
    expect(livenessToAttestation("unknown")).toBe("DELIVERED");
  });

  it("only 'gone' yields ABSENT — no other input does", () => {
    const inputs = ["alive", "unknown"] as const;
    for (const i of inputs) {
      expect(livenessToAttestation(i)).not.toBe("ABSENT");
    }
  });

  it("codomain is exactly {DELIVERED, ABSENT} — never CLEAN/FLAGGED/PENDING", () => {
    const outputs = new Set(
      (["alive", "gone", "unknown"] as const).map((l) => livenessToAttestation(l)),
    );
    for (const o of outputs) {
      expect(["DELIVERED", "ABSENT"]).toContain(o);
    }
    expect(outputs.has("DELIVERED" as never)).toBe(true);
    expect(outputs.has("ABSENT" as never)).toBe(true);
    // CLEAN / FLAGGED are unreachable from this function.
    expect([...outputs]).not.toContain("CLEAN");
    expect([...outputs]).not.toContain("FLAGGED");
  });
});
