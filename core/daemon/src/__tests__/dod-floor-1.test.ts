/**
 * DOD-FLOOR-1 — the deterministic trust-signal floor policy.
 *
 * Evaluates whether a counterparty's signals meet the minimum bar.
 * Predicates on ENVELOPE FIELDS ONLY: type, issuer_kind, count.
 * Never payload content (INV-ZERO-BUMP). Deterministic, no network, no LLM.
 */
import { describe, it, expect } from "vitest";
import {
  evaluateSignalPolicy,
  DEFAULT_UNKNOWN_POLICY,
  NO_REQUIREMENT,
  type SignalRequirementPolicy,
} from "../signal-requirement-policy.js";

function sig(type: string, issuerKind: "portal" | "agent", verdict: "active" | "revoked" = "active") {
  return { type, issuerKind, verdict };
}

describe("DOD-FLOOR-1 — SignalRequirementPolicy evaluation", () => {
  describe("min_count", () => {
    it("passes when enough active signals exist", () => {
      const policy: SignalRequirementPolicy = { min_count: 2 };
      const result = evaluateSignalPolicy(policy, [sig("phone", "portal"), sig("email", "portal")]);
      expect(result.pass).toBe(true);
    });

    it("fails when too few active signals", () => {
      const policy: SignalRequirementPolicy = { min_count: 2 };
      const result = evaluateSignalPolicy(policy, [sig("phone", "portal")]);
      expect(result.pass).toBe(false);
      expect(result.actual_count).toBe(1);
    });

    it("does NOT count revoked signals toward min_count", () => {
      const policy: SignalRequirementPolicy = { min_count: 2 };
      const result = evaluateSignalPolicy(policy, [sig("phone", "portal"), sig("email", "portal", "revoked")]);
      expect(result.pass).toBe(false);
      expect(result.actual_count).toBe(1);
    });
  });

  describe("require_issuer_kind", () => {
    it("passes when at least one signal has the required issuer_kind", () => {
      const policy: SignalRequirementPolicy = { require_issuer_kind: "portal" };
      const result = evaluateSignalPolicy(policy, [sig("phone", "portal")]);
      expect(result.pass).toBe(true);
    });

    it("fails when no signal has the required issuer_kind", () => {
      const policy: SignalRequirementPolicy = { require_issuer_kind: "portal" };
      const result = evaluateSignalPolicy(policy, [sig("endorsement", "agent")]);
      expect(result.pass).toBe(false);
      expect(result.missing_issuer_kind).toBe(true);
    });

    it("a revoked signal with matching issuer_kind does NOT satisfy", () => {
      const policy: SignalRequirementPolicy = { require_issuer_kind: "portal" };
      const result = evaluateSignalPolicy(policy, [sig("phone", "portal", "revoked")]);
      expect(result.pass).toBe(false);
    });
  });

  describe("require_types (the demand bundle)", () => {
    it("passes when all required types are present", () => {
      const policy: SignalRequirementPolicy = { require_types: ["phone", "email"] };
      const result = evaluateSignalPolicy(policy, [sig("phone", "portal"), sig("email", "portal")]);
      expect(result.pass).toBe(true);
    });

    it("fails with missing types when not all are present", () => {
      const policy: SignalRequirementPolicy = { require_types: ["phone", "email"] };
      const result = evaluateSignalPolicy(policy, [sig("phone", "portal")]);
      expect(result.pass).toBe(false);
      expect(result.missing_types).toEqual(["email"]);
    });

    it("unknown types can be required (INV-ZERO-BUMP — no enum, no type check)", () => {
      const policy: SignalRequirementPolicy = { require_types: ["future_unknown_type"] };
      const result = evaluateSignalPolicy(policy, [sig("future_unknown_type", "portal")]);
      expect(result.pass).toBe(true);
    });

    it("revoked signals do NOT satisfy require_types", () => {
      const policy: SignalRequirementPolicy = { require_types: ["phone"] };
      const result = evaluateSignalPolicy(policy, [sig("phone", "portal", "revoked")]);
      expect(result.pass).toBe(false);
      expect(result.missing_types).toEqual(["phone"]);
    });
  });

  describe("combined predicates", () => {
    it("all predicates must pass for overall pass", () => {
      const policy: SignalRequirementPolicy = {
        min_count: 2,
        require_issuer_kind: "portal",
        require_types: ["phone"],
      };
      // Has 2 signals, has portal, has phone type — all pass
      const result = evaluateSignalPolicy(policy, [sig("phone", "portal"), sig("email", "agent")]);
      expect(result.pass).toBe(true);
    });

    it("fails on the first predicate that doesn't hold", () => {
      const policy: SignalRequirementPolicy = {
        min_count: 3,
        require_issuer_kind: "portal",
        require_types: ["phone"],
      };
      const result = evaluateSignalPolicy(policy, [sig("phone", "portal")]);
      expect(result.pass).toBe(false);
    });
  });

  describe("default policies", () => {
    it("DEFAULT_UNKNOWN_POLICY requires 1 portal-attested signal", () => {
      expect(evaluateSignalPolicy(DEFAULT_UNKNOWN_POLICY, []).pass).toBe(false);
      expect(evaluateSignalPolicy(DEFAULT_UNKNOWN_POLICY, [sig("endorsement", "agent")]).pass).toBe(false);
      expect(evaluateSignalPolicy(DEFAULT_UNKNOWN_POLICY, [sig("phone", "portal")]).pass).toBe(true);
    });

    it("NO_REQUIREMENT passes unconditionally (for KNOWN+ contacts)", () => {
      expect(evaluateSignalPolicy(NO_REQUIREMENT, []).pass).toBe(true);
      expect(evaluateSignalPolicy(NO_REQUIREMENT, [sig("phone", "portal")]).pass).toBe(true);
    });
  });
});

/**
 * M10B / DOD-END-COUNT-1 — co-ownership does not count toward a floor.
 *
 * THE ATTACK: Alice runs ten agents, has each endorse another, and presents all ten. Every
 * endorsement is genuine — signed, notarized, active. A naive `active.length >= min_count` passes and
 * she has manufactured standing out of her own machines.
 */
describe("DOD-END-COUNT-1 — same-operator endorsements are excluded from min_count", () => {
  const endorsement = (sameOperator: boolean) => ({
    type: "endorsement", issuerKind: "agent" as const, verdict: "active" as const, sameOperator,
  });

  it("REFUSES a floor cleared only by an operator's own agents", () => {
    // Ten real endorsements, all Alice's. This is the whole point of the line.
    const ten = Array.from({ length: 10 }, () => endorsement(true));
    const r = evaluateSignalPolicy({ min_count: 3 }, ten);
    expect(r.pass, "ten self-endorsements must not clear a floor of three").toBe(false);
    expect(r.actual_count, "the COUNTABLE total, not the raw one").toBe(0);
    expect(r.excluded_same_operator, "and the operator can see why").toBe(10);
  });

  it("PASSES on genuine third-party endorsements — the exclusion is not 'reject everything'", () => {
    // Without this, satisfying the test above by failing every count would pass, and the floor would
    // be unusable rather than sound.
    const three = Array.from({ length: 3 }, () => endorsement(false));
    expect(evaluateSignalPolicy({ min_count: 3 }, three).pass).toBe(true);
  });

  it("counts the third-party ones and ignores the co-owned ones, in the same bundle", () => {
    // The realistic shape: Alice has two real endorsements and pads with three of her own.
    const mixed = [endorsement(false), endorsement(false), endorsement(true), endorsement(true), endorsement(true)];
    const r = evaluateSignalPolicy({ min_count: 3 }, mixed);
    expect(r.pass, "two genuine endorsements do not meet a floor of three").toBe(false);
    expect(r.actual_count).toBe(2);
    expect(r.excluded_same_operator).toBe(3);
    // And two genuine ones DO meet a floor of two — the padding neither helps nor hurts.
    expect(evaluateSignalPolicy({ min_count: 2 }, mixed).pass).toBe(true);
  });

  it("does NOT report an exclusion count when nothing was excluded", () => {
    // A field that is always present teaches a reader nothing. `excluded_same_operator` appearing at
    // all is the signal that padding was attempted.
    const r = evaluateSignalPolicy({ min_count: 5 }, [endorsement(false)]);
    expect(r.pass).toBe(false);
    expect(r.excluded_same_operator).toBeUndefined();
  });

  it("treats an ABSENT flag as not-co-owned, never as unknown", () => {
    // Absent means false by construction: the envelope preimage is a closed set, so a decoded signal
    // always carries a boolean. A signal that somehow reached here without one is a third-party
    // endorsement as far as this predicate is concerned — and the DECODER refuses a pre-M10B
    // 11-slot envelope outright, so there is no path by which an unflagged old signal arrives.
    const r = evaluateSignalPolicy({ min_count: 1 }, [{ type: "endorsement", issuerKind: "agent", verdict: "active" } as never]);
    expect(r.pass).toBe(true);
  });
});
