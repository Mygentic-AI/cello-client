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
