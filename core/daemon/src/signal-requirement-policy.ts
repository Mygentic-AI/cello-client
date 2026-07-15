/**
 * DOD-FLOOR-1 — the deterministic trust-signal floor.
 *
 * A SignalRequirementPolicy evaluates whether a counterparty's presented signals meet the
 * minimum bar. Predicates on ENVELOPE FIELDS ONLY: type string, issuer_kind, count, expiry,
 * age. Never the payload content (INV-ZERO-BUMP), never the LLM's judgment.
 *
 * The floor is a LOWER BOUND — the LLM/config may only RESTRICT on top, never relax.
 * A contact that fails the floor is refused; one that passes may still be refused by
 * the discretionary layer above.
 *
 * V1 field set (spec §14.4 defers definition here):
 *   - require_types: string[]  — type strings the contact MUST present (all must be satisfied)
 *   - require_issuer_kind: "portal" | "agent" | null — if set, at least one signal must match
 *   - min_count: number — minimum total active signals required
 *
 * The "demand bundle" (round-2 request) is exactly `require_types` serialized as a list.
 */

import type { ReceivedSignalRow } from "./trust-signal-store.js";

export interface SignalRequirementPolicy {
  require_types?: string[];
  require_issuer_kind?: "portal" | "agent";
  min_count?: number;
}

export interface PolicyEvaluation {
  pass: boolean;
  missing_types?: string[];
  missing_issuer_kind?: boolean;
  actual_count?: number;
}

/**
 * Evaluate a policy against a set of received (verified, active) signals.
 *
 * Only active-verdict signals count. The evaluation is deterministic: same inputs → same output,
 * no network calls, no LLM, no clock (expiry is pre-filtered by the caller or the store).
 */
export function evaluateSignalPolicy(
  policy: SignalRequirementPolicy,
  signals: ReadonlyArray<Pick<ReceivedSignalRow, "type" | "issuerKind" | "verdict">>,
): PolicyEvaluation {
  const active = signals.filter((s) => s.verdict === "active");

  if (policy.min_count !== undefined && policy.min_count > 0) {
    if (active.length < policy.min_count) {
      return { pass: false, actual_count: active.length };
    }
  }

  if (policy.require_issuer_kind) {
    const hasKind = active.some((s) => s.issuerKind === policy.require_issuer_kind);
    if (!hasKind) {
      return { pass: false, missing_issuer_kind: true };
    }
  }

  if (policy.require_types && policy.require_types.length > 0) {
    const presentTypes = new Set(active.map((s) => s.type));
    const missing = policy.require_types.filter((t) => !presentTypes.has(t));
    if (missing.length > 0) {
      return { pass: false, missing_types: missing };
    }
  }

  return { pass: true };
}

/**
 * The DEFAULT floor policy (alpha / v1):
 *   - Require at least 1 portal-attested signal for contacts below KNOWN tier.
 *   - KNOWN+ contacts pass unconditionally (they've already earned trust through interaction).
 *
 * The tier-conditioned policy is the CALLER's job — this module only evaluates a given policy
 * against a given signal set. The caller decides which policy applies based on the contact's
 * tier and passes it here.
 */
export const DEFAULT_UNKNOWN_POLICY: SignalRequirementPolicy = {
  min_count: 1,
  require_issuer_kind: "portal",
};

export const NO_REQUIREMENT: SignalRequirementPolicy = {};
