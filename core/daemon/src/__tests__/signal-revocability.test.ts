import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { revocabilityOf, REVOCABILITY_SETS } from "../signal-revocability.js";

/**
 * Not every trust signal is the operator's to destroy.
 *
 * Before this, `wallet_revoke_signal` took ANY signal in the wallet by hash prefix and went — no
 * type check anywhere. The signal used in the 2026-08-10 live test was a `track_record`, and the
 * tool accepted the instruction to destroy it and deleted the local copy. The directory path was
 * broken, which is the only reason an operator's behavioural history did not go with it.
 *
 * These tests cover the CLIENT courtesy. They are not the enforcement and must not be read as it —
 * the operator owns this process. The portal refuses mandatory revocations server-side, and the
 * directory already makes a non-issuer's tombstone inert for attestations.
 */
describe("which signals an operator may revoke", () => {
  it("REFUSES the behavioural record — the whole point of it being mandatory", () => {
    const r = revocabilityOf("track_record");
    expect(r.revocable).toBe(false);
    if (r.revocable) throw new Error("unreachable");
    expect(r.category).toBe("mandatory");
    // The reason has to say WHY, or an operator reads it as a bug and goes looking for a way round.
    expect(r.guidance).toMatch(/worth nothing/i);
  });

  it("REFUSES the verified baseline — and says why there is nothing private to remove", () => {
    for (const type of ["email", "phone"]) {
      const r = revocabilityOf(type);
      expect(r.revocable, `${type} must not be revocable`).toBe(false);
      if (r.revocable) throw new Error("unreachable");
      expect(r.category).toBe("mandatory");
      // These assert THAT a channel was verified, never the address or number — the reason the
      // privacy argument for removing them does not exist.
      expect(r.guidance).toMatch(/never the address or number/i);
    }
  });

  it("REFUSES the security-derived pair, and points at the portal instead of just saying no", () => {
    for (const type of ["webauthn", "totp"]) {
      const r = revocabilityOf(type);
      expect(r.revocable, `${type} must not be revocable from the client`).toBe(false);
      if (r.revocable) throw new Error("unreachable");
      expect(r.category).toBe("security_derived");
      // A refusal with no alternative is a dead end. The operator CAN remove these — by turning the
      // factor off — and the message has to carry that or they will assume it is impossible.
      expect(r.guidance).toMatch(/turn the factor off in the portal/i);
      // And it must name the trap, because "why can't I?" is otherwise unanswerable.
      expect(r.guidance).toMatch(/never get the signal back|already enrolled/i);
    }
  });

  it("ALLOWS the additive credentials — this is not 'refuse everything'", () => {
    // Revoking your GitHub link is your call: you added it to look more credible and removing it
    // just makes you look less credible. A guard that refused these would be wrong, and a guard
    // that fires on the normal case gets worked around.
    expect(revocabilityOf("github_id")).toEqual({ revocable: true });
    expect(revocabilityOf("github_anon")).toEqual({ revocable: true });
  });

  it("DEFAULTS an unknown type to revocable — the zero-bump invariant", () => {
    // A new signal type must cost a portal change and nothing else. Defaulting to non-revocable
    // would make every future type silently unrevocable until every operator upgraded their client,
    // and the operator would have no idea why.
    expect(revocabilityOf("some_type_invented_next_month")).toEqual({ revocable: true });
  });

  it("the two protected sets do not overlap", () => {
    const both = [...REVOCABILITY_SETS.mandatory].filter((t) => REVOCABILITY_SETS.securityDerived.has(t));
    expect(both, "a type in both sets would get whichever guidance the branch order happens to hit").toEqual([]);
  });
});

/**
 * WHERE the check sits is as load-bearing as the check itself.
 *
 * The handler's local delete is unconditional — the code says so: "Always hard-delete locally
 * regardless of directory result". A category refusal placed after it would still have destroyed
 * the operator's only copy before saying no.
 */
describe("the refusal happens before anything is destroyed", () => {
  const daemon = readFileSync(join(import.meta.dirname, "..", "daemon.ts"), "utf8");
  const handler = daemon.slice(daemon.indexOf('handlers.set("wallet_revoke_signal"'));
  const body = handler.slice(0, handler.indexOf('handlers.set("', 10));

  it("locates the handler (guards this check against passing vacuously)", () => {
    expect(body).toMatch(/removeWalletSignal/);
    expect(body.length).toBeGreaterThan(200);
  });

  it("checks revocability BEFORE the local delete", () => {
    const check = body.indexOf("revocabilityOf(");
    const del = body.indexOf("removeWalletSignal(");
    expect(check, "the category check must be present").toBeGreaterThan(-1);
    expect(check, "refusing after the delete would still destroy the operator's copy").toBeLessThan(del);
  });

  it("checks revocability BEFORE signing a revoke request", () => {
    // Signing first would put a signed destruction request on the wire for a signal we then refuse
    // to destroy locally — the two halves disagreeing is how divergence starts.
    const check = body.indexOf("revocabilityOf(");
    const sign = body.indexOf("await kp.sign(");
    expect(sign, "the signing step must be present").toBeGreaterThan(-1);
    expect(check).toBeLessThan(sign);
  });
});
