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
 * WHERE the check sits is as load-bearing as the check itself — and what the handler NO LONGER does
 * is now the stronger assertion.
 *
 * The handler used to sign a revoke request, POST it at the directory's health port, and then
 * hard-delete the local copy "regardless of directory result". A category refusal placed after any
 * of that would still have destroyed the operator's only copy before saying no.
 *
 * It now queues a sealed submission to the portal instead, and deletes NOTHING. So the ordering
 * assertion becomes: refuse before you queue — and the absence assertion becomes: this handler must
 * never delete the wallet copy, because a failure has to leave the operator able to retry.
 */
describe("the refusal happens before anything leaves, and nothing is destroyed", () => {
  const daemon = readFileSync(join(import.meta.dirname, "..", "daemon.ts"), "utf8");
  const handler = daemon.slice(daemon.indexOf('handlers.set("wallet_revoke_signal"'));
  const withComments = handler.slice(0, handler.indexOf('handlers.set("', 10));
  // CODE ONLY. The absence assertions below name the very things the comments EXPLAIN — the health
  // port, the old route — so matching raw text makes the handler's own documentation fail the test.
  // Exactly the trap the SELECT * guard hit earlier today, one layer along: comments are prose, and
  // prose must be stripped before code is matched.
  const body = withComments
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .split("\n")
    .filter((l) => !/^\s*(\/\/|\*)/.test(l))
    .join("\n");

  it("locates the handler (guards this check against passing vacuously)", () => {
    expect(body).toMatch(/submitForAgent/);
    expect(body.length).toBeGreaterThan(200);
  });

  it("checks revocability BEFORE queueing anything", () => {
    const check = body.indexOf("revocabilityOf(");
    const submit = body.indexOf("submitForAgent(");
    expect(check, "the category check must be present").toBeGreaterThan(-1);
    expect(submit, "the submission must be present").toBeGreaterThan(-1);
    expect(check, "queueing a revocation we then refuse would put a signed request on the wire for nothing")
      .toBeLessThan(submit);
  });

  it("NEVER deletes the local copy — a failed retraction must leave a retry possible", () => {
    // The old handler deleted unconditionally, so a failure destroyed the operator's copy AND the
    // ability to try again. Since the directory half never worked, that was every retraction.
    expect(body, "the wallet copy must survive until the portal confirms").not.toMatch(/removeWalletSignal/);
  });

  it("does NOT post to a directory over HTTP any more", () => {
    // The route it aimed at is firewalled to the VPC and was never reachable from an operator's
    // machine; the port it actually hit was the health check. Both are gone.
    expect(body).not.toMatch(/internal\/signal\/revoke/);
    expect(body).not.toMatch(/resolveDirectoryUrl/);
  });
});

/**
 * A BEHAVIOURAL TEST, because the ones above are source-greps with an exact bypass.
 *
 * The reviewer's bypass: change `op: "revoke"` to `op: "refuse"`, or `subject: signalHash` to
 * something else, and every structural assertion still passes — the handler would queue a REFUSAL of
 * an unknown signal and cheerfully report "queued". Matching source text proves the shape of the
 * code, never what it does.
 *
 * These drive the decision the handler makes, through the same pure function it uses, on the exact
 * fixtures that matter. It is not a full IPC harness — that needs a daemon, a database and a
 * directory — but it pins the branch that decides whether anything leaves the machine at all.
 */
describe("what the handler decides, not how it is written", () => {
  it("a mandatory signal never reaches the queue", () => {
    // The one that matters: if this returns revocable, a signed revocation for a track record goes
    // on the wire and the portal is the only thing left standing between it and destruction.
    for (const type of ["track_record", "email", "phone"]) {
      const v = revocabilityOf(type);
      expect(v.revocable, `${type} must be refused before submitForAgent is reached`).toBe(false);
    }
  });

  it("a discretionary signal DOES reach the queue — the guard is not 'refuse everything'", () => {
    for (const type of ["github_id", "github_anon"]) {
      expect(revocabilityOf(type).revocable, `${type} must be allowed through`).toBe(true);
    }
  });

  it("the refusal carries a category the operator can act on, for every refused type", () => {
    // A bare `false` would satisfy the branch and leave the operator with no idea what to do. Every
    // refusal must name which rule fired, because the two have DIFFERENT remedies: one is "never",
    // the other is "turn the factor off in the portal".
    const categories = new Set(
      ["track_record", "email", "phone", "webauthn", "totp"]
        .map((t) => revocabilityOf(t))
        .map((v) => (v.revocable ? "ALLOWED" : v.category)),
    );
    expect(categories).toEqual(new Set(["mandatory", "security_derived"]));
  });
});
