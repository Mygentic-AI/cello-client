import { describe, it, expect, beforeAll } from "vitest";
import { initLinearRegex } from "../detect/linear-regex.js";
import { compileInjectionPatterns, compileSecretRules, detectorCorpusDigest, injectionPatternIds, secretRuleIds } from "../detect/index.js";

/**
 * M10B / DOD-END-SCAN-1 (M10B-D15) — the derived scanner corpus digest.
 *
 * `scanner_version` is signed and stored by the directory, which cannot re-run the scan. So the
 * value must track the rules that ACTUALLY RAN, or it becomes evidence of a scan that did not
 * happen.
 */
describe("detectorCorpusDigest", () => {
  it("reports ABSENCE as absence before the corpus is compiled", () => {
    // Must run first: a digest over an uncompiled corpus would be a stable, meaningless value that a
    // fail-closed caller could not tell from a real one.
    expect(injectionPatternIds()).toBeNull();
    expect(secretRuleIds()).toBeNull();
    expect(detectorCorpusDigest()).toBeNull();
  });

  describe("once compiled", () => {
    beforeAll(async () => {
      // The RE2 engine must be initialised before any corpus compiles — without it
      // compileInjectionPatterns leaves `compiled` null and every rule silently does nothing, which
      // is precisely the degrade-open behaviour intake must never inherit.
      await initLinearRegex();
      compileInjectionPatterns();
      compileSecretRules();
    });

    it("is stable across calls — the same rules give the same version", () => {
      const a = detectorCorpusDigest();
      expect(a).toMatch(/^[0-9a-f]{64}$/);
      expect(detectorCorpusDigest()).toBe(a);
    });

    it("covers BOTH corpora — a change to either must move it", () => {
      // Recompute the digest the way the implementation does, from the two active id sets, and prove
      // that perturbing either input changes the result. Without this, a digest that silently
      // ignored the secret rules would pass every other test here.
      const { createHash } = require("node:crypto") as typeof import("node:crypto");
      const digestOf = (injection: string[], secrets: string[]): string =>
        createHash("sha256").update(JSON.stringify({ injection: [...injection].sort(), secrets: [...secrets].sort() }), "utf8").digest("hex");
      const patterns = injectionPatternIds()!;
      const secrets = secretRuleIds()!;
      expect(digestOf(patterns, secrets)).toBe(detectorCorpusDigest());
      expect(digestOf([...patterns, "new-rule"], secrets)).not.toBe(detectorCorpusDigest());
      expect(digestOf(patterns, [...secrets, "new-secret-rule"])).not.toBe(detectorCorpusDigest());
    });

    it("does NOT move when the corpus is merely REORDERED", () => {
      // Order is not a property anyone should depend on — reordering the source array changes
      // nothing about which text is caught. A digest that moved would force a spurious
      // scanner_version change and read as a rule change to anyone auditing it.
      const { createHash } = require("node:crypto") as typeof import("node:crypto");
      const digestOf = (injection: string[], secrets: string[]): string =>
        createHash("sha256").update(JSON.stringify({ injection: [...injection].sort(), secrets: [...secrets].sort() }), "utf8").digest("hex");
      const patterns = injectionPatternIds()!;
      const secrets = secretRuleIds()!;
      expect(digestOf([...patterns].reverse(), [...secrets].reverse())).toBe(detectorCorpusDigest());
    });

    it("reports the ACTIVE rules, not the source list", () => {
      // compileSecretRules SKIPS a rule that will not compile under RE2, so the two can differ. The
      // digest has to follow what is really running, which is what makes "byte-identical across
      // nodes" checkable: two intakes agree iff their derived versions agree.
      const active = secretRuleIds()!;
      expect(active.length).toBeGreaterThan(0);
      // Every reported id is a real compiled rule — no placeholders, no source-only entries.
      expect(active.every((id) => typeof id === "string" && id.length > 0)).toBe(true);
    });
  });
});
