/**
 * A DATE IS NOT A PHONE NUMBER — the first live false positive after the enforcing flip.
 *
 * Reported from real use on 2026-07-29, hours after the layer went live: an agent citing a date had
 * its message refused twice and could not clear the flag itself. `PHONE_RE` carries `-` in its
 * character class, so `2026-07-29` matched, and the PII disposition is WARN — which means NOT SENT
 * until an operator resolves it.
 *
 * These assert the exclusion is narrow: dates stop warning, real phone numbers still do.
 */
import { describe, it, expect } from "vitest";
import { OutboundPIIScreener } from "../detect/pii.js";

const screener = new OutboundPIIScreener({ whitelist: [] });
const cats = (t: string): string[] =>
  screener
    .screen(new TextEncoder().encode(t), `s-${Math.random()}`)
    .events.map((e) => e.category);

describe("M9B — the phone rule does not fire on dates agents actually write", () => {
  it("does NOT flag an ISO date", () => {
    expect(cats("tracked in 2026-07-29 planning")).not.toContain("pii:phone");
    expect(cats("PR #12345 closed 2026-07-29")).not.toContain("pii:phone");
  });

  it("does NOT flag an ISO datetime — the shape our own log lines carry", () => {
    expect(cats('"ts":"2026-07-29T18:33:51"')).not.toContain("pii:phone");
  });

  it("does NOT flag a digit run beyond the E.164 maximum", () => {
    // 16 digits. E.164 caps a dialable number at 15, so this cannot be a phone number.
    // (An earlier version of this test used 15 digits — exactly AT the maximum — and correctly
    // still flagged; the test data was wrong, not the rule.)
    expect(cats("the run took 1785350111106123 ms")).not.toContain("pii:phone");
  });

  it("STILL flags a 15-digit run — the E.164 maximum is dialable, so it is not excluded", () => {
    expect(cats("id 178535011110612 recorded")).toContain("pii:phone");
  });

  it("STILL flags a real phone number — the exclusion must not weaken the guard", () => {
    expect(cats("call me at +1 415 555 2671")).toContain("pii:phone");
    expect(cats("reach me on 415-555-2671")).toContain("pii:phone");
  });

  it("STILL flags a bare 11-digit run — deliberately NOT excluded", () => {
    // Overlaps the legitimate country-code phone range. Passing it silently would weaken the guard
    // to fix an annoyance; it warns, and the operator escape hatch is what makes that acceptable.
    expect(cats("commit 30479063088 succeeded")).toContain("pii:phone");
  });
});
