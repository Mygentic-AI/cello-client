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

  // REMOVED: "does NOT flag a digit run beyond the E.164 maximum". That rule is gone (review F4)
  // — `4155552671000000` is a real number with six zeros stapled on, and the exclusion passed it.
  // The reported false positive was dates, never long ids, so the rule bought nothing and cost a
  // covert channel. The replacement assertions are in the F3/F4 block below.

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

describe("M9B — review F3/F4: a date next to a phone number is still a phone number", () => {
  const screener2 = new OutboundPIIScreener({ whitelist: [] });
  const c = (t: string): string[] =>
    screener2.screen(new TextEncoder().encode(t), `s-${Math.random()}`).events.map((e) => e.category);

  it("FLAGS a phone number that follows a date — the start-anchor bypass", () => {
    // One greedy match starting date-shaped. The first fix discarded the whole thing.
    expect(c("2026-07-29 415-555-2671")).toContain("pii:phone");
    expect(c("2026-07-29 (415) 555-2671")).toContain("pii:phone");
    expect(c("2026-07-29 14155552671")).toContain("pii:phone");
    expect(c("2026-07-29-4155552671")).toContain("pii:phone");
  });

  it("FLAGS a phone number padded past 15 digits — the >15 exclusion is gone", () => {
    expect(c("ref 4155552671000000 end")).toContain("pii:phone");
    expect(c("ref 0000004155552671 end")).toContain("pii:phone");
  });

  it("STILL does not flag a bare date", () => {
    expect(c("tracked in 2026-07-29 planning")).not.toContain("pii:phone");
  });
});
