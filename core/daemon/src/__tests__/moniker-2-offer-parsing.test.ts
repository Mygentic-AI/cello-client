/**
 * MONIKER-2 — offer-moniker parsing helpers (M8C-MONIKER-SPEC §MONIKER-2).
 *
 * Tests are written RED-first per SPARC Phase R.
 *
 * These two helpers are THE validation seams:
 *  - extractOfferedMoniker: the receiver's wire boundary (AC2) — validated ONCE
 *    here so downstream code can never observe an invalid moniker. Absent ≠
 *    invalid: absent is an older client (silent); present-but-invalid is a
 *    modified sender (rejected: true → caller logs moniker.rejected).
 *  - resolveOutboundMoniker: the initiator's offer-construction re-validation
 *    (MONIKER-1 AC3's deferred half) — omit rather than send a bad value.
 */
import { describe, expect, it } from "vitest";
import { extractOfferedMoniker, resolveOutboundMoniker } from "../session-assignment-parser.js";

describe("MONIKER-2 AC2 — extractOfferedMoniker (the wire boundary)", () => {
  it("returns a valid moniker unchanged, not rejected", () => {
    expect(extractOfferedMoniker({ moniker: "Wonderland_Alice" })).toEqual({
      offeredMoniker: "Wonderland_Alice",
      rejected: false,
    });
  });

  it("absent field → null, NOT rejected (older client, log nothing)", () => {
    expect(extractOfferedMoniker({})).toEqual({ offeredMoniker: null, rejected: false });
    expect(extractOfferedMoniker({ moniker: undefined })).toEqual({ offeredMoniker: null, rejected: false });
  });

  it("present-but-invalid → null AND rejected, with a diagnostic reason (review F2)", () => {
    // Reason granularity: charset vs length vs not-a-string — so moniker.rejected tells the
    // operator WHAT was wrong without ever logging the raw value.
    expect(extractOfferedMoniker({ moniker: "not a name" })).toEqual({ offeredMoniker: null, rejected: true, reason: "charset" });
    expect(extractOfferedMoniker({ moniker: 'Bob"(unverified)' })).toEqual({ offeredMoniker: null, rejected: true, reason: "charset" });
    expect(extractOfferedMoniker({ moniker: "<channel>" })).toEqual({ offeredMoniker: null, rejected: true, reason: "charset" });
    expect(extractOfferedMoniker({ moniker: "A".repeat(65) })).toEqual({ offeredMoniker: null, rejected: true, reason: "length" });
    expect(extractOfferedMoniker({ moniker: "" })).toEqual({ offeredMoniker: null, rejected: true, reason: "length" });
    expect(extractOfferedMoniker({ moniker: 42 })).toEqual({ offeredMoniker: null, rejected: true, reason: "not_string" });
    expect(extractOfferedMoniker({ moniker: ["Bob"] })).toEqual({ offeredMoniker: null, rejected: true, reason: "not_string" });
  });

  it("strip-oracle: an invalid name is rejected, never repaired", () => {
    const r = extractOfferedMoniker({ moniker: "C*E*L*L*O*_*S*u*p*p*o*r*t" });
    expect(r.offeredMoniker).toBeNull();
    expect(r.rejected).toBe(true);
  });
});

describe("MONIKER-2 AC1 — resolveOutboundMoniker (offer construction, defense in depth)", () => {
  it("passes a valid outbound name through", () => {
    expect(resolveOutboundMoniker("CELLO_Support")).toBe("CELLO_Support");
  });

  it("omits (undefined) when there is no name — never an empty string", () => {
    expect(resolveOutboundMoniker(null)).toBeUndefined();
  });

  it("omits rather than sending a value that fails validation", () => {
    // Store-level validation should make this unreachable; this is the
    // defense-in-depth re-check the spec requires at offer construction.
    expect(resolveOutboundMoniker("broken name")).toBeUndefined();
    expect(resolveOutboundMoniker("")).toBeUndefined();
    expect(resolveOutboundMoniker("A".repeat(65))).toBeUndefined();
  });
});
