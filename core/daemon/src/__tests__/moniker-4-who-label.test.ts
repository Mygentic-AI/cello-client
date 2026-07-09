/**
 * MONIKER-4 AC1 — whoLabel: pure, total, never blank (M8C-MONIKER-SPEC §MONIKER-4).
 *
 * Tests are written RED-first per SPARC Phase R.
 */
import { describe, expect, it } from "vitest";
import { fingerprint, whoLabel } from "../who-label.js";

const PK = "178d420b86beb79d2cd819647368d3e24739dcfa526a95f32c0e95ba3bc3e44c";

describe("MONIKER-4 AC1 — fingerprint", () => {
  it("renders the spec's format: 'agent 178d420b…'", () => {
    expect(fingerprint(PK)).toBe("agent 178d420b…");
  });

  it("is total — garbage still yields a non-empty label, never a throw", () => {
    for (const bad of ["", null, undefined, 42, {}, "abc"]) {
      const out = fingerprint(bad as unknown as string);
      expect(typeof out).toBe("string");
      expect(out.length).toBeGreaterThan(0);
    }
  });

  it("always contains a space — the unforgeable discriminator (MONIKER_RE excludes spaces)", () => {
    expect(fingerprint(PK)).toContain(" ");
    expect(fingerprint("")).toContain(" ");
  });
});

describe("MONIKER-4 AC1 — whoLabel precedence (local ?? offered ?? fingerprint)", () => {
  it("local pet name always wins, and ONLY local sets whoKnown", () => {
    expect(whoLabel({ localMoniker: "MyBob", offeredMoniker: "Bob", pubkeyHex: PK })).toEqual({
      who: "MyBob",
      whoKnown: true,
      source: "local",
    });
  });

  it("offered name is the middle tier — an unverified hint, whoKnown false", () => {
    expect(whoLabel({ localMoniker: null, offeredMoniker: "Bob", pubkeyHex: PK })).toEqual({
      who: "Bob",
      whoKnown: false,
      source: "offered",
    });
  });

  it("fingerprint is the floor — never blank", () => {
    expect(whoLabel({ localMoniker: null, offeredMoniker: null, pubkeyHex: PK })).toEqual({
      who: "agent 178d420b…",
      whoKnown: false,
      source: "fingerprint",
    });
  });

  it("never truncates a name — a 64-char moniker survives intact (AC3: only fingerprints shorten)", () => {
    const long = "A".repeat(64);
    expect(whoLabel({ localMoniker: long, offeredMoniker: null, pubkeyHex: PK }).who).toBe(long);
    expect(whoLabel({ localMoniker: null, offeredMoniker: long, pubkeyHex: PK }).who).toBe(long);
  });

  it("is total — an invalid name that somehow reaches it degrades to the next tier, never throws", () => {
    // Boundary validation makes these unreachable; totality means whoLabel is safe even if misused.
    expect(whoLabel({ localMoniker: "bad name", offeredMoniker: "Bob", pubkeyHex: PK }).who).toBe("Bob");
    expect(whoLabel({ localMoniker: null, offeredMoniker: 'Bob"', pubkeyHex: PK }).who).toBe("agent 178d420b…");
    const out = whoLabel({ localMoniker: undefined as unknown as string, offeredMoniker: undefined, pubkeyHex: "" });
    expect(out.who.length).toBeGreaterThan(0);
    expect(out.whoKnown).toBe(false);
  });
});
