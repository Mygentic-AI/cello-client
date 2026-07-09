/**
 * MONIKER-0 — the charset's single home (M8C-MONIKER-SPEC §MONIKER-0)
 *
 * Tests are written RED-first per SPARC Phase R.
 *
 * This module is the ONE home of the agent-name / moniker rule. The charset is
 * the entire injection defense for the moniker work (no sanitizer subsystem
 * exists), so the reject battery below IS the defense — each security-relevant
 * reject is an individual, named assertion so a future widening of the rule
 * trips a named test instead of sliding through green (AC3).
 */
import { describe, expect, it } from "vitest";
import { MONIKER_RE, validateMoniker } from "../moniker.js";

describe("MONIKER-0 AC1 — the constant", () => {
  it("is byte-identical to the rule the daemon has always enforced", () => {
    // The exact literal previously inlined at daemon.ts:1941 and daemon.ts:2048.
    // MONIKER-0 is a pure refactor: any widening or narrowing here is the
    // failure this module exists to prevent.
    expect(MONIKER_RE.source).toBe("^[a-zA-Z0-9_-]{1,64}$");
    expect(MONIKER_RE.flags).toBe("");
  });
});

describe("MONIKER-0 — accept battery", () => {
  it.each([
    "a",
    "Bob",
    "CELLO_Support",
    "Ms_Chelly",
    "agent-1",
    "x_y-Z9",
    "0123456789",
    "_leading_underscore",
    "-leading-hyphen",
    "A".repeat(64),
  ])("accepts %j and returns it unchanged", (name) => {
    expect(validateMoniker(name)).toBe(name);
  });
});

describe("MONIKER-0 AC3 — named reject battery (the injection defense)", () => {
  // Each dangerous class is its own assertion, by name. Do NOT collapse these
  // into a loop over an array of "bad strings" — a named test failing is the
  // signal that someone widened the wire charset.

  it("rejects newline", () => {
    expect(validateMoniker("Bob\nEve")).toBeNull();
  });

  it("rejects carriage return", () => {
    expect(validateMoniker("Bob\rEve")).toBeNull();
  });

  it("rejects tab", () => {
    expect(validateMoniker("Bob\tEve")).toBeNull();
  });

  it("rejects other control characters", () => {
    expect(validateMoniker("Bob\x00Eve")).toBeNull(); // NUL
    expect(validateMoniker("Bob\x1bEve")).toBeNull(); // ESC
    expect(validateMoniker("Bob\x7fEve")).toBeNull(); // DEL
  });

  it("rejects double quote (the unverified-marker forgery character)", () => {
    // MONIKER-4 AC4 renders unverified names as `"Bob" (unverified)` — the
    // marker is unforgeable only because quotes cannot appear in a name.
    expect(validateMoniker('Bob"trusted')).toBeNull();
  });

  it("rejects single quote", () => {
    expect(validateMoniker("Bob'trusted")).toBeNull();
  });

  it("rejects open paren", () => {
    expect(validateMoniker("Bob(verified")).toBeNull();
  });

  it("rejects close paren", () => {
    expect(validateMoniker("Bob)verified")).toBeNull();
  });

  it("rejects space", () => {
    expect(validateMoniker("Bob verified")).toBeNull();
  });

  it("rejects non-ASCII codepoints (homoglyph defense)", () => {
    expect(validateMoniker("Вob")).toBeNull(); // Cyrillic В (U+0412)
    expect(validateMoniker("Bоb")).toBeNull(); // Cyrillic о (U+043E)
    expect(validateMoniker("Bob™")).toBeNull();
    expect(validateMoniker("👍")).toBeNull();
  });

  it("rejects markup characters", () => {
    expect(validateMoniker("<channel>")).toBeNull();
    expect(validateMoniker("Bob</channel")).toBeNull();
  });

  it("rejects 65 characters (one over the max)", () => {
    expect(validateMoniker("A".repeat(65))).toBeNull();
  });

  it("rejects empty string", () => {
    expect(validateMoniker("")).toBeNull();
  });

  it("rejects non-string inputs without throwing", () => {
    expect(validateMoniker(undefined)).toBeNull();
    expect(validateMoniker(null)).toBeNull();
    expect(validateMoniker(42 as unknown as string)).toBeNull();
    expect(validateMoniker({} as unknown as string)).toBeNull();
  });
});

describe("MONIKER-0 AC3 — strip-oracle regression", () => {
  // Stripping disallowed characters is a mutation oracle: a sender blocked
  // from "CELLO_Support" sends "C*E*L*L*O*_*S*u*p*p*o*r*t" and stripping
  // constructs the impersonation FOR them. The validator must REJECT invalid
  // input outright — never repair it into a valid name.

  it("rejects a starred impersonation attempt — never repairs it", () => {
    const attempt = "C*E*L*L*O*_*S*u*p*p*o*r*t";
    const result = validateMoniker(attempt);
    expect(result).toBeNull();
    expect(result).not.toBe("CELLO_Support");
  });

  it("returns either the input verbatim or null — never a transformed string", () => {
    const inputs = ["Bob", " Bob", "Bob ", "B ob", "Bob\n", "Bób", "A".repeat(65)];
    for (const raw of inputs) {
      const result = validateMoniker(raw);
      expect(result === raw || result === null).toBe(true);
    }
  });
});
