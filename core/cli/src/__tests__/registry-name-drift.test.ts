/**
 * Hardcoded command names must still resolve — and retired ones must be gone everywhere.
 *
 * Both halves of this file guard the SAME failure: a command's name is written down as a bare string
 * in places the compiler cannot check, so renaming the command leaves those strings pointing at
 * nothing. Types do not help; a green build proves only that the string is a string.
 *
 * Caught live. `cello consent` became `cello attestation-consent`, and:
 *   - `helpForSpec("consent")` kept the old name, so `cello attestation-consent <bad-sub>` died with
 *     "Fatal: registry: no command 'consent'" — on the very path that exists to HELP a confused user;
 *   - four prose references still told the reader to run `cello consent`, a command that no longer
 *     exists. A search-and-replace for "cello consent " missed every one of them, because they end in
 *     a backtick or a quote rather than a space.
 *
 * Both shipped in 0.0.101 with the full gate green.
 */
import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { COMMANDS } from "../registry.js";

const SRC = join(import.meta.dirname, "..");

/** Every shipping source file — prose in a comment reaches an operator just as code does. */
function shippingSources(): Array<{ file: string; text: string }> {
  const out: Array<{ file: string; text: string }> = [];
  for (const f of readdirSync(SRC).filter((f) => f.endsWith(".ts"))) {
    out.push({ file: f, text: readFileSync(join(SRC, f), "utf8") });
  }
  return out;
}

describe("registry name drift", () => {
  it("every hardcoded helpForSpec() name resolves to a real command", () => {
    // The lookup THROWS on a miss, which is the right behaviour — but it throws at the moment a user
    // asks for help, not at build time. This pulls that failure forward.
    const registry = readFileSync(join(SRC, "registry.ts"), "utf8");
    const names = [...registry.matchAll(/helpForSpec\("([^"]+)"\)/g)].map((m) => m[1]);
    expect(names.length, "no helpForSpec calls found — the pattern or the file changed").toBeGreaterThan(3);

    const known = new Set(COMMANDS.map((c) => c.name));
    const dangling = [...new Set(names)].filter((n) => !known.has(n));
    expect(dangling, "these help lookups name a command that no longer exists").toEqual([]);
  });

  it("no shipping source still tells an operator to run a retired command", () => {
    // A DENYLIST, not an allowlist. Listing the names that must be ABSENT is checkable; listing every
    // name that may appear is not, and an allowlist of prose would go stale the first time someone
    // wrote a sentence. Add a line here whenever a user-facing verb is renamed.
    //
    // The lookahead matters: `cello consent` must fail while `cello attestation-consent` passes, so
    // the pattern cannot simply be the old string — it has to reject a longer name ending in it.
    const RETIRED: Array<{ pattern: RegExp; wasRenamedTo: string }> = [
      { pattern: /(?<![a-z-])cello consent(?![a-z-])/, wasRenamedTo: "cello attestation-consent" },
      { pattern: /(?<![a-z_])cello_consent_/, wasRenamedTo: "cello_attestation_consent_*" },
      { pattern: /cello trust-signals issue(?![a-z-])/, wasRenamedTo: "cello attestations issue" },
      { pattern: /(?<![a-z_])cello_trust_signals_issue(?![a-z_])/, wasRenamedTo: "cello_attestations_issue" },
    ];

    const found: string[] = [];
    for (const { file, text } of shippingSources()) {
      if (file.endsWith(".test.ts")) continue; // this file names them on purpose
      for (const { pattern, wasRenamedTo } of RETIRED) {
        const m = text.match(pattern);
        if (m) found.push(`${file}: "${m[0]}" — renamed to ${wasRenamedTo}`);
      }
    }
    expect(found, "these name a command that no longer exists").toEqual([]);
  });
});
