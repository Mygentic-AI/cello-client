/**
 * DOD-DOC-TOOLS-1 review, finding 7 — the `cello doc` sub-verbs had NO guard at all.
 *
 * ── WHAT WAS UNPROTECTED ─────────────────────────────────────────────────────────────────────────
 *
 * `cello doc` dispatches eleven sub-verbs from one `run` body, as a chain of
 * `if (sub === "…" && target) return doc…(…)`. Two guards exist nearby and neither covers it:
 *
 *   - the vocabulary test checks only that the TOP-LEVEL word `doc` is a real command;
 *   - `dispatch-parity.test.ts` iterates a hand-maintained `expected` map with no doc entries at
 *     all — the classic hollow shape, where omitting something makes the loop shorter and never red.
 *
 * So deleting `if (sub === "diff" && target) return docDiff(...)` leaves every test green while
 * `cello doc diff` silently prints help and exits 1. The contact group has exactly this test
 * ("contact: every sub-verb routes to its OWN function"); the doc group did not.
 *
 * ── WHY THIS IS A SOURCE-STRUCTURAL TEST ─────────────────────────────────────────────────────────
 *
 * Invoking each sub-verb for real needs a running daemon, and would fail on the connection rather
 * than on the routing — so it would pass for the wrong reason exactly when the routing is broken.
 * Reading the dispatch body is what actually fails when a branch is removed, which is the property
 * this file exists to hold. Same reasoning as the composition-root guard in
 * `document-leaf-kind-on-the-wire.test.ts`: assert the seam that silently drops things.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { helpForSpec } from "../registry.js";

const REGISTRY_SRC = readFileSync(new URL("../registry.ts", import.meta.url), "utf8");

/** The body of `doc`'s `run`, which is where routing lives. */
function docRunBody(): string {
  const start = REGISTRY_SRC.indexOf('\n    name: "doc",');
  expect(start, "the doc command spec was renamed — this guard is now pointing at nothing").toBeGreaterThan(0);
  // The NEXT top-level command spec, matched at its own indentation. Matching `name: "` alone finds
  // the first flag declaration inside this spec and slices the body away — which made every case
  // here fail for a reason that had nothing to do with the code under test.
  const end = REGISTRY_SRC.indexOf('\n    name: "', start + 10);
  return REGISTRY_SRC.slice(start, end === -1 ? undefined : end);
}

/** Every sub-verb the help text advertises to an operator. */
const ADVERTISED = [
  "inbox", "list", "propose", "invite", "accept", "refuse",
  "read", "write", "diff", "watch", "publish", "close", "kill",
];

describe("every advertised `cello doc` sub-verb is actually routed", () => {
  const body = docRunBody();

  for (const verb of ADVERTISED) {
    it(`routes '${verb}'`, () => {
      expect(
        body.includes(`sub === "${verb}"`),
        `'cello doc ${verb}' is advertised but has no dispatch branch — it prints help and exits 1, ` +
          `and no other test in this repo fails when that happens`,
      ).toBe(true);
    });
  }

  it("the help text advertises exactly what is routed, in both directions", () => {
    // Catches the opposite drift too: a branch that exists but is undocumented, which an operator
    // can only find by reading source.
    const help = helpForSpec("doc");
    for (const verb of ADVERTISED) {
      expect(help, `'${verb}' is routed but the help never mentions it`).toContain(verb);
    }

    const routed = [...body.matchAll(/sub === "([a-z-]+)"/g)].map((m) => m[1]!);
    for (const verb of new Set(routed)) {
      expect(
        ADVERTISED,
        `'cello doc ${verb}' is dispatched but is not in this test's advertised list — add it here ` +
          `and to the help, or remove the branch`,
      ).toContain(verb);
    }
  });
});

describe("a flag where an id belongs is refused, not silently mis-parsed", () => {
  it("`doc propose --retry <id>` does not read the flag as the peer pubkey", () => {
    // `--retry` is a real flag on this command, and re-sending an offer takes no pubkey. With the
    // pubkey absent it landed in `target`, and the daemon answered `invalid_peer_pubkey` — an error
    // about the wrong thing entirely, on a command the operator typed exactly as documented.
    const body = docRunBody();
    expect(
      /rawTarget\.startsWith\("--"\)/.test(body),
      "nothing stops a flag being consumed as the positional id, so `--retry` becomes the pubkey",
    ).toBe(true);
  });
});
