/**
 * DOD-M15-TIERTEXT-1 — the MCP tool descriptions do not promise a gate that does not exist.
 *
 * ─── The defect, from the operator's chair ─────────────────────────────────────────────────────
 *
 * `cello_contact_set_tier` shipped as *"3=whitelisted (auto-accepted when you're away)"*, and
 * `cello_contact_add` as *"…NOT auto-accepted when you're away. Promote them to whitelisted/vip …
 * to let them reach you unattended."* Both attributed unattended acceptance to the tier.
 *
 * **EVERY tier is auto-accepted.** So the promise was not unkept — it was REDUNDANT, which is the
 * worse shape: whitelisting did not fail to let someone through, it failed to be the *reason* they
 * got through. An operator reading it concludes strangers are held back while they are away. They
 * are not, and **the reader is misled in the safe-feeling direction.**
 *
 * ─── ⚠️ WHY THIS FILE EXISTS AT ALL, WHICH IS THE PART WORTH READING ───────────────────────────
 *
 * The DoD line's enforcer is explicit that a hand audit is not evidence:
 *
 *   > *"Enforcer — NOT 'I read the file'. … every claim-vocabulary match in `cello-mcp.ts`
 *   > adjudicated into `helpers/claims-ledger.ts` with its verdict and evidence … so the work is a
 *   > **shrinking count**, not a paragraph saying it was done."*
 *
 * **`claims-ledger.ts` had NO IMPORTER.** 900 lines of adjudications, exported and read by nothing —
 * so the count was never computed, never compared, never asserted. Adding rows to it would have been
 * an assertion that the work happened, wearing the costume of evidence, which is the exact thing the
 * enforcer was written to forbid.
 *
 * That is the same defect this milestone keeps producing — **a value with no reader** — sitting in
 * the mechanism meant to enforce against it.
 *
 * **Scope, deliberately narrow.** This consumes the ledger for ONE surface: `cello-mcp.ts`. Sweeping
 * the other eight is `DOD-M15-LEDGER-1`, which Andre PARKED until after Tier 4. Building its
 * machinery here would be doing a parked line's work under another line's name.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ADJUDICATED, countClaimWords } from "./helpers/claims-ledger.js";

const SURFACE = "core/adapter-claude-code/src/bin/cello-mcp.ts (tool descriptions)";
const SURFACE_PATH = join(import.meta.dirname, "..", "bin", "cello-mcp.ts");

/** Only the description strings — the first string argument of each `server.tool(...)` call. */
function toolDescriptions(src: string): Array<{ tool: string; desc: string }> {
  return [...src.matchAll(/server\.tool\("([a-z_]+)",\s*"((?:[^"\\]|\\.)*)"/g)].map((m) => ({
    tool: m[1]!,
    desc: m[2]!,
  }));
}

describe("DOD-M15-TIERTEXT-1 — the tier descriptions, and the ledger that accounts for them", () => {
  const src = readFileSync(SURFACE_PATH, "utf8");
  const rows = ADJUDICATED.filter((r) => r.surface === SURFACE);

  it("★ THE FALSE CLAIM IS GONE — no description attributes unattended acceptance to a tier", () => {
    /**
     * The regression guard, and it is worth more than the ledger arithmetic below: this is the exact
     * sentence an operator read and believed, which is how the line was found.
     */
    for (const { tool, desc } of toolDescriptions(src)) {
      expect(
        /auto-accepted when you'?re away/i.test(desc),
        `${tool} still claims a tier decides who reaches you while you are away. Every tier is ` +
          `auto-accepted; tiers govern how much, not whether.`,
      ).toBe(false);
      expect(
        /promote them to whitelisted\/vip .* reach you unattended/i.test(desc),
        `${tool} still tells the operator to raise a tier in order to be reachable unattended`,
      ).toBe(false);
    }
  });

  it("★ every ledger excerpt for this surface still appears VERBATIM in it", () => {
    /**
     * A row whose excerpt has drifted accounts for nothing. Without this, the ledger silently stops
     * matching the file it claims to adjudicate — and the count below would keep reporting success
     * against text that no longer exists.
     */
    expect(rows.length, "the surface must have adjudicated rows at all").toBeGreaterThan(0);
    for (const row of rows) {
      for (const excerpt of row.excerpts) {
        expect(
          src.includes(excerpt),
          `ledger row "${row.claim}" quotes text that is no longer in the surface:\n  ${excerpt}`,
        ).toBe(true);
      }
    }
  });

  it("★ THE SHRINKING COUNT: every claim-vocabulary hit in a tier/contact description is adjudicated", () => {
    /**
     * The enforcer's actual demand. The ledger's own `countClaimWords` is used — the same regex the
     * scanner applies — so an unadjudicated claim shows up as a number, not as a feeling.
     *
     * Scoped to the contact/tier tools this DoD line owns. The remaining tools on this surface are
     * `LEDGER-1`'s sweep and it is parked; counting them here would report a failure for work
     * deliberately not being done yet.
     */
    const OWNED = ["cello_contacts", "cello_contact_add", "cello_contact_set_tier", "cello_config_set"];
    const accounted = rows.reduce((n, r) => n + r.excerpts.reduce((m, e) => m + countClaimWords(e), 0), 0);
    const present = toolDescriptions(src)
      .filter((t) => OWNED.includes(t.tool))
      .reduce((n, t) => n + countClaimWords(t.desc), 0);

    expect(
      accounted,
      `${present} claim-vocabulary hits across ${OWNED.length} owned descriptions, but the ledger ` +
        `accounts for ${accounted}. An unaccounted hit is an unaudited claim — adjudicate it into ` +
        `claims-ledger.ts with a verdict and evidence, or delete the claim.`,
    ).toBeGreaterThanOrEqual(present);
  });

  it("★ THE REPLACEMENT CLAIM IS TRUE TOO: nothing gates ACCEPTANCE on tier", () => {
    /**
     * The corrected text now asserts *"EVERY tier is auto-accepted; tiers govern how much, not
     * whether"*. A fix that replaces a false claim with an unverified one has moved the problem, so
     * this pins the new sentence rather than only the absence of the old one.
     *
     * The claim is an ABSENCE, so the evidence is one: `isAutoAccept` — the only tier check that
     * could gate acceptance — has NO PRODUCTION CALLER. `session-node-manager.ts` defines it and its
     * own docstring says the consumer is the offline mailbox and it is *"defined here as the seam"*.
     *
     * **This is the guard that matters if someone later wires it up.** The day acceptance starts
     * depending on tier, this test goes red — and the description saying tiers do not gate who
     * reaches you becomes false at the same moment. Better a red test than a quietly-true-again
     * promise nobody re-reads.
     *
     * The other two corrected claims already have behaviour tests and are not duplicated here:
     * the stranger-pool exemption at `m8c-abuse-1.test.ts` ("a KNOWN+ contact is not part of the
     * stranger pool"), and finite per-tier caps via `INV-TIER-BOUND`.
     */
    const { readdirSync } = require("node:fs") as typeof import("node:fs");
    const daemonSrc = join(import.meta.dirname, "..", "..", "..", "daemon", "src");
    const callers: string[] = [];
    for (const f of readdirSync(daemonSrc).filter((n) => n.endsWith(".ts"))) {
      const text = readFileSync(join(daemonSrc, f), "utf8");
      // A CALL, not the definition and not a mention in prose.
      for (const m of text.matchAll(/\bisAutoAccept\s*\(/g)) {
        const line = text.slice(0, m.index).split("\n").length;
        const isDefinition = /isAutoAccept\s*\(agentName: string/.test(text.slice(m.index, m.index + 60));
        if (!isDefinition) callers.push(`${f}:${line}`);
      }
    }
    expect(
      callers,
      "acceptance is now gated on tier somewhere — so 'EVERY tier is auto-accepted; tiers govern " +
        "how much, not whether' has become FALSE and the description must change with the code",
    ).toEqual([]);
  });

  it("★ a `true` verdict may not rest on nobody enforcing it", () => {
    /**
     * Carried from `DOD-M15-CLAIM-SCANNER-1` and load-bearing: a claim held up by the operator's own
     * rewritable client and one held up by the absence of a wire field are different facts. A row
     * marked `true` with `nobody-yet` is only honest when the claim asserts an ABSENCE.
     */
    for (const row of rows.filter((r) => r.verdict === "true")) {
      expect(
        row.enforcedBy,
        `"${row.claim}" is marked true but nothing enforces it`,
      ).not.toBe("nobody-yet");
      expect(row.evidence.length, `"${row.claim}" has no evidence`).toBeGreaterThan(80);
    }
  });
});
