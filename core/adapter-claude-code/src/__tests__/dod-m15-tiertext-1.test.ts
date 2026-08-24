/**
 * DOD-M15-TIERTEXT-1 — the MCP tool descriptions do not promise a gate that does not exist.
 *
 * ─── The defect, from the operator's chair ─────────────────────────────────────────────────────
 *
 * `cello_contact_set_tier` shipped as *"3=whitelisted (auto-accepted when you're away)"*, and
 * `cello_contact_add` as *"…NOT auto-accepted when you're away. Promote them to whitelisted/vip …
 * to let them reach you unattended."* Both attributed unattended acceptance to the tier, and both
 * misled the reader in the SAFE-FEELING direction: whitelisting is not the reason a peer got through.
 *
 * ─── ⚠️ AND THE FIRST REPLACEMENT WAS FALSE IN THE OTHER DIRECTION, WHICH IS WORSE ─────────────
 *
 * It read *"note EVERY tier is auto-accepted; tiers govern how much, not whether"*. **Acceptance IS
 * gated on tier.** `checkUnknownSenderAcceptanceBound` reads `getTier`, resolves that tier's
 * `max_sessions`, and refuses at the cap — and `DEFAULT_TIER_BOUNDS[BLOCKED]` is `0`, so a blocked
 * contact is refused on the FIRST knock (`inbound-sessions.ts`: *"BLOCKED 0 → refused here"*).
 *
 * So the sentence contradicted the `0=blocked` clause two clauses earlier, and told an operator —
 * and any agent reading the tool surface — **that their block does nothing.** The original defect
 * over-promised a protection; that one denied a protection that exists, and it pointed at the kill
 * switch. Corrected to "tiers 1-4 are auto-accepted WITHIN THEIR CAPS; above tier 0, tiers govern
 * how much, not whether."
 *
 * ─── What this file does and does NOT enforce ─────────────────────────────────────────────────
 *
 * The line's enforcer wants every claim-vocabulary match adjudicated into `claims-ledger.ts` so the
 * count shrinks. **That cannot be done from here yet**, and the reason is a dependency nobody wrote
 * down: `shippedSurfaces()` enumerates `.md` files plus one hard-coded string, so it cannot produce
 * `cello-mcp.ts` as a surface at all — adding rows for it made the scanner's own orphan guard fail
 * and turned main red. Teaching the scanner to read this surface is `DOD-M15-TOOLDESC-SCAN-1`.
 * **This file therefore pins the regression, not the ledger arithmetic.**
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const SURFACE_PATH = join(import.meta.dirname, "..", "bin", "cello-mcp.ts");

/**
 * Every tool description on the surface.
 *
 * ⚠️ `\s*` after `server.tool(` is load-bearing: the first version required the name on the SAME
 * line, which silently skipped `cello_backup` and `cello_restore` — two of fifty-eight, both
 * declared multi-line, both carrying claim vocabulary nobody had read. An extractor that
 * under-counts makes every guard built on it narrower than it appears, so the count is asserted
 * below rather than trusted.
 */
function toolDescriptions(src: string): Array<{ tool: string; desc: string }> {
  return [...src.matchAll(/server\.tool\(\s*"([a-z_0-9]+)",\s*"((?:[^"\\]|\\.)*)"/g)].map((m) => ({
    tool: m[1]!,
    desc: m[2]!,
  }));
}

describe("DOD-M15-TIERTEXT-1 — the tier descriptions", () => {
  const src = readFileSync(SURFACE_PATH, "utf8");

  it("★ the extractor sees EVERY tool — a guard is only as wide as what it reads", () => {
    const declared = src.split("server.tool(").length - 1;
    expect(
      toolDescriptions(src).length,
      `${declared} server.tool( declarations but the extractor found fewer — a description it cannot ` +
        `see is one the regression guard below cannot protect`,
    ).toBe(declared);
  });

  it("★ THE FALSE CLAIM IS GONE — no description attributes unattended acceptance to a tier", () => {
    /**
     * The regression guard, and the sentence an operator actually read and believed, which is how
     * this line was found.
     */
    for (const { tool, desc } of toolDescriptions(src)) {
      expect(
        /auto-accepted when you'?re away/i.test(desc),
        `${tool} still claims a tier decides who reaches you while you are away`,
      ).toBe(false);
      expect(
        /promote them to whitelisted\/vip .* reach you unattended/i.test(desc),
        `${tool} still tells the operator to raise a tier in order to be reachable unattended`,
      ).toBe(false);
    }
  });

  it("★ AND THE CORRECTION IS NOT FALSE THE OTHER WAY — nothing says every tier is accepted", () => {
    /**
     * The guard against my own first fix. Acceptance IS tier-gated at tier 0, so an unqualified
     * "EVERY tier is auto-accepted" denies the kill switch. Any future rewording that drops the
     * qualifier reddens here.
     */
    for (const { tool, desc } of toolDescriptions(src)) {
      expect(
        /every tier is auto-accepted/i.test(desc),
        `${tool} claims every tier is auto-accepted. Tier 0 is refused on the first knock — ` +
          `checkUnknownSenderAcceptanceBound reads getTier and BLOCKED's cap is 0. This sentence ` +
          `tells an operator their block does nothing.`,
      ).toBe(false);
    }
    const setTier = toolDescriptions(src).find((t) => t.tool === "cello_contact_set_tier")!;
    expect(
      setTier.desc,
      "and tier 0 must still be described as refusing — the one tier that does gate WHO",
    ).toMatch(/0=blocked \(refused/);
  });

  it("★ `isAutoAccept` still has no production caller — the OTHER tier gate stays unwired", () => {
    /**
     * ⚠️ NAMED FOR WHAT IT CHECKS, after review caught the previous name asserting something false.
     * It was called "nothing gates ACCEPTANCE on tier" — and something does. This test looks at the
     * one tier function that is NOT wired; it never proved the broader claim, and a green test
     * sitting beside a false description implied a proof it had not given.
     *
     * It is still worth having: if `isAutoAccept` is ever wired up, tier gains a SECOND acceptance
     * gate and every description on this surface needs re-reading.
     *
     * Walks all packages, not just the top level of one — the method is public on
     * `SessionNodeManager`, so a caller in `core/cli` or `core/client` would leave a daemon-only
     * scan green while the surface became wrong.
     */
    const root = join(import.meta.dirname, "..", "..", "..");
    const callers: string[] = [];
    const walk = (dir: string): void => {
      for (const e of readdirSync(dir, { withFileTypes: true })) {
        if (e.name === "node_modules" || e.name === "dist" || e.name === "__tests__") continue;
        const full = join(dir, e.name);
        if (e.isDirectory()) { walk(full); continue; }
        if (!e.name.endsWith(".ts")) continue;
        const text = readFileSync(full, "utf8");
        for (const m of text.matchAll(/\bisAutoAccept\s*\(/g)) {
          const isDefinition = /isAutoAccept\s*\(\s*agentName/.test(text.slice(m.index, m.index + 60));
          if (!isDefinition) callers.push(`${e.name}:${text.slice(0, m.index).split("\n").length}`);
        }
      }
    };
    for (const pkg of readdirSync(root, { withFileTypes: true })) {
      if (!pkg.isDirectory()) continue;
      try { walk(join(root, pkg.name, "src")); } catch { /* package has no src */ }
    }
    expect(
      callers,
      "isAutoAccept now has a caller — tier has a second acceptance gate and every tier description " +
        "on this surface must be re-read against it",
    ).toEqual([]);
  });
});
