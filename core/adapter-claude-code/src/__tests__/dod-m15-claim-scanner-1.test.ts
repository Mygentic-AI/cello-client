/**
 * DOD-M15-CLAIM-SCANNER-1 — an unlisted claim fails the build.
 *
 * ─── Why a test and not a document ─────────────────────────────────────────────────────────────
 *
 * `DOD-M15-LEDGER-1` produced a prose claims ledger, and its review found the ledger incomplete.
 * Andre's word for the shape was **"letter, not spirit"**: completeness rested on one grep
 * vocabulary at one moment — *never / cannot / impossible* — so it missed *tamper-proof*, *ACTIVE*,
 * *screened*, *encrypted*, *verifiable*, *notarized*, *proof*. A ledger is a chore that looks like a
 * control. The prose stays as the reasoning record; **this** is what makes it true tomorrow.
 *
 * ─── Iterate what the system HAS, never a list someone maintains ───────────────────────────────
 *
 * The surfaces are enumerated from `package.json#files` (what actually ships in the tarball), the
 * plugin tree, and the repo root — never from a hand-kept array. That is not fastidiousness: the
 * connect tarball's `SKILL.md` was missed by every audit written for a previous story **precisely
 * because it was not on anyone's list**, and it shipped naming three tools that had been renamed or
 * deleted. Follow what SHIPS, not what compiles.
 *
 * ─── The baseline is a BACKLOG, not an exemption ───────────────────────────────────────────────
 *
 * A first run found **101 claim-shaped lines across 9 shipped surfaces**, against a ledger holding
 * 13 rows and covering 2 of them. Seven surfaces had never been audited at all.
 *
 * Adjudicating 101 claims is real work and cannot be a precondition for having the guard. So the
 * current count per surface is recorded here as a dated baseline that may only **shrink**: a NEW
 * claim-shaped line fails immediately, and the numbers cannot be raised to accommodate one. That is
 * the same shape the chain-writes guard uses, and it is the difference between a backlog and a
 * blanket exemption.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

/** Repo root — the directory holding the workspace file. */
function repoRoot(): string {
  let dir = HERE;
  for (let i = 0; i < 10; i++) {
    if (existsSync(join(dir, "vitest.workspace.ts")) && existsSync(join(dir, "pnpm-workspace.yaml"))) return dir;
    dir = dirname(dir);
  }
  throw new Error("could not locate the repo root");
}
const ROOT = repoRoot();

/**
 * THE CLAIM VOCABULARY — words that make a promise a reader will act on.
 *
 * Deliberately absolute-leaning. "encrypted" and "verifiable" are here because both have already
 * appeared in a FALSE claim on a shipped surface: an AES-GCM envelope described as end-to-end when
 * it was not, and "both parties can independently verify" when one side could not.
 *
 * This list is expected to GROW. Each addition re-baselines, which is the point — a vocabulary
 * frozen at one moment is exactly how the prose ledger came to be incomplete.
 */
const CLAIM_VOCABULARY =
  /\b(never|cannot|impossible|tamper-proof|tamper-evident|independently verify|verifiable|notarized|zero-knowledge|no one can|nobody can|only you|guarantee[ds]?)\b/i;

/**
 * Every shipped prose surface, discovered from the system.
 *
 *   - `package.json#files` per workspace package — what the npm tarball actually carries.
 *   - the plugin tree — skills and agent definitions an operator installs.
 *   - the repo root — README, AUDIT-ME, what a prospective adopter reads first.
 */
function shippedSurfaces(): string[] {
  const out = new Set<string>();

  const coreDir = join(ROOT, "core");
  for (const pkg of readdirSync(coreDir)) {
    const pj = join(coreDir, pkg, "package.json");
    if (!existsSync(pj)) continue;
    const files = (JSON.parse(readFileSync(pj, "utf8")) as { files?: string[] }).files ?? [];
    for (const f of files) {
      if (!f.endsWith(".md")) continue;
      const full = join(coreDir, pkg, f);
      if (existsSync(full)) out.add(full);
    }
  }

  for (const f of readdirSync(ROOT)) {
    if (f.endsWith(".md") && statSync(join(ROOT, f)).isFile()) out.add(join(ROOT, f));
  }

  const plugins = join(ROOT, "plugins");
  if (existsSync(plugins)) {
    const walk = (dir: string): void => {
      for (const e of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, e.name);
        if (e.isDirectory()) walk(full);
        else if (e.name.endsWith(".md")) out.add(full);
      }
    };
    walk(plugins);
  }

  return [...out].sort();
}

function claimLines(file: string): number {
  return readFileSync(file, "utf8").split("\n").filter((l) => CLAIM_VOCABULARY.test(l)).length;
}

/**
 * Claim-shaped lines per shipped surface, as of 2026-08-22. **Shrink these; never raise them.**
 *
 * A number here is not an approval — it is a count of lines nobody has adjudicated yet. Lowering one
 * means those claims were checked against the code and either verified, corrected, or withdrawn, and
 * the reasoning went into the prose ledger.
 */
const UNADJUDICATED_BASELINE: Record<string, number> = {
  "AUDIT-ME.md": 12,
  "README.md": 12,
  "core/adapter-claude-code/SKILL.md": 19,
  "plugins/cello/agents/cello-receptionist.md": 7,
  "plugins/cello/skills/cello/SKILL.md": 17,
  "plugins/cello/skills/documents/SKILL.md": 16,
  "plugins/cello/skills/receptionist/SKILL.md": 7,
  "plugins/cello/skills/reconnect/SKILL.md": 5,
  "plugins/cello/skills/setup/SKILL.md": 6,
};

describe("DOD-M15-CLAIM-SCANNER-1: shipped surfaces are discovered, not remembered", () => {
  it("finds the surfaces that ship, including the ones no hand-kept list contained", () => {
    const surfaces = shippedSurfaces().map((f) => relative(ROOT, f));

    // The tarball SKILL.md — the exact file every previous audit missed, because it is not source
    // and was on nobody's list. If enumeration ever stops finding it, the guard has gone blind in
    // precisely the way that shipped a false claim before.
    expect(
      surfaces,
      "the connect tarball's SKILL.md must be discovered from package.json#files",
    ).toContain("core/adapter-claude-code/SKILL.md");
    expect(surfaces).toContain("README.md");
    expect(surfaces.some((s) => s.startsWith("plugins/")), "the installed plugin tree ships prose too").toBe(true);

    // A vacuous-pass guard: if discovery silently returned almost nothing, every count below would
    // pass as a comfortable zero.
    expect(surfaces.length, "surface discovery returned implausibly few files").toBeGreaterThanOrEqual(8);
  });
});

describe("DOD-M15-CLAIM-SCANNER-1: an unlisted claim fails the build", () => {
  it("no shipped surface carries MORE claim-shaped lines than its recorded baseline", () => {
    const grown: string[] = [];
    for (const file of shippedSurfaces()) {
      const rel = relative(ROOT, file);
      const found = claimLines(file);
      const allowed = UNADJUDICATED_BASELINE[rel] ?? 0;
      if (found > allowed) grown.push(`${rel}: ${found} claim lines, baseline ${allowed}`);
    }
    expect(
      grown,
      `These shipped surfaces gained claim-shaped lines that are not in the ledger: ${grown.join("; ")}. ` +
        `A claim on a surface an operator reads is a promise they will act on — audit it against the ` +
        `code and record the verdict in the claims ledger, or reword it. Raising the baseline to make ` +
        `this pass is the one response that is never right.`,
    ).toEqual([]);
  });

  it("THE BACKLOG ONLY SHRINKS — a baseline that has been paid down must be lowered", () => {
    // What stops the baseline becoming a permanent exemption nobody revisits. If a surface now has
    // FEWER claims than recorded, the work was done and the number must come down with it —
    // otherwise the ledger overstates the debt and hides that the guard is already stricter.
    const stale: string[] = [];
    for (const [rel, allowed] of Object.entries(UNADJUDICATED_BASELINE)) {
      const full = join(ROOT, rel);
      if (!existsSync(full)) { stale.push(`${rel}: file no longer exists`); continue; }
      const found = claimLines(full);
      if (found < allowed) stale.push(`${rel}: ${found} claim lines, baseline still says ${allowed}`);
    }
    expect(
      stale,
      `Lower these baselines to match — the claims were adjudicated: ${stale.join("; ")}`,
    ).toEqual([]);
  });

  it("every baselined surface is one the enumeration actually finds", () => {
    // A baseline entry for a file discovery no longer reaches is a silent hole: the count would
    // never be checked again, and nobody would know.
    const discovered = new Set(shippedSurfaces().map((f) => relative(ROOT, f)));
    const orphans = Object.keys(UNADJUDICATED_BASELINE).filter((rel) => !discovered.has(rel));
    expect(
      orphans,
      `These baselines name files the surface enumeration does not find, so their claims are no ` +
        `longer being counted: ${orphans.join(", ")}`,
    ).toEqual([]);
  });
});
