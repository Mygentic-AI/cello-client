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
 A first run found **188 claims across 10 shipped surfaces**, against a ledger holding 13 rows
 * and covering 2 of them. Eight surfaces had never been audited at all.
 *
 * Adjudicating 188 claims is real work and cannot be a precondition for having the guard. So the
 * current count per surface is recorded here as a dated baseline that may only **shrink**: a NEW
 * claim fails immediately, and the numbers cannot be raised to accommodate one. That is the same
 * shape the chain-writes guard uses, and it is the difference between a backlog and a blanket
 * exemption.
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
  /\b(never|cannot|impossible|tamper-proof|tamper-evident|independently verify|verifiable|verified|notarized|zero-knowledge|no one can|nobody can|only you|guarantee[ds]?|encrypted|screened|proof|ACTIVE)\b/g;

/**
 * COUNT EVERY MATCH, not every matching line.
 *
 * The first version counted LINES containing a claim word, and a review demonstrated the bypass by
 * appending *"CELLO guarantees nobody can ever read your messages, not even us"* to the end of an
 * existing README claim line: three new absolute claims, line count unchanged, build green. And
 * appending to a sentence that already makes a claim is the natural way marketing prose is edited.
 *
 * Counting matches also makes the number stable under REWRAPPING. A line count changes when a
 * paragraph reflows or a formatter runs, which would red the shrink-only test for a cosmetic edit
 * and teach people to "just adjust the baseline" — the one response this file's own failure message
 * says is never right.
 */
function countMatches(text: string): number {
  return (text.match(CLAIM_VOCABULARY) ?? []).length;
}

/** Every `.md` under a directory, at any depth. */
function walkMarkdown(dir: string, out: Set<string>): void {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, e.name);
    if (e.isDirectory()) walkMarkdown(full, out);
    else if (e.name.endsWith(".md")) out.add(full);
  }
}

function shippedSurfaces(): string[] {
  const out = new Set<string>();

  const coreDir = join(ROOT, "core");
  for (const pkg of readdirSync(coreDir)) {
    const pj = join(coreDir, pkg, "package.json");
    if (!existsSync(pj)) continue;
    const files = (JSON.parse(readFileSync(pj, "utf8")) as { files?: string[] }).files ?? [];
    for (const f of files) {
      /**
       * A `files` entry may be a FILE, a DIRECTORY, or a GLOB — npm ships all three, and the first
       * version of this only followed entries literally spelled `….md`.
       *
       * A review proved the hole by adding `"docs/"` to this package's `files` and dropping a
       * `docs/GUARANTEES.md` into it promising *"your key can never leave your machine… tamper-proof
       * and notarized"*. Four tests passed. That is the SAME failure as the tarball `SKILL.md` this
       * unit exists to prevent — the hand-kept list had simply moved from an array into "which
       * entries happen to be spelled as a .md path".
       */
      const base = f.replace(/\/?\*.*$/, "");
      const full = join(coreDir, pkg, base);
      if (!existsSync(full)) continue;
      if (statSync(full).isDirectory()) walkMarkdown(full, out);
      else if (full.endsWith(".md")) out.add(full);
    }
  }

  for (const f of readdirSync(ROOT)) {
    if (f.endsWith(".md") && statSync(join(ROOT, f)).isFile()) out.add(join(ROOT, f));
  }

  const plugins = join(ROOT, "plugins");
  if (existsSync(plugins)) walkMarkdown(plugins, out);

  return [...out].sort();
}

/**
 * The CLI's own operator-facing strings — the highest-stakes prose in the repo.
 *
 * Not markdown, so no `.md` walk reaches it, and the DoD line named it explicitly. These are the
 * sentences printed to an operator at the moment they decide to act: *"Both sides sign off and get a
 * tamper-proof receipt"*, *"each gets a notarized receipt"*, *"CELLO never holds your whole signing
 * key in one place"*, *"The agent becomes UNREACHABLE"*. A claim read at the point of action is
 * acted on harder than one in a README.
 */
const REGISTRY = join(ROOT, "core", "cli", "src", "registry.ts");

function registryClaimStrings(): string {
  if (!existsSync(REGISTRY)) return "";
  const src = readFileSync(REGISTRY, "utf8");
  /**
   * PROSE-SHAPED LITERALS, not `summary:`/`help:` values.
   *
   * Keying on the field name looks tidier and measured 3 claims in a 1514-line file, which is not
   * plausible for a CLI whose own help text says "tamper-proof receipt". The reason: a `help` value
   * is usually a multi-line CONCATENATION —
   *
   *     help:
   *       "Usage: cello close-session …\n" +
   *       "  Both parties sign off … each gets a notarized receipt\n" +
   *
   * — so a regex anchored to `help:` captures the first fragment and stops before every line that
   * carries a claim. Taking any literal of three or more words instead cannot miss a continuation.
   * It over-includes (an error message, a usage line), and that is the right direction to err: an
   * error string an operator reads at the moment something fails is a claim surface too.
   */
  return [...src.matchAll(/"((?:[^"\\\n]|\\.)*)"|`((?:[^`\\]|\\.)*)`/g)]
    .map((m) => m[1] ?? m[2] ?? "")
    .filter((s) => s.trim().split(/\s+/).length >= 3)
    .join("\n");
}

/** The CLI surface's name in the baseline — not a file path, so it is spelled to say so. */
const REGISTRY_SURFACE = "core/cli/src/registry.ts (operator-facing strings)";

/** Every surface and its claim text, as one map — markdown files plus the CLI's operator strings. */
function surfaceTexts(): Map<string, string> {
  const m = new Map<string, string>();
  for (const file of shippedSurfaces()) m.set(relative(ROOT, file), readFileSync(file, "utf8"));
  const registry = registryClaimStrings();
  if (registry) m.set(REGISTRY_SURFACE, registry);
  return m;
}

/**
 * Unadjudicated claim MATCHES per shipped surface, as of 2026-08-22. **Shrink these; never raise.**
 *
 * A number here is not an approval — it is a count of claims nobody has checked against the code
 * yet. Lowering one means those claims were verified, corrected, or withdrawn, and the reasoning
 * went into the prose ledger.
 *
 * These counts REPLACED an earlier set of line counts. They are larger, and the increase is not
 * inflation: it is the four vocabulary words the DoD line named and the regex had lost
 * (`encrypted`, `screened`, `proof`, `ACTIVE`), plus counting each claim on a line rather than the
 * line, plus two surfaces that were not being read at all.
 */
const UNADJUDICATED_BASELINE: Record<string, number> = {
  "AUDIT-ME.md": 18,
  "README.md": 20,
  "core/adapter-claude-code/SKILL.md": 30,
  "core/cli/src/registry.ts (operator-facing strings)": 41,
  "plugins/cello/agents/cello-receptionist.md": 8,
  "plugins/cello/skills/cello/SKILL.md": 29,
  "plugins/cello/skills/documents/SKILL.md": 18,
  "plugins/cello/skills/receptionist/SKILL.md": 11,
  "plugins/cello/skills/reconnect/SKILL.md": 4,
  "plugins/cello/skills/setup/SKILL.md": 9,
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
    // pass as a comfortable zero. Tied to the BASELINE's own size rather than a number typed once —
    // the first version said `>= 8` against 9 discovered surfaces, so it would have shrugged at
    // discovery losing a file, which is the failure it was written for.
    expect(
      surfaces.length,
      "surface discovery returned fewer files than the baseline names — something stopped being read",
    ).toBeGreaterThanOrEqual(Object.keys(UNADJUDICATED_BASELINE).length - 1);
  });

  it("reads the CLI's operator-facing strings, which no markdown walk reaches", () => {
    // The sentences printed at the moment an operator acts. `registry.ts` is TypeScript, so every
    // .md-based enumeration above is blind to it, and the DoD line named it specifically.
    const text = registryClaimStrings();
    expect(text, "no summary/help strings were extracted from registry.ts").not.toBe("");
    expect(text, "the extraction is matching something other than the operator-facing fields")
      .toMatch(/receipt|session|agent/i);
  });
});

describe("DOD-M15-CLAIM-SCANNER-1: an unlisted claim fails the build", () => {
  it("no shipped surface carries MORE claims than its recorded baseline", () => {
    const grown: string[] = [];
    for (const [surface, text] of surfaceTexts()) {
      const found = countMatches(text);
      const allowed = UNADJUDICATED_BASELINE[surface] ?? 0;
      if (found > allowed) grown.push(`${surface}: ${found} claims, baseline ${allowed}`);
    }
    expect(
      grown,
      `These shipped surfaces gained claims that are not in the ledger: ${grown.join("; ")}. ` +
        `A claim on a surface an operator reads is a promise they will act on — audit it against the ` +
        `code and record the verdict in the claims ledger, or reword it. Raising the baseline to make ` +
        `this pass is the one response that is never right.`,
    ).toEqual([]);
  });

  it("THE BACKLOG ONLY SHRINKS — a baseline that has been paid down must be lowered", () => {
    // What stops the baseline becoming a permanent exemption nobody revisits. If a surface now has
    // FEWER claims than recorded, the work was done and the number must come down with it —
    // otherwise the ledger overstates the debt and hides that the guard is already stricter.
    const texts = surfaceTexts();
    const stale: string[] = [];
    for (const [surface, allowed] of Object.entries(UNADJUDICATED_BASELINE)) {
      const text = texts.get(surface);
      if (text === undefined) { stale.push(`${surface}: no longer discovered`); continue; }
      const found = countMatches(text);
      if (found < allowed) stale.push(`${surface}: ${found} claims, baseline still says ${allowed}`);
    }
    expect(
      stale,
      `Lower these baselines to match — the claims were adjudicated: ${stale.join("; ")}`,
    ).toEqual([]);
  });

  it("every baselined surface is one the enumeration actually finds", () => {
    // A baseline entry for a surface discovery no longer reaches is a silent hole: the count would
    // never be checked again, and nobody would know.
    const discovered = surfaceTexts();
    const orphans = Object.keys(UNADJUDICATED_BASELINE).filter((s) => !discovered.has(s));
    expect(
      orphans,
      `These baselines name surfaces the enumeration does not find, so their claims are no ` +
        `longer being counted: ${orphans.join(", ")}`,
    ).toEqual([]);
  });
});
