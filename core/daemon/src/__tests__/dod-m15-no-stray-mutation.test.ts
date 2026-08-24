/**
 * A REVERT-TEST MUTATION MUST NEVER REACH A COMMIT.
 *
 * ── WHY THIS EXISTS, and it is not hypothetical ───────────────────────────────────────────────
 *
 * On 2026-08-24 `gracefulShutdown`'s relay-client close loop sat on main reading
 * `void key; void client; // MUTATION` instead of `client.close()`. For several commits, `cello
 * logout` released the daemon's own resources and none of the relay's — **the exact defect
 * `DOD-M15-RELAYLEAK-1` exists to fix, live in the tree that fixes it**, and the relay counts a
 * reservation per client against a finite pool.
 *
 * The mechanism matters more than the line, because no amount of care removes it. Two lanes share
 * this worktree. One mutates a single guard to prove a test reddens, then restores. The other
 * commits the same file for unrelated work while the mutation is on disk, and sweeps it in.
 * **Both lanes commit by explicit path, which is correct and did nothing here** — an explicit path
 * does not separate two agents editing one file, and this file has one nominal owner and two real
 * editors.
 *
 * So the two behavioural rules — *never leave a mutation across a turn boundary* and *read the diff
 * before committing a shared file* — are both right and both were already believed by the people who
 * broke them. This test is the version that does not depend on either lane remembering.
 *
 * ── WHAT IT CANNOT DO, stated so nobody trusts it further than it goes ────────────────────────
 *
 * It catches a mutation that carries a MARKER. A silent edit — flipping `>=` to `>`, deleting a
 * line — is invisible to it, and no grep closes that. The convention is that a deliberate mutation
 * is labelled, both lanes already follow it, and this makes the label load-bearing rather than
 * decorative: marking your mutation is now what stops it shipping.
 *
 * It is deliberately a TEST rather than a git hook. A hook lives in `.git/hooks`, is not committed,
 * and protects whichever machine happens to have it. This runs in the gate and in CI, for everyone.
 */
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

/** Repo root, from this file: `core/daemon/src/__tests__` → four levels up. */
const REPO_ROOT = join(__dirname, "..", "..", "..", "..");

/**
 * Markers that mean "this line was changed to prove a test reddens". Deliberately literal — a
 * clever pattern would match prose ABOUT mutations, and this file, and every journal entry
 * quoting one.
 */
const MUTATION_MARKERS = [
  "// MUTATION",
  "/* MUTATION",
  "MUTATION under test",
  "MUTANT:",
];

/**
 * `src` only, and `__tests__` included — a mutation left in a test file is the same defect. `dist`
 * is excluded because it is generated: a stale artifact would report a mutation that no longer
 * exists in any source, which is a false failure pointing at a file nobody edits.
 */
function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules" || entry === "dist" || entry === "node_modules.nosync") continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) sourceFiles(full, out);
    else if (entry.endsWith(".ts")) out.push(full);
  }
  return out;
}

function coreSourceRoots(): string[] {
  const core = join(REPO_ROOT, "core");
  return readdirSync(core)
    .map((pkg) => join(core, pkg, "src"))
    .filter((p) => {
      try { return statSync(p).isDirectory(); } catch { return false; }
    });
}

describe("DOD-M15: a revert-test mutation never reaches a commit", () => {
  it("no marked mutation is left in any core/*/src file", () => {
    const roots = coreSourceRoots();
    // POSITIVE CONTROL. An empty file list would pass this test while proving nothing, which is the
    // failure mode the milestone keeps finding — a guard that cannot see its own subject. The
    // daemon package alone has hundreds of source files, so a floor of 100 is far below the real
    // count and far above anything a broken walk would return.
    const files = roots.flatMap((r) => sourceFiles(r));
    expect(
      files.length,
      `the source walk found ${files.length} files across ${roots.length} package(s) — it is not ` +
      `reading the tree, so a clean result here would mean nothing. Roots: ${roots.join(", ")}`,
    ).toBeGreaterThan(100);

    const offenders: string[] = [];
    for (const file of files) {
      // This file names every marker in order to test for them, so it would report itself.
      if (file.endsWith("dod-m15-no-stray-mutation.test.ts")) continue;
      const text = readFileSync(file, "utf8");
      text.split("\n").forEach((line, i) => {
        const hit = MUTATION_MARKERS.find((m) => line.includes(m));
        if (hit) offenders.push(`${relative(REPO_ROOT, file)}:${i + 1}  ${line.trim()}`);
      });
    }

    expect(
      offenders,
      `A revert-test mutation is still on disk. Restore the original line before committing.\n\n` +
      `${offenders.join("\n")}\n\n` +
      `This is not a style rule. On 2026-08-24 a mutation of gracefulShutdown's relay-client close ` +
      `reached main and disabled it for several commits — the defect DOD-M15-RELAYLEAK-1 exists to ` +
      `fix, shipped by the branch fixing it. Apply, run, restore, verify clean, in ONE uninterrupted ` +
      `step; if the shared test runner is busy, wait for the slot rather than mutating and pausing.`,
    ).toEqual([]);
  });
});
