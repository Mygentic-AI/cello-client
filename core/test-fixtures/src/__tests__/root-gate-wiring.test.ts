/**
 * DOD-M15-CI-SKIPS-SILENT-1 (cello-client half) — a package that is not wired in reports nothing,
 * and nothing reads as green.
 *
 * `vitest.workspace.ts` lists projects explicitly, so a package missing from that list has every
 * one of its test files silently ignored by `pnpm run test`. The gate prints a healthy total and
 * never mentions them.
 *
 * THIS REPO HAS ALREADY PAID FOR IT. The comment in `vitest.workspace.ts` records it: `core/daemon`
 * and `core/cli` were both absent after REPOSPLIT-002, so the root gate — and therefore CI's Test
 * step — skipped the daemon's suite entirely, for as long as nobody noticed. The daemon is 238 test
 * files, the largest package in the repo.
 *
 * That makes the stakes here different from the sibling repo's. In trustless-cello nothing
 * automated runs the gate at all. Here `.github/workflows/ci.yml` runs `pnpm run test`, and a green
 * result is what gates publishing to npm — so a package quietly dropping out of the list does not
 * merely go untested, it ships untested.
 *
 * All eight packages are wired correctly today. This test exists so the ninth is not the next
 * REPOSPLIT-002, and it is unconditional by design.
 */

import { describe, it, expect } from "vitest";
import { readdirSync, statSync, existsSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";

/** Walk up to the repo root — the directory holding the workspace file. */
function repoRoot(): string {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 10; i++) {
    if (existsSync(join(dir, "vitest.workspace.ts")) && existsSync(join(dir, "pnpm-workspace.yaml"))) return dir;
    dir = dirname(dir);
  }
  throw new Error("could not locate the repo root from this test file");
}

const ROOT = repoRoot();
const CORE = join(ROOT, "core");
const SELF = fileURLToPath(import.meta.url);

function testFilesIn(dir: string, acc: string[] = []): string[] {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return acc;
  }
  for (const entry of entries) {
    if (entry === "node_modules" || entry === "dist" || entry === "node_modules.nosync") continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) testFilesIn(full, acc);
    else if (entry.endsWith(".test.ts")) acc.push(full);
  }
  return acc;
}

/**
 * The projects the workspace file actually declares.
 *
 * IMPORTED, not grepped. Matching the file's TEXT for `"core/<name>"` lets a commented-out entry
 * satisfy the check — and commenting out is the single most likely way someone disables a project.
 * Importing asks the config what it declares.
 */
async function declaredProjects(): Promise<string[]> {
  const mod = (await import(join(ROOT, "vitest.workspace.ts"))) as { default: unknown };
  const list = mod.default;
  if (!Array.isArray(list) || list.length === 0) {
    throw new Error("vitest.workspace.ts declares no projects — this guard cannot check what it cannot read");
  }
  return list.filter((entry): entry is string => typeof entry === "string");
}

describe("DOD-M15-CI-SKIPS-SILENT-1: the root gate runs every core package that has tests", () => {
  it("no core package with test files is missing from vitest.workspace.ts", async () => {
    const projects = await declaredProjects();
    const withTests = readdirSync(CORE)
      .filter((name) => statSync(join(CORE, name)).isDirectory())
      .filter((name) => testFilesIn(join(CORE, name)).length > 0);
    const missing = withTests.filter((name) => !projects.includes(`core/${name}`));

    expect(
      missing,
      `These packages contain .test.ts files but are NOT in vitest.workspace.ts, so ` +
        `\`pnpm run test\` never runs them — and in this repo that gate is what CI runs before it ` +
        `publishes: ${missing.join(", ")}. This is the REPOSPLIT-002 defect, which cost the daemon's ` +
        `entire suite. Add each to the workspace list.`,
    ).toEqual([]);
  });

  it("this guard is itself inside a wired-in package, or it cannot report its own absence", async () => {
    // A test cannot detect its own non-collection. What it can do is name the single line the whole
    // guarantee rests on, so anyone reading a green run knows where to look.
    const projects = await declaredProjects();
    const owning = `core/${relative(CORE, SELF).split("/")[0]}`;
    expect(
      projects,
      `${owning} holds this guard. Remove it from the workspace list and every check in this file ` +
        `silently disappears from the gate.`,
    ).toContain(owning);
  });
});
