/**
 * DOD-M9C-STORE-1 — absence asserted on the BUILT ARTIFACT, not on source.
 *
 * Source-level greps have missed this three times in this project: `tsc --build --clean` does not
 * remove an output whose source is gone, so a deleted file's `dist/` artifact survives and a warm
 * -tree publish re-ships it. What ships is `files: ["dist/"]` — so `dist/` is what must be clean.
 *
 * The build runs here rather than being assumed: the repo gate order is test → lint → typecheck →
 * build, so at test time `dist/` may be stale or absent, and a test that skipped in that case
 * would be a guard that is off exactly when it matters. `tsc --build` is a no-op when up to date.
 */
import { describe, it, expect, beforeAll } from "vitest";
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const PKG_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const DIST = join(PKG_ROOT, "dist");

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
}

describe("DOD-M9C-STORE-1 — the SHIPPED artifact carries no node:sqlite", () => {
  beforeAll(() => {
    execFileSync("npx", ["tsc", "--build"], { cwd: PKG_ROOT, stdio: "pipe", timeout: 180_000 });
  }, 200_000);

  it("no built file imports node:sqlite — the store is SQLCipher or it is nothing", () => {
    const offenders = walk(DIST)
      .filter((f) => f.endsWith(".js") || f.endsWith(".d.ts"))
      .filter((f) => /from\s+["']node:sqlite["']|require\(["']node:sqlite["']\)/.test(readFileSync(f, "utf8")))
      .map((f) => f.replace(DIST, "dist"));
    expect(offenders).toEqual([]);
  });

  it("the built store module is present — the assertion above is not vacuously true", () => {
    // Without this, deleting the store from the build entirely would make the test above pass.
    const built = walk(DIST).map((f) => f.replace(DIST, "dist"));
    expect(built).toContain(join("dist", "store", "encrypted-db.js"));
  });
});
