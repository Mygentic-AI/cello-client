/**
 * M16 044-POSTERBELL Part D — 043 Part F (the admin's poster-lane doorbell) is gone.
 *
 * The admin used to read its channels' poster lanes on its own collection schedule and ring the
 * members for a poster's post — which put the admin back in the middle and delayed delivery to its
 * poll. 044 makes the POSTER ring itself, so that admin-side collection is deleted. This guards the
 * deletion against both a surviving source file and a stale `dist/` that would keep shipping it.
 *
 * Members still collect every poster lane on a ring — that is `#posterLanesPass`, unchanged and NOT
 * named here, so this says nothing about it.
 */
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";

const CORE = join(import.meta.dirname, "../../../..", "core");

function filesUnder(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...filesUnder(full));
    else out.push(full);
  }
  return out;
}

/** Symbols that only ever existed for the admin-side poster-lane doorbell (043 Part F). */
const DEAD_SYMBOLS = ["collectPosterLanesAsAdmin", "createPosterDoorbell", "PosterDoorbell", "PosterDoorbellDeps"];

describe("M16 044-POSTERBELL: the admin-side poster doorbell is deleted", () => {
  it("1. no source file under core/*/src carries the deleted doorbell module or its symbols", () => {
    const sources = readdirSync(CORE)
      .flatMap((pkg) => filesUnder(join(CORE, pkg, "src")))
      // Skip test files: this guard names the dead symbols, so scanning it would match itself.
      .filter((f) => f.endsWith(".ts") && !f.includes("/__tests__/"));

    // The module file itself is gone.
    expect(sources.filter((f) => f.endsWith("/channel-poster-doorbell.ts"))).toEqual([]);

    const offenders: string[] = [];
    for (const file of sources) {
      const text = readFileSync(file, "utf-8");
      for (const symbol of DEAD_SYMBOLS) {
        if (text.includes(symbol)) offenders.push(`${file.slice(CORE.length + 1)}: ${symbol}`);
      }
    }
    expect(offenders, "the admin-side poster doorbell still has source references").toEqual([]);
  });

  it("2. no built artifact under core/*/dist mentions the deleted doorbell — a stale build ships it", () => {
    const builtDirs = readdirSync(CORE)
      .map((pkg) => join(CORE, pkg, "dist"))
      .filter((d) => existsSync(d));
    expect(builtDirs.length, "core/*/dist is empty — build before asserting on what ships").toBeGreaterThan(0);

    const offenders: string[] = [];
    for (const dir of builtDirs) {
      for (const file of filesUnder(dir)) {
        if (!/\.(js|d\.ts|map)$/.test(file)) continue;
        const text = readFileSync(file, "utf-8");
        for (const symbol of DEAD_SYMBOLS) {
          if (text.includes(symbol)) offenders.push(`${file.slice(CORE.length + 1)}: ${symbol}`);
        }
      }
    }
    expect(offenders, "stale dist output still ships the deleted doorbell; `rm -rf core/*/dist` and rebuild").toEqual([]);
  });
});
