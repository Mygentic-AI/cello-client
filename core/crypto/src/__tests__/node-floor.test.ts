/**
 * 001-PQPRIM decision 10 / test 21 — the install-time Node floor.
 *
 * `@cello-protocol/crypto`'s `preinstall` is an inline `node -e` one-liner (it must run on ANY Node,
 * with no dependency) that exits 1 below 24.7 with a message naming the version. This runs that exact
 * script text, taken from package.json, under spoofed `process.version(s)` — so the check is pinned in
 * CI. The gate also runs it for real on a Node 24.6.0 binary (journal, 001-PQPRIM).
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as {
  engines: { node: string };
  scripts: { preinstall: string };
};

const m = /^node -e "(.*)"$/s.exec(pkg.scripts.preinstall);
const SCRIPT = m ? m[1]!.replace(/\\"/g, '"') : "";

function runAs(version: string) {
  const spoof =
    `Object.defineProperty(process,"versions",{value:{...process.versions,node:${JSON.stringify(version)}}});` +
    `Object.defineProperty(process,"version",{value:${JSON.stringify("v" + version)}});`;
  return spawnSync(process.execPath, ["-e", spoof + SCRIPT], { encoding: "utf8" });
}

describe("001-PQPRIM test 21 — the preinstall Node floor", () => {
  it("engines.node is >=24.7 and preinstall is a node -e one-liner", () => {
    expect(pkg.engines.node).toBe(">=24.7");
    expect(SCRIPT.length).toBeGreaterThan(0);
  });

  it.each(["24.6.0", "24.0.0", "23.11.1", "22.22.0"])("refuses Node %s with the exact message", (v) => {
    const r = runAs(v);
    expect(r.status).toBe(1);
    expect(r.stderr.trim()).toBe(
      `@cello-protocol/crypto needs Node >= 24.7 (ML-KEM and ML-DSA are built into node:crypto from 24.7). You have v${v}.`,
    );
  });

  it.each(["24.7.0", "24.15.0", "25.0.0", "26.1.0"])("accepts Node %s", (v) => {
    const r = runAs(v);
    expect(r.status, r.stderr).toBe(0);
    expect(r.stderr).toBe("");
  });
});
