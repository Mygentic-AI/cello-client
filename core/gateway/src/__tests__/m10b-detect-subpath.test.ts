/**
 * M10B / DOD-END-SCAN-1 (`M10B-D17`) — the `./detect` subpath must stay NARROW.
 *
 * This test exists because the failure it prevents is invisible at the call site. The portal will
 * `import { scanInjectionPatterns } from "@cello-protocol/gateway/detect"` and it will work whether
 * or not that entry point transitively drags in `node:sqlite`, the gateway HTTP server, the sidecar
 * spawner, and an ONNX model loader. Nothing errors; the Next.js server bundle just quietly grows a
 * VERBOTEN dependency and a fail-OPEN scanner.
 *
 * So the assertion is on the transitive import GRAPH, not on behavior. Add a re-export of the barrel
 * — or of the DeBERTa scanner — to `detect/index.ts` and this goes red.
 */
import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SRC = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Strip block and line comments before scanning for imports.
 *
 * Not incidental tidiness — the first run of this test went red on `detect/index.ts` because its own
 * doc comment QUOTES `import { DatabaseSync } from "node:sqlite"` while explaining why that import
 * must never be reachable. A scanner that matches inside prose reports the documentation of a rule as
 * a violation of it, and the next person would "fix" it by deleting the explanation.
 */
function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
}

/** Every module reachable from `entry` by static `import`/`export … from`, within this package. */
function transitiveLocalImports(entry: string): Set<string> {
  const seen = new Set<string>();
  const stack = [entry];
  while (stack.length > 0) {
    const file = stack.pop()!;
    if (seen.has(file) || !existsSync(file)) continue;
    seen.add(file);
    const src = stripComments(readFileSync(file, "utf-8"));
    // Matches both `import … from "x"` and `export … from "x"`, which is the one a re-export barrel
    // would otherwise slip through.
    for (const m of src.matchAll(/(?:import|export)[^;]*?from\s+["']([^"']+)["']/g)) {
      const spec = m[1];
      if (!spec.startsWith(".")) continue; // external/builtin — captured by the bare-specifier check
      stack.push(resolve(dirname(file), spec.replace(/\.js$/, ".ts")));
    }
  }
  return seen;
}

/** Bare (non-relative) specifiers imported anywhere in the reachable graph. */
function bareSpecifiers(files: Set<string>): Set<string> {
  const out = new Set<string>();
  for (const f of files) {
    for (const m of stripComments(readFileSync(f, "utf-8")).matchAll(/(?:import|export)[^;]*?from\s+["']([^"']+)["']/g)) {
      if (!m[1].startsWith(".")) out.add(m[1]);
    }
  }
  return out;
}

describe("DOD-END-SCAN-1 / M10B-D17 — the ./detect subpath is narrow by construction", () => {
  const reachable = transitiveLocalImports(join(SRC, "detect/index.ts"));

  it("NEVER reaches node:sqlite — VERBOTEN, and the reason the subpath exists at all", () => {
    // The package barrel re-exports GatewayConfigStore/GatewayRecordStore, which both statically
    // import node:sqlite. Importing the barrel from a Next.js Fargate app pulls it in.
    expect([...bareSpecifiers(reachable)]).not.toContain("node:sqlite");
  });

  it("NEVER reaches the DeBERTa Layer-2 scanner — it degrades OPEN and intake must fail CLOSED", () => {
    // M10B-D16: a scanner that can be silently OFF cannot back a signed scanner_version assertion —
    // the notarized record would claim a scan that did not happen. Excluded structurally, not by
    // remembering not to call it.
    const names = [...reachable].map((f) => f.replace(SRC, ""));
    expect(names.filter((n) => n.includes("injection-scanner"))).toEqual([]);
    expect(names.filter((n) => n.includes("model-installer"))).toEqual([]);
    expect(names.filter((n) => n.includes("deberta"))).toEqual([]);
  });

  it("NEVER reaches the gateway server, its stores, or the sidecar spawner", () => {
    const names = [...reachable].map((f) => f.replace(SRC, ""));
    for (const forbidden of ["config-store", "record-store", "server", "sidecar", "/index.ts"]) {
      expect(names.filter((n) => n.includes(forbidden) && !n.includes("detect/index.ts")), forbidden).toEqual([]);
    }
  });

  it("DOES reach the two rule corpora — the shared component §7 constraint 2 asks for", () => {
    // The inverse assertion. Without it, an implementation that exports nothing at all would pass
    // every check above.
    const names = [...reachable].map((f) => f.replace(SRC, ""));
    expect(names.some((n) => n.includes("injection-patterns"))).toBe(true);
    expect(names.some((n) => n.includes("secrets"))).toBe(true);
  });

  it("exposes the corpus but NOT a verdict — the policy stays the portal's (M10B-D16)", async () => {
    // The gateway deliberately surfaces evidence and does not police content; intake is
    // reject-always, fail-closed. Re-exporting InboundScreener here would hand the portal a
    // disposition that never refuses anything, and its tests would still pass.
    const mod = await import("../detect/index.js");
    expect(Object.keys(mod).sort()).toEqual([
      // M10B-D15: the corpus-introspection exports expose WHICH RULES ARE ACTIVE, which is what
      // lets the portal DERIVE `scanner_version` rather than hand-maintain a constant that goes
      // stale the first time someone edits a regex. And `initLinearRegex` is here because the
      // corpus CANNOT COMPILE without it — omitting it made this subpath look complete while being
      // unusable: compileInjectionPatterns runs, leaves `compiled` null, and every rule silently
      // matches nothing, which is the degrade-open behaviour fail-closed intake must not inherit.
      // None of them judges anything, so M10B-D16 holds: the corpus is shared, the policy is the
      // portal's.
      "compileInjectionPatterns",
      "compileSecretRules",
      "detectorCorpusDigest",
      "initLinearRegex",
      "injectionPatternIds",
      "injectionPatternsReady",
      "linearRegexEngine",
      "redactSecrets",
      "scanInjectionPatterns",
      "secretRuleIds",
      "secretRulesReady",
    ]);
  });
});
