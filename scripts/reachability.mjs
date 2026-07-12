#!/usr/bin/env node
/**
 * CELLO dead-code reachability map.
 *
 * Answers, mechanically (not by grep), the question that keeps confusing AI coders:
 * "which source files are actually reachable from a live binary, and which are dead?"
 *
 * It walks the static import graph (import/export-from + dynamic/inline import())
 * starting from the live application entry points (the daemon, MCP adapter, CLI,
 * and gateway-sidecar binaries), resolving both relative specifiers and cross-package @cello-protocol/*
 * specifiers within this monorepo. Anything under core/<pkg>/src that the walk never
 * reaches is dead from the live runtime's perspective.
 *
 * For each unreachable file it also reports WHY it might still be tethered:
 *   - [api]  exported (transitively) from its package's public index.ts — reachable
 *            only via the published package surface, not the running binary.
 *   - [orphan] not even exported from the index — pure dead weight.
 *
 * Usage:
 *   node scripts/reachability.mjs                 # default roots = app bins
 *   node scripts/reachability.mjs --with-index    # also treat each pkg index.ts as a root
 *   node scripts/reachability.mjs --json          # machine-readable
 *
 * Exit code is always 0 here (reporting tool). A CI gate can wrap it with a
 * known-dead allowlist and fail when the dead set grows.
 */

import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join, dirname, resolve, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CORE = join(ROOT, "core");
const args = new Set(process.argv.slice(2));
const WITH_INDEX = args.has("--with-index");
const JSON_OUT = args.has("--json");

// ── npm package name → src dir (e.g. @cello-protocol/connect → core/adapter-claude-code) ──
const nameToSrc = new Map();
for (const entry of readdirSync(CORE)) {
  const pj = join(CORE, entry, "package.json");
  if (existsSync(pj)) {
    const name = JSON.parse(readFileSync(pj, "utf8")).name;
    if (name) nameToSrc.set(name, join(CORE, entry, "src"));
  }
}

// ── enumerate all real source files (the denominator) ──
function walkDir(dir, out = []) {
  for (const e of readdirSync(dir)) {
    const full = join(dir, e);
    const st = statSync(full);
    if (st.isDirectory()) {
      if (e === "__tests__" || e === "node_modules" || e === "dist") continue;
      walkDir(full, out);
    } else if (e.endsWith(".ts") && !e.endsWith(".d.ts") && !e.endsWith(".test.ts")) {
      out.push(full);
    }
  }
  return out;
}
const allFiles = new Set();
for (const [, src] of nameToSrc) if (existsSync(src)) for (const f of walkDir(src)) allFiles.add(f);

// ── resolve an import specifier (from a given importer file) to a source file, or null ──
function resolveSpec(spec, importer) {
  let target = null;
  if (spec.startsWith(".")) {
    target = resolve(dirname(importer), spec);
  } else if (spec.startsWith("@cello-protocol/")) {
    // @cello-protocol/NAME  or  @cello-protocol/NAME/sub/path.js
    const slash = spec.indexOf("/", "@cello-protocol/".length);
    const name = slash === -1 ? spec : spec.slice(0, slash);
    const src = nameToSrc.get(name);
    if (!src) return null;
    target = slash === -1 ? join(src, "index") : join(src, spec.slice(slash + 1));
  } else {
    return null; // node: builtin or external npm dep — not our code
  }
  // normalise extension: .js specifier → .ts file; or bare → .ts / /index.ts
  const candidates = [];
  if (target.endsWith(".js")) candidates.push(target.slice(0, -3) + ".ts");
  else if (target.endsWith(".ts")) candidates.push(target);
  else { candidates.push(target + ".ts", join(target, "index.ts")); }
  for (const c of candidates) if (allFiles.has(c)) return c;
  return null;
}

// Any `import ... from "x"` / `export ... from "x"` clause, including named imports
// whose `{ … }` would defeat a tighter pattern. Over-matching a stray `from "x"` is
// harmless: a bogus specifier just resolves to null.
const IMPORT_RE = /\bfrom\s*["']([^"']+)["']/g;
const SIDE_EFFECT_RE = /^\s*import\s+["']([^"']+)["']/gm;
const DYN_RE = /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g;

function specsOf(file) {
  const text = readFileSync(file, "utf8");
  const specs = [];
  for (const re of [IMPORT_RE, SIDE_EFFECT_RE, DYN_RE]) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) specs.push(m[1]);
  }
  return specs;
}

function reachFrom(roots) {
  const seen = new Set();
  const stack = [...roots];
  while (stack.length) {
    const f = stack.pop();
    if (!f || seen.has(f) || !allFiles.has(f)) continue;
    seen.add(f);
    for (const spec of specsOf(f)) {
      const r = resolveSpec(spec, f);
      if (r && !seen.has(r)) stack.push(r);
    }
  }
  return seen;
}

// ── roots: the live application binaries ──
// gateway is a REAL shipped binary: @cello-protocol/gateway is published with a
// `cello-gateway` bin and the daemon spawns it as a sidecar process (see ci.yml).
// Omitting it wrongly marks core/gateway/src/bin/cello-gateway.ts as dead.
const appBins = [
  join(nameToSrc.get("@cello-protocol/daemon") ?? "", "bin/cello-daemon.ts"),
  join(nameToSrc.get("@cello-protocol/connect") ?? "", "bin/cello-mcp.ts"),
  join(nameToSrc.get("@cello-protocol/cli") ?? "", "bin/cello.ts"),
  join(nameToSrc.get("@cello-protocol/gateway") ?? "", "bin/cello-gateway.ts"),
].filter((f) => existsSync(f));

const roots = [...appBins];
if (WITH_INDEX) for (const [, src] of nameToSrc) { const i = join(src, "index.ts"); if (allFiles.has(i)) roots.push(i); }

const liveFromBins = reachFrom(appBins);
const reachable = WITH_INDEX ? reachFrom(roots) : liveFromBins;

// ── classify the unreachable files ──
const indexReach = new Map(); // pkg src → set reachable from that pkg's index
for (const [, src] of nameToSrc) {
  const idx = join(src, "index.ts");
  if (allFiles.has(idx)) indexReach.set(src, reachFrom([idx]));
}
function pkgOf(file) { for (const [, src] of nameToSrc) if (file.startsWith(src + "/") || file === src) return src; return null; }
function exportedFromIndex(file) { const src = pkgOf(file); const s = src && indexReach.get(src); return !!(s && s.has(file)); }

const dead = [...allFiles].filter((f) => !reachable.has(f)).sort();
const byPkg = new Map();
for (const f of dead) {
  const src = pkgOf(f) ?? "?";
  const tag = exportedFromIndex(f) ? "api" : "orphan";
  if (!byPkg.has(src)) byPkg.set(src, []);
  byPkg.get(src).push({ file: relative(ROOT, f), tag });
}

if (JSON_OUT) {
  console.log(JSON.stringify({
    totals: { all: allFiles.size, reachable: reachable.size, dead: dead.length },
    roots: roots.map((r) => relative(ROOT, r)),
    dead: dead.map((f) => ({ file: relative(ROOT, f), tag: exportedFromIndex(f) ? "api" : "orphan" })),
  }, null, 2));
} else {
  console.log(`\nReachability map  (roots: ${WITH_INDEX ? "app bins + every package index" : "live app binaries only"})`);
  console.log(`  entry points: ${roots.map((r) => relative(ROOT, r)).join(", ")}`);
  console.log(`  source files: ${allFiles.size}   reachable: ${reachable.size}   DEAD: ${dead.length}\n`);
  for (const [src, files] of [...byPkg].sort((a, b) => b[1].length - a[1].length)) {
    console.log(`  ${relative(ROOT, src)}  (${files.length} dead)`);
    for (const { file, tag } of files) console.log(`     [${tag}] ${file}`);
  }
  console.log("");
  console.log("  [api]    = reachable only via the package's published index.ts, not the running binary");
  console.log("  [orphan] = not reachable from any binary OR any package index — pure dead weight\n");
}
