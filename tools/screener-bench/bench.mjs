/**
 * DOD-M9C-SCREENBASE-1 — the screener benchmark.
 *
 * Scores the deterministic layer ONLY against what it is answerable for (labels.json), and reports
 * the rest separately as the classifier's ground. A single blended number hides which half is weak:
 * it made a 27% catch rate look like our failure when most of the misses were fluent-language
 * attacks no rule can see, and it would equally hide a real Layer-1 regression behind a good average.
 *
 * Corpora are NOT in this repo — they are live attack catalogs. Clone them yourself:
 *   ~/cello-attack-sources/P4RS3LT0NGV3          git clone github.com/elder-plinius/P4RS3LT0NGV3
 *   ~/cello-attack-sources/bordair-multimodal    git clone github.com/Josh-blythe/bordair-multimodal
 *   ~/cello-attack-sources/mindgard/train.json   Mindgard/evaded-prompt-injection-and-jailbreak-samples (gated)
 *
 * Run:  node tools/screener-bench/bench.mjs            (after `pnpm --filter @cello-protocol/gateway build`)
 *       node tools/screener-bench/bench.mjs --misses   also prints the layer1 misses, which is the work list
 *
 * Two bordair numbers are reported, and the second is the one to trust. Categories are generated
 * from a handful of templates — 150 autodan rows come from about 12 — so a per-row score counts the
 * same sentence many times and rewards a pattern that transcribes one payload. The per-template
 * score collapses rows that share an opening, and is what tells you whether a family GENERALISES.
 */
import { readFileSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const SRC = join(homedir(), "cello-attack-sources");
const HERE = dirname(fileURLToPath(import.meta.url));
const GATEWAY = join(HERE, "..", "..", "core", "gateway", "dist");
const labels = JSON.parse(readFileSync(join(HERE, "labels.json"), "utf8"));
const showMisses = process.argv.includes("--misses");

const { initLinearRegex } = await import(join(GATEWAY, "detect/linear-regex.js"));
const { compileInjectionPatterns } = await import(join(GATEWAY, "detect/injection-patterns.js"));
const { InboundScreener } = await import(join(GATEWAY, "screen/inbound.js"));
await initLinearRegex();
compileInjectionPatterns();
const screener = new InboundScreener();
const enc = new TextEncoder();

/** BLOCKED / FLAGGED / PASSES — "caught" is either of the first two. */
async function verdict(text) {
  const v = await screener.screen(enc.encode(text));
  if (v.disposition === "block") return `BLOCKED:${v.reason}`;
  return v.events.some((e) => String(e.category).startsWith("injection:")) ? "FLAGGED" : "PASSES";
}
const caught = (v) => v !== "PASSES";
const pct = (x, n) => (n === 0 ? "n/a" : `${Math.round((100 * x) / n)}%`);

function loadJson(path) {
  return existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : null;
}

// ── bordair: labelled attack categories + benign false-positive set ──────────
async function bordair() {
  const sample = loadJson(join(SRC, "bordair-sample.json"));
  if (!sample) return console.log("bordair: sample missing (see header)");
  const score = { layer1: { n: 0, c: 0, miss: [] }, classifier: { n: 0, c: 0 }, unlabelled: [] };
  // Template key: the first eight words, lowercased, with digits and punctuation flattened. Rows
  // generated from one template share it; genuinely different payloads do not.
  const templateKey = (t) => t.toLowerCase().replace(/[^a-z\s]/g, " ").split(/\s+/).filter(Boolean).slice(0, 8).join(" ");
  const byTemplate = new Map();
  const benign = { n: 0, flagged: 0, blocked: 0 };
  for (const row of sample) {
    const v = await verdict(row.text);
    if (row.kind === "benign") {
      benign.n++;
      if (v === "FLAGGED") benign.flagged++;
      else if (v.startsWith("BLOCKED")) benign.blocked++;
      continue;
    }
    const cls = labels.bordair[row.group];
    if (!cls) { if (!score.unlabelled.includes(row.group)) score.unlabelled.push(row.group); continue; }
    score[cls].n++;
    if (caught(v)) score[cls].c++;
    else if (cls === "layer1") score.layer1.miss.push({ group: row.group, text: row.text });
    if (cls === "layer1") {
      const k = `${row.group}::${templateKey(row.text)}`;
      const t = byTemplate.get(k) ?? { n: 0, c: 0 };
      t.n++;
      if (caught(v)) t.c++;
      byTemplate.set(k, t);
    }
  }
  console.log(`bordair  LAYER 1 (ours):   ${score.layer1.c}/${score.layer1.n}  ${pct(score.layer1.c, score.layer1.n)}`);
  const tCaught = [...byTemplate.values()].filter((t) => t.c > 0).length;
  console.log(`bordair  LAYER 1 per template: ${tCaught}/${byTemplate.size}  ${pct(tCaught, byTemplate.size)}  ← the one to trust`);
  console.log(`bordair  classifier's:     ${score.classifier.c}/${score.classifier.n}  ${pct(score.classifier.c, score.classifier.n)}  (informational)`);
  console.log(`bordair  benign:           ${benign.flagged}/${benign.n} flagged by a pattern, ${benign.blocked} blocked by the language rule`);
  if (score.unlabelled.length > 0) console.log(`  ⚠ UNLABELLED categories (add to labels.json): ${score.unlabelled.join(", ")}`);
  if (showMisses) {
    const byGroup = {};
    for (const m of score.layer1.miss) (byGroup[m.group] ??= []).push(m.text);
    for (const [g, texts] of Object.entries(byGroup).sort((a, b) => b[1].length - a[1].length))
      console.log(`   miss ${g} (${texts.length}): ${texts[0].slice(0, 120).replace(/\n/g, " ")}`);
  }
}

// ── Mindgard: disguise robustness, not a catch rate ──────────────────────────
async function mindgard() {
  const rows = loadJson(join(SRC, "mindgard", "train.json"));
  if (!rows) return console.log("mindgard: train.json missing (gated dataset — see header)");
  const origCache = new Map();
  const per = {};
  for (const r of rows) {
    const cls = labels.mindgard[r.attack_name];
    if (!cls) continue;
    let o = origCache.get(r.original_sample);
    if (!o) { o = await verdict(r.original_sample); origCache.set(r.original_sample, o); }
    if (!caught(o)) continue; // the original is not ours to judge; only the disguise is
    const p = (per[r.attack_name] ??= { cls, n: 0, kept: 0 });
    p.n++;
    if (caught(await verdict(r.modified_sample))) p.kept++;
  }
  const sum = (cls) => Object.values(per).filter((p) => p.cls === cls).reduce((a, p) => ({ n: a.n + p.n, kept: a.kept + p.kept }), { n: 0, kept: 0 });
  const l1 = sum("layer1"), cl = sum("classifier");
  console.log(`mindgard LAYER 1 (ours):   ${l1.kept}/${l1.n}  ${pct(l1.kept, l1.n)} of attacks we catch plain survive the disguise`);
  console.log(`mindgard classifier's:     ${cl.kept}/${cl.n}  ${pct(cl.kept, cl.n)}  (word-swap attacks — informational)`);
  for (const [k, p] of Object.entries(per).filter(([, p]) => p.cls === "layer1").sort((a, b) => a[1].kept / a[1].n - b[1].kept / b[1].n))
    if (p.kept < p.n) console.log(`   weak ${k}: ${p.kept}/${p.n}`);
}

// ── P4RS3LT0NGV3: readable transforms only ──────────────────────────────────
async function p4rs() {
  const results = loadJson(join(SRC, "results-p4rs3lt0ngv3.json"));
  if (!results) return console.log("p4rs: run probe-p4rs3lt0ngv3.mjs first");
  const per = new Map();
  for (const r of results) {
    if (r.transform === "(plain control)" || r.verdict === "ERROR") continue;
    if (labels.p4rs_unreadable_categories.includes(r.category)) continue;
    const p = per.get(r.transform) ?? { caught: false, example: "" };
    if (caught(await verdict(r.out))) p.caught = true;
    else p.example = r.out;
    per.set(r.transform, p);
  }
  const rows = [...per.entries()];
  const ok = rows.filter(([, p]) => p.caught).length;
  console.log(`p4rs     LAYER 1 (ours):   ${ok}/${rows.length}  ${pct(ok, rows.length)} of model-readable transforms seen through`);
  if (showMisses) for (const [n, p] of rows.filter(([, p]) => !p.caught)) console.log(`   miss ${n}: ${JSON.stringify(p.example.slice(0, 90))}`);
}

await bordair();
await mindgard();
await p4rs();
