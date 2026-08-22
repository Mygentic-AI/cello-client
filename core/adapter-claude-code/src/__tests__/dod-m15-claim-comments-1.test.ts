/**
 * DOD-M15-CLAIM-COMMENTS-1 — a retired false assertion cannot come back.
 *
 * ─── Why a DENYLIST here, when the claim scanner uses an allowlist ─────────────────────────────
 *
 * `DOD-M15-CLAIM-SCANNER-1` counts claim-shaped prose on shipped SURFACES and holds a shrink-only
 * baseline, because there is a bounded set of files an operator reads and every sentence in them is
 * fair game. Source comments are the opposite: unbounded, mostly fine, and the dangerous ones are
 * dangerous for a specific reason that is known once it has been found. Counting them would produce
 * a number nobody could act on.
 *
 * So this is a denylist of sentences that were **investigated and found false**. Each entry is a
 * real defect somebody had to trace, and re-typing one is a regression, not a style question.
 *
 * ─── The failure mode these share: a comment that defers to a check nobody performs ────────────
 *
 * The worst instance was a MUTUAL deferral, and it is the reason this line exists rather than a
 * pull-request note. The directory's SEAL-leaf handler said root verification was *"deferred to a
 * follow-on story since clients perform this verification locally"*. The client's seal flow said
 * root agreement *"belongs to the FROST seal against the directory-held tree"*. Each half reads as
 * a considered decision to check somewhere else. There is no somewhere else.
 *
 * The certified root was therefore compared against NO participant's transcript on the bilateral
 * path — the receipt was not bound to the transcript, and if the two diverged nothing would say so.
 * Two comments pointing at each other is how that survived review: each one, read alone, looks like
 * diligence.
 *
 * ─── Rewrite, never delete ─────────────────────────────────────────────────────────────────────
 *
 * The rule the DoD line sets, and the reason the corrected comments are long. A deleted comment
 * takes with it the evidence that somebody believed it — and an absence reads as deliberate, which
 * is exactly what the original wording achieved by accident. So each site keeps its comment,
 * rewritten to say what the code does and what it deliberately does not.
 *
 * That is why the patterns below are matched with their CORRECTION EXCLUDED: the corrected comments
 * quote the false sentence in order to retire it, and a test that fired on the quote would force
 * deletion of the very evidence the rule preserves.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

function repoRoot(): string {
  let dir = HERE;
  for (let i = 0; i < 10; i++) {
    if (existsSync(join(dir, "vitest.workspace.ts")) && existsSync(join(dir, "pnpm-workspace.yaml"))) return dir;
    dir = dirname(dir);
  }
  throw new Error("could not locate the repo root");
}
const ROOT = repoRoot();

interface RetiredClaim {
  /** The sentence, as it appeared. */
  pattern: RegExp;
  /** What was actually true, and what it cost. Printed when the test fails. */
  why: string;
}

/**
 * Sentences investigated and found false. **Add to this; never remove an entry** — removing one
 * says the sentence became true, which for these means the underlying work landed and the DoD line
 * that owns it is closed.
 */
const RETIRED: RetiredClaim[] = [
  {
    pattern: /clients perform this verification locally/i,
    why:
      "The directory's SEAL-leaf handler used this to justify not comparing the certified root. The " +
      "client does not perform it — seal-flows.ts deferred the same check back to the directory. " +
      "Each half pointed at the other, so the root was compared against no participant's transcript " +
      "on the bilateral path. Owned by DOD-M15-SEALWIRE-1.",
  },
  {
    pattern: /belongs to the FROST seal against the directory-held tree/i,
    why:
      "The client half of that same mutual deferral. It reads as 'someone else checks it'. Nobody " +
      "does.",
  },
  {
    pattern: /FROST assignment signature verification deferred to SESSION-004/i,
    why:
      "The responder verifies inbound assignments as of DOD-M15-RESPONDER-VERIFY-1. This line was " +
      "still being logged on the SUCCESSFUL path, nine lines after the event saying verification " +
      "happened — so every healthy session emitted both, and the next person to debug one would " +
      "read the 'unverified' line and conclude the responder still trusts the directory blind.",
  },
  {
    pattern: /the responder path does NOT verify it/i,
    why:
      "Same change. The responder verifies — asymmetrically (pinned key for a repeat counterparty, " +
      "internal consistency on first contact), which is what the comment should say instead.",
  },
  {
    pattern: /screening.{0,40}\b(is|runs)\b.{0,30}\b(fully active|fully enabled)\b/i,
    why:
      "Content screening is TWO layers live and one off. The deterministic sanitizer and the " +
      "pattern matcher run enforcing; the layer that judges MEANING loads only if an ONNX " +
      "classifier is present at ~/.cello/gateway-model, and nothing ships one. 'Message content is " +
      "screened' is true; 'prompt-injection defense is fully active' is not. DOD-M15-CLAIM-SCREEN-1.",
  },
];

/**
 * Where a comment can actually mislead somebody: production source that ships.
 *
 * Test files are excluded deliberately — a test may legitimately quote a false claim in order to
 * assert it is gone, and this file is the clearest example of that.
 */
function shippedSources(): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.name === "node_modules" || e.name === "node_modules.nosync" || e.name === "dist") continue;
      if (e.name === "__tests__") continue;
      const full = join(dir, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.name.endsWith(".ts")) out.push(full);
    }
  };
  const core = join(ROOT, "core");
  for (const pkg of readdirSync(core)) {
    const src = join(core, pkg, "src");
    if (existsSync(src) && statSync(src).isDirectory()) walk(src);
  }
  return out;
}

/**
 * A line that RETIRES a claim by quoting it, versus one that ASSERTS it.
 *
 * The corrected comments all quote the sentence they are retiring — that is the "rewrite, never
 * delete" rule, and the quote is load-bearing evidence. What distinguishes them is a nearby marker
 * saying the claim is false: the DoD line id, or plain words like "used to", "is NOT true", "not
 * shipped". The window is the surrounding block, not the line, because the correction is usually a
 * sentence or two away from the quote.
 */
function isRetiringContext(text: string, index: number): boolean {
  const from = Math.max(0, index - 900);
  const to = Math.min(text.length, index + 900);
  const window = text.slice(from, to);
  return /DOD-M15-CLAIM-COMMENTS-1|DOD-M15-CLAIM-SCREEN-1|used to (say|imply|assert)|is NOT true|HAS BEEN SINCE IT WAS\s*\n?\s*\/\/\s*WRITTEN|previously asserted|there used to be|is not claimed|NOT TRUE/i.test(
    window,
  );
}

describe("DOD-M15-CLAIM-COMMENTS-1: no shipped comment asserts a property the code lacks", () => {
  it("finds source files to scan — an empty sweep would pass every claim below", () => {
    const files = shippedSources();
    expect(files.length, "source enumeration returned implausibly few files").toBeGreaterThan(50);
    expect(files.some((f) => f.endsWith("inbound-sessions.ts"))).toBe(true);
  });

  it("no retired claim has been re-asserted anywhere in shipped source", () => {
    const offenders: string[] = [];
    for (const file of shippedSources()) {
      const text = readFileSync(file, "utf8");
      for (const claim of RETIRED) {
        const re = new RegExp(claim.pattern.source, claim.pattern.flags.includes("g") ? claim.pattern.flags : `${claim.pattern.flags}g`);
        for (const m of text.matchAll(re)) {
          if (m.index !== undefined && isRetiringContext(text, m.index)) continue;
          const line = text.slice(0, m.index ?? 0).split("\n").length;
          offenders.push(`${relative(ROOT, file)}:${line} — "${m[0]}"\n      ${claim.why}`);
        }
      }
    }
    expect(
      offenders,
      `These sentences were investigated and found FALSE, and have been written again:\n` +
        `    ${offenders.join("\n    ")}\n` +
        `  Rewrite the comment to say what the code actually does and what it deliberately does not. ` +
        `If you are RETIRING the claim by quoting it, say so in the same block — name the DoD line, ` +
        `or write "used to say" — and this check will read it as a correction rather than a claim.`,
    ).toEqual([]);
  });

  it("the retiring-context escape hatch cannot swallow a fresh assertion", () => {
    /**
     * The guard on the guard, and the reason it is here: the escape hatch above is the only way this
     * test can be silenced, and silencing it is one `DOD-M15-CLAIM-COMMENTS-1` away.
     *
     * A bare re-assertion must still fail even inside a file that legitimately retires claims
     * elsewhere — the window is deliberately ~900 characters, not the whole file, so a correction at
     * the top cannot license a fresh false sentence at the bottom.
     */
    const fabricated = `
      // Some ordinary comment about parsing.
      // The responder path does NOT verify it and cannot without a directory lookup.
      const x = 1;
    `;
    expect(isRetiringContext(fabricated, fabricated.indexOf("The responder path"))).toBe(false);

    const corrected = `
      // DOD-M15-CLAIM-COMMENTS-1 — this used to say "The responder path does NOT verify it".
      // It does now, asymmetrically.
    `;
    expect(isRetiringContext(corrected, corrected.indexOf("The responder path"))).toBe(true);
  });
});
