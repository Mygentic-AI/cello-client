/**
 * EVERY `placeOwnLeaf` CALL SITE HANDS OVER A PROOF, OR SAYS WHY NOT — `DOD-M15-SEALWIRE-1` bullet 5.
 *
 * ─── What this catches, and it is a defect that already shipped ────────────────────────────────
 *
 * `placeOwnLeaf`'s `authorship` parameter was once optional, and **three of seven call sites omitted
 * it** — `daemon.ts` 1443, 1677, 1691, the away-reply path. Each had the proof sitting in a local
 * variable and handed it to `recordTranscriptMessage` one line below, but not to the leaf. Invisible
 * when the leaf is delivered; on the HELD path it commits `self_authored` with no signature.
 *
 * Making the parameter required turned OMISSION into a compile error. It did nothing about
 * SUBSTITUTION: measured, replacing `sentAuthorship(sendResult)` with `undefined` at all three away
 * sites gives `tsc --build` **exit 0**, `tsc -p tsconfig.test.json` **exit 0**, and the full package
 * **green**. Ten test files mention `authorship`/`sender_sig`; **not one drives the away responder.**
 *
 * ─── ⚠️ WHAT THIS IS, STATED HONESTLY: A RATCHET, NOT A PROOF ─────────────────────────────────
 *
 * This is a TEXT SCAN of `daemon.ts` and `session-content-handlers.ts`. It asserts every
 * `placeOwnLeaf(` call passes `sentAuthorship(` or an explicitly-reasoned `undefined`. **It does not
 * execute the away responder**, so it cannot prove the proof is correct at runtime — only that the
 * argument is still being handed over.
 *
 * **It is not a substitute for the runtime test the reviewer asked for**, which is filed as an AC:
 * drive the away responder with the tail one short so its own leaf is held, close the gap, and read
 * `sender_sig` off the released row. That is the only shape that proves the VALUE. This proves the
 * WIRING, deterministically, and it reddens on exactly the mutation that is currently invisible.
 *
 * Saying that plainly matters more than the check: an enforcer believed to be a runtime proof is
 * worse than none, because it stops someone writing the real one.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const SRC = join(import.meta.dirname, "..");

/**
 * Files that call `placeOwnLeaf` in production.
 *
 * ⚠️ THIS LIST IS THE GUARD'S WEAK POINT AND 040-DAEMONROOT KEEPS MOVING CODE ACROSS IT. A file
 * that leaves the list stops being SCANNED rather than going red — the guard shrinks quietly, which
 * is the failure mode it exists to prevent, one level up. Unit 4 moved the document delivery path
 * out of `daemon.ts` and this entry is why the suite went red instead of silent. Every later unit
 * that moves leaf-placing code adds its file here in the same commit.
 */
const CALLERS = ["daemon.ts", "session-content-handlers.ts", "document-wiring.ts", "attendance-wiring.ts"] as const;

interface Call { file: string; line: number; text: string }

/** Every `placeOwnLeaf(` call and the argument text up to its closing paren. */
function callSites(): Call[] {
  const out: Call[] = [];
  for (const file of CALLERS) {
    const src = readFileSync(join(SRC, file), "utf8");
    const lines = src.split("\n");
    lines.forEach((raw, i) => {
      if (!raw.includes("placeOwnLeaf(")) return;
      /**
       * ⚠️ THE WINDOW LOOKS BACKWARD TOO, and the first version did not — it flagged the doc
       * transport, whose whole reason for passing `undefined` is written in a block comment ABOVE the
       * call. A scan that can only see forward reports a deliberate, documented decision as a silent
       * omission, which is the cry-wolf failure that gets an enforcer ignored.
       */
      let text = raw;
      for (let j = i + 1; j < lines.length && !/\)\s*;?\s*$/.test(lines[j - 1]!.trim()); j++) {
        text += "\n" + lines[j]!;
        if (j - i > 45) break;
      }
      // The argument may be documented immediately above the call rather than inline.
      //
      // ⚠️ THE WINDOW STOPS AT THE PREVIOUS CALL SITE, and that bound is load-bearing. 040-DAEMONROOT
      // unit 6 put the three away-reply sites 14 lines apart in one file; a flat 25-line lookback then
      // reached over the previous site's `sentAuthorship(sendResult)` and read it as this site's, so
      // dropping the proof at the third site left this assertion GREEN. Measured by mutation, not
      // argued: with the bound, all three go red.
      let windowStart = Math.max(0, i - 25);
      for (let k = i - 1; k >= windowStart; k--) {
        if (lines[k]!.includes("placeOwnLeaf(")) { windowStart = k + 1; break; }
      }
      text += "\n" + lines.slice(windowStart, i).join("\n");
      out.push({ file, line: i + 1, text });
    });
  }
  return out;
}

describe("DOD-M15-SEALWIRE-1 bullet 5: no call site quietly stops handing over the proof", () => {
  it("★★ every production placeOwnLeaf call passes sentAuthorship(...) or a REASONED undefined", () => {
    const sites = callSites();

    /**
     * ⚠️ THE SCAN MUST FIND SOMETHING, or an empty result passes forever. This is the failure mode of
     * every scan-the-tree test and this one asserts a negative, so a regex that matches nothing is
     * indistinguishable from a clean tree.
     */
    expect(sites.length, "the scanner must actually see the production call sites").toBeGreaterThanOrEqual(6);

    const bare = sites.filter((s) => {
      if (s.text.includes("sentAuthorship(")) return false;
      // An explicit `undefined` is allowed ONLY where a comment gives the reason, so a silent
      // omission cannot hide behind the same token as a deliberate one.
      const deliberate = /undefined,/.test(s.text) && /(no consumer|No proof|deliberately|reason)/i.test(s.text);
      return !deliberate;
    });

    expect(
      bare.map((s) => `${s.file}:${s.line}`),
      "These placeOwnLeaf calls hand over no proof and give no reason. On the HELD path the leaf is " +
        "the ONLY carrier — recordTranscriptMessage never runs — so the released row commits " +
        "self_authored with NO signature, indistinguishable from a send the relay never witnessed. " +
        "Pass sentAuthorship(sendResult), or pass undefined WITH a comment saying why there is no " +
        "proof to pass.",
    ).toEqual([]);
  });

  it("★ and the away-reply sites specifically, because those are the three that shipped broken", () => {
    // Named individually rather than counted: the defect was three specific sites, and a count
    // passes while the wrong three are wired.
    // 040-DAEMONROOT unit 6: the away responder moved out of daemon.ts into attendance-wiring.ts.
    // Read from the file that HOLDS it — reading the old one would find zero sites and the
    // `.toBe(3)` below would go red for the right number and the wrong reason.
    const away = readFileSync(join(SRC, "attendance-wiring.ts"), "utf8");
    const awayCalls = away
      .split("\n")
      .filter((l) => l.includes("placeOwnLeaf(") && l.includes("sendResult.sequenceNumber"));

    expect(
      awayCalls.length,
      "the three away-reply call sites must still exist — if this drops, the scan below is vacuous",
    ).toBe(3);
    for (const call of awayCalls) {
      expect(
        call,
        "the away responder is the highest-traffic sent-writer in the daemon and the one with no " +
          "human watching when it runs. All three of these once omitted the proof entirely.",
      ).toContain("sentAuthorship(sendResult)");
    }
  });
});
