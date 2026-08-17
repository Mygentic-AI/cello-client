/**
 * DOD-M12B-SIGNAL-GUIDANCE-1 — the refusal an agent gets back must describe the fix that works.
 *
 * THE DEFECT, measured 2026-08-17. `cello_send` refuses a call with no `signal` PARAMETER and
 * hands back guidance that opens *"Missing signal token. Every cello_send message must end with
 * one of: [[OVER]] …"* and closes *"Append the appropriate token to your message and resend."*
 * Read literally — which is the only way an agent reads it — that says "put this token at the end
 * of `content`". The shim appends the token itself from the parameter, so a token typed into the
 * body changes nothing: the parameter is still absent and the SAME refusal comes back. Following
 * the guidance exactly loops forever. Cost: six consecutive failed sends across two agents and
 * three sessions, initially reported as a protocol defect.
 *
 * Both plugin skill files already tell agents the opposite ("Never write [[OVER]] into `content`
 * — cello_send appends the token itself"), so the error string was the single surface lying about
 * this, and it is the surface an agent hits at exactly the moment it has stopped reading docs.
 *
 * WHY THE ASSERTIONS ARE SHAPED THIS WAY. The teeth are not "the wording changed" — wording drifts
 * and a spelling test would just be re-typed. They are:
 *   1. Every remedy the guidance offers is a value the tool actually accepts (`SIGNAL_VALUES` is
 *      the same array the zod enum is built from), so "do what it says" cannot be a dead end again.
 *   2. The guidance carries no `[[`-token at all. A token shown in a refusal is a token an agent
 *      will copy into the body; the only way that cannot happen is for there to be nothing to copy.
 *   3. `standby` never appears as a remedy without `est_minutes`, because a caller that takes that
 *      remedy verbatim lands on the NEXT refusal.
 */

import { setupV3Tests, describe, it, expect } from "@claude-flow/testing";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { SIGNAL_ERROR, SIGNAL_VALUES } from "../signal-guidance.js";

setupV3Tests();

describe("DOD-M12B-SIGNAL-GUIDANCE-1: the missing_signal refusal names the parameter", () => {
  it("tells the caller the remedy is a PARAMETER, not text in the message", () => {
    expect(SIGNAL_ERROR).toMatch(/\bsignal\b/);
    expect(SIGNAL_ERROR).toMatch(/parameter/i);
  });

  it("does not instruct the caller to put anything at the end of the message", () => {
    // The exact two sentences that cost six sends. Neither may come back in any casing.
    expect(SIGNAL_ERROR).not.toMatch(/must end with/i);
    expect(SIGNAL_ERROR).not.toMatch(/append .{0,40}token/i);
    expect(SIGNAL_ERROR).not.toMatch(/end (of|with) your message/i);
  });

  it("shows no signal token an agent could copy into content", () => {
    // Not "[[OVER]] is absent" — NOTHING bracketed is, because any token shown gets pasted.
    expect(SIGNAL_ERROR).not.toContain("[[");
  });

  it("every value it offers as the remedy is a value the tool accepts", () => {
    const offered = [...SIGNAL_ERROR.matchAll(/signal:\s*"([a-z_]+)"/g)].map((m) => m[1]);
    expect(offered.length).toBeGreaterThan(0);
    for (const value of offered) {
      expect(SIGNAL_VALUES).toContain(value);
    }
    // And it withholds none of them — a refusal that hides a legal answer sends the caller looking.
    expect(new Set(offered)).toEqual(new Set(SIGNAL_VALUES));
  });

  it("never offers standby without est_minutes, which would land on the next refusal", () => {
    for (const line of SIGNAL_ERROR.split("\n")) {
      if (/signal:\s*"standby"/.test(line)) {
        expect(line).toMatch(/est_minutes/);
      }
    }
  });
});

describe("DOD-M12B-SIGNAL-GUIDANCE-1: the shim is wired to the shared constants", () => {
  const SHIM_SRC = join(import.meta.dirname, "..", "bin", "cello-mcp.ts");
  const source = readFileSync(SHIM_SRC, "utf8");

  it("cello-mcp.ts returns the shared SIGNAL_ERROR rather than a second copy of the prose", () => {
    expect(source).toMatch(/reason:\s*"missing_signal",\s*guidance:\s*SIGNAL_ERROR/);
    expect(source).not.toContain("Missing signal token");
  });

  it("the accepted enum is built from SIGNAL_VALUES, so guidance and schema cannot drift apart", () => {
    expect(source).toContain("z.enum(SIGNAL_VALUES)");
  });
});
