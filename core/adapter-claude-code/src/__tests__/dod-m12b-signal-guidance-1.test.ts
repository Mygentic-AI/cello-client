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
import { readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import { SIGNAL_ERROR, SIGNAL_VALUES, EST_MINUTES_ERROR } from "../signal-guidance.js";

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

describe("DOD-M12B-SIGNAL-GUIDANCE-1: the NEXT refusal on the same path", () => {
  // Taking the `standby` remedy lands here. A caller who follows the first message into the second
  // must not find the second written to a lower standard — that is how a two-step dead end forms.
  it("names est_minutes as a parameter and shows a real number, not a placeholder to paste", () => {
    expect(EST_MINUTES_ERROR).toMatch(/est_minutes/);
    expect(EST_MINUTES_ERROR).toMatch(/parameter/i);
    expect(EST_MINUTES_ERROR).not.toContain("[[");
    expect(EST_MINUTES_ERROR).not.toMatch(/<number>|<n>|<minutes>/i);
    expect(EST_MINUTES_ERROR).toMatch(/est_minutes:\s*\d+/);
  });

  it("names the way OUT — a caller who did not mean standby is told what to use instead", () => {
    expect(EST_MINUTES_ERROR).toMatch(/signal:\s*"over"/);
  });
});

describe("DOD-M12B-SIGNAL-GUIDANCE-1: the shim is wired to the shared constants", () => {
  const SHIM_SRC = join(import.meta.dirname, "..", "bin", "cello-mcp.ts");
  const source = readFileSync(SHIM_SRC, "utf8");

  /**
   * SCOPE LIMIT, stated rather than left for a green suite to imply. These are SOURCE-TEXT
   * assertions — the repo's established approach for this bin, because it is a side-effecting
   * entrypoint that connects to the daemon on import and cannot be driven in-process. They pin the
   * WIRING, not the handler's return value. An implementation that imported these constants,
   * satisfied every check below, and then returned a different string would pass. Reading the
   * handler confirms it does not; that is a gap in the proof, not a live defect.
   */
  it("cello-mcp.ts returns the shared constants rather than second copies of the prose", () => {
    // Two independent containment checks, deliberately NOT one regex spanning both keys: a regex
    // like /reason:.*guidance:/ goes red on a behaviour-preserving key reorder or a rewrap, which
    // pins formatting rather than behaviour.
    expect(source).toContain("guidance: SIGNAL_ERROR");
    expect(source).toContain("guidance: EST_MINUTES_ERROR");
    expect(source).not.toContain("Missing signal token");
    // The old inline est_minutes prose must not survive alongside the shared one.
    expect(source).not.toContain("requires est_minutes (a positive number");
  });

  it("the accepted enum is built from SIGNAL_VALUES, so guidance and schema cannot drift apart", () => {
    expect(source).toContain("z.enum(SIGNAL_VALUES)");
    // ...and no hand-written copy of the same list survives beside it, which is how the textual
    // assertion above gets satisfied while the drift is quietly reopened.
    expect(source).not.toMatch(/z\.enum\(\s*\[\s*"over"/);
  });

  it("every parameter the example names is a real parameter of the tool", () => {
    // Clause 5 closed VALUE drift. This closes NAME drift: `cello_session_id` and `content` are
    // free-floating prose inside the guidance, so renaming either would turn the worked example
    // into a second dead end with the whole suite still green — the exact class this unit exists
    // to close, closed for one half only.
    const named = new Set(
      [...SIGNAL_ERROR.matchAll(/cello_send\(\{([^}]*)\}\)/g)]
        .flatMap((m) => [...m[1].matchAll(/(\w+)\s*:/g)].map((k) => k[1])),
    );
    expect(named.size).toBeGreaterThan(0);
    // The zod shape is declared inline in the bin, so the schema keys are read from its source.
    const shape = source.slice(source.indexOf('server.tool("cello_send"'));
    for (const key of named) {
      expect(shape, `guidance names \`${key}\`, which is not a parameter of cello_send`)
        .toMatch(new RegExp(`\\n\\s*${key}:\\s*z\\.`));
    }
  });
});

/**
 * THE OMISSION AUDIT — the half a grep for wrong phrasing structurally cannot find.
 *
 * The unit review of this line found two documentation surfaces still teaching the refused call:
 * `core/adapter-claude-code/SKILL.md`, which SHIPS INSIDE the @cello-protocol/connect tarball, and
 * `.claude/commands/cello-chat.md`, a loaded skill whose own description advertises troubleshooting.
 * Neither contained a wrong string. Both were missing a right one — so searching for "must end
 * with", "append the token" and "[[OVER]]" could never have surfaced them, and did not.
 *
 * Fixing the seven call sites fixes today. This test is what stops the eighth: a doc that shows an
 * agent how to call cello_send and omits the required parameter is teaching it to fail, however
 * correct every word on the page is.
 */
describe("DOD-M12B-SIGNAL-GUIDANCE-1: no doc teaches the call that gets refused", () => {
  const REPO = join(import.meta.dirname, "..", "..", "..", "..");
  const SKIP = new Set(["node_modules", "dist", ".git", "coverage", ".turbo"]);

  function markdownFiles(dir: string, out: string[] = []): string[] {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (SKIP.has(entry.name)) continue;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) markdownFiles(full, out);
      else if (entry.name.endsWith(".md")) out.push(full);
    }
    return out;
  }

  it("every documented cello_send call names the signal parameter", () => {
    const offenders: string[] = [];
    for (const file of markdownFiles(REPO)) {
      const lines = readFileSync(file, "utf8").split("\n");
      lines.forEach((line, i) => {
        // Only a CALL — prose that merely mentions cello_send is not teaching a call shape.
        if (!line.includes("cello_send({")) return;
        if (/\bsignal\b/.test(line)) return;
        offenders.push(`${relative(REPO, file)}:${i + 1}  ${line.trim()}`);
      });
    }
    expect(
      offenders,
      "these documented calls omit the required `signal` parameter, so an agent copying them is " +
      "refused:\n" + offenders.join("\n"),
    ).toEqual([]);
  });
});
