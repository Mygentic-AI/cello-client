/**
 * DOD-DOC-TOOLS-1 review, finding 1 — an APPEND must not be diffed as a DELETION.
 *
 * ── THE DEFECT ───────────────────────────────────────────────────────────────────────────────────
 *
 * `toChunks` gives every line its own trailing newline, and the LAST line of a text that does not
 * end in one gets no newline. So appending to `"# Draft"`:
 *
 *     before → ["# Draft"]
 *     after  → ["# Draft\n", "new line\n"]
 *
 * The last chunk changed IDENTITY, so the LCS emits a hunk that DELETES `"# Draft"` and re-inserts
 * `"# Draft\nnew line\n"`. Nothing was deleted — but the receiver's `append_only` gate counts any
 * delete range, so it refuses the update as *"the update deletes or rewrites 1 existing range(s)"*.
 *
 * ── WHAT IT COSTS AN OPERATOR ────────────────────────────────────────────────────────────────────
 *
 * Alice proposes an append-only log with `starting_content: "# Draft"` — no trailing newline, and
 * nothing anywhere tells her that matters. Bob appends a line. His side says `ok: true,
 * published: true`. Alice's gate refuses it, describing a deletion Bob never made. Bob retries.
 * **Three refusals and the document is `stalled`, which is terminal.** An append-only document —
 * the one shape whose whole point is that appending is always safe — is destroyed by appending to
 * it.
 *
 * The existing spine test passes because every string in it ends in a newline, which is the one
 * shape that works.
 *
 * ── THE FIX, AND WHY IT IS AT THE HUNK LEVEL ─────────────────────────────────────────────────────
 *
 * Each hunk is trimmed of the text it shares with what it replaces — common prefix and common
 * suffix — so a hunk only ever spans what genuinely differs. A delete-and-reinsert of `"b"` as
 * `"b\n…"` collapses into a pure insert at the end.
 *
 * Done here rather than by special-casing "is this an append", because the same false deletion
 * appears whenever an edit touches the last line of a file with no trailing newline, and because
 * minimal hunks are better for the CRDT anyway: a delete the peer did not need is a delete that can
 * collide with their concurrent edit to the same line.
 */

import { describe, it, expect } from "vitest";
import { lineHunks } from "../document-write-path.js";

/** Total characters this hunk set would DELETE from `before`. The gate counts exactly this. */
function deletedChars(hunks: Array<{ from: number; to: number; insert: string }>): number {
  return hunks.reduce((n, h) => n + (h.to - h.from), 0);
}

/** Apply the hunks the way `cello_doc_write` does, to prove the result is still correct. */
function applyHunks(before: string, hunks: Array<{ from: number; to: number; insert: string }>): string {
  let out = before;
  for (const h of [...hunks].reverse()) {
    out = out.slice(0, h.from) + h.insert + out.slice(h.to);
  }
  return out;
}

describe("appending to a document deletes nothing", () => {
  const cases: Array<{ name: string; before: string; after: string }> = [
    {
      name: "no trailing newline — the case that stalls an append-only document",
      before: "# Draft",
      after: "# Draft\nline two\n",
    },
    {
      name: "no trailing newline, appending without adding one",
      before: "line one",
      after: "line one\nline two",
    },
    {
      name: "trailing newline — the shape the existing test uses, kept so the fix does not regress it",
      before: "line one\nline two\n",
      after: "line one\nline two\nline three\n",
    },
    {
      name: "single line, no newline anywhere",
      before: "a",
      after: "ab",
    },
    {
      name: "empty document",
      before: "",
      after: "first line\n",
    },
  ];

  for (const c of cases) {
    it(`${c.name}`, () => {
      const hunks = lineHunks(c.before, c.after);

      expect(
        deletedChars(hunks),
        "an append was diffed as a deletion — an append-only peer REFUSES this, and three refusals " +
          "stall the document permanently",
      ).toBe(0);

      // The hunks must still produce the right text. A fix that deletes nothing by producing the
      // wrong document would pass the assertion above and corrupt every write.
      expect(applyHunks(c.before, hunks)).toBe(c.after);
    });
  }
});

describe("hunks stay minimal without losing correctness", () => {
  it("a real edit still deletes what it replaces", () => {
    // The guard against over-correcting: if trimming made every hunk an insert, an actual deletion
    // would silently stop being one and `append_only` would admit real rewrites.
    const hunks = lineHunks("keep\nremove me\nkeep too\n", "keep\nkeep too\n");
    expect(deletedChars(hunks)).toBeGreaterThan(0);
    expect(applyHunks("keep\nremove me\nkeep too\n", hunks)).toBe("keep\nkeep too\n");
  });

  it("a mid-document rewrite deletes only the changed span, not the shared ends", () => {
    const before = "alpha\nbravo\ncharlie\n";
    const after = "alpha\nBRAVO\ncharlie\n";
    const hunks = lineHunks(before, after);
    expect(applyHunks(before, hunks)).toBe(after);
    // "bravo\n" is 6 chars; trimming the shared "\n" leaves at most that.
    expect(deletedChars(hunks)).toBeLessThanOrEqual(6);
  });

  it("a pure truncation is still a deletion", () => {
    const hunks = lineHunks("one\ntwo\nthree\n", "one\n");
    expect(deletedChars(hunks)).toBeGreaterThan(0);
    expect(applyHunks("one\ntwo\nthree\n", hunks)).toBe("one\n");
  });
});
