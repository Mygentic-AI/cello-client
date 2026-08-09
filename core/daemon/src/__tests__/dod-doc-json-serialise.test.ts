/**
 * DOD-DOC-TYPES-1, unit 4a — the deterministic serialiser.
 *
 * ── WHY THIS IS NEEDED NOW, NOT LATER ────────────────────────────────────────────────────────────
 *
 * The CRDT determines the document's MAP STATE. It does not determine the STRING that map is
 * printed as. `Y.Map.toJSON()` returns keys in INSERTION order, so two peers who added the same
 * keys in a different order hold the same document and render different files:
 *
 *   Alice adds `owner` then `status`  →  {"owner": "a", "status": "open"}
 *   Bob   adds `status` then `owner`  →  {"status": "open", "owner": "a"}
 *
 * Both are faithful. Both are correct. And every one of the following now breaks:
 *
 *   - **The file diff publishes a phantom edit.** The write path diffs the FILE against the recorded
 *     projection. Re-serialize in a different order and the diff is the whole document, published to
 *     the peer as a real signed rewrite.
 *   - **Two machines comparing files disagree** about a document they agree on.
 *   - **Paste-and-agree breaks.** Pasting the rendered document and asking the peer to confirm they
 *     hold the same thing is the way values get attested; it needs both sides to render identically.
 *
 * So this is not future-proofing. It is what makes a JSON document usable by two parties at all.
 *
 * ── THE RULE ─────────────────────────────────────────────────────────────────────────────────────
 *
 * Object keys are sorted, recursively, at every depth. ARRAYS ARE NOT SORTED — an array's order is
 * content, and reordering it changes what the document says.
 */

import { describe, it, expect } from "vitest";
import { serializeJsonDocument } from "../document-json.js";

describe("the same map always prints the same bytes", () => {
  it("sorts keys regardless of insertion order", () => {
    const a = serializeJsonDocument({ owner: "a", status: "open" });
    const b = serializeJsonDocument({ status: "open", owner: "a" });
    expect(a).toBe(b);
    expect(a).toContain('"owner"');
    // Sorted, so `owner` precedes `status` whichever order they arrived in.
    expect(a.indexOf('"owner"')).toBeLessThan(a.indexOf('"status"'));
  });

  it("sorts at EVERY depth, not just the top", () => {
    const a = serializeJsonDocument({ t: { z: 1, a: 2, m: { y: 1, b: 2 } } });
    const b = serializeJsonDocument({ t: { m: { b: 2, y: 1 }, a: 2, z: 1 } });
    expect(a).toBe(b);
  });

  it("does NOT sort arrays — order is content there", () => {
    // The one place sorting would change what the document SAYS. A task list, a sequence of steps,
    // a ranked set of options: reordering it is a lie about the agreement.
    const out = serializeJsonDocument({ steps: ["third", "first", "second"] });
    expect(out.indexOf("third")).toBeLessThan(out.indexOf("first"));
  });

  it("sorts objects INSIDE arrays, without moving the array elements", () => {
    const a = serializeJsonDocument({ rows: [{ b: 1, a: 2 }, { d: 1, c: 2 }] });
    const b = serializeJsonDocument({ rows: [{ a: 2, b: 1 }, { c: 2, d: 1 }] });
    expect(a).toBe(b);
    expect(a.indexOf('"a"')).toBeLessThan(a.indexOf('"c"'));
  });

  it("ends with exactly one newline, so a text editor does not add a phantom diff", () => {
    // Most editors add a trailing newline on save. Without one here, the first save of an untouched
    // file publishes an edit nobody made.
    const out = serializeJsonDocument({ a: 1 });
    expect(out.endsWith("}\n")).toBe(true);
    expect(out.endsWith("}\n\n")).toBe(false);
  });

  it("is stable across a round trip through JSON.parse", () => {
    // The property the file path depends on: read the file, parse it, re-serialize, get the same
    // bytes. If this fails, every publish diffs against a moving baseline.
    const once = serializeJsonDocument({ z: [3, 1, 2], a: { n: null, t: true } });
    expect(serializeJsonDocument(JSON.parse(once))).toBe(once);
  });

  it("carries the JSON types a document can actually hold", () => {
    const out = serializeJsonDocument({ s: "x", n: 1.5, b: false, nul: null, arr: [], obj: {} });
    expect(JSON.parse(out)).toEqual({ s: "x", n: 1.5, b: false, nul: null, arr: [], obj: {} });
  });

  it("is indented, because a human and an agent both have to read it", () => {
    const out = serializeJsonDocument({ a: { b: 1 } });
    expect(out).toContain("\n  ");
    // And the indentation is what a line diff can work with — nested values on their own lines.
    expect(out.split("\n").length).toBeGreaterThan(3);
  });
});
