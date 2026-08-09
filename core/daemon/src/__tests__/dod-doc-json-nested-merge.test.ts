/**
 * DOD-DOC-JSON-NESTED-1 — the per-key merge must hold at EVERY depth, not just the top.
 *
 * ── THE DEFECT ───────────────────────────────────────────────────────────────────────────────────
 *
 * `map.set(key, plainObject)` stores a nested object as an OPAQUE VALUE. Two actors editing two
 * different fields inside the same nested object are then editing one value, and last writer wins.
 *
 * Measured before the fix, with plain Yjs and nothing of ours involved:
 *
 *   Tamara raises   blocking_flags.settlement_failed  → true
 *   Lusaco clears   blocking_flags.insufficient_funds → false      (same minute, neither has seen
 *                                                                   the other)
 *   Both sides end: {insufficient_funds: false, settlement_failed: FALSE}
 *
 * Tamara's raise is gone from both machines, silently. In the reference workflow that is a
 * settlement failure that stops being flagged.
 *
 * ── WHY IT WAS DANGEROUS RATHER THAN MERELY LIMITED ──────────────────────────────────────────────
 *
 * `jsonDiff` walks the FULL depth and reports dotted paths, so every surface an operator sees says
 * `blocking_flags.insufficient_funds changed` — the system appears to understand the structure at
 * path granularity. A schema author therefore nests exactly where several actors write, which is the
 * collision case. The diff supplies the confidence the merge could not honour, and afterwards it
 * names the field that vanished.
 *
 * A limitation you can see is survivable. One that advertises its opposite is not.
 *
 * ── THE FIX ──────────────────────────────────────────────────────────────────────────────────────
 *
 * Nested objects are stored as nested `Y.Map`, and key operations recurse. Then two writes to two
 * paths are two operations on two different items and both survive, at any depth.
 *
 * ── WHAT STAYS ATOMIC, DELIBERATELY ──────────────────────────────────────────────────────────────
 *
 * **Arrays.** Element-level merge of concurrent array edits interleaves into an order neither party
 * wrote, and an array's order is content — a ranked list, a sequence of steps. Last-writer-wins on a
 * whole array beats a silently reordered one.
 *
 * The consequence is real and is recorded rather than hidden: a JOURNAL must not be an array, or two
 * concurrent appends lose one. It should be a map keyed per entry, which this fix then carries for
 * free at any depth. See the M14 spine findings document.
 */

import { describe, it, expect } from "vitest";
import * as Y from "yjs";
import { applyJsonToMap, projectDocumentText } from "../document-json.js";

/** Apply `next` to a fresh doc, then return the two docs merged both ways. */
function converge(seed: Record<string, unknown>, aNext: Record<string, unknown>, bNext: Record<string, unknown>) {
  const a = new Y.Doc();
  a.clientID = 1;
  applyJsonToMap(a.getMap("data"), seed as never, a);
  const b = new Y.Doc();
  b.clientID = 2;
  Y.applyUpdate(b, Y.encodeStateAsUpdate(a));

  // Concurrent: neither has seen the other.
  applyJsonToMap(a.getMap("data"), aNext as never, a);
  applyJsonToMap(b.getMap("data"), bNext as never, b);

  Y.applyUpdate(a, Y.encodeStateAsUpdate(b));
  Y.applyUpdate(b, Y.encodeStateAsUpdate(a));
  return { a: a.getMap("data").toJSON(), b: b.getMap("data").toJSON() };
}

describe("two actors editing two fields inside the same nested object both survive", () => {
  it("the measured case: a raised flag and a cleared flag, same minute", () => {
    const seed = { blocking_flags: { insufficient_funds: true, settlement_failed: false } };
    const { a, b } = converge(
      seed,
      { blocking_flags: { insufficient_funds: true, settlement_failed: true } },
      { blocking_flags: { insufficient_funds: false, settlement_failed: false } },
    );
    expect(a).toEqual({ blocking_flags: { insufficient_funds: false, settlement_failed: true } });
    expect(b).toEqual(a);
  });

  it("holds three levels down", () => {
    const seed = { handoffs: { phase2_to_phase3: { execution_confirmed: false, packaged: false } } };
    const { a, b } = converge(
      seed,
      { handoffs: { phase2_to_phase3: { execution_confirmed: true, packaged: false } } },
      { handoffs: { phase2_to_phase3: { execution_confirmed: false, packaged: true } } },
    );
    expect(a).toEqual({ handoffs: { phase2_to_phase3: { execution_confirmed: true, packaged: true } } });
    expect(b).toEqual(a);
  });

  it("a NEW nested key added by each side survives on both", () => {
    // The journal-as-map case: two actors appending entries under one parent.
    const { a, b } = converge(
      { journal: {} },
      { journal: { "2026-08-09T10:00:00Z-tamara-aa11": "raised settlement failure" } },
      { journal: { "2026-08-09T10:00:01Z-lusaco-bb22": "cleared funds hold" } },
    );
    expect(Object.keys(a.journal as object).sort()).toEqual([
      "2026-08-09T10:00:00Z-tamara-aa11",
      "2026-08-09T10:00:01Z-lusaco-bb22",
    ]);
    expect(b).toEqual(a);
  });
});

describe("untouched structure is not rewritten", () => {
  it("a write that changes one nested field does not disturb its siblings", () => {
    const doc = new Y.Doc();
    doc.clientID = 1;
    const map = doc.getMap("data");
    applyJsonToMap(map, { cfg: { a: 1, b: 2 }, other: "x" } as never, doc);
    const nested = map.get("cfg") as Y.Map<unknown>;

    applyJsonToMap(map, { cfg: { a: 9, b: 2 }, other: "x" } as never, doc);

    // The SAME nested map object, not a replacement — a replacement is what clobbers a peer's
    // concurrent edit to a sibling field.
    expect(map.get("cfg")).toBe(nested);
    expect(map.toJSON()).toEqual({ cfg: { a: 9, b: 2 }, other: "x" });
  });

  it("an unchanged write produces no operations at all", () => {
    const doc = new Y.Doc();
    doc.clientID = 1;
    const map = doc.getMap("data");
    applyJsonToMap(map, { cfg: { a: 1 } } as never, doc);
    const before = Y.encodeStateAsUpdate(doc).length;
    applyJsonToMap(map, { cfg: { a: 1 } } as never, doc);
    expect(Y.encodeStateAsUpdate(doc).length, "an identical write emitted operations").toBe(before);
  });
});

describe("deletion works at depth", () => {
  it("removing a nested key removes only that key", () => {
    const doc = new Y.Doc();
    doc.clientID = 1;
    const map = doc.getMap("data");
    applyJsonToMap(map, { cfg: { a: 1, b: 2 } } as never, doc);
    applyJsonToMap(map, { cfg: { a: 1 } } as never, doc);
    expect(map.toJSON()).toEqual({ cfg: { a: 1 } });
  });

  it("replacing a nested object with a scalar works, and back again", () => {
    const doc = new Y.Doc();
    doc.clientID = 1;
    const map = doc.getMap("data");
    applyJsonToMap(map, { cfg: { a: 1 } } as never, doc);
    applyJsonToMap(map, { cfg: "off" } as never, doc);
    expect(map.toJSON()).toEqual({ cfg: "off" });
    applyJsonToMap(map, { cfg: { a: 2 } } as never, doc);
    expect(map.toJSON()).toEqual({ cfg: { a: 2 } });
  });
});

describe("arrays stay atomic — DECIDED, and its consequence is stated", () => {
  it("an array is stored whole, so its order is never rearranged by a merge", () => {
    const doc = new Y.Doc();
    doc.clientID = 1;
    const map = doc.getMap("data");
    applyJsonToMap(map, { steps: ["third", "first", "second"] } as never, doc);
    expect(map.toJSON()).toEqual({ steps: ["third", "first", "second"] });
    // Not a Y.Array — atomic by construction, which is what stops an interleave.
    expect(Array.isArray(map.get("steps"))).toBe(true);
  });

  it("objects INSIDE an array are not merged either — the array is the unit", () => {
    const { a, b } = converge(
      { rows: [{ x: 1 }] },
      { rows: [{ x: 2 }] },
      { rows: [{ x: 3 }] },
    );
    // One of them wins whole; what must NOT happen is a blended row.
    expect(a).toEqual(b);
    expect([2, 3]).toContain((a.rows as Array<{ x: number }>)[0]!.x);
  });
});

describe("the rendering stays canonical through nesting", () => {
  it("nested maps serialize with keys sorted at every depth", () => {
    const doc = new Y.Doc();
    doc.clientID = 1;
    applyJsonToMap(doc.getMap("data"), { t: { z: 1, a: { y: 1, b: 2 } } } as never, doc);
    const text = projectDocumentText(doc, "json");
    expect(text.indexOf('"a"')).toBeLessThan(text.indexOf('"z"'));
    expect(text.indexOf('"b"')).toBeLessThan(text.indexOf('"y"'));
  });

  it("a document holding a legacy PLAIN nested object converts on first write", () => {
    // Documents created before this fix hold plain objects. Nothing migrates them; the first write
    // that touches the key replaces it with a nested map, and reads are identical either way.
    const doc = new Y.Doc();
    doc.clientID = 1;
    const map = doc.getMap("data");
    map.set("cfg", { a: 1, b: 2 }); // the old shape, written directly
    expect(map.get("cfg") instanceof Y.Map).toBe(false);

    applyJsonToMap(map, { cfg: { a: 1, b: 3 } } as never, doc);
    expect(map.get("cfg") instanceof Y.Map, "the legacy blob was not converted").toBe(true);
    expect(map.toJSON()).toEqual({ cfg: { a: 1, b: 3 } });
  });
});
