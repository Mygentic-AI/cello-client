/**
 * DOD-DOC-STALE-WRITE-1 — a write must not delete what the author never saw.
 *
 * ── THE INCIDENT, MEASURED 2026-08-09 ────────────────────────────────────────────────────────────
 *
 * Laptop and EC2, two machines, a shared HTML document. The peer published a paragraph. It was
 * admitted into the laptop's copy at **12:35:41.807**. The laptop published a write at
 * **12:35:42.033** — 226ms later — carrying the complete text as it had been READ a moment earlier,
 * which did not contain that paragraph.
 *
 * `cello_doc_write` takes the COMPLETE text, so "absent from your text" means "delete it". The
 * daemon did exactly as told, both copies converged on the deletion, and neither party was told
 * anything. The write returned `ok: true, published: true`.
 *
 * ── WHY THE LOST TEXT IS THE SMALLER HARM ────────────────────────────────────────────────────────
 *
 * The documented way to reject a peer's change is *"read the diff and publish a change that reverses
 * it"* ([[shared-documents-objection-rebuttal]] argument 2). That is the SAME OPERATION as this
 * accident — a full-text write lacking their contribution. Nothing distinguishes them, so the signed,
 * non-repudiable record attributes an accident to you as a **deliberate rejection of your
 * counterparty's work**. In a system whose entire claim is that the trail cannot be disputed later,
 * that is worse than losing a paragraph you can retype.
 *
 * ── THE RULE (option C, agreed with Andre) ───────────────────────────────────────────────────────
 *
 *   0. NO peer update admitted since you last looked → publish, unconditionally. Your view IS
 *      current by construction, so nothing in your text can be destroying someone else's work.
 *      Checked FIRST, and it is what keeps the guard quiet on ordinary solo editing.
 *   1. The write removes nothing            → publish.
 *   2. It removes something you HAD held    → publish, recorded as a DELIBERATE removal. That is the
 *      "second refusal" — explicit and attributable, not inferred from an absence.
 *   3. It removes something you had NOT held → REFUSE, and hand back what changed.
 *
 * "Held" is the union of what you last READ and what you last WROTE. An earlier version consulted
 * only the read, and refused every EDIT of an existing line by an author who had not called read —
 * because changing a line removes the old line's text. Two existing tests caught it. A guard that
 * fires on ordinary editing is worse than no guard, because it gets switched off.
 *
 * ── WHY LINES, AND WHY THIS COVERS JSON TOO ──────────────────────────────────────────────────────
 *
 * Both roots project to canonical text — JSON through the deterministic serialiser, which sorts keys
 * at every depth — so a removed key IS a removed line. One implementation, both document types.
 */

import { describe, it, expect } from "vitest";
import { classifyRemovals } from "../document-write-guard.js";

describe("a write that removes nothing is never refused", () => {
  it("a pure addition passes even with no read mark at all", () => {
    // The proposer who writes before ever reading. Refusing here would be friction with no safety
    // benefit — nothing is being destroyed.
    const r = classifyRemovals("A\nB\n", "A\nB\nC\n", []);
    expect(r.removed).toEqual([]);
    expect(r.unseen).toEqual([]);
    expect(r.refuse).toBe(false);
  });

  it("an unchanged write passes", () => {
    expect(classifyRemovals("A\nB\n", "A\nB\n", []).refuse).toBe(false);
  });
});

describe("removing something you had seen is a DELIBERATE removal, and is allowed", () => {
  it("you read their line, then chose to take it out", () => {
    // The second refusal. You looked at it and you do not want it — that is a real editorial act and
    // the system must let you perform it.
    const r = classifyRemovals("A\nTHEIRS\nB\n", "A\nB\n", ["A\nTHEIRS\nB\n"]);
    expect(r.removed).toEqual(["THEIRS"]);
    expect(r.unseen).toEqual([]);
    expect(r.refuse).toBe(false);
    expect(r.deliberate).toEqual(["THEIRS"]);
  });

  it("deleting your OWN line is allowed", () => {
    const r = classifyRemovals("A\nMINE\n", "A\n", ["A\nMINE\n"]);
    expect(r.refuse).toBe(false);
    expect(r.deliberate).toEqual(["MINE"]);
  });
});

describe("removing something you never saw is REFUSED", () => {
  it("the measured incident: their paragraph landed between the read and the write", () => {
    const seen = "<h1>T</h1>\n<p>mine</p>\n";
    const current = "<h1>T</h1>\n<p>mine</p>\n<p>THEIRS</p>\n";
    const mine = "<h1>T</h1>\n<p>mine</p>\n<footer>f</footer>\n";
    const r = classifyRemovals(current, mine, [seen]);
    expect(r.unseen).toEqual(["<p>THEIRS</p>"]);
    expect(r.refuse).toBe(true);
  });

  it("no read mark and a removal → refused, because nothing proves you saw it", () => {
    const r = classifyRemovals("A\nTHEIRS\n", "A\n", []);
    expect(r.refuse).toBe(true);
    expect(r.unseen).toEqual(["THEIRS"]);
  });

  it("an overlapping EDIT of a line the peer changed after your read is refused", () => {
    // You edit "foo"; they had already changed it to "foo baz". Your text removes "foo baz", which
    // you never saw. Refusing is right — this is the case where a merge would silently pick a winner.
    const r = classifyRemovals("foo baz\n", "foo bar\n", ["foo\n"]);
    expect(r.refuse).toBe(true);
    expect(r.unseen).toEqual(["foo baz"]);
  });

  it("mixed: one seen removal and one unseen removal still refuses", () => {
    // The unseen one governs. Publishing the batch would destroy it.
    const r = classifyRemovals("A\nSEEN\nUNSEEN\n", "A\n", ["A\nSEEN\n"]);
    expect(r.refuse).toBe(true);
    expect(r.unseen).toEqual(["UNSEEN"]);
    expect(r.deliberate).toEqual(["SEEN"]);
  });
});

describe("it works on a JSON document, because both roots project to canonical text", () => {
  it("a key the peer added between your read and your write is protected", () => {
    const seen = '{\n  "status": "open"\n}\n';
    const current = '{\n  "owner": "them",\n  "status": "open"\n}\n';
    const mine = '{\n  "due": "friday",\n  "status": "open"\n}\n';
    const r = classifyRemovals(current, mine, [seen]);
    expect(r.refuse).toBe(true);
    expect(r.unseen).toEqual(['"owner": "them",']);
  });

  it("a key you read and deliberately dropped is allowed", () => {
    const seen = '{\n  "owner": "them",\n  "status": "open"\n}\n';
    const current = seen;
    const mine = '{\n  "status": "open"\n}\n';
    const r = classifyRemovals(current, mine, [seen]);
    expect(r.refuse).toBe(false);
    expect(r.deliberate).toEqual(['"owner": "them",']);
  });
});

describe("blank lines and duplicates do not create phantom refusals", () => {
  it("repeated identical lines are counted, not set-matched", () => {
    // Two identical lines where one is removed: the remaining occurrence must not mask the removal,
    // and a document full of blank lines must not refuse on every write.
    const r = classifyRemovals("X\nX\n", "X\n", ["X\nX\n"]);
    expect(r.refuse).toBe(false);
    expect(r.deliberate).toEqual(["X"]);
  });

  it("whitespace-only lines are never treated as content worth refusing over", () => {
    const r = classifyRemovals("A\n\n\nB\n", "A\nB\n", []);
    expect(r.refuse, "blank-line reflow must not block a write").toBe(false);
  });
});
