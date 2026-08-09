/**
 * DOD-DOC-STALE-WRITE-1 — telling an accidental deletion apart from a deliberate one.
 *
 * ── WHY THIS EXISTS ──────────────────────────────────────────────────────────────────────────────
 *
 * `cello_doc_write` takes the COMPLETE text, so anything absent from what you send is a deletion.
 * That contract is deliberate and correct — a patch API means stale offsets, which in a CRDT is
 * permanent corruption both sides converge on. What it cannot express is the difference between:
 *
 *   - *"I read their paragraph and I do not want it"* — a real editorial act, and
 *   - *"their paragraph arrived while I was typing and I have never seen it"* — an accident.
 *
 * Both are the same bytes on the wire. Measured live on 2026-08-09 between two machines: a peer's
 * paragraph was admitted at 12:35:41.807 and destroyed by a write published at 12:35:42.033. A 226ms
 * window, hit on the first two-machine test anyone ran.
 *
 * **The lost text is the smaller harm.** The signed record cannot tell the two apart either, so an
 * accident is permanently attributed to you as a deliberate rejection of your counterparty's work —
 * in the one system whose selling point is that the trail cannot be disputed later.
 *
 * ── WHAT MAKES THE DISTINCTION AVAILABLE ─────────────────────────────────────────────────────────
 *
 * The read mark (`document_read_marks.seen_text`) stores the exact text you last read, durably. So
 * the question "could you have seen this?" is answerable without asking you.
 *
 * ── THE RULE ─────────────────────────────────────────────────────────────────────────────────────
 *
 * **Refusal is conditioned on REMOVAL in every branch.** A write that only adds is never refused,
 * whatever the read mark says — otherwise proposing a document and writing to it before reading it
 * would be refused for no safety benefit.
 *
 * Given a removal: seen it → allowed, and recorded as deliberate. Not seen it (or no read mark at
 * all) → refused, with what changed handed back.
 *
 * ── WHY LINES ────────────────────────────────────────────────────────────────────────────────────
 *
 * Both document roots project to canonical text — JSON through the deterministic serialiser, which
 * sorts keys at every depth — so a removed key IS a removed line. One implementation covers both.
 *
 * Counted, not set-matched: a document with two identical lines that loses one has genuinely lost a
 * line, and set logic would report nothing removed.
 */

/** What a proposed write would take out of the document, split by whether the author could have seen it. */
export interface RemovalVerdict {
  /** Every line the write removes, seen or not. */
  readonly removed: readonly string[];
  /** Removed lines that were present in the text the author last read — a deliberate act. */
  readonly deliberate: readonly string[];
  /** Removed lines the author has no record of having seen — the accident. */
  readonly unseen: readonly string[];
  /** Whether the write must be refused. True exactly when `unseen` is non-empty. */
  readonly refuse: boolean;
}

/** Line multiset. Blank and whitespace-only lines are excluded — see `classifyRemovals`. */
function lineCounts(text: string): Map<string, number> {
  const counts = new Map<string, number>();
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line.length === 0) continue;
    counts.set(line, (counts.get(line) ?? 0) + 1);
  }
  return counts;
}

/**
 * Decide whether `proposed` may replace `current`, given the text the author last read.
 *
 * `known` is every text this author demonstrably held — what they last read, what they last wrote,
 * and what they were given at propose/accept. Empty means nothing is known, and every removal is
 * treated as an accident.
 *
 * Whitespace-only lines are ignored throughout. Reflowing blank lines is not content destruction,
 * and refusing a write over one would make the guard fire constantly on ordinary editing — a guard
 * that cries wolf is a guard that gets worked around.
 */
export function classifyRemovals(current: string, proposed: string, known: readonly string[]): RemovalVerdict {
  const before = lineCounts(current);
  const after = lineCounts(proposed);
  // EVERY text this author is known to have held, unioned. There is more than one source and
  // omitting any of them refuses ordinary work:
  //   - what they last READ,
  //   - what they last WROTE (you have obviously seen your own text), and
  //   - what they were handed when they proposed or accepted the document.
  // The first version took only the read, and refused every EDIT of an existing line by an author
  // who had not called read — because changing a line removes the old line's text. Two existing
  // tests caught it. A guard that fires on ordinary editing is worse than no guard: it gets removed.
  const seenCounts = new Map<string, number>();
  for (const text of known) {
    for (const [line, n] of lineCounts(text)) seenCounts.set(line, Math.max(seenCounts.get(line) ?? 0, n));
  }

  const removed: string[] = [];
  const deliberate: string[] = [];
  const unseen: string[] = [];

  for (const [line, count] of before) {
    const gone = count - (after.get(line) ?? 0);
    if (gone <= 0) continue;
    removed.push(line);
    // Seen ANY occurrence is enough. The author read this text; which copy of a duplicated line they
    // meant to drop is not something the record can or should adjudicate.
    if ((seenCounts.get(line) ?? 0) > 0) deliberate.push(line);
    else unseen.push(line);
  }

  return { removed, deliberate, unseen, refuse: unseen.length > 0 };
}
