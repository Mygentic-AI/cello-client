/**
 * The line LCS, shared by the write path (DOD-DOC-WRITE-1) and the diff surfaces
 * (DOD-DOC-NOTIFY-1).
 *
 * One implementation, deliberately. These two need to agree about what changed — the write path
 * publishes hunks and the diff surfaces describe them to an operator — and two hand-rolled diffs
 * that must agree are two things to keep in step, which is how they stop agreeing.
 *
 * ── WHY A REAL LCS AND NOT A PREFIX/SUFFIX TRIM ───────────────────────────────────────────────
 *
 * Measured twice, in two units, with the same result. A prefix/suffix trim is correct only when
 * exactly one contiguous region changed; the moment a line is INSERTED or DELETED, everything after
 * it shifts and a naive positional walk reports the whole remainder as rewritten:
 *
 *     inserting one line at the top of a 3-line file  ->  +4 -3, one range covering the file
 *
 * In the write path (WRITE-1) that published text the file did not contain — four of six ordinary
 * markdown edits. In the diff surfaces (NOTIFY-1) it made the overlap flag permanently true, which
 * is worse than useless: the flag exists so an agent can tell whether the peer touched what it
 * touched, and one that always says yes trains the agent to ignore it.
 *
 * A real LCS is also what emits SEPARATE runs for separated edits. One span from the first change
 * to the last would delete and re-insert everything between them as new operations, resurrecting
 * text a peer concurrently deleted — and under publish-on-intent, multi-edit publishes are the
 * modal case.
 */

/** Above this many lines the table is not worth building — the caller falls back and says so. */
export const LCS_LINE_LIMIT = 4000;

/**
 * A contiguous run of changed lines, as HALF-OPEN index ranges into each side.
 *
 * `aStart === aEnd` is a pure insertion; `bStart === bEnd` is a pure deletion. Half-open because
 * the empty range then has an unambiguous spelling, which a closed range does not.
 */
export interface LineRun {
  aStart: number;
  aEnd: number;
  bStart: number;
  bEnd: number;
}

/** Lines carrying their own trailing newline; the last line carries none. */
export function toChunks(text: string): string[] {
  const lines = text.split("\n");
  return lines.map((line, index) => (index < lines.length - 1 ? `${line}\n` : line));
}

/**
 * The runs of changed lines between two chunk arrays.
 *
 * Returns `null` when either side exceeds `LCS_LINE_LIMIT` — the quadratic table on a document
 * that large is the wrong kind of thorough, and a caller that silently degraded instead of being
 * told would report a whole-file rewrite as if it were a measurement.
 */
export function lineRuns(a: readonly string[], b: readonly string[]): LineRun[] | null {
  if (a.length > LCS_LINE_LIMIT || b.length > LCS_LINE_LIMIT) return null;

  const lcs: number[][] = Array.from({ length: a.length + 1 }, () =>
    new Array<number>(b.length + 1).fill(0),
  );
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) {
      lcs[i]![j] = a[i] === b[j] ? lcs[i + 1]![j + 1]! + 1 : Math.max(lcs[i + 1]![j]!, lcs[i]![j + 1]!);
    }
  }

  const runs: LineRun[] = [];
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    if (i < a.length && j < b.length && a[i] === b[j]) {
      i++;
      j++;
      continue;
    }
    const aStart = i;
    const bStart = j;
    while ((i < a.length || j < b.length) && !(i < a.length && j < b.length && a[i] === b[j])) {
      if (j < b.length && (i === a.length || lcs[i]![j + 1]! >= lcs[i + 1]![j]!)) j++;
      else i++;
    }
    runs.push({ aStart, aEnd: i, bStart, bEnd: j });
  }
  return runs;
}
