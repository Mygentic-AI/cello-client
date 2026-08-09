/**
 * DOD-DOC-NOTIFY-1 — passive notification and the two read calls (§16.5, §4.1).
 *
 * ── WHY NO DOORBELL ───────────────────────────────────────────────────────────────────────────
 *
 * A document update raises NO doorbell (§11.3 — doorbell-on-update is parked). The notice sits in
 * the inbox aggregation and the agent finds it the next time it looks. That is the whole design:
 * a collaborator typing produces a stream of updates, and a doorbell per update would interrupt
 * the operator's agent continuously for something that has no deadline. The one-line summary the
 * agent eventually reads carries the same information at none of the cost.
 *
 * Following the `contact_rename_notices` precedent: there is no inbox store — the inbox is computed
 * per call — so a derived section needs its own table and its own getter.
 *
 * The notice carries `document_id` and a PENDING COUNT, and nothing else. Not a preview, not the
 * first line, not the author's words. Content reaches the agent only through the two read calls
 * below, which are screened; a notification that carried content would be an unscreened path into
 * the agent's context, which is the whole prompt-injection surface §3.1 exists to close.
 *
 * ── THE TWO READ CALLS (§4.1) ─────────────────────────────────────────────────────────────────
 *
 * `diffStats` is STRUCTURAL ONLY — counts, ranges, and the overlap flag. It exists so an agent can
 * decide whether to read without reading, which is exactly what a cautious agent should be able to
 * do. `diff` is the git-like diff itself and is an ordinary screened read.
 *
 * ── SUPPORTED TYPES FOR `diff`, DECIDED IN-UNIT ───────────────────────────────────────────────
 *
 * Markdown, plain text, and JSON. Markdown and plain text share one line-diff implementation (a
 * markdown file IS lines); JSON gets a key-path diff because a line diff over re-serialized JSON
 * reports the whole document as changed whenever a formatter touches it. Anything else returns a
 * REFUSAL naming the type rather than a line diff over bytes that are not lines — a diff that is
 * wrong is worse than no diff, because the agent cannot tell.
 */

import { lineRuns, toChunks } from "./line-lcs.js";
import { diffableDocumentTypes, rootForDocumentType } from "./document-types.js";
import type { DocumentStore } from "./document-store.js";
import type { Logger } from "./types.js";

const CREATE_NOTICES_SQL = `
  CREATE TABLE IF NOT EXISTS document_notices (
    agent_id     TEXT    NOT NULL,
    document_id  TEXT    NOT NULL,
    -- The count, not the content. See the header.
    pending      INTEGER NOT NULL,
    noticed_at   INTEGER NOT NULL,
    PRIMARY KEY (agent_id, document_id)
  );
`;

/**
 * WHAT THE OPERATOR LAST SAW, so `diff` can answer "what changed since I looked".
 *
 * The text itself, not a state vector. A state vector says which OPERATIONS this side has seen,
 * which is a fact about the CRDT — and the question an agent is asking before it builds on a shared
 * document is a fact about the TEXT: what words are different from the ones I read. Reconstructing
 * the old text from a vector means replaying the log to a point, which is both expensive and a
 * second answer to a question this column answers directly.
 *
 * Written by READ, never by write or by an arriving update. It marks what a human or an agent
 * actually looked at; moving it on an inbound update would erase the very change the diff exists to
 * show, silently, at the moment it arrived.
 */
/**
 * DOD-DOC-WATCH-1 — the paths an agent asked to be nudged about, per document.
 *
 * `paths` is a JSON array rather than a row per path: the list is small, always read and written
 * whole, and one row per (agent, document) means the ring-once bookkeeping has somewhere obvious to
 * live. `nudged_at` NULL means a nudge is owed; a read clears it back to NULL.
 */
const CREATE_WATCHES_SQL = `
  CREATE TABLE IF NOT EXISTS document_watches (
    agent_id     TEXT    NOT NULL,
    document_id  TEXT    NOT NULL,
    paths        TEXT    NOT NULL,
    nudged_at    INTEGER,
    PRIMARY KEY (agent_id, document_id)
  );
`;

const CREATE_READ_MARKS_SQL = `
  CREATE TABLE IF NOT EXISTS document_read_marks (
    agent_id     TEXT    NOT NULL,
    document_id  TEXT    NOT NULL,
    seen_text    TEXT    NOT NULL,
    seen_at      INTEGER NOT NULL,
    -- The last text WE wrote since that read, or NULL if we have not written since. See the
    -- myEditedLines comment below for why it exists: it is what makes the overlap flag a computed
    -- answer rather than a hardcoded null.
    --
    -- No backticks in this string. It is a JS template literal, so one would terminate it — which
    -- is exactly how this shipped broken for a minute.
    my_text      TEXT,
    PRIMARY KEY (agent_id, document_id)
  );
`;

/** Born on an existing table. See `PEER_DECISION_COLUMNS` in document-handshake.ts for the pattern. */
const READ_MARK_COLUMNS = ["ALTER TABLE document_read_marks ADD COLUMN my_text TEXT"];

/** Types `diff` can render. Decided in-unit; see the header for why the list is closed. */
/**
 * The types `cello_doc_diff` renders — DERIVED from the one registry, never listed here.
 *
 * This was a hardcoded `["markdown", "text", "json"]` sitting in parallel with the write path's
 * admitted set, and the two had drifted: `plaintext` was admitted and could not be diffed, so the
 * verb that says what changed was dead on a type the product offered.
 */
export const DIFFABLE_DOCUMENT_TYPES: readonly string[] = diffableDocumentTypes();
export type DiffableDocumentType = string;

export interface DocumentNotice {
  documentId: string;
  pending: number;
  noticedAtMs: number;
}

export interface DiffStats {
  documentId: string;
  linesAdded: number;
  linesRemoved: number;
  /** 1-based inclusive line ranges the change touches. Ranges, never the lines themselves. */
  ranges: Array<{ start: number; end: number }>;
  /** For JSON: the key paths touched. Empty for line-oriented types. */
  keyPaths: string[];
  /**
   * Whether the peer's change touches a region this operator also edited. The one field here that
   * is a judgement rather than a count, and the reason an agent reads stats before deciding.
   */
  overlap: boolean | null;
  /** Whether `keyPaths` was computed at all — an empty list is otherwise read as "none changed". */
  keyPathsComputed: boolean;
  /** The document exceeded the LCS limit, so the numbers above are bounds, not a measurement. */
  truncated: boolean;
}

export type DiffResult =
  | {
      ok: true;
      documentType: DiffableDocumentType;
      diff: string;
      /**
       * Set when the renderer could not do what the type asked for. A notice inside the diff STRING
       * is readable by a human and invisible to a caller branching on the result — and it travels
       * as screened content, which is the wrong channel for a fact about the renderer.
       */
      fallback?: "unparseable_json_line_diff";
    }
  | { ok: false; reason: string; detail: string };

export class DocumentNotifications {
  readonly #store: DocumentStore;
  readonly #logger: Logger;

  constructor(store: DocumentStore, logger: Logger) {
    this.#store = store;
    this.#logger = logger;
    this.#store.rawDb.exec(CREATE_NOTICES_SQL);
    this.#store.rawDb.exec(CREATE_READ_MARKS_SQL);
    this.#store.rawDb.exec(CREATE_WATCHES_SQL);
    for (const sql of READ_MARK_COLUMNS) {
      // Birth-gated so a daemon that already holds read marks gains the column instead of losing
      // them. A failure here is either "already present" — the ordinary case — or a locked
      // database, and the latter surfaces loudly on the very next SELECT rather than degrading.
      const has = (
        this.#store.rawDb.prepare("PRAGMA table_info(document_read_marks)").all() as Array<{ name: string }>
      ).some((c) => c.name === "my_text");
      if (!has) this.#store.rawDb.exec(sql);
    }
  }

  /**
   * Record what this agent last SAW, so a later diff has a "before".
   *
   * REPLACES. A read mark is a bookmark, not a history — keeping every read would make the table
   * grow with attention rather than with content, and no caller wants the second-most-recent read.
   */
  markRead(agentId: string, documentId: string, text: string, nowMs: number): void {
    this.#store.rawDb
      .prepare(
        `INSERT INTO document_read_marks (agent_id, document_id, seen_text, seen_at, my_text)
         VALUES (?, ?, ?, ?, NULL)
         ON CONFLICT (agent_id, document_id) DO UPDATE SET
           seen_text = excluded.seen_text, seen_at = excluded.seen_at,
           -- CLEARED. A read establishes a new baseline, so edits made before it are no longer
           -- "mine since I looked" — carrying them forward would report an overlap against work
           -- the operator has already seen merged.
           my_text = NULL`,
      )
      .run(agentId, documentId, text, nowMs);
    // RE-ARM THE NUDGE. A read is what spends the previous one — see `nudgeOwed`. Without this a
    // document nudges exactly once in its life and then goes quiet forever, which is worse than not
    // nudging at all because the operator would trust the silence.
    this.#store.rawDb
      .prepare("UPDATE document_watches SET nudged_at = NULL WHERE agent_id = ? AND document_id = ?")
      .run(agentId, documentId);
  }

  /**
   * Record the text WE just wrote, against the current read mark.
   *
   * No-ops when there is no read mark: without a baseline there is nothing to measure our edit
   * against, and inventing one would make the first diff after a write report the whole document as
   * a conflict.
   */
  /**
   * Every text this agent demonstrably held for this document — what it last READ and what it last
   * WROTE, in no particular order, with nulls dropped.
   *
   * Used by the stale-write guard to answer "could this author have seen the thing their write
   * removes?". Both sources are needed: a read establishes a baseline, and a write is text the
   * author obviously saw because they composed it.
   */
  knownTexts(agentId: string, documentId: string): string[] {
    const row = this.#store.rawDb
      .prepare("SELECT seen_text, my_text FROM document_read_marks WHERE agent_id = ? AND document_id = ?")
      .get(agentId, documentId) as { seen_text?: string | null; my_text?: string | null } | undefined;
    return [row?.seen_text ?? null, row?.my_text ?? null].filter((t): t is string => t !== null);
  }

  /**
   * The paths this agent has asked to be nudged about, for one document. Empty means none — never
   * "all"; see `matchWatchedPaths`.
   */
  watches(agentId: string, documentId: string): string[] {
    const row = this.#store.rawDb
      .prepare("SELECT paths FROM document_watches WHERE agent_id = ? AND document_id = ?")
      .get(agentId, documentId) as { paths?: string } | undefined;
    if (row?.paths === undefined) return [];
    try {
      const parsed = JSON.parse(row.paths) as unknown;
      return Array.isArray(parsed) ? (parsed as string[]) : [];
    } catch {
      return [];
    }
  }

  /** Replace the watch list. An empty list REMOVES the row, so "watching nothing" holds no state. */
  setWatches(agentId: string, documentId: string, paths: readonly string[]): void {
    if (paths.length === 0) {
      this.#store.rawDb
        .prepare("DELETE FROM document_watches WHERE agent_id = ? AND document_id = ?")
        .run(agentId, documentId);
      return;
    }
    this.#store.rawDb
      .prepare(
        `INSERT INTO document_watches (agent_id, document_id, paths, nudged_at)
         VALUES (?, ?, ?, NULL)
         ON CONFLICT (agent_id, document_id) DO UPDATE SET paths = excluded.paths, nudged_at = NULL`,
      )
      .run(agentId, documentId, JSON.stringify([...paths]));
  }

  /** Every document this agent is watching, for the surface that lists them. */
  allWatches(agentId: string): Array<{ documentId: string; paths: string[] }> {
    const rows = this.#store.rawDb
      .prepare("SELECT document_id, paths FROM document_watches WHERE agent_id = ? ORDER BY document_id")
      .all(agentId) as Array<{ document_id: string; paths: string }>;
    return rows.map((r) => {
      let paths: string[] = [];
      try {
        const parsed = JSON.parse(r.paths) as unknown;
        if (Array.isArray(parsed)) paths = parsed as string[];
      } catch {
        paths = [];
      }
      return { documentId: r.document_id, paths };
    });
  }

  /**
   * Whether a nudge is owed — true only if one has not already fired since this agent last READ.
   *
   * RINGS ONCE. A peer editing for ten minutes must produce one nudge, not forty; the Telegram
   * doorbell coalesces for the identical reason. Reading the document is what re-arms it, because
   * reading is what makes the earlier nudge spent.
   */
  nudgeOwed(agentId: string, documentId: string): boolean {
    const row = this.#store.rawDb
      .prepare("SELECT nudged_at FROM document_watches WHERE agent_id = ? AND document_id = ?")
      .get(agentId, documentId) as { nudged_at?: number | null } | undefined;
    return row !== undefined && (row.nudged_at ?? null) === null;
  }

  /** Record that a nudge fired, so it does not fire again until the next read. */
  markNudged(agentId: string, documentId: string, nowMs: number): void {
    this.#store.rawDb
      .prepare("UPDATE document_watches SET nudged_at = ? WHERE agent_id = ? AND document_id = ?")
      .run(nowMs, agentId, documentId);
  }

  markWritten(agentId: string, documentId: string, text: string): void {
    this.#store.rawDb
      .prepare("UPDATE document_read_marks SET my_text = ? WHERE agent_id = ? AND document_id = ?")
      .run(text, agentId, documentId);
  }

  /**
   * The lines WE edited since the last read, 1-based, in the baseline's coordinate space — or null
   * when we have not written since, which is "not computed" and must stay distinguishable from "no
   * conflict". `diffStats` requires the distinction for exactly that reason.
   */
  /**
   * WHY THIS EXISTS, stated where the reader will need it:
   *
   * At diff time the two texts in hand are the baseline and the current document, and no amount of
   * comparing them says which of the changes were the PEER's. So `overlap` was hardcoded `null`
   * while three shipped instruction sheets told agents to branch on it — and `null` is falsy in
   * JSON, so every one of them got the reassuring answer on every call. That is the precise trap
   * `diffStats` made its `myEdits` parameter required to prevent, defeated by the one caller.
   *
   * Diffing the baseline against what WE last wrote gives our own edited lines in the baseline's
   * coordinate space, which is the space the diff reports its ranges in. Exact, not inferred.
   */
  myEditedLines(agentId: string, documentId: string): number[] | null {
    const row = this.#store.rawDb
      .prepare("SELECT seen_text, my_text FROM document_read_marks WHERE agent_id = ? AND document_id = ?")
      .get(agentId, documentId) as { seen_text: string; my_text: string | null } | undefined;
    if (!row || row.my_text === null) return null;
    const lines: number[] = [];
    const runs = lineRuns(toChunks(row.seen_text), toChunks(row.my_text));
    if (runs === null) {
      // Above the LCS limit. Said as "not computed" rather than degraded into a whole-file range,
      // which would report every diff as an overlap and train the agent to ignore the field.
      return null;
    }
    for (const hunk of runs) {
      // The hunk's BEFORE range, which is what the diff reports its own ranges in. A pure insertion
      // has an empty before-range and is attributed to the line it precedes, matching `diffStats`.
      const start = hunk.aStart + 1;
      const end = hunk.aEnd === hunk.aStart ? hunk.aStart + 1 : hunk.aEnd;
      for (let n = start; n <= end; n++) lines.push(n);
    }
    return lines;
  }

  /**
   * The text this agent last saw, or null if it has never read this document.
   *
   * NULL IS NOT THE EMPTY STRING, and callers must not conflate them. Never-read means the whole
   * document is new to this agent; last-saw-empty means they read it when it was empty and
   * everything since is a change they can be shown against that. Returning "" for both would render
   * a first read of a long document as an enormous diff the agent then treats as "what just
   * changed".
   */
  lastSeen(agentId: string, documentId: string): string | null {
    const row = this.#store.rawDb
      .prepare("SELECT seen_text FROM document_read_marks WHERE agent_id = ? AND document_id = ?")
      .get(agentId, documentId) as { seen_text: string } | undefined;
    return row === undefined ? null : row.seen_text;
  }

  /**
   * How many of the PEER's updates have arrived since this agent last read the document.
   *
   * Derived from the envelope log against the read mark's timestamp, never a counter. A counter is
   * a second tally of a fact the log already holds, and the two disagree the first time a write is
   * missed or an envelope is redelivered — which happens routinely, since redelivery is how an
   * offline peer is caught up.
   *
   * No read mark means the agent has never read it, so everything the peer has sent is unread.
   */
  unreadFromPeer(agentId: string, documentId: string): number {
    const mark = this.#store.rawDb
      .prepare("SELECT seen_at FROM document_read_marks WHERE agent_id = ? AND document_id = ?")
      .get(agentId, documentId) as { seen_at: number } | undefined;
    const since = mark?.seen_at ?? 0;
    const row = this.#store.rawDb
      .prepare(
        `SELECT COUNT(*) AS n FROM document_envelopes
          WHERE owner_agent_id = ? AND document_id = ? AND sender_agent_id != ?
            AND kind = 'update' AND created_at > ?`,
      )
      .get(agentId, documentId, agentId, since) as { n: number } | undefined;
    return row?.n ?? 0;
  }

  /**
   * Note that a document has unread updates. Passive — this never pushes anything.
   *
   * The count is REPLACED rather than incremented, and is passed in by the caller from the log,
   * so the notice cannot drift from the document. An incremented counter is a second tally of a
   * fact the log already holds, and the two disagree the first time a notice write is missed.
   */
  notice(agentId: string, documentId: string, pending: number, nowMs: number): void {
    if (pending <= 0) {
      // Nothing pending is not a notice with zero in it — it is the absence of a notice. A row
      // saying "0 unread" is an inbox entry the agent must read to discover it has nothing to read.
      //
      // Deleted DIRECTLY rather than through `clear()`: that method's event means "the agent
      // fetched", and firing it because a count fell to zero reports a fetch that never happened.
      this.#store.rawDb
        .prepare("DELETE FROM document_notices WHERE agent_id = ? AND document_id = ?")
        .run(agentId, documentId);
      return;
    }
    this.#store.rawDb
      .prepare(
        `INSERT INTO document_notices (agent_id, document_id, pending, noticed_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT (agent_id, document_id)
           DO UPDATE SET pending = excluded.pending, noticed_at = excluded.noticed_at`,
      )
      .run(agentId, documentId, pending, nowMs);
  }

  /** The derived inbox section. Read-only — fetching is what clears, and that is explicit. */
  pending(agentId: string): DocumentNotice[] {
    const rows = this.#store.rawDb
      .prepare(
        `SELECT document_id, pending, noticed_at FROM document_notices
          WHERE agent_id = ? ORDER BY noticed_at ASC, document_id ASC`,
      )
      .all(agentId) as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      documentId: r["document_id"] as string,
      pending: r["pending"] as number,
      noticedAtMs: r["noticed_at"] as number,
    }));
  }

  /**
   * Cleared by the agent's EXPLICIT fetch, never by the aggregation that displays it.
   *
   * Reading the inbox and clearing the notice are different acts: an inbox render that cleared
   * would drop the notice for an agent that merely glanced at a summary, and the update would then
   * be unread and unannounced — invisible in both directions.
   */
  clear(agentId: string, documentId: string): boolean {
    const info = this.#store.rawDb
      .prepare("DELETE FROM document_notices WHERE agent_id = ? AND document_id = ?")
      .run(agentId, documentId);
    const cleared = Number(info.changes) > 0;
    // agentId included: this daemon attends several agents, and an event that names only the
    // document cannot be attributed to one of them.
    if (cleared) this.#logger.info("document.notice.cleared", { agentId, documentId });
    return cleared;
  }

  /**
   * Structural counts and ranges — NO content. Lets an agent decide whether to read.
   *
   * `before` and `after` are the materialized text of the document at the two points; the caller
   * holds the engine and therefore the materialization.
   *
   * Uses the SHARED line LCS, not a positional walk. The first version compared line i to line i,
   * which is correct only while the line count is unchanged: inserting one line at the top of a
   * three-line file reported `+4 -3` with a single range covering the whole document. The counts
   * being wrong is the smaller half — `overlap` is derived from those ranges, so it became
   * permanently true, and a flag that always says yes trains the agent to ignore it. Same defect
   * class WRITE-1 measured, which is why there is now one LCS rather than two.
   */
  diffStats(
    documentId: string,
    before: string,
    after: string,
    /**
     * The operator's own edited line numbers. REQUIRED — pass `null` to say "not computed".
     * Defaulting to `[]` made a caller that simply forgot receive `overlap: false`, the reassuring
     * answer, indistinguishable from "checked, and there is no conflict". This is the one
     * judgement field in an otherwise structural result.
     */
    myEdits: readonly number[] | null,
    documentType?: string,
  ): DiffStats {
    const a = toChunks(before);
    const b = toChunks(after);
    const runs = lineRuns(a, b);
    if (runs === null) {
      // Above the LCS limit. Said plainly rather than degraded silently into a whole-file range
      // that would read as a measurement.
      return {
        documentId,
        linesAdded: b.length,
        linesRemoved: a.length,
        ranges: [{ start: 1, end: Math.max(a.length, b.length) }],
        keyPaths: [],
        keyPathsComputed: false,
        overlap: myEdits === null ? null : myEdits.length > 0,
        truncated: true,
      };
    }

    // G3: for a JSON document the DoD asks for KEY ranges, not line ranges. Produced here rather
    // than left as a permanently-empty array, which reads as "no key paths changed" instead of
    // "not computed" — the same absent-is-not-fine trap as the overlap default above.
    let keyPaths: string[] = [];
    let keyPathsComputed = false;
    // Dispatched on the ROOT, not the type name — a second map-root type must not fall through to
    // the line path just because it is not called "json".
    if (documentType !== undefined && rootForDocumentType(documentType) === "map") {
      const paths = changedKeyPaths(before, after);
      if (paths !== null) {
        keyPaths = paths;
        keyPathsComputed = true;
      }
    }

    let added = 0;
    let removed = 0;
    const ranges: Array<{ start: number; end: number }> = [];
    for (const r of runs) {
      added += r.bEnd - r.bStart;
      removed += r.aEnd - r.aStart;
      // 1-based inclusive, over the BEFORE text — which is the text the operator's own edit line
      // numbers refer to, and therefore the only coordinate space in which the overlap comparison
      // means anything. A pure insertion has an empty before-range, so it is reported at the line
      // it precedes rather than as a zero-width range nobody can act on.
      ranges.push({ start: r.aStart + 1, end: r.aEnd === r.aStart ? r.aStart + 1 : r.aEnd });
    }

    const touched = new Set<number>();
    for (const r of ranges) for (let n = r.start; n <= r.end; n++) touched.add(n);
    return {
      documentId,
      linesAdded: added,
      linesRemoved: removed,
      ranges,
      keyPaths,
      keyPathsComputed,
      overlap: myEdits === null ? null : myEdits.some((line) => touched.has(line)),
      truncated: false,
    };
  }

  /**
   * The git-like diff. An ordinary screened read — the caller screens it; this renders it.
   *
   * An unsupported type is REFUSED by name rather than line-diffed anyway. A diff that is silently
   * wrong is worse than no diff, because the agent has no way to tell and will act on it.
   */
  diff(documentType: string, before: string, after: string, documentId: string): DiffResult {
    if (!(DIFFABLE_DOCUMENT_TYPES as readonly string[]).includes(documentType)) {
      return {
        ok: false,
        reason: "document_type_not_diffable",
        detail:
          `this build renders diffs for ${DIFFABLE_DOCUMENT_TYPES.join(", ")} and this document is ` +
          `"${documentType}" — read the document instead of a diff that would be guesswork`,
      };
    }
    void documentId;

    if (rootForDocumentType(documentType) === "map") {
      // A key-path diff, not a line diff. Re-serialized JSON changes shape whenever a formatter
      // touches it, so a line diff reports the entire document as rewritten for a change of one
      // value — which is the false "everything changed" alarm that makes an agent stop reading
      // diffs at all.
      const parsedPaths = changedKeyPaths(before, after);
      if (parsedPaths === null) {
        return {
          ok: true,
          documentType: "json",
          diff: `! this document does not parse as JSON; showing a line diff instead\n${lineDiff(before, after)}`,
          fallback: "unparseable_json_line_diff",
        };
      }
      return { ok: true, documentType: "json", diff: jsonDiff(before, after) };
    }
    return { ok: true, documentType: documentType as DiffableDocumentType, diff: lineDiff(before, after) };
  }
}

function lineDiff(before: string, after: string): string {
  // The SHARED LCS, same as diffStats. This renderer kept the positional walk after diffStats moved
  // off it, which is the worse half to leave behind: inserting one line into a ten-line file
  // rendered eighteen +/- lines, reporting the entire remainder as rewritten. That is the false
  // "everything changed" alarm that makes an agent stop reading diffs at all — the exact reasoning
  // that gave JSON a key-path diff, applied to markdown at last.
  const a = toChunks(before);
  const b = toChunks(after);
  const runs = lineRuns(a, b);
  if (runs === null) return "! this document is too large to diff line-by-line";

  const out: string[] = [];
  let ai = 0;
  for (const r of runs) {
    for (; ai < r.aStart; ai++) out.push(`  ${strip(a[ai]!)}`);
    for (let i = r.aStart; i < r.aEnd; i++) out.push(`- ${strip(a[i]!)}`);
    for (let j = r.bStart; j < r.bEnd; j++) out.push(`+ ${strip(b[j]!)}`);
    ai = r.aEnd;
  }
  for (; ai < a.length; ai++) out.push(`  ${strip(a[ai]!)}`);
  return out.join("\n");
}

/** Chunks carry their own trailing newline; the rendered diff supplies its own line breaks. */
function strip(chunk: string): string {
  return chunk.endsWith("\n") ? chunk.slice(0, -1) : chunk;
}

function flatten(value: unknown, prefix = ""): Map<string, string> {
  const out = new Map<string, string>();
  if (value === null || typeof value !== "object") {
    out.set(prefix || "$", JSON.stringify(value));
    return out;
  }
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    // The separator is ESCAPED in the key. Unescaped, {"a.b": 1} and {"a": {"b": 1}} flatten to the
    // same path, so a document using dotted keys reports no change where there was one — silently,
    // which is the exact behaviour this unit refuses everywhere else.
    const path = prefix ? `${prefix}.${k.replace(/\\/g, "\\\\").replace(/\./g, "\\.")}` : k.replace(/\\/g, "\\\\").replace(/\./g, "\\.");
    for (const [p, s] of flatten(v, path)) out.set(p, s);
  }
  return out;
}

/** The changed key paths, or null when either side does not parse. */
/**
 * Exported so the WATCH matcher (`DOD-DOC-WATCH-1`) computes paths the same way `cello_doc_diff`
 * renders them. Two implementations would let an agent be nudged about a path the diff never shows,
 * or shown a path no watch can name — and either makes the feature untrustworthy.
 */
export function changedKeyPaths(before: string, after: string): string[] | null {
  let a: Map<string, string>;
  let b: Map<string, string>;
  try {
    a = flatten(JSON.parse(before));
    b = flatten(JSON.parse(after));
  } catch {
    return null;
  }
  const paths = new Set<string>();
  for (const [path, value] of a) if (!b.has(path) || b.get(path) !== value) paths.add(path);
  for (const [path] of b) if (!a.has(path)) paths.add(path);
  return [...paths].sort();
}

function jsonDiff(before: string, after: string): string {
  let a: Map<string, string>;
  let b: Map<string, string>;
  try {
    a = flatten(JSON.parse(before));
    b = flatten(JSON.parse(after));
  } catch {
    // Deliberately explicit: unparseable JSON gets a stated fallback, not a silent line diff
    // pretending to be a key diff. The caller sees which it got.
    return `! this document does not parse as JSON; showing a line diff instead\n${lineDiff(before, after)}`;
  }
  const out: string[] = [];
  for (const [path, value] of a) {
    if (!b.has(path)) out.push(`- ${path}: ${value}`);
    else if (b.get(path) !== value) out.push(`~ ${path}: ${value} -> ${b.get(path)}`);
  }
  for (const [path, value] of b) if (!a.has(path)) out.push(`+ ${path}: ${value}`);
  return out.join("\n");
}
