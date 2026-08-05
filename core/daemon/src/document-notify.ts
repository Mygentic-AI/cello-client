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

/** Types `diff` can render. Decided in-unit; see the header for why the list is closed. */
export const DIFFABLE_DOCUMENT_TYPES = ["markdown", "text", "json"] as const;
export type DiffableDocumentType = (typeof DIFFABLE_DOCUMENT_TYPES)[number];

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
  overlap: boolean;
  /** The document exceeded the LCS limit, so the numbers above are bounds, not a measurement. */
  truncated: boolean;
}

export type DiffResult =
  | { ok: true; documentType: DiffableDocumentType; diff: string }
  | { ok: false; reason: string; detail: string };

export class DocumentNotifications {
  readonly #store: DocumentStore;
  readonly #logger: Logger;

  constructor(store: DocumentStore, logger: Logger) {
    this.#store = store;
    this.#logger = logger;
    this.#store.rawDb.exec(CREATE_NOTICES_SQL);
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
      this.clear(agentId, documentId);
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
    if (cleared) this.#logger.info("document.notice.cleared", { documentId });
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
  diffStats(documentId: string, before: string, after: string, myEdits: readonly number[] = []): DiffStats {
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
        overlap: myEdits.length > 0,
        truncated: true,
      };
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
      keyPaths: [],
      overlap: myEdits.some((line) => touched.has(line)),
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

    if (documentType === "json") {
      // A key-path diff, not a line diff. Re-serialized JSON changes shape whenever a formatter
      // touches it, so a line diff reports the entire document as rewritten for a change of one
      // value — which is the false "everything changed" alarm that makes an agent stop reading
      // diffs at all.
      return { ok: true, documentType: "json", diff: jsonDiff(before, after) };
    }
    return { ok: true, documentType: documentType as DiffableDocumentType, diff: lineDiff(before, after) };
  }
}

function lineDiff(before: string, after: string): string {
  const a = before.split("\n");
  const b = after.split("\n");
  const out: string[] = [];
  const max = Math.max(a.length, b.length);
  for (let i = 0; i < max; i++) {
    if (a[i] === b[i]) {
      if (a[i] !== undefined) out.push(`  ${a[i]}`);
      continue;
    }
    if (a[i] !== undefined) out.push(`- ${a[i]}`);
    if (b[i] !== undefined) out.push(`+ ${b[i]}`);
  }
  return out.join("\n");
}

function flatten(value: unknown, prefix = ""): Map<string, string> {
  const out = new Map<string, string>();
  if (value === null || typeof value !== "object") {
    out.set(prefix || "$", JSON.stringify(value));
    return out;
  }
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    const path = prefix ? `${prefix}.${k}` : k;
    for (const [p, s] of flatten(v, path)) out.set(p, s);
  }
  return out;
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
