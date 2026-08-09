/**
 * DOD-DOC-WRITE-1 — the write path (§16.2).
 *
 * **The document is a real file.** The agent edits it with Read/Edit like any other file, and the
 * human can open the same file; the daemon diffs it at publish and converts the diff into Yjs
 * operations. No new editing surface exists — that is the design, not a shortcut.
 *
 * ── THE FOLD ORDER IS THE DESIGN ──────────────────────────────────────────────────────────────
 *
 * On admission (§16.2): fold the agent's UNPUBLISHED file edits into the `Y.Doc` as local
 * operations FIRST, then merge the incoming update, then rewrite the file. Reversing the first
 * two silently destroys the agent's unpublished work, and §4.1's overlap flag — which IS whether
 * the merge touched what the fold just wrote — disappears with it.
 *
 * ── WHY THE PROJECTION IS PERSISTED ───────────────────────────────────────────────────────────
 *
 * §16.2 says publish diffs the file against "the last-known projection", and that baseline has to
 * outlive the process. Diffing against the DOC's current text instead looks equivalent and is not:
 * `admit` merges into the doc and rewrites the file as two separate steps, so a crash between them
 * leaves a stale file beside an advanced doc. Diffing that against the doc reads the peer's
 * admitted content as something the agent deleted, and publishes the deletion as deliberate
 * intent. Measured, so the projection is written to disk beside the document and read back.
 */

import { mkdir, readFile, writeFile, rename, access, rm } from "node:fs/promises";
import { join } from "node:path";
import * as Y from "yjs";
import type { DocumentEngine } from "./document-engine.js";
import type { Logger } from "./types.js";
import { lineRuns, toChunks } from "./line-lcs.js";
import { serializeJsonDocument, parseJsonDocument, applyJsonToMap, type JsonValue } from "./document-json.js";
import { extensionForDocumentType, admittedDocumentTypes, rootForDocumentType, DOCUMENT_TYPES } from "./document-types.js";

/** Yjs roots a materialized document projects from. TEXT_ROOT must match DocumentEngine's. */
const TEXT_ROOT = "content";
const MAP_ROOT = "data";


/**
 * The type registry moved to `document-types.ts` — see that file for why.
 *
 * These re-exports keep the existing call sites working. `SUPPORTED_DOCUMENT_TYPES` and the
 * extension rule used to be defined HERE, in parallel with a second list in `document-notify`, and
 * the two drifted: `plaintext` was admitted and could not be diffed.
 */
export { extensionForDocumentType, isSupportedDocumentType } from "./document-types.js";

/** The types `propose`/`accept` will admit — derived from the registry, never a second list. */
export const SUPPORTED_DOCUMENT_TYPES: ReadonlySet<string> = new Set(admittedDocumentTypes());

/**
 * The extension every type was materialized under before the registry existed.
 *
 * Documents created then are on operators' disks right now. The CONTENT of one is never at risk —
 * it lives in the CRDT and would be rewritten at the new path. What is at risk is whatever the
 * agent typed into the old file and has NOT published: those bytes exist nowhere else, and leaving
 * them at a path nothing reads again loses work silently.
 */
const LEGACY_EXTENSION = "md";

/** Ids are hex identities, never names, and they become path components. */
const ID_PATTERN = /^[0-9a-f]{64}$/;

export type DocumentWriteFailure =
  | "document_file_missing"
  | "document_file_unparseable"
  | "document_file_stale"
  | "document_file_changed_during_merge"
  | "document_projection_missing"
  | "document_file_unreadable"
  | "document_type_unsupported"
  | "document_id_invalid";

export class DocumentWriteError extends Error {
  readonly reason: DocumentWriteFailure;
  readonly detail: string;
  constructor(reason: DocumentWriteFailure, detail: string) {
    super(`${reason}: ${detail}`);
    this.name = "DocumentWriteError";
    this.reason = reason;
    this.detail = detail;
  }
}

export interface AdmitResult {
  /**
   * §4.1's overlap flag: the merge touched a region (or, for JSON, a key) holding UNPUBLISHED
   * local edits. Not a conflict warning — Yjs resolved it — but a signal that the agent should
   * re-read the merged projection before building on what it thought it had written.
   */
  overlap: boolean;
}

export class DocumentWritePath {
  readonly engine: DocumentEngine;
  readonly #root: string;
  readonly #logger: Logger;

  constructor(engine: DocumentEngine, workspaceRoot: string, logger: Logger) {
    this.engine = engine;
    this.#root = workspaceRoot;
    this.#logger = logger;
  }

  /**
   * The file a document lives at. Keyed on the FULL `agent_id`/`document_id` — truncating them
   * would let two documents sharing a prefix collide onto one file and destroy each other, and
   * both ids are validated because they become path components.
   */
  filePath(agentId: string, documentId: string, documentType: string): string {
    this.#assertId(agentId, "agent_id");
    this.#assertId(documentId, "document_id");
    return join(this.#root, agentId, `${documentId}.${this.#extension(documentType)}`);
  }

  /** The extension, refusing a type this build has no path rule for rather than defaulting. */
  #extension(documentType: string): string {
    const extension = extensionForDocumentType(documentType);
    if (extension === undefined) {
      throw new DocumentWriteError(
        "document_type_unsupported",
        `no file extension is defined for document type '${documentType}'`,
      );
    }
    return extension;
  }

  /**
   * Move a document created under the old everything-is-`.md` rule onto its typed path.
   *
   * The file and its projection move TOGETHER. Moving only the file leaves publish with no recorded
   * baseline (`document_file_missing`); moving only the projection leaves it diffing an absent file.
   *
   * A file already at the new path wins: both present means the new one is the live document and
   * the old one is a leftover, so preferring the old file would replay stale content over current
   * work — the reverse of the bug this fixes. The leftover is removed so a later run cannot find it.
   */
  async #migrateLegacyPath(agentId: string, documentId: string, documentType: string): Promise<void> {
    const extension = this.#extension(documentType);
    if (extension === LEGACY_EXTENSION) return;

    const pairs: Array<[string, string]> = [
      [
        join(this.#root, agentId, `${documentId}.${LEGACY_EXTENSION}`),
        join(this.#root, agentId, `${documentId}.${extension}`),
      ],
      [
        join(this.#root, ".cello", agentId, `${documentId}.${LEGACY_EXTENSION}.projection`),
        this.#projectionPath(agentId, documentId, documentType),
      ],
    ];

    let moved = false;
    for (const [from, to] of pairs) {
      try {
        await access(from);
      } catch {
        continue; // nothing there — the ordinary case for every document created since.
      }
      try {
        await access(to);
        await rm(from, { force: true }); // the new path is live; this is a leftover.
        continue;
      } catch {
        // no file at the new path — the legacy one IS the document.
      }
      await rename(from, to);
      moved = true;
    }

    if (moved) {
      this.#logger.info("document.file.migrated", { documentId, documentType, extension });
    }
  }

  /** Write the document's projection to disk and record it as the diff baseline. */
  async materialize(agentId: string, documentId: string, documentType: string, doc: Y.Doc): Promise<string> {
    this.#assertSupported(documentType);
    await this.#migrateLegacyPath(agentId, documentId, documentType);
    const path = this.filePath(agentId, documentId, documentType);
    const content = this.#project(doc, documentType);
    await this.#writeAtomic(agentId, path, content);
    await this.#saveProjection(agentId, documentId, documentType, content);
    this.#logger.info("document.file.materialized", { documentId, bytes: content.length });
    return path;
  }

  /**
   * Diff the file against the LAST-KNOWN PROJECTION and apply the difference as local operations.
   * Returns the resulting update, or null when the file is unchanged.
   *
   * Null is a real answer: publish is an intent, so a publish with nothing to say must produce no
   * envelope rather than an empty one that still costs a leaf and a round trip.
   */
  async publish(agentId: string, documentId: string, documentType: string, doc: Y.Doc): Promise<Uint8Array | null> {
    this.#assertSupported(documentType);
    await this.#migrateLegacyPath(agentId, documentId, documentType);
    const path = this.filePath(agentId, documentId, documentType);
    const onDisk = await this.#readOrRefuse(path, documentId);
    const projection = await this.#loadProjection(agentId, documentId, documentType);

    if (projection === null) {
      throw new DocumentWriteError(
        "document_file_missing",
        `no recorded projection for document ${documentId} — materialize it before publishing`,
      );
    }

    // A file that matches NEITHER the recorded projection nor the document's current state means
    // a rewrite did not complete (admit merges into the doc and rewrites the file as two steps).
    // Diffing it would read the peer's admitted content as an agent deletion and publish that
    // deletion as deliberate intent. Refuse and re-materialize instead.
    // THE BASELINE MUST MATCH THE DOCUMENT. Hunks are offsets into the projection, applied to the
    // doc's text, so they are sound only while the two agree. An earlier version refused only when
    // the file was ALSO untouched, which let through the one state that matters: the doc advanced
    // past the projection AND the agent edited the file. That applies projection-offset hunks to a
    // longer document and mutilates the peer's admitted content — measured. The condition is the
    // invariant itself, not a symptom of it.
    const current = this.#project(doc, documentType);
    if (projection !== current) {
      throw new DocumentWriteError(
        "document_file_stale",
        `the recorded projection for ${documentId} no longer matches the document — a rewrite did ` +
          `not complete, so re-materialize before publishing rather than diffing against a ` +
          `baseline the document has moved past`,
      );
    }

    const before = this.engine.encodeStateVector(doc);
    const changed = this.#fold(doc, projection, onDisk, documentType) !== null;
    if (!changed) return null;

    await this.#saveProjection(agentId, documentId, documentType, onDisk);
    this.#logger.info("document.publish.diffed", { documentId, bytes: onDisk.length });
    return this.engine.encodeState(doc, before);
  }

  /** Admit a peer's update: fold local edits, merge, rewrite, report overlap. */
  async admit(
    agentId: string,
    documentId: string,
    documentType: string,
    doc: Y.Doc,
    incoming: Uint8Array,
  ): Promise<AdmitResult> {
    this.#assertSupported(documentType);
    await this.#migrateLegacyPath(agentId, documentId, documentType);
    const path = this.filePath(agentId, documentId, documentType);

    // 1. FOLD unpublished local edits in as local operations.
    let onDisk: string | null = null;
    try {
      onDisk = await readFile(path, "utf8");
    } catch (err: unknown) {
      // ONLY a missing file means "nothing local to lose". Any other errno — EACCES, EIO, EMFILE —
      // read as that would skip the fold and then overwrite the file with the merged projection,
      // discarding the agent's unpublished work with no event at all.
      if ((err as NodeJS.ErrnoException)?.code !== "ENOENT") {
        throw new DocumentWriteError(
          "document_file_unreadable",
          `the file for ${documentId} could not be read (${(err as NodeJS.ErrnoException)?.code ?? "unknown"}) — ` +
            `refusing rather than treating it as absent and overwriting unpublished edits`,
        );
      }
      onDisk = null;
    }

    // REFUSE a missing baseline rather than substituting "". Diffing "" against the file yields a
    // whole-file hunk inserted at offset 0 of a document that already holds that content — the
    // body duplicated into the CRDT and out to the peer, permanently.
    const projection = await this.#loadProjection(agentId, documentId, documentType);
    if (onDisk !== null && projection === null) {
      throw new DocumentWriteError(
        "document_projection_missing",
        `no recorded projection for document ${documentId} — re-materialize before admitting, ` +
          `since without a baseline the file cannot be told apart from an empty document`,
      );
    }
    let localText: { from: number; to: number } | null = null;
    const localKeys = new Set<string>();
    if (onDisk !== null) {
      const folded = this.#fold(doc, projection!, onDisk, documentType);
      if (folded && "from" in folded) localText = folded;
      else if (folded) for (const k of folded.keys) localKeys.add(k);
    }

    // 2. MERGE, observing what the incoming update touches — in BOTH coordinate spaces, because
    //    a JSON document's edits live in the map and a text observer sees none of them.
    // Inserts and deletes are compared DIFFERENTLY, and the asymmetry is the point. A re-homed
    // insert landing exactly on the local edit's boundary IS overlap — Yjs put it there because
    // the local fold deleted the characters it was anchored to. A deletion landing on that
    // boundary is NOT: it happened above the local edit and merely shifted it down, which is the
    // ordinary case of a peer editing the paragraph above yours.
    const inserted: Array<{ from: number; to: number }> = [];
    const deletedAt: number[] = [];
    const mergedKeys = new Set<string>();
    const onText = (event: Y.YTextEvent): void => {
      let cursor = 0;
      for (const delta of event.delta) {
        if (delta.retain !== undefined) cursor += delta.retain;
        else if (typeof delta.insert === "string") {
          inserted.push({ from: cursor, to: cursor + delta.insert.length });
          // Shift any local region that sits at or after this insert into the SAME coordinate
          // system. Without it the flag depends on how LONG the peer's insert was rather than
          // where it landed — a disjoint edit reads as overlapping once the insert is big enough.
          if (localText && localText.from >= cursor) {
            localText = { from: localText.from + delta.insert.length, to: localText.to + delta.insert.length };
          }
          cursor += delta.insert.length;
        } else if (delta.delete !== undefined) {
          // A POINT in post-delete coordinates. Recording the delete's OLD width made any local
          // edit within N characters after it read as overlapping — the flag sensitive to how BIG
          // the peer's delete was rather than where it landed.
          deletedAt.push(cursor);
          if (localText && localText.from >= cursor) {
            const shift = Math.min(delta.delete, Math.max(0, localText.from - cursor));
            localText = { from: localText.from - shift, to: localText.to - shift };
          }
        }
      }
    };
    const onMap = (event: Y.YMapEvent<unknown>): void => {
      for (const key of event.keysChanged) mergedKeys.add(key);
    };

    const text = doc.getText(TEXT_ROOT);
    const map = doc.getMap(MAP_ROOT);
    text.observe(onText);
    map.observe(onMap);
    try {
      this.engine.applyUpdateOrThrow(doc, incoming);
    } finally {
      text.unobserve(onText);
      map.unobserve(onMap);
    }

    // 3. REWRITE so the agent sees the merged projection — refusing if the file moved under us.
    if (onDisk !== null) {
      // Re-read the CONTENT rather than trusting mtime: second-granularity filesystems hide a save
      // inside the merge window, and a stat that itself fails must not read as "unchanged" — this
      // guard exists precisely to prevent a silent clobber.
      let nowOnDisk: string;
      try {
        nowOnDisk = await readFile(path, "utf8");
      } catch (err: unknown) {
        throw new DocumentWriteError(
          "document_file_unreadable",
          `the file for ${documentId} became unreadable during the merge ` +
            `(${(err as NodeJS.ErrnoException)?.code ?? "unknown"}) — refusing rather than rewriting it`,
        );
      }
      if (nowOnDisk !== onDisk) {
        throw new DocumentWriteError(
          "document_file_changed_during_merge",
          `the file for ${documentId} was written while the merge was in flight — its content was ` +
            `not folded in, so rewriting would discard it`,
        );
      }
    }
    const merged = this.#project(doc, documentType);
    await this.#writeAtomic(agentId, path, merged);
    await this.#saveProjection(agentId, documentId, documentType, merged);

    // 4. OVERLAP falls out of the fold, in whichever space the document lives in.
    //    Endpoints are INCLUSIVE: when the local fold deletes the characters an incoming insert
    //    was anchored to, Yjs re-homes that insert onto the boundary of the local edit — and
    //    which side depends on its random clientID tie-break, so exclusive comparison answers a
    //    definite question with a coin flip.
    const region = localText;
    const overlap = region
      ? inserted.some((t) => t.from <= region.to && region.from <= t.to) ||
        // STRICTLY inside: a deletion at the region's own boundary is adjacency, not overlap.
        deletedAt.some((at) => at > region.from && at < region.to)
      : [...localKeys].some((k) => mergedKeys.has(k));

    this.#logger.info("document.file.rewritten", { documentId, bytes: merged.length });
    if (overlap) this.#logger.info("document.file.overlap_detected", { documentId });
    return { overlap };
  }

  // ─── internals ────────────────────────────────────────────────────────────

  #project(doc: Y.Doc, documentType: string): string {
    if (rootForDocumentType(documentType) === "map") {
      // DETERMINISTIC, not `JSON.stringify` of the map: `Y.Map.toJSON()` is in INSERTION order, so
      // two peers holding the same document would render different files, and this projection is
      // what publish diffs the file against — a reorder would publish as a rewrite of every line.
      return serializeJsonDocument(doc.getMap(MAP_ROOT).toJSON() as JsonValue);
    }
    return this.engine.readTextRoot(doc);
  }

  /**
   * Apply the file's content to the document, diffing against the recorded projection.
   * Returns the region (text) or key set (JSON) the local edit occupies, or null if unchanged.
   */
  #fold(
    doc: Y.Doc,
    projection: string,
    onDisk: string,
    documentType: string,
  ): { from: number; to: number } | { keys: string[] } | null {
    if (rootForDocumentType(documentType) === "map") {
      const keys = this.#foldJson(doc, onDisk);
      return keys.length > 0 ? { keys } : null;
    }
    return this.#foldText(doc, projection, onDisk);
  }

  /**
   * Text diff producing N hunks, not one span.
   *
   * A single prefix/suffix range is coarse in a way §16.2 does NOT licence: a publish batch with
   * two separated edits would delete and re-insert everything between them as new operations,
   * which resurrects text a peer concurrently deleted and re-homes their insertions into the
   * middle of it. Measured. Publish-on-intent makes multi-hunk the NORMAL shape — an agent edits
   * across a turn and publishes once — so the line-level hunks below are the granularity the
   * design actually wants, and they collapse to the old behaviour for one contiguous edit.
   */
  #foldText(doc: Y.Doc, projection: string, onDisk: string): { from: number; to: number } | null {
    const text = doc.getText(TEXT_ROOT);
    if (text.toString() === onDisk) return null;

    const hunks = lineHunks(projection, onDisk);
    if (hunks.length === 0) return null;

    // Apply back to front so earlier offsets stay valid.
    doc.transact(() => {
      for (const hunk of [...hunks].reverse()) {
        if (hunk.to > hunk.from) text.delete(hunk.from, hunk.to - hunk.from);
        if (hunk.insert.length > 0) text.insert(hunk.from, hunk.insert);
      }
    });

    // The span the local edits occupy AFTER folding — the coordinate system the merge's deltas
    // will be reported in.
    let shift = 0;
    let low = Number.POSITIVE_INFINITY;
    let high = 0;
    for (const hunk of hunks) {
      const from = hunk.from + shift;
      const to = from + hunk.insert.length;
      low = Math.min(low, from);
      high = Math.max(high, to);
      shift += hunk.insert.length - (hunk.to - hunk.from);
    }
    return { from: low, to: high };
  }

  /** Key diff: set what changed, delete what is gone. Returns the keys written. */
  /**
   * Fold the FILE's JSON into the map root, per key.
   *
   * Shares `jsonKeyOperations` with `cello_doc_write`, so the file path and the tool path cannot
   * disagree about what counts as a changed key — the same rule the text path already follows for
   * `lineHunks`.
   */
  /**
   * Fold the FILE's JSON into the map root, per key and at every depth.
   *
   * Shares `applyJsonToMap` with `cello_doc_write`, so the file path and the tool path cannot
   * disagree about what counts as a changed key — the same rule the text path already follows for
   * `lineHunks`.
   */
  #foldJson(doc: Y.Doc, onDisk: string): string[] {
    const parsed = parseJsonDocument(onDisk);
    if (!parsed.ok) {
      throw new DocumentWriteError(
        "document_file_unparseable",
        `the document's file is not valid JSON — ${parsed.detail}`,
      );
    }
    return applyJsonToMap(doc.getMap(MAP_ROOT), parsed.value, doc);
  }

  /** tmp + rename, so an interrupted write cannot leave a truncated file a later diff reads as
   *  a deliberate mass deletion. */
  async #writeAtomic(agentId: string, path: string, content: string): Promise<void> {
    await mkdir(join(this.#root, agentId), { recursive: true });
    const tmp = `${path}.tmp`;
    await writeFile(tmp, content, "utf8");
    await rename(tmp, path);
  }

  /**
   * The baseline lives in a dot-directory, NOT beside the document. §16.2's premise is that the
   * agent edits an ordinary file and no new surface exists — a sibling `<name>.md.projection` IS
   * a new surface, one an agent may open, edit, or tidy away, and deleting it used to duplicate
   * the document.
   */
  #projectionPath(agentId: string, documentId: string, documentType: string): string {
    return join(this.#root, ".cello", agentId, `${documentId}.${this.#extension(documentType)}.projection`);
  }

  /** The projection is persisted so it survives a restart — see the header. */
  async #saveProjection(agentId: string, documentId: string, documentType: string, content: string): Promise<void> {
    const path = this.#projectionPath(agentId, documentId, documentType);
    await mkdir(join(this.#root, ".cello", agentId), { recursive: true });
    await writeFile(`${path}.tmp`, content, "utf8");
    await rename(`${path}.tmp`, path);
  }

  async #loadProjection(agentId: string, documentId: string, documentType: string): Promise<string | null> {
    try {
      return await readFile(this.#projectionPath(agentId, documentId, documentType), "utf8");
    } catch {
      return null;
    }
  }

  async #readOrRefuse(path: string, documentId: string): Promise<string> {
    try {
      return await readFile(path, "utf8");
    } catch {
      throw new DocumentWriteError(
        "document_file_missing",
        `no materialized file for document ${documentId} at ${path} — materialize it before publishing`,
      );
    }
  }

  /**
   * A type this FILE can project and fold — knowing a root is exactly that capability.
   *
   * Deliberately wider than `isSupportedDocumentType`: `json` has a root here and is not admitted at
   * the door, because the write path serves it while read/write/diff do not.
   */
  #assertSupported(documentType: string): void {
    if (rootForDocumentType(documentType) === undefined) {
      throw new DocumentWriteError(
        "document_type_unsupported",
        `no diff strategy for '${documentType}' — known types are ${[...DOCUMENT_TYPES.keys()].sort().join(", ")}`,
      );
    }
  }

  #assertId(value: string, field: string): void {
    if (!ID_PATTERN.test(value)) {
      throw new DocumentWriteError(
        "document_id_invalid",
        `${field} must be 64 lowercase hex characters — it becomes a path component, and an ` +
          `unvalidated one escapes the workspace`,
      );
    }
  }
}

/**
 * Line-level hunks between two texts, as character offsets into `before`.
 *
 * Lines are represented as CHUNKS — each line carries its own trailing newline, except the last,
 * which does not. That representation is what makes newline handling fall out instead of being
 * special-cased: appending a line to "a\nb" turns the chunk "b" into "b\n" + "c", so the LCS
 * sees the last line as changed and the hunk replaces "b" with "b\nc". A hand-rolled
 * prefix/suffix trim got this wrong for every edit that changed the line count — measured, four
 * of six ordinary markdown edits published text that was not what the file said.
 *
 * A real LCS (not a prefix/suffix trim) is required because the whole point is to emit SEPARATE
 * hunks for separated edits: one span from the first change to the last would delete and
 * re-insert everything between them as new operations, resurrecting text a peer concurrently
 * deleted. Under publish-on-intent, multi-edit publishes are the modal case.
 */
export function lineHunks(
  before: string,
  after: string,
): Array<{ from: number; to: number; insert: string }> {
  if (before === after) return [];

  const a = toChunks(before);
  const b = toChunks(after);

  const runs = lineRuns(a, b);
  if (runs === null) {
    // Above the LCS limit — one hunk, and the caller is not misled into thinking this is a
    // measurement of what changed.
    return [{ from: 0, to: before.length, insert: after }];
  }

  const offsets: number[] = [0];
  for (const chunk of a) offsets.push(offsets[offsets.length - 1]! + chunk.length);

  return runs
    .map((r) =>
      trimShared(before, {
        from: offsets[r.aStart]!,
        to: offsets[r.aEnd]!,
        insert: b.slice(r.bStart, r.bEnd).join(""),
      }),
    )
    .filter((h) => h.to > h.from || h.insert.length > 0);
}

/**
 * Shrink a hunk to the span that genuinely differs, by dropping the text it SHARES with what it
 * replaces at each end.
 *
 * WHY THIS EXISTS. `toChunks` gives every line a trailing newline except the last, so a text that
 * does not end in one has a final chunk whose IDENTITY changes the moment anything is appended:
 *
 *     "# Draft"            → ["# Draft"]
 *     "# Draft\nline two\n" → ["# Draft\n", "line two\n"]
 *
 * The LCS therefore reports the last line as deleted and re-inserted. Nothing was deleted — but the
 * receiver's `append_only` gate counts any delete range, so it refuses the update naming a deletion
 * the sender never made, and THREE refusals stall the document permanently. An append-only
 * document, whose entire premise is that appending is always safe, was destroyed by appending to it
 * whenever the starting content lacked a trailing newline. Nothing told the operator that mattered.
 *
 * Trimming rather than special-casing "is this an append": the same false deletion appears for any
 * edit that touches the last line of a file with no trailing newline. Minimal hunks are also better
 * for the CRDT — a delete the peer did not need is one that can collide with their concurrent edit
 * to that line.
 *
 * The two ends are trimmed independently and never allowed to overlap, so a hunk can shrink to a
 * pure insert (`to === from`) or a pure delete (`insert === ""`), and never to something that
 * reproduces the wrong text.
 */
function trimShared(
  before: string,
  hunk: { from: number; to: number; insert: string },
): { from: number; to: number; insert: string } {
  const removed = before.slice(hunk.from, hunk.to);
  const { insert } = hunk;

  let prefix = 0;
  const maxPrefix = Math.min(removed.length, insert.length);
  while (prefix < maxPrefix && removed[prefix] === insert[prefix]) prefix++;

  let suffix = 0;
  const maxSuffix = Math.min(removed.length - prefix, insert.length - prefix);
  while (
    suffix < maxSuffix &&
    removed[removed.length - 1 - suffix] === insert[insert.length - 1 - suffix]
  ) {
    suffix++;
  }

  return {
    from: hunk.from + prefix,
    to: hunk.to - suffix,
    insert: insert.slice(prefix, insert.length - suffix),
  };
}
