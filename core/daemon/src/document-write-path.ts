/**
 * DOD-DOC-WRITE-1 — the write path (§16.2).
 *
 * **The document is a real file.** The agent edits it with Read/Edit like any other file, and the
 * human can open the same file in an editor; the daemon diffs it at publish and converts the diff
 * into Yjs operations. No new editing surface exists — that is the design, not a shortcut.
 *
 * Diff coarseness is acceptable *because* of publish-on-intent (§5): updates are already coarse,
 * intentional batches, so diff-granularity operations are the granularity the design wants.
 *
 * ── THE FOLD ORDER IS THE DESIGN ──────────────────────────────────────────────────────────────
 *
 * On admission (§16.2): fold the agent's UNPUBLISHED file edits into the `Y.Doc` as local
 * operations FIRST, then merge the incoming update, then rewrite the file.
 *
 * Reversing those first two steps silently destroys the agent's unpublished work — the file gets
 * rewritten from a document that never saw it. And §4.1's overlap flag is not a separate feature
 * to compute: it is whether the merge touched regions the local fold had just written. The two
 * mechanisms are one mechanism, and both are lost by getting the order wrong.
 */

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import * as Y from "yjs";
import type { DocumentEngine } from "./document-engine.js";
import type { Logger } from "./types.js";

/** The Yjs roots a materialized document projects from. Must match DocumentEngine's TEXT_ROOT. */
const TEXT_ROOT = "content";
const MAP_ROOT = "data";

/** Document types with a diff strategy. `xml` is declared in the store but has none yet. */
const TEXT_TYPES = new Set(["markdown", "text", "plaintext"]);
const JSON_TYPES = new Set(["json"]);

export interface AdmitResult {
  /**
   * §4.1's overlap flag: the incoming merge touched a region that held UNPUBLISHED local edits.
   * Not a warning about conflict — Yjs resolved it — but a signal the agent should re-read the
   * merged projection before building on what it thought it had written.
   */
  overlap: boolean;
}

export class DocumentWritePath {
  readonly engine: DocumentEngine;
  readonly #root: string;
  readonly #logger: Logger;
  /** document_id → the content last written to or read from disk, per agent. */
  readonly #projection = new Map<string, string>();

  constructor(engine: DocumentEngine, workspaceRoot: string, logger: Logger) {
    this.engine = engine;
    this.#root = workspaceRoot;
    this.#logger = logger;
  }

  /**
   * The file a document lives at. Keyed on `agent_id`/`document_id` — a filename is display, the
   * id is identity, and a document's name is mutable while its id is not.
   */
  filePath(agentId: string, documentId: string, documentType: string): string {
    const extension = JSON_TYPES.has(documentType) ? "json" : "md";
    return join(this.#root, agentId.slice(0, 16), `${documentId.slice(0, 16)}.${extension}`);
  }

  /** Write the document's current projection to disk, creating the workspace on demand. */
  async materialize(agentId: string, documentId: string, documentType: string, doc: Y.Doc): Promise<string> {
    this.#assertSupported(documentType);
    const path = this.filePath(agentId, documentId, documentType);
    await mkdir(join(this.#root, agentId.slice(0, 16)), { recursive: true });

    const content = this.#project(doc, documentType);
    await writeFile(path, content, "utf8");
    this.#projection.set(this.#key(agentId, documentId), content);
    this.#logger.info("document.file.materialized", { documentId, bytes: content.length });
    return path;
  }

  /**
   * Diff the file against the last-known projection and apply the difference to the document as
   * local operations. Returns the resulting Yjs update, or null when the file is unchanged.
   *
   * Null is a real answer, not a failure: publish is an intent, so a publish with nothing to say
   * must produce no envelope rather than an empty one that still costs a leaf and a round trip.
   */
  async publish(agentId: string, documentId: string, doc: Y.Doc): Promise<Uint8Array | null> {
    const documentType = this.#typeOf(doc);
    const path = this.filePath(agentId, documentId, documentType);

    let onDisk: string;
    try {
      onDisk = await readFile(path, "utf8");
    } catch {
      throw new Error(
        `document_file_missing: no materialized file for document ${documentId.slice(0, 16)}… at ${path} — ` +
          `materialize it before publishing`,
      );
    }

    const before = this.engine.encodeStateVector(doc);
    const changed = this.#foldFileInto(doc, onDisk, documentType);
    if (!changed) return null;

    this.#projection.set(this.#key(agentId, documentId), onDisk);
    this.#logger.info("document.publish.diffed", { documentId, bytes: onDisk.length });
    return this.engine.encodeState(doc, before);
  }

  /**
   * Admit a peer's update: fold local file edits, merge, rewrite the file, report overlap.
   *
   * The order is §16.2's, and it is the whole unit.
   */
  async admit(agentId: string, documentId: string, doc: Y.Doc, incoming: Uint8Array): Promise<AdmitResult> {
    const documentType = this.#typeOf(doc);
    const path = this.filePath(agentId, documentId, documentType);

    // 1. FOLD unpublished local edits in as local operations. If the file cannot be read the
    //    document has not been materialized, and there is nothing local to lose.
    let onDisk: string | null = null;
    try {
      onDisk = await readFile(path, "utf8");
    } catch {
      onDisk = null;
    }

    const localRegions: Array<{ from: number; to: number }> = [];
    if (onDisk !== null) {
      if (TEXT_TYPES.has(documentType)) {
        // The fold reports where the local edit ENDED UP, which is the coordinate system the
        // merge's deltas are reported in.
        const region = this.#foldText(doc, onDisk);
        if (region) localRegions.push(region);
      } else {
        this.#foldFileInto(doc, onDisk, documentType);
      }
    }

    // 2. MERGE the incoming update, and observe which regions it touched.
    const touched: Array<{ from: number; to: number }> = [];
    const observe = (event: Y.YTextEvent): void => {
      let cursor = 0;
      for (const delta of event.delta) {
        if (delta.retain !== undefined) cursor += delta.retain;
        else if (typeof delta.insert === "string") {
          touched.push({ from: cursor, to: cursor + delta.insert.length });
          cursor += delta.insert.length;
        } else if (delta.delete !== undefined) {
          touched.push({ from: cursor, to: cursor + delta.delete });
        }
      }
    };
    const text = doc.getText(TEXT_ROOT);
    text.observe(observe);
    try {
      this.engine.applyUpdateOrThrow(doc, incoming);
    } finally {
      text.unobserve(observe);
    }

    // 3. REWRITE the file so the agent sees the merged projection.
    const merged = this.#project(doc, documentType);
    await mkdir(join(this.#root, agentId.slice(0, 16)), { recursive: true });
    await writeFile(path, merged, "utf8");
    this.#projection.set(this.#key(agentId, documentId), merged);

    // 4. OVERLAP falls out of the fold — it is not tracked separately.
    // Endpoints are INCLUSIVE, and that is load-bearing rather than an off-by-one indulgence.
    // When the local fold deletes the characters an incoming insert was anchored to, Yjs re-homes
    // that insert to the boundary of the local edit — and which side of the boundary depends on
    // Yjs's clientID tie-break, which is RANDOM. Strict inequality therefore reported overlap
    // only about half the time for the very case where both sides rewrote the same words:
    // a flaky answer to a question that has a definite one.
    const overlap = localRegions.some((local) =>
      touched.some((t) => t.from <= local.to && local.from <= t.to),
    );
    this.#logger.info("document.file.materialized", { documentId, bytes: merged.length });
    if (overlap) this.#logger.info("document.file.overlap_detected", { documentId });
    return { overlap };
  }

  // ─── internals ────────────────────────────────────────────────────────────

  /** Project the document to the text its file holds. */
  #project(doc: Y.Doc, documentType: string): string {
    if (JSON_TYPES.has(documentType)) {
      return `${JSON.stringify(doc.getMap(MAP_ROOT).toJSON(), null, 2)}\n`;
    }
    return this.engine.readTextRoot(doc);
  }

  /** Apply the file's content to the document. Returns whether anything changed. */
  #foldFileInto(doc: Y.Doc, onDisk: string, documentType: string): boolean {
    if (JSON_TYPES.has(documentType)) return this.#foldJson(doc, onDisk);
    return this.#foldText(doc, onDisk) !== null;
  }

  /**
   * Text diff: replace the span between the common prefix and the common suffix.
   *
   * Deliberately ONE replacement range rather than a minimal edit script. §16.2 accepts diff
   * coarseness because publish-on-intent already batches, and a single range is the coarse end of
   * that: it keeps every character outside the changed span untouched, which is what preserves a
   * concurrent editor's work in the regions they touched.
   */
  #foldText(doc: Y.Doc, onDisk: string): { from: number; to: number } | null {
    const text = doc.getText(TEXT_ROOT);
    const current = text.toString();
    if (current === onDisk) return null;

    const { from, to } = diffRange(current, onDisk);
    const replacement = onDisk.slice(from, onDisk.length - (current.length - to));
    doc.transact(() => {
      if (to > from) text.delete(from, to - from);
      if (replacement.length > 0) text.insert(from, replacement);
    });
    // The region the local edit OCCUPIES AFTER folding. Returning the pre-fold range would
    // compare two different coordinate systems, since the merge reports its deltas against the
    // post-fold text.
    return { from, to: from + replacement.length };
  }

  /** Key diff: set what changed, delete what is gone, leave untouched keys alone. */
  #foldJson(doc: Y.Doc, onDisk: string): boolean {
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(onDisk) as Record<string, unknown>;
    } catch (err: unknown) {
      // REFUSE rather than half-apply. A broken file must not corrupt the CRDT, and the reason
      // names the file — not "unexpected token", which describes the parser's exit point.
      throw new Error(
        `document_file_unparseable: the document's file is not valid JSON — ` +
          `${err instanceof Error ? err.message : String(err)}`,
      );
    }

    const map = doc.getMap(MAP_ROOT);
    const before = JSON.stringify(map.toJSON());
    doc.transact(() => {
      for (const [key, value] of Object.entries(parsed)) {
        if (JSON.stringify(map.get(key)) !== JSON.stringify(value)) map.set(key, value);
      }
      for (const key of [...map.keys()]) {
        if (!(key in parsed)) map.delete(key);
      }
    });
    return JSON.stringify(map.toJSON()) !== before;
  }

  #typeOf(doc: Y.Doc): string {
    // A document carries its shape: a populated map root means JSON. Text is the default, and the
    // store's `documentType` is authoritative once the caller threads it through (P2).
    return doc.getMap(MAP_ROOT).size > 0 ? "json" : "markdown";
  }

  #assertSupported(documentType: string): void {
    if (!TEXT_TYPES.has(documentType) && !JSON_TYPES.has(documentType)) {
      throw new Error(
        `document_type_unsupported: no diff strategy for '${documentType}' — ` +
          `supported types are ${[...TEXT_TYPES, ...JSON_TYPES].join(", ")}`,
      );
    }
  }

  #key(agentId: string, documentId: string): string {
    return `${agentId}:${documentId}`;
  }
}

/**
 * The span that differs between two strings, as an offset range into `before`.
 *
 * Common prefix and common suffix, so an edit at one end does not report the whole string as
 * changed — which is what keeps the overlap flag meaningful rather than always true.
 */
export function diffRange(before: string, after: string): { from: number; to: number } {
  let from = 0;
  const maxPrefix = Math.min(before.length, after.length);
  while (from < maxPrefix && before[from] === after[from]) from++;

  let suffix = 0;
  const maxSuffix = Math.min(before.length - from, after.length - from);
  while (
    suffix < maxSuffix &&
    before[before.length - 1 - suffix] === after[after.length - 1 - suffix]
  ) {
    suffix++;
  }

  return { from, to: before.length - suffix };
}
