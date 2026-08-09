/**
 * DOD-DOC-TYPES-1 — the single registry of document types.
 *
 * ── WHY THIS FILE EXISTS ─────────────────────────────────────────────────────────────────────────
 *
 * The type list was kept in two places that had no link to each other:
 *
 *   `SUPPORTED_DOCUMENT_TYPES` (document-write-path)  = markdown, text, plaintext
 *   `DIFFABLE_DOCUMENT_TYPES`  (document-notify)      = markdown, text, json
 *
 * They had already drifted. **`plaintext` was admitted and could not be diffed** — an operator could
 * propose a `plaintext` document, have it accepted, edit it with a peer, and get *"this build renders
 * diffs for markdown, text, json"* from `cello_doc_diff`. The verb that says what changed was dead
 * on a type the product offered them.
 *
 * Neither list was wrong by itself; the defect was that there were two, so adding a type meant
 * remembering a second file. With three more types queued that is a step that gets forgotten, so the
 * properties became COLUMNS on one row and every list is derived.
 *
 * This module deliberately imports nothing. Both `document-write-path` and `document-notify` read
 * it, and a registry that pulled in either of them would be a cycle.
 */

/** Which Yjs root a type's content lives in. `text` merges by line; `map` merges per key. */
export type DocumentRoot = "text" | "map";

export interface DocumentTypeRow {
  /** The root the content projects from — this decides which merge strategy applies. */
  readonly root: DocumentRoot;
  /** The file extension it materializes as. The file IS the editing surface, so this is load-bearing. */
  readonly extension: string;
  /**
   * Whether `propose`/`accept` may admit it.
   *
   * `json` is present and NOT admitted: the write path serves it (map root) while read/write/diff
   * assume the text root, so it reads as empty, writes into a root nothing projects, and diffs as
   * unchanged forever. A type only some verbs can serve is worse than an absent one — it reads as
   * done and loses content in silence. The flag flips when the map path lands.
   */
  readonly admitted: boolean;
  /**
   * Opening this file runs its contents.
   *
   * True for `html`: double-clicking a document a peer co-authored executes their script with a
   * `file://` origin. It is NOT a reason to refuse the type or to strip tags — `<script>` is
   * legitimate content in an HTML document, and refusing it is the "a document about prompt formats
   * loses its subject" mistake from the screening audit. It is a reason to tell the operator plainly
   * at the moment they are handed the path, which is generated from this flag rather than from an
   * `if (type === "html")` the next executable type would not match.
   */
  readonly executableWhenOpened?: boolean;
}

const TEXT: DocumentTypeRow = { root: "text", extension: "txt", admitted: true };

/**
 * Every document type this build knows.
 *
 * `plaintext` and `text` share ONE row object by identity, not two equal rows — an alias cannot
 * drift from what it aliases if there is nothing to drift from.
 */
export const DOCUMENT_TYPES: ReadonlyMap<string, DocumentTypeRow> = new Map<string, DocumentTypeRow>([
  ["markdown", { root: "text", extension: "md", admitted: true }],
  ["text", TEXT],
  ["plaintext", TEXT],
  ["html", { root: "text", extension: "html", admitted: true, executableWhenOpened: true }],
  ["json", { root: "map", extension: "json", admitted: false }],
]);

/** The row for a type, or `undefined` for one this build does not know. */
export function documentTypeRow(documentType: string): DocumentTypeRow | undefined {
  return DOCUMENT_TYPES.get(documentType);
}

/**
 * The extension for a type, or `undefined` for an unknown one.
 *
 * Undefined rather than a default: a type nothing can serve must not be handed a plausible-looking
 * path. The silent `: "md"` default is what let `yaml` create a real signed peer-accepted document
 * with no file and no explanation.
 */
export function extensionForDocumentType(documentType: string): string | undefined {
  return DOCUMENT_TYPES.get(documentType)?.extension;
}

/** Whether `propose`/`accept` may admit this type. */
export function isSupportedDocumentType(documentType: string): boolean {
  return DOCUMENT_TYPES.get(documentType)?.admitted === true;
}

/** The admitted types, sorted — the set a refusal message names. */
export function admittedDocumentTypes(): readonly string[] {
  return [...DOCUMENT_TYPES.entries()].filter(([, row]) => row.admitted).map(([name]) => name).sort();
}

/**
 * The types `cello_doc_diff` can render.
 *
 * EVERY known type is diffable — a text root diffs by line and a map root by key, and there is no
 * third case. It is derived rather than listed because the listed version is what drifted out of
 * agreement with the admitted set and killed `plaintext`'s diff.
 */
export function diffableDocumentTypes(): readonly string[] {
  return [...DOCUMENT_TYPES.keys()].sort();
}

/**
 * What the operator is told when handed the path to a document whose file RUNS when opened.
 *
 * Returns `undefined` for every other type on purpose: a notice attached to every document is a
 * notice on none. Keyed on the row's flag rather than on the type name, so the next executable type
 * inherits it by setting the flag instead of by being remembered here.
 *
 * The wording states the consequence rather than the mechanism, because that is what an operator
 * decides from.
 */
export function openingNoticeFor(documentType: string): string | undefined {
  if (DOCUMENT_TYPES.get(documentType)?.executableWhenOpened !== true) return undefined;
  return (
    "This document is an .html file, and your peer can edit it. Opening it in a browser RUNS " +
    "whatever is in it, including anything they wrote — with access to your local files. Read it " +
    "with cello_doc_read, or open it in an editor, rather than double-clicking it."
  );
}

/** The Yjs root a type's content lives in, or `undefined` for an unknown type. */
export function rootForDocumentType(documentType: string): DocumentRoot | undefined {
  return DOCUMENT_TYPES.get(documentType)?.root;
}
