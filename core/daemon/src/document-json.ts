/**
 * DOD-DOC-TYPES-1 — rendering a JSON document to the bytes both sides must agree on.
 *
 * ── THE PROBLEM THIS SOLVES ──────────────────────────────────────────────────────────────────────
 *
 * The CRDT determines the map STATE. It does not determine the STRING that map is printed as.
 * `Y.Map.toJSON()` returns keys in INSERTION order, so two peers who added the same keys in a
 * different order hold the same document and render different files:
 *
 *   Alice adds `owner` then `status`  →  {"owner": "a", "status": "open"}
 *   Bob   adds `status` then `owner`  →  {"status": "open", "owner": "a"}
 *
 * Both faithful, both correct, and everything downstream breaks. The write path diffs the FILE
 * against the recorded projection, so a re-serialization in a different order reads as a rewrite of
 * the entire document and is PUBLISHED to the peer as a real, signed edit. Two machines comparing
 * files disagree about a document they agree on. And pasting the rendered document to have a peer
 * confirm they hold the same thing — which is how values get attested — stops working.
 *
 * ── THE RULE ─────────────────────────────────────────────────────────────────────────────────────
 *
 * Object keys sorted, recursively, at every depth. **Arrays are never sorted:** an array's order is
 * content, and reordering a list of steps or a ranked set of options is a lie about what was agreed.
 *
 * Trailing newline, because most editors add one on save and its absence would make the first save
 * of an untouched file publish an edit nobody made.
 */

/** A value that can live in a JSON document. */
import { rootForDocumentType } from "./document-types.js";

export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

/**
 * Return `value` with every object's keys in sorted order, at every depth.
 *
 * Arrays keep their order; only the objects INSIDE them are normalised. `JSON.stringify` walks
 * objects in own-property order, so sorting the keys into a fresh object is what makes its output
 * deterministic — there is no stringify option that does this.
 */
function withSortedKeys(value: JsonValue): JsonValue {
  if (Array.isArray(value)) return value.map(withSortedKeys);
  if (value === null || typeof value !== "object") return value;
  const sorted: { [key: string]: JsonValue } = {};
  for (const key of Object.keys(value).sort()) sorted[key] = withSortedKeys(value[key]!);
  return sorted;
}

/**
 * The canonical text of a JSON document — the bytes written to the file, recorded as the diff
 * baseline, and compared against a peer's.
 *
 * Indented rather than compact: a human and an agent both have to read this file, and a line diff
 * needs nested values on their own lines to say anything useful about what changed.
 */
export function serializeJsonDocument(value: JsonValue): string {
  return `${JSON.stringify(withSortedKeys(value), null, 2)}\n`;
}

/** A parsed JSON object, or the reason it could not be parsed. */
export type ParsedJsonDocument =
  | { ok: true; value: { [key: string]: JsonValue } }
  | { ok: false; detail: string };

/**
 * Parse the text an agent supplied as a whole JSON document.
 *
 * A non-object top level is refused as firmly as a syntax error: the map root holds KEYS, so a bare
 * array or string has nowhere to go, and accepting one would silently empty the document.
 */
export function parseJsonDocument(text: string): ParsedJsonDocument {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err: unknown) {
    return { ok: false, detail: err instanceof Error ? err.message : String(err) };
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, detail: "the top level of a JSON document must be an object" };
  }
  return { ok: true, value: parsed as { [key: string]: JsonValue } };
}

/**
 * The minimal set of key operations that turns `current` into `next`, as `[key, value]` pairs where
 * a `value` of `undefined` means delete.
 *
 * **This is the per-key merge, and it is the whole point of the map root.** Two agents editing
 * different fields of a shared plan produce disjoint key sets, so both survive; a line merge of the
 * serialized form would have them rewriting the same lines and interleaving into broken JSON.
 *
 * Values are compared on their CANONICAL rendering. Plain `JSON.stringify` is order-sensitive for a
 * nested object, so re-ordering a nested block — which any formatter may do — would count as a
 * changed value, publish a change nobody made, and beat the peer's real edit to that key.
 *
 * Untouched keys are not written at all. Writing a key back with an identical value is still a CRDT
 * operation, and it would clobber a peer's concurrent edit to a field this agent never looked at.
 */
export function jsonKeyOperations(
  current: ReadonlyMap<string, unknown> | { get(key: string): unknown; keys(): Iterable<string> },
  next: { [key: string]: JsonValue },
): Array<[string, JsonValue | undefined]> {
  const ops: Array<[string, JsonValue | undefined]> = [];
  for (const [key, value] of Object.entries(next)) {
    const before = current.get(key);
    if (
      before === undefined ||
      serializeJsonDocument(before as JsonValue) !== serializeJsonDocument(value)
    ) {
      ops.push([key, value]);
    }
  }
  for (const key of [...current.keys()]) {
    if (!(key in next)) ops.push([key, undefined]);
  }
  return ops;
}

/**
 * The document's content as the text an agent reads and writes back — whichever root it lives in.
 *
 * The three content verbs (`read`, `write`, `diff`) all called `doc.getText("content")` directly,
 * which is why `json` had to be refused at the door: its content is in the MAP root, so those verbs
 * saw an empty document and would have written that emptiness back over the peer's real content.
 *
 * Imported by both the handlers and the write path so one document has ONE textual form. Two
 * renderings of the same map would make the file diff fight the tool surface.
 */
export function projectDocumentText(doc: YDocLike, documentType: string): string {
  if (rootForDocumentType(documentType) === "map") {
    return serializeJsonDocument(doc.getMap(MAP_ROOT).toJSON() as JsonValue);
  }
  return doc.getText(TEXT_ROOT).toString();
}

/** Yjs roots a document projects from — must match `DocumentEngine`'s. */
const TEXT_ROOT = "content";
const MAP_ROOT = "data";

/** The slice of `Y.Doc` this module needs, so it does not depend on the engine. */
interface YDocLike {
  getMap(name: string): { toJSON(): unknown };
  getText(name: string): { toString(): string };
}
