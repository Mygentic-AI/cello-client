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
 * Apply `next` to `map` as the MINIMAL set of key operations, recursing into nested objects.
 *
 * **This is the per-key merge, and depth is the whole point of it.** Two actors editing two
 * different fields of a shared record must both survive. Storing a nested object as a plain value
 * makes it ONE item, so two writes to two fields inside it are two writes to the same item and last
 * writer wins — measured on the reference workflow: one actor raising `settlement_failed` and
 * another clearing `insufficient_funds` in the same minute ended with the raise gone from both
 * machines, silently.
 *
 * That was dangerous rather than merely limited, because `jsonDiff` reports full dotted paths. Every
 * surface said the structure was understood at path granularity, so a schema nests precisely where
 * several actors write — and afterwards the diff names the field that vanished.
 *
 * **Untouched keys are not written at all**, at any depth. Writing a key back with an identical
 * value is still a CRDT operation and would clobber a peer's concurrent edit to a field this author
 * never looked at. A nested object that already exists is REUSED rather than replaced, for the same
 * reason — replacing it is exactly the bug.
 *
 * **Arrays are stored whole, deliberately.** Element-level merge of two concurrent array edits
 * interleaves into an order neither party wrote, and an array's order is content: a ranked list, a
 * sequence of steps. Last-writer-wins on a whole array beats a silently reordered one. The
 * consequence, recorded rather than hidden: a JOURNAL must not be an array, because two concurrent
 * appends lose one. Key it as a map and this function carries it at any depth.
 *
 * Values are compared on their CANONICAL rendering. Plain `JSON.stringify` is order-sensitive for a
 * nested object, so re-ordering a nested block — which any formatter may do — would count as a
 * changed value, publish a change nobody made, and beat a peer's real edit to that key.
 *
 * Returns the dotted paths actually written, for the overlap flag.
 */
export function applyJsonToMap(
  map: YMapLike,
  next: { [key: string]: JsonValue },
  doc: { transact(fn: () => void): void },
  prefix = "",
): string[] {
  const written: string[] = [];
  const apply = () => {
    for (const [key, value] of Object.entries(next)) {
      const path = prefix === "" ? key : `${prefix}.${key}`;
      const before = map.get(key);
      const nestable = isPlainObject(value);

      if (nestable && isYMap(before)) {
        // RECURSE into the existing nested map. Never replace it — replacing is what destroys a
        // peer's concurrent edit to a sibling key.
        written.push(...applyJsonToMap(before, value as { [k: string]: JsonValue }, doc, path));
        continue;
      }
      if (nestable) {
        // Either absent, or a legacy PLAIN object written before nesting existed. Both become a
        // nested map here; that is the whole migration, and it happens on first touch.
        const child = newYMap(map);
        map.set(key, child);
        written.push(...applyJsonToMap(child, value as { [k: string]: JsonValue }, doc, path));
        continue;
      }
      if (before === undefined || serializeJsonDocument(toJson(before)) !== serializeJsonDocument(value)) {
        map.set(key, value);
        written.push(path);
      }
    }
    for (const key of [...map.keys()]) {
      if (!(key in next)) {
        map.delete(key);
        written.push(prefix === "" ? key : `${prefix}.${key}`);
      }
    }
  };
  // One transaction for the whole tree, so the edit is a single update rather than one per depth.
  if (prefix === "") doc.transact(apply);
  else apply();
  return written;
}

/** A `Y.Map`-shaped thing, kept structural so this module does not import the engine. */
export interface YMapLike {
  get(key: string): unknown;
  set(key: string, value: unknown): unknown;
  delete(key: string): void;
  keys(): Iterable<string>;
  toJSON(): unknown;
}

function isPlainObject(v: unknown): v is { [k: string]: JsonValue } {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** True for a Yjs map. Detected by shape — `toJSON` plus `keys` plus `delete`. */
function isYMap(v: unknown): v is YMapLike {
  return (
    v !== null &&
    typeof v === "object" &&
    typeof (v as YMapLike).get === "function" &&
    typeof (v as YMapLike).keys === "function" &&
    typeof (v as YMapLike).toJSON === "function"
  );
}

/** A stored value as plain JSON, whether it is a nested map or an ordinary value. */
function toJson(v: unknown): JsonValue {
  return (isYMap(v) ? v.toJSON() : v) as JsonValue;
}

/**
 * A new nested map of the SAME class as its parent.
 *
 * Constructed from the parent's own constructor rather than importing `yjs` here, so this module
 * stays free of the engine and the write path keeps one source of the Yjs dependency.
 */
function newYMap(sibling: YMapLike): YMapLike {
  const Ctor = (sibling as unknown as { constructor: new () => YMapLike }).constructor;
  return new Ctor();
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
