/**
 * DOD-DOC-TYPES-1, unit 4b — a JSON document's file, diff and per-key merge.
 *
 * ── WHAT A JSON DOCUMENT IS FOR ──────────────────────────────────────────────────────────────────
 *
 * Andre: *"structured data is super important — the whole use case of working on shared goals
 * depends on JSON."* Two agents holding a shared plan need to edit DIFFERENT FIELDS of it at the
 * same time and both survive. That is the per-key merge, and it is the whole reason a JSON document
 * uses the map root instead of being markdown that happens to contain braces.
 *
 * ── THE TWO WAYS THIS SILENTLY DESTROYS WORK ─────────────────────────────────────────────────────
 *
 * **1. Line-merging serialized JSON.** Two agents each set a different key. On a text root their
 * edits are two overlapping rewrites of the same lines and the CRDT interleaves them into
 * syntactically broken JSON, or one silently wins. On the map root they are edits to different keys
 * and both hold.
 *
 * **2. Non-deterministic rendering.** `Y.Map.toJSON()` is in INSERTION order, so re-rendering after
 * a peer's key arrives can reorder the whole file. The write path diffs the FILE against the
 * recorded projection, so that reordering is read as a rewrite of every line and PUBLISHED as a real
 * signed edit. The document then flip-flops between two orderings forever, each side publishing the
 * other's file back at them.
 *
 * The second is the one that looks like nothing is wrong until a document is unusable.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import * as Y from "yjs";
import { DocumentEngine } from "../document-engine.js";
import { DocumentWritePath } from "../document-write-path.js";
import { applyJsonToMap } from "../document-json.js";

const NOOP_LOGGER = { debug() {}, info() {}, warn() {}, error() {} } as never;
const AGENT = "aa".repeat(32);
const DOC = "cc".repeat(32);

let workspace: string;
beforeEach(async () => {
  workspace = await mkdtemp(join(tmpdir(), "cello-doc-json-"));
});
afterEach(async () => {
  await rm(workspace, { recursive: true, force: true });
});

function newWritePath(): DocumentWritePath {
  return new DocumentWritePath(new DocumentEngine(NOOP_LOGGER), workspace, NOOP_LOGGER);
}

/**
 * A doc whose map root holds `entries`, inserted in the given order — built the way the CODE builds
 * one, so nested objects become nested maps.
 *
 * It used to call `map.set(key, plainObject)` directly, which is the pre-nesting shape. Left that
 * way it silently made every case here a LEGACY-document case, and the re-order test below started
 * failing for the conversion rather than for the property it is about.
 */
function docWith(entries: Array<[string, unknown]>, clientId = 1): Y.Doc {
  const doc = new Y.Doc();
  doc.clientID = clientId;
  const obj: Record<string, unknown> = {};
  for (const [k, v] of entries) obj[k] = v;
  applyJsonToMap(doc.getMap("data"), obj as never, doc);
  return doc;
}

/** The pre-nesting shape: nested objects stored as opaque plain values. */
function legacyDocWith(entries: Array<[string, unknown]>, clientId = 1): Y.Doc {
  const doc = new Y.Doc();
  doc.clientID = clientId;
  const map = doc.getMap("data");
  doc.transact(() => {
    for (const [k, v] of entries) map.set(k, v);
  });
  return doc;
}

describe("the file a JSON document materializes to", () => {
  it("is written at .json and parses", async () => {
    const wp = newWritePath();
    const path = await wp.materialize(AGENT, DOC, "json", docWith([["status", "open"]]));
    expect(path.endsWith(".json")).toBe(true);
    expect(JSON.parse(await readFile(path, "utf8"))).toEqual({ status: "open" });
  });

  it("renders the SAME bytes whatever order the keys were inserted in", async () => {
    // The defect that makes a shared JSON document flip-flop forever. Two peers converge on one map
    // and must converge on one FILE, or each publishes the other's rendering back at them.
    const wp = newWritePath();
    const forward = await readFile(
      await wp.materialize(AGENT, DOC, "json", docWith([["owner", "a"], ["status", "open"]])),
      "utf8",
    );
    const reverse = await readFile(
      await wp.materialize(AGENT, DOC, "json", docWith([["status", "open"], ["owner", "a"]])),
      "utf8",
    );
    expect(reverse).toBe(forward);
  });

  it("a re-materialize after a peer's key arrives does not publish a phantom rewrite", async () => {
    // The end-to-end form of the same bug: materialize, let a peer's key land, materialize again,
    // and publish. Nothing the agent did changed, so there must be nothing to publish.
    const wp = newWritePath();
    const doc = docWith([["owner", "a"], ["status", "open"]]);
    await wp.materialize(AGENT, DOC, "json", doc);

    // A peer sets a key that sorts FIRST — the case that reorders the whole file.
    const peer = new Y.Doc();
    peer.clientID = 2;
    wp.engine.applyUpdate(peer, wp.engine.encodeState(doc));
    peer.getMap("data").set("assignee", "b");
    wp.engine.applyUpdate(doc, wp.engine.encodeState(peer));

    await wp.materialize(AGENT, DOC, "json", doc);
    const update = await wp.publish(AGENT, DOC, "json", doc);
    expect(update, "a re-render published an edit the agent never made").toBeNull();
  });
});

describe("two agents editing different keys both survive", () => {
  it("a local edit to one key does not disturb the peer's edit to another", async () => {
    const wp = newWritePath();
    const doc = docWith([["status", "open"]]);
    const path = await wp.materialize(AGENT, DOC, "json", doc);

    // The peer sets `owner` while the agent edits the FILE to set `status`.
    const peer = new Y.Doc();
    peer.clientID = 2;
    wp.engine.applyUpdate(peer, wp.engine.encodeState(doc));
    peer.getMap("data").set("owner", "bob");

    await writeFile(path, JSON.stringify({ status: "done" }, null, 2) + "\n", "utf8");
    await wp.publish(AGENT, DOC, "json", doc);
    wp.engine.applyUpdate(doc, wp.engine.encodeState(peer));

    const merged = doc.getMap("data").toJSON();
    expect(merged.status, "the agent's edit was lost").toBe("done");
    expect(merged.owner, "the peer's key was lost").toBe("bob");
  });

  it("a key removed from the file is removed from the document", async () => {
    const wp = newWritePath();
    const doc = docWith([["a", 1], ["b", 2]]);
    const path = await wp.materialize(AGENT, DOC, "json", doc);
    await writeFile(path, JSON.stringify({ a: 1 }, null, 2) + "\n", "utf8");

    expect(await wp.publish(AGENT, DOC, "json", doc)).not.toBeNull();
    expect(doc.getMap("data").toJSON()).toEqual({ a: 1 });
  });

  it("reordering a NESTED object's keys in the file publishes nothing", async () => {
    // The comparison that decides "did this key change" was `JSON.stringify(old) !== stringify(new)`,
    // which is order-sensitive for nested objects — so an agent (or a formatter) that rewrote a
    // nested block with the same content in a different order published a change to a value nobody
    // touched, and the peer's concurrent edit to that key would lose to it.
    const wp = newWritePath();
    const doc = docWith([["cfg", { z: 1, a: 2 }]]);
    const path = await wp.materialize(AGENT, DOC, "json", doc);
    await writeFile(path, JSON.stringify({ cfg: { a: 2, z: 1 } }, null, 2) + "\n", "utf8");

    expect(await wp.publish(AGENT, DOC, "json", doc), "a re-ordered nested object published as a real edit").toBeNull();
  });
});

describe("a file that is not valid JSON is refused, not guessed at", () => {
  it("refuses rather than publishing a truncated document", async () => {
    const wp = newWritePath();
    const doc = docWith([["a", 1]]);
    const path = await wp.materialize(AGENT, DOC, "json", doc);
    await writeFile(path, '{ "a": 1', "utf8");

    await expect(wp.publish(AGENT, DOC, "json", doc)).rejects.toThrow(/document_file_unparseable/);
    // And the document is untouched — a half-parsed file must not partially apply.
    expect(doc.getMap("data").toJSON()).toEqual({ a: 1 });
  });
});

describe("a document created before nested merge existed converts on first write", () => {
  it("converts ONCE, publishing a representation change, then goes quiet", async () => {
    // The migration, such as it is: nothing walks the store. A legacy document holding plain nested
    // objects converts the first time a write touches the key, and is normal thereafter.
    //
    // That first publish carries a structural change with NO content change — the peer applies it
    // and renders exactly what they rendered before. Worth pinning that it happens once rather than
    // on every publish, which would be a signed no-op edit forever.
    const wp = newWritePath();
    const doc = legacyDocWith([["cfg", { a: 1, b: 2 }]]);
    const path = await wp.materialize(AGENT, DOC, "json", doc);

    // Same content, re-written — this is the conversion, not an edit.
    const first = await wp.publish(AGENT, DOC, "json", doc);
    expect(first, "the legacy blob was never converted").not.toBeNull();
    expect(doc.getMap("data").toJSON()).toEqual({ cfg: { a: 1, b: 2 } });

    // And now it is quiet: an unchanged publish says nothing.
    await wp.materialize(AGENT, DOC, "json", doc);
    expect(await wp.publish(AGENT, DOC, "json", doc), "it converts on every publish").toBeNull();
    void path;
  });
});
