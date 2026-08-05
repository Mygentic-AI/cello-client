/**
 * DOD-DOC-WRITE-1 — the write path (§16.2).
 *
 * The document is a REAL FILE. The agent edits it with ordinary tools and the human can open the
 * same file; the daemon diffs it at publish and turns the diff into Yjs operations. No new
 * editing surface exists — that is the point, and it is why these tests write to disk rather than
 * calling an API to "set content".
 *
 * The property that is easy to lose: on admission the daemon folds the agent's UNPUBLISHED file
 * edits into the doc first, THEN merges the incoming update, THEN rewrites the file. Get that
 * order wrong and the agent's unpublished work is silently clobbered — and §4.1's overlap flag,
 * which falls out of the fold, disappears with it.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { DocumentEngine } from "../document-engine.js";
import { DocumentWritePath } from "../document-write-path.js";

const NOOP_LOGGER = { debug() {}, info() {}, warn() {}, error() {} } as never;
const AGENT = "aa".repeat(32);
const DOC = "cc".repeat(32);

let workspace: string;

beforeEach(async () => {
  workspace = await mkdtemp(join(tmpdir(), "cello-write-path-"));
});
afterEach(async () => {
  await rm(workspace, { recursive: true, force: true });
});

function newWritePath(): DocumentWritePath {
  return new DocumentWritePath(new DocumentEngine(NOOP_LOGGER), workspace, NOOP_LOGGER);
}

describe("DocumentWritePath — the document is a real file", () => {
  it("materializes a document into a per-agent workspace path keyed on the stable id", async () => {
    const wp = newWritePath();
    const doc = wp.engine.createDocument("initial content");
    const path = await wp.materialize(AGENT, DOC, "markdown", doc);

    expect(path).toContain(AGENT.slice(0, 16));
    expect(path).toContain(DOC.slice(0, 16));
    expect(await readFile(path, "utf8")).toBe("initial content");
  });

  it("an agent's ordinary file edit becomes Yjs operations at publish", async () => {
    const wp = newWritePath();
    const doc = wp.engine.createDocument("hello world");
    const path = await wp.materialize(AGENT, DOC, "markdown", doc);

    // The agent edits with its ordinary tools — no CELLO API involved.
    await writeFile(path, "hello brave new world", "utf8");

    const update = await wp.publish(AGENT, DOC, doc);
    expect(update).not.toBeNull();
    expect(wp.engine.readTextRoot(doc)).toBe("hello brave new world");
  });

  it("publish with no file change produces NO update — publish is intent, not a heartbeat", async () => {
    const wp = newWritePath();
    const doc = wp.engine.createDocument("unchanged");
    await wp.materialize(AGENT, DOC, "markdown", doc);
    expect(await wp.publish(AGENT, DOC, doc)).toBeNull();
  });

  it("round-trip: edit → publish → apply on a second doc → materialize → identical content", async () => {
    const wp = newWritePath();
    const mine = wp.engine.createDocument("shared start");
    const path = await wp.materialize(AGENT, DOC, "markdown", mine);

    await writeFile(path, "shared start, then my edit", "utf8");
    const update = await wp.publish(AGENT, DOC, mine);
    expect(update).not.toBeNull();

    // The peer's side: a fresh doc that has seen the same base, then the update.
    const theirs = wp.engine.createDocument("");
    wp.engine.applyUpdate(theirs, wp.engine.encodeState(mine));

    const theirPath = await wp.materialize("bb".repeat(32), DOC, "markdown", theirs);
    expect(await readFile(theirPath, "utf8")).toBe("shared start, then my edit");
  });
});

describe("DocumentWritePath — admission folds local edits FIRST (§16.2)", () => {
  it("an unpublished local edit SURVIVES an incoming update that does not touch it", async () => {
    const wp = newWritePath();
    const mine = wp.engine.createDocument("alpha\nbeta\ngamma");
    const path = await wp.materialize(AGENT, DOC, "markdown", mine);

    // A peer changes the FIRST line, in their own copy.
    const peer = wp.engine.createDocument("");
    wp.engine.applyUpdate(peer, wp.engine.encodeState(mine));
    peer.getText("content").delete(0, 5);
    peer.getText("content").insert(0, "ALPHA");
    const incoming = wp.engine.encodeState(peer, wp.engine.encodeStateVector(mine));

    // Meanwhile the agent edits the LAST line on disk and has not published.
    await writeFile(path, "alpha\nbeta\nGAMMA-EDITED", "utf8");

    const res = await wp.admit(AGENT, DOC, mine, incoming);
    const onDisk = await readFile(path, "utf8");

    // Both survive: the fold happens before the merge, so the local edit is a real operation
    // rather than a file that gets overwritten.
    expect(onDisk).toContain("ALPHA");
    expect(onDisk).toContain("GAMMA-EDITED");
    expect(res.overlap).toBe(false);
  });

  it("the overlap flag is TRUE when the merge touches a region holding unpublished edits", async () => {
    const wp = newWritePath();
    const mine = wp.engine.createDocument("the quick brown fox");
    const path = await wp.materialize(AGENT, DOC, "markdown", mine);

    // Peer rewrites the middle.
    const peer = wp.engine.createDocument("");
    wp.engine.applyUpdate(peer, wp.engine.encodeState(mine));
    peer.getText("content").delete(4, 5); // "quick"
    peer.getText("content").insert(4, "SLOW!");
    const incoming = wp.engine.encodeState(peer, wp.engine.encodeStateVector(mine));

    // The agent edits the SAME region on disk, unpublished.
    await writeFile(path, "the RAPID brown fox", "utf8");

    const res = await wp.admit(AGENT, DOC, mine, incoming);
    expect(res.overlap).toBe(true);
  });

  it("no unpublished edits means no overlap, however large the incoming change", async () => {
    const wp = newWritePath();
    const mine = wp.engine.createDocument("original text here");
    await wp.materialize(AGENT, DOC, "markdown", mine);

    const peer = wp.engine.createDocument("");
    wp.engine.applyUpdate(peer, wp.engine.encodeState(mine));
    peer.getText("content").delete(0, 18);
    peer.getText("content").insert(0, "completely different");
    const incoming = wp.engine.encodeState(peer, wp.engine.encodeStateVector(mine));

    const res = await wp.admit(AGENT, DOC, mine, incoming);
    expect(res.overlap).toBe(false);
  });

  it("admission REWRITES the file so the agent sees the merged projection", async () => {
    const wp = newWritePath();
    const mine = wp.engine.createDocument("base");
    const path = await wp.materialize(AGENT, DOC, "markdown", mine);

    const peer = wp.engine.createDocument("");
    wp.engine.applyUpdate(peer, wp.engine.encodeState(mine));
    peer.getText("content").insert(4, " plus theirs");
    const incoming = wp.engine.encodeState(peer, wp.engine.encodeStateVector(mine));

    await wp.admit(AGENT, DOC, mine, incoming);
    expect(await readFile(path, "utf8")).toBe("base plus theirs");
  });

  it("concurrent edits on both sides CONVERGE", async () => {
    const wp = newWritePath();
    const mine = wp.engine.createDocument("start");
    const path = await wp.materialize(AGENT, DOC, "markdown", mine);

    const peer = wp.engine.createDocument("");
    wp.engine.applyUpdate(peer, wp.engine.encodeState(mine));

    // Both edit concurrently: I on disk (unpublished), they in their doc.
    await writeFile(path, "start MINE", "utf8");
    peer.getText("content").insert(0, "THEIRS ");
    const incoming = wp.engine.encodeState(peer, wp.engine.encodeStateVector(mine));

    await wp.admit(AGENT, DOC, mine, incoming);
    const myUpdate = wp.engine.encodeState(mine, wp.engine.encodeStateVector(peer));
    wp.engine.applyUpdate(peer, myUpdate);

    // Both sides hold the same text — the CRDT property, through the file path.
    expect(wp.engine.readTextRoot(peer)).toBe(wp.engine.readTextRoot(mine));
    expect(wp.engine.readTextRoot(mine)).toContain("MINE");
    expect(wp.engine.readTextRoot(mine)).toContain("THEIRS");
  });
});

describe("DocumentWritePath — JSON documents diff by key (§16.2)", () => {
  it("a changed key becomes an operation; untouched keys are not rewritten", async () => {
    const wp = newWritePath();
    const doc = wp.engine.createDocument("");
    doc.getMap("data").set("kept", "same");
    doc.getMap("data").set("changed", "before");

    const path = await wp.materialize(AGENT, DOC, "json", doc);
    expect(JSON.parse(await readFile(path, "utf8"))).toEqual({ kept: "same", changed: "before" });

    await writeFile(path, JSON.stringify({ kept: "same", changed: "after" }, null, 2), "utf8");
    const update = await wp.publish(AGENT, DOC, doc);

    expect(update).not.toBeNull();
    expect(doc.getMap("data").get("changed")).toBe("after");
    expect(doc.getMap("data").get("kept")).toBe("same");
  });

  it("a removed key is removed from the map, not left stale", async () => {
    const wp = newWritePath();
    const doc = wp.engine.createDocument("");
    doc.getMap("data").set("a", 1);
    doc.getMap("data").set("b", 2);
    const path = await wp.materialize(AGENT, DOC, "json", doc);

    await writeFile(path, JSON.stringify({ a: 1 }), "utf8");
    await wp.publish(AGENT, DOC, doc);

    expect(doc.getMap("data").has("b")).toBe(false);
    expect(doc.getMap("data").get("a")).toBe(1);
  });

  it("malformed JSON on disk REFUSES the publish — it never half-applies", async () => {
    const wp = newWritePath();
    const doc = wp.engine.createDocument("");
    doc.getMap("data").set("intact", "yes");
    const path = await wp.materialize(AGENT, DOC, "json", doc);

    await writeFile(path, "{ this is not json", "utf8");
    await expect(wp.publish(AGENT, DOC, doc)).rejects.toThrow(/document_file_unparseable/);
    // The document is untouched — a broken file does not corrupt the CRDT.
    expect(doc.getMap("data").get("intact")).toBe("yes");
  });
});

describe("DocumentWritePath — refusals name their cause", () => {
  it("publishing a document that was never materialized REFUSES, naming what is missing", async () => {
    const wp = newWritePath();
    const doc = wp.engine.createDocument("x");
    await expect(wp.publish(AGENT, DOC, doc)).rejects.toThrow(/document_file_missing/);
  });

  it("a document type with no diff strategy REFUSES rather than silently doing nothing", async () => {
    const wp = newWritePath();
    const doc = wp.engine.createDocument("x");
    await expect(wp.materialize(AGENT, DOC, "xml", doc)).rejects.toThrow(/document_type_unsupported/);
  });

  it("the workspace directory is created on demand", async () => {
    const nested = join(workspace, "does", "not", "exist");
    await mkdir(workspace, { recursive: true });
    const wp = new DocumentWritePath(new DocumentEngine(NOOP_LOGGER), nested, NOOP_LOGGER);
    const doc = wp.engine.createDocument("content");
    const path = await wp.materialize(AGENT, DOC, "markdown", doc);
    expect(await readFile(path, "utf8")).toBe("content");
  });
});
