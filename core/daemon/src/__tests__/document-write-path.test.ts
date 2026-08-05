/**
 * DOD-DOC-WRITE-1 — the write path (§16.2).
 *
 * The document is a REAL FILE: these tests write to disk rather than calling an API to set
 * content, because "no new editing surface exists" is the design.
 *
 * DETERMINISM NOTE. Yjs breaks ties between concurrent operations by clientID, which is RANDOM —
 * so any test involving a concurrent peer edit is a coin flip unless the clientIDs are pinned.
 * The first version of this suite was: its overlap assertion held against the BROKEN comparison
 * 17 runs in 40. Every concurrent case below pins both clientIDs and exercises BOTH orderings,
 * so a property with one right answer is tested for one answer.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile, writeFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import * as Y from "yjs";
import { DocumentEngine } from "../document-engine.js";
import { DocumentWritePath, DocumentWriteError, lineHunks } from "../document-write-path.js";

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

/** A peer doc seeded from `mine`, with a PINNED clientID so tie-breaks are deterministic. */
function peerOf(wp: DocumentWritePath, mine: Y.Doc, clientId: number): Y.Doc {
  const peer = new Y.Doc();
  peer.clientID = clientId;
  wp.engine.applyUpdate(peer, wp.engine.encodeState(mine));
  return peer;
}

describe("DocumentWritePath — the document is a real file", () => {
  it("materializes into a per-agent path keyed on the FULL stable ids", async () => {
    const wp = newWritePath();
    const doc = wp.engine.createDocument("initial content");
    const path = await wp.materialize(AGENT, DOC, "markdown", doc);

    expect(path).toContain(AGENT); // full id, not a prefix — two documents sharing 16 hex
    expect(path).toContain(DOC);   // characters would otherwise collide onto one file
    expect(await readFile(path, "utf8")).toBe("initial content");
  });

  it("REFUSES an id that is not 64 hex characters — it becomes a path component", () => {
    const wp = newWritePath();
    expect(() => wp.filePath("../../../../etc", DOC, "markdown")).toThrow(DocumentWriteError);
    expect(() => wp.filePath(AGENT, "../../etc/passwd", "markdown")).toThrow(/document_id_invalid/);
  });

  it("an ordinary file edit becomes Yjs operations at publish", async () => {
    const wp = newWritePath();
    const doc = wp.engine.createDocument("hello world");
    const path = await wp.materialize(AGENT, DOC, "markdown", doc);
    await writeFile(path, "hello brave new world", "utf8");

    expect(await wp.publish(AGENT, DOC, "markdown", doc)).not.toBeNull();
    expect(wp.engine.readTextRoot(doc)).toBe("hello brave new world");
  });

  it("publish with no file change produces NO update — publish is intent, not a heartbeat", async () => {
    const wp = newWritePath();
    const doc = wp.engine.createDocument("unchanged");
    await wp.materialize(AGENT, DOC, "markdown", doc);
    expect(await wp.publish(AGENT, DOC, "markdown", doc)).toBeNull();
  });

  it("round-trip: edit → publish → apply on a second doc → materialize → identical content", async () => {
    const wp = newWritePath();
    const mine = wp.engine.createDocument("shared start");
    const path = await wp.materialize(AGENT, DOC, "markdown", mine);
    await writeFile(path, "shared start, then my edit", "utf8");
    expect(await wp.publish(AGENT, DOC, "markdown", mine)).not.toBeNull();

    const theirs = wp.engine.createDocument("");
    wp.engine.applyUpdate(theirs, wp.engine.encodeState(mine));
    const theirPath = await wp.materialize("bb".repeat(32), DOC, "markdown", theirs);
    expect(await readFile(theirPath, "utf8")).toBe("shared start, then my edit");
  });
});

describe("DocumentWritePath — publish diffs the LAST-KNOWN PROJECTION (§16.2)", () => {
  it("REFUSES a stale file rather than publishing the peer's content as an agent deletion", async () => {
    const wp = newWritePath();
    const mine = wp.engine.createDocument("shared base");
    await wp.materialize(AGENT, DOC, "markdown", mine);

    // A peer's paragraph is merged into the DOC, but the file rewrite never completes — the crash
    // window admit has by construction (merge and rewrite are separate steps).
    const peer = peerOf(wp, mine, 500);
    peer.getText("content").insert(11, " plus the peer's admitted paragraph");
    wp.engine.applyUpdate(mine, wp.engine.encodeState(peer, wp.engine.encodeStateVector(mine)));

    // Diffing the stale file against the doc would read the peer's paragraph as an agent deletion
    // and publish that deletion as deliberate intent. Measured before the fix; refused now.
    await expect(wp.publish(AGENT, DOC, "markdown", mine)).rejects.toThrow(/document_file_stale/);
    expect(wp.engine.readTextRoot(mine)).toContain("admitted paragraph");
  });

  it("the projection survives a NEW instance — it is on disk, not in memory", async () => {
    const first = newWritePath();
    const doc = first.engine.createDocument("baseline");
    const path = await first.materialize(AGENT, DOC, "markdown", doc);

    // A fresh instance stands in for a daemon restart.
    const second = newWritePath();
    await writeFile(path, "baseline plus more", "utf8");
    expect(await second.publish(AGENT, DOC, "markdown", doc)).not.toBeNull();
    expect(second.engine.readTextRoot(doc)).toBe("baseline plus more");
  });
});

describe("DocumentWritePath — the multi-hunk diff (§16.2 coarseness has a limit)", () => {
  it("two separated edits do NOT rewrite the untouched text between them", () => {
    const before = "line one\nline two\nline three\nline four";
    const after = "LINE ONE\nline two\nline three\nLINE FOUR";
    const hunks = lineHunks(before, after);
    // One hunk per changed line — not a single span swallowing lines two and three.
    expect(hunks).toHaveLength(2);
    expect(hunks[0]!.insert).toContain("LINE");
    expect(hunks[1]!.insert).toContain("FOUR");
  });

  it("a peer's concurrent DELETION between two local hunks stays deleted", async () => {
    const wp = newWritePath();
    const mine = wp.engine.createDocument("Intro.\nWRONG CLAIM.\nConclusion.");
    const path = await wp.materialize(AGENT, DOC, "markdown", mine);

    // The peer deletes the middle line. Pinned clientID: deterministic tie-break.
    const peer = peerOf(wp, mine, 500);
    peer.getText("content").delete(7, 13); // "WRONG CLAIM.\n"
    const incoming = wp.engine.encodeState(peer, wp.engine.encodeStateVector(mine));

    // The agent edits the FIRST and LAST lines in one publish batch — the normal shape under
    // publish-on-intent. A one-span diff would rewrite the middle line too, resurrecting it.
    await writeFile(path, "Intro, rewritten.\nWRONG CLAIM.\nConclusion, rewritten.", "utf8");
    await wp.publish(AGENT, DOC, "markdown", mine);
    wp.engine.applyUpdate(mine, incoming);

    expect(wp.engine.readTextRoot(mine)).not.toContain("WRONG CLAIM");
    expect(wp.engine.readTextRoot(mine)).toContain("Intro, rewritten.");
    expect(wp.engine.readTextRoot(mine)).toContain("Conclusion, rewritten.");
  });
});

describe("DocumentWritePath — admission folds local edits FIRST, in BOTH coordinate spaces", () => {
  for (const peerClientId of [500, 5_000_000]) {
    it(`overlap is TRUE when both sides rewrote the same words (peer clientID ${peerClientId})`, async () => {
      const wp = newWritePath();
      const mine = wp.engine.createDocument("the quick brown fox");
      mine.clientID = 1_000_000;
      const path = await wp.materialize(AGENT, DOC, "markdown", mine);

      const peer = peerOf(wp, mine, peerClientId);
      peer.getText("content").delete(4, 5);
      peer.getText("content").insert(4, "SLOW!");
      const incoming = wp.engine.encodeState(peer, wp.engine.encodeStateVector(mine));

      await writeFile(path, "the RAPID brown fox", "utf8");
      const res = await wp.admit(AGENT, DOC, "markdown", mine, incoming);
      // Both clientID orderings re-home the insert onto a different endpoint of the local edit,
      // so only an inclusive comparison gives ONE answer to a question that has one.
      expect(res.overlap).toBe(true);
    });
  }

  it("a LONG incoming insert far from the local edit is still NOT overlap", async () => {
    const wp = newWritePath();
    const mine = wp.engine.createDocument("alpha\nbeta\ngamma");
    mine.clientID = 1_000_000;
    const path = await wp.materialize(AGENT, DOC, "markdown", mine);

    // A long insert at the TOP. Before the region-shift fix the flag depended on the insert's
    // LENGTH rather than its position — 5 characters read as disjoint, 57 as overlapping.
    const peer = peerOf(wp, mine, 500);
    peer.getText("content").insert(0, "A LONG PREFACE THE PEER ADDED, WELL AWAY FROM MY EDIT.\n");
    const incoming = wp.engine.encodeState(peer, wp.engine.encodeStateVector(mine));

    await writeFile(path, "alpha\nbeta\nGAMMA-EDITED", "utf8");
    const res = await wp.admit(AGENT, DOC, "markdown", mine, incoming);

    const onDisk = await readFile(path, "utf8");
    expect(onDisk).toContain("LONG PREFACE");
    expect(onDisk).toContain("GAMMA-EDITED");
    expect(res.overlap).toBe(false);
  });

  it("no unpublished edits means no overlap, however large the incoming change", async () => {
    const wp = newWritePath();
    const mine = wp.engine.createDocument("original text here");
    mine.clientID = 1_000_000;
    await wp.materialize(AGENT, DOC, "markdown", mine);

    const peer = peerOf(wp, mine, 500);
    peer.getText("content").delete(0, 18);
    peer.getText("content").insert(0, "completely different");
    const incoming = wp.engine.encodeState(peer, wp.engine.encodeStateVector(mine));

    expect((await wp.admit(AGENT, DOC, "markdown", mine, incoming)).overlap).toBe(false);
  });

  it("admission REWRITES the file so the agent sees the merged projection", async () => {
    const wp = newWritePath();
    const mine = wp.engine.createDocument("base");
    mine.clientID = 1_000_000;
    const path = await wp.materialize(AGENT, DOC, "markdown", mine);

    const peer = peerOf(wp, mine, 500);
    peer.getText("content").insert(4, " plus theirs");
    const incoming = wp.engine.encodeState(peer, wp.engine.encodeStateVector(mine));

    await wp.admit(AGENT, DOC, "markdown", mine, incoming);
    expect(await readFile(path, "utf8")).toBe("base plus theirs");
  });
});

describe("DocumentWritePath — JSON documents (the path that had no admission coverage)", () => {
  it("a changed key becomes an operation; untouched keys are not rewritten", async () => {
    const wp = newWritePath();
    const doc = wp.engine.createDocument("");
    doc.getMap("data").set("kept", "same");
    doc.getMap("data").set("changed", "before");
    const path = await wp.materialize(AGENT, DOC, "json", doc);

    await writeFile(path, JSON.stringify({ kept: "same", changed: "after" }), "utf8");
    expect(await wp.publish(AGENT, DOC, "json", doc)).not.toBeNull();
    expect(doc.getMap("data").get("changed")).toBe("after");
    expect(doc.getMap("data").get("kept")).toBe("same");
  });

  it("an EMPTY json document round-trips — it used to infer as text and look for a .md file", async () => {
    const wp = newWritePath();
    const doc = wp.engine.createDocument("");
    const path = await wp.materialize(AGENT, DOC, "json", doc);
    expect(path.endsWith(".json")).toBe(true);

    await writeFile(path, JSON.stringify({ first: "content" }), "utf8");
    expect(await wp.publish(AGENT, DOC, "json", doc)).not.toBeNull();
    expect(doc.getMap("data").get("first")).toBe("content");

    // And no phantom sibling file was created for the wrong type.
    const files = await readdir(join(workspace, AGENT));
    expect(files.filter((f) => f.endsWith(".md"))).toHaveLength(0);
  });

  for (const peerClientId of [500, 5_000_000]) {
    it(`a same-key concurrent edit reports overlap (peer clientID ${peerClientId})`, async () => {
      const wp = newWritePath();
      const mine = wp.engine.createDocument("");
      mine.clientID = 1_000_000;
      mine.getMap("data").set("k", "base");
      const path = await wp.materialize(AGENT, DOC, "json", mine);

      const peer = peerOf(wp, mine, peerClientId);
      peer.getMap("data").set("k", "THEIRS");
      const incoming = wp.engine.encodeState(peer, wp.engine.encodeStateVector(mine));

      // The agent's unpublished edit to the SAME key. Whichever clientID wins the tie, the agent
      // must be told — Y.Map resolves silently, and before this the flag was hardcoded false for
      // every JSON document because the observer only watched the text root.
      await writeFile(path, JSON.stringify({ k: "MINE" }), "utf8");
      const res = await wp.admit(AGENT, DOC, "json", mine, incoming);
      expect(res.overlap).toBe(true);
    });
  }

  it("a DIFFERENT-key concurrent edit is not overlap, and both keys survive", async () => {
    const wp = newWritePath();
    const mine = wp.engine.createDocument("");
    mine.clientID = 1_000_000;
    mine.getMap("data").set("base", 1);
    const path = await wp.materialize(AGENT, DOC, "json", mine);

    const peer = peerOf(wp, mine, 500);
    peer.getMap("data").set("theirs", "value");
    const incoming = wp.engine.encodeState(peer, wp.engine.encodeStateVector(mine));

    await writeFile(path, JSON.stringify({ base: 1, mine: "value" }), "utf8");
    const res = await wp.admit(AGENT, DOC, "json", mine, incoming);

    expect(res.overlap).toBe(false);
    expect(mine.getMap("data").get("mine")).toBe("value");
    expect(mine.getMap("data").get("theirs")).toBe("value");
  });

  it("a removed key is removed from the map, not left stale", async () => {
    const wp = newWritePath();
    const doc = wp.engine.createDocument("");
    doc.getMap("data").set("a", 1);
    doc.getMap("data").set("b", 2);
    const path = await wp.materialize(AGENT, DOC, "json", doc);

    await writeFile(path, JSON.stringify({ a: 1 }), "utf8");
    await wp.publish(AGENT, DOC, "json", doc);
    expect(doc.getMap("data").has("b")).toBe(false);
  });

  it("malformed JSON REFUSES the publish — a broken file must not corrupt the CRDT", async () => {
    const wp = newWritePath();
    const doc = wp.engine.createDocument("");
    doc.getMap("data").set("intact", "yes");
    const path = await wp.materialize(AGENT, DOC, "json", doc);

    await writeFile(path, "{ this is not json", "utf8");
    await expect(wp.publish(AGENT, DOC, "json", doc)).rejects.toThrow(/document_file_unparseable/);
    expect(doc.getMap("data").get("intact")).toBe("yes");
  });
});

describe("DocumentWritePath — refusals are typed and name their cause", () => {
  it("publishing an unmaterialized document REFUSES, naming what is missing", async () => {
    const wp = newWritePath();
    const doc = wp.engine.createDocument("x");
    await expect(wp.publish(AGENT, DOC, "markdown", doc)).rejects.toThrow(DocumentWriteError);
    await expect(wp.publish(AGENT, DOC, "markdown", doc)).rejects.toThrow(/document_file_missing/);
  });

  it("an unsupported document type REFUSES on EVERY entry point, not just materialize", async () => {
    const wp = newWritePath();
    const doc = wp.engine.createDocument("x");
    await expect(wp.materialize(AGENT, DOC, "xml", doc)).rejects.toThrow(/document_type_unsupported/);
    await expect(wp.publish(AGENT, DOC, "xml", doc)).rejects.toThrow(/document_type_unsupported/);
    await expect(wp.admit(AGENT, DOC, "xml", doc, new Uint8Array([0, 0]))).rejects.toThrow(
      /document_type_unsupported/,
    );
  });

  it("every refusal carries a machine-readable reason, not just a message", async () => {
    const wp = newWritePath();
    const doc = wp.engine.createDocument("x");
    let thrown: unknown;
    try { await wp.publish(AGENT, DOC, "markdown", doc); } catch (e) { thrown = e; }
    expect(thrown).toBeInstanceOf(DocumentWriteError);
    expect((thrown as DocumentWriteError).reason).toBe("document_file_missing");
    expect((thrown as DocumentWriteError).detail).toBeTruthy();
  });
});
