/**
 * DOD-DOC-TYPES-1, unit 1 — the file extension follows the document TYPE.
 *
 * ── THE DEFECT ───────────────────────────────────────────────────────────────────────────────────
 *
 * The extension was decided by `JSON_TYPES.has(documentType) ? "json" : "md"`. Everything that is
 * not JSON is `.md`, so a `text` document — explicitly NOT markdown, that is why the type exists —
 * is handed to the agent as `<id>.md`.
 *
 * ── WHY IT MATTERS MORE THAN A COSMETIC NAME ─────────────────────────────────────────────────────
 *
 * The file IS the editing surface. There is no other one. The extension is what every editor, every
 * viewer and every agent reads to decide how to treat the bytes, so `.md` on a plain-text document
 * invites markdown rendering and markdown-aware autoformatting of content that is not markdown —
 * and an autoformatter's changes get diffed and PUBLISHED to the peer as deliberate edits.
 *
 * It is also the last moment this is cheap. Three more types are queued behind this unit; adding
 * them to a two-branch ternary is how a fourth wrong extension arrives without anyone deciding it.
 *
 * ── WHAT THIS PINS ───────────────────────────────────────────────────────────────────────────────
 *
 * 1. Every type maps to its own documented extension, from ONE table.
 * 2. The projection path uses the SAME extension as the document file. They were two independent
 *    copies of the ternary. A drifted pair does not fail loudly — it means the baseline a publish
 *    diffs against belongs to a different file, which is the `document_file_stale` refusal arriving
 *    for a reason no operator could act on.
 * 3. An unknown type does not silently receive a default extension. It cannot be admitted anyway
 *    (`isSupportedDocumentType`), and a default here is what let `yaml` create a real signed
 *    peer-accepted document with no file.
 *
 * ── AND THE MIGRATION, WHICH IS THE PART THAT COULD LOSE WORK ────────────────────────────────────
 *
 * `text` and `plaintext` documents that already exist live at `<id>.md`. Changing the extension
 * points the daemon at `<id>.txt`, which does not exist.
 *
 * The CONTENT is safe either way — it lives in the CRDT, and materialize would rewrite it at the new
 * path. What is NOT safe is anything the agent typed into the old file and had not published yet:
 * that exists only in those bytes, and leaving them at a path nothing reads again is losing work
 * silently, which is the one failure this milestone keeps finding. So the old file is carried over.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile, mkdir, readdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { DocumentEngine } from "../document-engine.js";
import { DocumentWritePath, extensionForDocumentType } from "../document-write-path.js";

const NOOP_LOGGER = { debug() {}, info() {}, warn() {}, error() {} } as never;
const AGENT = "aa".repeat(32);
const DOC = "cc".repeat(32);

let workspace: string;
beforeEach(async () => {
  workspace = await mkdtemp(join(tmpdir(), "cello-doc-ext-"));
});
afterEach(async () => {
  await rm(workspace, { recursive: true, force: true });
});

function newWritePath(): DocumentWritePath {
  return new DocumentWritePath(new DocumentEngine(NOOP_LOGGER), workspace, NOOP_LOGGER);
}

describe("the extension follows the document type", () => {
  it("each type has its own documented extension", () => {
    expect(extensionForDocumentType("markdown")).toBe("md");
    expect(extensionForDocumentType("text")).toBe("txt");
    expect(extensionForDocumentType("plaintext")).toBe("txt");
    expect(extensionForDocumentType("json")).toBe("json");
  });

  it("an unknown type gets no extension rather than a default", () => {
    // The `yaml` case: a type nothing can serve must not be handed a plausible-looking path. It is
    // refused upstream, and this is the second line of that defence rather than a duplicate of it.
    expect(extensionForDocumentType("yaml")).toBeUndefined();
    expect(extensionForDocumentType("")).toBeUndefined();
  });

  it("the document file carries it", () => {
    const wp = newWritePath();
    expect(wp.filePath(AGENT, DOC, "text").endsWith(`${DOC}.txt`)).toBe(true);
    expect(wp.filePath(AGENT, DOC, "plaintext").endsWith(`${DOC}.txt`)).toBe(true);
    expect(wp.filePath(AGENT, DOC, "markdown").endsWith(`${DOC}.md`)).toBe(true);
    expect(wp.filePath(AGENT, DOC, "json").endsWith(`${DOC}.json`)).toBe(true);
  });

  it("the projection path uses the SAME extension as the file it is the baseline for", async () => {
    // Two independent copies of the extension rule is how the baseline ends up belonging to a
    // different file than the one being diffed.
    const wp = newWritePath();
    const doc = wp.engine.createDocument("hello\n");
    await wp.materialize(AGENT, DOC, "text", doc);

    const projections = await readdir(join(workspace, ".cello", AGENT));
    expect(projections).toContain(`${DOC}.txt.projection`);
    expect(projections).not.toContain(`${DOC}.md.projection`);
  });
});

describe("a document that already lives at the old .md path is carried over, not stranded", () => {
  /** The world as it was: file AND projection written under the old everything-is-.md rule. */
  async function seedLegacy(content: string, projection: string): Promise<void> {
    await mkdir(join(workspace, AGENT), { recursive: true });
    await mkdir(join(workspace, ".cello", AGENT), { recursive: true });
    await writeFile(join(workspace, AGENT, `${DOC}.md`), content, "utf8");
    await writeFile(join(workspace, ".cello", AGENT, `${DOC}.md.projection`), projection, "utf8");
  }

  it("an unpublished edit in the old file is PUBLISHED rather than stranded", async () => {
    // The verb that matters. `materialize` overwrites the file by contract, so it is not where work
    // is rescued — `publish` is, because it diffs whatever the agent left on disk. If the migration
    // did not move the file, publish would read an absent path and refuse; if it moved the file but
    // not the projection, publish would refuse `document_file_missing` with no recorded baseline.
    const wp = newWritePath();
    const doc = wp.engine.createDocument("published line\n");
    await seedLegacy("published line\nan unpublished edit\n", "published line\n");

    const update = await wp.publish(AGENT, DOC, "text", doc);

    expect(update, "nothing was published — the agent's edit is still only in the old file").not.toBeNull();
    expect(doc.getText("content").toString()).toContain("an unpublished edit");
  });

  it("moves the file and its projection together, and leaves neither behind", async () => {
    const wp = newWritePath();
    const doc = wp.engine.createDocument("published line\n");
    await seedLegacy("published line\n", "published line\n");

    await wp.publish(AGENT, DOC, "text", doc);

    expect(await readdir(join(workspace, AGENT))).toEqual([`${DOC}.txt`]);
    expect(await readdir(join(workspace, ".cello", AGENT))).toEqual([`${DOC}.txt.projection`]);
  });

  it("does not touch a markdown document, whose extension did not change", async () => {
    const wp = newWritePath();
    const doc = wp.engine.createDocument("# Title\n");
    await wp.materialize(AGENT, DOC, "markdown", doc);
    expect(await readdir(join(workspace, AGENT))).toEqual([`${DOC}.md`]);
  });

  it("never prefers the old file when one already exists at the NEW path", async () => {
    // Both present means the new one is the live document and the old one is a leftover. Preferring
    // the old file would replay stale content over current work — the reverse of the bug being fixed.
    const wp = newWritePath();
    const doc = wp.engine.createDocument("current\n");
    await seedLegacy("STALE LEFTOVER\n", "STALE LEFTOVER\n");
    await writeFile(join(workspace, AGENT, `${DOC}.txt`), "current\nlive edit\n", "utf8");
    await mkdir(join(workspace, ".cello", AGENT), { recursive: true });
    await writeFile(join(workspace, ".cello", AGENT, `${DOC}.txt.projection`), "current\n", "utf8");

    await wp.publish(AGENT, DOC, "text", doc);

    expect(doc.getText("content").toString()).toContain("live edit");
    expect(doc.getText("content").toString()).not.toContain("STALE LEFTOVER");
  });
});
