/**
 * DOD-DOC-TYPES-1, unit 2 — ONE type registry, and `html`.
 *
 * ── THE DEFECT THIS FOUND, WHICH IS LIVE RIGHT NOW ───────────────────────────────────────────────
 *
 * There were TWO lists of document types, in two files, with no link between them:
 *
 *   `SUPPORTED_DOCUMENT_TYPES` (document-write-path)  = markdown, text, plaintext
 *   `DIFFABLE_DOCUMENT_TYPES`  (document-notify)      = markdown, text, json
 *
 * Read them together and two things fall out. **`plaintext` is admitted and cannot be diffed** — an
 * operator proposes a `plaintext` document, the peer accepts it, both sides edit it, and
 * `cello_doc_diff` answers *"this build renders diffs for markdown, text, json and this document is
 * plaintext"*. Nothing is lost, but the verb that tells you what changed is dead on a type the
 * product offered you. And `json` is diffable while being refused at the door, which is harmless
 * only by accident.
 *
 * Neither list is wrong on its own. The defect is that there are two, so adding a type means
 * remembering a second file — and `html` is the third type queued behind this, which is exactly when
 * a forgettable step gets forgotten.
 *
 * ── WHAT THIS PINS ───────────────────────────────────────────────────────────────────────────────
 *
 * One table with a row per type, and every other list DERIVED from it. The properties that used to
 * be separate lists are now columns: which Yjs root the content lives in, what extension it
 * materializes as, and whether it can be admitted yet.
 *
 * The tests below are mostly consistency laws rather than value checks, because the value checks are
 * what already passed while the registries disagreed.
 *
 * ── `html` ───────────────────────────────────────────────────────────────────────────────────────
 *
 * A text-root type like markdown: it merges by line, it just is not markdown. It needs no new engine
 * and no new screening — the content screen is character-level (BIDI overrides, chat-template
 * markers) and cares nothing for markup.
 *
 * It does carry one thing markdown does not, recorded on the type row rather than in a comment: an
 * `.html` file on disk is EXECUTABLE by the thing most likely to open it. Double-clicking a document
 * a peer co-authored runs their script with a `file://` origin. That is not a reason to refuse the
 * type — refusing `<script>` in an HTML document is the "a document about prompt formats loses its
 * subject" mistake from the screening audit, and it would make the type half-supported, which this
 * milestone has already established is worse than absent. It is a reason for the operator to be told
 * plainly, once, at the moment they are handed the path.
 */

import { describe, it, expect } from "vitest";
import {
  DOCUMENT_TYPES,
  openingNoticeFor,
  documentTypeRow,
  extensionForDocumentType,
  admittedDocumentTypes,
  diffableDocumentTypes,
  isSupportedDocumentType,
} from "../document-types.js";
import { SUPPORTED_DOCUMENT_TYPES } from "../document-write-path.js";
import { DIFFABLE_DOCUMENT_TYPES } from "../document-notify.js";

describe("there is one registry, and the old lists are derived from it", () => {
  it("the write path's admitted set IS the registry's", () => {
    expect([...SUPPORTED_DOCUMENT_TYPES].sort()).toEqual([...admittedDocumentTypes()].sort());
  });

  it("the notify module's diffable list IS the registry's", () => {
    expect([...DIFFABLE_DOCUMENT_TYPES].sort()).toEqual([...diffableDocumentTypes()].sort());
  });

  it("EVERY admitted type can be diffed", () => {
    // The law that was broken. `plaintext` was admitted and not diffable, so the verb that says
    // what changed was dead on a type the product offered.
    for (const type of admittedDocumentTypes()) {
      expect(diffableDocumentTypes(), `'${type}' is admitted but cello_doc_diff refuses it`).toContain(type);
    }
  });

  it("every type in the registry has an extension, and every extension has a type", () => {
    for (const type of DOCUMENT_TYPES.keys()) {
      expect(extensionForDocumentType(type), `'${type}' has no extension`).toBeTruthy();
    }
    expect(extensionForDocumentType("yaml")).toBeUndefined();
  });

  it("a type not in the registry is not admitted and not diffable", () => {
    expect(isSupportedDocumentType("yaml")).toBe(false);
    expect(documentTypeRow("yaml")).toBeUndefined();
    expect(diffableDocumentTypes()).not.toContain("yaml");
  });
});

describe("html is a first-class text type", () => {
  it("is admitted, diffable, and materializes as .html", () => {
    expect(isSupportedDocumentType("html")).toBe(true);
    expect(diffableDocumentTypes()).toContain("html");
    expect(extensionForDocumentType("html")).toBe("html");
  });

  it("uses the TEXT root — it merges by line, like markdown", () => {
    expect(documentTypeRow("html")?.root).toBe("text");
    expect(documentTypeRow("json")?.root).toBe("map");
  });

  it("is marked as executable-when-opened, and is the only text type that is", () => {
    // Carried as a property so the guidance is generated from the row rather than a hardcoded
    // `if (type === "html")` that the next executable type will not match.
    expect(documentTypeRow("html")?.executableWhenOpened).toBe(true);
    for (const type of ["markdown", "text", "plaintext"]) {
      expect(documentTypeRow(type)?.executableWhenOpened ?? false, `'${type}'`).toBe(false);
    }
  });
});

describe("plaintext and text are the same thing, said once", () => {
  it("plaintext resolves to text's row", () => {
    // Three names that behave identically is a product wart, but they must at least not DIVERGE.
    // Aliasing at the registry means there is one row and no second behaviour to drift.
    expect(documentTypeRow("plaintext")).toBe(documentTypeRow("text"));
  });

  it("plaintext is diffable — the live defect", () => {
    expect(diffableDocumentTypes()).toContain("plaintext");
  });
});

describe("an executable document type says so where the operator meets the path", () => {
  it("html carries a notice naming what opening the file does", () => {
    const notice = openingNoticeFor("html");
    expect(notice, "html is handed over with no warning at all").toBeTruthy();
    // The consequence, not the mechanism — an operator decides from what happens to them.
    expect(notice!.toLowerCase()).toContain("browser");
    expect(notice!.toLowerCase()).toContain("run");
  });

  it("no other type carries one, so the notice keeps its meaning", () => {
    // A warning on every document is a warning on none.
    for (const type of ["markdown", "text", "plaintext", "json"]) {
      expect(openingNoticeFor(type), `'${type}' must not warn`).toBeUndefined();
    }
    expect(openingNoticeFor("yaml")).toBeUndefined();
  });

  it("is derived from the row, not from the type NAME", () => {
    // The next executable type must inherit this by setting the flag, not by being remembered in an
    // `if (type === "html")` somewhere.
    const executable = [...DOCUMENT_TYPES.entries()].filter(([, row]) => row.executableWhenOpened);
    expect(executable.length).toBeGreaterThan(0);
    for (const [name] of executable) expect(openingNoticeFor(name)).toBeTruthy();
  });
});
