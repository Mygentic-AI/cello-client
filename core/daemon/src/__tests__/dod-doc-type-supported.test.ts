/**
 * DOD-DOC-TOOLS-1 review, findings 2 and 8 — a document type we cannot actually serve must be
 * REFUSED at the door, not accepted and then half-worked.
 *
 * ── FINDING 2: `json` was advertised and silently broken ─────────────────────────────────────────
 *
 * `document_type: "json"` is offered in the MCP tool description, accepted by `propose`, and
 * genuinely supported by `DocumentWritePath` — a JSON document's content lives in the MAP root.
 * But `read`, `write` and `diff` all use `doc.getText("content")`, the TEXT root. Nothing bridges
 * them, so:
 *
 *   - the file is written as `{}` however rich the starting content was
 *   - `cello_doc_read` answers `ok: true, content: ""` — the exact "an empty document handed to an
 *     agent would be written back over the peer's real content" hazard the read path names in its
 *     own comment
 *   - `cello_doc_write` puts text into a root the file projection and the peer never read
 *   - `cello_doc_diff` compares "" with "" and reports `unchanged: true` forever
 *
 * ── FINDING 8: any other string was accepted too ─────────────────────────────────────────────────
 *
 * `document_type` was never validated. `"yaml"` created a real, signed, peer-accepted document
 * whose `materialize` throws `document_type_unsupported`; the throw was swallowed and came back as
 * `filePath: null` with no explanation — while the tool description promises a path. The same
 * applied on the receiving side: a peer could propose an unsupported type and the accepter silently
 * got a document with no file.
 *
 * ── WHY REFUSE RATHER THAN FINISH JSON ───────────────────────────────────────────────────────────
 *
 * Finishing JSON means branching read/write/diff on the type and folding through the map root — a
 * real feature, in the week the milestone closes, on a path with no test coverage at the handler
 * level at all. Half-support is the worst of the three options: it reads as done in every review
 * and loses an operator's content in silence. Refusing costs a caller nothing they had, because
 * nothing they had worked.
 *
 * The refusal is at BOTH ends on purpose. Refusing only at `propose` leaves the accepter able to
 * take on a document it cannot serve, and the party who gets hurt is the one who did not choose it.
 */

import { describe, it, expect } from "vitest";
import { SUPPORTED_DOCUMENT_TYPES, isSupportedDocumentType } from "../document-write-path.js";

describe("the supported document types are exactly what every verb can serve", () => {
  it("accepts the text types the whole verb set handles", () => {
    for (const t of ["markdown", "text", "plaintext"]) {
      expect(isSupportedDocumentType(t), `${t} is a text type and every verb handles it`).toBe(true);
    }
  });

  it("ADMITS json now that the three content verbs serve it (DOD-DOC-TYPES-1)", () => {
    // This asserted `false`, and the reason was right at the time: the write path had real JSON
    // support while read/write/diff read the TEXT root, so a JSON document read as empty and that
    // emptiness would be written back over the peer's content. Half-support reads as done in every
    // review and loses content in silence, so it was refused rather than finished.
    //
    // It has now been finished, not merely re-enabled: the three verbs project through the document's
    // ROOT, the fold is per-key, and the rendering is deterministic. The condition that justified the
    // refusal is gone, so the refusal goes with it.
    expect(isSupportedDocumentType("json")).toBe(true);
  });

  it("refuses anything else rather than creating a document with no file", () => {
    for (const t of ["yaml", "toml", "docx", "", "MARKDOWN "]) {
      expect(isSupportedDocumentType(t), `'${t}' must not create an unusable document`).toBe(false);
    }
  });

  it("the exported set is what the refusal message can name, so guidance cannot drift from behaviour", () => {
    // A hardcoded list in a guidance string is how the message and the check stop agreeing.
    expect([...SUPPORTED_DOCUMENT_TYPES].sort()).toEqual(["html", "json", "markdown", "plaintext", "text"]);
  });
});
