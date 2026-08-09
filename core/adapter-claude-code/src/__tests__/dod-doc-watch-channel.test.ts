/**
 * DOD-DOC-WATCH-1 — the nudge has to SAY something when it wakes an agent.
 *
 * Proven live between two machines on 2026-08-09: the doorbell fired correctly and rendered as
 * `CELLO event: document_watch.` — the generic fallback. An agent woken and told nothing has to spend
 * a read discovering why, which is most of what the feature was meant to save.
 *
 * ── AND THE PART THAT IS NOT WORDING ─────────────────────────────────────────────────────────────
 *
 * This body is NOT screened. A changed path can contain a key the PEER chose — watch `blocking_flags`
 * and a counterparty may add `blocking_flags.<anything>` — so rendering changed paths would hand a
 * counterparty an unscreened route into the operator's agent context, arriving as a doorbell the
 * agent never asked for. The nudge therefore carries the agent's OWN watch patterns, which it wrote
 * locally and which never crossed the wire.
 */

import { describe, it, expect } from "vitest";
import { buildChannelParams } from "../channel-params.js";

function body(data: Record<string, unknown>): string {
  const params = buildChannelParams(data, "document_watch") as { content?: string };
  return String(params.content ?? "");
}

describe("a watch doorbell explains itself", () => {
  it("names what fired and what to do next", () => {
    const text = body({ documentId: "a".repeat(64), paths: ["blocking_flags"] });
    expect(text, "fell through to the generic event line").not.toContain("CELLO event:");
    expect(text).toContain("blocking_flags");
    expect(text).toContain("cello_doc_diff");
  });

  it("shortens the document id — it is a fingerprint, not a name", () => {
    const text = body({ documentId: "b".repeat(64), paths: ["x"] });
    expect(text).not.toContain("b".repeat(64));
    expect(text).toContain("bbbbbbbbbbbb…");
  });

  it("still says something useful when the daemon sends no paths", () => {
    // An older daemon sends no `paths`. Skew is the expected state, not the exception.
    const text = body({ documentId: "c".repeat(64) });
    expect(text).not.toContain("CELLO event:");
    expect(text.toLowerCase()).toContain("watching");
  });
});
