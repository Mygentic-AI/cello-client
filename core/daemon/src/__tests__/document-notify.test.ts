/**
 * DOD-DOC-NOTIFY-1 — passive notification and the two read calls (§16.5, §4.1).
 *
 * `node:sqlite` here is the test-file allowance; production is SQLCipher.
 */

import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { DocumentStore } from "../document-store.js";
import { DocumentNotifications, DIFFABLE_DOCUMENT_TYPES } from "../document-notify.js";
import type { Logger } from "../types.js";

const AGENT = "owner-agent";
const DOC = "cc".repeat(32);
const OTHER = "dd".repeat(32);
const NOW = 1_700_000_000_000;

function recordingLogger(): { logger: Logger; events: Array<{ event: string; fields: Record<string, unknown> }> } {
  const events: Array<{ event: string; fields: Record<string, unknown> }> = [];
  const push = (event: string, fields?: Record<string, unknown>) => {
    events.push({ event, fields: fields ?? {} });
  };
  const logger = { debug: push, info: push, warn: push, error: push, child: () => logger } as unknown as Logger;
  return { logger, events };
}

function newFixture() {
  const { logger, events } = recordingLogger();
  const db = new DatabaseSync(":memory:");
  const store = new DocumentStore(db, logger);
  return { notify: new DocumentNotifications(store, logger), events, db, store, logger };
}

describe("DocumentNotifications — the notice carries a COUNT, never content", () => {
  it("surfaces document_id and a pending count", () => {
    const f = newFixture();
    f.notify.notice(AGENT, DOC, 3, NOW);

    const [n] = f.notify.pending(AGENT);
    expect(n).toMatchObject({ documentId: DOC, pending: 3 });
    // The shape IS the guarantee. Content reaches the agent only through the screened read calls;
    // a notification carrying a preview would be an unscreened path straight into the agent's
    // context, which is the whole prompt-injection surface §3.1 exists to close.
    expect(Object.keys(n!).sort()).toEqual(["documentId", "noticedAtMs", "pending"]);
  });

  it("REPLACES the count rather than accumulating its own tally", () => {
    const f = newFixture();
    f.notify.notice(AGENT, DOC, 3, NOW);
    f.notify.notice(AGENT, DOC, 5, NOW + 1);
    // An incremented counter is a second tally of a fact the log already holds, and the two
    // disagree the first time a notice write is missed.
    expect(f.notify.pending(AGENT)[0]!.pending).toBe(5);
  });

  it("a zero count is the ABSENCE of a notice, not a notice saying zero", () => {
    const f = newFixture();
    f.notify.notice(AGENT, DOC, 2, NOW);
    f.notify.notice(AGENT, DOC, 0, NOW + 1);
    // A row saying "0 unread" is an inbox entry the agent must read to discover it has nothing to
    // read.
    expect(f.notify.pending(AGENT)).toHaveLength(0);
  });

  it("is scoped per agent", () => {
    const f = newFixture();
    f.notify.notice(AGENT, DOC, 1, NOW);
    expect(f.notify.pending("another-agent")).toHaveLength(0);
  });
});

describe("DocumentNotifications — cleared by an EXPLICIT fetch", () => {
  it("reading the pending list does not clear it", () => {
    const f = newFixture();
    f.notify.notice(AGENT, DOC, 1, NOW);
    f.notify.pending(AGENT);
    // An inbox render that cleared would drop the notice for an agent that merely glanced at a
    // summary, and the update would then be unread AND unannounced — invisible in both directions.
    expect(f.notify.pending(AGENT)).toHaveLength(1);
  });

  it("clear removes exactly one document's notice, and reports whether there was one", () => {
    const f = newFixture();
    f.notify.notice(AGENT, DOC, 1, NOW);
    f.notify.notice(AGENT, OTHER, 2, NOW);

    expect(f.notify.clear(AGENT, DOC)).toBe(true);
    expect(f.notify.pending(AGENT).map((n) => n.documentId)).toEqual([OTHER]);
    // Reporting a clear that cleared nothing would emit an event for a fetch that found nothing.
    expect(f.notify.clear(AGENT, DOC)).toBe(false);
    expect(f.events.filter((e) => e.event === "document.notice.cleared")).toHaveLength(1);
  });
});

describe("DocumentNotifications — diffStats is STRUCTURAL, with no content", () => {
  it("reports counts and ranges but never a line of the document", () => {
    const f = newFixture();
    const stats = f.notify.diffStats(DOC, "one\ntwo\nthree\n", "one\nTWO CHANGED\nthree\n");

    expect(stats.ranges).toEqual([{ start: 2, end: 2 }]);
    expect(stats.linesAdded).toBe(1);
    expect(stats.linesRemoved).toBe(1);
    // The point of this call is that an agent can decide whether to read WITHOUT reading. Leaking
    // one line of the peer's content here would defeat it entirely.
    expect(JSON.stringify(stats)).not.toContain("TWO CHANGED");
    expect(JSON.stringify(stats)).not.toContain("two");
  });

  it("reports NO overlap when the peer changed lines this operator did not touch", () => {
    const f = newFixture();
    const stats = f.notify.diffStats(DOC, "a\nb\nc\n", "a\nB\nc\n", [3]);
    expect(stats.overlap).toBe(false);
  });

  it("reports overlap when the peer's change touches a line this operator edited", () => {
    const f = newFixture();
    const stats = f.notify.diffStats(DOC, "a\nb\nc\n", "a\nB\nc\n", [2]);
    // The one judgement in an otherwise purely structural result, and the reason an agent reads
    // stats before deciding whether to read at all.
    expect(stats.overlap).toBe(true);
  });

  it("reports nothing changed as nothing changed", () => {
    const f = newFixture();
    const stats = f.notify.diffStats(DOC, "a\nb\n", "a\nb\n", [1, 2]);
    expect(stats).toMatchObject({ linesAdded: 0, linesRemoved: 0, ranges: [], overlap: false });
  });
});

describe("DocumentNotifications — diff renders the supported types and REFUSES the rest", () => {
  it("supports markdown, plain text and JSON", () => {
    expect([...DIFFABLE_DOCUMENT_TYPES]).toEqual(["markdown", "text", "json"]);
  });

  it("renders a line diff for markdown and text", () => {
    const f = newFixture();
    for (const type of ["markdown", "text"]) {
      const res = f.notify.diff(type, "# Title\nbody\n", "# Title\nnew body\n", DOC);
      expect(res.ok).toBe(true);
      expect((res as { diff: string }).diff).toContain("- body");
      expect((res as { diff: string }).diff).toContain("+ new body");
    }
  });

  it("renders a KEY-PATH diff for JSON, not a line diff", () => {
    const f = newFixture();
    const before = JSON.stringify({ a: 1, nested: { keep: true, drop: 1 } }, null, 2);
    const after = JSON.stringify({ a: 2, nested: { keep: true } }, null, 4);

    const res = f.notify.diff("json", before, after, DOC);
    expect(res.ok).toBe(true);
    const diff = (res as { diff: string }).diff;
    // Re-serialized JSON changes shape whenever a formatter touches it — here the indent went from
    // 2 to 4 — so a line diff would report the whole document rewritten for a one-value change.
    // That false "everything changed" alarm is what makes an agent stop reading diffs at all.
    expect(diff).toContain("~ a: 1 -> 2");
    expect(diff).toContain("- nested.drop");
    expect(diff).not.toContain("nested.keep");
  });

  it("says so, rather than line-diffing JSON that does not parse", () => {
    const f = newFixture();
    const res = f.notify.diff("json", "{not json", "{still not", DOC);
    expect(res.ok).toBe(true);
    // A stated fallback, not a silent one: the caller can see it got a line diff where it asked
    // for a key diff.
    expect((res as { diff: string }).diff).toContain("does not parse as JSON");
  });

  it("REFUSES an unsupported type by name instead of guessing", () => {
    const f = newFixture();
    const res = f.notify.diff("spreadsheet", "a", "b", DOC);
    expect(res.ok).toBe(false);
    expect((res as { reason: string }).reason).toBe("document_type_not_diffable");
    // A diff that is silently wrong is worse than no diff, because the agent cannot tell and will
    // act on it. The refusal names the type and the supported set.
    expect((res as { detail: string }).detail).toContain("spreadsheet");
    expect((res as { detail: string }).detail).toContain("markdown");
  });
});
