/**
 * DOD-FRONTIER-STRAND-1 AC3 — a stranded session LOOKS stranded on the session list.
 *
 * Session `dbb93dfc…` sat unsealable for a week and nothing said so. A close was attempted, refused
 * with `seal_interrupted_rejected_by_counterparty`, and that was the end of it: the refusal was a
 * transient string in one command's output. `cello_status` / `cello_sessions` went on listing the
 * session as plain `interrupted` — indistinguishable from one that is merely paused and will seal
 * fine once both parties are online. The operator could not tell "waiting" from "will never seal",
 * and the only way to find out was to attempt another close and read the error again.
 *
 * Detection is inherently at close time — two frontiers can only be compared when the two sides
 * talk — so this line is not about detecting earlier. It is about RETENTION: the answer was thrown
 * away the instant it was produced.
 *
 * Scope, stated so this is not read as more than it is: `FrontierMismatchStore` is in-memory, so a
 * daemon restart forgets. That costs one re-detection on the next close attempt and can never
 * produce a WRONG answer, whereas persisting it would mean a client-side schema migration on every
 * operator's machine, which AC3 does not ask for.
 */

import { describe, it, expect } from "vitest";
import { FrontierMismatchStore, renderFrontierMismatch } from "../frontier-mismatch.js";

describe("DOD-FRONTIER-STRAND-1 AC3: an observed mismatch is retained and surfaced", () => {
  it("S1: a recorded mismatch is readable afterwards — no second close attempt needed", () => {
    const store = new FrontierMismatchStore();
    expect(store.get("alice", "sid-1"), "nothing observed yet").toBeNull();

    store.record("alice", "sid-1", { ours: 3, theirs: 2, divergingLeafIndex: 2 }, 1_700_000_000_000);

    const m = store.get("alice", "sid-1");
    expect(m).toMatchObject({ ours: 3, theirs: 2, divergingLeafIndex: 2, observedAtMs: 1_700_000_000_000 });
  });

  it("S2: a SUCCESSFUL seal clears it — a flag that outlives its condition is the defect inverted", () => {
    // An operator told a healthy session is stranded stops believing the flag, and then the next
    // REAL strand reads as noise. That is the same failure this line exists to fix, pointing the
    // other way, so it gets its own clause rather than a comment.
    const store = new FrontierMismatchStore();
    store.record("alice", "sid-1", { ours: 3, theirs: 2, divergingLeafIndex: 2 }, 1);
    store.clear("alice", "sid-1");
    expect(store.get("alice", "sid-1")).toBeNull();
  });

  it("S3: re-observation overwrites — the NEWEST numbers win, never a stale pair", () => {
    const store = new FrontierMismatchStore();
    store.record("alice", "sid-1", { ours: 3, theirs: 2, divergingLeafIndex: 2 }, 1);
    store.record("alice", "sid-1", { ours: 5, theirs: 4, divergingLeafIndex: 4 }, 2);
    expect(store.get("alice", "sid-1")).toMatchObject({ ours: 5, theirs: 4, divergingLeafIndex: 4, observedAtMs: 2 });
  });

  it("S4: sessions are isolated — one strand does not tar another", () => {
    const store = new FrontierMismatchStore();
    store.record("alice", "sid-1", { ours: 3, theirs: 2, divergingLeafIndex: 2 }, 1);
    expect(store.get("alice", "sid-2")).toBeNull();
    // ...and the same session id under a DIFFERENT agent is a different session (loopback: both
    // ends of dbb93dfc… lived on one daemon under two agent names, so this is the real shape).
    expect(store.get("bob", "sid-1")).toBeNull();
  });

  it("S5: the store is BOUNDED — an unstated cap would be a silent leak", () => {
    const store = new FrontierMismatchStore();
    for (let i = 0; i < 300; i++) {
      store.record("alice", `sid-${i}`, { ours: 2, theirs: 1, divergingLeafIndex: 1 }, i);
    }
    // The oldest are evicted; the newest survive. A daemon runs for days and nothing else sweeps
    // this map, so "it only holds mismatches" is not by itself a bound.
    expect(store.get("alice", "sid-0"), "oldest evicted").toBeNull();
    expect(store.get("alice", "sid-299"), "newest retained").not.toBeNull();
  });

  it("S6: the rendered session-list field names both counts, the diverging leaf, and the remedy", () => {
    // This is the AC's literal deliverable — the `cello_sessions` field — so it is asserted rather
    // than assumed. daemon.ts calls exactly this function, which is why it was extracted: an inline
    // closure inside buildInterruptedSessions could only be reached by standing up a daemon and
    // driving a real seal exchange, so in practice it would have shipped uncovered.
    const rendered = renderFrontierMismatch(
      { ours: 3, theirs: 2, divergingLeafIndex: 2, observedAtMs: 1_700_000_000_000 },
      "dbb93dfcf415b7cbfe13626f5b168a3f",
    );
    expect(rendered).toMatchObject({ ours: 3, theirs: 2, divergingLeafIndex: 2 });
    expect(rendered.observedAt).toBe("2023-11-14T22:13:20.000Z");
    // The operator must learn WHAT disagreed, WHERE, and that it is terminal — the old refusal
    // ("ask the counterparty to check their end") gave none of the three.
    expect(rendered.guidance).toMatch(/you hold 3 messages/);
    expect(rendered.guidance).toMatch(/counterparty holds 2/);
    expect(rendered.guidance).toMatch(/diverge at leaf 2/);
    expect(rendered.guidance).toMatch(/dbb93dfcf415b7cbfe13626f5b168a3f/);
    expect(rendered.guidance).toMatch(/never be co-signed/);
  });
});
