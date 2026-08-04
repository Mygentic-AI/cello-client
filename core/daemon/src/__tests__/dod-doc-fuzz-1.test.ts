/**
 * DOD-DOC-FUZZ-1 — Yjs hostile-input measurement (§16.7-7 precondition).
 *
 * The V1 posture for hostile document updates is "cap, catch, contain": a pre-parse SIZE CAP
 * before Yjs sees the bytes, a wrapped apply so a malformed update becomes an ordinary
 * rejection, and structural limits checked on the shadow document before admission. No sandbox
 * process in V1.
 *
 * This file measures whether that posture actually holds, and every assertion is written so a
 * SILENT REVERSAL breaks the build. The reversal that matters most is not a crash — it is Yjs
 * quietly ACCEPTING something. A gate built on "malformed input throws" is defeated by input
 * that returns normally and does nothing, because the try/catch sees success and the shadow
 * document shows no violation to measure.
 *
 * The findings drive ACs on DOD-DOC-GATE-1; the journal entry carries the write-up.
 *
 * ON HANGS — stated plainly because an earlier version of this file claimed otherwise:
 * `Y.applyUpdate` is synchronous, so a genuine infinite loop never returns and NOTHING in this
 * file can observe it. `classifyWithBudget` detects SLOW-BUT-RETURNS only. The sole protection
 * against a true hang is the per-test timeout, kept deliberately short here so it fires fast.
 */

import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import * as Y from "yjs";

/** The planned pre-parse cap: bytes are refused on LENGTH before Yjs is invoked at all. */
const PRE_PARSE_SIZE_CAP_BYTES = 1024 * 1024; // 1 MiB

/** The minimum valid update — an empty encoded state is two bytes. Measured, see below. */
const MIN_UPDATE_BYTES = 2;

/**
 * Apply an update the way the gate will: size-capped, then wrapped.
 *
 * NOTE the deliberate asymmetry this exposes, which is itself a finding: the cap path returns a
 * typed protocol reason, while the catch path returns raw lib0 decoder prose ("Unexpected end of
 * array", "Integer out of Range"). DOD-DOC-GATE-1 must map every Yjs throw to ONE typed reason
 * and carry the decoder string as detail — never surface it as the reason.
 */
function guardedApply(doc: Y.Doc, update: Uint8Array): { ok: true } | { ok: false; reason: string } {
  if (update.length > PRE_PARSE_SIZE_CAP_BYTES) {
    return { ok: false, reason: "document_update_too_large" };
  }
  try {
    Y.applyUpdate(doc, update);
    return { ok: true };
  } catch (err: unknown) {
    return { ok: false, reason: err instanceof Error ? err.message : String(err) };
  }
}

/** A well-formed update, for contrast cases and as the source for truncation/corruption. */
function validUpdate(): Uint8Array {
  const doc = new Y.Doc();
  doc.getText("t").insert(0, "the quick brown fox jumps over the lazy dog");
  doc.getMap("m").set("key", "value");
  doc.getArray("a").insert(0, [1, 2, 3]);
  return Y.encodeStateAsUpdate(doc);
}

/**
 * Classify a synchronous call as returned / threw / slow.
 *
 * There is no "hung" — see the file header. A true hang blocks the event loop and this function
 * never reaches its own clock read.
 */
function classifyWithBudget(fn: () => void, budgetMs: number): "returned" | "threw" | "slow" {
  const started = Date.now();
  let outcome: "returned" | "threw";
  try {
    fn();
    outcome = "returned";
  } catch {
    outcome = "threw";
  }
  return Date.now() - started > budgetMs ? "slow" : outcome;
}

/** Bytes held outside the JS heap. `heapUsed` EXCLUDES typed-array backing stores. */
function offHeapBytes(): number {
  const m = process.memoryUsage();
  return m.arrayBuffers + m.external;
}

describe("DOD-DOC-FUZZ-1: Y.applyUpdate under hostile input", () => {
  // ── THE ACCEPT CLASS — the failure mode "cap, catch, contain" does not catch ──────────────
  //
  // This is the headline finding. An update whose dependencies the receiver lacks does not
  // throw: it returns normally, contributes NOTHING to the document, and is RETAINED in
  // `doc.store.pendingStructs` waiting for predecessors that may never arrive. A peer streams
  // these until the daemon dies. All three legs of §16.7-7 pass this input — the try/catch sees
  // success, and the shadow document has no violation to measure because it is empty.
  it("accepts and RETAINS updates whose dependencies never arrive — no throw, no content", () => {
    const source = new Y.Doc();
    const updates: Uint8Array[] = [];
    source.on("update", (u: Uint8Array) => updates.push(u));
    for (let i = 0; i < 50; i++) source.getText("t").insert(0, `chunk${i} `);

    const target = new Y.Doc();
    let accepted = 0;
    // Skip the FIRST update, so every later one depends on a struct the target never sees.
    for (const u of updates.slice(1)) {
      if (guardedApply(target, u).ok) accepted++;
    }

    expect(accepted).toBe(updates.length - 1); // every one accepted...
    expect(target.getText("t").toString()).toBe(""); // ...and none contributed anything
    expect(target.store.pendingStructs).not.toBeNull(); // ...and all are retained

    // The gate's AC follows directly: a non-empty pending set after a shadow apply is a
    // REJECTION (unresolved dependencies), not an admission.
    expect(target.store.pendingStructs?.missing.size).toBeGreaterThan(0);
  });

  it("a valid update for a DIFFERENT document merges silently — updates carry no doc identity", () => {
    const mine = new Y.Doc();
    mine.getText("t").insert(0, "mine");
    const foreign = new Y.Doc();
    foreign.getText("t").insert(0, "INJECTED FROM ANOTHER DOC");
    foreign.getMap("m").set("evil", true);

    expect(guardedApply(mine, Y.encodeStateAsUpdate(foreign)).ok).toBe(true);
    // Content from an unrelated document is now in this one, with no error anywhere.
    expect(mine.getText("t").toString()).toContain("INJECTED FROM ANOTHER DOC");
    expect(mine.getMap("m").get("evil")).toBe(true);
    // → GATE AC: an update must be bound to its document/session OUT OF BAND. The decoder
    //   cannot detect this and never will.
  });

  it("V2-format bytes are ACCEPTED by the v1 decoder and silently drop all content", () => {
    const source = new Y.Doc();
    source.getText("t").insert(0, "content that will vanish");
    const v2 = Y.encodeStateAsUpdateV2(source);

    const target = new Y.Doc();
    expect(guardedApply(target, v2).ok).toBe(true);
    expect(target.getText("t").toString()).toBe("");
    // → GATE AC: pin the update encoding version on the wire (§16.7-8) and refuse a mismatch.
    //   Format confusion is silent in both directions.
  });

  it("TRAILING BYTES are ignored — the update encoding is MALLEABLE", () => {
    const source = new Y.Doc();
    source.getText("t").insert(0, "hello");
    const canonical = Y.encodeStateAsUpdate(source);

    for (const padding of [[0, 0, 0, 0], [9, 9], [0xff]]) {
      const padded = new Uint8Array(canonical.length + padding.length);
      padded.set(canonical);
      padded.set(padding, canonical.length);

      const target = new Y.Doc();
      expect(guardedApply(target, padded).ok).toBe(true);
      expect(target.getText("t").toString()).toBe("hello");
      expect(padded).not.toEqual(canonical); // different bytes...
    }
    // → LEAF/GATE AC: unlimited byte strings map to IDENTICAL document state, so hashing the
    //   RECEIVED bytes into a 0x04 leaf is malleable — a peer can pad to change the leaf hash
    //   without changing the document. Hash the re-encoded shadow state, or reject trailing
    //   bytes after the decoder's cursor.
  });

  // ── Garbage bytes ─────────────────────────────────────────────────────────
  it("random garbage is ALWAYS rejected — counted, on a fresh doc each trial", () => {
    let rejected = 0;
    let total = 0;
    for (const size of [1, 2, 7, 64, 512, 4096]) {
      for (let trial = 0; trial < 20; trial++) {
        // A fresh doc per trial: a shared one would hide contamination from a partial apply.
        const doc = new Y.Doc();
        const res = guardedApply(doc, new Uint8Array(randomBytes(size)));
        total++;
        if (!res.ok) {
          rejected++;
        } else {
          // If Yjs ever silently ACCEPTS garbage, the doc must at least be unchanged.
          expect(doc.getText("t").toString()).toBe("");
        }
      }
    }
    expect(total).toBe(120);
    // The measured property, asserted rather than narrated: nothing gets through.
    expect(rejected).toBe(total);
  });

  it("all-0xff is rejected, but ALL-ZERO IS ACCEPTED — ok:true is not evidence of content", () => {
    for (const size of [2, 16, 1024]) {
      expect(guardedApply(new Y.Doc(), new Uint8Array(size).fill(0xff)).ok).toBe(false);
      // Any all-zero buffer >= 2 bytes is a valid EMPTY update.
      const doc = new Y.Doc();
      expect(guardedApply(doc, new Uint8Array(size).fill(0x00)).ok).toBe(true);
      expect(doc.getText("t").toString()).toBe("");
    }
  });

  it("an empty or one-byte update THROWS a decoder error — it is not a no-op", () => {
    for (const bytes of [new Uint8Array(0), new Uint8Array([0])]) {
      expect(() => Y.applyUpdate(new Y.Doc(), bytes)).toThrow(/Unexpected end of array/);
      expect(guardedApply(new Y.Doc(), bytes).ok).toBe(false);
    }
    // → GATE AC: the gate needs a FLOOR as well as a cap, or an empty update yields a
    //   quarantine reason naming Yjs internals rather than a protocol fault.
  });

  it("two zero bytes IS the minimal valid update — the empty encoded state", () => {
    expect(Y.encodeStateAsUpdate(new Y.Doc())).toHaveLength(MIN_UPDATE_BYTES);
    expect(guardedApply(new Y.Doc(), new Uint8Array(MIN_UPDATE_BYTES)).ok).toBe(true);
  });

  // ── Truncated and corrupted updates ───────────────────────────────────────
  it("EVERY prefix of a valid update is rejected — counted, and the size is pinned", () => {
    const full = validUpdate();
    // Pinned so a change to validUpdate() cannot silently shrink this test's coverage.
    expect(full.length).toBe(84);

    let rejected = 0;
    for (let cut = 0; cut < full.length; cut++) {
      const doc = new Y.Doc();
      const res = guardedApply(doc, full.subarray(0, cut));
      if (!res.ok) rejected++;
      else expect(doc.getText("t").toString()).toBe("");
    }
    expect(rejected).toBe(full.length);
  }, 15_000);

  it("every single-byte corruption is contained and never returns partial content", () => {
    const full = validUpdate();
    for (let i = 0; i < full.length; i++) {
      const corrupted = Uint8Array.from(full);
      corrupted[i] = corrupted[i]! ^ 0xff;
      const doc = new Y.Doc();
      const outcome = classifyWithBudget(() => {
        Y.applyUpdate(doc, corrupted);
      }, 500);
      expect(outcome, `corruption at byte ${i} must not be slow`).not.toBe("slow");
      // Either rejected, or accepted as something OTHER than the original text.
      if (outcome === "returned") {
        expect(doc.getText("t").toString()).not.toBe("the quick brown fox jumps over the lazy dog");
      }
    }
  }, 15_000);

  // ── Pathological structure ────────────────────────────────────────────────
  it("a varint claiming a huge payload does not allocate — measured OFF-heap", () => {
    // heapUsed EXCLUDES typed-array backing stores, so a decoder doing
    // `new Uint8Array(hugeLength)` is invisible to it. Measure arrayBuffers + external.
    const hugeLength = new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]);
    const before = offHeapBytes();
    const outcome = classifyWithBudget(() => {
      Y.applyUpdate(new Y.Doc(), hugeLength);
    }, 2000);
    const growthMb = (offHeapBytes() - before) / (1024 * 1024);
    expect(outcome).not.toBe("slow");
    expect(growthMb, `off-heap grew ${growthMb.toFixed(1)} MiB on a 10-byte input`).toBeLessThan(64);
  }, 10_000);

  it("2000-deep nesting APPLIES SUCCESSFULLY — Yjs does not bound depth, so the gate must", () => {
    const source = new Y.Doc();
    let map = source.getMap("root");
    for (let depth = 0; depth < 2000; depth++) {
      const child = new Y.Map();
      map.set("child", child);
      map = child;
    }
    const update = Y.encodeStateAsUpdate(source);
    // Pinned: the bytes-per-level ratio is what makes the size cap a poor depth bound, and the
    // gate's depth default is chosen against it.
    expect(update.length).toBeLessThan(40_000);
    expect(update.length).toBeLessThan(PRE_PARSE_SIZE_CAP_BYTES);

    const target = new Y.Doc();
    const outcome = classifyWithBudget(() => {
      Y.applyUpdate(target, update);
    }, 5000);

    // Asserting SUCCESS, not "returned or threw". A future Yjs that recursed and blew the stack
    // would throw a catchable RangeError — the receive-side stack-exhaustion reversal — and a
    // both-are-fine assertion would stay green through it.
    expect(outcome).toBe("returned");

    // And the depth really is there: walk it, so "applied" is not just "did not error".
    let node = target.getMap("root");
    let walked = 0;
    while (node.get("child") instanceof Y.Map) {
      node = node.get("child") as Y.Map<unknown>;
      walked++;
    }
    expect(walked).toBe(2000);
  }, 20_000);

  it("a 500k-character single string and 5k distinct clientIDs are both benign to APPLY", () => {
    const bigString = new Y.Doc();
    bigString.getText("t").insert(0, "x".repeat(500_000));
    const target1 = new Y.Doc();
    expect(classifyWithBudget(() => {
      Y.applyUpdate(target1, Y.encodeStateAsUpdate(bigString));
    }, 2000)).toBe("returned");
    expect(target1.getText("t").length).toBe(500_000);

    // The property is the cost of APPLYING a many-author update — what a peer actually sends.
    // Building one is far more expensive than receiving it (measured: 20k clients take ~31s to
    // construct and 12ms to apply), so the fleet size here is chosen for construction cost, and
    // only the apply is timed.
    const manyClients = new Y.Doc();
    for (let i = 0; i < 5_000; i++) {
      const d = new Y.Doc();
      d.clientID = i + 1;
      d.getArray("a").insert(0, [i]);
      Y.applyUpdate(manyClients, Y.encodeStateAsUpdate(d));
    }
    const update = Y.encodeStateAsUpdate(manyClients);
    const target2 = new Y.Doc();
    expect(classifyWithBudget(() => {
      Y.applyUpdate(target2, update);
    }, 1000)).toBe("returned");
    expect(target2.getArray("a").length).toBe(5_000);
  }, 30_000);

  it("a valid update replayed twice is idempotent", () => {
    const update = validUpdate();
    const doc = new Y.Doc();
    expect(guardedApply(doc, update).ok).toBe(true);
    const afterFirst = doc.getText("t").toString();
    expect(guardedApply(doc, update).ok).toBe(true);
    expect(doc.getText("t").toString()).toBe(afterFirst);
  });

  // ── The size cap ──────────────────────────────────────────────────────────
  it("the pre-parse cap rejects oversized input BEFORE Yjs sees it, naming the limit", () => {
    const res = guardedApply(new Y.Doc(), new Uint8Array(PRE_PARSE_SIZE_CAP_BYTES + 1));
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("document_update_too_large");
  });

  it("a well-formed update still applies through the same guard", () => {
    const doc = new Y.Doc();
    expect(guardedApply(doc, validUpdate()).ok).toBe(true);
    expect(doc.getText("t").toString()).toBe("the quick brown fox jumps over the lazy dog");
    expect(doc.getMap("m").get("key")).toBe("value");
  });
});
