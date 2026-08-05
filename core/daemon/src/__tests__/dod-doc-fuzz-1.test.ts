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

/**
 * A well-formed update, for contrast cases and as the source for truncation/corruption.
 *
 * The clientID is PINNED. Yjs mints a random uint32 and every item reference encodes it as a
 * varint, so the update's SIZE depends on the draw — a clientID below 2^28 encodes in four bytes
 * instead of five, making this update 83 bytes rather than 84. That is roughly one run in
 * sixteen, which is exactly how the byte-count assertion below turned up as an unreproducible
 * intermittent failure. Same root cause as the deep-nesting measurement in this file, which was
 * pinned when it was found; this one was missed.
 */
function validUpdate(): Uint8Array {
  const doc = new Y.Doc();
  doc.clientID = 4294967290;
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

    expect(updates.length).toBe(50); // pinned: a future Yjs that batched would shrink the trial

    const target = new Y.Doc();
    let accepted = 0;
    // Skip the FIRST update, so every later one depends on a struct the target never sees.
    const pending = updates.slice(1);
    for (const u of pending.slice(0, 5)) {
      if (guardedApply(target, u).ok) accepted++;
    }
    // RETENTION is the DoS claim, so measure that it GROWS. `missing.size` is keyed by client
    // and there is one source client, so it is always 1 — asserting it proves nothing.
    const retainedAfter5 = target.store.pendingStructs?.update.length ?? 0;
    for (const u of pending.slice(5)) {
      if (guardedApply(target, u).ok) accepted++;
    }
    const retainedAfterAll = target.store.pendingStructs?.update.length ?? 0;

    expect(accepted).toBe(pending.length); // every one accepted...
    expect(target.getText("t").toString()).toBe(""); // ...and none contributed anything
    expect(target.store.pendingStructs).not.toBeNull(); // ...and they are retained...
    expect(retainedAfterAll).toBeGreaterThan(retainedAfter5); // ...and the retention GROWS
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

  it("a 10-byte well-formed update DELETES a document's entire content", () => {
    // Structural limits are UPPER bounds, so a shrinking update passes every one of them. The
    // shadow document after this is smaller and perfectly well-formed — all three legs of
    // §16.7-7 pass it. GATE-1's append_only rule is the intended defense, and this is the
    // measurement that makes it load-bearing rather than a nicety.
    const doc = new Y.Doc();
    doc.getText("t").insert(0, "everything that will be destroyed");
    const beforeLength = doc.getText("t").length;

    const attacker = new Y.Doc();
    Y.applyUpdate(attacker, Y.encodeStateAsUpdate(doc));
    attacker.getText("t").delete(0, beforeLength);
    const deletion = Y.encodeStateAsUpdate(attacker, Y.encodeStateVector(doc));

    expect(deletion.length).toBeLessThan(32); // tiny, and far under any cap
    expect(guardedApply(doc, deletion).ok).toBe(true);
    expect(doc.getText("t").toString()).toBe(""); // content gone, no error anywhere
  });

  it("a COLLIDING clientID silently wins, and leaves NO pending set to detect it", () => {
    // The accept-class shape that GATE-1 AC (a) does NOT catch — recorded because an AC that
    // implies completeness it lacks is worse than no AC. Yjs identifies authorship by clientID
    // alone, so an attacker writing under a client's ID is indistinguishable from that client.
    const honest = new Y.Doc();
    honest.clientID = 777;
    honest.getText("t").insert(0, "honest content");

    const forger = new Y.Doc();
    forger.clientID = 777; // the collision
    forger.getText("t").insert(0, "FORGED AS 777");

    const target = new Y.Doc();
    expect(guardedApply(target, Y.encodeStateAsUpdate(forger)).ok).toBe(true);
    // The honest client's REAL update is now accepted and silently dropped — same clock range.
    expect(guardedApply(target, Y.encodeStateAsUpdate(honest)).ok).toBe(true);

    // The result is NEITHER party's content: the honest update's overlapping clock range is
    // dropped as already-seen, and only its TAIL beyond the forger's range survives — splicing
    // a stray "t" (from "honest content") onto the forged text. A document assembled from two
    // authors who never collaborated, with no error on any path.
    const result = target.getText("t").toString();
    expect(result).toContain("FORGED AS 777");
    expect(result).not.toBe("honest content");
    expect(result).not.toBe("FORGED AS 777");
    // And crucially: nothing is pending, so a pending-set check cannot see this at all.
    expect(target.store.pendingStructs).toBeNull();
    // → GATE AC: the clientID observed in an update must be bound to the peer's identity
    //   OUT OF BAND. No property of the update itself can establish it.
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
      target.clientID = source.clientID; // so re-encoded state is comparable across paddings
      expect(guardedApply(target, padded).ok).toBe(true);
      expect(target.getText("t").toString()).toBe("hello");
      // THE malleability property: different wire bytes, byte-identical re-encoded state.
      // This is what would go red if the decoder started absorbing or rejecting trailing bytes.
      expect(Buffer.from(Y.encodeStateAsUpdate(target))).toEqual(Buffer.from(canonical));
    }
    // → LEAF/GATE AC: unlimited byte strings map to IDENTICAL document state, so hashing the
    //   RECEIVED bytes into a 0x04 leaf is malleable — a peer can pad to change the leaf hash
    //   without changing the document. Hash the re-encoded shadow state, or reject trailing
    //   bytes after the decoder's cursor.
  });

  // ── Garbage bytes ─────────────────────────────────────────────────────────
  // Random garbage is CONTAINED, not always rejected — a distinction measured, not assumed.
  // ~1 in 100,000 random 7-byte buffers is ACCEPTED: any buffer starting `00 00` is a valid
  // EMPTY update whose remaining bytes are ignored as trailing (this file's own trailing-byte
  // finding falsifying its own garbage finding). An earlier version asserted
  // `rejected === total`, which was both a false claim and FLAKY — roughly 1 CI run in 650
  // would have gone red with nothing broken, and read as noise rather than as this finding.
  //
  // The property that actually matters for a shadow-apply gate is that nothing garbage ever
  // contributes CONTENT.
  it("random garbage never contributes content — accepted-but-inert is the residual", () => {
    let rejected = 0;
    let acceptedInert = 0;
    let acceptedWithContent = 0;
    let total = 0;
    for (const size of [1, 2, 7, 64, 512, 4096]) {
      for (let trial = 0; trial < 20; trial++) {
        const doc = new Y.Doc(); // fresh per trial — a shared doc would hide contamination
        total++;
        if (!guardedApply(doc, new Uint8Array(randomBytes(size))).ok) {
          rejected++;
        } else if (doc.getText("t").toString().length === 0 && doc.getMap("m").size === 0) {
          acceptedInert++;
        } else {
          acceptedWithContent++;
        }
      }
    }
    // The load-bearing assertion. Deterministic: garbage cannot forge content.
    expect(acceptedWithContent).toBe(0);
    // And everything is accounted for — no third outcome slipped through.
    expect(rejected + acceptedInert).toBe(total);
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
    // Deterministic now that validUpdate() pins its clientID — see the note there.
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
    let threw = 0;
    let returned = 0;
    for (let i = 0; i < full.length; i++) {
      const corrupted = Uint8Array.from(full);
      corrupted[i] = corrupted[i]! ^ 0xff;
      const doc = new Y.Doc();
      const outcome = classifyWithBudget(() => {
        Y.applyUpdate(doc, corrupted);
      }, 500);
      expect(outcome, `corruption at byte ${i} must not be slow`).not.toBe("slow");
      if (outcome === "threw") threw++;
      else {
        returned++;
        // Accepted — but it must never reproduce the original content from corrupted bytes.
        expect(doc.getText("t").toString()).not.toBe("the quick brown fox jumps over the lazy dog");
      }
    }
    // Pin the split, so a wholesale flip from throw to accept cannot pass unnoticed.
    expect(threw + returned).toBe(full.length);
    expect(threw).toBeGreaterThan(returned);
  }, 15_000);

  // ── Pathological structure ────────────────────────────────────────────────
  it("a declared length far larger than the buffer is bounds-checked, not allocated", () => {
    // TWO distinct paths, and an earlier version only exercised the first while claiming the
    // second. `ff*9 7f` throws in the VARINT decoder in 0ms — no length is ever produced, so
    // nothing about allocation is tested; a lib0 that dropped its length bounds-check would
    // have kept that test green.
    const varintOutOfRange = new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]);
    expect(guardedApply(new Y.Doc(), varintOutOfRange).ok).toBe(false);

    // The real path: a well-formed update whose declared STRING LENGTH is in varint range but
    // vastly exceeds the buffer. This is the amplification a hostile peer actually sends.
    const base = Buffer.from("01018de4fbdc06000401017408616263646566676800", "hex");
    const declared = 100_000_000;
    const varint: number[] = [];
    let v = declared;
    while (v > 0x7f) { varint.push((v & 0x7f) | 0x80); v >>>= 7; }
    varint.push(v);
    const inflated = new Uint8Array(base.length - 1 + varint.length);
    inflated.set(base.subarray(0, 10));
    inflated.set(varint, 10);
    inflated.set(base.subarray(11), 10 + varint.length);

    const before = offHeapBytes();
    const outcome = classifyWithBudget(() => {
      Y.applyUpdate(new Y.Doc(), inflated);
    }, 2000);
    const growthMb = (offHeapBytes() - before) / (1024 * 1024);

    expect(outcome).toBe("threw"); // bounds-checked, not allocated
    expect(growthMb, `off-heap grew ${growthMb.toFixed(1)} MiB from a ${inflated.length}-byte input`).toBeLessThan(64);
  }, 10_000);

  it("2000-deep nesting APPLIES SUCCESSFULLY — Yjs does not bound depth, so the gate must", () => {
    const source = new Y.Doc();
    // The clientID is PINNED because the update size depends on it: every item's parent
    // reference encodes the clientID as a varint, so a 1-byte clientID gives 23,880 bytes and a
    // 5-byte one gives 31,880. Yjs mints a random uint32, so PRODUCTION is effectively always
    // the 5-byte case — which is the figure the gate's depth limit must be chosen against.
    source.clientID = 4294967290;
    let map = source.getMap("root");
    for (let depth = 0; depth < 2000; depth++) {
      const child = new Y.Map();
      map.set("child", child);
      map = child;
    }
    const update = Y.encodeStateAsUpdate(source);
    // Exact, now that the clientID is pinned: ~16 bytes/level in the production case, so a
    // 1 MiB update carries roughly 65,000 levels — the size cap is a poor depth bound.
    expect(update.length).toBe(31_880);
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
    // Pinned, not read back: comparing the doc to itself would stay green if the FIRST apply
    // silently did nothing — and ok:true is exactly what this file proves is not evidence.
    const afterFirst = doc.getText("t").toString();
    expect(afterFirst).toBe("the quick brown fox jumps over the lazy dog");
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
