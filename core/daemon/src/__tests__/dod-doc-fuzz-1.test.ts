/**
 * DOD-DOC-FUZZ-1 — Yjs hostile-input measurement (§16.7-7 precondition).
 *
 * The V1 posture for hostile document updates is "cap, catch, contain": a pre-parse SIZE CAP
 * before Yjs sees the bytes, a wrapped apply so a malformed update becomes an ordinary
 * rejection rather than a crash, and structural limits checked on the shadow document before
 * admission. No sandbox process in V1.
 *
 * That posture is only sound if `Y.applyUpdate`'s actual failure modes are THROWS — recoverable
 * at a try/catch boundary — rather than crashes, hangs, or unbounded allocation, which a
 * try/catch cannot contain. This file MEASURES that rather than assuming it. Every case here
 * asserts the observable failure mode, so a Yjs upgrade that turns a throw into a hang breaks
 * the build instead of shipping a denial-of-service into the receive path.
 *
 * These are not "does Yjs work" tests. Each one is a hostile input a peer can put on the wire.
 *
 * The findings drive ACs on DOD-DOC-GATE-1 — see the journal entry for the write-up.
 */

import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import * as Y from "yjs";

/**
 * The planned pre-parse cap. Bytes are rejected on LENGTH before Yjs is invoked at all, so no
 * hostile-input property below has to hold for inputs larger than this.
 */
const PRE_PARSE_SIZE_CAP_BYTES = 1024 * 1024; // 1 MiB

/** Apply an update the way the validation gate will: size-capped, then wrapped. */
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

/** A well-formed update, for the contrast cases and for truncation sources. */
function validUpdate(): Uint8Array {
  const doc = new Y.Doc();
  doc.getText("t").insert(0, "the quick brown fox jumps over the lazy dog");
  doc.getMap("m").set("key", "value");
  doc.getArray("a").insert(0, [1, 2, 3]);
  return Y.encodeStateAsUpdate(doc);
}

/**
 * Run `fn` and classify the outcome. A HANG is the failure mode a try/catch cannot contain, so
 * it is measured explicitly rather than left to the test timeout (which would report as a
 * generic failure without saying which input caused it).
 */
async function classify(fn: () => void, budgetMs = 2000): Promise<"returned" | "threw" | "hung"> {
  const started = Date.now();
  let outcome: "returned" | "threw";
  try {
    fn();
    outcome = "returned";
  } catch {
    outcome = "threw";
  }
  const elapsed = Date.now() - started;
  return elapsed > budgetMs ? "hung" : outcome;
}

describe("DOD-DOC-FUZZ-1: Y.applyUpdate under hostile input", () => {
  // ── Garbage bytes ─────────────────────────────────────────────────────────
  it("random garbage is contained — never a crash, never a hang", async () => {
    const doc = new Y.Doc();
    for (const size of [1, 2, 7, 64, 512, 4096]) {
      for (let trial = 0; trial < 20; trial++) {
        const garbage = new Uint8Array(randomBytes(size));
        const outcome = await classify(() => {
          try {
            Y.applyUpdate(doc, garbage);
          } catch {
            throw new Error("threw");
          }
        });
        expect(outcome, `size=${size} trial=${trial}`).not.toBe("hung");
        // Either it threw (the common case) or Yjs decoded it as a no-op. Both are contained;
        // what matters is that the process survives and the guard reports a typed failure.
        const res = guardedApply(doc, garbage);
        expect(typeof res.ok).toBe("boolean");
      }
    }
  }, 60_000);

  it("all-zero and all-0xff buffers are contained", () => {
    const doc = new Y.Doc();
    for (const fill of [0x00, 0xff]) {
      for (const size of [1, 16, 1024]) {
        const buf = new Uint8Array(size).fill(fill);
        const res = guardedApply(doc, buf);
        expect(typeof res.ok).toBe("boolean");
      }
    }
  });

  // MEASURED, not assumed: the minimum valid Yjs update is TWO bytes — an empty encoded state
  // is `[0, 0]`. A zero-length or one-byte buffer throws "Unexpected end of array", a DECODER
  // error that says nothing about the protocol. So the gate needs a floor as well as a cap, or
  // a peer sending an empty update gets a quarantine reason naming Yjs internals.
  it("an empty or one-byte update THROWS a decoder error — it is not a no-op", () => {
    const doc = new Y.Doc();
    for (const bytes of [new Uint8Array(0), new Uint8Array([0])]) {
      expect(() => Y.applyUpdate(doc, bytes)).toThrow(/Unexpected end of array/);
      const res = guardedApply(doc, bytes);
      expect(res.ok).toBe(false);
    }
  });

  it("two zero bytes IS the minimal valid update — the empty encoded state", () => {
    const doc = new Y.Doc();
    expect(Y.encodeStateAsUpdate(new Y.Doc())).toHaveLength(2);
    expect(guardedApply(doc, new Uint8Array([0, 0])).ok).toBe(true);
  });

  // ── Truncated updates ─────────────────────────────────────────────────────
  //
  // The most likely hostile shape in practice: a valid update cut short. Every prefix of a
  // real update is tried, because a length-prefix decoder reading past its buffer is the
  // classic path to a hang or an unbounded allocation.
  it("EVERY prefix of a valid update is contained", async () => {
    const full = validUpdate();
    expect(full.length).toBeGreaterThan(8);
    for (let cut = 0; cut < full.length; cut++) {
      const doc = new Y.Doc();
      const truncated = full.subarray(0, cut);
      const outcome = await classify(() => {
        Y.applyUpdate(doc, truncated);
      }, 1000);
      expect(outcome, `prefix length ${cut} must not hang`).not.toBe("hung");
      const res = guardedApply(doc, truncated);
      expect(typeof res.ok).toBe("boolean");
    }
  }, 120_000);

  it("a valid update with a corrupted interior byte is contained", async () => {
    const full = validUpdate();
    for (let i = 0; i < full.length; i++) {
      const corrupted = Uint8Array.from(full);
      corrupted[i] = corrupted[i]! ^ 0xff;
      const doc = new Y.Doc();
      const outcome = await classify(() => {
        Y.applyUpdate(doc, corrupted);
      }, 1000);
      expect(outcome, `corrupt at byte ${i} must not hang`).not.toBe("hung");
    }
  }, 120_000);

  // ── Pathological structure ────────────────────────────────────────────────
  //
  // A LENGTH FIELD claiming far more than the buffer holds is the shape that turns a decoder
  // into an allocator. Yjs uses variable-length integers, so an 0x80-continuation run encodes a
  // huge length in few bytes — the cheapest possible amplification for an attacker.
  it("a varint length claiming a huge payload does not allocate unbounded memory", async () => {
    const doc = new Y.Doc();
    // 0xff bytes with the continuation bit set, then a terminator: a maximal varint in 10 bytes.
    const hugeLength = new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]);
    const before = process.memoryUsage().heapUsed;
    const outcome = await classify(() => {
      Y.applyUpdate(doc, hugeLength);
    }, 2000);
    const growthMb = (process.memoryUsage().heapUsed - before) / (1024 * 1024);
    expect(outcome).not.toBe("hung");
    // Generous bound: the point is to catch UNBOUNDED allocation, not to measure precisely.
    expect(growthMb, `heap grew ${growthMb.toFixed(1)} MiB on a 10-byte input`).toBeLessThan(256);
  }, 30_000);

  it("deeply nested structure is contained at the decoder", async () => {
    // Build a genuinely deep document, then apply it to a fresh doc. This measures whether
    // depth alone can exhaust the stack on the RECEIVING side.
    const source = new Y.Doc();
    let map = source.getMap("root");
    for (let depth = 0; depth < 2000; depth++) {
      const child = new Y.Map();
      map.set("child", child);
      map = child;
    }
    const update = Y.encodeStateAsUpdate(source);
    const target = new Y.Doc();
    const outcome = await classify(() => {
      Y.applyUpdate(target, update);
    }, 5000);
    expect(outcome).not.toBe("hung");
    // Whether it returns or throws, the process must survive — that is the containable outcome.
    expect(["returned", "threw"]).toContain(outcome);
  }, 30_000);

  it("a valid update replayed twice is idempotent — no duplication, no error", () => {
    const update = validUpdate();
    const doc = new Y.Doc();
    expect(guardedApply(doc, update).ok).toBe(true);
    const afterFirst = doc.getText("t").toString();
    expect(guardedApply(doc, update).ok).toBe(true);
    expect(doc.getText("t").toString()).toBe(afterFirst);
  });

  // ── The size cap itself ───────────────────────────────────────────────────
  it("the pre-parse cap rejects oversized input BEFORE Yjs sees it", () => {
    const doc = new Y.Doc();
    const oversized = new Uint8Array(PRE_PARSE_SIZE_CAP_BYTES + 1);
    const res = guardedApply(doc, oversized);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("document_update_too_large");
  });

  it("the cap's rejection names the limit, not the exit point", () => {
    const doc = new Y.Doc();
    const res = guardedApply(doc, new Uint8Array(PRE_PARSE_SIZE_CAP_BYTES + 1));
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.reason).toContain("too_large");
      expect(res.reason).not.toContain("undefined");
    }
  });

  // ── The contrast case — the guard must not reject what is valid ───────────
  it("a well-formed update still applies through the same guard", () => {
    const doc = new Y.Doc();
    const res = guardedApply(doc, validUpdate());
    expect(res.ok).toBe(true);
    expect(doc.getText("t").toString()).toBe("the quick brown fox jumps over the lazy dog");
    expect(doc.getMap("m").get("key")).toBe("value");
  });
});
