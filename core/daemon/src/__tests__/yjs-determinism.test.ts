/**
 * M14 — the clientID determinism rule, enforced.
 *
 * ── CAN WE MAKE Yjs's CLIENT ID DETERMINISTIC? Two answers, and they are opposite. ────────────
 *
 * **In PRODUCTION: no, and deliberately not.** §14 is explicit — "let Yjs generate its own random
 * clientID per live `Y.Doc`; never derive it from agent identity, never persist and restore one."
 * Yjs identifies every operation by `(clientID, clock)` and assumes that pair is globally unique.
 * Two live documents sharing a clientID mint colliding ids for different operations, and
 * DOD-DOC-FUZZ-1 MEASURED what that costs: the colliding writer silently wins, the honest client's
 * update is accepted-and-dropped, and the document becomes a splice of two authors — with an EMPTY
 * pending set, so the gate's dependency check cannot see it, and no error on any path. A derived
 * or persisted clientID is precisely how two live docs come to share one. The randomness is a
 * safety property, not an inconvenience.
 *
 * **In TESTS: yes, and it must be.** Everything a test asserts about a Yjs result is either a
 * SIZE (the clientID's varint width changes it) or an ORDER (concurrent operations are tie-broken
 * by clientID). Leave it random and the test asks a question with one right answer and accepts a
 * coin flip. That cost four separate incidents in M14:
 *
 *   1. a deep-nesting byte count that two measurements disagreed on (23,880 vs 31,880);
 *   2. a colliding-clientID splice whose result depended on the draw;
 *   3. the write path's overlap flag, whose assertion survived a BROKEN comparison 17 runs in 40;
 *   4. `validUpdate()`'s length — 83 or 84 bytes, ~1 run in 16 — which surfaced as an
 *      unreproducible full-suite failure and took a captured log to identify.
 *
 * All four are the same mechanism wearing different clothes. So the rule is: **a test that
 * asserts a size or an order over a `Y.Doc` MUST pin the clientID**, and where a tie-break decides
 * the outcome it must run BOTH orderings rather than whichever one it happened to draw.
 *
 * This file is the enforcement. It is a guard test rather than a lint rule because the property is
 * about intent — a doc whose size and order are never asserted needs no pin — and a grep for the
 * assertion is what catches the real cases.
 */

import { describe, it, expect } from "vitest";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import * as Y from "yjs";

const TEST_DIR = new URL(".", import.meta.url).pathname;

/** Pin a document's clientID. The one legitimate use of assigning it, and only in tests. */
export function pinnedDoc(clientId: number): Y.Doc {
  const doc = new Y.Doc();
  doc.clientID = clientId;
  return doc;
}

/** A clientID whose varint encodes in 5 bytes — the case production effectively always draws. */
export const WIDE_CLIENT_ID = 4_294_967_290;
/** A clientID whose varint encodes in fewer bytes, which is what makes sizes differ. */
export const NARROW_CLIENT_ID = 1;

describe("Yjs clientID — why production must NOT pin it", () => {
  it("two live docs sharing a clientID splice two authors together, with an empty pending set", () => {
    const honest = pinnedDoc(777);
    honest.getText("t").insert(0, "honest content");
    const forger = pinnedDoc(777);
    forger.getText("t").insert(0, "FORGED");

    const target = new Y.Doc();
    Y.applyUpdate(target, Y.encodeStateAsUpdate(forger));
    Y.applyUpdate(target, Y.encodeStateAsUpdate(honest));

    // Neither party's content, and nothing anywhere reports a problem — which is why §14 forbids
    // deriving or persisting a clientID in production, however convenient determinism would be.
    expect(target.getText("t").toString()).toContain("FORGED");
    expect(target.getText("t").toString()).not.toBe("honest content");
    expect(target.store.pendingStructs).toBeNull();
  });
});

describe("Yjs clientID — why every test that asserts a size or order MUST pin it", () => {
  it("the SAME document content encodes to different byte lengths under different clientIDs", () => {
    const build = (clientId: number): number => {
      const doc = pinnedDoc(clientId);
      doc.getText("t").insert(0, "the quick brown fox jumps over the lazy dog");
      doc.getMap("m").set("key", "value");
      return Y.encodeStateAsUpdate(doc).length;
    };
    // Identical content, different sizes — this is the mechanism behind the 83-vs-84 failure and
    // the 23,880-vs-31,880 disagreement.
    expect(build(NARROW_CLIENT_ID)).not.toBe(build(WIDE_CLIENT_ID));
  });

  it("concurrent inserts resolve in the order the clientIDs decide, not the order they were made", () => {
    const base = pinnedDoc(1);
    base.getText("t").insert(0, "base");
    const state = Y.encodeStateAsUpdate(base);

    const resultWith = (peerId: number): string => {
      // The base uses a DIFFERENT id from either party on purpose. Yjs RE-MINTS a document's
      // clientID when it applies an update authored under that same id ("Changed the client-id
      // because another client seems to be using it") — a real built-in collision defence, though
      // not one that saves the FUZZ-1 splice, where neither doc sees the other's update before
      // writing. Pinning a doc to the base's id silently defeats the pinning.
      const mine = pinnedDoc(1000);
      Y.applyUpdate(mine, state);
      const peer = pinnedDoc(peerId);
      Y.applyUpdate(peer, state);
      mine.getText("t").insert(4, "-MINE");
      peer.getText("t").insert(4, "-PEER");
      Y.applyUpdate(mine, Y.encodeStateAsUpdate(peer));
      return mine.getText("t").toString();
    };

    // Same operations, opposite outcomes — decided purely by the clientID draw. A test that runs
    // only one of these is asserting a coin flip.
    expect(resultWith(500)).toBe("base-PEER-MINE");
    expect(resultWith(5_000_000)).toBe("base-MINE-PEER");
  });
});

describe("Yjs clientID — the rule is enforced, not just documented", () => {
  it("every M14 document test that asserts a byte length pins its clientID", async () => {
    const all = await readdir(TEST_DIR);
    const files = all.filter((f) => f.startsWith("document-") || f.startsWith("dod-doc-"));
    // A guard that scans zero files passes vacuously, so the empty case must fail LOUDLY and say
    // where it looked. A bare `toBeGreaterThan(0)` reports "expected 0 to be greater than 0",
    // which names neither the directory nor whether the read itself came back empty — and this
    // assertion failed exactly once in six full-suite runs and has not reproduced since. If it
    // recurs, this message is the difference between a diagnosis and another unexplained number.
    expect(
      files.length,
      `no document test files found under ${TEST_DIR} — the readdir returned ${all.length} ` +
        `entr${all.length === 1 ? "y" : "ies"}, so this guard was about to pass over nothing`,
    ).toBeGreaterThan(0);

    const offenders: string[] = [];
    for (const file of files) {
      const source = await readFile(join(TEST_DIR, file), "utf8");
      // A test asserting an exact byte length over Yjs output is size-sensitive by definition.
      // An EXACT length assertion over an ENCODED UPDATE is size-sensitive by definition. The
      // first version matched any multi-digit `toBe(...)` and flagged two files whose numbers
      // were nesting depths and character counts — clientID-independent. A guard with false
      // positives gets disabled, so it asks the narrow question.
      const encodesUpdate = /encodeStateAsUpdate|validUpdate\(/.test(source);
      const assertsLength = encodesUpdate && /\.length\)\s*\.toBe\(\s*\d/.test(source);
      const pinsClientId = /clientID\s*=/.test(source);
      if (assertsLength && !pinsClientId) offenders.push(file);
    }

    expect(
      offenders,
      `these tests assert a size over Yjs output without pinning a clientID, so they are a coin ` +
        `flip: ${offenders.join(", ")}`,
    ).toEqual([]);
  });
});
