/**
 * Tests for RFC 6962 consistency proofs (M16 order 001-TREE, DOD-M16-CT-1).
 *
 * The property under test: a log at size n is a genuine extension of the log at size m —
 * nothing inserted, removed, or rewritten. Expected values come from the separately-tested
 * buildMerkleTree + merkleRoot oracle, or from hand-built nodeHash expressions. Never from the
 * code under test. Real SHA-256 throughout — no mocks.
 *
 * References:
 *   RFC 6962 §2.1.2   — consistency proof generation
 *   RFC 9162 §2.1.4.2 — consistency proof verification
 */

import {
  setupV3Tests,
  describe,
  it,
  expect,
} from "@claude-flow/testing";
import { msgLeafHash, nodeHash } from "../hashing.js";
import { buildMerkleTree, merkleRoot } from "../merkle.js";
import { consistencyProof, verifyConsistency } from "../consistency.js";

setupV3Tests();

// ── Helpers ────────────────────────────────────────────────────────────────

const toHex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

const makeLeaves = (n: number): Uint8Array[] =>
  Array.from({ length: n }, (_, i) => msgLeafHash(new TextEncoder().encode("leaf-" + i)));

/** The independent oracle: root of a tree over pre-computed leaf hashes. */
const rootOf = (hashes: readonly Uint8Array[]): Uint8Array =>
  merkleRoot(buildMerkleTree(hashes.map((h) => ({ kind: "hash" as const, data: h }))));

const flipByte = (b: Uint8Array, i = 0): Uint8Array => {
  const copy = Uint8Array.from(b);
  copy[i] ^= 0x01;
  return copy;
};

// ── Tests ──────────────────────────────────────────────────────────────────

describe("consistency proofs (RFC 6962 §2.1.2 / RFC 9162 §2.1.4.2)", () => {
  it("exhaustive: every (m, n) with 1 <= m <= n <= 32 round-trips", () => {
    const all = makeLeaves(32);
    let pairs = 0;
    for (let n = 1; n <= 32; n++) {
      const leaves = all.slice(0, n);
      const newRoot = rootOf(leaves);
      for (let m = 1; m <= n; m++) {
        const oldRoot = rootOf(leaves.slice(0, m));
        const proof = consistencyProof(leaves, m);
        expect(verifyConsistency(m, oldRoot, n, newRoot, proof), `m=${m} n=${n}`).toBe(true);
        pairs++;
      }
    }
    expect(pairs).toBe(528);
  });

  it("worked example m=3 n=7 produces the exact RFC path", () => {
    const L = makeLeaves(7);
    const expected = [L[2], L[3], nodeHash(L[0], L[1]), nodeHash(nodeHash(L[4], L[5]), L[6])];
    const proof = consistencyProof(L, 3);
    expect(proof.map(toHex)).toEqual(expected.map(toHex));
  });

  it("m === n requires empty proof and equal roots", () => {
    const leaves = makeLeaves(6);
    const root = rootOf(leaves);
    const otherRoot = rootOf(makeLeaves(7));
    expect(consistencyProof(leaves, 6)).toEqual([]);
    expect(verifyConsistency(6, root, 6, root, [])).toBe(true);
    expect(verifyConsistency(6, root, 6, root, [new Uint8Array(32)])).toBe(false);
    expect(verifyConsistency(6, root, 6, otherRoot, [])).toBe(false);
  });

  it("power-of-two boundary m=4 n=7", () => {
    const L = makeLeaves(7);
    const proof = consistencyProof(L, 4);
    expect(proof.map(toHex)).toEqual([toHex(nodeHash(nodeHash(L[4], L[5]), L[6]))]);
    expect(verifyConsistency(4, rootOf(L.slice(0, 4)), 7, rootOf(L), proof)).toBe(true);
  });

  describe("tampering, m=5 n=13", () => {
    const fixture = () => {
      const leaves = makeLeaves(13);
      return {
        oldRoot: rootOf(leaves.slice(0, 5)),
        newRoot: rootOf(leaves),
        proof: consistencyProof(leaves, 5),
      };
    };

    it("tampered newRoot fails", () => {
      const { oldRoot, newRoot, proof } = fixture();
      expect(verifyConsistency(5, oldRoot, 13, newRoot, proof)).toBe(true);
      expect(verifyConsistency(5, oldRoot, 13, flipByte(newRoot), proof)).toBe(false);
    });

    it("tampered oldRoot fails", () => {
      const { oldRoot, newRoot, proof } = fixture();
      expect(verifyConsistency(5, flipByte(oldRoot), 13, newRoot, proof)).toBe(false);
    });

    it("tampered proof entry fails", () => {
      const { oldRoot, newRoot, proof } = fixture();
      expect(proof.length).toBeGreaterThan(0);
      for (let i = 0; i < proof.length; i++) {
        const tampered = proof.slice();
        tampered[i] = flipByte(proof[i], 31);
        expect(verifyConsistency(5, oldRoot, 13, newRoot, tampered), `entry ${i}`).toBe(false);
      }
    });

    it("truncated and extended proofs fail", () => {
      const { oldRoot, newRoot, proof } = fixture();
      expect(verifyConsistency(5, oldRoot, 13, newRoot, proof.slice(0, -1))).toBe(false);
      expect(
        verifyConsistency(5, oldRoot, 13, newRoot, [...proof, proof[proof.length - 1]]),
      ).toBe(false);
    });
  });

  it("an unchanged root claimed as a grown log fails", () => {
    // The extended proof in test 8 dies on the in-loop sn == 0 check. This is the case only the
    // FINAL sn == 0 check rejects: a power-of-two old size, an empty proof, and the old root
    // presented as the root of a larger log — the path is [oldRoot] and the loop never runs.
    const leaves = makeLeaves(7);
    const oldRoot = rootOf(leaves.slice(0, 4));
    expect(verifyConsistency(4, oldRoot, 7, oldRoot, [])).toBe(false);
  });

  it("a rewritten history fails", () => {
    const leaves = makeLeaves(13);
    const oldRoot = rootOf(leaves.slice(0, 5));
    const rewritten = leaves.slice();
    rewritten[2] = msgLeafHash(new TextEncoder().encode("history-rewritten"));
    const newRoot = rootOf(rewritten);
    const proof = consistencyProof(rewritten, 5);
    expect(verifyConsistency(5, oldRoot, 13, newRoot, proof)).toBe(false);
  });

  it("malformed input returns false, never throws", () => {
    const leaves = makeLeaves(13);
    const oldRoot = rootOf(leaves.slice(0, 5));
    const newRoot = rootOf(leaves);
    const proof = consistencyProof(leaves, 5);
    const short = proof.slice();
    short[0] = new Uint8Array(31);
    expect(verifyConsistency(0, oldRoot, 13, newRoot, proof)).toBe(false);
    expect(verifyConsistency(5, oldRoot, 0, newRoot, proof)).toBe(false);
    expect(verifyConsistency(13, oldRoot, 5, newRoot, proof)).toBe(false);
    expect(verifyConsistency(5, new Uint8Array(31), 13, newRoot, proof)).toBe(false);
    expect(verifyConsistency(5, oldRoot, 13, newRoot, short)).toBe(false);
    expect(verifyConsistency(5, oldRoot, 13, newRoot, [])).toBe(false);
  });

  it("consistencyProof rejects bad input with RangeError", () => {
    const leaves = makeLeaves(5);
    expect(() => consistencyProof(leaves, 0)).toThrow(RangeError);
    expect(() => consistencyProof(leaves, 6)).toThrow(RangeError);
    const bad = leaves.slice();
    bad[3] = new Uint8Array(33);
    expect(() => consistencyProof(bad, 2)).toThrow(RangeError);
  });
});
