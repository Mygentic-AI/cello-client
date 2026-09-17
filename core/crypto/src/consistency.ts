/**
 * RFC 6962 Merkle Consistency Proofs
 *
 * A consistency proof shows that the log at size n is a genuine extension of the log at size m:
 * the first m leaves are unchanged, nothing inserted, removed, or rewritten. This is what lets a
 * broadcast channel prove it never rewrote its history. Inclusion proofs live in merkle.ts.
 *
 * References:
 *   RFC 6962 §2.1     — Merkle Tree Hash (MTH), split at the largest power of two below n
 *   RFC 6962 §2.1.2   — Merkle Consistency Proofs (generation: PROOF / SUBPROOF)
 *   RFC 9162 §2.1.4.2 — Verifying consistency between two tree heads
 *
 * PSEUDOCODE (Phase P)
 * ====================
 * --- consistencyProof(leafHashes, m) --- called as subProof(m, 0, n, true)
 *   subProof(m, lo, hi, isOriginalSubtree):
 *     n = hi - lo
 *     if m == n: return isOriginalSubtree ? [] : [MTH(lo, hi)]
 *     k = largest power of two < n
 *     if m <= k: return subProof(m, lo, lo + k, isOriginalSubtree) ++ [MTH(lo + k, hi)]
 *     else:      return subProof(m - k, lo + k, hi, false) ++ [MTH(lo, lo + k)]
 *
 * --- verifyConsistency(m, oldRoot, n, newRoot, proof) --- RFC 9162 §2.1.4.2
 *   any hash not 32 bytes → false; m < 1, n < 1, m > n → false
 *   m == n → proof empty AND oldRoot == newRoot
 *   path = m is a power of two ? [oldRoot, ...proof] : proof; empty path → false
 *   fn = m - 1; sn = n - 1; while LSB(fn): shift both right
 *   fr = sr = path[0]
 *   for c in path[1..]:
 *     sn == 0 → false
 *     if LSB(fn) or fn == sn:
 *       fr = H(c, fr); sr = H(c, sr)
 *       if not LSB(fn): while fn != 0 and not LSB(fn): shift both right
 *     else: sr = H(sr, c)
 *     shift both right
 *   return fr == oldRoot AND sr == newRoot AND sn == 0
 *
 * Tree shape: splitting at the largest power of two below n yields the same roots as merkle.ts's
 * pair-and-promote construction (an odd last node is promoted, never duplicated).
 */

import { nodeHash } from "./hashing.js";

/**
 * Consistency proof that leafHashes[0:oldSize) is a prefix of the log leafHashes[0:n).
 * leafHashes are 32-byte LEAF hashes (already domain-prefixed by the caller, as everywhere
 * in merkle.ts's { kind: "hash" } leaves). Throws RangeError if oldSize < 1, oldSize > n,
 * or any hash is not 32 bytes. Returns [] when oldSize === n.
 */
export function consistencyProof(
  leafHashes: readonly Uint8Array[],
  oldSize: number,
): Uint8Array[] {
  const n = leafHashes.length;
  if (!Number.isInteger(oldSize) || oldSize < 1 || oldSize > n) {
    throw new RangeError(
      `consistencyProof: oldSize ${oldSize} out of range for log of size ${n}`,
    );
  }
  for (let i = 0; i < n; i++) {
    if (leafHashes[i].length !== 32) {
      throw new RangeError(
        `consistencyProof: leaf hash at index ${i} is ${leafHashes[i].length} bytes, expected 32`,
      );
    }
  }
  return subProof(leafHashes, oldSize, 0, n, true);
}

/**
 * Verify that (newSize, newRoot) extends (oldSize, oldRoot). Never throws; malformed
 * input returns false. oldSize === newSize requires an empty proof and equal roots.
 */
export function verifyConsistency(
  oldSize: number,
  oldRoot: Uint8Array,
  newSize: number,
  newRoot: Uint8Array,
  proof: readonly Uint8Array[],
): boolean {
  if (oldRoot.length !== 32 || newRoot.length !== 32) return false;
  for (const entry of proof) {
    if (entry.length !== 32) return false;
  }
  if (oldSize < 1 || newSize < 1 || oldSize > newSize) return false;

  if (oldSize === newSize) {
    return proof.length === 0 && constantTimeEqual(oldRoot, newRoot);
  }

  const path = isPowerOfTwo(oldSize) ? [oldRoot, ...proof] : proof;
  if (path.length === 0) return false;

  let fn = oldSize - 1;
  let sn = newSize - 1;
  while ((fn & 1) === 1) {
    fn = fn >>> 1;
    sn = sn >>> 1;
  }

  let fr = path[0];
  let sr = path[0];
  for (let i = 1; i < path.length; i++) {
    const c = path[i];
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      if ((fn & 1) === 0) {
        while (fn !== 0 && (fn & 1) === 0) {
          fn = fn >>> 1;
          sn = sn >>> 1;
        }
      }
    } else {
      sr = nodeHash(sr, c);
    }
    fn = fn >>> 1;
    sn = sn >>> 1;
  }

  return constantTimeEqual(fr, oldRoot) && constantTimeEqual(sr, newRoot) && sn === 0;
}

/** RFC 6962 §2.1.2 SUBPROOF over the absolute range [lo, hi). */
function subProof(
  leafHashes: readonly Uint8Array[],
  m: number,
  lo: number,
  hi: number,
  isOriginalSubtree: boolean,
): Uint8Array[] {
  const n = hi - lo;
  if (m === n) {
    // The verifier already holds the root of an original subtree; anything else must be sent.
    return isOriginalSubtree ? [] : [subtreeRoot(leafHashes, lo, hi)];
  }
  const k = largestPowerOfTwoBelow(n);
  if (m <= k) {
    return [
      ...subProof(leafHashes, m, lo, lo + k, isOriginalSubtree),
      subtreeRoot(leafHashes, lo + k, hi),
    ];
  }
  return [
    ...subProof(leafHashes, m - k, lo + k, hi, false),
    subtreeRoot(leafHashes, lo, lo + k),
  ];
}

/** RFC 6962 §2.1 MTH over leafHashes[lo, hi); the range is never empty. */
function subtreeRoot(leafHashes: readonly Uint8Array[], lo: number, hi: number): Uint8Array {
  if (hi - lo === 1) return leafHashes[lo];
  const split = lo + largestPowerOfTwoBelow(hi - lo);
  return nodeHash(subtreeRoot(leafHashes, lo, split), subtreeRoot(leafHashes, split, hi));
}

/** Largest power of two strictly less than n, for n >= 2. */
function largestPowerOfTwoBelow(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function isPowerOfTwo(m: number): boolean {
  return m > 0 && (m & (m - 1)) === 0;
}

/**
 * Constant-time byte array comparison to prevent timing side-channels.
 * A local copy of merkle.ts's private helper.
 */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
