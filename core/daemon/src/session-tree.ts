/**
 * CELLO Daemon — SessionTree (CELLO-M7-DAEMON-004, Option A)
 *
 * The DAEMON-OWNED per-session Merkle tree. This is the authoritative running
 * transcript of every leaf (sent or received) for a session. Before this story,
 * the daemon "did not maintain the session Merkle tree — the client supplied it"
 * (daemon.ts:568). Option A re-homes ownership here: the daemon is the component
 * that sends and receives every message, so the transcript belongs where the
 * messages flow.
 *
 * Specification (SPARC Phase S):
 *   - A leaf is the 32-byte leaf hash of a message or control entry, in order.
 *     For a message leaf the leaf hash is content_hash = SHA-256(0x00 || content)
 *     (msgLeafHash, RFC 6962 §2.1 leaf hashing). For a control leaf (SEAL) the
 *     leaf hash is SHA-256(0x02 || canonical_bytes) (ctrlLeafHash). Both sides of
 *     a session compute the SAME leaf hash for the SAME message, so appending the
 *     SAME leaves in the SAME order yields the SAME root (AC-002).
 *   - The root is recomputed over all leaves after every append (RFC 6962 §2.1,
 *     left-balanced binary Merkle tree). Empty tree root = SHA-256("").
 *   - The tree is serializable to/from an ordered list of leaf-hash hex strings so
 *     it can be persisted to SQLCipher and reloaded across a daemon restart (AC-007).
 *
 * Pseudocode (SPARC Phase P):
 *   appendLeafHash(kind, hashHex):
 *     1. push {kind, hashHex} onto leaves
 *     2. return { leafIndex: leaves.length - 1, newRootHex: rootHex() }
 *   rootHex():
 *     1. build = buildMerkleTree(leaves.map(l => {kind:"hash", data: bytes(l.hashHex)}))
 *     2. return hex(merkleRoot(build))   // empty → hex(SHA-256(""))
 *   fromLeaves(leaves): reconstruct from persisted ordered list.
 *
 * Crypto refs: RFC 6962 §2.1 (Merkle hash trees), FIPS 180-4 (SHA-256).
 */

import { buildMerkleTree, merkleRoot, type LeafInput } from "@cello-protocol/crypto";

export type SessionTreeLeafKind = "msg" | "ctrl";

export interface SessionTreeLeaf {
  /** Domain of the leaf — metadata only; the stored hash already encodes the prefix. */
  readonly kind: SessionTreeLeafKind;
  /** 32-byte leaf hash, hex-encoded. */
  readonly hashHex: string;
}

/**
 * A daemon-owned per-session Merkle tree. Leaves are stored as pre-computed
 * 32-byte leaf hashes (hex), so reconstruction is exact regardless of the
 * original payload — the daemon never needs the plaintext to recompute the root.
 */
export class SessionTree {
  readonly #leaves: SessionTreeLeaf[];

  private constructor(leaves: SessionTreeLeaf[]) {
    this.#leaves = leaves;
  }

  /** Construct an empty tree. */
  static empty(): SessionTree {
    return new SessionTree([]);
  }

  /** Reconstruct a tree from a persisted, ordered list of leaves (AC-007). */
  static fromLeaves(leaves: readonly SessionTreeLeaf[]): SessionTree {
    return new SessionTree(leaves.map((l) => ({ kind: l.kind, hashHex: l.hashHex })));
  }

  /** Number of leaves currently in the tree. */
  size(): number {
    return this.#leaves.length;
  }

  /** Ordered copy of the leaves (for persistence / inspection). */
  leaves(): SessionTreeLeaf[] {
    return this.#leaves.map((l) => ({ kind: l.kind, hashHex: l.hashHex }));
  }

  /**
   * Append a leaf (by its pre-computed 32-byte leaf-hash hex) and advance the root.
   * @returns the new leaf's index and the recomputed root hex.
   */
  appendLeafHash(kind: SessionTreeLeafKind, hashHex: string): { leafIndex: number; newRootHex: string } {
    if (!/^[0-9a-f]{64}$/.test(hashHex)) {
      throw new Error(`SessionTree.appendLeafHash: hashHex must be 64 lowercase hex chars (32 bytes), got length ${hashHex.length}`);
    }
    this.#leaves.push({ kind, hashHex });
    return { leafIndex: this.#leaves.length - 1, newRootHex: this.rootHex() };
  }

  /**
   * Recompute and return the current Merkle root as hex.
   * Empty tree → hex(SHA-256("")) per RFC 6962 §2.1.
   */
  rootHex(): string {
    const inputs: LeafInput[] = this.#leaves.map((l) => ({
      kind: "hash" as const,
      data: hexToBytes(l.hashHex),
    }));
    const tree = buildMerkleTree(inputs);
    return bytesToHex(merkleRoot(tree));
  }

  /**
   * SESSION-002: the Merkle root this tree WOULD have if one more leaf (hashHex) were
   * appended — WITHOUT mutating the tree. Used to compute the reported_root for a unilateral
   * seal: the post-SEAL-ctrl-leaf root the directory rebuilds from the relay's content-hash
   * chain and verifies, without advancing the durable tree / message_count.
   */
  rootWithAppendedHex(hashHex: string): string {
    if (!/^[0-9a-f]{64}$/.test(hashHex)) {
      throw new Error(`SessionTree.rootWithAppendedHex: hashHex must be 64 lowercase hex chars (32 bytes), got length ${hashHex.length}`);
    }
    const inputs: LeafInput[] = [...this.#leaves, { kind: "ctrl" as const, hashHex }].map((l) => ({
      kind: "hash" as const,
      data: hexToBytes(l.hashHex),
    }));
    return bytesToHex(merkleRoot(buildMerkleTree(inputs)));
  }
}

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}
