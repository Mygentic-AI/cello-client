/**
 * CELLO-M7-DAEMON-004 — SessionTree (daemon-owned Merkle tree)
 *
 * Specification (SPARC Phase S) — the daemon OWNS the per-session Merkle tree.
 *
 * AC-002 (mechanism): two trees that append the SAME ordered leaf hashes report
 *   the SAME root. This is the cross-process root-agreement primitive — both
 *   daemons compute content_hash = SHA-256(0x00 || content) identically, so the
 *   sequence of appends produces a byte-identical root. No external party supplies
 *   the root.
 *
 * AC-007 (mechanism): a tree reconstructed from a persisted ordered leaf list has
 *   the same size and the same root as the original — the transcript survives the
 *   restart boundary.
 *
 * SI-001 (mechanism): the root is computed ONLY from the appended leaves; there is
 *   no setter that injects a root. Reconstruction is exact from the leaves alone.
 *
 * Crypto refs: RFC 6962 §2.1, FIPS 180-4.
 */

import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { SessionTree } from "../session-tree.js";

function msgLeafHashHex(content: Uint8Array): string {
  return createHash("sha256").update(new Uint8Array([0x00])).update(content).digest("hex");
}

function emptySha256Hex(): string {
  return createHash("sha256").update(new Uint8Array(0)).digest("hex");
}

describe("DAEMON-004: SessionTree", () => {
  it("empty tree root is SHA-256(\"\") per RFC 6962 §2.1", () => {
    const tree = SessionTree.empty();
    expect(tree.size()).toBe(0);
    expect(tree.rootHex()).toBe(emptySha256Hex());
  });

  it("appendLeafHash advances the root and returns the leaf index", () => {
    const tree = SessionTree.empty();
    const rootBefore = tree.rootHex();
    const h1 = msgLeafHashHex(new TextEncoder().encode("hello"));
    const r1 = tree.appendLeafHash("msg", h1);
    expect(r1.leafIndex).toBe(0);
    expect(tree.size()).toBe(1);
    expect(r1.newRootHex).not.toBe(rootBefore);
    // Single-leaf tree: root IS the leaf hash (RFC 6962 §2.1).
    expect(r1.newRootHex).toBe(h1);

    const h2 = msgLeafHashHex(new TextEncoder().encode("world"));
    const r2 = tree.appendLeafHash("msg", h2);
    expect(r2.leafIndex).toBe(1);
    expect(tree.size()).toBe(2);
    expect(r2.newRootHex).not.toBe(r1.newRootHex);
  });

  it("AC-002: two trees with the SAME ordered leaves report the SAME root", () => {
    const contents = ["alice-1", "bob-1", "alice-2", "bob-2", "alice-3"];
    const a = SessionTree.empty();
    const b = SessionTree.empty();
    for (const c of contents) {
      const h = msgLeafHashHex(new TextEncoder().encode(c));
      a.appendLeafHash("msg", h);
      b.appendLeafHash("msg", h);
    }
    expect(a.size()).toBe(5);
    expect(b.size()).toBe(5);
    expect(a.rootHex()).toBe(b.rootHex());
  });

  it("AC-002: leaf ORDER is load-bearing — different order, different root", () => {
    const h1 = msgLeafHashHex(new TextEncoder().encode("one"));
    const h2 = msgLeafHashHex(new TextEncoder().encode("two"));
    const a = SessionTree.empty();
    a.appendLeafHash("msg", h1);
    a.appendLeafHash("msg", h2);
    const b = SessionTree.empty();
    b.appendLeafHash("msg", h2);
    b.appendLeafHash("msg", h1);
    expect(a.rootHex()).not.toBe(b.rootHex());
  });

  it("AC-007 / SI-001: fromLeaves reconstructs an identical tree (size + root) from the leaf list alone", () => {
    const original = SessionTree.empty();
    for (const c of ["m1", "m2", "m3", "m4"]) {
      original.appendLeafHash("msg", msgLeafHashHex(new TextEncoder().encode(c)));
    }
    // Add a control (SEAL) leaf to exercise mixed kinds.
    original.appendLeafHash("ctrl", createHash("sha256").update(new Uint8Array([0x02])).update(new TextEncoder().encode("SEAL")).digest("hex"));

    const persisted = original.leaves();
    const reloaded = SessionTree.fromLeaves(persisted);
    expect(reloaded.size()).toBe(original.size());
    expect(reloaded.rootHex()).toBe(original.rootHex());
  });

  it("appendLeafHash rejects a non-32-byte hex hash", () => {
    const tree = SessionTree.empty();
    expect(() => tree.appendLeafHash("msg", "deadbeef")).toThrow(/64 lowercase hex/);
  });
});
