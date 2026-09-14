import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { computeChainAnchor, computeGenesisPrevRoot } from "../session.js";

const G = computeGenesisPrevRoot(new Uint8Array(32).fill(1), new Uint8Array(32).fill(2), new Uint8Array(16).fill(3), 1_789_000_000_000);

describe("computeChainAnchor — the opening ceremony is in the chain", () => {
  it("is SHA-256(domain || genesis || signature), fixed bytes", () => {
    const sig = new Uint8Array(64).fill(9);
    const expected = createHash("sha256").update("cello/chain-anchor/v1").update(G).update(sig).digest();
    expect(Buffer.from(computeChainAnchor(G, sig)).equals(expected)).toBe(true);
  });

  it("a different signature gives a different first link — the chain cannot start without the real one", () => {
    const a = computeChainAnchor(G, new Uint8Array(64).fill(9));
    const b = computeChainAnchor(G, new Uint8Array(64).fill(8));
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
    expect(Buffer.from(a).equals(Buffer.from(G))).toBe(false);
  });

  it("refuses wrong-width inputs rather than hashing them", () => {
    expect(() => computeChainAnchor(G, new Uint8Array(63))).toThrow(/64 bytes/);
    expect(() => computeChainAnchor(new Uint8Array(31), new Uint8Array(64))).toThrow(/32 bytes/);
  });
});
