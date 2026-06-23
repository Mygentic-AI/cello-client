/**
 * DOD-LEG-2 (SI-002) — client-side content-frontier re-derivation unit tests.
 *
 * The client re-derives each party's content_frontier_seq from the SIGNED leaves and rejects
 * a published frontier that exceeds what the leaves support (an inflating directory). These
 * tests pin: honest re-derivation, the inflation guard, and the forged-leaf rejection. The
 * teeth: an implementation that skips signature verification, or that accepts any published
 * value, fails these.
 */
import { describe, it, expect } from "vitest";
import { generateKeypair } from "@cello-protocol/crypto";
import { encodeStructure1 } from "../session-relay-client.js";
import { reDeriveFrontiers, findInflatedFrontier, type SealFrontierLeaf } from "../seal-frontier-verify.js";

async function signedLeaf(
  kp: ReturnType<typeof generateKeypair>,
  lastSeenSeq: number,
  opts: { corruptSig?: boolean } = {},
): Promise<SealFrontierLeaf> {
  const pubkey = await kp.getPublicKey();
  const s1 = encodeStructure1(new Uint8Array(32), pubkey, new Uint8Array(16), lastSeenSeq, 1_700_000_000_000);
  let sig = await kp.sign(s1);
  if (opts.corruptSig) { sig = new Uint8Array(sig); sig[0] ^= 0xff; }
  return { structure1_cbor: s1, sender_pubkey: pubkey, sender_signature: sig };
}

describe("DOD-LEG-2: reDeriveFrontiers", () => {
  it("re-derives the max signed last_seen_seq per party from signed leaves", async () => {
    const a = generateKeypair();
    const b = generateKeypair();
    const aHex = Buffer.from(await a.getPublicKey()).toString("hex").toLowerCase();
    const bHex = Buffer.from(await b.getPublicKey()).toString("hex").toLowerCase();

    const res = reDeriveFrontiers([
      await signedLeaf(a, 1),
      await signedLeaf(a, 2), // A's max is 2
      await signedLeaf(b, 3), // B's max is 3
    ]);
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.frontiers.get(aHex)).toBe(2);
    expect(res.frontiers.get(bHex)).toBe(3);
  });

  it("rejects a forged leaf (signature does not verify)", async () => {
    const a = generateKeypair();
    const res = reDeriveFrontiers([
      await signedLeaf(a, 1),
      await signedLeaf(a, 9, { corruptSig: true }), // a fabricated high frontier the directory can't sign
    ]);
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.reason).toBe("leaf_signature_invalid");
  });
});

describe("DOD-LEG-2: findInflatedFrontier", () => {
  it("returns null when every published frontier matches the re-derived value (honest)", async () => {
    const a = generateKeypair();
    const b = generateKeypair();
    const aHex = Buffer.from(await a.getPublicKey()).toString("hex").toLowerCase();
    const bHex = Buffer.from(await b.getPublicKey()).toString("hex").toLowerCase();
    const res = reDeriveFrontiers([await signedLeaf(a, 2), await signedLeaf(b, 3)]);
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const inflated = findInflatedFrontier(
      [{ pubkey: aHex, content_frontier_seq: 2 }, { pubkey: bHex, content_frontier_seq: 3 }],
      res.frontiers,
    );
    expect(inflated).toBeNull();
  });

  it("flags a party whose published frontier exceeds its signed leaves (inflation)", async () => {
    const a = generateKeypair();
    const aHex = Buffer.from(await a.getPublicKey()).toString("hex").toLowerCase();
    const res = reDeriveFrontiers([await signedLeaf(a, 2)]); // A really only reached 2
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const inflated = findInflatedFrontier([{ pubkey: aHex, content_frontier_seq: 15 }], res.frontiers);
    expect(inflated).not.toBeNull();
    expect(inflated!.party.toLowerCase()).toBe(aHex);
    expect(inflated!.publishedFrontier).toBe(15);
    expect(inflated!.derivedFrontier).toBe(2);
  });

  it("equal published == derived is honest (not flagged)", async () => {
    const a = generateKeypair();
    const aHex = Buffer.from(await a.getPublicKey()).toString("hex").toLowerCase();
    const res = reDeriveFrontiers([await signedLeaf(a, 4)]);
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(findInflatedFrontier([{ pubkey: aHex, content_frontier_seq: 4 }], res.frontiers)).toBeNull();
  });
});
