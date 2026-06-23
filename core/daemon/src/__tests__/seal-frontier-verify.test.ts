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

const SID = new Uint8Array(16).fill(7); // the session being sealed

async function signedLeaf(
  kp: ReturnType<typeof generateKeypair>,
  lastSeenSeq: number,
  opts: { corruptSig?: boolean; sessionId?: Uint8Array } = {},
): Promise<SealFrontierLeaf> {
  const pubkey = await kp.getPublicKey();
  const s1 = encodeStructure1(new Uint8Array(32), pubkey, opts.sessionId ?? SID, lastSeenSeq, 1_700_000_000_000);
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
    ], SID);
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
    ], SID);
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.reason).toBe("leaf_signature_invalid");
  });

  it("rejects a leaf from a DIFFERENT session (cross-session replay)", async () => {
    // A malicious directory holds a party's genuinely-signed leaf from another session (where it
    // reached a high frontier) and replays it to inflate THIS session. The signature verifies, so
    // session-binding is the only defense: a leaf whose signed session_id ≠ the sealed session is
    // rejected. (Teeth: an impl that ignores structure1[3] would accept it and derive the inflated value.)
    const a = generateKeypair();
    const otherSession = new Uint8Array(16).fill(99);
    const res = reDeriveFrontiers([await signedLeaf(a, 100, { sessionId: otherSession })], SID);
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.reason).toBe("leaf_session_mismatch");
  });
});

describe("DOD-LEG-2: findInflatedFrontier", () => {
  it("returns null when every published frontier matches the re-derived value (honest)", async () => {
    const a = generateKeypair();
    const b = generateKeypair();
    const aHex = Buffer.from(await a.getPublicKey()).toString("hex").toLowerCase();
    const bHex = Buffer.from(await b.getPublicKey()).toString("hex").toLowerCase();
    const res = reDeriveFrontiers([await signedLeaf(a, 2), await signedLeaf(b, 3)], SID);
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
    const res = reDeriveFrontiers([await signedLeaf(a, 2)], SID); // A really only reached 2
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const inflated = findInflatedFrontier([{ pubkey: aHex, content_frontier_seq: 15 }], res.frontiers);
    expect(inflated).not.toBeNull();
    expect(inflated!.party.toLowerCase()).toBe(aHex);
    expect(inflated!.publishedFrontier).toBe(15);
    expect(inflated!.derivedFrontier).toBe(2);
  });

  it("flags a NON-FIRST party when only the second-listed party's frontier is inflated", async () => {
    // SI-002: the guard must reject if ANY party's published frontier is inflated — not just the
    // first. Here A (index 0) is honest and B (index 1) is inflated; an impl that only inspects
    // participants[0] would wrongly return null. (Teeth: a participants[0]-only impl fails this.)
    const a = generateKeypair();
    const b = generateKeypair();
    const aHex = Buffer.from(await a.getPublicKey()).toString("hex").toLowerCase();
    const bHex = Buffer.from(await b.getPublicKey()).toString("hex").toLowerCase();
    const res = reDeriveFrontiers([await signedLeaf(a, 2), await signedLeaf(b, 3)], SID);
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const inflated = findInflatedFrontier(
      [{ pubkey: aHex, content_frontier_seq: 2 /* honest */ }, { pubkey: bHex, content_frontier_seq: 9 /* inflated */ }],
      res.frontiers,
    );
    expect(inflated, "the inflated SECOND party must be flagged").not.toBeNull();
    expect(inflated!.party.toLowerCase()).toBe(bHex);
    expect(inflated!.publishedFrontier).toBe(9);
    expect(inflated!.derivedFrontier).toBe(3);
  });

  it("equal published == derived is honest (not flagged)", async () => {
    const a = generateKeypair();
    const aHex = Buffer.from(await a.getPublicKey()).toString("hex").toLowerCase();
    const res = reDeriveFrontiers([await signedLeaf(a, 4)], SID);
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(findInflatedFrontier([{ pubkey: aHex, content_frontier_seq: 4 }], res.frontiers)).toBeNull();
  });
});
