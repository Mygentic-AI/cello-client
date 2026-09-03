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
import { encodeStructure1 } from "@cello-protocol/protocol-types";
import {
  reDeriveFrontiers,
  findInflatedFrontier,
  checkUnilateralFrontier,
  type SealFrontierLeaf,
} from "../seal-frontier-verify.js";

const SID = new Uint8Array(16).fill(7); // the session being sealed

async function signedLeaf(
  kp: ReturnType<typeof generateKeypair>,
  lastSeenSeq: number,
  opts: { corruptSig?: boolean; sessionId?: Uint8Array } = {},
): Promise<SealFrontierLeaf> {
  const pubkey = await kp.getPublicKey();
  const s1 = encodeStructure1({
    contentHash: new Uint8Array(32),
    senderPubkey: pubkey,
    sessionId: opts.sessionId ?? SID,
    lastSeenSeq,
    timestamp: 1_700_000_000_000,
  });
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

// ─── FINDING-5 (SI-002): attestation-aware unilateral frontier check ────────────
//
// OVERRIDE, never reject. The unilateral seal has a directory-side dedup guard (#unilateralSeals)
// that makes a client REJECTION unrecoverable — a retry close is silently ignored and no receipt is
// ever produced (worse than FINDING-3). So the client CORRECTS rather than rejects: the present party
// (attestation_mode 'live') carries all its own signed leaves, so an inflated 'live' frontier is
// overridden DOWN to the re-derived (provable) value. The absent party ('absent') is directory-attested
// — its received-frontier remainder isn't the present party's to re-derive, so it is never corrected.
// No frontier_leaves (a pre-FINDING-5 directory) → the cert stays directory-attested (FINDING-3
// behavior), never rejected, so the fix never regresses FINDING-3. A receipt is ALWAYS persisted.
describe("FINDING-5: checkUnilateralFrontier (attestation-aware, override-not-reject)", () => {
  async function liveAbsent(): Promise<{
    a: ReturnType<typeof generateKeypair>;
    b: ReturnType<typeof generateKeypair>;
    aHex: string;
    bHex: string;
  }> {
    const a = generateKeypair();
    const b = generateKeypair();
    const aHex = Buffer.from(await a.getPublicKey()).toString("hex").toLowerCase();
    const bHex = Buffer.from(await b.getPublicKey()).toString("hex").toLowerCase();
    return { a, b, aHex, bHex };
  }

  it("leaves present + honest live frontier → verified, no corrections", async () => {
    const { a, b, aHex, bHex } = await liveAbsent();
    const leaves = [await signedLeaf(a, 2), await signedLeaf(b, 1)];
    const check = checkUnilateralFrontier(
      [
        { pubkey: aHex, content_frontier_seq: 2, attestation_mode: "live" },
        { pubkey: bHex, content_frontier_seq: 1, attestation_mode: "absent" },
      ],
      leaves,
      SID,
    );
    expect(check.status).toBe("verified");
    expect(check.corrections.size).toBe(0);
  });

  it("leaves present + INFLATED live frontier → corrected DOWN to the re-derived value (not rejected)", async () => {
    const { a, aHex } = await liveAbsent();
    const leaves = [await signedLeaf(a, 2)]; // A really only reached 2
    const check = checkUnilateralFrontier(
      [{ pubkey: aHex, content_frontier_seq: 15, attestation_mode: "live" }],
      leaves,
      SID,
    );
    expect(check.status).toBe("corrected");
    expect(check.corrections.get(aHex)).toBe(2); // overridden 15 → 2 (the provable value)
  });

  it("an inflated ABSENT (directory-attested) frontier is left untouched — not the present party's to re-derive", async () => {
    const { a, b, aHex, bHex } = await liveAbsent();
    // A (live) honest at 2; B (absent) published 9 though B signed only up to 1 — the un-derivable
    // received-frontier remainder. Never corrected; stays directory-attested (marked per-participant).
    const leaves = [await signedLeaf(a, 2), await signedLeaf(b, 1)];
    const check = checkUnilateralFrontier(
      [
        { pubkey: aHex, content_frontier_seq: 2, attestation_mode: "live" },
        { pubkey: bHex, content_frontier_seq: 9, attestation_mode: "absent" },
      ],
      leaves,
      SID,
    );
    expect(check.status).toBe("verified");
    expect(check.corrections.has(bHex)).toBe(false);
  });

  it("NO frontier_leaves → directory_attested (FINDING-3 back-compat, never rejected, no corrections)", async () => {
    const { aHex, bHex } = await liveAbsent();
    const check = checkUnilateralFrontier(
      [
        { pubkey: aHex, content_frontier_seq: 2, attestation_mode: "live" },
        { pubkey: bHex, content_frontier_seq: 0, attestation_mode: "absent" },
      ],
      undefined,
      SID,
    );
    expect(check.status).toBe("directory_attested");
    expect(check.corrections.size).toBe(0);
  });

  it("forged leaves + an INFLATED live value → leaves_invalid AND corrected to 0 (strongest tamper → strongest correction)", async () => {
    // The dangerous case: a directory ships an unverifiable leaf alongside an inflated published value.
    // Forged leaves are zero trustworthy evidence, so the 'live' frontier is corrected DOWN to 0 — NOT
    // left at the inflated value (which would make malformed leaves an easier bypass than shipping none).
    const { a, aHex } = await liveAbsent();
    const leaves = [await signedLeaf(a, 2), await signedLeaf(a, 9, { corruptSig: true })];
    const check = checkUnilateralFrontier(
      [{ pubkey: aHex, content_frontier_seq: 9, attestation_mode: "live" }],
      leaves,
      SID,
    );
    expect(check.status).toBe("leaves_invalid");
    expect(check.corrections.get(aHex)).toBe(0);
  });
});
