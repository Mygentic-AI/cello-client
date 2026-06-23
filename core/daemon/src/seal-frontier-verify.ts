/**
 * DOD-LEG-2 (SESSION-004 SI-002) — client-side content-frontier re-derivation.
 *
 * The directory builds + signs the seal legibility, including each party's
 * `content_frontier_seq` ("the highest message the party provably received"). The client
 * must NOT trust that published value: a buggy or malicious directory could inflate it.
 * The client independently re-derives each party's frontier from the SIGNED leaves the
 * directory ships on the session_sealed frame, and rejects the certificate
 * (`certificate_frontier_unverifiable`) if any published frontier EXCEEDS what the signed
 * leaves support.
 *
 * Why signature-verification alone is sufficient to catch inflation: the directory cannot
 * forge a leaf signed by a participant (it holds no participant key), so it can only ship
 * REAL signed leaves. The maximum real signed last_seen_seq for a party IS that party's
 * honest frontier — there is no way to fabricate a higher one. (A malicious directory could
 * OMIT leaves, lowering the re-derived value and DoS-ing its own seal, but that is a refusal
 * to seal, not an inflation attack — and Merkle-binding the shipped leaves to the sealed_root
 * is a further hardening tracked separately.)
 *
 * Mirrors the directory's buildSealLegibility frontier derivation
 * (trustless-cello/packages/directory/src/seal-legibility.ts): max signed last_seen_seq
 * (Structure 1 index 4) per sender, over that sender's OWN signed leaves.
 */

import { verify } from "@cello-protocol/crypto";
import { decode } from "cbor-x";

export interface SealFrontierLeaf {
  structure1_cbor: Uint8Array;
  sender_pubkey: Uint8Array;
  sender_signature: Uint8Array;
}

export type ReDeriveResult =
  | { ok: true; frontiers: Map<string, number> }
  | { ok: false; reason: "leaf_signature_invalid" | "leaf_malformed" };

/**
 * Re-derive each party's content_frontier_seq from the signed leaves. Verifies every leaf's
 * Ed25519 signature over its Structure 1 bytes first — an unverifiable leaf fails the whole
 * re-derivation (a directory shipping a forged leaf is itself a tamper signal). Returns a
 * map of lowercase-hex sender pubkey → max signed last_seen_seq.
 */
export function reDeriveFrontiers(leaves: SealFrontierLeaf[]): ReDeriveResult {
  const frontiers = new Map<string, number>();
  for (const leaf of leaves) {
    if (!verify(leaf.sender_pubkey, leaf.structure1_cbor, leaf.sender_signature)) {
      return { ok: false, reason: "leaf_signature_invalid" };
    }
    let arr: unknown;
    try {
      arr = decode(leaf.structure1_cbor);
    } catch {
      return { ok: false, reason: "leaf_malformed" };
    }
    // Structure 1 = [1, content_hash(32), sender_pubkey(32), session_id(16), last_seen_seq, ts]
    if (!Array.isArray(arr) || arr.length < 5) return { ok: false, reason: "leaf_malformed" };
    const raw = arr[4];
    const lss = typeof raw === "bigint" ? Number(raw) : raw;
    if (typeof lss !== "number" || !Number.isFinite(lss)) continue; // leaf carries no signed last_seen
    const senderHex = Buffer.from(leaf.sender_pubkey).toString("hex").toLowerCase();
    const cur = frontiers.get(senderHex) ?? 0;
    if (lss > cur) frontiers.set(senderHex, lss);
  }
  return { ok: true, frontiers };
}

/**
 * Compare each published per-party content_frontier_seq against the re-derived value. Returns
 * the first party whose PUBLISHED frontier exceeds what its signed leaves support (inflation —
 * the certificate_frontier_unverifiable case), or null when every published frontier is honest.
 */
export function findInflatedFrontier(
  participants: ReadonlyArray<{ pubkey: string; content_frontier_seq: number }>,
  derived: Map<string, number>,
): { party: string; publishedFrontier: number; derivedFrontier: number } | null {
  for (const p of participants) {
    const d = derived.get(p.pubkey.toLowerCase()) ?? 0;
    if (p.content_frontier_seq > d) {
      return { party: p.pubkey, publishedFrontier: p.content_frontier_seq, derivedFrontier: d };
    }
  }
  return null;
}
