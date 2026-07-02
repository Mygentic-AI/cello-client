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
  | { ok: false; reason: "leaf_signature_invalid" | "leaf_malformed" | "leaf_session_mismatch" };

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * Re-derive each party's content_frontier_seq from the signed leaves. Verifies every leaf's
 * Ed25519 signature over its Structure 1 bytes AND that the leaf's SIGNED session_id matches
 * the session being sealed — otherwise a malicious directory could replay a party's genuinely
 * signed leaves from a DIFFERENT session (where it reached a higher frontier) to inflate this
 * session's frontier. An unverifiable or wrong-session leaf fails the whole re-derivation.
 * Returns a map of lowercase-hex sender pubkey → max signed last_seen_seq.
 */
export function reDeriveFrontiers(leaves: SealFrontierLeaf[], expectedSessionId: Uint8Array): ReDeriveResult {
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
    const sid = arr[3];
    if (!(sid instanceof Uint8Array) || !bytesEqual(sid, expectedSessionId)) {
      return { ok: false, reason: "leaf_session_mismatch" };
    }
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

// ─── M8B FINDING-5 (SI-002): attestation-aware UNILATERAL frontier check ────────

export interface UnilateralFrontierParticipant {
  pubkey: string;
  content_frontier_seq: number;
  attestation_mode: string;
}

export type UnilateralFrontierVerdict =
  /** frontier_leaves present; every CLIENT-VERIFIABLE ('live') party's frontier is leaf-backed. */
  | { status: "verified" }
  /**
   * No frontier_leaves shipped (a pre-FINDING-5 directory). The cert stays DIRECTORY-attested — the
   * same provenance FINDING-3 shipped (each participant already carries attestation_mode). NEVER a
   * rejection, so FINDING-5 never regresses FINDING-3's "you always get a receipt".
   */
  | { status: "directory_attested" }
  /** A client-verifiable party's published frontier exceeds its signed leaves, or the leaves are bad. */
  | { status: "unverifiable"; reason: string; party?: string };

/**
 * FINDING-5 — the present party independently re-verifies the UNILATERAL receipt's frontiers.
 *
 * The unilateral legibility is FROST-notarized by the directory but the frontier VALUES are NOT
 * bound into the seal signature (unlike the bilateral seal, whose signer binds the legibility hash),
 * so the client must not trust them blindly. The asymmetry (why this is not a plain reuse of the
 * bilateral guard):
 *   - CLIENT-VERIFIABLE ('live') party: the present (submitting) party carries all its own signed
 *     leaves, so its content_frontier_seq is fully re-derivable → reject any inflation.
 *   - DIRECTORY-ATTESTED ('absent' / anything not 'live') party: its received-frontier remainder
 *     (acks of the present party's content) lives with the absent party and was never provided, so a
 *     published value ABOVE what the present party can derive is not provably inflation — it stays
 *     directory-attested (already marked per-participant) and is NEVER rejected here.
 *
 * Returns a verdict; the caller logs + (on 'unverifiable') refuses to persist the cert, and (on
 * 'directory_attested') persists with the provenance already marked on each participant.
 */
export function checkUnilateralFrontier(
  participants: ReadonlyArray<UnilateralFrontierParticipant>,
  frontierLeaves: SealFrontierLeaf[] | undefined,
  sessionId: Uint8Array,
): UnilateralFrontierVerdict {
  const haveLeaves = Array.isArray(frontierLeaves) && frontierLeaves.length > 0;
  // Pre-FINDING-5 directory (no leaves): keep FINDING-3's directory-attested behavior. Do NOT reject —
  // rejecting a claimed-but-unbacked frontier here would regress the shipped FINDING-3 receipt and
  // break unilateral seals against a not-yet-upgraded directory during rollout.
  if (!haveLeaves) return { status: "directory_attested" };

  // Only the CLIENT-VERIFIABLE ('live') parties are subject to the inflation reject.
  const verifiable = participants.filter((p) => p.attestation_mode === "live");
  const rederived = reDeriveFrontiers(frontierLeaves as SealFrontierLeaf[], sessionId);
  if (!rederived.ok) return { status: "unverifiable", reason: rederived.reason };

  const inflated = findInflatedFrontier(
    verifiable.map((p) => ({ pubkey: p.pubkey, content_frontier_seq: p.content_frontier_seq })),
    rederived.frontiers,
  );
  if (inflated) return { status: "unverifiable", reason: "frontier_inflated", party: inflated.party };
  return { status: "verified" };
}
