/**
 * Client-side content-frontier re-derivation.
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

// ─── Attestation-aware UNILATERAL frontier check ────────

export interface UnilateralFrontierParticipant {
  pubkey: string;
  content_frontier_seq: number;
  attestation_mode: string;
}

export interface UnilateralFrontierCheck {
  /**
   *  - verified:           leaves present, no CLIENT-VERIFIABLE ('live') frontier exceeded its leaves.
   *  - corrected:          leaves present, one or more 'live' frontiers were inflated and overridden
   *                        DOWN to the re-derived value (see `corrections`).
   *  - directory_attested: no frontier_leaves shipped (an older directory) — the cert stays
   *                        directory-attested. No correction possible.
   *  - leaves_invalid:     frontier_leaves are forged / cross-session (reDeriveFrontiers failed) — a
   *                        tamper signal; persist the directory-attested frontiers, log loudly. NEVER
   *                        rejected: the unilateral dedup guard makes rejection an unrecoverable
   *                        dead-end.
   */
  status: "verified" | "corrected" | "directory_attested" | "leaves_invalid";
  /** lowercased pubkey → corrected content_frontier_seq, for inflated 'live' parties. The caller
   *  lowers the persisted frontier to this before recording the receipt. Empty unless status is 'corrected'. */
  corrections: Map<string, number>;
  reason?: string;
}

/**
 * The present party independently re-verifies (and CORRECTS) the UNILATERAL receipt's frontiers.
 * OVERRIDE, never reject.
 *
 * The unilateral legibility is FROST-notarized by the directory but the frontier VALUES are NOT bound
 * into the seal signature (unlike the bilateral seal, whose signer binds the legibility hash), so the
 * client must not trust them blindly. Because the directory-side dedup guard makes a client REJECTION
 * of a unilateral cert unrecoverable (a retry close is silently ignored — no receipt is ever
 * produced), the client CORRECTS rather than rejects:
 *   - CLIENT-VERIFIABLE ('live') party: the present (submitting) party carries all its own signed
 *     leaves, so its content_frontier_seq is fully re-derivable. The directory cannot forge signed
 *     leaves, so the re-derived value is the provable truth → an inflated published value is OVERRIDDEN
 *     DOWN to it (inflation neutralized, receipt still persisted).
 *   - DIRECTORY-ATTESTED ('absent' / anything not 'live') party: its received-frontier remainder
 *     (acks of the present party's content) lives with the absent party and was never provided, so a
 *     published value ABOVE what the present party can derive is not provably inflation — left
 *     untouched, directory-attested (already marked per-participant).
 *
 * The caller applies `corrections` to the persisted legibility and logs per `status`; it ALWAYS
 * persists a receipt (never dead-ends the close).
 */
export function checkUnilateralFrontier(
  participants: ReadonlyArray<UnilateralFrontierParticipant>,
  frontierLeaves: SealFrontierLeaf[] | undefined,
  sessionId: Uint8Array,
): UnilateralFrontierCheck {
  const corrections = new Map<string, number>();
  const haveLeaves = Array.isArray(frontierLeaves) && frontierLeaves.length > 0;
  // A directory that ships no leaves leaves the cert directory-attested. Never reject — rejecting
  // would break unilateral seals against a not-yet-upgraded directory during rollout.
  if (!haveLeaves) return { status: "directory_attested", corrections };

  const rederived = reDeriveFrontiers(frontierLeaves as SealFrontierLeaf[], sessionId);
  // Forged / cross-session leaves are the STRONGEST tamper evidence, so they get the strongest
  // correction: treat them as ZERO trustworthy evidence (an empty derived map), which drives any
  // 'live' frontier > 0 down to 0. Do NOT leave the published value untouched on invalid leaves —
  // that would make malformed leaves an EASIER inflation bypass than shipping none. Still never
  // REJECT (the directory dedup guard makes rejection an unrecoverable dead-end); the caller logs.
  const derived = rederived.ok ? rederived.frontiers : new Map<string, number>();

  // Only CLIENT-VERIFIABLE ('live') parties are re-derivable; override any value above the provable
  // one DOWN to it. The absent party is directory-attested (its remainder is not re-derivable here).
  for (const p of participants) {
    if (p.attestation_mode !== "live") continue;
    const d = derived.get(p.pubkey.toLowerCase()) ?? 0;
    if (p.content_frontier_seq > d) corrections.set(p.pubkey.toLowerCase(), d);
  }
  if (!rederived.ok) return { status: "leaves_invalid", corrections, reason: rederived.reason };
  return { status: corrections.size > 0 ? "corrected" : "verified", corrections };
}
