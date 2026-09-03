/**
 * THE LEAF SET THE DIRECTORY NOTARIZED — recovered from the seal frame, checked against the signed
 * root, and kept so a message can later be proved to sit under it.
 *
 * ─── WHY THIS EXISTS AND WHY THE LOCAL TREE CANNOT DO THE JOB ─────────────────────────────────
 *
 * The daemon's `SessionTree` is NOT the tree the certified root covers, and the difference is not a
 * rounding error:
 *
 *   - the certified root is `merkleRoot` over **every** leaf's content hash in the relay's canonical
 *     order, **control leaves included** (`directory-node.ts` — "THE CERTIFIED ROOT —
 *     client-reproducible, and the one every signature below binds");
 *   - `SessionTree` holds **content leaves only**. Nothing appends a SEAL ctrl leaf to it —
 *     `submitSealLeaf` deliberately computes its root without mutating the durable tree, and the
 *     inbound handler routes a counterparty ctrl leaf to the auto-acknowledge path, never to an
 *     append.
 *
 * So `SessionTree.rootHex()` equals the SEAL payload's `final_root` (the root over the non-ctrl
 * leaves, which is what each party signs), and it does **not** equal `sealed_root`. An audit path
 * built from the local tree therefore lands on a root no certificate names — which is precisely the
 * "a proof against your own root proves nothing" trap, reached by accident rather than by design.
 *
 * ─── WHAT MAKES THE STORED SET TRUSTWORTHY ────────────────────────────────────────────────────
 *
 * It is never stored on the directory's word. `recordSealedLeafSet` rebuilds the Merkle root over
 * the hashes and refuses unless it reproduces the `sealed_root` the FROST signature covers. A
 * directory that reorders, adds, drops or alters a single leaf produces a different root and the set
 * is refused — so what lands on disk is, by construction, the leaf set the consortium signed.
 *
 * ⚠️ THE PARAGRAPH THAT USED TO SIT HERE OVERSTATED IT, and it is rewritten rather than deleted
 * because it is what a future reader would have reasoned from. It said: *"the hashes come out of
 * `structure1_cbor`, each leaf's participant-signed to-be-signed bytes; `reDeriveFrontiers` has
 * already verified those signatures on this same array before we are called, so the content hashes
 * are the senders' own, not the directory's."*
 *
 * **That holds on the BILATERAL path only.** There, `seal-coordinator.ts` returns outright when
 * `reDeriveFrontiers` fails, so nothing unverified reaches this module. On the UNILATERAL path
 * `checkUnilateralFrontier` deliberately never rejects — a forged or cross-session leaf yields
 * `leaves_invalid`, the frontier is corrected DOWN to zero, and the seal proceeds rather than
 * dead-ending — and those same leaves are then handed here.
 *
 * **What is true on EVERY path is the root comparison below, and it is the load-bearing one.** A
 * leaf set only lands if it reproduces the FROST-signed `sealed_root`, so forged leaves cannot enter
 * the store unless they hash to a root the consortium already signed. The per-leaf signature check is
 * a second, path-dependent line of defence, not the guarantee — and stating it as the guarantee is
 * exactly the shape `DOD-M15-CLAIM-COMMENTS-1` exists to catch.
 *
 * The hashes still come out of `structure1_cbor`, each leaf's to-be-signed bytes — that part was
 * always accurate, and it is why the hashes are the ones a sender's signature would cover.
 *
 * Crypto refs: RFC 6962 §2.1 (Merkle hash trees).
 */

import { decodeStructure1 } from "@cello-protocol/protocol-types";
import { rootOverLeafHashes } from "./inclusion-proof.js";
import type { SealFrontierLeaf } from "./seal-frontier-verify.js";

/**
 * Every leaf's content hash, hex, in the order the directory certified.
 *
 * Structure 1 TBS is `[version, content_hash, sender_pubkey, session_id, last_seen_seq, timestamp]`,
 * plus `last_seen_hash` at index 6 on a v2 claim (020-ACKHASH). Index 1 is the content hash in both,
 * and it is the same value the directory feeds to `buildMerkleTree`. Decoded here rather than taken
 * from any other field so the hashes are the ones the sender's signature actually covers.
 *
 * Returns null on ANY undecodable or wrong-width leaf rather than skipping it. Skipping would build
 * a SHORTER leaf set that still hashes to something, and that something would then be compared to
 * the certified root — a comparison that fails for the right reason today and would silently start
 * passing the moment a dropped leaf happened to be the last one.
 */
export function sealedLeafHashesFromSignedLeaves(leaves: readonly SealFrontierLeaf[]): string[] | null {
  // AN EMPTY SET IS NOT A LEAF SET — the guard belongs here, not in the caller that happens to have
  // one. `[]` yields a root of sha256("") (RFC 6962 §2.1's empty tree), so a certificate whose root
  // were ever that value would "verify" against zero leaves, be stored as zero rows, and log
  // `leafCount: 0` as a success. Unreachable today only because `parseFrontierLeaves` filters empty
  // arrays upstream — which is a property of the caller, not of this function.
  if (leaves.length === 0) return null;
  const hashes: string[] = [];
  for (const leaf of leaves) {
    // `length < 2` before 020-ACKHASH, which read index 1 out of an array of ANY length — a shape
    // this build cannot name would have contributed a leaf hash to a set compared against a
    // certified root. An unnamed layout now returns null, exactly as an undecodable leaf does.
    const s1 = decodeStructure1(leaf.structure1_cbor);
    if (!s1.ok) return null;
    hashes.push(Buffer.from(s1.fields.contentHash).toString("hex"));
  }
  return hashes;
}

/** Why a candidate leaf set was not accepted as the notarized one. */
export const SEALED_LEAF_SET_REASONS = {
  /** A leaf's Structure 1 bytes did not decode, or carried no 32-byte content hash. */
  LEAVES_MALFORMED: "sealed_leaves_malformed",
  /** The Merkle root over these hashes is not the root the certificate is signed over. */
  ROOT_DISAGREES: "sealed_leaves_root_disagrees",
} as const;

export type SealedLeafSetReason =
  (typeof SEALED_LEAF_SET_REASONS)[keyof typeof SEALED_LEAF_SET_REASONS];

export type SealedLeafSetResult =
  | { ok: true; leafHashes: string[] }
  | { ok: false; reason: SealedLeafSetReason; detail: string };

/**
 * Recover the certified leaf set from the seal frame's signed leaves, and prove it against the
 * certified root before handing it back.
 *
 * The root comparison is the ONLY thing that makes the result usable, so it is not optional and not
 * a warning: a set that does not reproduce `sealedRootHex` is refused outright.
 */
export function certifiedLeafSetFrom(
  leaves: readonly SealFrontierLeaf[],
  sealedRootHex: string,
): SealedLeafSetResult {
  const hashes = sealedLeafHashesFromSignedLeaves(leaves);
  if (hashes === null) {
    return {
      ok: false,
      reason: SEALED_LEAF_SET_REASONS.LEAVES_MALFORMED,
      detail: `one of the ${leaves.length} signed leaves carried no decodable 32-byte content hash at Structure 1 index 1`,
    };
  }
  const recomputed = rootOverLeafHashes(hashes);
  const expected = sealedRootHex.toLowerCase();
  if (recomputed !== expected) {
    return {
      ok: false,
      reason: SEALED_LEAF_SET_REASONS.ROOT_DISAGREES,
      detail: `${hashes.length} leaves hash to ${recomputed}, and the certificate is signed over ${expected}`,
    };
  }
  return { ok: true, leafHashes: hashes };
}
