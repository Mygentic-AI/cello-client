/**
 * Proving that ONE message sits under the root the directory notarized.
 *
 * ─── WHAT MAKES THIS A PROOF AND NOT A DATA STRUCTURE ────────────────────────────────────────
 *
 * Two things, and both are easy to get wrong in a way that still looks like a proof.
 *
 * **1. The root comes from the CERTIFICATE, never from the proof.** A proof that carries its own
 * root and is checked against it proves that the machine which wrote the proof is self-consistent —
 * and that machine is the one a sceptic distrusts. So `verifyInclusionProof` REQUIRES the root as a
 * separate argument, supplied by whoever holds the directory-signed certificate, and the root inside
 * the proof is only ever compared to it. Drop that argument and the whole file becomes theatre.
 *
 * **2. The leaf is recomputed from the MESSAGE BYTES, never taken from the proof.** The Merkle leaf
 * is a content hash, and since `DOD-M15-SEALWIRE-1` that hash is `HMAC-SHA256(salt, 0x00 ‖ content)`
 * for a salted session. A proof over the leaf hash alone answers "is this opaque 32-byte number in
 * the tree", and the operator's question is about a sentence. So the salt and the algorithm NAME
 * travel with the proof, the verifier recomputes the leaf from the plaintext it holds, and a message
 * that differs by one byte produces a different leaf and fails — which is the assertion the whole
 * feature exists to make.
 *
 * Neither hash nor Merkle maths is reimplemented here. `contentHashFor` (wire-content-hash.ts) is
 * the daemon's ONE content-hash derivation and `verifyInclusion` (@cello-protocol/crypto) is the ONE
 * RFC 6962 verifier. A second copy of either drifts from the seal, and the drift surfaces as a lost
 * dispute rather than as a failing test.
 *
 * Crypto refs: RFC 6962 §2.1.1 (Merkle audit paths), RFC 2104 (HMAC), FIPS 180-4 (SHA-256).
 */

import { verifyInclusion, buildMerkleTree, merkleRoot, inclusionProof, type LeafInput } from "@cello-protocol/crypto";
import {
  CONTENT_HASH_ALGS,
  contentHashFor,
  isKnownContentHashAlg,
  type ContentHashAlg,
} from "./wire-content-hash.js";

/** Everything a third party needs alongside the message bytes and the certificate. */
export interface InclusionProof {
  /** Proof format version. Bumped when any field below changes meaning. */
  readonly version: 1;
  /** The session this proof is about, hex — so a proof cannot be silently read against another. */
  readonly session_id: string;
  /**
   * The root this proof lands on, hex. NOT authoritative on its own: `verifyInclusionProof`
   * compares it to the root the caller took from the certificate and refuses if they differ.
   */
  readonly certified_root: string;
  /** Zero-based position of this message's leaf under the certified root. */
  readonly leaf_index: number;
  /** How many leaves the certified root covers (content leaves AND the seal's control leaves). */
  readonly leaf_count: number;
  /** The leaf hash this proof is for, hex — recomputed by the verifier, never trusted from here. */
  readonly leaf_hash: string;
  /** RFC 6962 §2.1.1 audit path: sibling hashes, hex, leaf level upward. */
  readonly proof_path: readonly string[];
  /** How the leaf hash is derived from the message bytes. Named, never assumed. */
  readonly content_hash_alg: ContentHashAlg;
  /**
   * The session salt, hex. Required — this build issues salted proofs only, and a proof carrying no
   * salt is refused rather than checked. The type stays nullable because the shape check runs over
   * an object off the wire, and "carried null" must be refusable BY NAME rather than by a crash.
   */
  readonly content_salt: string | null;
}

/**
 * Why a verification did not conclude "verified".
 *
 * A CLOSED set with a total guidance map below, so a new code cannot be added without something the
 * reader can act on. `message_does_not_match_leaf` and `proof_path_invalid` are the two that mean
 * "the proof is bad"; the rest mean "this proof was not checkable as presented".
 */
export const INCLUSION_VERIFY_REASONS = {
  /** The proof object is not a v1 proof, or a field is missing / the wrong width. */
  PROOF_MALFORMED: "proof_malformed",
  /** The proof names a root that is not the one in the certificate the caller holds. */
  ROOT_NOT_FROM_CERTIFICATE: "root_not_from_certificate",
  /** The proof names a hash algorithm this build cannot reproduce. */
  UNKNOWN_HASH_ALG: "unknown_content_hash_alg",
  /**
   * The proof is over an UNSALTED content hash. Refused rather than checked.
   *
   * There is no compatibility branch here on purpose. An unsalted leaf hash is `sha256(0x00 ‖
   * content)` — a value anyone holding the plaintext can compute, so it correlates the message
   * across every record that carries it, which is exactly what the session salt exists to stop.
   * Verifying one anyway would hand back `ok: true` for a proof carrying strictly weaker protection
   * than the one this build issues, under the same word.
   */
  UNSALTED_PROOF: "unsalted_proof_refused",
  /** The salted algorithm was named and no salt was carried. */
  SALT_MISSING: "salt_missing",
  /** The message hashes to a different leaf than the proof is for — the message was altered. */
  MESSAGE_DOES_NOT_MATCH_LEAF: "message_does_not_match_leaf",
  /** The audit path does not reconstruct the certified root from this leaf at this index. */
  PROOF_PATH_INVALID: "proof_path_invalid",
} as const;

export type InclusionVerifyReason =
  (typeof INCLUSION_VERIFY_REASONS)[keyof typeof INCLUSION_VERIFY_REASONS];

/** What the reader should DO about each. Total over the union by construction. */
export const INCLUSION_VERIFY_GUIDANCE: Record<InclusionVerifyReason, string> = {
  [INCLUSION_VERIFY_REASONS.PROOF_MALFORMED]:
    "This is not a well-formed CELLO inclusion proof. Ask whoever gave it to you for the exact JSON " +
    "object cello_get_inclusion_proof returned — a proof that has been reformatted, truncated, or " +
    "had fields renamed cannot be checked.",
  [INCLUSION_VERIFY_REASONS.ROOT_NOT_FROM_CERTIFICATE]:
    "The proof lands on a DIFFERENT root than the certificate you supplied. It may be a proof for " +
    "another session, or for an earlier seal of this one. Check the session id on both, and take the " +
    "root from the certificate (cello_sealed_receipt reports it as sealed_root) — never from the proof.",
  [INCLUSION_VERIFY_REASONS.UNKNOWN_HASH_ALG]:
    "The proof names a content-hash algorithm this build does not implement, so there is no value to " +
    "compare against. This is a version difference, NOT evidence of tampering. Upgrade the client and " +
    "check again before drawing any conclusion.",
  [INCLUSION_VERIFY_REASONS.UNSALTED_PROOF]:
    "This proof is over an UNSALTED content hash, which this build does not accept — a leaf anyone " +
    "holding the plaintext can recompute is the exact correlation the session salt exists to prevent. " +
    "It has NOT been shown to be false; it has not been checked. Ask for a proof from a salted " +
    "session (cello_sealed_receipt reports whether the session's content hashes are salted).",
  [INCLUSION_VERIFY_REASONS.SALT_MISSING]:
    "The proof names the salted algorithm and carries no salt, so the leaf cannot be recomputed from " +
    "the message. Ask for the proof to be re-issued; do not treat this as a failed verification.",
  [INCLUSION_VERIFY_REASONS.MESSAGE_DOES_NOT_MATCH_LEAF]:
    "THE MESSAGE YOU SUPPLIED IS NOT THE ONE THIS PROOF IS ABOUT. Its bytes hash to a different leaf. " +
    "Either the text was altered (even by one character, or by trailing whitespace a copy/paste added) " +
    "or this proof belongs to a different message. Compare against the exact bytes from cello_transcript.",
  [INCLUSION_VERIFY_REASONS.PROOF_PATH_INVALID]:
    "The audit path does not rebuild the certified root from this message. The proof does not " +
    "establish that this message is in the sealed conversation. Ask for a freshly issued proof; if a " +
    "fresh one fails the same way, the record and the certificate genuinely disagree.",
};

export type InclusionVerifyResult =
  | {
      ok: true;
      session_id: string;
      leaf_index: number;
      leaf_count: number;
      certified_root: string;
      content_hash_alg: ContentHashAlg;
    }
  | { ok: false; reason: InclusionVerifyReason; detail: string; guidance: string };

const HEX32 = /^[0-9a-f]{64}$/;

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

/**
 * The Merkle root over an ordered list of leaf HASHES (hex).
 *
 * `kind: "hash"` because these values already ARE leaf hashes — the certified root the directory
 * signs is built the same way (`directory-node.ts`, over each leaf's `s2.content_hash`), and
 * applying a leaf prefix here would produce a root nobody else computes.
 */
export function rootOverLeafHashes(leafHashesHex: readonly string[]): string {
  const inputs: LeafInput[] = leafHashesHex.map((h) => ({ kind: "hash" as const, data: hexToBytes(h) }));
  return bytesToHex(merkleRoot(buildMerkleTree(inputs)));
}

/**
 * Build the audit path for one leaf of a leaf-hash list.
 *
 * Delegates to `inclusionProof`. Deliberately NOT a local tree walk: the seal and the proof must
 * come from the same Merkle implementation or they drift, and the drift is invisible until a real
 * dispute.
 */
export function proofPathFor(leafHashesHex: readonly string[], index: number): string[] {
  const inputs: LeafInput[] = leafHashesHex.map((h) => ({ kind: "hash" as const, data: hexToBytes(h) }));
  return inclusionProof(buildMerkleTree(inputs), index).map(bytesToHex);
}

/**
 * Is this a structurally valid v1 proof? Shape only — says nothing about whether it verifies.
 *
 * Separated so the daemon's verify handler can refuse a malformed object by name before it reaches
 * any hashing, and so a test can assert the two failure classes apart.
 */
export function isInclusionProofShape(value: unknown): value is InclusionProof {
  if (typeof value !== "object" || value === null) return false;
  const p = value as Record<string, unknown>;
  if (p["version"] !== 1) return false;
  if (typeof p["session_id"] !== "string" || p["session_id"].length === 0) return false;
  if (typeof p["certified_root"] !== "string" || !HEX32.test(p["certified_root"])) return false;
  if (typeof p["leaf_hash"] !== "string" || !HEX32.test(p["leaf_hash"])) return false;
  if (!Number.isInteger(p["leaf_index"]) || (p["leaf_index"] as number) < 0) return false;
  if (!Number.isInteger(p["leaf_count"]) || (p["leaf_count"] as number) <= 0) return false;
  if ((p["leaf_index"] as number) >= (p["leaf_count"] as number)) return false;
  const path = p["proof_path"];
  if (!Array.isArray(path) || path.some((s) => typeof s !== "string" || !HEX32.test(s))) return false;
  if (typeof p["content_hash_alg"] !== "string") return false;
  const salt = p["content_salt"];
  if (salt !== null && (typeof salt !== "string" || salt.length === 0 || !/^([0-9a-f]{2})+$/.test(salt))) {
    return false;
  }
  return true;
}

/**
 * VERIFY — the whole point of the file, and it touches no database.
 *
 * Three inputs and nothing else: the proof, the message bytes, and the root the caller took from the
 * directory-signed certificate. That is what makes it runnable by a third party who has never seen
 * the daemon that issued the proof.
 *
 * `certifiedRootHex` is REQUIRED and is the anchor. Making it optional — defaulting to the root
 * inside the proof — would turn every call into the proof checking itself, which is the exact shape
 * this feature exists to replace.
 */
export function verifyInclusionProof(
  proof: unknown,
  messageBytes: Uint8Array,
  certifiedRootHex: string,
): InclusionVerifyResult {
  const fail = (reason: InclusionVerifyReason, detail: string): InclusionVerifyResult => ({
    ok: false,
    reason,
    detail,
    guidance: INCLUSION_VERIFY_GUIDANCE[reason],
  });

  if (!isInclusionProofShape(proof)) {
    return fail(
      INCLUSION_VERIFY_REASONS.PROOF_MALFORMED,
      "the proof is not a version-1 inclusion proof with the required fields at their required widths",
    );
  }

  if (typeof certifiedRootHex !== "string" || !HEX32.test(certifiedRootHex.toLowerCase())) {
    return fail(
      INCLUSION_VERIFY_REASONS.ROOT_NOT_FROM_CERTIFICATE,
      `the certified root supplied is not a 32-byte hex value (got ${typeof certifiedRootHex === "string" ? `${certifiedRootHex.length} chars` : typeof certifiedRootHex})`,
    );
  }

  const anchor = certifiedRootHex.toLowerCase();
  if (proof.certified_root !== anchor) {
    return fail(
      INCLUSION_VERIFY_REASONS.ROOT_NOT_FROM_CERTIFICATE,
      `the proof lands on ${proof.certified_root} and the certificate names ${anchor}`,
    );
  }

  if (!isKnownContentHashAlg(proof.content_hash_alg)) {
    return fail(
      INCLUSION_VERIFY_REASONS.UNKNOWN_HASH_ALG,
      `the proof names content-hash algorithm "${proof.content_hash_alg}"`,
    );
  }

  if (proof.content_hash_alg !== CONTENT_HASH_ALGS.HMAC_SALT_V1) {
    return fail(
      INCLUSION_VERIFY_REASONS.UNSALTED_PROOF,
      `the proof names content-hash algorithm "${proof.content_hash_alg}"; only ${CONTENT_HASH_ALGS.HMAC_SALT_V1} is accepted`,
    );
  }

  if (proof.content_salt === null) {
    return fail(
      INCLUSION_VERIFY_REASONS.SALT_MISSING,
      `algorithm ${proof.content_hash_alg} needs a salt and the proof carries none`,
    );
  }

  // The leaf is DERIVED from the bytes in hand, never read out of the proof. This line is what makes
  // a one-byte edit fail.
  const recomputed = bytesToHex(
    contentHashFor(messageBytes, { alg: proof.content_hash_alg, salt: hexToBytes(proof.content_salt) }),
  );

  if (recomputed !== proof.leaf_hash) {
    return fail(
      INCLUSION_VERIFY_REASONS.MESSAGE_DOES_NOT_MATCH_LEAF,
      `the message supplied hashes to ${recomputed} under ${proof.content_hash_alg}; the proof is for leaf ${proof.leaf_hash}`,
    );
  }

  const verified = verifyInclusion(
    hexToBytes(recomputed),
    proof.leaf_index,
    proof.leaf_count,
    proof.proof_path.map(hexToBytes),
    hexToBytes(anchor),
  );

  if (!verified) {
    return fail(
      INCLUSION_VERIFY_REASONS.PROOF_PATH_INVALID,
      `the audit path (${proof.proof_path.length} sibling hashes) does not rebuild ${anchor} from leaf ${proof.leaf_index} of ${proof.leaf_count}`,
    );
  }

  return {
    ok: true,
    session_id: proof.session_id,
    leaf_index: proof.leaf_index,
    leaf_count: proof.leaf_count,
    certified_root: anchor,
    content_hash_alg: proof.content_hash_alg,
  };
}
