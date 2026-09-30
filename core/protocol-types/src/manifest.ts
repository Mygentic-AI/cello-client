/**
 * M7-MANIFEST-001 — Consortium manifest type definitions.
 *
 * A ConsortiumManifest describes the current set of directory nodes forming
 * the CELLO consortium. It is threshold-signed by officer keys to prevent
 * unauthorized modification.
 *
 * Types defined here are consumed by core/crypto (verification logic) and core/daemon (manifest
 * fetching, caching, and bootstrap).
 */

/**
 * A node's role in the consortium (M12 role split).
 *
 * - `validator` holds FROST shares, participates in DKG, signs seals, and honors the kill
 *   switch — it is counted in `T = majority(validators)`.
 * - `replica` holds no shares and never signs; it replicates state for redundancy and reads
 *   and is NEVER counted in the threshold arithmetic.
 */
export type NodeRole = "validator" | "replica";

/** A single directory node in the consortium. */
export interface ConsortiumNode {
  nodeId: string;
  /** Ed25519 public key — 64 character hex (32 bytes). */
  pubkey: string;
  region: string;
  provider: "aws" | "gcp" | "azure";
  endpoint: string;
  /** M12 role split. Required; `verifyManifest` rejects a node without one. */
  role: NodeRole;
  /**
   * libp2p PeerId — needed by directory↔directory anti-entropy to dial a peer (M12), and checked
   * by the client against the node's /bootstrap probe. Required, inside the signed body.
   */
  peerId: string;
  /** M9D 004: the node's ML-DSA-44 public key — 2,624 lowercase hex chars (1,312 bytes), unique. */
  mldsa_pubkey: string;
}

/**
 * The role of a node. A manifest that reached a consumer has already passed `verifyManifest`,
 * which rejects a node whose role is not exactly "validator" or "replica".
 */
export function nodeRole(node: ConsortiumNode): NodeRole {
  return (node.role as unknown) === "replica" ? "replica" : "validator";
}

/** True iff the node is (effectively) a validator. */
export function isValidator(node: ConsortiumNode): boolean {
  return nodeRole(node) === "validator";
}

/**
 * The validator-role nodes of a manifest — the ONLY set that enters threshold arithmetic
 * (`consortiumNodeCount`, DKG quorum, kill-switch honoring). Replicas are excluded.
 */
export function validatorNodes(nodes: readonly ConsortiumNode[]): ConsortiumNode[] {
  return nodes.filter(isValidator);
}

/** An officer's Ed25519 signature over the canonical manifest body. */
export interface OfficerSignature {
  /** 0-based officer index into the root key array. */
  officerIndex: number;
  /** Ed25519 signature — 128 character hex (64 bytes). */
  signature: string;
}

/**
 * The portal's intake encryption key, as published in the manifest (M10B-D11).
 *
 * REQUIRED since M9D 004: `verifyManifest` refuses a manifest without a well-formed one, so a
 * verified manifest always carries it and a submission can always be sealed.
 */
export interface ManifestIntakeKey {
  /** Which key this is. Recorded on every queue row, so a rotated-out private key can be retained
   *  until no undrained row references it — retention driven by the queue, not by a timer. */
  key_id: string;
  /** Ed25519 public key, hex. Submissions are sealed to this. */
  pubkey: string;
}

/** The full consortium manifest with threshold signatures. */
export interface ConsortiumManifest {
  version: number;
  /** ISO 8601 timestamp — manifest is not valid before this time. */
  not_before: string;
  /** ISO 8601 timestamp — manifest expires at this time. */
  expires: string;
  nodes: ConsortiumNode[];
  signatures: OfficerSignature[];
  /** M9D 004: the ML-DSA officer signatures, over the same canonical body as `signatures`. */
  pq_signatures: OfficerSignature[];
  /**
   * M10B-D11 — the portal's intake key. `canonicalManifestBody` builds the signed body from
   * `Object.keys(manifest)` minus both signature sets, so every top-level field is covered by the
   * officer signatures — which is the whole reason the manifest is the right channel for a SEALING
   * key. An unauthenticated channel (a `/bootstrap` route, client config) is not a shortcut here: a
   * substituted intake key means every endorsement is sealed to the attacker.
   *
   * Rotation is a manifest version bump the daemon's existing poll rolls forward, under its
   * `manifest_version_rollback` guard.
   */
  intake_key: ManifestIntakeKey;
  /** M9D 004: the portal's ML-KEM-768 intake public key, 2,368 lowercase hex chars. It shares
   *  `intake_key.key_id` by sitting beside it; there is no second key id. */
  mlkem_intake_key: string;
}

/** Distinct error codes for manifest verification failures. */
export type ManifestError =
  | "manifest_signature_invalid"
  | "manifest_version_rollback"
  | "manifest_expired";

/** Error constant: signature verification failed. */
export const MANIFEST_SIGNATURE_INVALID: ManifestError = "manifest_signature_invalid";

/** Error constant: manifest version is older than the currently cached version. */
export const MANIFEST_VERSION_ROLLBACK: ManifestError = "manifest_version_rollback";

/** Error constant: manifest has passed its expiration time. */
export const MANIFEST_EXPIRED: ManifestError = "manifest_expired";
