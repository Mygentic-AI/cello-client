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

/** A single directory node in the consortium. */
export interface ConsortiumNode {
  nodeId: string;
  /** Ed25519 public key — 64 character hex (32 bytes). */
  pubkey: string;
  region: string;
  provider: "aws" | "gcp" | "azure";
  endpoint: string;
}

/** An officer's Ed25519 signature over the canonical manifest body. */
export interface OfficerSignature {
  /** 0-based officer index into the root key array. */
  officerIndex: number;
  /** Ed25519 signature — 128 character hex (64 bytes). */
  signature: string;
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
