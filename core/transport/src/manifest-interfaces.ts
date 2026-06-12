/**
 * M7-MANIFEST-002 — Manifest-related interface definitions for the CELLO client daemon.
 *
 * These interfaces decouple the daemon and SignalingManager from their concrete
 * implementations. All interfaces are narrow by design.
 *
 * Interface overview:
 *
 * Client-side (daemon / SignalingManager):
 *   IManifestVersionStore   — persists the last-seen manifest version (monotonicity gate)
 *   IManifestProvider       — loads, verifies, and caches the consortium manifest
 *   IDirectoryChallengeVerifier — verifies the directory's step-5 Ed25519 challenge response
 *   IManifestPollScheduler  — schedules background manifest poll calls
 *
 * Directory-side (directory node):
 *   DirectoryKeyProvider    — provides the per-node nodeId and signs TBS bytes
 *   DirectoryManifestStore  — provides the current consortium manifest for poll responses
 *
 * Crypto reference: RFC 8032 (Ed25519).
 */

import type { ConsortiumManifest } from "@cello-protocol/protocol-types";

// ─── Client-side interfaces ───────────────────────────────────────────────────

/**
 * Persists the last-seen manifest version number across daemon restarts.
 * Used to enforce version monotonicity: a manifest with a lower version number
 * than the last-seen version is rejected as a potential rollback attack.
 *
 * In production: backed by SQLCipher local database.
 * In tests: InMemoryManifestVersionStore (starts at null, holds in memory).
 */
export interface IManifestVersionStore {
  /** Returns the last persisted version number, or null if none has been seen. */
  getLastSeenVersion(): Promise<number | null>;
  /** Persists a new version number, replacing the previous value. */
  persistVersion(version: number): Promise<void>;
}

/**
 * Loads, verifies, and caches the consortium manifest.
 * Abstracts manifest source (bundled JSON file vs test-supplied object).
 *
 * Production: FileManifestProvider reads consortium-manifest.json from package root.
 * Tests: TestManifestProvider takes a pre-built ConsortiumManifest, skips file read.
 */
export interface IManifestProvider {
  /**
   * Load the manifest from its source, verify the threshold signatures against
   * the supplied root keys, and cache it for getCurrentManifest().
   * Throws on signature failure, expiry, or missing nodes.
   */
  loadAndVerify(rootKeys: readonly string[], threshold: number): Promise<ConsortiumManifest>;
  /**
   * Returns the cached manifest from the last successful loadAndVerify() call.
   * Returns null if loadAndVerify() has not been called or failed.
   */
  getCurrentManifest(): ConsortiumManifest | null;
  /**
   * Replace the cached manifest with a newly polled manifest.
   * Called by SignalingManager.handleManifestPollResponse() after successful poll
   * verification. This ensures IDirectoryChallengeVerifier (which reads from
   * getCurrentManifest()) picks up key rotations reflected in the polled manifest.
   */
  updateManifest(manifest: ConsortiumManifest): void;
}

/**
 * Verifies the directory's step-5 challenge response.
 *
 * Step 5 TBS (RFC 8032 signing input):
 *   UTF-8('cello-directory-auth-challenge-v1\n') +
 *   UTF-8(nodeId) + UTF-8('\n') +
 *   UTF-8(agentPubkeyHex) + UTF-8('\n') +
 *   UTF-8(nonceHex) + UTF-8('\n') +
 *   UTF-8(isoTimestamp)
 *
 * Production: ManifestDirectoryChallengeVerifier reads the node's pubkey from
 * the in-memory manifest loaded by IManifestProvider, verifies with @noble/curves.
 * Tests: TestDirectoryChallengeVerifier — configurable pass/fail per nodeId.
 */
/** Result from a successful challenge verification. */
export interface ChallengeVerifyOk {
  valid: true;
}

/** Result from a failed challenge verification — reason distinguishes the failure cause. */
export interface ChallengeVerifyFail {
  valid: false;
  /** 'key_not_in_manifest': nodeId not present in the loaded manifest.
   *  'signature_invalid': nodeId found but Ed25519 signature failed verification. */
  reason: "key_not_in_manifest" | "signature_invalid";
}

export type ChallengeVerifyResult = ChallengeVerifyOk | ChallengeVerifyFail;

export interface IDirectoryChallengeVerifier {
  /**
   * Verify an Ed25519 signature over tbsBytes for the given nodeId.
   * The nodeId is looked up in the loaded manifest; the corresponding pubkey
   * is used for verification.
   * Returns ChallengeVerifyOk if valid.
   * Returns ChallengeVerifyFail with reason 'key_not_in_manifest' if nodeId absent.
   * Returns ChallengeVerifyFail with reason 'signature_invalid' if nodeId found but sig fails.
   * Never throws — all errors produce a ChallengeVerifyFail.
   */
  verifyChallenge(nodeId: string, tbsBytes: Uint8Array, signatureHex: string): ChallengeVerifyResult;
}

/**
 * Schedules background manifest poll callbacks.
 *
 * Production: RandomizedPollScheduler — fires the callback after a random interval
 * in the 6–12 hour window.
 * Tests: ImmediatePollScheduler — fires once with a configurable delay (0ms default).
 */
export interface IManifestPollScheduler {
  /**
   * Schedule the next poll call. After the delay elapses, callbackFn() is invoked.
   */
  scheduleNext(callbackFn: () => Promise<void>): void;
  /** Cancel any pending scheduled callback. Idempotent. */
  cancel(): void;
}

// ─── Directory-side interfaces ────────────────────────────────────────────────

/**
 * Provides the directory node's unique identifier and signing capability.
 * Each directory node has its own Ed25519 private key — never shared between nodes.
 *
 * Production: SecretsManagerDirectoryKeyProvider reads from AWS Secrets Manager at startup.
 * Tests: TestDirectoryKeyProvider — takes { nodeId, privateKeyHex } in constructor.
 */
export interface DirectoryKeyProvider {
  /** Returns the node's unique identifier string. */
  getNodeId(): string;
  /**
   * Sign tbsBytes with the node's Ed25519 private key (RFC 8032).
   * Returns a 64-byte signature as Uint8Array.
   */
  sign(tbsBytes: Uint8Array): Promise<Uint8Array>;
}

/**
 * Provides the current consortium manifest for manifest_poll_response frames.
 *
 * Production: FileDirectoryManifestStore reads the manifest JSON deployed alongside
 * the directory binary.
 * Tests: TestDirectoryManifestStore — takes a fixed ConsortiumManifest.
 */
export interface DirectoryManifestStore {
  /** Returns the current consortium manifest. Never throws in production. */
  getCurrentManifest(): ConsortiumManifest;
}
