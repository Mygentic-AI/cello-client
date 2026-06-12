/**
 * M7-MANIFEST-002 — In-memory stubs for manifest interfaces.
 *
 * These stubs are test-only implementations of the interfaces defined in
 * manifest-interfaces.ts. They are intentionally simple — no file I/O, no external calls.
 *
 * Crypto reference: RFC 8032 (Ed25519).
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import type { ConsortiumManifest } from "@cello-protocol/protocol-types";
import type {
  IManifestVersionStore,
  IManifestProvider,
  IDirectoryChallengeVerifier,
  ChallengeVerifyResult,
  IManifestPollScheduler,
  DirectoryKeyProvider,
  DirectoryManifestStore,
} from "./manifest-interfaces.js";

// ─── IManifestVersionStore ───────────────────────────────────────────────────

/**
 * InMemoryManifestVersionStore — starts at null, holds state in memory.
 *
 * // SQLCipher: InMemory stub used — real store wired in DAEMON-001
 */
export class InMemoryManifestVersionStore implements IManifestVersionStore {
  #lastSeenVersion: number | null = null;

  async getLastSeenVersion(): Promise<number | null> {
    return this.#lastSeenVersion;
  }

  async persistVersion(version: number): Promise<void> {
    this.#lastSeenVersion = version;
  }
}

// ─── IManifestProvider ───────────────────────────────────────────────────────

/**
 * TestManifestProvider — takes a pre-built ConsortiumManifest, skips file read.
 *
 * loadAndVerify() returns the supplied manifest without signature verification.
 */
export class TestManifestProvider implements IManifestProvider {
  #manifest: ConsortiumManifest;
  #loaded: ConsortiumManifest | null = null;

  constructor(manifest: ConsortiumManifest) {
    this.#manifest = manifest;
  }

  async loadAndVerify(_rootKeys: readonly string[], _threshold: number): Promise<ConsortiumManifest> {
    this.#loaded = this.#manifest;
    return this.#manifest;
  }

  getCurrentManifest(): ConsortiumManifest | null {
    return this.#loaded;
  }

  updateManifest(manifest: ConsortiumManifest): void {
    this.#manifest = manifest;
    this.#loaded = manifest;
  }
}

// ─── IDirectoryChallengeVerifier ─────────────────────────────────────────────

/**
 * TestDirectoryChallengeVerifier — configurable pass/fail per nodeId.
 * Rejected nodeIds produce 'key_not_in_manifest'; all other failures produce 'signature_invalid'.
 */
export class TestDirectoryChallengeVerifier implements IDirectoryChallengeVerifier {
  readonly #rejectedNodeIds = new Set<string>();
  readonly #invalidSigNodeIds = new Set<string>();

  rejectNodeId(nodeId: string): void {
    this.#rejectedNodeIds.add(nodeId);
  }

  invalidateSig(nodeId: string): void {
    this.#invalidSigNodeIds.add(nodeId);
  }

  verifyChallenge(nodeId: string, _tbsBytes: Uint8Array, _signatureHex: string): ChallengeVerifyResult {
    if (this.#rejectedNodeIds.has(nodeId)) {
      return { valid: false, reason: "key_not_in_manifest" };
    }
    if (this.#invalidSigNodeIds.has(nodeId)) {
      return { valid: false, reason: "signature_invalid" };
    }
    return { valid: true };
  }
}

/**
 * ManifestDirectoryChallengeVerifier — reads pubkey from in-memory manifest, verifies
 * with @noble/curves Ed25519 (RFC 8032). Production client-side verifier.
 *
 * Pseudocode (RFC 8032 — Ed25519 verify):
 *   1. Get the current manifest from IManifestProvider.
 *   2. Find the node entry with nodeId == nodeId.
 *   3. Decode pubkey hex (32 bytes) and signatureHex (64 bytes).
 *   4. Call ed25519.verify(sigBytes, tbsBytes, pubkeyBytes).
 *   5. Return the result; catch all errors and return false.
 */
export class ManifestDirectoryChallengeVerifier implements IDirectoryChallengeVerifier {
  readonly #manifestProvider: IManifestProvider;

  constructor(manifestProvider: IManifestProvider) {
    this.#manifestProvider = manifestProvider;
  }

  verifyChallenge(nodeId: string, tbsBytes: Uint8Array, signatureHex: string): ChallengeVerifyResult {
    try {
      const manifest = this.#manifestProvider.getCurrentManifest();
      if (!manifest) return { valid: false, reason: "key_not_in_manifest" };

      const node = manifest.nodes.find((n) => n.nodeId === nodeId);
      if (!node) return { valid: false, reason: "key_not_in_manifest" };

      // Decode 32-byte pubkey from 64-char hex (RFC 8032)
      if (node.pubkey.length !== 64 || !/^[0-9a-fA-F]+$/.test(node.pubkey)) {
        return { valid: false, reason: "signature_invalid" };
      }
      const pubkeyBytes = hexToBytes(node.pubkey);

      // Decode 64-byte signature from 128-char hex
      if (signatureHex.length !== 128 || !/^[0-9a-fA-F]+$/.test(signatureHex)) {
        return { valid: false, reason: "signature_invalid" };
      }
      const sigBytes = hexToBytes(signatureHex);

      // RFC 8032: ed25519.verify(signature, message, publicKey)
      const ok = ed25519.verify(sigBytes, tbsBytes, pubkeyBytes);
      return ok ? { valid: true } : { valid: false, reason: "signature_invalid" };
    } catch {
      return { valid: false, reason: "signature_invalid" };
    }
  }
}

// ─── IManifestPollScheduler ───────────────────────────────────────────────────

/**
 * ImmediatePollScheduler — fires once with a configurable delay (0ms default).
 */
export class ImmediatePollScheduler implements IManifestPollScheduler {
  readonly #delayMs: number;
  #timer: ReturnType<typeof setTimeout> | null = null;

  constructor(delayMs = 0) {
    this.#delayMs = delayMs;
  }

  scheduleNext(callbackFn: () => Promise<void>): void {
    this.cancel();
    this.#timer = setTimeout(() => {
      this.#timer = null;
      // Let errors propagate in test context — swallowing them hides assertion failures
      callbackFn().catch((err: unknown) => {
        throw err instanceof Error ? err : new Error(String(err));
      });
    }, this.#delayMs);
  }

  cancel(): void {
    if (this.#timer !== null) {
      clearTimeout(this.#timer);
      this.#timer = null;
    }
  }
}

// ─── DirectoryKeyProvider ─────────────────────────────────────────────────────

/**
 * TestDirectoryKeyProvider — takes { nodeId, privateKeyHex } in constructor.
 *
 * Crypto reference: RFC 8032 (Ed25519).
 */
export class TestDirectoryKeyProvider implements DirectoryKeyProvider {
  readonly #nodeId: string;
  readonly #privateKeyBytes: Uint8Array;

  constructor(opts: { nodeId: string; privateKeyHex: string }) {
    this.#nodeId = opts.nodeId;
    if (opts.privateKeyHex.length !== 64) {
      throw new Error(`TestDirectoryKeyProvider: privateKeyHex must be 64 chars (32 bytes), got ${opts.privateKeyHex.length}`);
    }
    this.#privateKeyBytes = hexToBytes(opts.privateKeyHex);
  }

  getNodeId(): string {
    return this.#nodeId;
  }

  /** Sign tbsBytes with Ed25519 private key (RFC 8032). Returns 64-byte Uint8Array. */
  async sign(tbsBytes: Uint8Array): Promise<Uint8Array> {
    return ed25519.sign(tbsBytes, this.#privateKeyBytes);
  }

  /** Returns the corresponding Ed25519 public key (32 bytes) as hex. */
  getPublicKeyHex(): string {
    return Buffer.from(ed25519.getPublicKey(this.#privateKeyBytes)).toString("hex");
  }
}

// ─── DirectoryManifestStore ────────────────────────────────────────────────────

/**
 * TestDirectoryManifestStore — holds a fixed ConsortiumManifest.
 */
export class TestDirectoryManifestStore implements DirectoryManifestStore {
  readonly #manifest: ConsortiumManifest;

  constructor(manifest: ConsortiumManifest) {
    this.#manifest = manifest;
  }

  getCurrentManifest(): ConsortiumManifest {
    return this.#manifest;
  }
}

// ─── Internal helpers ────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
