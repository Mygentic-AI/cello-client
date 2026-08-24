/**
 * Test fixture for consortium manifest creation.
 *
 * Provides makeTestManifest() which creates a fully-signed ConsortiumManifest
 * using deterministic test officer keys. The manifest is signed with officer
 * indices 0, 1, 2 (meeting the threshold of 3).
 *
 * The private keys (TEST_OFFICER_SEEDS) are defined here and MUST NOT be exported
 * from the package index. They are only available via direct import of this file
 * for internal test use.
 *
 * Crypto reference: RFC 8032 (Ed25519).
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { canonicalManifestBody } from "./manifest.js";
import type { ConsortiumManifestInput } from "./manifest.js";

/**
 * Deterministic test officer seeds (private keys). Used to derive
 * TEST_CONSORTIUM_ROOT_KEYS and to sign test manifests.
 *
 * MUST NOT be exported from the package index — only from this file for internal use.
 */
export const TEST_OFFICER_SEEDS: readonly [Uint8Array, Uint8Array, Uint8Array, Uint8Array, Uint8Array] = [
  new Uint8Array(32).fill(0x01),
  new Uint8Array(32).fill(0x02),
  new Uint8Array(32).fill(0x03),
  new Uint8Array(32).fill(0x04),
  new Uint8Array(32).fill(0x05),
] as const;

/** Node entry for makeTestManifest input. Structurally matches ConsortiumNode from protocol-types. */
export type TestConsortiumNode = {
  nodeId: string;
  pubkey: string;
  region: string;
  provider: "aws" | "gcp" | "azure";
  endpoint: string;
  /** M12 role split — optional; absent ⇒ validator (canonical body omits absent fields). */
  role?: "validator" | "replica";
  /** M12 anti-entropy dial identity — optional. */
  peerId?: string;
};

export interface MakeTestManifestOpts {
  version?: number;
  notBefore?: string;
  expires?: string;
}

/**
 * Create a test ConsortiumManifest signed by officers 0, 1, 2 with Ed25519 (RFC 8032)
 * over the canonical body bytes from canonicalManifestBody.
 */
export function makeTestManifest(
  nodes: TestConsortiumNode[],
  opts?: MakeTestManifestOpts,
): ConsortiumManifestInput {
  const manifest: ConsortiumManifestInput = {
    version: opts?.version ?? 1,
    not_before: opts?.notBefore ?? "2026-01-01T00:00:00Z",
    /**
     * ⚠️ A FIXTURE THAT EXPIRES IS A TEST SUITE WITH A FUSE. This defaulted to `2027-01-01`, four
     * months out when it was found (2026-08-24) — after which every default-fixture manifest becomes
     * EXPIRED and every test that needs an in-window one goes red **on a date, with no code change**.
     * It would also have silently switched on the lapsed-manifest branches added by
     * `DOD-M15-EXPIRY-CONSUMER-POLICY-1` for every existing verifier test at the same moment.
     *
     * Far-future and FIXED, not `Date.now() + 1y`: a rolling default makes the fixture's window
     * depend on the clock, and the tests that care about window boundaries pass their own dates
     * anyway — which is the reason this default only ever needs to mean "in window".
     */
    expires: opts?.expires ?? "2099-01-01T00:00:00Z",
    nodes: nodes as readonly Record<string, unknown>[],
    signatures: [],
  };

  // Compute canonical body for signing
  const body = canonicalManifestBody(manifest);

  // Sign with officers 0, 1, 2 — meeting threshold of 3
  const signatures = [0, 1, 2].map((idx) => ({
    officerIndex: idx,
    signature: Buffer.from(ed25519.sign(body, TEST_OFFICER_SEEDS[idx])).toString("hex"),
  }));

  manifest.signatures = signatures;
  return manifest;
}

// ─── Test directory node keypair ─────────────────────────────────────────────

/**
 * Deterministic test directory node keypair for step-5 challenge signing tests.
 *
 * Derived from SHA-256("cello-test-directory-node-key-0") as a 32-byte seed.
 * This seed is DISTINCT from TEST_OFFICER_SEEDS (0x01..0x05) — it is NOT an
 * officer key. It represents a directory node's per-node Ed25519 signing key.
 *
 * Crypto reference: RFC 8032 (Ed25519).
 * Seed derivation: SHA-256("cello-test-directory-node-key-0") — deterministic.
 */
export const TEST_DIRECTORY_NODE_KEYPAIR = {
  privateKeyHex: "707a125efaed6d467e8cac1758b3a87af260a5b9c7a6f0d6a74d364c1d5dacd9",
  publicKeyHex: "b93092dd6bf675c00a895abc05503dfd1214a170a2d945d97bab81fd5cfe6a1b",
} as const;
