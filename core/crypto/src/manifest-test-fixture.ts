/**
 * M7-MANIFEST-001 — Test fixture for consortium manifest creation.
 *
 * Provides makeTestManifest() which creates a fully-signed ConsortiumManifest
 * using deterministic test officer keys. The manifest is signed with officer
 * indices 0, 1, 2 (meeting the threshold of 3).
 *
 * The private keys used for signing are NOT exported from the package index —
 * they stay internal to this file and consortium-keys.ts (AC-011).
 *
 * Crypto reference: RFC 8032 (Ed25519).
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { canonicalManifestBody } from "./manifest.js";
import type { ConsortiumManifestInput } from "./manifest.js";
import { TEST_OFFICER_SEEDS } from "./consortium-keys.js";

/** Node entry for makeTestManifest input. Structurally matches ConsortiumNode from protocol-types. */
export type TestConsortiumNode = {
  nodeId: string;
  pubkey: string;
  region: string;
  provider: "aws" | "gcp" | "azure";
  endpoint: string;
};

export interface MakeTestManifestOpts {
  version?: number;
  notBefore?: string;
  expires?: string;
}

/**
 * Create a test ConsortiumManifest signed by officers 0, 1, 2.
 *
 * Pseudocode:
 *   1. Build the manifest body with provided nodes and optional overrides.
 *   2. Compute canonical body bytes via canonicalManifestBody.
 *   3. Sign with TEST_OFFICER_SEEDS[0], [1], [2] using Ed25519 (RFC 8032).
 *   4. Return the complete manifest with 3 valid signatures.
 */
export function makeTestManifest(
  nodes: TestConsortiumNode[],
  opts?: MakeTestManifestOpts,
): ConsortiumManifestInput {
  const manifest: ConsortiumManifestInput = {
    version: opts?.version ?? 1,
    not_before: opts?.notBefore ?? "2026-01-01T00:00:00Z",
    expires: opts?.expires ?? "2027-01-01T00:00:00Z",
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
