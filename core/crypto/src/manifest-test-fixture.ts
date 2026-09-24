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

import { createHash } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";
import { canonicalManifestBody } from "./manifest.js";
import { mlDsaProviderFromSeed } from "./ml-dsa.js";
import { mlKemKeypairFromSeed } from "./ml-kem.js";
import { signMlDsa } from "./pq-frame.js";
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
  /** M9D 004: defaults to a deterministic key per nodeId. */
  mldsa_pubkey?: string;
  nodeId: string;
  pubkey: string;
  region: string;
  provider: "aws" | "gcp" | "azure";
  endpoint: string;
  /** M12 role split. Defaults to "validator" here — the verifier requires one. */
  role?: "validator" | "replica";
  /** libp2p PeerId. Defaults to a per-nodeId test value here — the verifier requires one. */
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
export async function makeTestManifest(
  nodes: TestConsortiumNode[],
  opts?: MakeTestManifestOpts,
): Promise<ConsortiumManifestInput> {
  const manifest: ConsortiumManifestInput = {
    version: opts?.version ?? 1,
    not_before: opts?.notBefore ?? "2026-01-01T00:00:00Z",
    /**
     * ⚠️ A FIXTURE THAT EXPIRES IS A TEST SUITE WITH A FUSE. Far-future and FIXED, not a rolling
     * default: a rolling default makes the fixture's window depend on the clock, and the tests that
     * care about window boundaries pass their own dates anyway.
     */
    expires: opts?.expires ?? "2099-01-01T00:00:00Z",
    nodes: await Promise.all(nodes.map(async (n) => ({
      ...n,
      role: n.role ?? "validator",
      peerId: n.peerId ?? `12D3KooWTest${n.nodeId}`,
      // M9D 004: every node names its ML-DSA key — deterministic per nodeId unless the test names one.
      mldsa_pubkey: n.mldsa_pubkey ?? await testNodeMlDsaPubkeyHex(n.nodeId),
    }))) as readonly Record<string, unknown>[],
    intake_key: { key_id: "test-intake-0", pubkey: "d".repeat(64) },
    mlkem_intake_key: await testMlKemIntakeKeyHex(),
    signatures: [],
    pq_signatures: [],
  };

  // Both officer sets sign the same canonical body (which excludes both signature fields).
  const body = canonicalManifestBody(manifest);
  manifest.signatures = [0, 1, 2].map((idx) => ({
    officerIndex: idx,
    signature: Buffer.from(ed25519.sign(body, TEST_OFFICER_SEEDS[idx])).toString("hex"),
  }));
  manifest.pq_signatures = await Promise.all([0, 1, 2].map(async (idx) => ({
    officerIndex: idx,
    signature: Buffer.from(await signMlDsa(await mlDsaProviderFromSeed(TEST_OFFICER_PQ_SEEDS[idx]), "cello-mldsa-consortium-manifest-v1", body)).toString("hex"),
  })));
  return manifest;
}

// ─── Test root keys (M9D 004: moved here from the deleted consortium-keys.ts) ──

export const TEST_CONSORTIUM_ROOT_KEYS: readonly string[] = TEST_OFFICER_SEEDS.map((s) =>
  Buffer.from(ed25519.getPublicKey(s)).toString("hex"),
);
export const TEST_CONSORTIUM_THRESHOLD = 3;

/** The test ML-DSA officer seeds — distinct from the Ed25519 ones. Never exported from the index. */
export const TEST_OFFICER_PQ_SEEDS: readonly Uint8Array[] = [0x11, 0x12, 0x13, 0x14, 0x15].map((b) => new Uint8Array(32).fill(b));

/** The test ML-DSA officer PUBLIC keys, hex — the PQ roots a test verifies against. */
export async function testConsortiumRootKeysPq(): Promise<string[]> {
  return Promise.all(TEST_OFFICER_PQ_SEEDS.map(async (s) =>
    Buffer.from(await (await mlDsaProviderFromSeed(s)).getPublicKey()).toString("hex")));
}
export const TEST_CONSORTIUM_PQ_THRESHOLD = 3;

/** A test node's ML-DSA public key, deterministic from its nodeId. */
export async function testNodeMlDsaPubkeyHex(nodeId: string): Promise<string> {
  const seed = new Uint8Array(createHash("sha256").update(`cello-test-node-mldsa:${nodeId}`).digest());
  return Buffer.from(await (await mlDsaProviderFromSeed(seed)).getPublicKey()).toString("hex");
}

/** A deterministic test ML-KEM intake public key, hex. */
export async function testMlKemIntakeKeyHex(): Promise<string> {
  return Buffer.from((await mlKemKeypairFromSeed(new Uint8Array(64).fill(0x6b))).publicKey).toString("hex");
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
