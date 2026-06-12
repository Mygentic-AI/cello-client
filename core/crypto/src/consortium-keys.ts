/**
 * M7-MANIFEST-001 — Consortium officer root key constants.
 *
 * These Ed25519 public keys are the root of trust for consortium manifest
 * threshold signatures. A manifest is valid only if at least CONSORTIUM_THRESHOLD
 * unique officer keys have signed it.
 *
 * Production keys are placeholder zeros until the initial key ceremony is
 * conducted. Test keys are derived from deterministic seeds defined in
 * manifest-test-fixture.ts (AC-011).
 *
 * Crypto reference: RFC 8032 (Ed25519).
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { TEST_OFFICER_SEEDS } from "./manifest-test-fixture.js";

// ─── Production constants ────────────────────────────────────────────────────

/**
 * Production consortium officer root keys.
 *
 * Pre-ceremony placeholder: all zeros. These will be replaced with real
 * Ed25519 public keys after the initial officer key ceremony is conducted.
 * Until then, no production manifest can pass verification — this is by design.
 */
export const CONSORTIUM_ROOT_KEYS: readonly [string, string, string, string, string] = [
  "0".repeat(64),
  "0".repeat(64),
  "0".repeat(64),
  "0".repeat(64),
  "0".repeat(64),
] as const;

/** Minimum number of valid officer signatures required for manifest acceptance. */
export const CONSORTIUM_THRESHOLD = 3;

// ─── Test constants ──────────────────────────────────────────────────────────

/**
 * Test consortium officer root keys — real Ed25519 public keys derived from
 * deterministic fixed seeds in manifest-test-fixture.ts. Completely disjoint
 * from production keys (SI-003).
 */
export const TEST_CONSORTIUM_ROOT_KEYS: readonly [string, string, string, string, string] = [
  Buffer.from(ed25519.getPublicKey(TEST_OFFICER_SEEDS[0])).toString("hex"),
  Buffer.from(ed25519.getPublicKey(TEST_OFFICER_SEEDS[1])).toString("hex"),
  Buffer.from(ed25519.getPublicKey(TEST_OFFICER_SEEDS[2])).toString("hex"),
  Buffer.from(ed25519.getPublicKey(TEST_OFFICER_SEEDS[3])).toString("hex"),
  Buffer.from(ed25519.getPublicKey(TEST_OFFICER_SEEDS[4])).toString("hex"),
] as const;

/** Test threshold — same as production for realistic test coverage. */
export const TEST_CONSORTIUM_THRESHOLD = 3;
