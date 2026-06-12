/**
 * M7-MANIFEST-001 — Consortium manifest verification.
 *
 * Provides canonical serialization and threshold signature verification for
 * ConsortiumManifest instances. The verification logic:
 *
 * 1. Computes the canonical body bytes (all fields except `signatures`,
 *    object keys sorted lexicographically at every nesting level, no whitespace,
 *    UTF-8 encoded).
 * 2. For each signature entry, verifies it against the officer key at the
 *    specified index.
 * 3. Counts only unique valid officer indices — duplicates count once.
 * 4. Returns ok: true if unique valid count >= threshold.
 *
 * Security properties:
 * - Out-of-bounds officer indices are silently skipped (AC-008).
 * - Malformed hex is caught gracefully, never throws (AC-009).
 * - Duplicate officer indices count as 1 (SI-001).
 * - Canonical serialization is insertion-order independent (SI-002).
 *
 * Crypto reference: RFC 8032 (Ed25519).
 */

import { ed25519 } from "@noble/curves/ed25519.js";

/**
 * Structural type for ConsortiumManifest — compatible with
 * @cello-protocol/protocol-types without creating a circular dependency
 * (protocol-types depends on crypto).
 */
export interface ConsortiumManifestInput {
  version: number;
  not_before: string;
  expires: string;
  nodes: readonly Record<string, unknown>[];
  signatures: readonly { officerIndex: number; signature: string }[];
  [key: string]: unknown;
}

// ─── Result type ─────────────────────────────────────────────────────────────

export type ManifestVerifySkipReason = "out_of_bounds" | "duplicate" | "malformed_signature" | "malformed_key" | "verification_failed";

export interface ManifestVerifyDiagnostics {
  threshold: number;
  validOfficers: number[];
  skippedEntries: Array<{ index: number; reason: ManifestVerifySkipReason }>;
}

export type ManifestVerifyResult =
  | { ok: true; signerCount: number }
  | { ok: false; reason: "manifest_signature_invalid"; detail: string; diagnostics: ManifestVerifyDiagnostics };

// ─── Canonical serialization ─────────────────────────────────────────────────

/**
 * Produce the canonical byte representation of a manifest body for signing.
 *
 * Pseudocode (RFC 8032 — signing input):
 *   1. Copy all fields from manifest EXCEPT `signatures`.
 *   2. Sort object keys lexicographically at EVERY nesting level (recursive).
 *   3. Serialize as JSON with no whitespace and no trailing newline.
 *   4. Encode as UTF-8 bytes.
 *
 * The resulting bytes are the message that officers sign with Ed25519.
 */
export function canonicalManifestBody(manifest: ConsortiumManifestInput): Uint8Array {
  // Step 1: exclude signatures — build body object with all fields except signatures
  const body: Record<string, unknown> = {};
  for (const key of Object.keys(manifest)) {
    if (key !== "signatures") {
      body[key] = (manifest as Record<string, unknown>)[key];
    }
  }

  // Step 2+3: sort keys recursively and serialize
  const json = JSON.stringify(body, sortedReplacer);

  // Step 4: UTF-8 encode
  return new TextEncoder().encode(json);
}

/**
 * JSON.stringify replacer that sorts object keys lexicographically at every level.
 * Arrays preserve their order (insertion-order independent only for objects).
 */
function sortedReplacer(_key: string, value: unknown): unknown {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    const sorted: Record<string, unknown> = {};
    for (const k of Object.keys(value).sort()) {
      sorted[k] = (value as Record<string, unknown>)[k];
    }
    return sorted;
  }
  return value;
}

// ─── Threshold signature verification ────────────────────────────────────────

/**
 * Verify a consortium manifest against a set of officer root keys.
 *
 * Pseudocode (RFC 8032 — Ed25519 verification):
 *   1. Compute canonical body bytes via canonicalManifestBody.
 *   2. For each signature entry in manifest.signatures:
 *      a. If officerIndex is out of bounds (< 0 or >= rootKeys.length), skip.
 *      b. If officerIndex has already been seen, skip (duplicate — SI-001).
 *      c. Decode the hex signature to bytes. If malformed, skip.
 *      d. Decode the root key at officerIndex to bytes. If malformed, skip.
 *      e. Verify: ed25519.verify(signature, body, publicKey).
 *      f. If valid, add officerIndex to the set of verified signers.
 *   3. If |verified signers| >= threshold → { ok: true, signerCount }.
 *   4. Otherwise → { ok: false, reason, detail }.
 *
 * This function NEVER throws. All error conditions produce a result value.
 */
export function verifyManifest(
  manifest: ConsortiumManifestInput,
  rootKeys: readonly string[],
  threshold: number,
): ManifestVerifyResult {
  const body = canonicalManifestBody(manifest);
  const verifiedIndices = new Set<number>();
  const seenIndices = new Set<number>();
  const skippedEntries: Array<{ index: number; reason: ManifestVerifySkipReason }> = [];

  for (const entry of manifest.signatures) {
    const { officerIndex, signature } = entry;

    // Skip out-of-bounds indices (AC-008)
    if (officerIndex < 0 || officerIndex >= rootKeys.length) {
      skippedEntries.push({ index: officerIndex, reason: "out_of_bounds" });
      continue;
    }

    // Skip duplicate indices — only first occurrence counts (SI-001)
    if (seenIndices.has(officerIndex)) {
      skippedEntries.push({ index: officerIndex, reason: "duplicate" });
      continue;
    }
    seenIndices.add(officerIndex);

    // Decode signature hex to bytes (Ed25519 signature = 64 bytes)
    const sigBytes = hexToBytes(signature, 64);
    if (sigBytes === null) {
      skippedEntries.push({ index: officerIndex, reason: "malformed_signature" });
      continue;
    }

    // Decode public key hex to bytes (Ed25519 public key = 32 bytes)
    const pubkeyBytes = hexToBytes(rootKeys[officerIndex], 32);
    if (pubkeyBytes === null) {
      skippedEntries.push({ index: officerIndex, reason: "malformed_key" });
      continue;
    }

    // Verify Ed25519 signature (RFC 8032)
    try {
      if (ed25519.verify(sigBytes, body, pubkeyBytes)) {
        verifiedIndices.add(officerIndex);
      } else {
        skippedEntries.push({ index: officerIndex, reason: "verification_failed" });
      }
    } catch {
      skippedEntries.push({ index: officerIndex, reason: "verification_failed" });
      continue;
    }
  }

  const signerCount = verifiedIndices.size;

  if (signerCount >= threshold) {
    return { ok: true, signerCount };
  }

  return {
    ok: false,
    reason: "manifest_signature_invalid",
    detail: `${signerCount} valid of ${threshold} required`,
    diagnostics: {
      threshold,
      validOfficers: Array.from(verifiedIndices).sort((a, b) => a - b),
      skippedEntries,
    },
  };
}

// ─── Internal helpers ────────────────────────────────────────────────────────

/**
 * Decode a hex string to Uint8Array with expected byte length validation.
 * Returns null if the input is not valid hex or doesn't match expectedBytes.
 * Never throws.
 */
function hexToBytes(hex: string, expectedBytes: number): Uint8Array | null {
  if (hex.length !== expectedBytes * 2) {
    return null;
  }
  try {
    const bytes = new Uint8Array(expectedBytes);
    for (let i = 0; i < bytes.length; i++) {
      const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
      if (Number.isNaN(byte)) {
        return null;
      }
      bytes[i] = byte;
    }
    return bytes;
  } catch {
    return null;
  }
}
