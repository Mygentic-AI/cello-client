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
import { hexToBytes } from "./hex.js";

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

export interface ManifestVerifySkippedEntry {
  index: number;
  reason: ManifestVerifySkipReason;
  error?: string;
}

export interface ManifestVerifyDiagnostics {
  threshold: number;
  validOfficers: number[];
  skippedEntries: ManifestVerifySkippedEntry[];
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
 *      b. Decode the hex signature to bytes. If malformed, skip.
 *      c. Decode the root key at officerIndex to bytes. If malformed, skip.
 *      d. Verify: ed25519.verify(signature, body, publicKey).
 *      e. If valid AND officerIndex not already in verified set, add it (SI-001).
 *      f. If valid BUT officerIndex already verified, mark as duplicate.
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
  // A manifest with no nodes is structurally invalid — the consumer has no nodes
  // to connect to and cannot distinguish "empty by design" from "tampered" (AC-003(d)).
  if (manifest.nodes.length === 0) {
    return {
      ok: false,
      reason: "manifest_signature_invalid",
      detail: "manifest contains no nodes",
      diagnostics: { threshold, validOfficers: [], skippedEntries: [] },
    };
  }

  // M12 ROLE-MANIFEST-1: close the role domain at the verification boundary. `role` is
  // untrusted input; nothing upstream validates it. Reject any node whose role is PRESENT and
  // is neither exactly "validator" nor exactly "replica" — otherwise a one-character tooling
  // error (e.g. "Replica") would be counted as a validator here (`!== "replica"`) while the
  // directory's `validatorNodes` helper (`role === "validator"`) excludes it, a cross-repo
  // gate/arithmetic split-brain. On the validated domain the two spellings coincide.
  for (const n of manifest.nodes) {
    const role = (n as { role?: unknown }).role;
    if (role !== undefined && role !== "validator" && role !== "replica") {
      return {
        ok: false,
        reason: "manifest_signature_invalid",
        detail: `node has unknown role ${JSON.stringify(role)} (expected "validator" or "replica")`,
        diagnostics: { threshold, validOfficers: [], skippedEntries: [] },
      };
    }
  }

  // A manifest with nodes but ZERO validators (every node role="replica") is rejected loudly.
  // Replicas hold no shares and never sign, so no ceremony could ever complete — a replica-only
  // consortium is non-functional and is treated as tampered, exactly like the empty case.
  // Absent `role` ⇒ validator (backward compat), so pre-M12 manifests always have ≥1 validator.
  const validatorCount = manifest.nodes.filter(
    (n) => (n as { role?: unknown }).role !== "replica",
  ).length;
  if (validatorCount === 0) {
    return {
      ok: false,
      reason: "manifest_signature_invalid",
      detail: "manifest contains no validator nodes (all replicas)",
      diagnostics: { threshold, validOfficers: [], skippedEntries: [] },
    };
  }

  const body = canonicalManifestBody(manifest);
  const verifiedIndices = new Set<number>();
  const skippedEntries: ManifestVerifySkippedEntry[] = [];

  for (const entry of manifest.signatures) {
    const { officerIndex, signature } = entry;

    // Skip out-of-bounds indices (AC-008)
    if (officerIndex < 0 || officerIndex >= rootKeys.length) {
      skippedEntries.push({ index: officerIndex, reason: "out_of_bounds" });
      continue;
    }

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
    let isValid = false;
    try {
      isValid = ed25519.verify(sigBytes, body, pubkeyBytes);
    } catch (err: unknown) {
      skippedEntries.push({ index: officerIndex, reason: "verification_failed", error: err instanceof Error ? err.message : String(err) });
      continue;
    }

    if (!isValid) {
      skippedEntries.push({ index: officerIndex, reason: "verification_failed" });
      continue;
    }

    // Check uniqueness AFTER verification — only first valid sig per officer counts (SI-001)
    if (verifiedIndices.has(officerIndex)) {
      skippedEntries.push({ index: officerIndex, reason: "duplicate" });
      continue;
    }

    verifiedIndices.add(officerIndex);
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
 * hexToBytes is shared from ./hex.js (also used by ae-peer-auth) so validation strictness cannot
 * diverge between callers — strict regex + exact length, never throws.
 */
