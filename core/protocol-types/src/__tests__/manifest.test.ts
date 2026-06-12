/**
 * M7-MANIFEST-001 — ConsortiumManifest type tests (protocol-types package)
 *
 * SPARC Specification:
 *
 * AC-001: ConsortiumManifest type has all required fields —
 *   version (number), not_before (string), expires (string),
 *   nodes (ConsortiumNode[]), signatures (OfficerSignature[]).
 *   ConsortiumNode has: nodeId, pubkey (64 hex), region, provider ('aws'|'gcp'|'azure'), endpoint.
 *   OfficerSignature has: officerIndex (number, 0-based), signature (128 hex).
 *
 * AC-002: ManifestError is a string literal union with const exports:
 *   MANIFEST_SIGNATURE_INVALID, MANIFEST_VERSION_ROLLBACK, MANIFEST_EXPIRED.
 */

import { describe, it, expect } from "vitest";
import type {
  ConsortiumManifest,
  ConsortiumNode,
  OfficerSignature,
  ManifestError,
} from "../manifest.js";
import {
  MANIFEST_SIGNATURE_INVALID,
  MANIFEST_VERSION_ROLLBACK,
  MANIFEST_EXPIRED,
} from "../manifest.js";

// ─── AC-001: ConsortiumManifest type completeness ────────────────────────────

describe("AC-001: ConsortiumManifest type completeness", () => {
  it("ConsortiumNode accepts all required fields with correct types", () => {
    const node: ConsortiumNode = {
      nodeId: "node-us-east-1",
      pubkey: "a".repeat(64),
      region: "us-east-1",
      provider: "aws",
      endpoint: "https://dir-us-east-1.cello.example.com",
    };
    expect(node.nodeId).toBe("node-us-east-1");
    expect(node.pubkey).toHaveLength(64);
    expect(node.provider).toBe("aws");
  });

  it("ConsortiumNode provider field only accepts aws | gcp | azure", () => {
    // Type-level test — these all compile:
    const awsNode: ConsortiumNode = { nodeId: "n1", pubkey: "a".repeat(64), region: "us-east-1", provider: "aws", endpoint: "https://a.example.com" };
    const gcpNode: ConsortiumNode = { nodeId: "n2", pubkey: "b".repeat(64), region: "europe-west1", provider: "gcp", endpoint: "https://b.example.com" };
    const azureNode: ConsortiumNode = { nodeId: "n3", pubkey: "c".repeat(64), region: "westeurope", provider: "azure", endpoint: "https://c.example.com" };
    expect(awsNode.provider).toBe("aws");
    expect(gcpNode.provider).toBe("gcp");
    expect(azureNode.provider).toBe("azure");
  });

  it("OfficerSignature has officerIndex (number) and signature (string)", () => {
    const sig: OfficerSignature = {
      officerIndex: 0,
      signature: "f".repeat(128),
    };
    expect(sig.officerIndex).toBe(0);
    expect(sig.signature).toHaveLength(128);
  });

  it("ConsortiumManifest has version, not_before, expires, nodes, signatures", () => {
    const manifest: ConsortiumManifest = {
      version: 1,
      not_before: "2026-01-01T00:00:00Z",
      expires: "2027-01-01T00:00:00Z",
      nodes: [
        { nodeId: "n1", pubkey: "a".repeat(64), region: "us-east-1", provider: "aws", endpoint: "https://a.example.com" },
      ],
      signatures: [
        { officerIndex: 0, signature: "f".repeat(128) },
      ],
    };
    expect(manifest.version).toBe(1);
    expect(manifest.not_before).toBe("2026-01-01T00:00:00Z");
    expect(manifest.expires).toBe("2027-01-01T00:00:00Z");
    expect(manifest.nodes).toHaveLength(1);
    expect(manifest.signatures).toHaveLength(1);
  });
});

// ─── AC-002: ManifestError type with const exports ───────────────────────────

describe("AC-002: ManifestError type with const exports", () => {
  it("MANIFEST_SIGNATURE_INVALID equals 'manifest_signature_invalid'", () => {
    expect(MANIFEST_SIGNATURE_INVALID).toBe("manifest_signature_invalid");
  });

  it("MANIFEST_VERSION_ROLLBACK equals 'manifest_version_rollback'", () => {
    expect(MANIFEST_VERSION_ROLLBACK).toBe("manifest_version_rollback");
  });

  it("MANIFEST_EXPIRED equals 'manifest_expired'", () => {
    expect(MANIFEST_EXPIRED).toBe("manifest_expired");
  });

  it("ManifestError const values are assignable to ManifestError type", () => {
    // Type-level test — all three compile as ManifestError
    const a: ManifestError = MANIFEST_SIGNATURE_INVALID;
    const b: ManifestError = MANIFEST_VERSION_ROLLBACK;
    const c: ManifestError = MANIFEST_EXPIRED;
    expect([a, b, c]).toHaveLength(3);
  });

  it("all three error codes are distinct strings", () => {
    const codes = new Set([MANIFEST_SIGNATURE_INVALID, MANIFEST_VERSION_ROLLBACK, MANIFEST_EXPIRED]);
    expect(codes.size).toBe(3);
  });
});
