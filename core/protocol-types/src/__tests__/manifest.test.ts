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
  NodeRole,
} from "../manifest.js";
import {
  MANIFEST_SIGNATURE_INVALID,
  MANIFEST_VERSION_ROLLBACK,
  MANIFEST_EXPIRED,
  nodeRole,
  isValidator,
  validatorNodes,
} from "../manifest.js";

const mkNode = (nodeId: string, role?: NodeRole): ConsortiumNode => ({
  nodeId,
  pubkey: "a".repeat(64),
  region: "us-east-1",
  provider: "aws",
  endpoint: "https://x.example.com",
  ...(role ? { role } : {}),
});

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

// ─── M12 role split: role defaulting + validator filtering ───────────────────

describe("M12 ROLE-MANIFEST-1: node role defaulting", () => {
  it("a node with no role field is (effectively) a validator — backward compat", () => {
    const node = mkNode("legacy");
    expect(node.role).toBeUndefined();
    expect(nodeRole(node)).toBe("validator");
    expect(isValidator(node)).toBe(true);
  });

  it("an explicit validator is a validator; an explicit replica is not", () => {
    expect(isValidator(mkNode("v", "validator"))).toBe(true);
    expect(isValidator(mkNode("r", "replica"))).toBe(false);
    expect(nodeRole(mkNode("r", "replica"))).toBe("replica");
  });

  it("validatorNodes excludes replicas and keeps role-less (default validator) nodes", () => {
    const nodes = [mkNode("a"), mkNode("b", "validator"), mkNode("c", "replica")];
    const vs = validatorNodes(nodes);
    expect(vs.map((n) => n.nodeId)).toEqual(["a", "b"]);
  });

  it("an all-legacy (role-less) manifest counts every node as a validator", () => {
    const nodes = [mkNode("a"), mkNode("b"), mkNode("c")];
    expect(validatorNodes(nodes)).toHaveLength(3);
  });

  it("a replica-only node set yields zero validators (caller must reject)", () => {
    const nodes = [mkNode("r1", "replica"), mkNode("r2", "replica")];
    expect(validatorNodes(nodes)).toHaveLength(0);
  });

  it("nodeRole/isValidator treat any non-'replica' string as validator (matches crypto count)", () => {
    // Untrusted input can carry a bad role despite the type; the verify boundary rejects it, but
    // the in-memory helpers must never disagree with crypto's `!== "replica"` count. A capital
    // "Replica" is NOT the exact replica sentinel → validator, identical to the crypto side.
    const bad = { ...mkNode("x"), role: "Replica" as unknown as NodeRole };
    expect(nodeRole(bad)).toBe("validator");
    expect(isValidator(bad)).toBe(true);
    const realReplica = { ...mkNode("y"), role: "replica" as NodeRole };
    expect(isValidator(realReplica)).toBe(false);
  });

  it("ConsortiumNode accepts optional role and peerId", () => {
    const node: ConsortiumNode = {
      nodeId: "gcp-usc1",
      pubkey: "b".repeat(64),
      region: "us-central1",
      provider: "gcp",
      endpoint: "https://d.example.com",
      role: "replica",
      peerId: "12D3KooWTest",
    };
    expect(node.role).toBe("replica");
    expect(node.peerId).toBe("12D3KooWTest");
  });
});
