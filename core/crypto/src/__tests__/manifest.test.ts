/**
 * M7-MANIFEST-001 — Consortium manifest verification and fixture tests
 *
 * SPARC Specification — AC coverage:
 *
 * AC-003: canonicalManifestBody is deterministic — forward/reverse key order → identical bytes.
 * AC-004: 3 valid signatures → { ok: true, signerCount: 3 }; corrupting any byte → { ok: false }.
 * AC-005: 1 corrupted signature → only 2 count → { ok: false, detail contains '2 valid' and '3 required' }.
 * AC-006: Only 2 valid sigs → { ok: false }.
 * AC-007: 3 entries all officerIndex: 0 → only 1 unique → { ok: false }.
 * AC-008: officerIndex: 99 → silently skipped, no RangeError.
 * AC-009: Malformed hex → silently handled, no throw.
 * AC-010: CONSORTIUM_ROOT_KEYS is readonly tuple of 5 hex(64), CONSORTIUM_THRESHOLD=3.
 * AC-011: TEST_CONSORTIUM_ROOT_KEYS separate from production, test privkeys not in public exports.
 * AC-012: makeTestManifest produces valid manifests that pass verifyManifest.
 * AC-013: Ceremony output verifies; rogue key signature fails.
 * AC-014: Error distinctness — every failure path is unique and diagnosable.
 * AC-017: Empty signatures array → { ok: false, detail: '0 valid of 3 required' }.
 * AC-018: All malformed entries → processes all (no early exit), returns { ok: false }.
 *
 * SI-001: Duplicate officer index → only 1 unique counts.
 * SI-002: Canonical serialization is insertion-order independent.
 * SI-003: Test keys and production keys are completely disjoint sets.
 *
 * Crypto reference: RFC 8032 (Ed25519).
 */

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  canonicalManifestBody,
  verifyManifest,
  CONSORTIUM_ROOT_KEYS,
  CONSORTIUM_THRESHOLD,
  TEST_CONSORTIUM_ROOT_KEYS,
  TEST_CONSORTIUM_THRESHOLD,
  makeTestManifest,
} from "../index.js";
import type { ConsortiumManifestInput } from "../manifest.js";
import type { TestConsortiumNode } from "../manifest-test-fixture.js";

// ─── Test helpers ────────────────────────────────────────────────────────────

const toHex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

/** Deterministic test officer seeds — same as in manifest-test-fixture.ts */
const TEST_OFFICER_SEEDS = [
  new Uint8Array(32).fill(0x01),
  new Uint8Array(32).fill(0x02),
  new Uint8Array(32).fill(0x03),
  new Uint8Array(32).fill(0x04),
  new Uint8Array(32).fill(0x05),
] as const;

const TEST_OFFICER_PUBKEYS = TEST_OFFICER_SEEDS.map((seed) =>
  toHex(ed25519.getPublicKey(seed)),
);

function makeNodes(): TestConsortiumNode[] {
  return [
    { nodeId: "node-us-east-1", pubkey: "a".repeat(64), region: "us-east-1", provider: "aws", endpoint: "https://us.example.com" },
    { nodeId: "node-eu-central-1", pubkey: "b".repeat(64), region: "eu-central-1", provider: "gcp", endpoint: "https://eu.example.com" },
    { nodeId: "node-ap-northeast-1", pubkey: "c".repeat(64), region: "ap-northeast-1", provider: "azure", endpoint: "https://ap.example.com" },
  ];
}

function signManifest(manifest: ConsortiumManifestInput, officerIndices: number[]): { officerIndex: number; signature: string }[] {
  const body = canonicalManifestBody(manifest);
  return officerIndices.map((idx) => ({
    officerIndex: idx,
    signature: toHex(ed25519.sign(body, TEST_OFFICER_SEEDS[idx])),
  }));
}

// ─── AC-003: canonicalManifestBody determinism ───────────────────────────────

describe("AC-003: canonicalManifestBody determinism", () => {
  it("produces identical bytes regardless of object property insertion order", () => {
    const nodes = makeNodes();

    // Forward key order
    const manifestForward: ConsortiumManifestInput = {
      version: 1,
      not_before: "2026-01-01T00:00:00Z",
      expires: "2027-01-01T00:00:00Z",
      nodes,
      signatures: [],
    };

    // Reverse key order — same data, different property insertion order
    const manifestReverse = {
      signatures: [],
      nodes,
      expires: "2027-01-01T00:00:00Z",
      not_before: "2026-01-01T00:00:00Z",
      version: 1,
    } as ConsortiumManifestInput;

    const bodyForward = canonicalManifestBody(manifestForward);
    const bodyReverse = canonicalManifestBody(manifestReverse);

    expect(toHex(bodyForward)).toBe(toHex(bodyReverse));
  });

  it("produces identical bytes regardless of node property insertion order", () => {
    const nodeForward: TestConsortiumNode = { nodeId: "n1", pubkey: "a".repeat(64), region: "us-east-1", provider: "aws", endpoint: "https://a.com" };
    const nodeReverse = { endpoint: "https://a.com", provider: "aws" as const, region: "us-east-1", pubkey: "a".repeat(64), nodeId: "n1" };

    const m1: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes: [nodeForward], signatures: [] };
    const m2: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes: [nodeReverse], signatures: [] };

    expect(toHex(canonicalManifestBody(m1))).toBe(toHex(canonicalManifestBody(m2)));
  });

  it("signatures field is excluded from canonical body", () => {
    const nodes = makeNodes();
    const m1: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes, signatures: [] };
    const m2: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes, signatures: [{ officerIndex: 0, signature: "f".repeat(128) }] };

    expect(toHex(canonicalManifestBody(m1))).toBe(toHex(canonicalManifestBody(m2)));
  });

  it("returns a Uint8Array (UTF-8 encoded bytes)", () => {
    const manifest: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes: [], signatures: [] };
    const body = canonicalManifestBody(manifest);
    expect(body).toBeInstanceOf(Uint8Array);
    expect(body.length).toBeGreaterThan(0);
  });

  it("output is valid JSON with sorted keys", () => {
    const manifest: ConsortiumManifestInput = { version: 2, not_before: "2026-06-01T00:00:00Z", expires: "2027-06-01T00:00:00Z", nodes: makeNodes(), signatures: [] };
    const body = canonicalManifestBody(manifest);
    const json = new TextDecoder().decode(body);
    const parsed = JSON.parse(json);

    // Top-level keys should be sorted
    const keys = Object.keys(parsed);
    const sortedKeys = [...keys].sort();
    expect(keys).toEqual(sortedKeys);

    // signatures should NOT be present
    expect(parsed).not.toHaveProperty("signatures");
  });
});

// ─── SI-002: Canonical serialization is insertion-order independent ──────────

describe("SI-002: canonical serialization is insertion-order independent", () => {
  it("deeply nested objects are sorted at every level", () => {
    const node1: TestConsortiumNode = { nodeId: "n1", pubkey: "a".repeat(64), region: "us-east-1", provider: "aws", endpoint: "https://a.com" };
    // Same node but properties in reverse order
    const node2 = { endpoint: "https://a.com", provider: "aws" as const, region: "us-east-1", pubkey: "a".repeat(64), nodeId: "n1" };

    const m1: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes: [node1], signatures: [] };
    const m2: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes: [node2], signatures: [] };

    expect(toHex(canonicalManifestBody(m1))).toBe(toHex(canonicalManifestBody(m2)));
  });
});

// ─── AC-004: 3 valid signatures → ok: true ──────────────────────────────────

describe("AC-004: threshold verification — 3 valid signatures", () => {
  it("3 valid signatures → { ok: true, signerCount: 3 }", () => {
    const nodes = makeNodes();
    const manifest: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes, signatures: [] };
    manifest.signatures = signManifest(manifest, [0, 1, 2]);

    const result = verifyManifest(manifest, TEST_OFFICER_PUBKEYS, 3);
    expect(result).toEqual({ ok: true, signerCount: 3 });
  });

  it("corrupting any single byte in a signature → { ok: false }", () => {
    const nodes = makeNodes();
    const manifest: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes, signatures: [] };
    manifest.signatures = signManifest(manifest, [0, 1, 2]);

    // Corrupt first byte of first signature
    const corrupted = { ...manifest };
    const sigHex = corrupted.signatures[0].signature;
    const firstByte = parseInt(sigHex.slice(0, 2), 16);
    const corruptedByte = ((firstByte + 1) % 256).toString(16).padStart(2, "0");
    corrupted.signatures = [
      { officerIndex: 0, signature: corruptedByte + sigHex.slice(2) },
      ...manifest.signatures.slice(1),
    ];

    const result = verifyManifest(corrupted, TEST_OFFICER_PUBKEYS, 3);
    expect(result.ok).toBe(false);
  });

  it("4 valid signatures → { ok: true, signerCount: 4 }", () => {
    const nodes = makeNodes();
    const manifest: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes, signatures: [] };
    manifest.signatures = signManifest(manifest, [0, 1, 2, 3]);

    const result = verifyManifest(manifest, TEST_OFFICER_PUBKEYS, 3);
    expect(result).toEqual({ ok: true, signerCount: 4 });
  });
});

// ─── AC-005: 1 corrupted → 2 valid → below threshold ────────────────────────

describe("AC-005: 1 corrupted signature leaves 2 valid (below threshold 3)", () => {
  it("returns { ok: false } with detail containing '2 valid' and '3 required'", () => {
    const nodes = makeNodes();
    const manifest: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes, signatures: [] };
    manifest.signatures = signManifest(manifest, [0, 1, 2]);

    // Corrupt the first signature
    const sigHex = manifest.signatures[0].signature;
    const firstByte = parseInt(sigHex.slice(0, 2), 16);
    const corruptedByte = ((firstByte + 1) % 256).toString(16).padStart(2, "0");
    manifest.signatures[0] = { officerIndex: 0, signature: corruptedByte + sigHex.slice(2) };

    const result = verifyManifest(manifest, TEST_OFFICER_PUBKEYS, 3);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("manifest_signature_invalid");
      expect(result.detail).toContain("2 valid");
      expect(result.detail).toContain("3 required");
    }
  });
});

// ─── AC-006: Only 2 valid sigs → below threshold ────────────────────────────

describe("AC-006: only 2 valid signatures → below threshold", () => {
  it("2 valid signatures with threshold 3 → { ok: false }", () => {
    const nodes = makeNodes();
    const manifest: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes, signatures: [] };
    manifest.signatures = signManifest(manifest, [0, 1]);

    const result = verifyManifest(manifest, TEST_OFFICER_PUBKEYS, 3);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("manifest_signature_invalid");
      expect(result.detail).toContain("2 valid");
      expect(result.detail).toContain("3 required");
    }
  });
});

// ─── AC-007 / SI-001: Duplicate officer index ────────────────────────────────

describe("AC-007 / SI-001: duplicate officerIndex — only 1 unique counts", () => {
  it("3 entries all officerIndex: 0 → only 1 unique → { ok: false }", () => {
    const nodes = makeNodes();
    const manifest: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes, signatures: [] };
    const body = canonicalManifestBody(manifest);
    const sig = toHex(ed25519.sign(body, TEST_OFFICER_SEEDS[0]));

    manifest.signatures = [
      { officerIndex: 0, signature: sig },
      { officerIndex: 0, signature: sig },
      { officerIndex: 0, signature: sig },
    ];

    const result = verifyManifest(manifest, TEST_OFFICER_PUBKEYS, 3);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.detail).toContain("1 valid");
      expect(result.detail).toContain("3 required");
    }
  });
});

// ─── AC-008: Out-of-bounds officerIndex → silently skipped ───────────────────

describe("AC-008: out-of-bounds officerIndex is silently skipped", () => {
  it("officerIndex: 99 → no RangeError, silently skipped", () => {
    const nodes = makeNodes();
    const manifest: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes, signatures: [] };
    manifest.signatures = signManifest(manifest, [0, 1, 2]);

    // Add an out-of-bounds entry
    manifest.signatures.push({ officerIndex: 99, signature: "f".repeat(128) });

    // Should NOT throw — the out-of-bounds entry is silently skipped
    const result = verifyManifest(manifest, TEST_OFFICER_PUBKEYS, 3);
    expect(result).toEqual({ ok: true, signerCount: 3 });
  });

  it("negative officerIndex → silently skipped", () => {
    const nodes = makeNodes();
    const manifest: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes, signatures: [] };
    manifest.signatures = signManifest(manifest, [0, 1, 2]);
    manifest.signatures.push({ officerIndex: -1, signature: "f".repeat(128) });

    const result = verifyManifest(manifest, TEST_OFFICER_PUBKEYS, 3);
    expect(result).toEqual({ ok: true, signerCount: 3 });
  });
});

// ─── AC-009: Malformed hex → silently handled ────────────────────────────────

describe("AC-009: malformed hex signature is silently handled", () => {
  it("non-hex characters → no throw, signature not counted", () => {
    const nodes = makeNodes();
    const manifest: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes, signatures: [] };
    manifest.signatures = signManifest(manifest, [1, 2]);

    // Add a malformed hex entry for officer 0
    manifest.signatures.unshift({ officerIndex: 0, signature: "zzzz" + "f".repeat(124) });

    const result = verifyManifest(manifest, TEST_OFFICER_PUBKEYS, 3);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.detail).toContain("2 valid");
    }
  });

  it("empty string signature → no throw", () => {
    const nodes = makeNodes();
    const manifest: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes, signatures: [] };
    manifest.signatures = [
      { officerIndex: 0, signature: "" },
      ...signManifest(manifest, [1, 2]),
    ];

    // Should not throw
    const result = verifyManifest(manifest, TEST_OFFICER_PUBKEYS, 3);
    expect(result.ok).toBe(false);
  });

  it("odd-length hex → no throw", () => {
    const nodes = makeNodes();
    const manifest: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes, signatures: [] };
    manifest.signatures = [
      { officerIndex: 0, signature: "abc" }, // odd-length
      ...signManifest(manifest, [1, 2]),
    ];

    const result = verifyManifest(manifest, TEST_OFFICER_PUBKEYS, 3);
    expect(result.ok).toBe(false);
  });
});

// ─── AC-010: CONSORTIUM_ROOT_KEYS ────────────────────────────────────────────

describe("AC-010: CONSORTIUM_ROOT_KEYS constants", () => {
  it("CONSORTIUM_ROOT_KEYS is an array of 5 hex strings, each 64 chars", () => {
    expect(CONSORTIUM_ROOT_KEYS).toHaveLength(5);
    for (const key of CONSORTIUM_ROOT_KEYS) {
      expect(key).toHaveLength(64);
      expect(key).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("CONSORTIUM_THRESHOLD equals 3", () => {
    expect(CONSORTIUM_THRESHOLD).toBe(3);
  });

  it("CONSORTIUM_ROOT_KEYS is readonly (placeholder zeros)", () => {
    // Placeholder keys are all zeros
    for (const key of CONSORTIUM_ROOT_KEYS) {
      expect(key).toBe("0".repeat(64));
    }
  });
});

// ─── AC-011: TEST_CONSORTIUM_ROOT_KEYS ───────────────────────────────────────

describe("AC-011: TEST_CONSORTIUM_ROOT_KEYS separate from production", () => {
  it("TEST_CONSORTIUM_ROOT_KEYS is an array of 5 hex strings, each 64 chars", () => {
    expect(TEST_CONSORTIUM_ROOT_KEYS).toHaveLength(5);
    for (const key of TEST_CONSORTIUM_ROOT_KEYS) {
      expect(key).toHaveLength(64);
      expect(key).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("TEST_CONSORTIUM_THRESHOLD equals 3", () => {
    expect(TEST_CONSORTIUM_THRESHOLD).toBe(3);
  });

  it("test keys are real public keys (not zeros)", () => {
    for (const key of TEST_CONSORTIUM_ROOT_KEYS) {
      expect(key).not.toBe("0".repeat(64));
    }
  });

  it("test keys are all distinct", () => {
    const unique = new Set(TEST_CONSORTIUM_ROOT_KEYS);
    expect(unique.size).toBe(5);
  });
});

// ─── SI-003: Test keys and production keys are disjoint ──────────────────────

describe("SI-003: test keys and production keys are completely disjoint sets", () => {
  it("no overlap between CONSORTIUM_ROOT_KEYS and TEST_CONSORTIUM_ROOT_KEYS", () => {
    const prodSet = new Set(CONSORTIUM_ROOT_KEYS);
    for (const testKey of TEST_CONSORTIUM_ROOT_KEYS) {
      expect(prodSet.has(testKey)).toBe(false);
    }
  });
});

// ─── AC-012: makeTestManifest produces valid manifests ───────────────────────

describe("AC-012: makeTestManifest produces valid manifests", () => {
  it("default manifest passes verifyManifest with TEST_CONSORTIUM_ROOT_KEYS", () => {
    const manifest = makeTestManifest(makeNodes());
    const result = verifyManifest(manifest, TEST_CONSORTIUM_ROOT_KEYS, TEST_CONSORTIUM_THRESHOLD);
    expect(result).toEqual({ ok: true, signerCount: 3 });
  });

  it("accepts optional version override", () => {
    const manifest = makeTestManifest(makeNodes(), { version: 42 });
    expect(manifest.version).toBe(42);
    const result = verifyManifest(manifest, TEST_CONSORTIUM_ROOT_KEYS, TEST_CONSORTIUM_THRESHOLD);
    expect(result.ok).toBe(true);
  });

  it("accepts optional notBefore and expires overrides", () => {
    const manifest = makeTestManifest(makeNodes(), {
      notBefore: "2025-01-01T00:00:00Z",
      expires: "2028-12-31T23:59:59Z",
    });
    expect(manifest.not_before).toBe("2025-01-01T00:00:00Z");
    expect(manifest.expires).toBe("2028-12-31T23:59:59Z");
    const result = verifyManifest(manifest, TEST_CONSORTIUM_ROOT_KEYS, TEST_CONSORTIUM_THRESHOLD);
    expect(result.ok).toBe(true);
  });

  it("manifest contains the provided nodes", () => {
    const nodes = makeNodes();
    const manifest = makeTestManifest(nodes);
    expect(manifest.nodes).toEqual(nodes);
  });

  it("manifest has exactly 3 signatures (threshold)", () => {
    const manifest = makeTestManifest(makeNodes());
    expect(manifest.signatures).toHaveLength(3);
    expect(manifest.signatures[0].officerIndex).toBe(0);
    expect(manifest.signatures[1].officerIndex).toBe(1);
    expect(manifest.signatures[2].officerIndex).toBe(2);
  });
});

// ─── AC-013: Ceremony output verifies; rogue key fails ──────────────────────

describe("AC-013: ceremony verification — rogue key fails", () => {
  it("signature from a key not in the root key set fails verification", () => {
    const nodes = makeNodes();
    const manifest: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes, signatures: [] };
    const body = canonicalManifestBody(manifest);

    // Sign with a rogue key (not in the test root keys)
    const rogueKey = new Uint8Array(32).fill(0xff);
    const rogueSig = toHex(ed25519.sign(body, rogueKey));

    manifest.signatures = [
      { officerIndex: 0, signature: rogueSig }, // Will fail — signed with wrong key
      ...signManifest(manifest, [1, 2]),
    ];

    const result = verifyManifest(manifest, TEST_OFFICER_PUBKEYS, 3);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.detail).toContain("2 valid");
    }
  });
});

// ─── AC-014: Error distinctness ──────────────────────────────────────────────

describe("AC-014: every failure path produces a unique, diagnosable error", () => {
  it("all failure results include reason and detail", () => {
    const nodes = makeNodes();
    const manifest: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes, signatures: [] };
    manifest.signatures = signManifest(manifest, [0]); // only 1 valid

    const result = verifyManifest(manifest, TEST_OFFICER_PUBKEYS, 3);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("manifest_signature_invalid");
      expect(typeof result.detail).toBe("string");
      expect(result.detail.length).toBeGreaterThan(0);
    }
  });

  it("detail differs between 0-valid and 2-valid failures", () => {
    const nodes = makeNodes();

    const manifest0: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes, signatures: [] };
    const manifest2: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes, signatures: [] };
    manifest2.signatures = signManifest(manifest2, [0, 1]);

    const result0 = verifyManifest(manifest0, TEST_OFFICER_PUBKEYS, 3);
    const result2 = verifyManifest(manifest2, TEST_OFFICER_PUBKEYS, 3);

    expect(result0.ok).toBe(false);
    expect(result2.ok).toBe(false);
    if (!result0.ok && !result2.ok) {
      expect(result0.detail).not.toBe(result2.detail);
    }
  });
});

// ─── AC-017: Empty signatures array ─────────────────────────────────────────

describe("AC-017: empty signatures array", () => {
  it("empty signatures → { ok: false, detail: '0 valid of 3 required' }", () => {
    const nodes = makeNodes();
    const manifest: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes, signatures: [] };

    const result = verifyManifest(manifest, TEST_OFFICER_PUBKEYS, 3);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("manifest_signature_invalid");
      expect(result.detail).toContain("0 valid");
      expect(result.detail).toContain("3 required");
    }
  });
});

// ─── AC-018: All malformed entries → processes all, no early exit ─────────────

describe("AC-018: all malformed entries processed — no early exit", () => {
  it("all entries malformed → returns { ok: false }, processes every entry", () => {
    const nodes = makeNodes();
    const manifest: ConsortiumManifestInput = {
      version: 1,
      not_before: "2026-01-01T00:00:00Z",
      expires: "2027-01-01T00:00:00Z",
      nodes,
      signatures: [
        { officerIndex: 0, signature: "zz".repeat(64) },
        { officerIndex: 1, signature: "not-hex-at-all!" },
        { officerIndex: 2, signature: "" },
        { officerIndex: 3, signature: "abc" },
        { officerIndex: 99, signature: "f".repeat(128) },
      ],
    };

    const result = verifyManifest(manifest, TEST_OFFICER_PUBKEYS, 3);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.detail).toContain("0 valid");
    }
  });
});
