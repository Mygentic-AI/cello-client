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
 * AC-011: TEST_CONSORTIUM_ROOT_KEYS separate from production, test privkeys not in public exports.
 * AC-012: makeTestManifest produces valid manifests that pass verifyManifest.
 * AC-013: Ceremony output verifies; rogue key signature fails.
 * AC-014: Error distinctness — every failure path is unique and diagnosable.
 * AC-017: Empty signatures array → { ok: false, detail: '0 valid of 3 required' }.
 * AC-018: All malformed entries → processes all (no early exit), returns { ok: false }.
 * Empty nodes guard: manifest.nodes === [] → { ok: false, detail: 'manifest contains no nodes' }.
 *
 * SI-001: Duplicate officer index → only 1 unique counts.
 * SI-002: Canonical serialization is insertion-order independent.
 * M9D 004: every case verifies under BOTH officer sets; tests 1–6 at the end cover the PQ set.
 * (AC-010 and SI-003 tested the all-zero placeholder roots, which 004 deleted.)
 *
 * Crypto reference: RFC 8032 (Ed25519).
 */

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  canonicalManifestBody,
  verifyManifest,
  TEST_CONSORTIUM_ROOT_KEYS,
  TEST_CONSORTIUM_THRESHOLD,
  TEST_CONSORTIUM_PQ_THRESHOLD,
  testConsortiumRootKeysPq,
  makeTestManifest,
} from "../index.js";
import type { ConsortiumManifestInput } from "../manifest.js";
import { mlDsaProviderFromSeed } from "../ml-dsa.js";
import { mlKemKeypairFromSeed } from "../ml-kem.js";
import { signMlDsa } from "../pq-frame.js";
import { TEST_OFFICER_SEEDS } from "../manifest-test-fixture.js";
import type { TestConsortiumNode } from "../manifest-test-fixture.js";

// ─── Test helpers ────────────────────────────────────────────────────────────

const toHex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

const TEST_OFFICER_PUBKEYS = TEST_OFFICER_SEEDS.map((seed) =>
  toHex(ed25519.getPublicKey(seed)),
);

function makeNodes(): TestConsortiumNode[] {
  return [
    { nodeId: "node-us-east-1", pubkey: "a".repeat(64), region: "us-east-1", provider: "aws", endpoint: "https://us.example.com", role: "validator", peerId: "12D3KooWUs" },
    { nodeId: "node-eu-central-1", pubkey: "b".repeat(64), region: "eu-central-1", provider: "gcp", endpoint: "https://eu.example.com", role: "validator", peerId: "12D3KooWEu" },
    { nodeId: "node-ap-northeast-1", pubkey: "c".repeat(64), region: "ap-northeast-1", provider: "azure", endpoint: "https://ap.example.com", role: "validator", peerId: "12D3KooWAp" },
  ];
}

/**
 * M9D 004: a manifest that passes every structural and post-quantum check, with NO Ed25519
 * signatures — so the Ed25519 cases below exercise exactly the Ed25519 path. The PQ set stays valid
 * because both sets sign a body that excludes both signature fields.
 */
async function edUnsigned(nodes: TestConsortiumNode[]): Promise<ConsortiumManifestInput> {
  const m = await makeTestManifest(nodes, { expires: "2027-01-01T00:00:00Z" });
  m.signatures = [];
  return m;
}

/** Verify under the test roots: Ed25519 threshold 3, the test ML-DSA officers at their threshold. */
async function verify(m: ConsortiumManifestInput) {
  return verifyManifest(m, {
    rootKeys: TEST_OFFICER_PUBKEYS,
    threshold: TEST_CONSORTIUM_THRESHOLD,
    rootKeysPq: await testConsortiumRootKeysPq(),
    pqThreshold: TEST_CONSORTIUM_PQ_THRESHOLD,
  });
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
  it("produces identical bytes regardless of object property insertion order", async () => {
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

  it("produces identical bytes regardless of node property insertion order", async () => {
    const nodeForward: TestConsortiumNode = { nodeId: "n1", pubkey: "a".repeat(64), region: "us-east-1", provider: "aws", endpoint: "https://a.com" };
    const nodeReverse = { endpoint: "https://a.com", provider: "aws" as const, region: "us-east-1", pubkey: "a".repeat(64), nodeId: "n1" };

    const m1: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes: [nodeForward], signatures: [] };
    const m2: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes: [nodeReverse], signatures: [] };

    expect(toHex(canonicalManifestBody(m1))).toBe(toHex(canonicalManifestBody(m2)));
  });

  it("signatures field is excluded from canonical body", async () => {
    const nodes = makeNodes();
    const m1: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes, signatures: [] };
    const m2: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes, signatures: [{ officerIndex: 0, signature: "f".repeat(128) }] };

    expect(toHex(canonicalManifestBody(m1))).toBe(toHex(canonicalManifestBody(m2)));
  });

  it("returns a Uint8Array (UTF-8 encoded bytes)", async () => {
    const manifest: ConsortiumManifestInput = { version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes: [], signatures: [] };
    const body = canonicalManifestBody(manifest);
    expect(body).toBeInstanceOf(Uint8Array);
    expect(body.length).toBeGreaterThan(0);
  });

  it("output is valid JSON with sorted keys and exactly the expected fields", async () => {
    const manifest: ConsortiumManifestInput = { version: 2, not_before: "2026-06-01T00:00:00Z", expires: "2027-06-01T00:00:00Z", nodes: makeNodes(), signatures: [] };
    const body = canonicalManifestBody(manifest);
    const json = new TextDecoder().decode(body);
    const parsed = JSON.parse(json);

    // Top-level keys should be sorted and exactly the expected set
    const keys = Object.keys(parsed);
    expect(keys).toEqual(["expires", "nodes", "not_before", "version"]);

    // signatures should NOT be present
    expect(parsed).not.toHaveProperty("signatures");
  });

  it("extra fields on manifest input are included in canonical body", async () => {
    const manifest: ConsortiumManifestInput = {
      version: 1,
      not_before: "2026-01-01T00:00:00Z",
      expires: "2027-01-01T00:00:00Z",
      nodes: [],
      signatures: [],
      _extra_field: "unexpected",
    };

    const body = canonicalManifestBody(manifest);
    const json = new TextDecoder().decode(body);
    const parsed = JSON.parse(json);

    // Extra fields ARE included — the canonical body captures all non-signature fields.
    // This is correct: officers sign what they see. If a field is present, it's signed.
    expect(parsed).toHaveProperty("_extra_field", "unexpected");
    // Keys remain sorted even with the extra field
    const keys = Object.keys(parsed);
    expect(keys).toEqual([...keys].sort());
  });
});

// ─── AC-003 (continued): deeply nested object key sorting ───────────────────

describe("AC-003: deeply nested object key sorting", () => {
  it("sorts object keys at three levels of nesting", async () => {
    const nodeWithMeta = {
      nodeId: "n1",
      pubkey: "a".repeat(64),
      region: "us-east-1",
      provider: "aws" as const,
      endpoint: "https://a.com",
      metadata: { zulu: "last", alpha: "first", bravo: { zebra: 2, apple: 1 } },
    };

    const manifest: ConsortiumManifestInput = {
      version: 1,
      not_before: "2026-01-01T00:00:00Z",
      expires: "2027-01-01T00:00:00Z",
      nodes: [nodeWithMeta],
      signatures: [],
    };

    const json = new TextDecoder().decode(canonicalManifestBody(manifest));
    // All three levels are sorted: top-level, node fields, and nested metadata
    expect(json).toContain('"metadata":{"alpha":"first","bravo":{"apple":1,"zebra":2},"zulu":"last"}');
  });
});

// ─── SI-002: Canonical serialization is insertion-order independent ──────────

describe("SI-002: canonical serialization is insertion-order independent", () => {
  it("deeply nested objects are sorted at every level", async () => {
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
  it("3 valid signatures → { ok: true, signerCount: 3 }", async () => {
    const nodes = makeNodes();
    const manifest = await edUnsigned(nodes);
    manifest.signatures = signManifest(manifest, [0, 1, 2]);

    const result = await verify(manifest);
    expect(result).toEqual({ ok: true, signerCount: 3, pqSignerCount: 3 });
  });

  it("corrupting any single byte in a signature → { ok: false }", async () => {
    const nodes = makeNodes();
    const manifest = await edUnsigned(nodes);
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

    const result = await verify(corrupted);
    expect(result.ok).toBe(false);
  });

  it("4 valid signatures → { ok: true, signerCount: 4 }", async () => {
    const nodes = makeNodes();
    const manifest = await edUnsigned(nodes);
    manifest.signatures = signManifest(manifest, [0, 1, 2, 3]);

    const result = await verify(manifest);
    expect(result).toEqual({ ok: true, signerCount: 4, pqSignerCount: 3 });
  });
});

// ─── AC-005: 1 corrupted → 2 valid → below threshold ────────────────────────

describe("AC-005: 1 corrupted signature leaves 2 valid (below threshold 3)", () => {
  it("returns { ok: false } with detail containing '2 valid' and '3 required'", async () => {
    const nodes = makeNodes();
    const manifest = await edUnsigned(nodes);
    manifest.signatures = signManifest(manifest, [0, 1, 2]);

    // Corrupt the first signature
    const sigHex = manifest.signatures[0].signature;
    const firstByte = parseInt(sigHex.slice(0, 2), 16);
    const corruptedByte = ((firstByte + 1) % 256).toString(16).padStart(2, "0");
    manifest.signatures = [
      { officerIndex: 0, signature: corruptedByte + sigHex.slice(2) },
      ...manifest.signatures.slice(1),
    ];

    const result = await verify(manifest);
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
  it("2 valid signatures with threshold 3 → { ok: false }", async () => {
    const nodes = makeNodes();
    const manifest = await edUnsigned(nodes);
    manifest.signatures = signManifest(manifest, [0, 1]);

    const result = await verify(manifest);
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
  it("3 entries all officerIndex: 0 → only 1 unique → { ok: false }", async () => {
    const nodes = makeNodes();
    const manifest = await edUnsigned(nodes);
    const body = canonicalManifestBody(manifest);
    const sig = toHex(ed25519.sign(body, TEST_OFFICER_SEEDS[0]));

    manifest.signatures = [
      { officerIndex: 0, signature: sig },
      { officerIndex: 0, signature: sig },
      { officerIndex: 0, signature: sig },
    ];

    const result = await verify(manifest);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.detail).toContain("1 valid");
      expect(result.detail).toContain("3 required");
    }
  });
});

// ─── AC-008: Out-of-bounds officerIndex → silently skipped ───────────────────

describe("AC-008: out-of-bounds officerIndex is silently skipped", () => {
  it("officerIndex: 99 → no RangeError, silently skipped", async () => {
    const nodes = makeNodes();
    const manifest = await edUnsigned(nodes);
    manifest.signatures = signManifest(manifest, [0, 1, 2]);

    // Add an out-of-bounds entry
    manifest.signatures = [...manifest.signatures, { officerIndex: 99, signature: "f".repeat(128) }];

    // Should NOT throw — the out-of-bounds entry is silently skipped
    const result = await verify(manifest);
    expect(result).toEqual({ ok: true, signerCount: 3, pqSignerCount: 3 });
  });

  it("negative officerIndex → silently skipped", async () => {
    const nodes = makeNodes();
    const manifest = await edUnsigned(nodes);
    manifest.signatures = signManifest(manifest, [0, 1, 2]);
    manifest.signatures = [...manifest.signatures, { officerIndex: -1, signature: "f".repeat(128) }];

    const result = await verify(manifest);
    expect(result).toEqual({ ok: true, signerCount: 3, pqSignerCount: 3 });
  });
});

// ─── AC-009: Malformed hex → silently handled ────────────────────────────────

describe("AC-009: malformed hex signature is silently handled", () => {
  it("non-hex characters → no throw, signature not counted", async () => {
    const nodes = makeNodes();
    const manifest = await edUnsigned(nodes);
    manifest.signatures = signManifest(manifest, [1, 2]);

    // Add a malformed hex entry for officer 0
    manifest.signatures = [{ officerIndex: 0, signature: "zzzz" + "f".repeat(124) }, ...manifest.signatures];

    const result = await verify(manifest);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.detail).toContain("2 valid");
    }
  });

  it("empty string signature → no throw", async () => {
    const nodes = makeNodes();
    const manifest = await edUnsigned(nodes);
    manifest.signatures = [
      { officerIndex: 0, signature: "" },
      ...signManifest(manifest, [1, 2]),
    ];

    // Should not throw
    const result = await verify(manifest);
    expect(result.ok).toBe(false);
  });

  it("odd-length hex → no throw", async () => {
    const nodes = makeNodes();
    const manifest = await edUnsigned(nodes);
    manifest.signatures = [
      { officerIndex: 0, signature: "abc" }, // odd-length
      ...signManifest(manifest, [1, 2]),
    ];

    const result = await verify(manifest);
    expect(result.ok).toBe(false);
  });

  it("partially-invalid hex ('0g'.repeat) → classified as malformed_signature, not verification_failed", async () => {
    // parseInt("0g", 16) === 0 (not NaN) — naive NaN check would accept this as valid hex.
    // The strict /^[0-9a-fA-F]+$/ regex guard must reject it as malformed_signature.
    const nodes = makeNodes();
    const manifest = await edUnsigned(nodes);
    manifest.signatures = [
      { officerIndex: 0, signature: "0g".repeat(64) }, // 128 chars, correct length, invalid hex
      ...signManifest(manifest, [1, 2]),
    ];

    const result = await verify(manifest);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      const entry = result.diagnostics.skippedEntries.find((e) => e.index === 0);
      expect(entry?.reason).toBe("malformed_signature");
    }
  });
});

// ─── AC-011: TEST_CONSORTIUM_ROOT_KEYS ───────────────────────────────────────

describe("AC-011: TEST_CONSORTIUM_ROOT_KEYS separate from production", () => {
  it("TEST_CONSORTIUM_ROOT_KEYS is an array of 5 hex strings, each 64 chars", async () => {
    expect(TEST_CONSORTIUM_ROOT_KEYS).toHaveLength(5);
    for (const key of TEST_CONSORTIUM_ROOT_KEYS) {
      expect(key).toHaveLength(64);
      expect(key).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("TEST_CONSORTIUM_THRESHOLD equals 3", async () => {
    expect(TEST_CONSORTIUM_THRESHOLD).toBe(3);
  });

  it("test keys are real public keys (not zeros)", async () => {
    for (const key of TEST_CONSORTIUM_ROOT_KEYS) {
      expect(key).not.toBe("0".repeat(64));
    }
  });

  it("test keys are all distinct", async () => {
    const unique = new Set(TEST_CONSORTIUM_ROOT_KEYS);
    expect(unique.size).toBe(5);
  });
});

// ─── AC-012: makeTestManifest produces valid manifests ───────────────────────

describe("AC-012: makeTestManifest produces valid manifests", () => {
  it("default manifest passes verifyManifest with TEST_CONSORTIUM_ROOT_KEYS", async () => {
    const manifest = await makeTestManifest(makeNodes());
    const result = await verify(manifest);
    expect(result).toEqual({ ok: true, signerCount: 3, pqSignerCount: 3 });
  });

  it("accepts optional version override", async () => {
    const manifest = await makeTestManifest(makeNodes(), { version: 42 });
    expect(manifest.version).toBe(42);
    const result = await verify(manifest);
    expect(result.ok).toBe(true);
  });

  it("accepts optional notBefore and expires overrides", async () => {
    const manifest = await makeTestManifest(makeNodes(), {
      notBefore: "2025-01-01T00:00:00Z",
      expires: "2028-12-31T23:59:59Z",
    });
    expect(manifest.not_before).toBe("2025-01-01T00:00:00Z");
    expect(manifest.expires).toBe("2028-12-31T23:59:59Z");
    const result = await verify(manifest);
    expect(result.ok).toBe(true);
  });

  it("manifest contains the provided nodes", async () => {
    const nodes = makeNodes();
    const manifest = await makeTestManifest(nodes);
    // The fixture fills each node's mldsa_pubkey; every field the test supplied is carried as given.
    expect(manifest.nodes).toMatchObject(nodes);
  });

  it("manifest has exactly 3 signatures (threshold)", async () => {
    const manifest = await makeTestManifest(makeNodes());
    expect(manifest.signatures).toHaveLength(3);
    expect(manifest.signatures[0].officerIndex).toBe(0);
    expect(manifest.signatures[1].officerIndex).toBe(1);
    expect(manifest.signatures[2].officerIndex).toBe(2);
  });
});

// ─── M12 ROLE-MANIFEST-1: role-bearing manifests + replica-only rejection ─────

describe("M12 ROLE-MANIFEST-1: verifyManifest and node roles", () => {
  it("rejects a node with NO role — the verifier requires one", async () => {
    const manifest = await makeTestManifest(makeNodes());
    const unsigned = { ...manifest, nodes: manifest.nodes.map((n, i) => {
      if (i !== 1) return n;
      const rest = { ...(n as Record<string, unknown>) };
      delete rest["role"];
      return rest;
    }) };
    const result = await verify(unsigned);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.detail).toContain("unknown role");
  });

  it("rejects a node with NO peerId — the client checks it against the /bootstrap probe", async () => {
    const manifest = await makeTestManifest(makeNodes());
    const stripped = { ...manifest, nodes: manifest.nodes.map((n, i) => {
      if (i !== 0) return n;
      const rest = { ...(n as Record<string, unknown>) };
      delete rest["peerId"];
      return rest;
    }) };
    const result = await verify(stripped);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.detail).toContain("no peerId");
  });

  it("GOLDEN: a node canonicalizes to fixed bytes with role and peerId inside the signed body", async () => {
    // Pins canonicalManifestBody so any change to it — which would silently invalidate every
    // signed manifest — goes red.
    const manifest = {
      version: 1,
      not_before: "2026-01-01T00:00:00Z",
      expires: "2027-01-01T00:00:00Z",
      nodes: [
        { nodeId: "n1", pubkey: "a".repeat(64), region: "us-east-1", provider: "aws", endpoint: "https://a", role: "validator", peerId: "12D3KooWN1" },
      ],
      signatures: [],
    };
    const golden =
      '{"expires":"2027-01-01T00:00:00Z",' +
      '"nodes":[{"endpoint":"https://a","nodeId":"n1","peerId":"12D3KooWN1","provider":"aws","pubkey":"' +
      "a".repeat(64) +
      '","region":"us-east-1","role":"validator"}],' +
      '"not_before":"2026-01-01T00:00:00Z","version":1}';
    expect(new TextDecoder().decode(canonicalManifestBody(manifest))).toBe(golden);
  });

  it("rejects a node with an unknown role string (closes the domain — F1)", async () => {
    const nodes = makeNodes();
    (nodes[1] as { role?: string }).role = "Replica"; // capital R — a tooling typo
    const manifest = await makeTestManifest(nodes);
    const result = await verify(manifest);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.detail).toContain("unknown role");
    }
  });

  it("a mixed validator/replica manifest verifies and the role is inside the signed body", async () => {
    const nodes = makeNodes();
    nodes[2] = { ...nodes[2], role: "replica", peerId: "12D3KooWReplica" };
    const manifest = await makeTestManifest(nodes);
    // Signed successfully over the canonical body that now includes role/peerId:
    const result = await verify(manifest);
    expect(result.ok).toBe(true);
    // Tamper: flipping the replica to a validator must break the signature (role is signed).
    const tampered = {
      ...manifest,
      nodes: manifest.nodes.map((n, i) => (i === 2 ? { ...n, role: "validator" } : n)),
    };
    const t = await verify(tampered);
    expect(t.ok).toBe(false);
  });

  it("a replica-only manifest is rejected loudly even with valid signatures", async () => {
    const nodes = makeNodes().map((n) => ({ ...n, role: "replica" as const }));
    const manifest = await makeTestManifest(nodes);
    const result = await verify(manifest);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("manifest_signature_invalid");
      expect(result.detail).toContain("no validator nodes");
    }
  });

  it("one validator among replicas is enough to pass the validator-count gate", async () => {
    const nodes = makeNodes().map((n, i) => ({ ...n, role: (i === 0 ? "validator" : "replica") as "validator" | "replica" }));
    const manifest = await makeTestManifest(nodes);
    const result = await verify(manifest);
    expect(result.ok).toBe(true);
  });
});

// ─── AC-013: Ceremony output verifies; rogue key fails ──────────────────────

describe("AC-013: ceremony verification — rogue key fails", () => {
  it("signature from a key not in the root key set fails verification", async () => {
    const nodes = makeNodes();
    const manifest = await edUnsigned(nodes);
    const body = canonicalManifestBody(manifest);

    // Sign with a rogue key (not in the test root keys)
    const rogueKey = new Uint8Array(32).fill(0xff);
    const rogueSig = toHex(ed25519.sign(body, rogueKey));

    manifest.signatures = [
      { officerIndex: 0, signature: rogueSig }, // Will fail — signed with wrong key
      ...signManifest(manifest, [1, 2]),
    ];

    const result = await verify(manifest);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.detail).toContain("2 valid");
    }
  });
});

// ─── AC-014: Error distinctness ──────────────────────────────────────────────

describe("AC-014: every failure path produces a unique, diagnosable error", () => {
  it("all failure results include reason and detail", async () => {
    const nodes = makeNodes();
    const manifest = await edUnsigned(nodes);
    manifest.signatures = signManifest(manifest, [0]); // only 1 valid

    const result = await verify(manifest);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("manifest_signature_invalid");
      expect(typeof result.detail).toBe("string");
      expect(result.detail.length).toBeGreaterThan(0);
    }
  });

  it("detail differs between 0-valid and 2-valid failures", async () => {
    const nodes = makeNodes();

    const manifest0 = await edUnsigned(nodes);
    const manifest2 = await edUnsigned(nodes);
    manifest2.signatures = signManifest(manifest2, [0, 1]);

    const result0 = await verify(manifest0);
    const result2 = await verify(manifest2);

    expect(result0.ok).toBe(false);
    expect(result2.ok).toBe(false);
    if (!result0.ok && !result2.ok) {
      expect(result0.detail).not.toBe(result2.detail);
    }
  });
});

// ─── AC-017: Empty signatures array ─────────────────────────────────────────

describe("AC-017: empty signatures array", () => {
  it("empty signatures → { ok: false, detail: '0 valid of 3 required' }", async () => {
    const nodes = makeNodes();
    const manifest = await edUnsigned(nodes);

    const result = await verify(manifest);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("manifest_signature_invalid");
      expect(result.detail).toContain("0 valid");
      expect(result.detail).toContain("3 required");
    }
  });
});

// ─── Empty nodes guard ───────────────────────────────────────────────────────

describe("verifyManifest: empty nodes array", () => {
  it("manifest with nodes: [] → { ok: false, detail: 'manifest contains no nodes' }", async () => {
    const manifest: ConsortiumManifestInput = {
      version: 1,
      not_before: "2026-01-01T00:00:00Z",
      expires: "2027-01-01T00:00:00Z",
      nodes: [],
      signatures: [],
    };

    const result = await verify(manifest);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("manifest_signature_invalid");
      expect(result.detail).toBe("manifest contains no nodes");
    }
  });

  it("empty nodes → { ok: false } even when threshold signatures are present", async () => {
    const manifest: ConsortiumManifestInput = {
      version: 1,
      not_before: "2026-01-01T00:00:00Z",
      expires: "2027-01-01T00:00:00Z",
      nodes: [],
      signatures: signManifest({ version: 1, not_before: "2026-01-01T00:00:00Z", expires: "2027-01-01T00:00:00Z", nodes: [], signatures: [] }, [0, 1, 2]),
    };

    const result = await verify(manifest);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.detail).toBe("manifest contains no nodes");
    }
  });
});

// ─── AC-018: All malformed entries → processes all, no early exit ─────────────

describe("AC-018: all malformed entries processed — no early exit", () => {
  it("all entries malformed → returns { ok: false }, processes every entry", async () => {
    const manifest = await edUnsigned(makeNodes());
    manifest.signatures = [
      { officerIndex: 0, signature: "zz".repeat(64) },
      { officerIndex: 1, signature: "not-hex-at-all!" },
      { officerIndex: 2, signature: "" },
      { officerIndex: 3, signature: "abc" },
      { officerIndex: 99, signature: "f".repeat(128) },
    ];

    const result = await verify(manifest);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.detail).toContain("0 valid");
    }
  });
});

// ─── M9D 004-PQNODEKEYS: the manifest is signed post-quantum too (D21) ───────────────────────────

describe("004 — both signature sets are required", () => {
  const PQ_CONTEXT = "cello-mldsa-consortium-manifest-v1" as const;

  async function pqOfficer(seedByte: number) {
    const provider = await mlDsaProviderFromSeed(new Uint8Array(32).fill(seedByte));
    return { provider, pubHex: toHex(await provider.getPublicKey()) };
  }

  /** A fully valid v4-shape manifest: every node has an ML-DSA key, plus the ML-KEM intake key. */
  async function pqManifest(): Promise<ConsortiumManifestInput> {
    const nodes = await Promise.all(makeNodes().map(async (n, i) => ({
      ...n,
      mldsa_pubkey: (await pqOfficer(0x60 + i)).pubHex,
    })));
    const kem = await mlKemKeypairFromSeed(new Uint8Array(64).fill(0x77));
    return {
      version: 4,
      not_before: "2026-01-01T00:00:00Z",
      expires: "2099-01-01T00:00:00Z",
      nodes,
      intake_key: { key_id: "intake-0", pubkey: "d".repeat(64) },
      mlkem_intake_key: toHex(kem.publicKey),
      signatures: [],
      pq_signatures: [],
    };
  }

  async function signBoth(m: ConsortiumManifestInput, edIdx: number[], pqSigners: Array<{ idx: number; seedByte: number }>) {
    m.signatures = signManifest(m, edIdx);
    const body = canonicalManifestBody(m);
    m["pq_signatures"] = await Promise.all(pqSigners.map(async ({ idx, seedByte }) => ({
      officerIndex: idx,
      signature: toHex(await signMlDsa((await pqOfficer(seedByte)).provider, PQ_CONTEXT, body)),
    })));
    return m;
  }

  const ROOT_PQ_SEED = 0x51;
  async function opts(threshold = 3) {
    return { rootKeys: TEST_OFFICER_PUBKEYS, threshold, rootKeysPq: [(await pqOfficer(ROOT_PQ_SEED)).pubHex], pqThreshold: 1 };
  }

  it("control: both sets valid → accepted", async () => {
    const m = await signBoth(await pqManifest(), [0, 1, 2], [{ idx: 0, seedByte: ROOT_PQ_SEED }]);
    expect(await verifyManifest(m, await opts())).toMatchObject({ ok: true });
  });

  it("★ test 1 (exemplar): valid Ed25519 + a genuine ML-DSA signature by a NON-root key → manifest_pq_signatures_below_threshold", async () => {
    const m = await signBoth(await pqManifest(), [0, 1, 2], [{ idx: 0, seedByte: 0x52 }]);
    const r = await verifyManifest(m, await opts());
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("manifest_pq_signatures_below_threshold");
  });

  it("test 2: valid PQ, Ed25519 below threshold → the existing Ed25519 reason", async () => {
    const m = await signBoth(await pqManifest(), [0, 1], [{ idx: 0, seedByte: ROOT_PQ_SEED }]);
    const r = await verifyManifest(m, await opts(3));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("manifest_signature_invalid");
  });

  it("test 3: pq_signatures absent → manifest_pq_signatures_missing", async () => {
    const m = await signBoth(await pqManifest(), [0, 1, 2], []);
    delete (m as Record<string, unknown>)["pq_signatures"];
    const r = await verifyManifest(m, await opts());
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("manifest_pq_signatures_missing");
  });

  it("test 4: the same PQ officer index twice counts once", async () => {
    const m = await signBoth(await pqManifest(), [0, 1, 2], [{ idx: 0, seedByte: ROOT_PQ_SEED }, { idx: 0, seedByte: ROOT_PQ_SEED }]);
    const two = { ...(await opts()), pqThreshold: 2, rootKeysPq: [(await pqOfficer(ROOT_PQ_SEED)).pubHex, (await pqOfficer(0x53)).pubHex] };
    const r = await verifyManifest(m, two);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("manifest_pq_signatures_below_threshold");
  });

  it("test 5: the body covers every node's mldsa_pubkey, and excludes BOTH signature fields", async () => {
    const m = await signBoth(await pqManifest(), [0, 1, 2], [{ idx: 0, seedByte: ROOT_PQ_SEED }]);
    const withoutPq = { ...m } as Record<string, unknown>;
    delete withoutPq["pq_signatures"];
    expect(toHex(canonicalManifestBody(withoutPq as ConsortiumManifestInput))).toBe(toHex(canonicalManifestBody(m)));

    const tampered = JSON.parse(JSON.stringify(m)) as ConsortiumManifestInput;
    (tampered.nodes[0] as Record<string, unknown>)["mldsa_pubkey"] = (await pqOfficer(0x70)).pubHex;
    const r = await verifyManifest(tampered, await opts());
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("manifest_signature_invalid"); // Ed25519 is checked first, and it fails
    const edOnly = await verifyManifest(tampered, { ...(await opts()), threshold: 0 });
    expect(edOnly.ok).toBe(false);
    if (!edOnly.ok) expect(edOnly.reason).toBe("manifest_pq_signatures_below_threshold"); // and so does the PQ set
  });

  it("test 6: malformed or duplicate node keys and a short intake key are refused by name", async () => {
    const short = await pqManifest();
    (short.nodes[0] as Record<string, unknown>)["mldsa_pubkey"] = "a".repeat(2622);
    await signBoth(short, [0, 1, 2], [{ idx: 0, seedByte: ROOT_PQ_SEED }]);
    const r1 = await verifyManifest(short, await opts());
    expect(r1.ok === false && r1.reason).toBe("manifest_node_mldsa_pubkey_invalid");

    const dup = await pqManifest();
    (dup.nodes[1] as Record<string, unknown>)["mldsa_pubkey"] = (dup.nodes[0] as Record<string, unknown>)["mldsa_pubkey"];
    await signBoth(dup, [0, 1, 2], [{ idx: 0, seedByte: ROOT_PQ_SEED }]);
    const r2 = await verifyManifest(dup, await opts());
    expect(r2.ok === false && r2.reason).toBe("manifest_node_mldsa_pubkey_invalid");

    const kem = await pqManifest();
    kem["mlkem_intake_key"] = "e".repeat(2366);
    await signBoth(kem, [0, 1, 2], [{ idx: 0, seedByte: ROOT_PQ_SEED }]);
    const r3 = await verifyManifest(kem, await opts());
    expect(r3.ok === false && r3.reason).toBe("manifest_mlkem_intake_key_invalid");
  });

  it("intake_key is required: absent, or with a malformed pubkey → manifest_intake_key_invalid", async () => {
    const absent = await pqManifest();
    delete (absent as Record<string, unknown>)["intake_key"];
    await signBoth(absent, [0, 1, 2], [{ idx: 0, seedByte: ROOT_PQ_SEED }]);
    const r1 = await verifyManifest(absent, await opts());
    expect(r1.ok === false && r1.reason).toBe("manifest_intake_key_invalid");

    // Moved here from the daemon's submission test: sealing to a non-key produces a blob nobody can
    // open, which reaches the portal as unattributable poison. Uppercase is refused rather than
    // lowercased — repairing a signed value hides a manifest-generation bug. An empty key_id breaks
    // the portal's rotation bookkeeping.
    const good = "d".repeat(64);
    for (const intake of [
      { key_id: "intake-0", pubkey: "" }, { key_id: "intake-0", pubkey: "not-hex" },
      { key_id: "intake-0", pubkey: "aabb" }, { key_id: "intake-0", pubkey: "D".repeat(64) },
      { key_id: "intake-0", pubkey: good + "00" }, { key_id: "", pubkey: good },
    ]) {
      const bad = await pqManifest();
      bad["intake_key"] = intake;
      await signBoth(bad, [0, 1, 2], [{ idx: 0, seedByte: ROOT_PQ_SEED }]);
      const r2 = await verifyManifest(bad, await opts());
      expect(r2.ok === false && r2.reason, JSON.stringify(intake)).toBe("manifest_intake_key_invalid");
    }
  });
});
