/**
 * MERKLE-001 / AC-006 — RFC 6962 cross-implementation conformance.
 *
 * This is CELLO's only check that its Merkle inclusion proofs agree with an EXTERNAL, pre-committed
 * vector rather than only with themselves. `test/vectors/rfc6962-external-verify.json` is checked in;
 * this test verifies (a) `verifyInclusion` accepts the fixture's proof against the fixture's root,
 * and (b) the tree CELLO builds from the same leaves produces byte-identical leaf hashes and root.
 * If our hashing ever drifts from RFC 6962, self-consistent tests would all still pass — this is the
 * one that would fail.
 *
 * DOD-LEGACY-MCP-1 (2026-07-12): extracted verbatim from `mcp002.test.ts`, which was deleted. That
 * file's other 19 cases drove the legacy in-process MCP server (`createMcpSessionServer`) against a
 * fully stubbed CelloClient, asserting the dead server's tool registry and response shapes. This case
 * never touched it — and it is the SOLE consumer of the fixture, so a file-level deletion would have
 * orphaned the vector and silently dropped CELLO's only external Merkle conformance check.
 */

import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildMerkleTree, merkleRoot, verifyInclusion } from "@cello-protocol/crypto";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function fromHex(s: string): Uint8Array {
  return Buffer.from(s, "hex");
}

// A deterministic 7-leaf tree (5 msg + 2 ctrl). Matches rfc6962-external-verify.json.
function buildFixtureLeaves(): Array<{ kind: "msg" | "ctrl"; s2_cbor: Uint8Array }> {
  return [
    { kind: "msg",  s2_cbor: new Uint8Array(32).fill(0x01) },
    { kind: "msg",  s2_cbor: new Uint8Array(32).fill(0x02) },
    { kind: "msg",  s2_cbor: new Uint8Array(32).fill(0x03) },
    { kind: "msg",  s2_cbor: new Uint8Array(32).fill(0x04) },
    { kind: "msg",  s2_cbor: new Uint8Array(32).fill(0x05) },
    { kind: "ctrl", s2_cbor: new Uint8Array(32).fill(0x10) },
    { kind: "ctrl", s2_cbor: new Uint8Array(32).fill(0x11) },
  ];
}

describe("AC-006: RFC 6962 cross-implementation fixture", () => {
  it("AC-006: MERKLE-001 verifyInclusion agrees with the pre-committed rfc6962-external-verify.json fixture", async () => {
    // Load the committed fixture from disk — cross-validates the computation below against the JSON
    // file so the two cannot drift independently.
    const fixturePath = join(__dirname, "../../test/vectors/rfc6962-external-verify.json");
    const fixtureJson = JSON.parse(await readFile(fixturePath, "utf-8")) as {
      sealed_root: string;
      leaf_hash: string;
      leaf_index: number;
      tree_size: number;
      proof: string[];
      expected: boolean;
    };

    const leafHashBytes = fromHex(fixtureJson.leaf_hash);
    const sealedRootBytes = fromHex(fixtureJson.sealed_root);
    const proofBytes = fixtureJson.proof.map(fromHex);

    const result = verifyInclusion(
      leafHashBytes,
      fixtureJson.leaf_index,
      fixtureJson.tree_size,
      proofBytes,
      sealedRootBytes,
    );

    expect(result).toBe(fixtureJson.expected);

    // The fixture's leaf_hash and sealed_root must equal what MERKLE-001 computes from the same
    // leaves (msg leaf at index 3, data 0x04 × 32). This is what makes the check cross-implementation
    // rather than a tautology.
    const leaves = buildFixtureLeaves();
    const inputs = leaves.map((l) => ({ kind: l.kind, data: l.s2_cbor }));
    const tree = buildMerkleTree(inputs);
    const expectedLeafHash = tree.levelHashes[0][fixtureJson.leaf_index];
    expect(toHex(expectedLeafHash)).toBe(fixtureJson.leaf_hash);

    const expectedRoot = merkleRoot(tree);
    expect(toHex(expectedRoot)).toBe(fixtureJson.sealed_root);
  });
});
