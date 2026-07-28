/**
 * M12 DOD-AE-APPEND-1 — directory<->directory anti-entropy peer-auth TBS.
 *
 * The mutual, manifest-pinned handshake (M12-ANTI-ENTROPY-DESIGN §1c): each side proves
 * possession of its manifest-pinned NODE key over a TBS that binds both nodeIds, both libp2p
 * PeerIds (channel binding), both nonces (replay defense in each direction), and a timestamp.
 * New domain — reuses none of the existing ones. Shared builder in @cello-protocol/crypto so
 * signer and verifier cannot diverge.
 */

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { buildAePeerAuthTbs, verifyAePeerAuth, AE_PEER_AUTH_DOMAIN, type AePeerAuthParams } from "../ae-peer-auth.js";

const seed = new Uint8Array(32).fill(7);
const pub = Buffer.from(ed25519.getPublicKey(seed)).toString("hex");

const params: AePeerAuthParams = {
  nodeIdA: "gcp-usc1",
  nodeIdB: "aws-use1",
  peerIdA: "12D3KooWA",
  peerIdB: "12D3KooWB",
  nonceAHex: "aa".repeat(32),
  nonceBHex: "bb".repeat(32),
  timestamp: "2026-07-28T10:00:00Z",
};

describe("M12 AE peer-auth TBS", () => {
  it("domain is the new dedicated string, not a reused one", () => {
    expect(AE_PEER_AUTH_DOMAIN).toBe("cello-ae-peer-auth-v1");
  });

  it("is deterministic and includes the domain", () => {
    const t1 = buildAePeerAuthTbs(params);
    const t2 = buildAePeerAuthTbs({ ...params });
    expect(t1).toEqual(t2);
    expect(new TextDecoder().decode(t1)).toContain(AE_PEER_AUTH_DOMAIN);
  });

  it("a signature by the node key verifies against that node's manifest pubkey", () => {
    const sig = ed25519.sign(buildAePeerAuthTbs(params), seed);
    expect(verifyAePeerAuth(pub, params, sig)).toBe(true);
  });

  it("verification fails against a DIFFERENT pubkey (proves manifest pinning)", () => {
    const other = Buffer.from(ed25519.getPublicKey(new Uint8Array(32).fill(9))).toString("hex");
    const sig = ed25519.sign(buildAePeerAuthTbs(params), seed);
    expect(verifyAePeerAuth(other, params, sig)).toBe(false);
  });

  it("tampering ANY bound field breaks verification (nodeIds, peerIds, nonces, timestamp)", () => {
    const sig = ed25519.sign(buildAePeerAuthTbs(params), seed);
    const tampered: Partial<AePeerAuthParams>[] = [
      { nodeIdA: "evil" }, { nodeIdB: "evil" },
      { peerIdA: "12D3KooWX" }, { peerIdB: "12D3KooWX" }, // channel binding
      { nonceAHex: "cc".repeat(32) }, { nonceBHex: "cc".repeat(32) }, // replay defense
      { timestamp: "2026-07-28T10:00:01Z" },
    ];
    for (const t of tampered) {
      expect(verifyAePeerAuth(pub, { ...params, ...t }, sig), `tampering ${Object.keys(t)[0]} must fail`).toBe(false);
    }
  });

  it("role order matters — swapping A/B is a different TBS (dialer role is bound)", () => {
    const swapped: AePeerAuthParams = {
      ...params,
      nodeIdA: params.nodeIdB, nodeIdB: params.nodeIdA,
      peerIdA: params.peerIdB, peerIdB: params.peerIdA,
      nonceAHex: params.nonceBHex, nonceBHex: params.nonceAHex,
    };
    expect(buildAePeerAuthTbs(params)).not.toEqual(buildAePeerAuthTbs(swapped));
  });

  it("verifyAePeerAuth never throws on a malformed pubkey or signature (returns false)", () => {
    expect(verifyAePeerAuth("not-hex", params, new Uint8Array(64))).toBe(false);
    expect(verifyAePeerAuth(pub, params, new Uint8Array(3))).toBe(false);
  });

  it("INJECTIVITY: a newline inside any field is rejected (build throws) — no cross-context reuse", () => {
    // Without validation, {nodeIdA:'x\ny', nodeIdB:'z'} and {nodeIdA:'x', nodeIdB:'y\nz'} would
    // produce identical TBS bytes. Rejecting embedded newlines makes the join injective.
    for (const field of ["nodeIdA", "nodeIdB", "peerIdA", "peerIdB", "timestamp"] as const) {
      expect(() => buildAePeerAuthTbs({ ...params, [field]: "x\ny" }), field).toThrow(/newline/);
    }
  });

  it("A==B is rejected (a single node cannot complete a 'mutual' handshake alone)", () => {
    expect(() => buildAePeerAuthTbs({ ...params, nodeIdB: params.nodeIdA })).toThrow(/distinct/);
    expect(() => buildAePeerAuthTbs({ ...params, peerIdB: params.peerIdA })).toThrow(/distinct/);
  });

  it("a non-hex or wrong-length nonce is rejected", () => {
    expect(() => buildAePeerAuthTbs({ ...params, nonceAHex: "zz".repeat(32) })).toThrow(/nonce/);
    expect(() => buildAePeerAuthTbs({ ...params, nonceBHex: "aa" })).toThrow(/nonce/);
  });

  it("verifyAePeerAuth fails CLOSED on an invalid param set (build would throw) — returns false, no throw", () => {
    const sig = ed25519.sign(buildAePeerAuthTbs(params), seed);
    expect(verifyAePeerAuth(pub, { ...params, nodeIdA: "x\ny" }, sig)).toBe(false);
    expect(verifyAePeerAuth(pub, { ...params, nodeIdB: params.nodeIdA }, sig)).toBe(false);
  });
});
