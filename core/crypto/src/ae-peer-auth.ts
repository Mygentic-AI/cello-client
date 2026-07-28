/**
 * M12 DOD-AE-APPEND-1 — directory↔directory anti-entropy peer-auth TBS.
 *
 * The mutual, manifest-pinned handshake for the `/cello/anti-entropy/1.0.0` channel
 * (M12-ANTI-ENTROPY-DESIGN §1c). Each directory proves possession of its manifest-pinned NODE key
 * (the key the officer-signed consortium manifest binds to its nodeId) over a TBS that binds:
 *   - both nodeIds (who is talking to whom),
 *   - both libp2p PeerIds (channel binding — ties the manifest identity to the actual Noise
 *     connection, closing the gap the client step-6 handshake leaves open),
 *   - both nonces (replay defense in EACH direction),
 *   - a timestamp (freshness, defense-in-depth).
 *
 * Roles A/B are fixed by who dialed (A = dialer), so the TBS is asymmetric and a signature from
 * one side cannot be reflected as the other's. A brand-new domain is used — reusing any existing
 * domain string would let a signature minted for another purpose verify here.
 *
 * SHARED builder: signer (each directory) and verifier (its peer) both call this, so neither can
 * diverge. Newline-joined UTF-8 text TBS, matching the directory step-5 challenge style. The
 * builder VALIDATES every field (no embedded newline; nonces are 32-byte hex; A≠B) so the
 * newline-join is injective by construction — two different param sets can never produce the same
 * TBS bytes, closing the cross-context signature-reuse footgun. `verifyAePeerAuth` treats an
 * invalid param set as a failed verification (fail closed), never a throw.
 *
 * Channel obligations this primitive CANNOT enforce (the `/cello/anti-entropy/1.0.0` handler MUST):
 *  - each side mints its own nonce from a CSPRNG;
 *  - a single-use nonce store rejects any replayed nonce;
 *  - a bounded timestamp-window check;
 *  - **peerIdA/peerIdB MUST be taken from the LOCAL Noise-authenticated connection, never from a
 *    wire claim** — this is the load-bearing channel-binding assumption; without it the binding is
 *    forgeable.
 *
 * Reference: RFC 8032 (Ed25519).
 */

import { verify as ed25519Verify } from "./ed25519.js";
import { hexToBytes } from "./hex.js";

/** Dedicated domain — MUST NOT collide with any other TBS domain in the system. */
export const AE_PEER_AUTH_DOMAIN = "cello-ae-peer-auth-v1";

export interface AePeerAuthParams {
  /** Dialer nodeId. */
  nodeIdA: string;
  /** Responder nodeId. */
  nodeIdB: string;
  /** Dialer libp2p PeerId (from the Noise-authenticated connection). */
  peerIdA: string;
  /** Responder libp2p PeerId. */
  peerIdB: string;
  /** Dialer-minted 32-byte nonce, hex. */
  nonceAHex: string;
  /** Responder-minted 32-byte nonce, hex. */
  nonceBHex: string;
  /** ISO-8601 timestamp. */
  timestamp: string;
}

/**
 * Build the canonical TBS bytes for the AE peer-auth handshake. Both sides compute the identical
 * bytes from the same params (roles fixed by who dialed); each signs it with its own node key.
 */
export function buildAePeerAuthTbs(p: AePeerAuthParams): Uint8Array {
  // Injectivity: the fields are newline-joined, so a newline INSIDE a field would let two distinct
  // param sets produce identical TBS bytes (cross-context signature reuse). Reject embedded
  // newlines and pin the nonce format so the encoding is injective by construction. Build-time
  // inputs are this node's own → throwing is correct (verifyAePeerAuth catches it → false).
  const isHex64 = (s: string): boolean => /^[0-9a-fA-F]{64}$/.test(s);
  for (const f of [p.nodeIdA, p.nodeIdB, p.peerIdA, p.peerIdB, p.timestamp]) {
    if (f.includes("\n")) throw new Error("ae-peer-auth: field contains a newline");
  }
  if (!isHex64(p.nonceAHex) || !isHex64(p.nonceBHex)) {
    throw new Error("ae-peer-auth: nonce must be 32-byte hex");
  }
  // A==B collapses the "mutual" handshake — both sides sign identical bytes verified against the
  // same key, so ONE signature satisfies both directions (a single node completes it alone,
  // violating the sovereign invariant). Distinct identities are required.
  if (p.nodeIdA === p.nodeIdB || p.peerIdA === p.peerIdB) {
    throw new Error("ae-peer-auth: A and B must be distinct nodes");
  }
  const tbs = [
    AE_PEER_AUTH_DOMAIN,
    p.nodeIdA,
    p.nodeIdB,
    p.peerIdA,
    p.peerIdB,
    p.nonceAHex,
    p.nonceBHex,
    p.timestamp,
  ].join("\n");
  return new TextEncoder().encode(tbs);
}

/**
 * Verify a peer's AE handshake signature against the pubkey the manifest pins for that peer's
 * nodeId. Never throws — a malformed pubkey or signature returns false.
 *
 * @param peerPubkeyHex 64-char hex Ed25519 public key from the consortium manifest for the peer
 * @param params the handshake params (must be byte-identical on both sides)
 * @param signature the peer's 64-byte Ed25519 signature over buildAePeerAuthTbs(params)
 */
export function verifyAePeerAuth(peerPubkeyHex: string, params: AePeerAuthParams, signature: Uint8Array): boolean {
  const pub = hexToBytes(peerPubkeyHex, 32);
  if (pub === null) return false;
  let tbs: Uint8Array;
  try {
    // Fail closed: a malformed/hostile param set (embedded newline, bad nonce, A==B) makes the
    // builder throw; that is a verification failure, never an exception out of verify.
    tbs = buildAePeerAuthTbs(params);
  } catch {
    return false;
  }
  return ed25519Verify(pub, tbs, signature);
}
