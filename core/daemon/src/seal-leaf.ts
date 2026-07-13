/**
 * The SEAL-INTERRUPTED leaf: canonical bytes, K_local signing, and counterparty verification.
 *
 * The canonical encoding is the load-bearing part. Field order is fixed and deterministic, and the
 * initiator, the responder and the verifier MUST all use exactly this encoding — any drift causes a
 * SILENT signature-verification failure, which is the worst kind. That is why these three live
 * together in one file: they are one agreement about bytes, and splitting them is how they drift.
 *
 * The private key never leaves the KeyProvider. Only the Ed25519 signature comes back.
 */
import { Buffer } from "node:buffer";
import type { SealInterruptedLeaf } from "@cello-protocol/protocol-types";
import { verify as ed25519Verify } from "@cello-protocol/crypto";
import type { KeyProvider } from "@cello-protocol/crypto";

export type SealLeafVerifyReason = "nonce_mismatch" | "leaf_count_mismatch" | "leaf_signature_invalid";

/**
 * M7-SESSION-001 (H-1): canonical byte encoding of a SEAL-INTERRUPTED leaf for
 * Ed25519 signing/verification. Field order is fixed and deterministic. Both the
 * initiator and the responder, and the verifier, MUST use exactly this encoding —
 * any drift causes silent signature-verification failure.
 */
export function canonicalSealInterruptedLeafBytes(leaf: {
  type: string;
  sessionId: string;
  leafCount: number;
  merkleRootAtInterruption: string;
  timestamp: number;
  signerPubkey: string;
}): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({
      type: leaf.type,
      sessionId: leaf.sessionId,
      leafCount: leaf.leafCount,
      merkleRootAtInterruption: leaf.merkleRootAtInterruption,
      timestamp: leaf.timestamp,
      signerPubkey: leaf.signerPubkey,
    }),
  );
}

/**
 * M7-SESSION-001 (H-1): construct and K_local-sign a SEAL-INTERRUPTED leaf.
 * The private key never leaves keyProvider — only the Ed25519 signature is returned.
 */
export async function buildSignedSealInterruptedLeaf(
  keyProvider: KeyProvider,
  opts: {
    sessionId: string;
    leafCount: number;
    merkleRootAtInterruption: string;
    signerPubkeyHex: string;
  },
): Promise<SealInterruptedLeaf> {
  const partial = {
    type: "SEAL_INTERRUPTED" as const,
    sessionId: opts.sessionId,
    leafCount: opts.leafCount,
    merkleRootAtInterruption: opts.merkleRootAtInterruption,
    timestamp: Date.now(),
    signerPubkey: opts.signerPubkeyHex,
  };
  const sig = await keyProvider.sign(canonicalSealInterruptedLeafBytes(partial));
  return { ...partial, signature: Buffer.from(sig).toString("hex") };
}

/**
 * M7-SESSION-001 / DAEMON-004: verify a counterparty's SEAL-INTERRUPTED ack leaf.
 *
 * Shared by BOTH the interrupted-seal flow (SESSION-001) and the active-session
 * seal flow (DAEMON-004 finding #1) so the two paths perform an identical
 * bilateral check. Returns a generic reason; each caller maps it to its own
 * reason codes / observability events / guidance.
 *
 * Checks, in order:
 *   1. L-2: the ack echoes the exact nonce we sent (replay / stale-response guard).
 *   2. leafCount agreement: the counterparty's leafCount equals our own — an
 *      independent value, so a genuine divergence in transcript length is caught.
 *   3. SI-002 / SI-003: the leaf carries a valid Ed25519 signature produced by the
 *      counterparty's OWN key (signerPubkey must equal the expected counterparty).
 *
 * Crypto: Ed25519 RFC 8032.
 */
export function verifyCounterpartySealLeaf(opts: {
  leaf: Record<string, unknown>;
  sentNonce: string;
  ackNonce: string | null;
  ownLeafCount: number;
  expectedCounterpartyPubkey: string;
}): { ok: true } | { ok: false; reason: SealLeafVerifyReason; error: string } {
  const { leaf, sentNonce, ackNonce, ownLeafCount, expectedCounterpartyPubkey } = opts;

  // 1. L-2: the counterparty MUST echo the exact nonce we sent.
  if (ackNonce !== sentNonce) {
    return { ok: false, reason: "nonce_mismatch", error: "ack nonce did not match the request nonce" };
  }

  // 2. leafCount agreement against our own independent count.
  const cpLeafCount = typeof leaf["leafCount"] === "number" ? (leaf["leafCount"] as number) : null;
  if (cpLeafCount !== ownLeafCount) {
    return {
      ok: false,
      reason: "leaf_count_mismatch",
      error: `counterparty leafCount ${String(cpLeafCount)} != own leafCount ${ownLeafCount}`,
    };
  }

  // 3. SI-002/SI-003: verify the counterparty's Ed25519 signature on its OWN leaf.
  try {
    const signerPubkeyHex = typeof leaf["signerPubkey"] === "string" ? (leaf["signerPubkey"] as string) : null;
    const signatureHex = typeof leaf["signature"] === "string" ? (leaf["signature"] as string) : null;
    if (!signerPubkeyHex || !signatureHex) {
      throw new Error("leaf missing signerPubkey or signature");
    }
    if (signerPubkeyHex !== expectedCounterpartyPubkey) {
      throw new Error(
        `leaf signerPubkey ${signerPubkeyHex.slice(0, 16)} does not match counterparty ${expectedCounterpartyPubkey.slice(0, 16)}`,
      );
    }
    const canonicalLeaf = {
      type: leaf["type"],
      sessionId: leaf["sessionId"],
      leafCount: leaf["leafCount"],
      merkleRootAtInterruption: leaf["merkleRootAtInterruption"],
      timestamp: leaf["timestamp"],
      signerPubkey: leaf["signerPubkey"],
    };
    const leafBytes = new TextEncoder().encode(JSON.stringify(canonicalLeaf));
    const pubkeyBytes = new Uint8Array(Buffer.from(signerPubkeyHex, "hex"));
    const sigBytes = new Uint8Array(Buffer.from(signatureHex, "hex"));
    if (!ed25519Verify(pubkeyBytes, leafBytes, sigBytes)) {
      return { ok: false, reason: "leaf_signature_invalid", error: "Ed25519 signature verification failed on SEAL-INTERRUPTED leaf" };
    }
    return { ok: true };
  } catch (verifyErr: unknown) {
    return {
      ok: false,
      reason: "leaf_signature_invalid",
      error: verifyErr instanceof Error ? verifyErr.message : String(verifyErr),
    };
  }
}
