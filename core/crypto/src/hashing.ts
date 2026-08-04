import { createHash } from "node:crypto";
import { sha256 } from "@noble/hashes/sha2.js";

const MSG_LEAF = 0x00;
const INTERNAL_NODE = 0x01;
const CTRL_LEAF = 0x02;
const DOC_LEAF = 0x04;
const REJECT_LEAF = 0x05;

function prefixed(prefix: number, data: Uint8Array): Uint8Array {
  const buf = new Uint8Array(1 + data.length);
  buf[0] = prefix;
  buf.set(data, 1);
  return buf;
}

export function hash(data: Uint8Array): Uint8Array {
  return sha256(data);
}

export function msgLeafHash(data: Uint8Array): Uint8Array {
  return sha256(prefixed(MSG_LEAF, data));
}

export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  if (left.length !== 32 || right.length !== 32) {
    throw new Error(`nodeHash: expected 32-byte inputs, got left=${left.length} right=${right.length}`);
  }
  const buf = new Uint8Array(1 + left.length + right.length);
  buf[0] = INTERNAL_NODE;
  buf.set(left, 1);
  buf.set(right, 1 + left.length);
  return sha256(buf);
}

export function ctrlLeafHash(data: Uint8Array): Uint8Array {
  return sha256(prefixed(CTRL_LEAF, data));
}

/**
 * Document-operation leaf (DOD-DOC-LEAF-1): SHA-256(0x04 || data). RFC 6962 §2.1 domain separation.
 *
 * PREIMAGE CONTRACT: `data` MUST be re-encoded canonical state, NEVER the bytes received from a
 * peer. The Yjs v1 update encoding is malleable — trailing bytes past the decoder's cursor are
 * ignored, so unlimited distinct byte strings decode to identical document state (measured,
 * DOD-DOC-FUZZ-1). Hashing received bytes would let a peer change a leaf hash without changing
 * the document, and two honest peers holding identical state would produce different leaves.
 */
export function docLeafHash(data: Uint8Array): Uint8Array {
  return sha256(prefixed(DOC_LEAF, data));
}

/** Rejection leaf (DOD-DOC-LEAF-1): SHA-256(0x05 || data), referencing a rejected update envelope. */
export function rejectLeafHash(data: Uint8Array): Uint8Array {
  return sha256(prefixed(REJECT_LEAF, data));
}

/**
 * Opaque leaf hash for a kind byte the caller does not recognize (§16.7-10 verifier
 * tolerance): SHA-256(prefix || data). A verifier rebuilding a tree that contains a
 * future leaf kind hashes it with this instead of erroring, so root recomputation
 * survives protocol additions. The prefix must be a single byte — anything else
 * would silently alias a different domain.
 */
export function opaqueLeafHash(prefix: number, data: Uint8Array): Uint8Array {
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 255) {
    throw new RangeError(`opaqueLeafHash: prefix must be an integer 0–255, got ${prefix}`);
  }
  if (prefix === INTERNAL_NODE) {
    throw new RangeError(
      `opaqueLeafHash: prefix 0x01 is the RFC 6962 internal-node domain and can never be a leaf kind — ` +
        `a 64-byte leaf hashed under it is byte-identical to nodeHash(left, right), which forges tree shape (§2.1.3)`,
    );
  }
  return sha256(prefixed(prefix, data));
}

/**
 * Build the to-be-signed bytes for a relay hash-submit ACK.
 *
 * TBS = SHA-256(hash_bytes || seq_BE4 || ts_BE8)
 *   hash_bytes: 32 raw bytes (the Structure 1 content_hash — NOT hex-encoded)
 *   seq_BE4:    sequence_number as 4-byte big-endian uint32
 *   ts_BE8:     timestamp as 8-byte big-endian uint64
 *
 * Both the relay (signer) and the client (verifier) must use this function so
 * they cannot diverge. RFC 8032 (Ed25519), FIPS 180-4 (SHA-256).
 */
export function buildRelayAckTbs(
  hashBytes: Uint8Array,
  sequenceNumber: number,
  timestamp: number,
): Uint8Array {
  const seqBuf = Buffer.allocUnsafe(4);
  seqBuf.writeUInt32BE(sequenceNumber >>> 0, 0);

  const tsBuf = Buffer.allocUnsafe(8);
  tsBuf.writeBigUInt64BE(BigInt(timestamp), 0);

  const preimage = Buffer.concat([Buffer.from(hashBytes), seqBuf, tsBuf]);
  return new Uint8Array(createHash("sha256").update(preimage).digest());
}
