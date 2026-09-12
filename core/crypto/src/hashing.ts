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
 * DOD-M15-ORDERPROOF-1 — the bytes a relay signs when it assigns a leaf a position.
 *
 * This is the relay's ordering ATTESTATION, and both participants end up holding it. The relay is
 * a blind witness: every field below is a hash, an identifier, a counter or a root the relay
 * computed itself, so signing this never requires it to see content (INV-3).
 *
 * TBS = SHA-256( DOMAIN ‖ session_id(16) ‖ content_hash(32) ‖ seq_BE4 ‖ running_root(32) ‖ ts_BE8 )
 *
 * Every field is FIXED WIDTH, which is why this is a plain concatenation and not a CBOR encoding:
 * with no variable-length field there is no way to shift a byte from one field into the next, so
 * the preimage is unambiguous without a length prefix or an encoder both sides must agree on.
 *
 * ⚠️ **WHAT EACH FIELD IS FOR — none of them is decoration.**
 * - `DOMAIN` — CELLO has several relay signatures (`CELLO-RELAY-WITNESS-v1`, the liveness
 *   response). Without a tag, one is replayable as another.
 * - `session_id` — without it an attestation lifts cleanly out of one conversation and into
 *   another: same hash, same position, different session, still verifies.
 * - `running_root` — the root of the tree AFTER this leaf is appended. A position alone says where
 *   a leaf sits in a COUNTER; the root says where it sits in a CHAIN, which is what lets a party
 *   prove a prefix when the relay is gone (`070-CARRIEDSEAL`).
 *
 * Both the relay (signer) and the participants (verifiers) call this, so they cannot diverge.
 * RFC 8032 (Ed25519), FIPS 180-4 (SHA-256).
 *
 * A wrong-length field THROWS rather than being hashed. A 15-byte session id is not a session, and
 * silently hashing it would produce an attestation that verifies and means nothing.
 */
export const RELAY_ORDER_DOMAIN = "CELLO-RELAY-ORDER-v1";

export function buildRelayAckTbs(
  sessionId: Uint8Array,
  hashBytes: Uint8Array,
  sequenceNumber: number,
  runningRoot: Uint8Array,
  timestamp: number,
): Uint8Array {
  if (sessionId.length !== 16) {
    throw new RangeError(`buildRelayAckTbs: session_id must be 16 bytes, got ${sessionId.length}`);
  }
  if (hashBytes.length !== 32) {
    throw new RangeError(`buildRelayAckTbs: content_hash must be 32 bytes, got ${hashBytes.length}`);
  }
  if (runningRoot.length !== 32) {
    throw new RangeError(`buildRelayAckTbs: running_root must be 32 bytes, got ${runningRoot.length}`);
  }

  const seqBuf = Buffer.allocUnsafe(4);
  seqBuf.writeUInt32BE(sequenceNumber >>> 0, 0);

  const tsBuf = Buffer.allocUnsafe(8);
  tsBuf.writeBigUInt64BE(BigInt(timestamp), 0);

  const preimage = Buffer.concat([
    Buffer.from(RELAY_ORDER_DOMAIN, "utf8"),
    Buffer.from(sessionId),
    Buffer.from(hashBytes),
    seqBuf,
    Buffer.from(runningRoot),
    tsBuf,
  ]);
  return new Uint8Array(createHash("sha256").update(preimage).digest());
}
