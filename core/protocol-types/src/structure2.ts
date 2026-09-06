/**
 * CELLO-MERKLE-002 — Structure 2 wire type and codec.
 *
 * Structure 2 is the relay-built Merkle leaf:
 *   [sequence_number, sender_pubkey, content_hash, sender_signature, scan_result, prev_root]
 *
 * scan_result in M1 is a sentinel placeholder: {score: null, verdict: "unscanned", model_hash: <32 zero bytes>}.
 * The field is present to keep the wire layout stable for future scanner integration (M4+).
 *
 * Canonical CBOR per RFC 8949 §4.2.1.
 * Ed25519 verification per RFC 8032.
 *
 * Structure 1 TBS (for signature verification):
 *   [1, content_hash, sender_pubkey, session_id, last_seen_seq, timestamp]
 * This is what the sender signs. It is verified over the `structure1_cbor` bytes AS RECEIVED —
 * never rebuilt from Structure 2 fields, which is what the deleted verifier below did wrong
 * plus the session_id, last_seen_seq, and timestamp carried through the relay path.
 */

import { encodeCbor } from "./cbor.js";
import type { EnvelopeError } from "./types.js";


// ─── Types ───────────────────────────────────────────────────────────────────

export interface ScanResultSentinel {
  score: null;
  verdict: "unscanned";
  model_hash: Uint8Array;
}

export interface Structure2 {
  sequence_number: number;
  sender_pubkey: Uint8Array;
  content_hash: Uint8Array;
  sender_signature: Uint8Array;
  scan_result: ScanResultSentinel;
  prev_root: Uint8Array;
}

export type BuildStructure2Result =
  | { ok: true; structure2: Structure2 }
  | { ok: false; error: EnvelopeError };

// ─── Sentinel ─────────────────────────────────────────────────────────────────

/** M1 placeholder scan_result sentinel. The scanner field is stable but unset until M4+. */
export const SCAN_RESULT_SENTINEL: ScanResultSentinel = Object.freeze({
  score: null,
  verdict: "unscanned" as const,
  model_hash: new Uint8Array(32),
});

/**
 * Encodes the scan_result sentinel as canonical CBOR (RFC 8949 §4.2.1).
 *
 * Keys are sorted by byte length per RFC 8949 §4.2.1 core deterministic encoding:
 *   "score" (5) < "verdict" (7) < "model_hash" (10)
 *
 * cbor-x's default POJO encoding uses non-canonical map-size encoding (uint16 length prefix).
 * We construct the canonical bytes manually to guarantee RFC 8949 §4.2.1 compliance.
 */
export function encodeScanResultSentinel(): Uint8Array {
  // a3 = 3-item CBOR map (major type 5, additional info 3)
  // Keys sorted by length: "score"(5) < "verdict"(7) < "model_hash"(10)
  return new Uint8Array(
    Buffer.concat([
      Buffer.from([0xa3]),
      // "score": null
      Buffer.from([0x65]), Buffer.from("score"),
      Buffer.from([0xf6]),
      // "verdict": "unscanned"
      Buffer.from([0x67]), Buffer.from("verdict"),
      Buffer.from([0x69]), Buffer.from("unscanned"),
      // "model_hash": 32-byte zero byte string
      Buffer.from([0x6a]), Buffer.from("model_hash"),
      Buffer.from([0x58, 0x20]), Buffer.alloc(32),
    ])
  );
}

// ─── Build ────────────────────────────────────────────────────────────────────

/**
 * Constructs a Structure 2 object after validating all field lengths.
 * scan_result is always the M1 sentinel — callers do not supply it.
 */
export function buildStructure2(
  sequence_number: number,
  sender_pubkey: Uint8Array,
  content_hash: Uint8Array,
  sender_signature: Uint8Array,
  prev_root: Uint8Array
): BuildStructure2Result {
  if (sender_pubkey.length !== 32) {
    return {
      ok: false,
      error: { reason: "invalid_field", field: "sender_pubkey", message: `sender_pubkey must be 32 bytes, got ${sender_pubkey.length}` },
    };
  }
  if (content_hash.length !== 32) {
    return {
      ok: false,
      error: { reason: "invalid_field", field: "content_hash", message: `content_hash must be 32 bytes, got ${content_hash.length}` },
    };
  }
  if (sender_signature.length !== 64) {
    return {
      ok: false,
      error: { reason: "invalid_field", field: "sender_signature", message: `sender_signature must be 64 bytes, got ${sender_signature.length}` },
    };
  }
  if (prev_root.length !== 32) {
    return {
      ok: false,
      error: { reason: "invalid_field", field: "prev_root", message: `prev_root must be 32 bytes, got ${prev_root.length}` },
    };
  }

  return {
    ok: true,
    structure2: {
      sequence_number,
      sender_pubkey,
      content_hash,
      sender_signature,
      scan_result: SCAN_RESULT_SENTINEL,
      prev_root,
    },
  };
}

// ─── Encode ───────────────────────────────────────────────────────────────────

/**
 * Encodes Structure 2 as canonical CBOR (RFC 8949 §4.2.1).
 * Wire format: [sequence_number, sender_pubkey, content_hash, sender_signature, scan_result, prev_root]
 */
export function encodeStructure2(s2: Structure2): Uint8Array {
  const sentinelBytes = encodeScanResultSentinel();
  // We must embed the pre-encoded sentinel bytes as raw CBOR, not re-encode the object.
  // Construct the 6-element array manually to preserve canonical byte representation.
  const arrayHeader = new Uint8Array([0x86]); // 6-element CBOR array
  const seqBytes = encodeCbor(s2.sequence_number) as Uint8Array;
  const pubBytes = encodeCbor(s2.sender_pubkey) as Uint8Array;
  const hashBytes = encodeCbor(s2.content_hash) as Uint8Array;
  const sigBytes = encodeCbor(s2.sender_signature) as Uint8Array;
  const prevBytes = encodeCbor(s2.prev_root) as Uint8Array;

  return new Uint8Array(
    Buffer.concat([arrayHeader, seqBytes, pubBytes, hashBytes, sigBytes, sentinelBytes, prevBytes])
  );
}

// ─── Verify ───────────────────────────────────────────────────────────────────

/**
 * ⚠️ `verifyStructure2Signature` WAS DELETED HERE — `DOD-M15-SELFCHAIN-1`.
 *
 * It rebuilt Structure 1 inline, as a six-field array, instead of calling `encodeStructure1`. A
 * second builder for a signed structure is the defect this package's own header warns about, and it
 * had already drifted: the one layout carries eight fields, so the function could not verify a real
 * signature any more and its own tests were the only thing that noticed.
 *
 * It had NO production caller in either repo — only the barrel export and its tests. So it went,
 * rather than being taught the new layout: a verifier nothing calls is a claim nobody checks, and
 * keeping it would have left a second definition of the signed bytes for the next reader to trust.
 *
 * Callers verify a Structure 1 signature the way every production path already does: over the
 * `structure1_cbor` bytes AS RECEIVED, never over a re-encoding.
 */
