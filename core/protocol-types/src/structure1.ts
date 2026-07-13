/**
 * Structure 1 — the sender's signed ordering claim, canonical CBOR.
 *
 * The daemon PARSES Structure 1 (it arrives from the relay, the ordering authority) but does not
 * build one, so this encoder has no production caller. It is kept because it is the only written
 * definition of the Structure 1 FIELD ORDER, and `structure1-canonical.json` is the only vector in
 * either repo pinning the resulting bytes. Delete it and the wire format is defined solely by
 * whatever the relay happens to emit, with nothing to catch a drift.
 *
 * Field order is LOAD-BEARING: it is signed over. Reorder a field and signatures produced by any
 * other implementation stop verifying against ours.
 */
import { encodeCbor } from "./cbor.js";

/** The Structure 1 version tag. Bound as the FIRST field, so a v1 claim can never read as a v2 one. */
export const STRUCTURE1_VERSION = 1;

/**
 * Canonical Structure 1 bytes: [version, content_hash, sender_pubkey, session_id, last_seen_seq, timestamp].
 *
 * A timestamp above 2^32-1 is encoded as a CBOR bigint — a plain number would silently lose
 * precision, and the sender's signature is over THESE bytes.
 */
export function encodeStructure1(fields: {
  contentHash: Uint8Array;
  senderPubkey: Uint8Array;
  sessionId: Uint8Array;
  lastSeenSeq: number;
  timestamp: number;
}): Uint8Array {
  const ts = fields.timestamp > 0xffffffff ? BigInt(fields.timestamp) : fields.timestamp;
  return encodeCbor([
    STRUCTURE1_VERSION,
    fields.contentHash,
    fields.senderPubkey,
    fields.sessionId,
    fields.lastSeenSeq,
    ts,
  ]);
}
