/**
 * Structure 1 — the sender's signed ordering claim, canonical CBOR.
 *
 * The daemon does not BUILD Structure 1 today: it arrives from the relay (the ordering authority)
 * inside the content frame and inside a parked envelope, and the daemon parses and carries it. So
 * this encoder has no production caller.
 *
 * It is kept anyway, and it is not dead code. It is the only place the Structure 1 FIELD ORDER is
 * written down, and `structure1-canonical.json` is the only vector in either repo that pins the
 * resulting bytes. A CELLO node must be able to parse what another implementation produced; if the
 * layout drifts, nothing else in the tree notices. Deleting this deletes the wire spec and the test
 * that guards it, and leaves the format defined only by whatever the relay happens to emit.
 *
 * Field order is LOAD-BEARING. It is signed over — reorder a field and every signature made by
 * another implementation fails to verify against ours.
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
