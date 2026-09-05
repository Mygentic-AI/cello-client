/**
 * Structure 1 — the sender's signed ordering claim, canonical CBOR.
 *
 * THE ONE BUILDER AND THE ONE READER. The daemon kept a second, positional `encodeStructure1` in
 * `session-relay-client.ts` until 020-ACKHASH; the two were maintained separately and only a
 * convention kept them equal. It had already broken — the copy emitted a timestamp above 2^32-1 as
 * a CBOR float64 where this one promotes to uint64 — so the vector below was pinning bytes
 * production never emitted. Import this; never write a third.
 *
 * Field order is LOAD-BEARING: it is signed over. Reorder a field and signatures produced by any
 * other implementation stop verifying against ours. `structure1-canonical.json` and
 * `structure1-v2-canonical.json` pin the resulting bytes for each version.
 */
import { encodeCbor, decodeCbor } from "./cbor.js";

/** The Structure 1 version tag. Bound as the FIRST field, so a v1 claim can never read as a v2 one. */
export const STRUCTURE1_VERSION = 1;

/**
 * v2 — `last_seen_hash` APPENDED at index 6 (`DOD-M15-WITHHOLD-SEAL-1`).
 *
 * `last_seen_seq` is a NUMBER, so "I saw position 7" attests to a POSITION and never to CONTENT.
 * `last_seen_hash` binds the acknowledgement to what was actually received. It ADDS: `last_seen_seq`
 * stays and keeps doing ordering and dedup work.
 */
export const STRUCTURE1_VERSION_V2 = 2;

/**
 * v3 — `prev_own_hash` APPENDED at index 7 (`DOD-M15-SELFCHAIN-1`).
 *
 * ⚠️ THIS IS THE OTHER HALF OF THE CHAIN, AND WITHOUT IT THERE IS NO CHAIN.
 *
 * `last_seen_hash` links a sender to the counterparty: *"the last thing I got from you."* That
 * chains ACROSS the two parties and it does not chain a sender to themselves — so when one party
 * sends twice in a row, BOTH of their messages carry the same `last_seen_hash`, because nothing
 * arrived in between. Nothing in the signed bytes distinguishes them, and nothing links the second
 * to the first.
 *
 * Position cannot fill that gap: the relay assigns position AFTER the sender has signed, so a
 * sender can never sign their own position. The relay's receipt pins it, but the receipt goes to
 * the SENDER — so whoever hands a conversation to a new relay holds no receipt for the
 * counterparty's messages and can reorder any run of them. Measured in `031-RELAYREPLAY`.
 *
 * `prev_own_hash` is the `content_hash` of this sender's OWN previous message in this session. With
 * both links every position is committed: move a message inside your own run and your self-link
 * breaks; move one across the interleaving and the counterparty link breaks.
 */
export const STRUCTURE1_VERSION_V3 = 3;

/** `last_seen_hash` is a SHA-256 root — always exactly 32 bytes, never a prefix and never empty. */
export const LAST_SEEN_HASH_BYTES = 32;

/** `prev_own_hash` is a content hash — always exactly 32 bytes, same rule, same reason. */
export const PREV_OWN_HASH_BYTES = 32;

/**
 * ⚠️ INDEX 6 IS ALREADY SPOKEN FOR, WHICH IS WHY THE VERSION DECIDES AND NOT THE LENGTH.
 *
 * `DOD-M15-SUBMIT-ID-1` widened the relay to accept a SIX OR SEVEN field Structure 1, reserving
 * index 6 for a sender-minted submission id, and shipped that tolerance ahead of any emitter. So a
 * seven-field array has two possible meanings and `arr.length` cannot tell them apart:
 *
 *   length 7 && version 1  ⇒  the pre-existing submission-id layout (index 6 is NOT an ack hash)
 *   length 7 && version 2  ⇒  the ack-hash layout
 *   length 8 && version 3  ⇒  the ack-hash layout PLUS `prev_own_hash` at index 7
 *   anything else          ⇒  refused BY NAME, never coerced
 *
 * A reader that silently admits an unrecognised length is not tolerant, it is fail-open: it would
 * verify a signature over bytes whose meaning is not agreed.
 */
export const STRUCTURE1_DECODE_REASONS = {
  /** The bytes are not CBOR at all. */
  NOT_CBOR: "structure1_not_cbor",
  /** Valid CBOR, but not the positional array every Structure 1 is. */
  NOT_ARRAY: "structure1_not_array",
  /** A (version, length) pair this build cannot name — including a v2 that omits `last_seen_hash`. */
  UNKNOWN_LAYOUT: "structure1_unknown_layout",
  /** A field at one of the unchanged indices 1–5 is the wrong type or the wrong width. */
  FIELD_MALFORMED: "structure1_field_malformed",
  /** A v2 carried `last_seen_hash`, and it was not 32 bytes. Present-but-wrong, never dropped. */
  LAST_SEEN_HASH_MALFORMED: "structure1_last_seen_hash_malformed",
  /** A v3 carried `prev_own_hash`, and it was not 32 bytes. Present-but-wrong, never dropped. */
  PREV_OWN_HASH_MALFORMED: "structure1_prev_own_hash_malformed",
} as const;

export type Structure1DecodeReason =
  (typeof STRUCTURE1_DECODE_REASONS)[keyof typeof STRUCTURE1_DECODE_REASONS];

export interface Structure1Fields {
  version: number;
  contentHash: Uint8Array;
  senderPubkey: Uint8Array;
  sessionId: Uint8Array;
  lastSeenSeq: number;
  /**
   * `number` for a legacy float64 leaf, `bigint` for the canonical uint64 form. Never re-encoded on
   * a verification path — the signature is over the bytes as received, so both are carried as read.
   */
  timestamp: number | bigint;
  /**
   * The 32 bytes on a v2 claim; `null` on any v1 claim, INCLUDING a v1 seven-array whose index 6 is
   * a submission id. `null` means "this layout carries no ack hash", never "the hash was missing" —
   * a v2 that omits the field is refused as UNKNOWN_LAYOUT and never reaches here.
   */
  lastSeenHash: Uint8Array | null;
  /**
   * The 32 bytes on a v3 claim; `null` on v1 and v2. `null` means "this layout carries no self
   * link", never "the link was missing" — a v3 that omits it is refused as UNKNOWN_LAYOUT and never
   * reaches here.
   */
  prevOwnHash: Uint8Array | null;
}

export type Structure1DecodeResult =
  | { ok: true; fields: Structure1Fields }
  | { ok: false; reason: Structure1DecodeReason };

/**
 * Canonical Structure 1 bytes.
 *
 *   v1: [1, content_hash(32), sender_pubkey(32), session_id(16), last_seen_seq, timestamp]
 *   v2: [2, content_hash(32), sender_pubkey(32), session_id(16), last_seen_seq, timestamp,
 *        last_seen_hash(32)]
 *   v3: [3, …the same six…, last_seen_hash(32), prev_own_hash(32)]
 *
 * `lastSeenHash` ABSENT ⇒ v1, six fields, byte-identical to the pinned v1 vector. PRESENT ⇒ v2.
 * `prevOwnHash` PRESENT as well ⇒ v3. The version tag is what disambiguates, so no two layouts can
 * be confused by a reader, and the v1 and v2 vectors are unchanged by the addition.
 *
 * ⚠️ `prev_own_hash` IS A VALUE, NEVER AN ABSENCE — the same rule as `last_seen_hash` and the same
 * reason. A sender's first message in a session has no predecessor, and that case is
 * `computeGenesisPrevRoot` for the session: not 32 zero bytes, which would be presentable for any
 * session, and not a shorter array, which is refused.
 *
 * ⚠️ `last_seen_hash` IS A VALUE, NEVER AN ABSENCE. The first message of a session has seen nothing,
 * and that case is a defined 32-byte value: `computeGenesisPrevRoot` for the session — the agreed
 * starting point of this two-party chain. Not 32 zero bytes, which would be a constant identical
 * across every session and therefore presentable for any of them; and not a shorter array, which is
 * refused. A caller that has no hash to send sends v1, and a v1 claim makes no content assertion at
 * all — which is honest — rather than an empty one that reads as satisfied.
 *
 * A timestamp above 2^32-1 is encoded as a CBOR bigint — a plain number encodes as a float64, and
 * two implementations that disagree about which one they emit produce different signed bytes for
 * the same value. Same promotion as `buildSessionEstablishmentTbs`.
 */
export function encodeStructure1(fields: {
  contentHash: Uint8Array;
  senderPubkey: Uint8Array;
  sessionId: Uint8Array;
  lastSeenSeq: number;
  timestamp: number;
  lastSeenHash?: Uint8Array;
  /**
   * The sender's OWN previous message in this session — `DOD-M15-SELFCHAIN-1`. Supplying it selects
   * v3 and is what makes the conversation a chain rather than a set of cross-acknowledgements.
   *
   * A sender's FIRST message in a session has no predecessor, and that case is a defined 32 bytes:
   * `computeGenesisPrevRoot` for the session. Never omitted to mean "first" — see the header.
   */
  prevOwnHash?: Uint8Array;
}): Uint8Array {
  const ts = fields.timestamp > 0xffffffff ? BigInt(fields.timestamp) : fields.timestamp;
  const head = [
    fields.contentHash,
    fields.senderPubkey,
    fields.sessionId,
    fields.lastSeenSeq,
    ts,
  ];

  // Branch on the VALUE, not on `"lastSeenHash" in fields`: an explicit `undefined` must encode as
  // v1, not as a seven-field array whose index 6 is CBOR undefined — a v2 claim with no hash in it.
  if (fields.lastSeenHash === undefined) {
    return encodeCbor([STRUCTURE1_VERSION, ...head]);
  }
  if (fields.lastSeenHash.length !== LAST_SEEN_HASH_BYTES) {
    // Thrown, not silently downgraded to v1. A caller that meant to acknowledge content and cannot
    // must find out here, at the last point before these bytes are signed — a signature over a v2
    // nobody accepts is worse than a refusal, and a silent drop to v1 is the downgrade this layout
    // exists to close.
    throw new Error(
      `structure1: last_seen_hash must be ${LAST_SEEN_HASH_BYTES} bytes, got ${fields.lastSeenHash.length}`,
    );
  }
  if (fields.prevOwnHash === undefined) {
    return encodeCbor([STRUCTURE1_VERSION_V2, ...head, fields.lastSeenHash]);
  }
  if (fields.prevOwnHash.length !== PREV_OWN_HASH_BYTES) {
    // Thrown for the same reason the ack hash is: a caller that meant to chain to its own previous
    // message and cannot must find out HERE, at the last point before these bytes are signed.
    // Silently emitting v2 instead would be the downgrade this layout exists to close — and unlike
    // the ack hash, a missing self-link is invisible in a single message and only shows up later,
    // as a conversation whose order cannot be proven.
    throw new Error(
      `structure1: prev_own_hash must be ${PREV_OWN_HASH_BYTES} bytes, got ${fields.prevOwnHash.length}`,
    );
  }
  return encodeCbor([STRUCTURE1_VERSION_V3, ...head, fields.lastSeenHash, fields.prevOwnHash]);
}

/** Bytes at `i` of exactly `len`, tolerating a Buffer from a decoder that produced one. */
function bytesAt(arr: unknown[], i: number, len: number): Uint8Array | null {
  const v = arr[i];
  const b = v instanceof Uint8Array ? v : Buffer.isBuffer(v) ? new Uint8Array(v as Buffer) : null;
  return b !== null && b.length === len ? b : null;
}

/**
 * Read a Structure 1 claim, branching on the VERSION at index 0 — never on the array length (see
 * `STRUCTURE1_DECODE_REASONS` for why the two are not interchangeable).
 *
 * Exported because the readers across both repos each hand-rolled their own positional
 * destructuring, and the next layout change should not have to find them again.
 *
 * Never throws: these bytes arrive off a wire, and a decode failure is a named refusal to report,
 * not an exception escaping into a stream handler.
 */
export function decodeStructure1(cbor: Uint8Array): Structure1DecodeResult {
  let arr: unknown;
  try {
    arr = decodeCbor(cbor);
  } catch {
    return { ok: false, reason: STRUCTURE1_DECODE_REASONS.NOT_CBOR };
  }
  if (!Array.isArray(arr)) return { ok: false, reason: STRUCTURE1_DECODE_REASONS.NOT_ARRAY };

  const version = arr[0];
  const isV1 = version === STRUCTURE1_VERSION && (arr.length === 6 || arr.length === 7);
  const isV2 = version === STRUCTURE1_VERSION_V2 && arr.length === 7;
  const isV3 = version === STRUCTURE1_VERSION_V3 && arr.length === 8;
  if (!isV1 && !isV2 && !isV3) return { ok: false, reason: STRUCTURE1_DECODE_REASONS.UNKNOWN_LAYOUT };

  const contentHash = bytesAt(arr, 1, 32);
  const senderPubkey = bytesAt(arr, 2, 32);
  /**
   * SESSION ID: THE WIDTH IS NOT CHECKED HERE, AND THAT IS DELIBERATE.
   *
   * The wire contract is 16 bytes, and it is enforced where peer-supplied bytes arrive — the relay's
   * and the directory's own decoders each refuse anything else, and both keep doing so. This decoder
   * also reads leaves THIS daemon just produced, and it must not newly refuse a leaf it accepted
   * before: no client-side reader ever checked this width, and requiring it here would turn a
   * layout reader into a second, quieter place that can reject a session.
   *
   * Each consumer is safe for one of two reasons, and it is worth naming both rather than claiming
   * the stronger one for all of them. `seal-frontier-verify` COMPARES the value against an expected
   * session id, so a wrong width fails exactly as a wrong value does. `#captureReceipt`
   * (`session-relay-client.ts`) does NOT compare it — it hexes the value straight into the
   * `relay_ack_receipts` primary key — and is safe instead because those bytes are
   * `#pendingStructure1`, which this daemon produced and signed moments earlier.
   *
   * An earlier version of this comment said every consumer compares it. That was false for
   * `#captureReceipt`, and a comment asserting a safety property the code does not have is how
   * defects survive review in this repo — so it is corrected here rather than deleted.
   */
  const sessionId = arr[3] instanceof Uint8Array
    ? arr[3]
    : Buffer.isBuffer(arr[3]) ? new Uint8Array(arr[3] as Buffer) : null;
  const lastSeenSeq = arr[4];
  const timestamp = arr[5];
  if (contentHash === null || senderPubkey === null || sessionId === null) {
    return { ok: false, reason: STRUCTURE1_DECODE_REASONS.FIELD_MALFORMED };
  }
  if (typeof lastSeenSeq !== "number") {
    return { ok: false, reason: STRUCTURE1_DECODE_REASONS.FIELD_MALFORMED };
  }
  if (typeof timestamp !== "number" && typeof timestamp !== "bigint") {
    return { ok: false, reason: STRUCTURE1_DECODE_REASONS.FIELD_MALFORMED };
  }

  // A v1 seven-array's index 6 is a SUBMISSION ID and is not read here — it is the relay's concern,
  // and reading it as an ack hash is exactly the confusion the version tag prevents.
  let lastSeenHash: Uint8Array | null = null;
  if (isV2 || isV3) {
    lastSeenHash = bytesAt(arr, 6, LAST_SEEN_HASH_BYTES);
    if (lastSeenHash === null) {
      return { ok: false, reason: STRUCTURE1_DECODE_REASONS.LAST_SEEN_HASH_MALFORMED };
    }
  }

  // `DOD-M15-SELFCHAIN-1`. Present-but-wrong is refused, never dropped to null: a v3 whose self link
  // is unreadable is a chain nobody can check, and admitting it without the field would make a
  // corrupt link indistinguishable from an honest v2 that never claimed one.
  let prevOwnHash: Uint8Array | null = null;
  if (isV3) {
    prevOwnHash = bytesAt(arr, 7, PREV_OWN_HASH_BYTES);
    if (prevOwnHash === null) {
      return { ok: false, reason: STRUCTURE1_DECODE_REASONS.PREV_OWN_HASH_MALFORMED };
    }
  }

  return {
    ok: true,
    fields: {
      version, contentHash, senderPubkey, sessionId, lastSeenSeq, timestamp, lastSeenHash, prevOwnHash,
    },
  };
}
