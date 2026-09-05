/**
 * Structure 1 — the sender's signed claim, canonical CBOR. **ONE LAYOUT. EVERY FIELD REQUIRED.**
 *
 * ```
 * [3, content_hash(32), sender_pubkey(32), session_id(16), last_seen_seq, timestamp,
 *     last_seen_hash(32), prev_own_hash(32)]
 * ```
 *
 * Field order is LOAD-BEARING: it is signed over. Reorder a field and signatures produced by any
 * other implementation stop verifying against ours. `structure1-canonical.json` pins the bytes.
 *
 * ─── THE TWO HASHES ARE THE WHOLE POINT ────────────────────────────────────────────────────────
 *
 * A conversation is a cryptographic chain, and moving any message in it breaks a signature. Two
 * links do that, and both are known to the sender at signing time:
 *
 *   - `last_seen_hash` — the last message I received from YOU. Chains me to you.
 *   - `prev_own_hash`  — MY own previous message. Chains me to myself.
 *
 * Neither alone is enough, and `DOD-M15-SELFCHAIN-1` exists because only the first one existed.
 * When one party sends twice in a row, both of their messages acknowledge the SAME message from the
 * other side — nothing arrived in between — so their acknowledgements are identical and nothing in
 * the signed bytes says which came first. Whoever later hands the conversation to a new relay could
 * swap them.
 *
 * The relay-assigned position cannot fill that gap, and this is the fact everything here follows
 * from: **the relay assigns position AFTER the sender has signed, so a sender can never sign their
 * own position.** The relay's receipt does pin it — but the receipt goes to the SENDER, so the party
 * handing over a conversation holds no receipt for the counterparty's messages.
 *
 * ─── WHAT IS STILL DISPUTABLE, AND WHY IT IS NOT A GAP ─────────────────────────────────────────
 *
 * The chain works because the act of sending proves what you received. It follows that **the last
 * message each side sent has been ratified by nobody** — there is no reply to chain it to yet, and
 * there is nothing that could be. Every message with a reply after it is immutable; the
 * unacknowledged tail is covered by the relay's ACK receipt and by `DOD-M15-WITHHOLD-SEAL-1`, not
 * by this. Do not try to "fix" the tail by chaining it to something: the ratification IS the reply.
 *
 * ─── ONE LAYOUT, AND WHAT WAS DELETED TO GET THERE ─────────────────────────────────────────────
 *
 * CELLO is alpha with no users, so **backward compatibility is an anti-requirement** (Andre,
 * 2026-09-05). Three tolerances are gone rather than carried:
 *
 *   - the six-field layout with no acknowledgement at all;
 *   - the seven-field layout carrying `last_seen_hash`;
 *   - the seven-field layout whose index 6 was a sender-minted SUBMISSION ID
 *     (`DOD-M15-SUBMIT-ID-1`). That shipped as relay tolerance and no client ever emitted one —
 *     measured, not assumed: nothing in `core/*` builds it. It was dead code waiting for a caller.
 *
 * With one layout, the ambiguity those versions existed to resolve is gone too: index 6 had two
 * possible meanings and only the version tag could separate them. Now it has one.
 *
 * The version tag STAYS at index 0. It is domain separation, not compatibility — every to-be-signed
 * structure in this protocol carries one, and dropping it would let these bytes be confused with
 * another structure of the same shape.
 *
 * A timestamp above 2^32-1 is encoded as a CBOR bigint — a plain number encodes as a float64, and
 * two implementations that disagree about which they emit produce different signed bytes for the
 * same value. Same promotion as `buildSessionEstablishmentTbs`.
 */
import { encodeCbor, decodeCbor } from "./cbor.js";

/** The Structure 1 domain tag, bound as the FIRST signed field. One layout; nothing else is read. */
export const STRUCTURE1_VERSION = 3;

/** The number of fields in the one layout. A different arity is a different structure. */
export const STRUCTURE1_FIELD_COUNT = 8;

/** Both chain links are SHA-256 outputs — always exactly 32 bytes, never a prefix and never empty. */
export const LAST_SEEN_HASH_BYTES = 32;
export const PREV_OWN_HASH_BYTES = 32;

export const STRUCTURE1_DECODE_REASONS = {
  /** The bytes are not CBOR at all. */
  NOT_CBOR: "structure1_not_cbor",
  /** Valid CBOR, but not the positional array every Structure 1 is. */
  NOT_ARRAY: "structure1_not_array",
  /** Not the one layout — wrong domain tag, wrong arity, or both. Refused, never coerced. */
  UNKNOWN_LAYOUT: "structure1_unknown_layout",
  /** A field at indices 1–5 is the wrong type or the wrong width. */
  FIELD_MALFORMED: "structure1_field_malformed",
  /** `last_seen_hash` was not 32 bytes. Present-but-wrong, never dropped. */
  LAST_SEEN_HASH_MALFORMED: "structure1_last_seen_hash_malformed",
  /** `prev_own_hash` was not 32 bytes. Present-but-wrong, never dropped. */
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
   * The last message this sender RECEIVED. Never null: a claim that carries no acknowledgement is
   * not a layout this build accepts.
   *
   * The first message of a session has received nothing, and that case is a defined 32-byte value —
   * `computeGenesisPrevRoot` for the session, the agreed starting point of this two-party chain.
   * Not 32 zero bytes, which would be a constant identical across every session and therefore
   * presentable for any of them.
   */
  lastSeenHash: Uint8Array;
  /**
   * This sender's OWN previous message. Never null, same rule, same genesis for a sender who has
   * not spoken in this session yet.
   */
  prevOwnHash: Uint8Array;
}

export type Structure1DecodeResult =
  | { ok: true; fields: Structure1Fields }
  | { ok: false; reason: Structure1DecodeReason };

/**
 * Canonical Structure 1 bytes. Both chain links are REQUIRED — there is no shape that omits one.
 *
 * Throws on a wrong-width hash rather than emitting something shorter, at the last point before
 * these bytes are signed. A caller that meant to chain and cannot must find out here: a signature
 * over a claim nobody accepts is worse than a refusal, and a silently unlinked message is invisible
 * until the conversation's order is disputed, long after anyone could act on it.
 */
export function encodeStructure1(fields: {
  contentHash: Uint8Array;
  senderPubkey: Uint8Array;
  sessionId: Uint8Array;
  lastSeenSeq: number;
  timestamp: number;
  lastSeenHash: Uint8Array;
  prevOwnHash: Uint8Array;
}): Uint8Array {
  if (fields.lastSeenHash.length !== LAST_SEEN_HASH_BYTES) {
    throw new Error(
      `structure1: last_seen_hash must be ${LAST_SEEN_HASH_BYTES} bytes, got ${fields.lastSeenHash.length}`,
    );
  }
  if (fields.prevOwnHash.length !== PREV_OWN_HASH_BYTES) {
    throw new Error(
      `structure1: prev_own_hash must be ${PREV_OWN_HASH_BYTES} bytes, got ${fields.prevOwnHash.length}`,
    );
  }
  const ts = fields.timestamp > 0xffffffff ? BigInt(fields.timestamp) : fields.timestamp;
  return encodeCbor([
    STRUCTURE1_VERSION,
    fields.contentHash,
    fields.senderPubkey,
    fields.sessionId,
    fields.lastSeenSeq,
    ts,
    fields.lastSeenHash,
    fields.prevOwnHash,
  ]);
}

/** Bytes at `i` of exactly `len`, tolerating a Buffer from a decoder that produced one. */
function bytesAt(arr: unknown[], i: number, len: number): Uint8Array | null {
  const v = arr[i];
  const b = v instanceof Uint8Array ? v : Buffer.isBuffer(v) ? new Uint8Array(v as Buffer) : null;
  return b !== null && b.length === len ? b : null;
}

/**
 * Read a Structure 1 claim. One layout: the domain tag AND the arity must both match, and every
 * field must be present and the right width.
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
  if (version !== STRUCTURE1_VERSION || arr.length !== STRUCTURE1_FIELD_COUNT) {
    return { ok: false, reason: STRUCTURE1_DECODE_REASONS.UNKNOWN_LAYOUT };
  }

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
   * Each consumer is safe for one of two reasons. `seal-frontier-verify` COMPARES the value against
   * an expected session id, so a wrong width fails exactly as a wrong value does. `#captureReceipt`
   * (`session-relay-client.ts`) does NOT compare it — it hexes the value straight into the
   * `relay_ack_receipts` primary key — and is safe instead because those bytes are
   * `#pendingStructure1`, which this daemon produced and signed moments earlier.
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

  // Each link names ITSELF when it is wrong. Two 32-byte fields sit side by side, and a reader that
  // checked them in one place would send an investigation to the wrong one.
  const lastSeenHash = bytesAt(arr, 6, LAST_SEEN_HASH_BYTES);
  if (lastSeenHash === null) {
    return { ok: false, reason: STRUCTURE1_DECODE_REASONS.LAST_SEEN_HASH_MALFORMED };
  }
  const prevOwnHash = bytesAt(arr, 7, PREV_OWN_HASH_BYTES);
  if (prevOwnHash === null) {
    return { ok: false, reason: STRUCTURE1_DECODE_REASONS.PREV_OWN_HASH_MALFORMED };
  }

  return {
    ok: true,
    fields: {
      version, contentHash, senderPubkey, sessionId, lastSeenSeq, timestamp, lastSeenHash, prevOwnHash,
    },
  };
}
