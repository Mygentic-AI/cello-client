/**
 * The channel-epoch-seal receipt (M16 / DOD-M16-SEAL-TYPE-1): sign, encode, decode, verify the
 * publisher's signature, and check the link between consecutive epochs.
 *
 * A session seal is a TWO-party record: both participants approve it. A broadcast channel has no
 * counterparty, so its epoch seal is a ONE-party record. The publisher commits to one epoch's
 * Merkle root, and the directory consortium later notarizes that the commitment existed at a
 * time. That is weaker than a session seal, and CHANNEL_EPOCH_SEAL_ATTESTS says so wherever the
 * receipt is shown. This file shares no code with `session.ts` on purpose: the two seal families
 * must stay independently evolvable.
 *
 * The shape follows `broadcast-artifact.ts`:
 *
 *   - A CBOR ARRAY WITH THE DOMAIN IN SLOT 0, NEVER A MAP. The TBS is slots 0–7; the encoded seal
 *     appends publisher_signature, notarization and cosig_ext as slots 8–10.
 *   - THE NOTARIZATION IS OUTSIDE THE TBS. Publisher and directory both sign the same 8-slot TBS,
 *     so the directory countersigns the publisher's exact commitment. Putting the notarization
 *     inside would make the publisher's signature depend on the directory's.
 *   - `cosig_ext` IS RESERVED (a future conclave co-signature) and MUST be null in v1.
 *   - ONE STRICT DECODER, ONE WIRE FORM. Decode refuses any byte form the encoder would not write.
 *   - `leaf_count` IS THE AUTHORITY FOR AN EPOCH'S SIZE. A consistency proof does not bind a size
 *     to a root; this signed field does.
 */

import { verify } from "@cello-protocol/crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import { encodeCbor, decodeCbor } from "./cbor.js";

export const CHANNEL_EPOCH_SEAL_DOMAIN = "cello-channel-epoch-seal-v1";

/** What this receipt proves, and what it does not. Rendered wherever the receipt is shown. */
// Frozen, not only `as const`: the claim must not be strengthened at runtime either.
export const CHANNEL_EPOCH_SEAL_ATTESTS = Object.freeze({
  attests: "publisher-commitment",
  counterparty_approved: false,
  disclaimer:
    "One-party record. The publisher committed to this exact epoch tree, and the directory " +
    "consortium notarized that the commitment existed at this time. No counterparty approved " +
    "the contents; notarization attests existence and timing, not truth.",
} as const);

const PUBKEY_BYTES = 32;
const ROOT_BYTES = 32;
const SIGNATURE_BYTES = 64;
const MAX_NOTARIZATION_BYTES = 4096;
const ENCODED_SLOT_COUNT = 11;

export interface ChannelEpochSeal {
  /** Channel identity: 32-byte Ed25519 public key. */
  channel_pubkey: Uint8Array;
  /** Which epoch this seals, starting at 0. */
  epoch_index: number;
  /** Merkle root over the epoch's artifact leaf hashes (32 bytes). */
  epoch_root: Uint8Array;
  /** Sequence number of the FIRST artifact in this epoch (>= 1). */
  first_seq: number;
  /** Number of artifacts in this epoch (>= 1 — empty epochs never seal). */
  leaf_count: number;
  /** Previous epoch's epoch_root (32 bytes); null ONLY when epoch_index === 0. */
  prev_epoch_root: Uint8Array | null;
  /** Unix ms timestamp the publisher sealed at. */
  sealed_at: number;
  /** Publisher's Ed25519 signature over buildChannelEpochSealTbs(...). */
  publisher_signature: Uint8Array;
  /** Directory threshold notarization over the same TBS; null until the directory signs
   *  (Tier 1 fills this). Opaque bytes at this layer. */
  notarization: Uint8Array | null;
  /** Reserved extension slot (future conclave co-signature). MUST be null in v1. */
  cosig_ext: null;
}

export type EpochSealDecodeReason =
  | "not_cbor" | "wrong_shape" | "wrong_domain" | "bad_channel_pubkey" | "bad_epoch_index"
  | "bad_epoch_root" | "bad_first_seq" | "bad_leaf_count" | "bad_prev_epoch_root"
  | "bad_sealed_at" | "bad_publisher_signature" | "bad_notarization" | "cosig_ext_not_null";

export type EpochChainReason =
  | "channel_mismatch" | "epoch_index_not_next" | "prev_root_mismatch" | "seq_not_contiguous";

type TbsFields = Omit<ChannelEpochSeal, "publisher_signature" | "notarization" | "cosig_ext">;
type FieldFailure = { reason: EpochSealDecodeReason; detail: string };

function isBytes(v: unknown, length?: number): v is Uint8Array {
  return v instanceof Uint8Array && (length === undefined || v.length === length);
}

/** The eight TBS fields, in wire order. `epoch_index` is checked before prev_epoch_root reads it. */
function checkTbsFields(s: {
  channel_pubkey: unknown; epoch_index: unknown; epoch_root: unknown; first_seq: unknown;
  leaf_count: unknown; prev_epoch_root: unknown; sealed_at: unknown;
}): FieldFailure | null {
  if (!isBytes(s.channel_pubkey, PUBKEY_BYTES)) {
    return { reason: "bad_channel_pubkey", detail: `channel_pubkey must be ${PUBKEY_BYTES} bytes` };
  }
  if (!Number.isSafeInteger(s.epoch_index) || (s.epoch_index as number) < 0) {
    return { reason: "bad_epoch_index", detail: "epoch_index must be a safe integer >= 0" };
  }
  if (!isBytes(s.epoch_root, ROOT_BYTES)) {
    return { reason: "bad_epoch_root", detail: `epoch_root must be ${ROOT_BYTES} bytes` };
  }
  if (!Number.isSafeInteger(s.first_seq) || (s.first_seq as number) < 1) {
    return { reason: "bad_first_seq", detail: "first_seq must be a safe integer >= 1" };
  }
  if (!Number.isSafeInteger(s.leaf_count) || (s.leaf_count as number) < 1) {
    return { reason: "bad_leaf_count", detail: "leaf_count must be a safe integer >= 1 (empty epochs never seal)" };
  }
  if (s.epoch_index === 0) {
    if (s.prev_epoch_root !== null) {
      return { reason: "bad_prev_epoch_root", detail: "prev_epoch_root must be null when epoch_index is 0" };
    }
  } else if (!isBytes(s.prev_epoch_root, ROOT_BYTES)) {
    return { reason: "bad_prev_epoch_root", detail: `prev_epoch_root must be ${ROOT_BYTES} bytes when epoch_index >= 1` };
  }
  if (!Number.isSafeInteger(s.sealed_at) || (s.sealed_at as number) < 0) {
    return { reason: "bad_sealed_at", detail: "sealed_at must be a safe integer >= 0" };
  }
  return null;
}

function tbsSlots(s: TbsFields): unknown[] {
  return [
    CHANNEL_EPOCH_SEAL_DOMAIN,
    s.channel_pubkey,
    s.epoch_index,
    s.epoch_root,
    s.first_seq,
    s.leaf_count,
    s.prev_epoch_root,
    s.sealed_at,
  ];
}

export function buildChannelEpochSealTbs(s: TbsFields): Uint8Array {
  return encodeCbor(tbsSlots(s));
}

/** Signs a new seal with notarization and cosig_ext null. Throws RangeError on the first bad field. */
export async function signChannelEpochSeal(
  keyProvider: KeyProvider,
  fields: Omit<TbsFields, "channel_pubkey">,
): Promise<ChannelEpochSeal> {
  const unsigned: TbsFields = {
    channel_pubkey: await keyProvider.getPublicKey(),
    epoch_index: fields.epoch_index,
    epoch_root: fields.epoch_root,
    first_seq: fields.first_seq,
    leaf_count: fields.leaf_count,
    prev_epoch_root: fields.prev_epoch_root,
    sealed_at: fields.sealed_at,
  };
  const failure = checkTbsFields(unsigned);
  if (failure) throw new RangeError(`${failure.reason}: ${failure.detail}`);
  const publisher_signature = await keyProvider.sign(buildChannelEpochSealTbs(unsigned));
  return { ...unsigned, publisher_signature, notarization: null, cosig_ext: null };
}

export function encodeChannelEpochSeal(s: ChannelEpochSeal): Uint8Array {
  return encodeCbor([...tbsSlots(s), s.publisher_signature, s.notarization, s.cosig_ext]);
}

/** Validates every field and never throws. Does NOT verify any signature. */
export function decodeChannelEpochSeal(
  bytes: Uint8Array,
): { ok: true; seal: ChannelEpochSeal } | { ok: false; reason: EpochSealDecodeReason; detail: string } {
  let raw: unknown;
  try {
    raw = decodeCbor(bytes);
  } catch (err) {
    return { ok: false, reason: "not_cbor", detail: err instanceof Error ? err.message : "CBOR decode failed" };
  }
  if (!Array.isArray(raw) || raw.length !== ENCODED_SLOT_COUNT) {
    return { ok: false, reason: "wrong_shape", detail: `expected an array of ${ENCODED_SLOT_COUNT} elements` };
  }
  if (raw[0] !== CHANNEL_EPOCH_SEAL_DOMAIN) {
    return { ok: false, reason: "wrong_domain", detail: `slot 0 must be ${CHANNEL_EPOCH_SEAL_DOMAIN}` };
  }
  const [
    , channel_pubkey, epoch_index, epoch_root, first_seq, leaf_count, prev_epoch_root, sealed_at,
    publisher_signature, notarization, cosig_ext,
  ] = raw;
  const failure = checkTbsFields({
    channel_pubkey, epoch_index, epoch_root, first_seq, leaf_count, prev_epoch_root, sealed_at,
  });
  if (failure) return { ok: false, ...failure };
  if (!isBytes(publisher_signature, SIGNATURE_BYTES)) {
    return { ok: false, reason: "bad_publisher_signature", detail: `publisher_signature must be ${SIGNATURE_BYTES} bytes` };
  }
  if (
    notarization !== null &&
    (!isBytes(notarization) || notarization.length < 1 || notarization.length > MAX_NOTARIZATION_BYTES)
  ) {
    return {
      ok: false,
      reason: "bad_notarization",
      detail: `notarization must be null or 1..${MAX_NOTARIZATION_BYTES} bytes`,
    };
  }
  if (cosig_ext !== null) {
    return { ok: false, reason: "cosig_ext_not_null", detail: "cosig_ext is reserved and must be null in v1" };
  }
  const seal: ChannelEpochSeal = {
    channel_pubkey: new Uint8Array(channel_pubkey as Uint8Array),
    epoch_index: epoch_index as number,
    epoch_root: new Uint8Array(epoch_root as Uint8Array),
    first_seq: first_seq as number,
    leaf_count: leaf_count as number,
    prev_epoch_root: prev_epoch_root === null ? null : new Uint8Array(prev_epoch_root as Uint8Array),
    sealed_at: sealed_at as number,
    publisher_signature: new Uint8Array(publisher_signature),
    notarization: notarization === null ? null : new Uint8Array(notarization as Uint8Array),
    cosig_ext: null,
  };
  // One seal, one wire form. The decoder also reads floats for integers and tag-64 typed arrays for
  // bytes; admitting those would give one signed seal several byte forms, and anything that hashes
  // the RECEIVED bytes would disagree with the channel's own record.
  if (!bytesEqual(encodeChannelEpochSeal(seal), bytes)) {
    return { ok: false, reason: "wrong_shape", detail: "non-canonical encoding" };
  }
  return { ok: true, seal };
}

function bytesEqual(x: Uint8Array, y: Uint8Array): boolean {
  if (x.length !== y.length) return false;
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return false;
  return true;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

/**
 * Checks the PUBLISHER's signature only. It does not check the notarization: that needs the
 * consortium key and lands in Tier 1. Never throws: a hand-built seal with a field the encoder
 * cannot take is false before the TBS is built, and crypto's `verify` returns false on failure.
 */
export function verifyChannelEpochSealSignature(s: ChannelEpochSeal): boolean {
  if (!isObject(s) || checkTbsFields(s) !== null || !isBytes(s.publisher_signature, SIGNATURE_BYTES)) {
    return false;
  }
  return verify(s.channel_pubkey, buildChannelEpochSealTbs(s), s.publisher_signature);
}

function isIndex(v: unknown): v is number {
  return Number.isSafeInteger(v) && (v as number) >= 0;
}

function isPositive(v: unknown): v is number {
  return Number.isSafeInteger(v) && (v as number) >= 1;
}

/**
 * Structure only, no crypto: does `next` directly follow `prev` on the same channel? A dropped
 * artifact between two epochs shows up as `seq_not_contiguous`. Returns the first failure.
 *
 * Never throws. A hand-built seal holding a value no real seal can hold (a missing pubkey, a
 * negative or fractional index or sequence number) fails the comparison that reads that field,
 * under that comparison's reason, rather than crashing or linking.
 */
export function checkEpochChainLink(
  prev: ChannelEpochSeal,
  next: ChannelEpochSeal,
): { ok: true } | { ok: false; reason: EpochChainReason; detail: string } {
  if (!isObject(prev) || !isObject(next)) {
    return { ok: false, reason: "channel_mismatch", detail: "both arguments must be seal objects" };
  }
  if (
    !isBytes(prev.channel_pubkey, PUBKEY_BYTES) ||
    !isBytes(next.channel_pubkey, PUBKEY_BYTES) ||
    !bytesEqual(prev.channel_pubkey, next.channel_pubkey)
  ) {
    return { ok: false, reason: "channel_mismatch", detail: "the two seals belong to different channels" };
  }
  if (!isIndex(prev.epoch_index) || !isIndex(next.epoch_index)) {
    return { ok: false, reason: "epoch_index_not_next", detail: "epoch_index must be a safe integer >= 0 on both seals" };
  }
  if (next.epoch_index !== prev.epoch_index + 1) {
    return {
      ok: false,
      reason: "epoch_index_not_next",
      detail: `expected epoch_index ${prev.epoch_index + 1}, got ${next.epoch_index}`,
    };
  }
  if (
    !isBytes(prev.epoch_root, ROOT_BYTES) ||
    !isBytes(next.prev_epoch_root, ROOT_BYTES) ||
    !bytesEqual(next.prev_epoch_root, prev.epoch_root)
  ) {
    return { ok: false, reason: "prev_root_mismatch", detail: "prev_epoch_root does not match the previous epoch_root" };
  }
  if (!isPositive(prev.first_seq) || !isPositive(prev.leaf_count) || !isPositive(next.first_seq)) {
    return {
      ok: false,
      reason: "seq_not_contiguous",
      detail: "first_seq and leaf_count must be safe integers >= 1",
    };
  }
  if (next.first_seq !== prev.first_seq + prev.leaf_count) {
    return {
      ok: false,
      reason: "seq_not_contiguous",
      detail: `expected first_seq ${prev.first_seq + prev.leaf_count}, got ${next.first_seq}`,
    };
  }
  return { ok: true };
}
