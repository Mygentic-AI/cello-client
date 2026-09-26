/**
 * The sealed channel notice (M16 / 045-NOTICEBELL): how a channel's admin tells ONE member
 * something — a posting pass, an ejection, a new group key — without opening a session.
 *
 * ⚠️ **SIGNED BY THE CHANNEL KEY, SEALED TO THE MEMBER, STORED UNDER A SLOT ONLY THE TWO OF THEM CAN
 * COMPUTE.** `slot = H(domain ‖ type ‖ X25519(channel key, member key))`: the relay holds a record
 * per slot and learns nothing about who is a member. There is at most one record per
 * (channel, member, type); a newer signed `issued_at` replaces the old one, an older one is refused.
 *
 * Fixed CBOR shapes, no free text: a record that fails decode or signature is dropped by the member.
 * Same wire discipline as the posting pass — a CBOR array with the domain in slot 0, one strict
 * decoder, one canonical form.
 */

import { createHash } from "node:crypto";
import { verify } from "@cello-protocol/crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import { encodeCbor, decodeCbor } from "./cbor.js";

export const CHANNEL_NOTICE_DOMAIN = "cello-channel-notice-v1";
export const CHANNEL_NOTICE_SLOT_DOMAIN = "cello-channel-notice-slot-v1";

export type ChannelNoticeType = "pass" | "eject" | "group_key";
export const CHANNEL_NOTICE_TYPES: readonly ChannelNoticeType[] = ["pass", "eject", "group_key"];

/**
 * The fixed maximum size of a notice's SEALED body, per type. A pass carries the member list (32
 * bytes a member), so it is the large one; an eject carries only the channel key.
 */
export const CHANNEL_NOTICE_MAX_SEALED_BYTES: Readonly<Record<ChannelNoticeType, number>> = {
  pass: 64 * 1024,
  eject: 256,
  group_key: 1024,
};

const PUBKEY_BYTES = 32;
const SLOT_BYTES = 32;
const SIGNATURE_BYTES = 64;
/** domain + 5 fields + signature. The TBS is the first six. */
const ENCODED_SLOT_COUNT = 7;

export interface ChannelNotice {
  channel_pubkey: Uint8Array;
  slot: Uint8Array;
  type: ChannelNoticeType;
  /** ms. The member and the relay both keep only the newest per slot. */
  issued_at: number;
  /** The body, sealed to the member's identity key (`sealToRecipient`). */
  sealed: Uint8Array;
  /** Ed25519 by the CHANNEL key over the TBS. */
  signature: Uint8Array;
}

export type ChannelNoticeDecodeReason =
  | "not_cbor" | "wrong_shape" | "wrong_domain" | "bad_channel_pubkey" | "bad_slot" | "bad_type"
  | "bad_issued_at" | "bad_sealed" | "too_large" | "bad_signature_shape";

type Unsigned = Omit<ChannelNotice, "signature">;
type FieldFailure = { reason: ChannelNoticeDecodeReason; detail: string };

function isBytes(v: unknown, length?: number): v is Uint8Array {
  return v instanceof Uint8Array && (length === undefined || v.length === length);
}

function isNoticeType(v: unknown): v is ChannelNoticeType {
  return typeof v === "string" && (CHANNEL_NOTICE_TYPES as readonly string[]).includes(v);
}

/** The slot a (channel, member, type) notice lives under. `sharedSecret` is the X25519 secret. */
export function channelNoticeSlot(sharedSecret: Uint8Array, type: ChannelNoticeType): Uint8Array {
  return new Uint8Array(createHash("sha256")
    .update(CHANNEL_NOTICE_SLOT_DOMAIN, "utf8").update(Buffer.from([0]))
    .update(type, "utf8").update(Buffer.from([0]))
    .update(Buffer.from(sharedSecret))
    .digest());
}

function checkFields(n: { channel_pubkey: unknown; slot: unknown; type: unknown; issued_at: unknown; sealed: unknown }): FieldFailure | null {
  if (!isBytes(n.channel_pubkey, PUBKEY_BYTES)) return { reason: "bad_channel_pubkey", detail: `channel_pubkey must be ${PUBKEY_BYTES} bytes` };
  if (!isBytes(n.slot, SLOT_BYTES)) return { reason: "bad_slot", detail: `slot must be ${SLOT_BYTES} bytes` };
  if (!isNoticeType(n.type)) return { reason: "bad_type", detail: `type must be one of ${CHANNEL_NOTICE_TYPES.join(", ")}` };
  if (!Number.isSafeInteger(n.issued_at) || (n.issued_at as number) < 1) return { reason: "bad_issued_at", detail: "issued_at must be a safe integer >= 1 (ms)" };
  if (!isBytes(n.sealed) || n.sealed.length === 0) return { reason: "bad_sealed", detail: "sealed must be non-empty bytes" };
  if (n.sealed.length > CHANNEL_NOTICE_MAX_SEALED_BYTES[n.type]) {
    return { reason: "too_large", detail: `a ${n.type} notice is at most ${CHANNEL_NOTICE_MAX_SEALED_BYTES[n.type]} sealed bytes` };
  }
  return null;
}

function tbsSlots(n: Unsigned): unknown[] {
  return [CHANNEL_NOTICE_DOMAIN, n.channel_pubkey, n.slot, n.type, n.issued_at, n.sealed];
}

export function buildChannelNoticeTbs(n: Unsigned): Uint8Array {
  return encodeCbor(tbsSlots(n));
}

/** Sign with the CHANNEL key; the channel pubkey is read from the provider, never accepted. */
export async function signChannelNotice(
  channelKeyProvider: KeyProvider,
  fields: Omit<Unsigned, "channel_pubkey">,
): Promise<ChannelNotice> {
  const unsigned: Unsigned = { channel_pubkey: await channelKeyProvider.getPublicKey(), ...fields };
  const failure = checkFields(unsigned);
  if (failure) throw new RangeError(`${failure.reason}: ${failure.detail}`);
  return { ...unsigned, signature: await channelKeyProvider.sign(buildChannelNoticeTbs(unsigned)) };
}

export function encodeChannelNotice(n: ChannelNotice): Uint8Array {
  return encodeCbor([...tbsSlots(n), n.signature]);
}

/** Validates every field and never throws. Does NOT verify the signature — see verifyChannelNotice. */
export function decodeChannelNotice(
  bytes: Uint8Array,
): { ok: true; notice: ChannelNotice } | { ok: false; reason: ChannelNoticeDecodeReason; detail: string } {
  let raw: unknown;
  try {
    raw = decodeCbor(bytes);
  } catch (err) {
    return { ok: false, reason: "not_cbor", detail: err instanceof Error ? err.message : "CBOR decode failed" };
  }
  if (!Array.isArray(raw) || raw.length !== ENCODED_SLOT_COUNT) {
    return { ok: false, reason: "wrong_shape", detail: `expected an array of ${ENCODED_SLOT_COUNT} elements` };
  }
  if (raw[0] !== CHANNEL_NOTICE_DOMAIN) return { ok: false, reason: "wrong_domain", detail: `slot 0 must be ${CHANNEL_NOTICE_DOMAIN}` };
  const [, channel_pubkey, slot, type, issued_at, sealed, signature] = raw;
  const failure = checkFields({ channel_pubkey, slot, type, issued_at, sealed });
  if (failure) return { ok: false, ...failure };
  if (!isBytes(signature, SIGNATURE_BYTES)) return { ok: false, reason: "bad_signature_shape", detail: `signature must be ${SIGNATURE_BYTES} bytes` };
  const notice: ChannelNotice = {
    channel_pubkey: new Uint8Array(channel_pubkey as Uint8Array),
    slot: new Uint8Array(slot as Uint8Array),
    type: type as ChannelNoticeType,
    issued_at: issued_at as number,
    sealed: new Uint8Array(sealed as Uint8Array),
    signature: new Uint8Array(signature),
  };
  if (!bytesEqual(encodeChannelNotice(notice), bytes)) return { ok: false, reason: "wrong_shape", detail: "non-canonical encoding" };
  return { ok: true, notice };
}

/** Signed by the channel key the record names. Whether that is the EXPECTED channel is the caller's. */
export function verifyChannelNotice(n: ChannelNotice): boolean {
  return verify(n.channel_pubkey, buildChannelNoticeTbs(n), n.signature);
}

/** A `pass` notice's body, before sealing: the signed pass and the channel's current member list. */
export function encodeNoticePassBody(passCbor: Uint8Array, members: Uint8Array[]): Uint8Array {
  return encodeCbor([passCbor, members]);
}

export function decodeNoticePassBody(bytes: Uint8Array): { pass_cbor: Uint8Array; members: Uint8Array[] } | null {
  let raw: unknown;
  try {
    raw = decodeCbor(bytes);
  } catch {
    return null;
  }
  if (!Array.isArray(raw) || raw.length !== 2 || !isBytes(raw[0]) || !Array.isArray(raw[1])) return null;
  const members = raw[1] as unknown[];
  if (!members.every((m) => isBytes(m, PUBKEY_BYTES))) return null;
  return { pass_cbor: new Uint8Array(raw[0]), members: (members as Uint8Array[]).map((m) => new Uint8Array(m)) };
}

/** An `eject` notice's body, before sealing: the channel it ends. */
export function encodeNoticeEjectBody(channelPubkey: Uint8Array): Uint8Array {
  return encodeCbor([channelPubkey]);
}

function bytesEqual(x: Uint8Array, y: Uint8Array): boolean {
  if (x.length !== y.length) return false;
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return false;
  return true;
}
