/**
 * The channel posting pass (M16 / 043-POSTERS): the admin's signed, expiring permission for another
 * agent to post on a channel.
 *
 * ⚠️ **ONLY THE CHANNEL KEY SIGNS IT.** The channel key is the right to publish; a pass is that right
 * lent to one named agent for a bounded time. The poster then signs its posts with its OWN agent key
 * and carries the pass, so a post stays tied to the operator who wrote it.
 *
 * A pass EXPIRES (the lease): the admin's daemon re-issues it before it runs out, so an admin gone
 * longer than the lease stops every other poster. Revocation is published in the channel info record
 * by poster pubkey and time — a pass issued before that time is dead.
 *
 * Same wire discipline as the post and the info record: a CBOR array with the domain in slot 0,
 * fixed field order, one strict decoder, one canonical form.
 */

import { verify } from "@cello-protocol/crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import { encodeCbor, decodeCbor } from "./cbor.js";

export const CHANNEL_POSTER_PASS_DOMAIN = "cello-channel-poster-pass-v1";

const PUBKEY_BYTES = 32;
const SIGNATURE_BYTES = 64;
/** domain + 4 fields + signature. The TBS is the first five. */
const ENCODED_SLOT_COUNT = 6;

export interface ChannelPosterPass {
  channel_pubkey: Uint8Array;
  /** The agent allowed to post. Must equal the post's `agent_pubkey`. */
  poster_pubkey: Uint8Array;
  issued_at: number;
  /** A post published after this (ms) is refused. */
  expires_at: number;
  /** Ed25519 by the CHANNEL key over the TBS. */
  signature: Uint8Array;
}

export type ChannelPosterPassDecodeReason =
  | "not_cbor" | "wrong_shape" | "wrong_domain" | "bad_channel_pubkey" | "bad_poster_pubkey"
  | "bad_issued_at" | "bad_expires_at" | "bad_signature_shape";

export type ChannelPosterPassVerifyResult =
  | { ok: true }
  | { ok: false; reason: "wrong_channel" | "signature_invalid" };

type Unsigned = Omit<ChannelPosterPass, "signature">;
type FieldFailure = { reason: ChannelPosterPassDecodeReason; detail: string };

function isBytes(v: unknown, length?: number): v is Uint8Array {
  return v instanceof Uint8Array && (length === undefined || v.length === length);
}

function checkFields(p: { channel_pubkey: unknown; poster_pubkey: unknown; issued_at: unknown; expires_at: unknown }): FieldFailure | null {
  if (!isBytes(p.channel_pubkey, PUBKEY_BYTES)) {
    return { reason: "bad_channel_pubkey", detail: `channel_pubkey must be ${PUBKEY_BYTES} bytes` };
  }
  if (!isBytes(p.poster_pubkey, PUBKEY_BYTES)) {
    return { reason: "bad_poster_pubkey", detail: `poster_pubkey must be ${PUBKEY_BYTES} bytes` };
  }
  if (!Number.isSafeInteger(p.issued_at) || (p.issued_at as number) < 1) {
    return { reason: "bad_issued_at", detail: "issued_at must be a safe integer >= 1 (ms)" };
  }
  if (!Number.isSafeInteger(p.expires_at) || (p.expires_at as number) <= (p.issued_at as number)) {
    return { reason: "bad_expires_at", detail: "expires_at must be a safe integer > issued_at (ms)" };
  }
  return null;
}

function tbsSlots(p: Unsigned): unknown[] {
  return [CHANNEL_POSTER_PASS_DOMAIN, p.channel_pubkey, p.poster_pubkey, p.issued_at, p.expires_at];
}

export function buildChannelPosterPassTbs(p: Unsigned): Uint8Array {
  return encodeCbor(tbsSlots(p));
}

/** Sign with the CHANNEL key; the channel pubkey is read from the provider, never accepted. */
export async function signChannelPosterPass(
  channelKeyProvider: KeyProvider,
  fields: Omit<Unsigned, "channel_pubkey">,
): Promise<ChannelPosterPass> {
  const unsigned: Unsigned = { channel_pubkey: await channelKeyProvider.getPublicKey(), ...fields };
  const failure = checkFields(unsigned);
  if (failure) throw new RangeError(`${failure.reason}: ${failure.detail}`);
  return { ...unsigned, signature: await channelKeyProvider.sign(buildChannelPosterPassTbs(unsigned)) };
}

export function encodeChannelPosterPass(p: ChannelPosterPass): Uint8Array {
  return encodeCbor([...tbsSlots(p), p.signature]);
}

/** Validates every field and never throws. Does NOT verify the signature — see verifyPosterPass. */
export function decodeChannelPosterPass(
  bytes: Uint8Array,
): { ok: true; pass: ChannelPosterPass } | { ok: false; reason: ChannelPosterPassDecodeReason; detail: string } {
  let raw: unknown;
  try {
    raw = decodeCbor(bytes);
  } catch (err) {
    return { ok: false, reason: "not_cbor", detail: err instanceof Error ? err.message : "CBOR decode failed" };
  }
  if (!Array.isArray(raw) || raw.length !== ENCODED_SLOT_COUNT) {
    return { ok: false, reason: "wrong_shape", detail: `expected an array of ${ENCODED_SLOT_COUNT} elements` };
  }
  if (raw[0] !== CHANNEL_POSTER_PASS_DOMAIN) {
    return { ok: false, reason: "wrong_domain", detail: `slot 0 must be ${CHANNEL_POSTER_PASS_DOMAIN}` };
  }
  const [, channel_pubkey, poster_pubkey, issued_at, expires_at, signature] = raw;
  const failure = checkFields({ channel_pubkey, poster_pubkey, issued_at, expires_at });
  if (failure) return { ok: false, ...failure };
  if (!isBytes(signature, SIGNATURE_BYTES)) {
    return { ok: false, reason: "bad_signature_shape", detail: `signature must be ${SIGNATURE_BYTES} bytes` };
  }
  const pass: ChannelPosterPass = {
    channel_pubkey: new Uint8Array(channel_pubkey as Uint8Array),
    poster_pubkey: new Uint8Array(poster_pubkey as Uint8Array),
    issued_at: issued_at as number,
    expires_at: expires_at as number,
    signature: new Uint8Array(signature),
  };
  if (!bytesEqual(encodeChannelPosterPass(pass), bytes)) {
    return { ok: false, reason: "wrong_shape", detail: "non-canonical encoding" };
  }
  return { ok: true, pass };
}

function bytesEqual(x: Uint8Array, y: Uint8Array): boolean {
  if (x.length !== y.length) return false;
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return false;
  return true;
}

/**
 * The pass must name `channelPubkey` AND be signed by it. Expiry and revocation are the caller's:
 * they depend on a clock (the relay's) or a record (the channel info) this format does not hold.
 */
export function verifyPosterPass(p: ChannelPosterPass, channelPubkey: Uint8Array): ChannelPosterPassVerifyResult {
  if (!bytesEqual(p.channel_pubkey, channelPubkey)) return { ok: false, reason: "wrong_channel" };
  if (!verify(channelPubkey, buildChannelPosterPassTbs(p), p.signature)) return { ok: false, reason: "signature_invalid" };
  return { ok: true };
}
