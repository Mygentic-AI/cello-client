/**
 * M16 046-JOINBELL — joining a channel is signed records plus a directory ring, never a session.
 *
 *   ChannelJoinRequest     joiner → admin   signed by the JOINER, sealed to the admin, held on the
 *                                           channel's relays in a hashed join slot
 *   ChannelJoinSlotRecord  what the relay holds: the channel, the slot, the signed time, the sealed
 *                                           request. The relay cannot read who is asking.
 *   ChannelJoinWithdrawal  joiner → admin   signed by the JOINER; overwrites its own join slot
 *                                           (newest signed time wins) — the request is dropped
 *   ChannelJoinAnswer      admin → joiner   signed by the CHANNEL key, sealed to the joiner, carried
 *                                           in the joiner's 045 notice slot (type `join_answer`)
 *
 * ⚠️ **THE JOIN NOTE IS FREE TEXT FROM A STRANGER.** It is the only free text in any of these
 * records: bounded, no control characters, no unpaired surrogates — refused at sign time AND at
 * decode time. Every other field is fixed-shape; a record that fails decode or signature is dropped.
 *
 * Slot: `H(domain ‖ "join" ‖ X25519(joiner key, channel key))` — only the joiner and the channel's
 * admin can compute it, so the relay learns nothing about who asked to join what.
 */
import { createHash } from "node:crypto";
import { verify } from "@cello-protocol/crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import { encodeCbor, decodeCbor } from "./cbor.js";

/** A note is read by a human deciding whether to admit a stranger. Bounded, and plain text. */
export const MAX_JOIN_NOTE_CHARS = 200;
/** The sealed request (note ≤ 800 UTF-8 bytes + keys + signature + seal overhead), with margin. */
export const MAX_JOIN_SEALED_BYTES = 2048;

export const JOIN_REQUEST_DOMAIN = "cello-channel-join-request-v1";
export const JOIN_SLOT_DOMAIN = "cello-channel-join-slot-v1";
export const JOIN_ANSWER_DOMAIN = "cello-channel-join-answer-v1";
export const JOIN_WITHDRAWN_DOMAIN = "cello-channel-join-withdrawn-v1";

const PUBKEY_BYTES = 32;
const SLOT_BYTES = 32;
const SIGNATURE_BYTES = 64;
/** A wrapped group key is a sealed blob; this bounds it rather than describing it. */
const MAX_KEY_BUNDLE_BYTES = 768;

const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f]/u;
const UNPAIRED_SURROGATE = /\p{Surrogate}/u;

export type ChannelJoinOutcome = "accepted" | "refused" | "pending";
export const CHANNEL_JOIN_OUTCOMES: readonly ChannelJoinOutcome[] = ["accepted", "refused", "pending"];

/** The fixed refusal vocabulary. Never free text. */
export type ChannelJoinRefusedReason = "not_admin_of_channel" | "refused_by_admin" | "already_member" | "ejected";
export const CHANNEL_JOIN_REFUSED_REASONS: readonly ChannelJoinRefusedReason[] = [
  "not_admin_of_channel", "refused_by_admin", "already_member", "ejected",
];

export interface ChannelJoinRequest {
  channel_pubkey: Uint8Array;
  joiner_pubkey: Uint8Array;
  note: string;
  /** ms. The admin keeps only the newest per (joiner, channel). */
  signed_at: number;
  /** Ed25519 by the JOINER over the TBS. */
  signature: Uint8Array;
}

export interface ChannelJoinSlotRecord {
  channel_pubkey: Uint8Array;
  slot: Uint8Array;
  signed_at: number;
  /** The encoded ChannelJoinRequest, sealed to the admin's identity key. */
  sealed: Uint8Array;
}

export interface ChannelJoinAnswer {
  channel_pubkey: Uint8Array;
  outcome: ChannelJoinOutcome;
  /** Set only on `refused`, from the fixed vocabulary. */
  reason: ChannelJoinRefusedReason | null;
  /** The group key wrapped for the joiner. Only on `accepted`, and null for a public channel. */
  key_bundle: Uint8Array | null;
  signed_at: number;
  /** Ed25519 by the CHANNEL key over the TBS. */
  signature: Uint8Array;
}

export type JoinDecodeReason =
  | "not_cbor" | "wrong_shape" | "wrong_domain" | "bad_channel_pubkey" | "bad_joiner_pubkey"
  | "bad_note" | "bad_signed_at" | "bad_slot" | "bad_sealed" | "too_large" | "bad_outcome"
  | "bad_reason" | "bad_key_bundle" | "bad_signature_shape";

type Failure = { ok: false; reason: JoinDecodeReason; detail: string };

function isBytes(v: unknown, length?: number): v is Uint8Array {
  return v instanceof Uint8Array && (length === undefined || v.length === length);
}

function badNote(v: unknown): boolean {
  return typeof v !== "string" || [...v].length > MAX_JOIN_NOTE_CHARS || CONTROL_CHARS.test(v) || UNPAIRED_SURROGATE.test(v);
}

function badTime(v: unknown): boolean {
  return !Number.isSafeInteger(v) || (v as number) < 1;
}

function bytesEqual(x: Uint8Array, y: Uint8Array): boolean {
  if (x.length !== y.length) return false;
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return false;
  return true;
}

/** Decode a fixed-length array with the domain in slot 0. Never throws. */
function decodeArray(bytes: Uint8Array, domain: string, length: number): { ok: true; slots: unknown[] } | Failure {
  let raw: unknown;
  try {
    raw = decodeCbor(bytes);
  } catch (err) {
    return { ok: false, reason: "not_cbor", detail: err instanceof Error ? err.message : "CBOR decode failed" };
  }
  if (!Array.isArray(raw) || raw.length !== length) return { ok: false, reason: "wrong_shape", detail: `expected an array of ${String(length)} elements` };
  if (raw[0] !== domain) return { ok: false, reason: "wrong_domain", detail: `slot 0 must be ${domain}` };
  return { ok: true, slots: raw };
}

/** The join slot for one (joiner, channel). `sharedSecret` is X25519(joiner, channel). */
export function channelJoinSlot(sharedSecret: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256")
    .update(JOIN_SLOT_DOMAIN, "utf8").update(Buffer.from([0]))
    .update("join", "utf8").update(Buffer.from([0]))
    .update(Buffer.from(sharedSecret))
    .digest());
}

// ─── Request ────────────────────────────────────────────────────────────────────────────────────

function requestTbs(r: Omit<ChannelJoinRequest, "signature">): Uint8Array {
  return encodeCbor([JOIN_REQUEST_DOMAIN, r.channel_pubkey, r.joiner_pubkey, r.note, r.signed_at]);
}

/** Sign with the JOINER's key; the joiner pubkey is read from the provider, never accepted. */
export async function signChannelJoinRequest(
  joinerKey: KeyProvider, f: { channel_pubkey: Uint8Array; note: string; signed_at: number },
): Promise<ChannelJoinRequest> {
  if (!isBytes(f.channel_pubkey, PUBKEY_BYTES)) throw new RangeError("bad_channel_pubkey: must be 32 bytes");
  if (badNote(f.note)) throw new RangeError(`bad_note: a plain string of at most ${String(MAX_JOIN_NOTE_CHARS)} code points`);
  if (badTime(f.signed_at)) throw new RangeError("bad_signed_at: a safe integer >= 1 (ms)");
  const unsigned = { channel_pubkey: f.channel_pubkey, joiner_pubkey: await joinerKey.getPublicKey(), note: f.note, signed_at: f.signed_at };
  return { ...unsigned, signature: await joinerKey.sign(requestTbs(unsigned)) };
}

export function encodeChannelJoinRequest(r: ChannelJoinRequest): Uint8Array {
  return encodeCbor([JOIN_REQUEST_DOMAIN, r.channel_pubkey, r.joiner_pubkey, r.note, r.signed_at, r.signature]);
}

/** Validates every field and never throws. Does NOT verify the signature. */
export function decodeChannelJoinRequest(bytes: Uint8Array): { ok: true; request: ChannelJoinRequest } | Failure {
  const raw = decodeArray(bytes, JOIN_REQUEST_DOMAIN, 6);
  if (!raw.ok) return raw;
  const [, channel_pubkey, joiner_pubkey, note, signed_at, signature] = raw.slots;
  if (!isBytes(channel_pubkey, PUBKEY_BYTES)) return { ok: false, reason: "bad_channel_pubkey", detail: "must be 32 bytes" };
  if (!isBytes(joiner_pubkey, PUBKEY_BYTES)) return { ok: false, reason: "bad_joiner_pubkey", detail: "must be 32 bytes" };
  if (badNote(note)) return { ok: false, reason: "bad_note", detail: "too long or not plain text" };
  if (badTime(signed_at)) return { ok: false, reason: "bad_signed_at", detail: "a safe integer >= 1 (ms)" };
  if (!isBytes(signature, SIGNATURE_BYTES)) return { ok: false, reason: "bad_signature_shape", detail: "must be 64 bytes" };
  const request: ChannelJoinRequest = {
    channel_pubkey: new Uint8Array(channel_pubkey), joiner_pubkey: new Uint8Array(joiner_pubkey),
    note: note as string, signed_at: signed_at as number, signature: new Uint8Array(signature),
  };
  if (!bytesEqual(encodeChannelJoinRequest(request), bytes)) return { ok: false, reason: "wrong_shape", detail: "non-canonical encoding" };
  return { ok: true, request };
}

/** Signed by the joiner the request names. Whether that is the EXPECTED joiner is the caller's. */
export function verifyChannelJoinRequest(r: ChannelJoinRequest): boolean {
  return verify(r.joiner_pubkey, requestTbs(r), r.signature);
}

// ─── Withdrawal ─────────────────────────────────────────────────────────────────────────────────

/** Decision 12: the joiner takes its request back. Same slot, same sealing, a newer signed time. */
export interface ChannelJoinWithdrawal {
  channel_pubkey: Uint8Array;
  joiner_pubkey: Uint8Array;
  signed_at: number;
  signature: Uint8Array;
}

function withdrawalTbs(w: Omit<ChannelJoinWithdrawal, "signature">): Uint8Array {
  return encodeCbor([JOIN_WITHDRAWN_DOMAIN, w.channel_pubkey, w.joiner_pubkey, w.signed_at]);
}

export async function signChannelJoinWithdrawal(
  joinerKey: KeyProvider, f: { channel_pubkey: Uint8Array; signed_at: number },
): Promise<ChannelJoinWithdrawal> {
  if (!isBytes(f.channel_pubkey, PUBKEY_BYTES)) throw new RangeError("bad_channel_pubkey: must be 32 bytes");
  if (badTime(f.signed_at)) throw new RangeError("bad_signed_at: a safe integer >= 1 (ms)");
  const unsigned = { channel_pubkey: f.channel_pubkey, joiner_pubkey: await joinerKey.getPublicKey(), signed_at: f.signed_at };
  return { ...unsigned, signature: await joinerKey.sign(withdrawalTbs(unsigned)) };
}

export function encodeChannelJoinWithdrawal(w: ChannelJoinWithdrawal): Uint8Array {
  return encodeCbor([JOIN_WITHDRAWN_DOMAIN, w.channel_pubkey, w.joiner_pubkey, w.signed_at, w.signature]);
}

/** Validates every field and never throws. Does NOT verify the signature. */
export function decodeChannelJoinWithdrawal(bytes: Uint8Array): { ok: true; withdrawal: ChannelJoinWithdrawal } | Failure {
  const raw = decodeArray(bytes, JOIN_WITHDRAWN_DOMAIN, 5);
  if (!raw.ok) return raw;
  const [, channel_pubkey, joiner_pubkey, signed_at, signature] = raw.slots;
  if (!isBytes(channel_pubkey, PUBKEY_BYTES)) return { ok: false, reason: "bad_channel_pubkey", detail: "must be 32 bytes" };
  if (!isBytes(joiner_pubkey, PUBKEY_BYTES)) return { ok: false, reason: "bad_joiner_pubkey", detail: "must be 32 bytes" };
  if (badTime(signed_at)) return { ok: false, reason: "bad_signed_at", detail: "a safe integer >= 1 (ms)" };
  if (!isBytes(signature, SIGNATURE_BYTES)) return { ok: false, reason: "bad_signature_shape", detail: "must be 64 bytes" };
  const withdrawal: ChannelJoinWithdrawal = {
    channel_pubkey: new Uint8Array(channel_pubkey), joiner_pubkey: new Uint8Array(joiner_pubkey),
    signed_at: signed_at as number, signature: new Uint8Array(signature),
  };
  if (!bytesEqual(encodeChannelJoinWithdrawal(withdrawal), bytes)) return { ok: false, reason: "wrong_shape", detail: "non-canonical encoding" };
  return { ok: true, withdrawal };
}

export function verifyChannelJoinWithdrawal(w: ChannelJoinWithdrawal): boolean {
  return verify(w.joiner_pubkey, withdrawalTbs(w), w.signature);
}

// ─── The slot record the relay holds ─────────────────────────────────────────────────────────────

function slotFailure(r: { channel_pubkey: unknown; slot: unknown; signed_at: unknown; sealed: unknown }): Failure | null {
  if (!isBytes(r.channel_pubkey, PUBKEY_BYTES)) return { ok: false, reason: "bad_channel_pubkey", detail: "must be 32 bytes" };
  if (!isBytes(r.slot, SLOT_BYTES)) return { ok: false, reason: "bad_slot", detail: "must be 32 bytes" };
  if (badTime(r.signed_at)) return { ok: false, reason: "bad_signed_at", detail: "a safe integer >= 1 (ms)" };
  if (!isBytes(r.sealed) || r.sealed.length === 0) return { ok: false, reason: "bad_sealed", detail: "non-empty bytes" };
  if (r.sealed.length > MAX_JOIN_SEALED_BYTES) return { ok: false, reason: "too_large", detail: `at most ${String(MAX_JOIN_SEALED_BYTES)} sealed bytes` };
  return null;
}

export function encodeChannelJoinSlotRecord(r: ChannelJoinSlotRecord): Uint8Array {
  const failure = slotFailure(r);
  if (failure) throw new RangeError(`${failure.reason}: ${failure.detail}`);
  return encodeCbor([JOIN_SLOT_DOMAIN, r.channel_pubkey, r.slot, r.signed_at, r.sealed]);
}

export function decodeChannelJoinSlotRecord(bytes: Uint8Array): { ok: true; record: ChannelJoinSlotRecord } | Failure {
  const raw = decodeArray(bytes, JOIN_SLOT_DOMAIN, 5);
  if (!raw.ok) return raw;
  const [, channel_pubkey, slot, signed_at, sealed] = raw.slots;
  const failure = slotFailure({ channel_pubkey, slot, signed_at, sealed });
  if (failure) return failure;
  const record: ChannelJoinSlotRecord = {
    channel_pubkey: new Uint8Array(channel_pubkey as Uint8Array), slot: new Uint8Array(slot as Uint8Array),
    signed_at: signed_at as number, sealed: new Uint8Array(sealed as Uint8Array),
  };
  if (!bytesEqual(encodeChannelJoinSlotRecord(record), bytes)) return { ok: false, reason: "wrong_shape", detail: "non-canonical encoding" };
  return { ok: true, record };
}

// ─── Answer ─────────────────────────────────────────────────────────────────────────────────────

function answerTbs(a: Omit<ChannelJoinAnswer, "signature">): Uint8Array {
  return encodeCbor([JOIN_ANSWER_DOMAIN, a.channel_pubkey, a.outcome, a.reason, a.key_bundle, a.signed_at]);
}

function answerFailure(a: { channel_pubkey: unknown; outcome: unknown; reason: unknown; key_bundle: unknown; signed_at: unknown }): Failure | null {
  if (!isBytes(a.channel_pubkey, PUBKEY_BYTES)) return { ok: false, reason: "bad_channel_pubkey", detail: "must be 32 bytes" };
  if (typeof a.outcome !== "string" || !(CHANNEL_JOIN_OUTCOMES as readonly string[]).includes(a.outcome)) {
    return { ok: false, reason: "bad_outcome", detail: `one of ${CHANNEL_JOIN_OUTCOMES.join(", ")}` };
  }
  const refused = a.outcome === "refused";
  if (refused ? !(typeof a.reason === "string" && (CHANNEL_JOIN_REFUSED_REASONS as readonly string[]).includes(a.reason)) : a.reason !== null) {
    return { ok: false, reason: "bad_reason", detail: "a refusal carries one fixed reason; nothing else carries one" };
  }
  const keyed = a.key_bundle !== null;
  if (keyed && (a.outcome !== "accepted" || !isBytes(a.key_bundle) || a.key_bundle.length === 0 || a.key_bundle.length > MAX_KEY_BUNDLE_BYTES)) {
    return { ok: false, reason: "bad_key_bundle", detail: "only an acceptance carries a key, of bounded size" };
  }
  if (badTime(a.signed_at)) return { ok: false, reason: "bad_signed_at", detail: "a safe integer >= 1 (ms)" };
  return null;
}

/** Sign with the CHANNEL key; the channel pubkey is read from the provider, never accepted. */
export async function signChannelJoinAnswer(
  channelKey: KeyProvider, f: Omit<ChannelJoinAnswer, "channel_pubkey" | "signature">,
): Promise<ChannelJoinAnswer> {
  const unsigned = { channel_pubkey: await channelKey.getPublicKey(), ...f };
  const failure = answerFailure(unsigned);
  if (failure) throw new RangeError(`${failure.reason}: ${failure.detail}`);
  return { ...unsigned, signature: await channelKey.sign(answerTbs(unsigned)) };
}

export function encodeChannelJoinAnswer(a: ChannelJoinAnswer): Uint8Array {
  return encodeCbor([JOIN_ANSWER_DOMAIN, a.channel_pubkey, a.outcome, a.reason, a.key_bundle, a.signed_at, a.signature]);
}

/** Validates every field and never throws. Does NOT verify the signature. */
export function decodeChannelJoinAnswer(bytes: Uint8Array): { ok: true; answer: ChannelJoinAnswer } | Failure {
  const raw = decodeArray(bytes, JOIN_ANSWER_DOMAIN, 7);
  if (!raw.ok) return raw;
  const [, channel_pubkey, outcome, reason, key_bundle, signed_at, signature] = raw.slots;
  const failure = answerFailure({ channel_pubkey, outcome, reason, key_bundle, signed_at });
  if (failure) return failure;
  if (!isBytes(signature, SIGNATURE_BYTES)) return { ok: false, reason: "bad_signature_shape", detail: "must be 64 bytes" };
  const answer: ChannelJoinAnswer = {
    channel_pubkey: new Uint8Array(channel_pubkey as Uint8Array),
    outcome: outcome as ChannelJoinOutcome,
    reason: reason as ChannelJoinRefusedReason | null,
    key_bundle: key_bundle === null ? null : new Uint8Array(key_bundle as Uint8Array),
    signed_at: signed_at as number,
    signature: new Uint8Array(signature),
  };
  if (!bytesEqual(encodeChannelJoinAnswer(answer), bytes)) return { ok: false, reason: "wrong_shape", detail: "non-canonical encoding" };
  return { ok: true, answer };
}

/** Signed by the channel key the answer names. Whether that is the EXPECTED channel is the caller's. */
export function verifyChannelJoinAnswer(a: ChannelJoinAnswer): boolean {
  return verify(a.channel_pubkey, answerTbs(a), a.signature);
}
