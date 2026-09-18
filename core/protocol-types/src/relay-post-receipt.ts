/**
 * The relay's signed receipt for a post (M16 / DOD-M16-ARTIFACT-1).
 *
 * `published_at` inside a post is the publisher's own clock and proves nothing on its own — a
 * publisher can write any time it likes. The receipt is what makes time meaningful: the relay signs
 * the post's HASH together with the time IT received the post, so the publisher holds proof of what
 * it sent and when that relay took it. That proof is what a recovery later rests on.
 *
 * THE RECEIPT BINDS ITS POST BY HASH, never by sequence number alone. A receipt that matched on
 * (channel, seq) would attest to whatever post the publisher later chose to put at that number,
 * which is exactly the substitution the receipt exists to make impossible.
 *
 * Same wire discipline as the post: a CBOR array with the domain in slot 0, fixed field order, one
 * strict decoder.
 */

import { hash, verify } from "@cello-protocol/crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import { encodeCbor, decodeCbor } from "./cbor.js";
import { encodeBroadcastArtifact } from "./broadcast-artifact.js";
import type { BroadcastArtifact } from "./broadcast-artifact.js";

export const RELAY_POST_RECEIPT_DOMAIN = "cello-relay-post-receipt-v1";

const PUBKEY_BYTES = 32;
const HASH_BYTES = 32;
const SIGNATURE_BYTES = 64;
const ENCODED_SLOT_COUNT = 7;

export interface RelayPostReceipt {
  /** The relay's own 32-byte Ed25519 public key. */
  relay_pubkey: Uint8Array;
  /** The channel the post belongs to. */
  channel_pubkey: Uint8Array;
  /** The post's sequence number — for lookup; the hash is what binds. */
  seq: number;
  /** SHA-256 over the encoded post. */
  post_hash: Uint8Array;
  /** The relay's clock when it took the post, ms. */
  received_at: number;
  /** Ed25519 signature by `relay_pubkey` over buildRelayPostReceiptTbs(...). */
  signature: Uint8Array;
}

export type RelayPostReceiptDecodeReason =
  | "not_cbor" | "wrong_shape" | "wrong_domain" | "bad_relay_pubkey" | "bad_channel_pubkey"
  | "bad_seq" | "bad_post_hash" | "bad_received_at" | "bad_signature_shape";

type FieldFailure = { reason: RelayPostReceiptDecodeReason; detail: string };

function isBytes(v: unknown, length?: number): v is Uint8Array {
  return v instanceof Uint8Array && (length === undefined || v.length === length);
}

function checkFields(r: {
  relay_pubkey: unknown; channel_pubkey: unknown; seq: unknown; post_hash: unknown; received_at: unknown;
}): FieldFailure | null {
  if (!isBytes(r.relay_pubkey, PUBKEY_BYTES)) {
    return { reason: "bad_relay_pubkey", detail: `relay_pubkey must be ${PUBKEY_BYTES} bytes` };
  }
  if (!isBytes(r.channel_pubkey, PUBKEY_BYTES)) {
    return { reason: "bad_channel_pubkey", detail: `channel_pubkey must be ${PUBKEY_BYTES} bytes` };
  }
  if (!Number.isSafeInteger(r.seq) || (r.seq as number) < 1) {
    return { reason: "bad_seq", detail: "seq must be a safe integer >= 1" };
  }
  if (!isBytes(r.post_hash, HASH_BYTES)) {
    return { reason: "bad_post_hash", detail: `post_hash must be ${HASH_BYTES} bytes` };
  }
  if (!Number.isSafeInteger(r.received_at) || (r.received_at as number) < 1) {
    return { reason: "bad_received_at", detail: "received_at must be a safe integer >= 1 (ms)" };
  }
  return null;
}

/** SHA-256 over the post's canonical encoding — what the receipt commits to. */
export function broadcastPostHash(post: BroadcastArtifact): Uint8Array {
  return hash(encodeBroadcastArtifact(post));
}

export function buildRelayPostReceiptTbs(r: Omit<RelayPostReceipt, "signature">): Uint8Array {
  return encodeCbor([
    RELAY_POST_RECEIPT_DOMAIN,
    r.relay_pubkey,
    r.channel_pubkey,
    r.seq,
    r.post_hash,
    r.received_at,
  ]);
}

export async function signRelayPostReceipt(
  relayKeyProvider: KeyProvider,
  post: BroadcastArtifact,
  receivedAtMs: number,
): Promise<RelayPostReceipt> {
  const unsigned: Omit<RelayPostReceipt, "signature"> = {
    relay_pubkey: await relayKeyProvider.getPublicKey(),
    channel_pubkey: new Uint8Array(post.channel_pubkey),
    seq: post.seq,
    post_hash: broadcastPostHash(post),
    received_at: receivedAtMs,
  };
  const failure = checkFields(unsigned);
  if (failure) throw new RangeError(`${failure.reason}: ${failure.detail}`);
  const signature = await relayKeyProvider.sign(buildRelayPostReceiptTbs(unsigned));
  return { ...unsigned, signature };
}

export function encodeRelayPostReceipt(r: RelayPostReceipt): Uint8Array {
  return encodeCbor([
    RELAY_POST_RECEIPT_DOMAIN,
    r.relay_pubkey,
    r.channel_pubkey,
    r.seq,
    r.post_hash,
    r.received_at,
    r.signature,
  ]);
}

/** Validates every field and never throws. Does NOT verify the signature — see verifyRelayPostReceipt. */
export function decodeRelayPostReceipt(
  bytes: Uint8Array,
): { ok: true; receipt: RelayPostReceipt } | { ok: false; reason: RelayPostReceiptDecodeReason; detail: string } {
  let raw: unknown;
  try {
    raw = decodeCbor(bytes);
  } catch (err) {
    return { ok: false, reason: "not_cbor", detail: err instanceof Error ? err.message : "CBOR decode failed" };
  }
  if (!Array.isArray(raw) || raw.length !== ENCODED_SLOT_COUNT) {
    return { ok: false, reason: "wrong_shape", detail: `expected an array of ${ENCODED_SLOT_COUNT} elements` };
  }
  if (raw[0] !== RELAY_POST_RECEIPT_DOMAIN) {
    return { ok: false, reason: "wrong_domain", detail: `slot 0 must be ${RELAY_POST_RECEIPT_DOMAIN}` };
  }
  const [, relay_pubkey, channel_pubkey, seq, post_hash, received_at, signature] = raw;
  const failure = checkFields({ relay_pubkey, channel_pubkey, seq, post_hash, received_at });
  if (failure) return { ok: false, ...failure };
  if (!isBytes(signature, SIGNATURE_BYTES)) {
    return { ok: false, reason: "bad_signature_shape", detail: `signature must be ${SIGNATURE_BYTES} bytes` };
  }
  const receipt: RelayPostReceipt = {
    relay_pubkey: new Uint8Array(relay_pubkey as Uint8Array),
    channel_pubkey: new Uint8Array(channel_pubkey as Uint8Array),
    seq: seq as number,
    post_hash: new Uint8Array(post_hash as Uint8Array),
    received_at: received_at as number,
    signature: new Uint8Array(signature),
  };
  // One receipt, one wire form — the same reason the post has: anything that dedups or hashes the
  // received bytes would otherwise see two receipts where one relay signed once.
  if (!bytesEqual(encodeRelayPostReceipt(receipt), bytes)) {
    return { ok: false, reason: "wrong_shape", detail: "non-canonical encoding" };
  }
  return { ok: true, receipt };
}

function bytesEqual(x: Uint8Array, y: Uint8Array): boolean {
  if (x.length !== y.length) return false;
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return false;
  return true;
}

/**
 * The signature AND the recomputed post hash. Checking only the signature would accept a receipt
 * the relay really signed, for a DIFFERENT post — which is the whole substitution this guards.
 */
export function verifyRelayPostReceipt(receipt: RelayPostReceipt, post: BroadcastArtifact): boolean {
  if (!bytesEqual(receipt.post_hash, broadcastPostHash(post))) return false;
  if (receipt.seq !== post.seq) return false;
  if (!bytesEqual(receipt.channel_pubkey, post.channel_pubkey)) return false;
  return verify(receipt.relay_pubkey, buildRelayPostReceiptTbs(receipt), receipt.signature);
}
