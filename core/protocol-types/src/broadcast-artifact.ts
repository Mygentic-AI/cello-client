/**
 * The signed broadcast artifact (M16 / DOD-M16-ARTIFACT-1): encode, decode, sign, verify, leaf hash.
 *
 * A broadcast is a SIGNED ARTIFACT, not a conversation: the channel signs it once and every
 * subscriber verifies it against the channel's public key. What is frozen here is what every
 * daemon speaks, so the shape follows `trust-signal.ts`:
 *
 *   - THE ENCODING IS A CBOR ARRAY WITH THE DOMAIN IN SLOT 0, NEVER A MAP. The shared encoder is only
 *     deterministic for arrays (see `cbor.ts`), so determinism is a property of the shape.
 *   - FIELD ORDER IS THE WIRE FORMAT. The TBS is slots 0–8; the encoded artifact appends the
 *     signature as slot 9. Reordering is a breaking change to every signature and leaf hash.
 *   - NULLABLE FIELDS ARE AN EXPLICIT CBOR null IN A FIXED SLOT, never omitted, never a sentinel.
 *   - `ext` IS RESERVED (a future co-signature) and MUST be null in v1. Decode rejects anything
 *     else, so a v1 reader can never silently accept a field it does not understand.
 *   - ONE STRICT DECODER. There are no older artifacts; nothing but exactly v1 is accepted.
 */

import { msgLeafHash, verify } from "@cello-protocol/crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import { encodeCbor, decodeCbor } from "./cbor.js";
import { MAX_CONTENT_BYTES } from "./limits.js";

export const BROADCAST_ARTIFACT_DOMAIN = "cello-broadcast-artifact-v1";
export const MAX_BROADCAST_TITLE_CHARS = 200;
export const MAX_BROADCAST_BODY_BYTES = MAX_CONTENT_BYTES; // same ceiling as session content

const PUBKEY_BYTES = 32;
const EPOCH_ROOT_BYTES = 32;
const SIGNATURE_BYTES = 64;
const ENCODED_SLOT_COUNT = 10;

export interface BroadcastArtifact {
  /** Channel identity: 32-byte Ed25519 public key. */
  channel_pubkey: Uint8Array;
  /** Monotonic per-channel sequence number, starting at 1. */
  seq: number;
  /** Which epoch this artifact belongs to, starting at 0. */
  epoch_index: number;
  /** Human/agent-readable title. First-class: digests render it without opening the body. */
  title: string;
  /** Group-key-encrypted body. Opaque bytes at this layer. */
  body_ciphertext: Uint8Array;
  /** Sequence this artifact replaces, or null. Present from v1; semantics minimal. */
  supersedes: number | null;
  /** Previous epoch's sealed root (32 bytes) — non-null ONLY on the first artifact of an
   *  epoch with epoch_index >= 1; null otherwise. */
  prev_epoch_root: Uint8Array | null;
  /** Reserved extension slot (future co-signature). MUST be null in v1; decode rejects
   *  anything else. */
  ext: null;
  /** Ed25519 signature by channel_pubkey over buildBroadcastArtifactTbs(...). */
  signature: Uint8Array;
}

export type BroadcastDecodeReason =
  | "not_cbor" | "wrong_shape" | "wrong_domain" | "bad_channel_pubkey" | "bad_seq"
  | "bad_epoch_index" | "bad_title" | "body_too_large" | "bad_supersedes"
  | "bad_prev_epoch_root" | "ext_not_null" | "bad_signature_shape";

type FieldFailure = { reason: BroadcastDecodeReason; detail: string };

const UNPAIRED_SURROGATE = /\p{Surrogate}/u;
// NUL through US, plus DEL.
const CONTROL_CHARS = /[\u0000-\u001F\u007F]/u;

export function validateBroadcastTitle(
  title: unknown,
): { ok: true } | { ok: false; reason: "bad_title"; detail: string } {
  if (typeof title !== "string") return { ok: false, reason: "bad_title", detail: "title is not a string" };
  if (title.length === 0) return { ok: false, reason: "bad_title", detail: "title is empty" };
  // Code points, not UTF-16 units: "🚨".length is 2.
  const chars = [...title].length;
  if (chars > MAX_BROADCAST_TITLE_CHARS) {
    return { ok: false, reason: "bad_title", detail: `title is ${chars} code points, max ${MAX_BROADCAST_TITLE_CHARS}` };
  }
  if (CONTROL_CHARS.test(title)) return { ok: false, reason: "bad_title", detail: "title contains a control character" };
  // UTF-8 encoding rewrites an unpaired surrogate to U+FFFD, so such a title would sign and then
  // fail verification for every subscriber. Refused here so the signer hears about it instead.
  if (UNPAIRED_SURROGATE.test(title)) {
    return { ok: false, reason: "bad_title", detail: "title contains an unpaired surrogate" };
  }
  return { ok: true };
}

function isBytes(v: unknown, length?: number): v is Uint8Array {
  return v instanceof Uint8Array && (length === undefined || v.length === length);
}

/** Every non-signature field, in wire order. `seq` is checked before `supersedes` reads it. */
function checkFields(a: {
  channel_pubkey: unknown; seq: unknown; epoch_index: unknown; title: unknown;
  body_ciphertext: unknown; supersedes: unknown; prev_epoch_root: unknown; ext: unknown;
}): FieldFailure | null {
  if (!isBytes(a.channel_pubkey, PUBKEY_BYTES)) {
    return { reason: "bad_channel_pubkey", detail: `channel_pubkey must be ${PUBKEY_BYTES} bytes` };
  }
  if (!Number.isSafeInteger(a.seq) || (a.seq as number) < 1) {
    return { reason: "bad_seq", detail: "seq must be a safe integer >= 1" };
  }
  const seq = a.seq as number;
  if (!Number.isSafeInteger(a.epoch_index) || (a.epoch_index as number) < 0) {
    return { reason: "bad_epoch_index", detail: "epoch_index must be a safe integer >= 0" };
  }
  const title = validateBroadcastTitle(a.title);
  if (!title.ok) return { reason: title.reason, detail: title.detail };
  if (!isBytes(a.body_ciphertext) || a.body_ciphertext.length > MAX_BROADCAST_BODY_BYTES) {
    return { reason: "body_too_large", detail: `body_ciphertext must be bytes of at most ${MAX_BROADCAST_BODY_BYTES}` };
  }
  if (a.supersedes !== null) {
    if (!Number.isSafeInteger(a.supersedes) || (a.supersedes as number) < 1 || (a.supersedes as number) >= seq) {
      return { reason: "bad_supersedes", detail: "supersedes must be null or a safe integer with 1 <= supersedes < seq" };
    }
  }
  if (a.prev_epoch_root !== null) {
    if (!isBytes(a.prev_epoch_root, EPOCH_ROOT_BYTES)) {
      return { reason: "bad_prev_epoch_root", detail: `prev_epoch_root must be null or ${EPOCH_ROOT_BYTES} bytes` };
    }
    if (a.epoch_index === 0) {
      return { reason: "bad_prev_epoch_root", detail: "prev_epoch_root must be null when epoch_index is 0" };
    }
  }
  if (a.ext !== null) return { reason: "ext_not_null", detail: "ext is reserved and must be null in v1" };
  return null;
}

function tbsSlots(a: Omit<BroadcastArtifact, "signature">): unknown[] {
  return [
    BROADCAST_ARTIFACT_DOMAIN,
    a.channel_pubkey,
    a.seq,
    a.epoch_index,
    a.title,
    a.body_ciphertext,
    a.supersedes,
    a.prev_epoch_root,
    a.ext,
  ];
}

export function buildBroadcastArtifactTbs(a: Omit<BroadcastArtifact, "signature">): Uint8Array {
  return encodeCbor(tbsSlots(a));
}

export async function signBroadcastArtifact(
  keyProvider: KeyProvider,
  fields: Omit<BroadcastArtifact, "signature" | "channel_pubkey">,
): Promise<BroadcastArtifact> {
  const unsigned: Omit<BroadcastArtifact, "signature"> = {
    channel_pubkey: await keyProvider.getPublicKey(),
    seq: fields.seq,
    epoch_index: fields.epoch_index,
    title: fields.title,
    body_ciphertext: fields.body_ciphertext,
    supersedes: fields.supersedes,
    prev_epoch_root: fields.prev_epoch_root,
    ext: fields.ext,
  };
  const failure = checkFields(unsigned);
  if (failure) throw new RangeError(`${failure.reason}: ${failure.detail}`);
  const signature = await keyProvider.sign(buildBroadcastArtifactTbs(unsigned));
  return { ...unsigned, signature };
}

export function encodeBroadcastArtifact(a: BroadcastArtifact): Uint8Array {
  return encodeCbor([...tbsSlots(a), a.signature]);
}

/** Validates every field and never throws. Does NOT verify the signature — see verifyBroadcastArtifact. */
export function decodeBroadcastArtifact(
  bytes: Uint8Array,
): { ok: true; artifact: BroadcastArtifact } | { ok: false; reason: BroadcastDecodeReason; detail: string } {
  let raw: unknown;
  try {
    raw = decodeCbor(bytes);
  } catch (err) {
    return { ok: false, reason: "not_cbor", detail: err instanceof Error ? err.message : "CBOR decode failed" };
  }
  if (!Array.isArray(raw) || raw.length !== ENCODED_SLOT_COUNT) {
    return { ok: false, reason: "wrong_shape", detail: `expected an array of ${ENCODED_SLOT_COUNT} elements` };
  }
  if (raw[0] !== BROADCAST_ARTIFACT_DOMAIN) {
    return { ok: false, reason: "wrong_domain", detail: `slot 0 must be ${BROADCAST_ARTIFACT_DOMAIN}` };
  }
  const [, channel_pubkey, seq, epoch_index, title, body_ciphertext, supersedes, prev_epoch_root, ext, signature] = raw;
  const failure = checkFields({ channel_pubkey, seq, epoch_index, title, body_ciphertext, supersedes, prev_epoch_root, ext });
  if (failure) return { ok: false, ...failure };
  if (!isBytes(signature, SIGNATURE_BYTES)) {
    return { ok: false, reason: "bad_signature_shape", detail: `signature must be ${SIGNATURE_BYTES} bytes` };
  }
  return {
    ok: true,
    artifact: {
      channel_pubkey: new Uint8Array(channel_pubkey as Uint8Array),
      seq: seq as number,
      epoch_index: epoch_index as number,
      title: title as string,
      body_ciphertext: new Uint8Array(body_ciphertext as Uint8Array),
      supersedes: supersedes as number | null,
      prev_epoch_root: prev_epoch_root === null ? null : new Uint8Array(prev_epoch_root as Uint8Array),
      ext: null,
      signature: new Uint8Array(signature),
    },
  };
}

/** Never throws: crypto's `verify` returns false on any failure. */
export function verifyBroadcastArtifact(a: BroadcastArtifact): boolean {
  return verify(a.channel_pubkey, buildBroadcastArtifactTbs(a), a.signature);
}

/** The leaf commits to the SIGNED artifact, so the channel log commits to exactly what subscribers received. */
export function broadcastArtifactLeafHash(a: BroadcastArtifact): Uint8Array {
  return msgLeafHash(encodeBroadcastArtifact(a));
}
