/**
 * M16 046-JOINBELL — the channel relay record the DIRECTORY holds.
 *
 * Before admission a joiner knows only the channel key. The admin's daemon publishes this record to
 * the directory (and renews it on any relay change): the channel key, its relay list and a signed
 * time, signed by the CHANNEL key. The directory verifies it, keeps the newest by signed time,
 * replicates it, and hands it back from the channel lookup — by channel key only; there is no list
 * or search. The joiner then reads access, guidance, retention and posting from the channel's info
 * record on those relays.
 *
 * Wire: a CBOR MAP, with room for the discovery fields (name, description, tags, …). Until discovery
 * ships, a record that sets ANY of them is refused — nothing reads them.
 */
import { verify } from "@cello-protocol/crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import { encodeCbor, decodeCbor } from "./cbor.js";

export const CHANNEL_RELAY_RECORD_DOMAIN = "cello-channel-relays-v1";
export const MAX_RELAY_RECORD_RELAYS = 8;
const MAX_RELAY_CHARS = 512;
/** The largest record the directory accepts, checked before decode. */
export const MAX_RELAY_RECORD_BYTES = 8 * 1024;

/** Reserved for discovery. A record that sets any of these is refused until discovery ships. */
export const CHANNEL_DISCOVERY_KEYS = [
  "discoverable", "name", "description", "tags", "access", "language", "discoverable_at", "discovery_expires_at",
] as const;

const RECORD_KEYS = ["domain", "channel_pubkey", "relays", "signed_at", "signature"] as const;

export interface ChannelRelayRecord {
  channel_pubkey: Uint8Array;
  relays: string[];
  /** ms. The directory keeps the newest. */
  signed_at: number;
  /** Ed25519 by the CHANNEL key over the TBS. */
  signature: Uint8Array;
}

export type ChannelRelayRecordDecodeReason =
  | "not_cbor" | "too_large" | "wrong_shape" | "wrong_domain" | "discovery_not_supported"
  | "bad_channel_pubkey" | "bad_relays" | "bad_signed_at" | "bad_signature_shape";

type Failure = { ok: false; reason: ChannelRelayRecordDecodeReason; detail: string };

function isBytes(v: unknown, length?: number): v is Uint8Array {
  return v instanceof Uint8Array && (length === undefined || v.length === length);
}

function badRelays(v: unknown): boolean {
  return !Array.isArray(v) || v.length === 0 || v.length > MAX_RELAY_RECORD_RELAYS
    || !v.every((r) => typeof r === "string" && r.length > 0 && [...r].length <= MAX_RELAY_CHARS);
}

function tbs(r: Omit<ChannelRelayRecord, "signature">): Uint8Array {
  return encodeCbor([CHANNEL_RELAY_RECORD_DOMAIN, r.channel_pubkey, r.relays, r.signed_at]);
}

/** Sign with the CHANNEL key; the channel pubkey is read from the provider, never accepted. */
export async function signChannelRelayRecord(
  channelKey: KeyProvider, f: { relays: string[]; signed_at: number },
): Promise<ChannelRelayRecord> {
  if (badRelays(f.relays)) throw new RangeError(`bad_relays: 1 to ${String(MAX_RELAY_RECORD_RELAYS)} non-empty relay addresses`);
  if (!Number.isSafeInteger(f.signed_at) || f.signed_at < 1) throw new RangeError("bad_signed_at: a safe integer >= 1 (ms)");
  const unsigned = { channel_pubkey: await channelKey.getPublicKey(), relays: [...f.relays], signed_at: f.signed_at };
  return { ...unsigned, signature: await channelKey.sign(tbs(unsigned)) };
}

export function encodeChannelRelayRecord(r: ChannelRelayRecord): Uint8Array {
  return encodeCbor({
    domain: CHANNEL_RELAY_RECORD_DOMAIN, channel_pubkey: r.channel_pubkey, relays: r.relays,
    signed_at: r.signed_at, signature: r.signature,
  });
}

/** Validates every field and never throws. Does NOT verify the signature. */
export function decodeChannelRelayRecord(bytes: Uint8Array): { ok: true; record: ChannelRelayRecord } | Failure {
  if (bytes.length > MAX_RELAY_RECORD_BYTES) return { ok: false, reason: "too_large", detail: `at most ${String(MAX_RELAY_RECORD_BYTES)} bytes` };
  let raw: unknown;
  try {
    raw = decodeCbor(bytes);
  } catch (err) {
    return { ok: false, reason: "not_cbor", detail: err instanceof Error ? err.message : "CBOR decode failed" };
  }
  if (raw === null || typeof raw !== "object" || Array.isArray(raw) || raw instanceof Uint8Array) {
    return { ok: false, reason: "wrong_shape", detail: "expected a CBOR map" };
  }
  const map = raw as Record<string, unknown>;
  const keys = Object.keys(map);
  if (keys.some((k) => (CHANNEL_DISCOVERY_KEYS as readonly string[]).includes(k))) {
    return { ok: false, reason: "discovery_not_supported", detail: "discovery fields are refused until discovery ships" };
  }
  if (keys.length !== RECORD_KEYS.length || !RECORD_KEYS.every((k) => k in map)) {
    return { ok: false, reason: "wrong_shape", detail: `exactly the keys ${RECORD_KEYS.join(", ")}` };
  }
  if (map["domain"] !== CHANNEL_RELAY_RECORD_DOMAIN) return { ok: false, reason: "wrong_domain", detail: `domain must be ${CHANNEL_RELAY_RECORD_DOMAIN}` };
  const { channel_pubkey, relays, signed_at, signature } = map;
  if (!isBytes(channel_pubkey, 32)) return { ok: false, reason: "bad_channel_pubkey", detail: "must be 32 bytes" };
  if (badRelays(relays)) return { ok: false, reason: "bad_relays", detail: `1 to ${String(MAX_RELAY_RECORD_RELAYS)} relay addresses` };
  if (!Number.isSafeInteger(signed_at) || (signed_at as number) < 1) return { ok: false, reason: "bad_signed_at", detail: "a safe integer >= 1 (ms)" };
  if (!isBytes(signature, 64)) return { ok: false, reason: "bad_signature_shape", detail: "must be 64 bytes" };
  const record: ChannelRelayRecord = {
    channel_pubkey: new Uint8Array(channel_pubkey), relays: [...(relays as string[])],
    signed_at: signed_at as number, signature: new Uint8Array(signature),
  };
  if (!Buffer.from(encodeChannelRelayRecord(record)).equals(Buffer.from(bytes))) {
    return { ok: false, reason: "wrong_shape", detail: "non-canonical encoding" };
  }
  return { ok: true, record };
}

/** Signed by the channel key the record names. */
export function verifyChannelRelayRecord(r: ChannelRelayRecord): boolean {
  return verify(r.channel_pubkey, tbs(r), r.signature);
}
