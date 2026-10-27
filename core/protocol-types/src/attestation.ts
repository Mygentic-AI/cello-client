/**
 * M10E / M10E-RECORDS-1 — the attestation ("review") records, as canonical fixed-order CBOR arrays.
 *
 * Every later order (directory, portal, daemon) passes these records around and hashes them, and two
 * parties must ALWAYS compute the same hash from the same record. So they are defined ONCE, here, the
 * same way the trust-signal envelope is in `trust-signal.ts`: a fixed-order CBOR array whose element 0
 * is a domain string, with every optional field present as an explicit `null`.
 *
 * The rules that make the hash reproducible across implementations, all enforced below:
 *   - FIELD ORDER IS THE WIRE FORMAT. Reordering an array is a breaking hash change, not a refactor.
 *   - Optional fields are an explicit `null` in a fixed slot, never omitted (arity is constant).
 *   - Timestamps are integer epoch SECONDS; integers above 2^32 cross CBOR as BigInt so they never
 *     encode as float64 (see `asCborInteger`).
 *   - Strings must already be NFC; a non-NFC string is REFUSED, never normalized — silently
 *     normalizing would make two different inputs hash to one record.
 *   - The field set is CLOSED: an unknown key is rejected, never ignored.
 *
 * Pure functions, no I/O, no new dependencies.
 */

import { hash as sha256 } from "@cello-protocol/crypto";
import { encodeCbor, decodeCbor } from "./cbor.js";

export type AttestationRecordErrorCode =
  | "bad_shape" | "wrong_domain" | "unknown_field" | "bad_pubkey" | "not_nfc" | "bad_bytes"
  | "bad_namespace" | "bad_mode" | "bad_template" | "bad_ttl" | "bad_condition" | "bad_text"
  | "bad_rating" | "bad_time" | "self_reference" | "bad_count";

export class AttestationRecordError extends Error {
  constructor(readonly code: AttestationRecordErrorCode, message: string) {
    super(`attestation record: ${code}: ${message}`);
    this.name = "AttestationRecordError";
  }
}

const fail = (code: AttestationRecordErrorCode, message: string): never => {
  throw new AttestationRecordError(code, message);
};

// ── shared field validators ────────────────────────────────────────────────────────────────────

/** cbor-x emits any JS `number` above 0xffffffff as float64; a BigInt crosses as uint64, which is
 *  what every conforming CBOR implementation does. Local copy on purpose — trust-signal.ts does not
 *  export it, and coupling the two would let a change to one silently move the other's wire format. */
const CBOR_UINT32_MAX = 0xffff_ffff;
const asCborInteger = (value: number): number | bigint => (value > CBOR_UINT32_MAX ? BigInt(value) : value);

const TTL_MIN_S = 604_800; // 7 days
const TTL_MAX_S = 15_552_000; // 180 days
const MAX_CONDITION_CODE_POINTS = 280;
const TEMPLATE_TEXT_MAX_CODE_POINTS = 500;

const requirePubkey = (name: string, value: unknown): string => {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    return fail("bad_pubkey", `${name} must be a lowercase 64-hex pubkey, got ${String(value)}`);
  }
  return value;
};

const requirePubkeyOrNull = (name: string, value: unknown): string | null =>
  value === null ? null : requirePubkey(name, value);

const requireBytes = (name: string, value: unknown, len: number): Uint8Array => {
  if (!(value instanceof Uint8Array) || value.length !== len) {
    return fail("bad_bytes", `${name} must be ${len} bytes, got ${value instanceof Uint8Array ? `${value.length} bytes` : typeof value}`);
  }
  return value;
};

/** Integer epoch seconds, ≥ 0. Floats, NaN, Infinity and values past MAX_SAFE_INTEGER are refused:
 *  past 2^53 the value meant and the value hashed may already differ. */
const requireTimestamp = (name: string, value: unknown): number | bigint => {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER) {
    return fail("bad_time", `${name} must be a non-negative integer epoch-seconds value, got ${String(value)}`);
  }
  return asCborInteger(value);
};

const requireCount = (name: string, value: unknown): number | bigint => {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER) {
    return fail("bad_count", `${name} must be a non-negative integer, got ${String(value)}`);
  }
  return asCborInteger(value);
};

const requireTtl = (name: string, value: unknown): number => {
  if (typeof value !== "number" || !Number.isInteger(value) || value < TTL_MIN_S || value > TTL_MAX_S) {
    return fail("bad_ttl", `${name} must be an integer ${TTL_MIN_S}..${TTL_MAX_S} seconds (7 to 180 days), got ${String(value)}`);
  }
  return value;
};

/** 1 to 3 segments joined by `.`; each segment /^[a-z0-9_]{1,32}$/. Wildcards and empty segments refused. */
const requireNamespace = (value: unknown): string => {
  if (typeof value !== "string") return fail("bad_namespace", `namespace must be a string, got ${typeof value}`);
  const segs = value.split(".");
  if (segs.length < 1 || segs.length > 3) return fail("bad_namespace", `namespace must have 1 to 3 segments, got ${segs.length}`);
  for (const s of segs) {
    if (!/^[a-z0-9_]{1,32}$/.test(s)) return fail("bad_namespace", `namespace segment "${s}" must match [a-z0-9_]{1,32}`);
  }
  return value;
};

const requireMode = (value: unknown): "public" | "private" => {
  if (value !== "public" && value !== "private") return fail("bad_mode", `mode must be "public" or "private", got ${String(value)}`);
  return value;
};

/** Condition: NFC, 1 to 280 code points. Length violations → bad_condition; non-NFC → not_nfc
 *  (the shared string rule governs normalization for every field). */
const requireCondition = (value: unknown): string => {
  if (typeof value !== "string") return fail("bad_condition", `condition must be a string, got ${typeof value}`);
  const cp = [...value].length;
  if (cp < 1 || cp > MAX_CONDITION_CODE_POINTS) {
    return fail("bad_condition", `condition must be 1 to ${MAX_CONDITION_CODE_POINTS} code points, got ${cp}`);
  }
  if (value.normalize("NFC") !== value) return fail("not_nfc", `condition must already be Unicode NFC`);
  return value;
};

// ── templates ───────────────────────────────────────────────────────────────────────────────────

export type AttestationTemplateId = "text" | "scored";
export const ATTESTATION_TEMPLATE_DOMAIN = "CELLO-ATPL-v1";

// The template DEFINITIONS, hashed. Field order is the payload body order.
const TEMPLATE_DEFS: Record<AttestationTemplateId, unknown[]> = {
  text: [ATTESTATION_TEMPLATE_DOMAIN, "text", 1, [["text", "string", 1, 500]]],
  scored: [ATTESTATION_TEMPLATE_DOMAIN, "scored", 1, [["rating_1_low_5_high", "int", 1, 5], ["text", "string", 1, 500]]],
};

const TEMPLATE_HASHES: Record<AttestationTemplateId, Uint8Array> = {
  text: sha256(encodeCbor(TEMPLATE_DEFS.text)),
  scored: sha256(encodeCbor(TEMPLATE_DEFS.scored)),
};

/** sha256(encodeCbor(def)) for the given template. */
export function attestationTemplateHash(id: AttestationTemplateId): Uint8Array {
  return new Uint8Array(TEMPLATE_HASHES[id]);
}

const ctEq = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
};

/** Which template a 32-byte hash denotes, or null. Constant-time compare against each known template. */
export function templateIdForHash(hash: Uint8Array): AttestationTemplateId | null {
  let found: AttestationTemplateId | null = null;
  for (const id of ["text", "scored"] as const) {
    if (ctEq(hash, TEMPLATE_HASHES[id])) found = id;
  }
  return found;
}

const requireKnownTemplateHash = (name: string, value: unknown): Uint8Array => {
  const bytes = requireBytes(name, value, 32);
  if (templateIdForHash(bytes) === null) return fail("bad_template", `${name} is not a known template hash`);
  return bytes;
};

/** Template text field: 1 to 500 code points, NFC. Length → bad_text; non-NFC → not_nfc. */
const requireTemplateText = (value: unknown): string => {
  if (typeof value !== "string") return fail("bad_text", `text must be a string, got ${value === null ? "null" : typeof value}`);
  const cp = [...value].length;
  if (cp < 1 || cp > TEMPLATE_TEXT_MAX_CODE_POINTS) return fail("bad_text", `text must be 1 to ${TEMPLATE_TEXT_MAX_CODE_POINTS} code points, got ${cp}`);
  if (value.normalize("NFC") !== value) return fail("not_nfc", `text must already be Unicode NFC`);
  return value;
};

/** Rating: integer 1 to 5. `null` and floats are refused — an optional score is skipped exactly on
 *  the reviews where it matters. */
const requireRating = (value: unknown): number => {
  const v = typeof value === "bigint" ? Number(value) : value;
  if (typeof v !== "number" || !Number.isInteger(v) || v < 1 || v > 5) {
    return fail("bad_rating", `rating must be an integer 1 to 5, got ${String(value)}`);
  }
  return v;
};

/** The payload body, validated against the template its hash denotes. Returns the validated array. */
const validateBody = (templateHash: Uint8Array, body: unknown): unknown[] => {
  const id = templateIdForHash(templateHash);
  if (id === null) return fail("bad_template", `payload template_hash is not a known template`);
  if (!Array.isArray(body)) return fail("bad_shape", `payload body must be an array, got ${typeof body}`);
  if (id === "text") {
    if (body.length !== 1) return fail("bad_shape", `text template body must have 1 field, got ${body.length}`);
    return [requireTemplateText(body[0])];
  }
  if (body.length !== 2) return fail("bad_shape", `scored template body must have 2 fields, got ${body.length}`);
  return [requireRating(body[0]), requireTemplateText(body[1])];
};

// ── closed-set key check ───────────────────────────────────────────────────────────────────────

const checkKeys = (record: unknown, keys: readonly string[]): void => {
  if (record === null || typeof record !== "object") fail("bad_shape", `expected a record object, got ${String(record)}`);
  const known = new Set<string>(keys);
  for (const key of Object.keys(record as object)) {
    if (!known.has(key)) fail("unknown_field", `unknown field "${key}" — the record field set is closed`);
  }
};

// ── records ──────────────────────────────────────────────────────────────────────────────────────

export const ATTESTATION_NAMESPACE_DOMAIN = "CELLO-ANS-v1";
export const ATTESTATION_NAMESPACE_CLOSE_DOMAIN = "CELLO-ANSCLOSE-v1";
export const SERVICE_EVENT_DOMAIN = "CELLO-ASVC-v1";
export const ATTESTATION_RIGHT_DOMAIN = "CELLO-ARIGHT-v1";
export const ATTESTATION_PAYLOAD_DOMAIN = "CELLO-ATT-v1";
export const SERVICE_RECEIVED_CLAIM_DOMAIN = "CELLO-ASRC-v1";
export const ATTESTATION_HEAD_DOMAIN = "CELLO-AHEAD-v1";

/** The trust-signal envelope `type` an attestation travels under. */
export const ATTESTATION_SIGNAL_TYPE = "attestation";

export interface AttestationNamespace {
  owner_pubkey: string;
  namespace: string;
  mode: "public" | "private";
  template_hash: Uint8Array;
  right_ttl_s: number;
  condition: string;
  created_at: number;
}

export interface AttestationNamespaceClose {
  owner_pubkey: string;
  namespace: string;
  closed_at: number;
}

export interface ServiceEvent {
  session_id: Uint8Array;
  subject_pubkey: string;
  namespace: string;
  counterparty_pubkey: string;
  chain_head_hash: Uint8Array;
  marked_at: number;
  origin_channel: string | null;
}

export interface AttestationRight {
  service_event_hash: Uint8Array;
  holder_pubkey: string;
  subject_pubkey: string;
  namespace: string;
  template_hash: Uint8Array;
  session_id: Uint8Array;
  created_at: number;
  expires_at: number;
  kind: "service_event";
}

export interface AttestationPayload {
  right_id: Uint8Array;
  namespace: string;
  template_hash: Uint8Array;
  session_id: Uint8Array;
  origin_channel: string | null;
  body: unknown[];
}

export interface ServiceReceivedClaim {
  session_id: Uint8Array;
  claimant_pubkey: string;
  subject_pubkey: string;
  namespace: string;
  claimed_at: number;
}

export interface AttestationHead {
  subject_pubkey: string;
  namespace: string;
  count: number;
  merkle_root: Uint8Array;
  sum_of_ratings: number;
  removed_count: number;
  suspended_count: number;
  service_events: number;
  unmarked_claims: number;
  as_of: number;
}

// Preimage builders: validate the record and return the fixed-order array (element 0 = domain).

const NAMESPACE_KEYS = ["owner_pubkey", "namespace", "mode", "template_hash", "right_ttl_s", "condition", "created_at"] as const;
function namespacePreimage(r: AttestationNamespace): unknown[] {
  checkKeys(r, NAMESPACE_KEYS);
  return [
    ATTESTATION_NAMESPACE_DOMAIN,
    requirePubkey("owner_pubkey", r.owner_pubkey),
    requireNamespace(r.namespace),
    requireMode(r.mode),
    requireKnownTemplateHash("template_hash", r.template_hash),
    requireTtl("right_ttl_s", r.right_ttl_s),
    requireCondition(r.condition),
    requireTimestamp("created_at", r.created_at),
  ];
}

const NAMESPACE_CLOSE_KEYS = ["owner_pubkey", "namespace", "closed_at"] as const;
function namespaceClosePreimage(r: AttestationNamespaceClose): unknown[] {
  checkKeys(r, NAMESPACE_CLOSE_KEYS);
  return [
    ATTESTATION_NAMESPACE_CLOSE_DOMAIN,
    requirePubkey("owner_pubkey", r.owner_pubkey),
    requireNamespace(r.namespace),
    requireTimestamp("closed_at", r.closed_at),
  ];
}

const SERVICE_EVENT_KEYS = ["session_id", "subject_pubkey", "namespace", "counterparty_pubkey", "chain_head_hash", "marked_at", "origin_channel"] as const;
function serviceEventPreimage(r: ServiceEvent): unknown[] {
  checkKeys(r, SERVICE_EVENT_KEYS);
  const subject = requirePubkey("subject_pubkey", r.subject_pubkey);
  const counterparty = requirePubkey("counterparty_pubkey", r.counterparty_pubkey);
  if (counterparty === subject) fail("self_reference", "counterparty_pubkey must differ from subject_pubkey");
  return [
    SERVICE_EVENT_DOMAIN,
    requireBytes("session_id", r.session_id, 16),
    subject,
    requireNamespace(r.namespace),
    counterparty,
    requireBytes("chain_head_hash", r.chain_head_hash, 32),
    requireTimestamp("marked_at", r.marked_at),
    requirePubkeyOrNull("origin_channel", r.origin_channel),
  ];
}

const RIGHT_KEYS = ["service_event_hash", "holder_pubkey", "subject_pubkey", "namespace", "template_hash", "session_id", "created_at", "expires_at", "kind"] as const;
function rightPreimage(r: AttestationRight): unknown[] {
  checkKeys(r, RIGHT_KEYS);
  const holder = requirePubkey("holder_pubkey", r.holder_pubkey);
  const subject = requirePubkey("subject_pubkey", r.subject_pubkey);
  if (holder === subject) fail("self_reference", "holder_pubkey must differ from subject_pubkey");
  const created = requireTimestamp("created_at", r.created_at);
  const expires = requireTimestamp("expires_at", r.expires_at);
  const delta = Number(expires) - Number(created);
  if (delta < TTL_MIN_S || delta > TTL_MAX_S) {
    fail("bad_ttl", `expires_at - created_at must be ${TTL_MIN_S}..${TTL_MAX_S} seconds, got ${delta}`);
  }
  if (r.kind !== "service_event") fail("bad_shape", `kind must be "service_event" in v1, got ${String(r.kind)}`);
  return [
    ATTESTATION_RIGHT_DOMAIN,
    requireBytes("service_event_hash", r.service_event_hash, 32),
    holder,
    subject,
    requireNamespace(r.namespace),
    requireKnownTemplateHash("template_hash", r.template_hash),
    requireBytes("session_id", r.session_id, 16),
    created,
    expires,
    r.kind,
  ];
}

const PAYLOAD_KEYS = ["right_id", "namespace", "template_hash", "session_id", "origin_channel", "body"] as const;
function payloadPreimage(r: AttestationPayload): unknown[] {
  checkKeys(r, PAYLOAD_KEYS);
  const templateHash = requireKnownTemplateHash("template_hash", r.template_hash);
  return [
    ATTESTATION_PAYLOAD_DOMAIN,
    requireBytes("right_id", r.right_id, 32),
    requireNamespace(r.namespace),
    templateHash,
    requireBytes("session_id", r.session_id, 16),
    requirePubkeyOrNull("origin_channel", r.origin_channel),
    validateBody(templateHash, r.body),
  ];
}

const CLAIM_KEYS = ["session_id", "claimant_pubkey", "subject_pubkey", "namespace", "claimed_at"] as const;
function claimPreimage(r: ServiceReceivedClaim): unknown[] {
  checkKeys(r, CLAIM_KEYS);
  const claimant = requirePubkey("claimant_pubkey", r.claimant_pubkey);
  const subject = requirePubkey("subject_pubkey", r.subject_pubkey);
  if (claimant === subject) fail("self_reference", "claimant_pubkey must differ from subject_pubkey");
  return [
    SERVICE_RECEIVED_CLAIM_DOMAIN,
    requireBytes("session_id", r.session_id, 16),
    claimant,
    subject,
    requireNamespace(r.namespace),
    requireTimestamp("claimed_at", r.claimed_at),
  ];
}

const HEAD_KEYS = ["subject_pubkey", "namespace", "count", "merkle_root", "sum_of_ratings", "removed_count", "suspended_count", "service_events", "unmarked_claims", "as_of"] as const;
function headPreimage(r: AttestationHead): unknown[] {
  checkKeys(r, HEAD_KEYS);
  const count = requireCount("count", r.count);
  const sum = requireCount("sum_of_ratings", r.sum_of_ratings);
  if (Number(sum) > 5 * Number(count)) fail("bad_count", `sum_of_ratings (${Number(sum)}) exceeds 5 * count (${5 * Number(count)})`);
  return [
    ATTESTATION_HEAD_DOMAIN,
    requirePubkey("subject_pubkey", r.subject_pubkey),
    requireNamespace(r.namespace),
    count,
    requireBytes("merkle_root", r.merkle_root, 32),
    sum,
    requireCount("removed_count", r.removed_count),
    requireCount("suspended_count", r.suspended_count),
    requireCount("service_events", r.service_events),
    requireCount("unmarked_claims", r.unmarked_claims),
    requireTimestamp("as_of", r.as_of),
  ];
}

// ── decode helpers ───────────────────────────────────────────────────────────────────────────────

const decodeArray = (bytes: Uint8Array, domain: string, len: number): unknown[] => {
  const arr = decodeCbor(bytes);
  if (!Array.isArray(arr) || arr.length !== len) {
    return fail("bad_shape", `expected a ${len}-element CBOR array, got ${Array.isArray(arr) ? `${arr.length} elements` : typeof arr}`);
  }
  if (arr[0] !== domain) return fail("wrong_domain", `domain is ${String(arr[0])}, expected ${domain}`);
  return arr;
};

/** Normalize a decoded byte string to a plain, owned Uint8Array (node returns a pooled Buffer). */
const toBytes = (v: unknown): Uint8Array => (v instanceof Uint8Array ? new Uint8Array(v) : (v as Uint8Array));
/** Coerce a decoded integer that cbor-x may have returned as bigint back to number for validation. */
const toNum = (v: unknown): number => (typeof v === "bigint" ? Number(v) : (v as number));

// ── per-type encode / decode / hash ───────────────────────────────────────────────────────────────

export function encodeAttestationNamespace(r: AttestationNamespace): Uint8Array { return encodeCbor(namespacePreimage(r)); }
export function hashAttestationNamespace(r: AttestationNamespace): Uint8Array { return sha256(encodeAttestationNamespace(r)); }
export function decodeAttestationNamespace(bytes: Uint8Array): AttestationNamespace {
  const a = decodeArray(bytes, ATTESTATION_NAMESPACE_DOMAIN, 8);
  const r: AttestationNamespace = {
    owner_pubkey: a[1] as string,
    namespace: a[2] as string,
    mode: a[3] as "public" | "private",
    template_hash: toBytes(a[4]),
    right_ttl_s: toNum(a[5]),
    condition: a[6] as string,
    created_at: toNum(a[7]),
  };
  namespacePreimage(r);
  return r;
}

export function encodeAttestationNamespaceClose(r: AttestationNamespaceClose): Uint8Array { return encodeCbor(namespaceClosePreimage(r)); }
export function hashAttestationNamespaceClose(r: AttestationNamespaceClose): Uint8Array { return sha256(encodeAttestationNamespaceClose(r)); }
export function decodeAttestationNamespaceClose(bytes: Uint8Array): AttestationNamespaceClose {
  const a = decodeArray(bytes, ATTESTATION_NAMESPACE_CLOSE_DOMAIN, 4);
  const r: AttestationNamespaceClose = {
    owner_pubkey: a[1] as string,
    namespace: a[2] as string,
    closed_at: toNum(a[3]),
  };
  namespaceClosePreimage(r);
  return r;
}

export function encodeServiceEvent(r: ServiceEvent): Uint8Array { return encodeCbor(serviceEventPreimage(r)); }
export function hashServiceEvent(r: ServiceEvent): Uint8Array { return sha256(encodeServiceEvent(r)); }
export function decodeServiceEvent(bytes: Uint8Array): ServiceEvent {
  const a = decodeArray(bytes, SERVICE_EVENT_DOMAIN, 8);
  const r: ServiceEvent = {
    session_id: toBytes(a[1]),
    subject_pubkey: a[2] as string,
    namespace: a[3] as string,
    counterparty_pubkey: a[4] as string,
    chain_head_hash: toBytes(a[5]),
    marked_at: toNum(a[6]),
    origin_channel: a[7] === null ? null : (a[7] as string),
  };
  serviceEventPreimage(r);
  return r;
}

export function encodeAttestationRight(r: AttestationRight): Uint8Array { return encodeCbor(rightPreimage(r)); }
export function hashAttestationRight(r: AttestationRight): Uint8Array { return sha256(encodeAttestationRight(r)); }
export function decodeAttestationRight(bytes: Uint8Array): AttestationRight {
  const a = decodeArray(bytes, ATTESTATION_RIGHT_DOMAIN, 10);
  const r: AttestationRight = {
    service_event_hash: toBytes(a[1]),
    holder_pubkey: a[2] as string,
    subject_pubkey: a[3] as string,
    namespace: a[4] as string,
    template_hash: toBytes(a[5]),
    session_id: toBytes(a[6]),
    created_at: toNum(a[7]),
    expires_at: toNum(a[8]),
    kind: a[9] as "service_event",
  };
  rightPreimage(r);
  return r;
}

export function encodeAttestationPayload(r: AttestationPayload): Uint8Array { return encodeCbor(payloadPreimage(r)); }
export function hashAttestationPayload(r: AttestationPayload): Uint8Array { return sha256(encodeAttestationPayload(r)); }
export function decodeAttestationPayload(bytes: Uint8Array): AttestationPayload {
  const a = decodeArray(bytes, ATTESTATION_PAYLOAD_DOMAIN, 7);
  const r: AttestationPayload = {
    right_id: toBytes(a[1]),
    namespace: a[2] as string,
    template_hash: toBytes(a[3]),
    session_id: toBytes(a[4]),
    origin_channel: a[5] === null ? null : (a[5] as string),
    body: a[6] as unknown[],
  };
  payloadPreimage(r);
  return r;
}

export function encodeServiceReceivedClaim(r: ServiceReceivedClaim): Uint8Array { return encodeCbor(claimPreimage(r)); }
export function hashServiceReceivedClaim(r: ServiceReceivedClaim): Uint8Array { return sha256(encodeServiceReceivedClaim(r)); }
export function decodeServiceReceivedClaim(bytes: Uint8Array): ServiceReceivedClaim {
  const a = decodeArray(bytes, SERVICE_RECEIVED_CLAIM_DOMAIN, 6);
  const r: ServiceReceivedClaim = {
    session_id: toBytes(a[1]),
    claimant_pubkey: a[2] as string,
    subject_pubkey: a[3] as string,
    namespace: a[4] as string,
    claimed_at: toNum(a[5]),
  };
  claimPreimage(r);
  return r;
}

export function encodeAttestationHead(r: AttestationHead): Uint8Array { return encodeCbor(headPreimage(r)); }
export function hashAttestationHead(r: AttestationHead): Uint8Array { return sha256(encodeAttestationHead(r)); }
export function decodeAttestationHead(bytes: Uint8Array): AttestationHead {
  const a = decodeArray(bytes, ATTESTATION_HEAD_DOMAIN, 11);
  const r: AttestationHead = {
    subject_pubkey: a[1] as string,
    namespace: a[2] as string,
    count: toNum(a[3]),
    merkle_root: toBytes(a[4]),
    sum_of_ratings: toNum(a[5]),
    removed_count: toNum(a[6]),
    suspended_count: toNum(a[7]),
    service_events: toNum(a[8]),
    unmarked_claims: toNum(a[9]),
    as_of: toNum(a[10]),
  };
  headPreimage(r);
  return r;
}

/** right_id is the hash of the right. One name for one fact. */
export function rightId(r: AttestationRight): Uint8Array { return hashAttestationRight(r); }
