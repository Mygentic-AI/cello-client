/**
 * CELLO-M7-MSG-001 — Content-delivery wire types.
 *
 * Three families of frames:
 *
 *   1. Delivery ACK (D-c) — on the Noise-authenticated SESSION channel.
 *      Unsigned, transport-authenticated. Levels form an OPEN ladder
 *      (received → persisted → future). The protocol acts on 'persisted' ONLY.
 *
 *   2. Content recovery reverse-channel — on the SESSION channel.
 *      The receiver asks the sender to resend the content behind a known
 *      content_hash (the persisted-ACK channel running in reverse).
 *
 *   3. Park / store-and-forward — on the RELAY channel. The relay holds only
 *      ciphertext (SI-001); every datum gets its own named slot (API parsimony).
 *
 * The application content size cap is the existing MAX_CONTENT_BYTES (1 MB),
 * re-exported from ./envelope.js — a single named constant used at both the send
 * and inbound-decode enforcement points (AC-018). It is strictly below the
 * it-length-prefixed transport default below so the app cap always fires first.
 */

import { createHash } from "node:crypto";

/**
 * The default maximum frame size of it-length-prefixed (`it-length-prefixed`)
 * decoding used by the transport content stream. The application content cap
 * (MAX_CONTENT_BYTES) must stay strictly below this so oversize content is
 * rejected with a clear error before the bare transport decode can fire (SI-003).
 */
export const IT_LENGTH_PREFIX_DEFAULT_MAX = 4 * 1024 * 1024;

/** libp2p protocol id for the relay store-and-forward content-park queue. */
export const CONTENT_PARK_PROTOCOL_ID = "/cello/content-park/1.0.0";

/**
 * Domain separator for the content-park pull/confirm auth signature (I1). The caller
 * signs SHA-256(utf8(CONTENT_PARK_AUTH_DOMAIN) || nonce(32) || recipient_pubkey(32))
 * with its Ed25519 identity key to prove ownership before the relay serves/deletes.
 */
export const CONTENT_PARK_AUTH_DOMAIN = "CELLO-CONTENT-PARK-AUTH-v1";

/**
 * Canonical content-park auth message: SHA-256( utf8(CONTENT_PARK_AUTH_DOMAIN) ||
 * nonce(32) || recipient_pubkey(32) ). Single source of truth for BOTH the client
 * (signs this with its identity key on pull/confirm) and the relay (verifies it). If
 * this construction ever drifts between the two repos, pull/confirm auth silently
 * breaks — so both sides import this one function (M1: no per-repo redeclaration).
 */
export function buildContentParkAuthMsg(nonce: Uint8Array, recipientPubkey: Uint8Array): Uint8Array {
  const domain = new TextEncoder().encode(CONTENT_PARK_AUTH_DOMAIN);
  const msg = new Uint8Array(domain.length + nonce.length + recipientPubkey.length);
  msg.set(domain, 0);
  msg.set(nonce, domain.length);
  msg.set(recipientPubkey, domain.length + nonce.length);
  return new Uint8Array(createHash("sha256").update(msg).digest());
}

// ─── 1. Delivery ACK (D-c) ──────────────────────────────────────────────────

/**
 * Delivery-ACK ladder level. OPEN enum: 'received' and 'persisted' are defined
 * today; future levels can be added without a wire break. The protocol acts on
 * 'persisted' ONLY (AC-002). The string-template member keeps the union open.
 */
export type ContentAckLevel = "received" | "persisted" | (string & {});

/**
 * Unsigned delivery ACK emitted by the receiver AFTER it durably persists the
 * content AND its content_hash cross-check succeeds. Carries NO signature —
 * authentication is the Noise session channel (D-c, SI-004). Never an input to
 * the seal, the Merkle tree, or last_seen_seq.
 */
export interface ContentDeliveryAck {
  type: "content_delivery_ack";
  /** Session identifier (raw bytes as carried on the session channel). */
  session_id: Uint8Array;
  /** SHA-256 content hash this ACK acknowledges (32 bytes). */
  content_hash: Uint8Array;
  /** Ladder level; the sender acts on 'persisted' only. */
  level: ContentAckLevel;
}

// ─── 2. Content recovery reverse-channel ────────────────────────────────────

/**
 * Receiver → sender resend request over the session channel. The receiver drained
 * a hash leaf but never got the matching content; it asks the sender to resend
 * the content behind content_hash. Recovery, not desync (AC-009).
 */
export interface ContentResendRequest {
  type: "content_resend_request";
  session_id: Uint8Array;
  content_hash: Uint8Array;
}

// ─── 3. Park / store-and-forward (relay channel) ────────────────────────────

/**
 * Sender → relay: deposit ENCRYPTED content into the recipient-keyed
 * store-and-forward queue. The relay holds only ciphertext (SI-001).
 */
export interface ContentParkDeposit {
  type: "content_park_deposit";
  /** Recipient's stable identity pubkey — the store key (32 bytes). */
  recipient_pubkey: Uint8Array;
  /** SHA-256 hash of the PLAINTEXT content (the relay already sees the hash layer). */
  content_hash: Uint8Array;
  /** Session this content belongs to (so the recipient can route it on pull). */
  session_id: Uint8Array;
  /** The sealed (E2E-encrypted) content blob. Its own named slot — never buried. */
  ciphertext: Uint8Array;
}

/** Relay → sender: deposit confirmation / failure. */
export interface ContentParkDepositAck {
  type: "content_park_deposit_ack";
  content_hash: Uint8Array;
  ok: boolean;
  /** Present only when ok === false. */
  reason?: string;
}

/**
 * Relay → recipient: a notification that parked content is available. Fires when
 * an online (or newly-reconnected) recipient has entries in its queue.
 */
export interface ContentParkNotify {
  type: "content_park_notify";
  recipient_pubkey: Uint8Array;
  content_hash: Uint8Array;
}

/**
 * Recipient → relay: pull request. When content_hash is omitted the relay returns
 * all parked entries for the recipient; when present it returns that one entry.
 */
export interface ContentParkPullRequest {
  type: "content_park_pull_request";
  recipient_pubkey: Uint8Array;
  content_hash?: Uint8Array;
}

/**
 * Relay → recipient: a single parked entry (ciphertext). `found` is false when no
 * matching entry exists (recovery falls back to "never parked"). delete-on-pickup
 * happens after the recipient confirms a successful cross-check.
 */
export interface ContentParkPullResponse {
  type: "content_park_pull_response";
  found: boolean;
  content_hash: Uint8Array;
  session_id?: Uint8Array;
  ciphertext?: Uint8Array;
}

// ─── Type guards ────────────────────────────────────────────────────────────

function hasBytes(v: unknown): v is Uint8Array {
  return v instanceof Uint8Array || (typeof Buffer !== "undefined" && Buffer.isBuffer(v));
}

export function isContentDeliveryAck(frame: unknown): frame is ContentDeliveryAck {
  if (frame === null || typeof frame !== "object") return false;
  const f = frame as Record<string, unknown>;
  return (
    f["type"] === "content_delivery_ack" &&
    hasBytes(f["session_id"]) &&
    hasBytes(f["content_hash"]) &&
    typeof f["level"] === "string"
  );
}

export function isContentResendRequest(frame: unknown): frame is ContentResendRequest {
  if (frame === null || typeof frame !== "object") return false;
  const f = frame as Record<string, unknown>;
  return (
    f["type"] === "content_resend_request" &&
    hasBytes(f["session_id"]) &&
    hasBytes(f["content_hash"])
  );
}

export function isContentParkDeposit(frame: unknown): frame is ContentParkDeposit {
  if (frame === null || typeof frame !== "object") return false;
  const f = frame as Record<string, unknown>;
  return (
    f["type"] === "content_park_deposit" &&
    hasBytes(f["recipient_pubkey"]) &&
    hasBytes(f["content_hash"]) &&
    hasBytes(f["ciphertext"])
  );
}
