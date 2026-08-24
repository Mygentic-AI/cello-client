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
 * The relay's park-deposit refusal codes — **ONE definition, consumed by both sides of the wire.**
 *
 * ⚠️ These were declared INDEPENDENTLY in each repo: the relay threw the strings and the client
 * matched them, and they agreed only because I checked by hand once. Verification-once is not a
 * guard. If the relay renames `rate_limited`, nothing goes red — the client's branch simply stops
 * matching and falls through to the generic "the relay link is down" wording, which is the exact
 * defect that family of work exists to remove, reintroduced by a rename nobody thought was a
 * protocol change.
 *
 * They live here for the same reason `CONTENT_PARK_PROTOCOL_ID` and `buildContentParkAuthMsg` do:
 * this package is the one both repos already consume, so a change on either side is a change to a
 * shared symbol rather than to a private copy that happens to agree.
 *
 * ⚠️ THESE ARE WIRE VALUES. The string is the contract, not the key — renaming a key is free,
 * changing a value is a protocol change and breaks every deployed peer on the other side.
 */
export const RELAY_PARK_REFUSALS = {
  /** The relay is throttling this depositor. Self-clears; the relay says when via `retry_after_ms`. */
  RATE_LIMITED: "rate_limited",
  /** The relay's parked-content store is at a global bound. Another relay may still accept. */
  STORE_FULL: "content_store_full",
  /** This RECIPIENT's mailbox is at its own bound — another relay would refuse it too. */
  RECIPIENT_FULL: "content_store_recipient_full",
} as const;

/** A value of {@link RELAY_PARK_REFUSALS}. */
export type RelayParkRefusal = (typeof RELAY_PARK_REFUSALS)[keyof typeof RELAY_PARK_REFUSALS];

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

/**
 * SEC-1 — domain separator for the per-message PARK CONTENT signature.
 *
 * Distinct from CONTENT_PARK_AUTH_DOMAIN: that one proves "I am the recipient" to the RELAY on
 * pull/confirm. This one proves "I, the sender, authored this exact message for this exact session
 * and mailbox" to the RECIPIENT — and it rides INSIDE the seal, so the relay can neither read,
 * strip, nor forge it. The relay is in the threat model (it is handed the session_id in plaintext
 * on every deposit and holds the recipient pubkey as its mailbox key), which is precisely why this
 * signature is end-to-end and not a deposit-time check.
 */
export const PARK_CONTENT_DOMAIN = "CELLO-PARK-CONTENT-v1";

/**
 * SEC-1 — canonical to-be-signed statement for a parked content entry:
 *
 *   SHA-256( utf8(PARK_CONTENT_DOMAIN) || len(session_id) || session_id
 *            || recipient_pubkey(32) || content_hash(32) )
 *
 * The sender signs this with its Ed25519 K_local (RFC 8032); the recipient verifies it on recovery
 * and REFUSES the entry unless the signer is that session's counterparty (fail closed).
 *
 * Every field is load-bearing, and each kills one replay:
 *  - session_id      — a signature cannot be moved to a different session.
 *  - recipient_pubkey— a signature cannot be moved to a different mailbox.
 *  - content_hash    — a signature cannot be made to cover different bytes.
 * The session id is LENGTH-PREFIXED because it is the one variable-length field; without the prefix
 * the concatenation would be ambiguous against the fixed-width fields that follow it.
 */
export function buildParkContentTbs(
  sessionIdHex: string,
  recipientPubkey: Uint8Array,
  contentHash: Uint8Array,
): Uint8Array {
  const domain = new TextEncoder().encode(PARK_CONTENT_DOMAIN);
  const sessionId = Uint8Array.from(Buffer.from(sessionIdHex, "hex"));
  const h = createHash("sha256");
  h.update(domain);
  h.update(new Uint8Array([sessionId.length]));
  h.update(sessionId);
  h.update(recipientPubkey);
  h.update(contentHash);
  return new Uint8Array(h.digest());
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
