/**
 * CELLO-M7-SESSION-003 — session-path liveness wire types + codec
 *
 * The relay is the session-path liveness authority for relay-mode sessions. The
 * client queries it over the relay protocol stream with a session_liveness_query
 * frame and receives a session_liveness_response.
 *
 * WIRE CONVENTION (cross-ref SESSION-001 L-1): on-wire keys are snake_case,
 * matching every other relay frame. session_id is the 16-byte binary session id
 * and counterparty_pubkey is the 32-byte Ed25519 pubkey — identical to the keys
 * the relay uses for its delivery queue. The relay (trustless-cello) re-encodes
 * the SAME shape independently in relay-frames.ts (it cannot import this
 * unpublished package); the two MUST agree byte-for-byte. These tests pin the
 * shape.
 *
 * liveness is exactly 'alive' | 'gone' | 'unknown':
 *   - 'alive'   : the relay currently holds the recipient's standing connection
 *   - 'gone'    : the relay positively observed the recipient's disconnect with
 *                 no subsequent reconnect
 *   - 'unknown' : the relay has no tracked entry for the recipient. The relay
 *                 NEVER fabricates 'gone' from a missing entry (no observation is
 *                 'unknown', not 'gone').
 */

import { Encoder, decode as cborDecode } from "cbor-x";

const CBOR_ENC = new Encoder({ tagUint8Array: false });

export type SessionLiveness = "alive" | "gone" | "unknown";

export interface SessionLivenessQuery {
  type: "session_liveness_query";
  /** 16-byte binary session id */
  session_id: Uint8Array;
  /** 32-byte Ed25519 pubkey of the counterparty whose liveness is queried */
  counterparty_pubkey: Uint8Array;
}

export interface SessionLivenessResponse {
  type: "session_liveness_response";
  session_id: Uint8Array;
  counterparty_pubkey: Uint8Array;
  liveness: SessionLiveness;
  /** Unix ms timestamp of the relay's most recent observation for this recipient */
  observed_at: number;
}

function toUint8Array(v: unknown): Uint8Array | null {
  if (v instanceof Uint8Array) return v;
  if (Buffer.isBuffer(v)) return new Uint8Array(v);
  return null;
}

function isLiveness(v: unknown): v is SessionLiveness {
  return v === "alive" || v === "gone" || v === "unknown";
}

export function encodeSessionLivenessQuery(frame: SessionLivenessQuery): Uint8Array {
  return CBOR_ENC.encode({
    type: "session_liveness_query",
    session_id: frame.session_id,
    counterparty_pubkey: frame.counterparty_pubkey,
  }) as Uint8Array;
}

export function decodeSessionLivenessQuery(bytes: Uint8Array): SessionLivenessQuery | null {
  let obj: unknown;
  try {
    obj = cborDecode(bytes);
  } catch {
    return null;
  }
  if (typeof obj !== "object" || obj === null) return null;
  const o = obj as Record<string, unknown>;
  if (o["type"] !== "session_liveness_query") return null;
  const session_id = toUint8Array(o["session_id"]);
  const counterparty_pubkey = toUint8Array(o["counterparty_pubkey"]);
  if (!session_id || session_id.length !== 16) return null;
  if (!counterparty_pubkey || counterparty_pubkey.length !== 32) return null;
  return { type: "session_liveness_query", session_id, counterparty_pubkey };
}

export function encodeSessionLivenessResponse(frame: SessionLivenessResponse): Uint8Array {
  return CBOR_ENC.encode({
    type: "session_liveness_response",
    session_id: frame.session_id,
    counterparty_pubkey: frame.counterparty_pubkey,
    liveness: frame.liveness,
    observed_at: frame.observed_at,
  }) as Uint8Array;
}

export function decodeSessionLivenessResponse(bytes: Uint8Array): SessionLivenessResponse | null {
  let obj: unknown;
  try {
    obj = cborDecode(bytes);
  } catch {
    return null;
  }
  if (typeof obj !== "object" || obj === null) return null;
  const o = obj as Record<string, unknown>;
  if (o["type"] !== "session_liveness_response") return null;
  const session_id = toUint8Array(o["session_id"]);
  const counterparty_pubkey = toUint8Array(o["counterparty_pubkey"]);
  const liveness = o["liveness"];
  const observed_at = o["observed_at"];
  if (!session_id || session_id.length !== 16) return null;
  if (!counterparty_pubkey || counterparty_pubkey.length !== 32) return null;
  if (!isLiveness(liveness)) return null;
  if (typeof observed_at !== "number") return null;
  return { type: "session_liveness_response", session_id, counterparty_pubkey, liveness, observed_at };
}
