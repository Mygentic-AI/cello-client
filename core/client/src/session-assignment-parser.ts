/**
 * ADAPTER-003: Session assignment frame parsing helpers.
 *
 * Decodes raw CBOR-decoded objects into typed protocol structures.
 * No @cello-protocol/directory import needed — fields are validated by
 * shape only, after cbor-x decoding of the outer frame.
 */

import type { SessionAssignment } from "@cello-protocol/protocol-types";
import type { InitiateSessionResult } from "./types.js";

function toU8Safe(v: unknown): Uint8Array | null {
  if (v instanceof Uint8Array) return v;
  if (Buffer.isBuffer(v)) return new Uint8Array(v as Buffer);
  return null;
}

/**
 * Decode a raw CBOR-decoded object (from frame["assignment"]) into a typed SessionAssignment.
 * Returns null if any required field is missing or malformed.
 *
 * Wire shape (from encodeSessionAssignment in directory-frames.ts):
 *   {
 *     session_id: Uint8Array (16),
 *     participant_a: { pubkey: Uint8Array (32), peer_id: string, multiaddrs: string[] },
 *     participant_b: { pubkey: Uint8Array (32), peer_id: string, multiaddrs: string[] },
 *     relay_endpoint: { peer_id: string, multiaddrs: string[] },
 *     directory_endpoint: { peer_id: string, multiaddrs: string[] },
 *     session_timestamp: number,
 *     directory_pubkey: Uint8Array (32),
 *     directory_signature: Uint8Array (64),
 *   }
 */
export function parseSessionAssignment(raw: Record<string, unknown>): SessionAssignment | null {
  const sessionId = toU8Safe(raw["session_id"]);
  if (!sessionId || sessionId.length !== 16) return null;

  const dirPubkey = toU8Safe(raw["directory_pubkey"]);
  if (!dirPubkey || dirPubkey.length !== 32) return null;

  const dirSig = toU8Safe(raw["directory_signature"]);
  if (!dirSig || dirSig.length !== 64) return null;

  const tsRaw = raw["session_timestamp"];
  const sessionTimestamp = typeof tsRaw === "number" ? tsRaw
    : typeof tsRaw === "bigint" ? Number(tsRaw) : null;
  if (sessionTimestamp === null) return null;

  const participantA = parseParticipantInfo(raw["participant_a"]);
  if (!participantA) return null;

  const participantB = parseParticipantInfo(raw["participant_b"]);
  if (!participantB) return null;

  const relayEndpoint = parseEndpointInfo(raw["relay_endpoint"]);
  if (!relayEndpoint) return null;

  const directoryEndpoint = parseEndpointInfo(raw["directory_endpoint"]);
  if (!directoryEndpoint) return null;

  const sigType = typeof raw["signature_type"] === "string" ? raw["signature_type"] : "single";

  // M7 WIRE-001: parse session peer ID and transport mode fields (undefined when absent for pre-M7 compat)
  const initiatorSessionPeerId = typeof raw["initiator_session_peer_id"] === "string" && raw["initiator_session_peer_id"] !== "" ? raw["initiator_session_peer_id"] : undefined;
  const initiatorSessionAddrs = parseStringArray(raw["initiator_session_addrs"]) ?? undefined;
  const counterpartySessionPeerId = typeof raw["counterparty_session_peer_id"] === "string" && raw["counterparty_session_peer_id"] !== "" ? raw["counterparty_session_peer_id"] : undefined;
  const counterpartySessionAddrs = parseStringArray(raw["counterparty_session_addrs"]) ?? undefined;
  const transportModeRaw = raw["transport_mode"];
  const transportMode: "direct" | "relay" | undefined = transportModeRaw === "direct" ? "direct" : transportModeRaw === "relay" ? "relay" : undefined;

  if (sigType === "frost") {
    const signerPubkey = toU8Safe(raw["signer_pubkey"]);
    if (!signerPubkey || signerPubkey.length !== 32) return null;
    return {
      session_id: sessionId,
      participant_a: participantA,
      participant_b: participantB,
      relay_endpoint: relayEndpoint,
      directory_endpoint: directoryEndpoint,
      session_timestamp: sessionTimestamp,
      directory_pubkey: dirPubkey,
      directory_signature: dirSig,
      signature_type: "frost" as const,
      signer_pubkey: signerPubkey,
      initiator_session_peer_id: initiatorSessionPeerId,
      initiator_session_addrs: initiatorSessionAddrs,
      counterparty_session_peer_id: counterpartySessionPeerId,
      counterparty_session_addrs: counterpartySessionAddrs,
      transport_mode: transportMode,
    };
  }

  return {
    session_id: sessionId,
    participant_a: participantA,
    participant_b: participantB,
    relay_endpoint: relayEndpoint,
    directory_endpoint: directoryEndpoint,
    session_timestamp: sessionTimestamp,
    directory_pubkey: dirPubkey,
    directory_signature: dirSig,
    signature_type: "single" as const,
    initiator_session_peer_id: initiatorSessionPeerId,
    initiator_session_addrs: initiatorSessionAddrs,
    counterparty_session_peer_id: counterpartySessionPeerId,
    counterparty_session_addrs: counterpartySessionAddrs,
    transport_mode: transportMode,
  };
}

function parseParticipantInfo(raw: unknown): import("@cello-protocol/protocol-types").ParticipantInfo | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  const pubkey = toU8Safe(r["pubkey"]);
  if (!pubkey || pubkey.length !== 32) return null;
  const peerId = typeof r["peer_id"] === "string" ? r["peer_id"] : null;
  if (!peerId) return null;
  const multiaddrs = parseStringArray(r["multiaddrs"]);
  if (!multiaddrs) return null;
  return { pubkey, peer_id: peerId, multiaddrs };
}

function parseEndpointInfo(raw: unknown): import("@cello-protocol/protocol-types").RelayEndpointInfo | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  const peerId = typeof r["peer_id"] === "string" ? r["peer_id"] : null;
  if (!peerId) return null;
  const multiaddrs = parseStringArray(r["multiaddrs"]);
  if (!multiaddrs) return null;
  return { peer_id: peerId, multiaddrs };
}

function parseStringArray(v: unknown): string[] | null {
  if (!Array.isArray(v)) return null;
  if (!v.every((x) => typeof x === "string")) return null;
  return v as string[];
}

/**
 * Map a raw decoded session_request_error frame to an InitiateSessionResult.
 * Exported for direct unit testing (AC-005, AC-006).
 * The frame must have type === "session_request_error".
 */
export function mapSessionRequestErrorFrame(
  frame: Record<string, unknown>,
): InitiateSessionResult {
  const reason = frame["reason"];
  if (reason === "target_offline") return { ok: false, reason: "target_offline" };
  if (reason === "relay_unavailable") return { ok: false, reason: "relay_unavailable" };
  if (reason === "frost_signer_not_configured") return { ok: false, reason: "frost_signer_not_configured" };
  if (reason === "directory_below_threshold") return { ok: false, reason: "directory_below_threshold" };
  if (reason === "ceremony_timeout") return { ok: false, reason: "ceremony_timeout" };
  if (reason === "ceremony_exhausted") return { ok: false, reason: "ceremony_exhausted" };
  if (reason === "ceremony_conflict") return { ok: false, reason: "ceremony_conflict" };
  if (reason === "no_connection") return { ok: false, reason: "no_connection" };
  if (reason === "connection_id_required") return { ok: false, reason: "no_connection" };
  if (reason === "session_request_missing_peer_id") return { ok: false, reason: "session_request_missing_peer_id" };
  return { ok: false, reason: "directory_unreachable" };
}
