/**
 * Session assignment parsing — ported onto the daemon (DOD-SPINE-5).
 *
 * Decodes a raw CBOR-decoded `assignment` object (from a directory
 * `session_assignment` frame) into a typed SessionAssignment. Shape-validates only;
 * the FROST/single signature is verified downstream by the transport/session layer
 * against the directory's pinned key. This is a faithful port of
 * core/client/src/session-assignment-parser.ts — the daemon must NOT import the dead
 * core/client stack, so the proven logic lives here.
 */

import type { SessionAssignment } from "@cello-protocol/protocol-types";

function toU8Safe(v: unknown): Uint8Array | null {
  if (v instanceof Uint8Array) return v;
  if (Buffer.isBuffer(v)) return new Uint8Array(v as Buffer);
  return null;
}

function parseStringArray(v: unknown): string[] | null {
  if (!Array.isArray(v)) return null;
  if (!v.every((x) => typeof x === "string")) return null;
  return v as string[];
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

/**
 * Decode a raw CBOR-decoded object (frame["assignment"]) into a typed SessionAssignment.
 * Returns null if any required field is missing or malformed.
 */
export function parseSessionAssignment(raw: Record<string, unknown>): SessionAssignment | null {
  const sessionId = toU8Safe(raw["session_id"]);
  if (!sessionId || sessionId.length !== 16) return null;

  const dirPubkey = toU8Safe(raw["directory_pubkey"]);
  if (!dirPubkey || dirPubkey.length !== 32) return null;

  const dirSig = toU8Safe(raw["directory_signature"]);
  if (!dirSig || dirSig.length !== 64) return null;

  const tsRaw = raw["session_timestamp"];
  const sessionTimestamp = typeof tsRaw === "number" ? tsRaw : typeof tsRaw === "bigint" ? Number(tsRaw) : null;
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

  // M7 WIRE-001: session peer IDs + transport mode (undefined when absent, pre-M7 compat).
  const initiatorSessionPeerId =
    typeof raw["initiator_session_peer_id"] === "string" && raw["initiator_session_peer_id"] !== ""
      ? raw["initiator_session_peer_id"]
      : undefined;
  const initiatorSessionAddrs = parseStringArray(raw["initiator_session_addrs"]) ?? undefined;
  const counterpartySessionPeerId =
    typeof raw["counterparty_session_peer_id"] === "string" && raw["counterparty_session_peer_id"] !== ""
      ? raw["counterparty_session_peer_id"]
      : undefined;
  const counterpartySessionAddrs = parseStringArray(raw["counterparty_session_addrs"]) ?? undefined;
  const transportModeRaw = raw["transport_mode"];
  const transportMode: "direct" | "relay" | undefined =
    transportModeRaw === "direct" ? "direct" : transportModeRaw === "relay" ? "relay" : undefined;

  const common = {
    session_id: sessionId,
    participant_a: participantA,
    participant_b: participantB,
    relay_endpoint: relayEndpoint,
    directory_endpoint: directoryEndpoint,
    session_timestamp: sessionTimestamp,
    directory_pubkey: dirPubkey,
    directory_signature: dirSig,
    initiator_session_peer_id: initiatorSessionPeerId,
    initiator_session_addrs: initiatorSessionAddrs,
    counterparty_session_peer_id: counterpartySessionPeerId,
    counterparty_session_addrs: counterpartySessionAddrs,
    transport_mode: transportMode,
  };

  if (sigType === "frost") {
    const signerPubkey = toU8Safe(raw["signer_pubkey"]);
    if (!signerPubkey || signerPubkey.length !== 32) return null;
    return { ...common, signature_type: "frost" as const, signer_pubkey: signerPubkey };
  }
  return { ...common, signature_type: "single" as const };
}

/**
 * Map a raw `session_request_error` frame's reason to a stable negotiator reason code.
 * Distinct cause → distinct code (M7 error discipline); unknown → directory_unreachable.
 */
export function sessionRequestErrorReason(frame: Record<string, unknown>): string {
  const reason = frame["reason"];
  const known = new Set([
    "target_offline",
    "relay_unavailable",
    "frost_signer_not_configured",
    "directory_below_threshold",
    "ceremony_timeout",
    "ceremony_exhausted",
    "ceremony_conflict",
    "not_registered",
    "peer_not_registered",
    "no_connection",
    "connection_id_required",
    "session_request_missing_peer_id",
    "agent_revoked", // CELLO-M7-REMOVE-001 DOD-REMOVE-3: the target (or initiator) agent is revoked
  ]);
  return typeof reason === "string" && known.has(reason) ? reason : "directory_unreachable";
}
