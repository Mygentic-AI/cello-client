/**
 * Session assignment parsing.
 *
 * Decodes a raw CBOR-decoded `assignment` object (from a directory
 * `session_assignment` frame) into a typed SessionAssignment. **Shape-validates ONLY** — it checks
 * that a signature is 64 bytes, never that it is correct. The logic lives here in the daemon
 * because the daemon must NOT import the core/client stack.
 *
 * ⚠️ DOD-M15-CLAIM-COMMENTS-1 — THIS HEADER NAMED A CHECK THAT DID NOT EXIST. It read: *"the
 * FROST/single signature is verified downstream by the transport/session layer against the
 * directory's pinned key."* There was no such site anywhere in the tree —
 * `buildSessionEstablishmentTbs` was called to SIGN and nowhere to verify — so every caller of this
 * parser was relying on a verification the sentence invented.
 *
 * Verification now exists, in exactly one place: `assignment-verify.ts`, called by
 * `outbound-sessions.ts` on the initiator path, which REFUSES the session when it fails. Two
 * corrections to the old sentence while the record is open: it is not verified by "the
 * transport/session layer", and it is not "the directory's pinned key" — the FROST signature is by
 * the INITIATOR's own threshold group key, which is why the verifier compares `signer_pubkey`
 * against this agent's persisted `primaryPubkey` before trusting it.
 *
 * **The responder verifies it too, but asymmetrically** (`verifyInboundAssignment`,
 * `DOD-M15-RESPONDER-VERIFY-1`). It has no key of its own to compare against, so for a REPEAT
 * counterparty it verifies under the key this daemon pinned during an earlier session, and on FIRST
 * CONTACT it can only prove the signature holds over the assignment's own recomputed contents —
 * which catches tampering but cannot authenticate a directory. Said plainly rather than left for
 * the next reader to assume symmetry, because assuming symmetry is what the original sentence cost.
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
  /**
   * `peer_id` IS TOLERATED TOO, and it is the WORSE of the two.
   *
   * Same three properties as `multiaddrs` below — unread (the only reads anywhere are the
   * directory's own encoder), covered by no signature, and it refused the entire assignment. But
   * the killing value is not a bug's output, it is a DEFAULT the directory writes on purpose:
   * `directory-node.ts:2049` seeds `{ peer_id: "", multiaddrs: [] }` on auth, and `:3867` uses the
   * same object when the peer-info map misses. `:4120` copies whichever it got into
   * `participant_a/b`, and nothing gates it — the only announce requirement checks the INITIATOR,
   * never the TARGET.
   *
   * So an agent whose peer-info announce is late or absent could not be talked to at all: the
   * directory FROST-signs a valid assignment, both clients parse it, both refuse over an empty
   * string neither one reads, and the operator is told the assignment was "missing or malformed"
   * when it was neither.
   */
  const peerId = typeof r["peer_id"] === "string" ? r["peer_id"] : "";
  /**
   * `multiaddrs` IS TOLERATED, NOT VALIDATED — `DOD-M15-DEAD-WIRE-FIELD-1`.
   *
   * It has been permanently `[]` on every session assignment since the directory-facing node
   * stopped listening. The directory stores it and SIGNS NOTHING over it — neither the session nor
   * the relay TBS includes it — and the only read of a parsed participant takes `.pubkey`.
   *
   * Rejecting the WHOLE assignment when it was malformed therefore ended a conversation over a
   * value that cannot affect anything and that no signature protects: a checked-then-ignored, and
   * the refusing half is the one that costs. Absent or malformed now yields `[]`, which is what it
   * always is in practice.
   *
   * ⚠️ NOT the same field on `parseEndpointInfo` below. Those multiaddrs belong to the RELAY and
   * DIRECTORY endpoints and are DIALED — a malformed one is a session that cannot connect, worth
   * refusing at the boundary rather than discovering at dial time. Identical name, adjacent
   * function, one dead and one load-bearing.
   *
   * Removing the field from the wire is bilateral and rides with the other pending wire changes so
   * the two repos move once; accepting its ABSENCE here is what makes this client already
   * compatible when that lands.
   */
  const multiaddrs = parseStringArray(r["multiaddrs"]) ?? [];
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

  // The per-node directory signature over the relay TBS. Optional — absent on older assignments and on
  // direct-mode sessions. When present it must be a valid 64-byte sig; a malformed value is dropped to
  // undefined (the session then has no relay assignment to present, which surfaces as a relay-witness
  // gap, not a hard failure).
  const relayDirSigRaw = toU8Safe(raw["relay_directory_signature"]);
  const relayDirSig = relayDirSigRaw && relayDirSigRaw.length === 64 ? relayDirSigRaw : undefined;

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

  // Session peer IDs + transport mode — undefined when absent (an older peer omits them).
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
    relay_directory_signature: relayDirSig,
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

// ─── Cross-node discovery ────────────────────

export interface DiscoveryLookupResultParsed {
  state: "online" | "offline" | "unknown_agent";
  /** Non-empty only when state = "online" (length 1 until the k>1 homing knob lands). */
  owningNodeIds: string[];
}

/**
 * Decode a `discovery_lookup_result` frame. Shape-validates the 3-state answer; returns null on an
 * unrecognized state (never fabricates one). A malformed/missing owning_node_ids defaults to [] — the
 * negotiator treats online-with-no-owner as not-actionable (retry), never dials a fabricated node.
 */
export function parseDiscoveryLookupResult(frame: Record<string, unknown>): DiscoveryLookupResultParsed | null {
  const state = frame["state"];
  if (state !== "online" && state !== "offline" && state !== "unknown_agent") return null;
  const owningNodeIds = parseStringArray(frame["owning_node_ids"]) ?? [];
  return { state, owningNodeIds };
}

/**
 * Map a `discovery_lookup_error` frame's reason to a stable code. The directory returns this on a DB
 * error during the lookup — a RETRYABLE condition, never a fabricated authoritative offline/unknown.
 * Unknown reasons collapse to the same retryable "lookup_failed".
 */
export function discoveryLookupErrorReason(_frame: Record<string, unknown>): string {
  // Only one reason today; any discovery_lookup_error is the same retryable condition. Kept as a
  // function (not a constant) so a future reason set slots in without touching call sites.
  return "lookup_failed";
}

/**
 * Map a raw `session_request_error` frame's reason to a stable negotiator reason code.
 * Distinct cause → distinct code; an unknown reason collapses to directory_unreachable.
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
    "agent_revoked", // the target (or initiator) agent is revoked
    "agent_suspended", // the target/initiator is PAUSED (reversible suspend)
    // The directory fails closed instead of FROST-signing an endpoint-less assignment — the target
    // never accepted the session_offer. Distinct from target_offline: the target IS connected to the
    // directory, it just cannot serve this session (e.g. its standing receiver has not come up).
    // Omitting it here collapses the cause to `directory_unreachable`, blaming the DIRECTORY for a
    // healthy directory and a COUNTERPARTY that declined — the wrong subsystem, which is what makes
    // such bugs cost days.
    "counterparty_did_not_accept",
  ]);
  return typeof reason === "string" && known.has(reason) ? reason : "directory_unreachable";
}

// ─── The offer-moniker validation seams ──────────────────────────

import { validateMoniker } from "@cello-protocol/protocol-types";

/**
 * The receiver's wire boundary, validated ONCE here so downstream code can never
 * observe an invalid moniker. Absent ≠ invalid: an absent field is an older client
 * (silent, rejected: false); a present-but-invalid value means the sender runs
 * modified code (rejected: true — the caller logs `moniker.rejected`, never the raw
 * value). Reject, never strip: the value is returned verbatim or null, never repaired.
 */
export function extractOfferedMoniker(raw: Record<string, unknown>): {
  offeredMoniker: string | null;
  rejected: boolean;
  /** Set ONLY when rejected — WHAT was wrong, for moniker.rejected (never the raw value). */
  reason?: "not_string" | "length" | "charset";
} {
  if (!("moniker" in raw) || raw["moniker"] === undefined) {
    return { offeredMoniker: null, rejected: false };
  }
  const value = raw["moniker"];
  if (typeof value !== "string") {
    return { offeredMoniker: null, rejected: true, reason: "not_string" };
  }
  if (value.length < 1 || value.length > 64) {
    return { offeredMoniker: null, rejected: true, reason: "length" };
  }
  const valid = validateMoniker(value);
  return valid !== null
    ? { offeredMoniker: valid, rejected: false }
    : { offeredMoniker: null, rejected: true, reason: "charset" };
}

/**
 * Defense-in-depth re-validation of the initiator's own outbound name. Returns
 * undefined (field OMITTED from the wire, never an empty string) when there is no
 * name or the stored value somehow fails validation.
 */
export function resolveOutboundMoniker(outboundName: string | null): string | undefined {
  if (outboundName === null) return undefined;
  return validateMoniker(outboundName) ?? undefined;
}
