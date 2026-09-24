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
 * **The responder verifies it too** (`verifyInboundAssignment`, `DOD-M15-RESPONDER-VERIFY-1`), and
 * 038-KEYBIND changed what that is worth on FIRST CONTACT. The old sentence here said the responder
 * *"can only prove the signature holds over the assignment's own recomputed contents — which catches
 * tampering but cannot authenticate a directory"*, and that was accurate: with no pin it verified
 * against `signer_pubkey`, a field of the frame under verification.
 *
 * The frame now carries `participant_a_key_binding` — a signature by the INITIATOR's own K_local
 * naming their group key. The responder checks that FIRST and verifies the threshold signature under
 * the key it proved, so a directory can no longer name a group key of its choosing. What first
 * contact still cannot tell you is whether `participant_a` is who you think: the identity key itself
 * is the out-of-band value, and no field on this frame can vouch for it.
 */

import type { SessionAssignment } from "@cello-protocol/protocol-types";

/**
 * The per-party key fields of a FROST assignment (038-KEYBIND, M9D 002-PQKEYS). REQUIRED on the wire
 * type — a directory always sends them — but a frame from a hostile or broken directory may not, so
 * the PARSED shape carries each as possibly `undefined` and `assignment-verify.ts` refuses by name.
 */
export const ASSIGNMENT_KEY_FIELDS = [
  "participant_a_key_binding", "participant_a_key_binding_pq", "participant_a_ml_dsa_pubkey", "participant_a_ml_kem_pubkey",
  "participant_b_primary_pubkey", "participant_b_key_binding", "participant_b_key_binding_pq",
  "participant_b_ml_dsa_pubkey", "participant_b_ml_kem_pubkey",
] as const;
type AssignmentKeyField = (typeof ASSIGNMENT_KEY_FIELDS)[number];

/** An assignment as parsed: every key field present-and-right-width, or `undefined`. */
export type ParsedSessionAssignment =
  Omit<SessionAssignment, AssignmentKeyField> & { [K in AssignmentKeyField]: Uint8Array | undefined };

/** The width each key field must have; any other width parses as `undefined`. */
const KEY_FIELD_BYTES: Record<AssignmentKeyField, number> = {
  participant_a_key_binding: 64,
  participant_a_key_binding_pq: 2420,
  participant_a_ml_dsa_pubkey: 1312,
  participant_a_ml_kem_pubkey: 1184,
  participant_b_primary_pubkey: 32,
  participant_b_key_binding: 64,
  participant_b_key_binding_pq: 2420,
  participant_b_ml_dsa_pubkey: 1312,
  participant_b_ml_kem_pubkey: 1184,
};

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

/**
 * A participant is its K_local pubkey and nothing else. The directory's `peer_id` / `multiaddrs` on a
 * participant were read by nothing and covered by no signature (`DOD-M15-DEAD-WIRE-FIELD-1`), so
 * they are no longer part of the type; any that still arrive are ignored.
 */
function parseParticipantInfo(raw: unknown): import("@cello-protocol/protocol-types").ParticipantInfo | null {
  if (typeof raw !== "object" || raw === null) return null;
  const pubkey = toU8Safe((raw as Record<string, unknown>)["pubkey"]);
  if (!pubkey || pubkey.length !== 32) return null;
  return { pubkey };
}

/**
 * The RELAY and DIRECTORY endpoints, whose multiaddrs ARE dialed — a malformed one is a session
 * that cannot connect, refused at the boundary rather than discovered at dial time.
 */
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
export function parseSessionAssignment(
  raw: Record<string, unknown>,
): ParsedSessionAssignment | null {
  const sessionId = toU8Safe(raw["session_id"]);
  if (!sessionId || sessionId.length !== 16) return null;

  const dirPubkey = toU8Safe(raw["directory_pubkey"]);
  if (!dirPubkey || dirPubkey.length !== 32) return null;

  const dirSig = toU8Safe(raw["directory_signature"]);
  if (!dirSig || dirSig.length !== 64) return null;

  // The per-node directory signature over the relay TBS. Absent on direct-mode sessions. When present it must be a valid 64-byte sig; a malformed value is dropped to
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

  // Session peer IDs, transport mode and the three 017-TBS / 069-ORDERPROOF values are all inside
  // the directory-signed 13-field statement, and a directory always sends them. Any one missing, or
  // of the wrong type, makes the assignment malformed — there is no shorter statement to verify.
  //
  // The TYPE is the test, never truthiness: `high_stakes: false`, `prior_relay_id: ""` (fresh session)
  // and `relay_id: ""` (direct session) are ANSWERS. The session peer ids must be non-empty: the
  // directory refuses to sign an assignment whose counterparty never accepted the offer.
  const initiatorSessionPeerId = raw["initiator_session_peer_id"];
  const initiatorSessionAddrs = parseStringArray(raw["initiator_session_addrs"]);
  const counterpartySessionPeerId = raw["counterparty_session_peer_id"];
  const counterpartySessionAddrs = parseStringArray(raw["counterparty_session_addrs"]);
  const transportModeRaw = raw["transport_mode"];
  const transportMode: "direct" | "relay" | null =
    transportModeRaw === "direct" || transportModeRaw === "relay" ? transportModeRaw : null;
  const highStakes = raw["high_stakes"];
  const priorRelayId = raw["prior_relay_id"];
  const relayId = raw["relay_id"];
  if (
    typeof initiatorSessionPeerId !== "string" || initiatorSessionPeerId === "" || !initiatorSessionAddrs ||
    typeof counterpartySessionPeerId !== "string" || counterpartySessionPeerId === "" || !counterpartySessionAddrs ||
    transportMode === null ||
    typeof highStakes !== "boolean" || typeof priorRelayId !== "string" || typeof relayId !== "string"
  ) {
    return null;
  }

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
    high_stakes: highStakes,
    prior_relay_id: priorRelayId,
    relay_id: relayId,
  };

  {
    // Every assignment is FROST-signed; one without the initiator's group key is malformed.
    const signerPubkey = toU8Safe(raw["signer_pubkey"]);
    if (!signerPubkey || signerPubkey.length !== 32) return null;
    /**
     * 038-KEYBIND — the key bindings are SHAPE-CHECKED HERE AND JUDGED IN `assignment-verify.ts`.
     *
     * A wrong-length value yields `undefined`, which the verifiers treat exactly as absent: both
     * take the REFUSE path, and refuse by name. That is the missing/malformed/mismatched collapse
     * the milestone requires — there is no shape of these fields that reaches a session.
     *
     * They are NOT rejected here (a `return null`) on purpose. `null` from this parser means "the
     * assignment was malformed", which tells an operator nothing about which protection stopped
     * them. Carrying the absence one layer further is what lets the refusal say
     * "this counterparty's directory did not supply the proof that its group key is theirs".
     */
    const keyFields = {} as { [K in AssignmentKeyField]: Uint8Array | undefined };
    for (const f of ASSIGNMENT_KEY_FIELDS) {
      const v = toU8Safe(raw[f]);
      keyFields[f] = v && v.length === KEY_FIELD_BYTES[f] ? v : undefined;
    }
    return {
      ...common,
      signer_pubkey: signerPubkey,
      ...keyFields,
    };
  }
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
    // M16: the initiator or target is a broadcast channel, which never holds a session. Collapsed to
    // `directory_unreachable`, a caller trying to reach a channel was sent to debug their network.
    "channel_participant",
    // M16: the directory could not check whether a side is a channel, and refused rather than broker
    // unchecked. Its own reason, so a database fault is never reported as "that is a channel".
    "channel_check_failed",
    // M9D 002-PQKEYS: a profile lacks a post-quantum key or binding on the node that answered —
    // replication has not delivered it yet. Collapsed to `directory_unreachable`, the operator would
    // be sent to debug their network for a row that has not reached one node.
    "counterparty_keys_unavailable",
  ]);
  return typeof reason === "string" && known.has(reason) ? reason : "directory_unreachable";
}

/**
 * The guidance returned with a `session_request_error`. Most reasons share one sentence; the M16
 * channel refusals get their own, because "ensure the counterparty is registered and online" is
 * the wrong advice for an identity that is online and simply never converses.
 */
export function sessionRequestErrorGuidance(reason: string): string {
  if (reason === "channel_participant") {
    return "The directory refused the session request (channel_participant): one side is a broadcast channel. Channels publish and never hold sessions. To reach the operator behind a channel, open a session with the channel's admin agent instead.";
  }
  if (reason === "channel_check_failed") {
    return "The directory refused the session request (channel_check_failed): it could not check whether either side is a broadcast channel, and does not broker a session it could not check. Retry; if it repeats, the directory node is failing to read its own records.";
  }
  if (reason === "counterparty_keys_unavailable") {
    return "The directory refused the session request (counterparty_keys_unavailable): the node that answered does not yet hold one side's post-quantum keys, so it could not give each side the other's. This usually means a recent registration has not replicated to that node. Nothing was opened. Retry in a moment; another directory node may serve it.";
  }
  return `The directory refused the session request (${reason}). Ensure the counterparty is registered and online.`;
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
