/**
 * CELLO-SESSION-002/MSG-004/SESSION-003/SESSION-004/SESSION-005 — session.ts
 *
 * SessionAssignment: shared wire type used by directory (sender), client (receiver),
 * and relay (verifier). Lives here so client can import it without touching @cello-protocol/directory.
 *
 * SESSION-004 additions to SessionAssignment:
 *   signature_type: 'frost' | 'single'
 *     - 'frost': the directory_signature field carries the 64-byte combined FROST output
 *     - 'single': M1-era single-key directory signature (refused by M2 clients)
 *   signer_pubkey?: Uint8Array (32 bytes, present when signature_type === 'frost')
 *     - The initiator's primary_pubkey (group FROST key). Embedded so the counterparty
 *       can verify without a separate directory round-trip.
 *
 * FROST TBS for session establishment (RFC 9591, domain separation per CONTEXT.md):
 *   context: "cello-frost-session-establishment-v1"
 *   tbs: canonical CBOR([session_id, agent_A_pubkey, agent_B_pubkey, genesis_prev_root, timestamp])
 *   framing: <context>\0<tbs_cbor>
 *   Note: signer_pubkey is NOT in the TBS — it is derived from DKG and embedded in the frame.
 *
 * SealPayload: canonical CBOR of [session_id, final_root, close_timestamp, "PENDING"].
 * Per SESSION-003. content_hash = SHA-256(0x00 || SealPayload) per MERKLE-001.
 *
 * computeGenesisPrevRoot: deterministic genesis prev_root for a two-party session.
 *
 * Formula (SI-004):
 *   SHA-256(min(A_pubkey, B_pubkey) || max(A_pubkey, B_pubkey) || session_id || timestamp_be8)
 *
 * Pubkeys are sorted bytewise-lexicographically (Buffer.compare).
 * timestamp_be8 is the session_timestamp encoded as an 8-byte big-endian unsigned integer
 * (milliseconds since Unix epoch). Raw byte concatenation — no CBOR at this boundary,
 * which would introduce width ambiguity on the timestamp encoding.
 *
 * Per FIPS 180-4 (SHA-256) and SESSION-002 SI-004.
 *
 * ─── Phase P: SESSION-004 Pseudocode ─────────────────────────────────────────
 *
 * SessionAssignment type changes (MEDIUM-6: discriminated union enforces signer_pubkey):
 *   // Use a discriminated union so TypeScript enforces signer_pubkey is present for 'frost'
 *   type SessionAssignmentFrost = { ...common fields..., signature_type: 'frost', signer_pubkey: Uint8Array }
 *   type SessionAssignmentSingle = { ...common fields..., signature_type: 'single' }
 *   type SessionAssignment = SessionAssignmentFrost | SessionAssignmentSingle
 *
 *   // Common fields (all existing SessionAssignment fields plus signature_type + signer_pubkey):
 *   session_id, participant_a, participant_b, relay_endpoint, directory_endpoint,
 *   session_timestamp, directory_pubkey, directory_signature
 *
 * buildSessionEstablishmentTbs(sessionId, pubA, pubB, genesisPrevRoot, timestamp):
 *   // HIGH-5: exported from protocol-types so both directory and client use identical CBOR encoding
 *   //         Any encoding drift would cause silent verification failures.
 *   // TBS = canonical CBOR([session_id, agent_A_pubkey, agent_B_pubkey, genesis_prev_root, timestamp])
 *   // Per CONTEXT.md: uses CBOR_ENC.encode() with tagUint8Array: false
 *   // timestamp is uint32 or BigInt depending on size (>0xffffffff → BigInt)
 *   return CBOR_ENC.encode([sessionId, pubA, pubB, genesisPrevRoot,
 *                           timestamp > 0xffffffff ? BigInt(timestamp) : timestamp])
 *
 * IMPORTANT-8: Existing test files that build SessionAssignment objects need updating to
 * include signature_type. Files affected (all M1 tests add signature_type: 'single'):
 *   - packages/client/src/__tests__/session.test.ts (makeDirectoryAssignment helper)
 *   - packages/client/src/__tests__/msg004.test.ts (makeDirectoryAssignment helper)
 *   - packages/client/src/__tests__/session003.test.ts (multiple construction sites)
 *   - packages/client/src/__tests__/session006.test.ts (makeDirectoryAssignment helper)
 *   - packages/e2e-tests/src/__tests__/mcp-002.test.ts (assignment construction)
 *   - packages/relay/src/__tests__/relay-node.test.ts (makeAssignment helper)
 *   - packages/relay/src/__tests__/relay-incremental.test.ts (makeAssignment helper)
 *   - packages/directory/src/directory-frames.ts (decodeOutboundSignalingFrame parser)
 *
 * IMPORTANT-9: ReceiveAssignmentResult in client/src/types.ts needs 'unsupported_signature_type'
 *   added to its reason union.
 *
 * ─── End Phase P Pseudocode ───────────────────────────────────────────────────
 *
 * buildSealTbs: FROST TBS for conversation seal (SESSION-005).
 * FROST TBS fields: [session_id, sealed_root, leaf_count, timestamp]
 * Context string: "cello-frost-seal-v1" (per CONTEXT.md)
 * Both sides (directory as signer, client as verifier) must use the same encoding.
 * Per RFC 9591 (FROST), RFC 8949 (CBOR canonical), FIPS 180-4 (SHA-256).
 */

import { createHash } from "node:crypto";
import { Encoder, decode as cborDecode } from "cbor-x";

const CBOR_ENC = new Encoder({ tagUint8Array: false });

// ─── SessionAssignment (shared wire type — SESSION-002 / SESSION-004) ─────────

export interface ParticipantInfo {
  pubkey: Uint8Array;    // 32-byte K_local pubkey
  peer_id: string;       // libp2p Peer ID string
  multiaddrs: string[];  // dialing multiaddrs
}

export interface RelayEndpointInfo {
  peer_id: string;
  multiaddrs: string[];
}

/** Common fields shared by both SessionAssignment variants. */
interface SessionAssignmentCommon {
  session_id: Uint8Array;           // 16 bytes, CSPRNG
  participant_a: ParticipantInfo;
  participant_b: ParticipantInfo;
  relay_endpoint: RelayEndpointInfo;
  directory_endpoint: RelayEndpointInfo; // SESSION-003: client dials directory for session_sealed events
  session_timestamp: number;        // Unix ms
  directory_pubkey: Uint8Array;     // 32-byte directory identity pubkey
  directory_signature: Uint8Array;  // 64-byte threshold/single signature over TBS
  // FED-OPTIONB-SETUP-001 (Option B, any-relay/any-directory): the per-node directory signature over
  // the relay TBS ([session_id, participant_a, participant_b, session_timestamp, (initiator_peer_id,
  // counterparty_peer_id)]). Distinct from `directory_signature` (the FROST session-establishment sig
  // authorizing the peer↔peer session): this authorizes the RELAY ASSIGNMENT. The client carries it to
  // its chosen relay (a `client_record_assignment` frame), which verifies it against any consortium
  // directory pubkey — replacing the old directory→relay `recordAssignment` dial. Optional for pre-M8B
  // assignments and direct-mode sessions (no relay).
  relay_directory_signature?: Uint8Array; // 64-byte per-node directory sig over the relay TBS
  // M7 WIRE-001: session-layer transport peer IDs and mode (optional for pre-M7 backward compat)
  initiator_session_peer_id?: string;       // libp2p session node Peer ID of initiator
  initiator_session_addrs?: string[];       // multiaddrs of initiator's session node
  counterparty_session_peer_id?: string;    // libp2p session node Peer ID of counterparty
  counterparty_session_addrs?: string[];    // multiaddrs of counterparty's session node
  transport_mode?: 'direct' | 'relay';      // whether session uses direct P2P or relay-mediated transport
}

/**
 * SESSION-004: FROST-signed assignment. `signer_pubkey` is the initiator's
 * group public key (primary_pubkey from DKG / trustedDealer commitments[0]).
 * Embedded so the counterparty can verify without a directory round-trip.
 */
export interface SessionAssignmentFrost extends SessionAssignmentCommon {
  signature_type: "frost";
  signer_pubkey: Uint8Array; // 32-byte FROST group public key — required for 'frost'
}

/**
 * M1-era single-key directory signature. Refused by M2+ clients.
 */
export interface SessionAssignmentSingle extends SessionAssignmentCommon {
  signature_type: "single";
  // signer_pubkey absent — M1 clients use directory_pubkey for verification
}

/**
 * Discriminated union. TypeScript enforces `signer_pubkey` is present only
 * when `signature_type === 'frost'`.
 *
 * SESSION-004: M2+ code should only handle 'frost'. M1 assignments with
 * 'single' are rejected with `unsupported_signature_type`.
 */
export type SessionAssignment = SessionAssignmentFrost | SessionAssignmentSingle;

// ─── Session establishment TBS builder (SESSION-004 / HIGH-5) ─────────────────

/**
 * Build the FROST to-be-signed bytes for session establishment.
 *
 * Exported from protocol-types so BOTH the directory (signer) and the client
 * (verifier) use identical canonical CBOR encoding. Any drift would silently
 * break verification.
 *
 * Legacy (M1–M6) TBS = canonical CBOR([session_id, pubA, pubB, genesis_prev_root, timestamp])
 * M7+ TBS = canonical CBOR([session_id, pubA, pubB, genesis_prev_root, timestamp,
 *   initiatorSessionPeerId, JSON.stringify(initiatorSessionAddrs.slice().sort()),
 *   counterpartySessionPeerId, JSON.stringify(counterpartySessionAddrs.slice().sort()),
 *   transportMode])
 *
 * Per CONTEXT.md: tagUint8Array: false. Timestamp encoded as BigInt when > 0xffffffff.
 * Address arrays are sorted and JSON-stringified for canonical ordering.
 *
 * @param sessionId - 16-byte session identifier
 * @param pubA - 32-byte K_local pubkey of participant A
 * @param pubB - 32-byte K_local pubkey of participant B
 * @param genesisPrevRoot - 32-byte genesis prev_root (output of computeGenesisPrevRoot)
 * @param timestamp - session_timestamp in Unix milliseconds
 * @param initiatorSessionPeerId - M7: session node Peer ID of initiator (optional for backward compat)
 * @param initiatorSessionAddrs - M7: multiaddrs of initiator session node (optional for backward compat)
 * @param counterpartySessionPeerId - M7: session node Peer ID of counterparty (optional for backward compat)
 * @param counterpartySessionAddrs - M7: multiaddrs of counterparty session node (optional for backward compat)
 * @param transportMode - M7: 'direct' or 'relay' (optional for backward compat)
 * @returns canonical CBOR bytes of the TBS array
 */
export function buildSessionEstablishmentTbs(
  sessionId: Uint8Array,
  pubA: Uint8Array,
  pubB: Uint8Array,
  genesisPrevRoot: Uint8Array,
  timestamp: number | bigint,
  initiatorSessionPeerId?: string,
  initiatorSessionAddrs?: string[],
  counterpartySessionPeerId?: string,
  counterpartySessionAddrs?: string[],
  transportMode?: 'direct' | 'relay',
): Uint8Array {
  const tsEncoded = typeof timestamp === "bigint" || timestamp > 0xffffffff ? BigInt(timestamp) : timestamp;

  // M7+: when all new fields are provided, encode all 10 fields
  if (
    initiatorSessionPeerId !== undefined &&
    initiatorSessionAddrs !== undefined &&
    counterpartySessionPeerId !== undefined &&
    counterpartySessionAddrs !== undefined &&
    transportMode !== undefined
  ) {
    return CBOR_ENC.encode([
      sessionId,
      pubA,
      pubB,
      genesisPrevRoot,
      tsEncoded,
      initiatorSessionPeerId,
      JSON.stringify(initiatorSessionAddrs.slice().sort()),
      counterpartySessionPeerId,
      JSON.stringify(counterpartySessionAddrs.slice().sort()),
      transportMode,
    ]) as Uint8Array;
  }

  // Legacy (M1–M6): encode only the original 5 fields
  return CBOR_ENC.encode([
    sessionId,
    pubA,
    pubB,
    genesisPrevRoot,
    tsEncoded,
  ]) as Uint8Array;
}

// ─── SealPayload (SESSION-003) ────────────────────────────────────────────────

/**
 * SEAL control payload carried as the content_bytes of a ctrl leaf.
 * Canonical CBOR encoding: [session_id, final_root, close_timestamp, "PENDING"].
 * Per SESSION-003 behavior spec.
 */
export interface SealPayload {
  session_id: Uint8Array;   // 16 bytes — matches the session
  final_root: Uint8Array;   // 32-byte Merkle root at the time of SEAL signing
  close_timestamp: number;  // Unix ms
  attestation: "PENDING";   // M1 placeholder; M7 replaces with CLEAN/FLAGGED
}

/**
 * Encode a SealPayload as canonical CBOR: [session_id, final_root, close_timestamp, "PENDING"].
 * Per SESSION-003 behavior spec and RFC 8949 §4.2.1.
 */
export function encodeSealPayload(payload: SealPayload): Uint8Array {
  return CBOR_ENC.encode([
    payload.session_id,
    payload.final_root,
    payload.close_timestamp > 0xffffffff
      ? BigInt(payload.close_timestamp)
      : payload.close_timestamp,
    payload.attestation,
  ]) as Uint8Array;
}

/**
 * Decode a SEAL payload CBOR. Returns null on malformed input.
 */
export function decodeSealPayload(bytes: Uint8Array): SealPayload | null {
  let arr: unknown;
  try {
    arr = cborDecode(bytes);
  } catch {
    return null;
  }
  if (!Array.isArray(arr) || arr.length !== 4) return null;
  const [_sid, _root, _ts, _attest] = arr;
  const sid = _sid instanceof Uint8Array ? _sid : Buffer.isBuffer(_sid) ? new Uint8Array(_sid as Buffer) : null;
  const root = _root instanceof Uint8Array ? _root : Buffer.isBuffer(_root) ? new Uint8Array(_root as Buffer) : null;
  if (!sid || sid.length !== 16) return null;
  if (!root || root.length !== 32) return null;
  const ts = typeof _ts === "number" ? _ts : typeof _ts === "bigint" ? Number(_ts) : null;
  if (ts === null) return null;
  if (_attest !== "PENDING") return null;
  return { session_id: sid, final_root: root, close_timestamp: ts, attestation: "PENDING" };
}

// ─── buildSealTbs (SESSION-005) ───────────────────────────────────────────────

/**
 * Build the FROST to-be-signed bytes for a conversation seal ceremony.
 *
 * FROST TBS for seal (CONTEXT.md): canonical CBOR([session_id, sealed_root, leaf_count, timestamp])
 * Context string: "cello-frost-seal-v1" (domain separation, prevents establishment replay)
 * Per RFC 9591 (FROST) and RFC 8949 §4.2.1 (canonical CBOR).
 *
 * Both the directory (as ceremony participant verifying the signature) and the client
 * (as the coordinator who submits the signature) MUST use this exact encoding.
 *
 * @param sessionId - 16-byte session identifier
 * @param sealedRoot - 32-byte final Merkle root
 * @param leafCount - total number of leaves in the sealed tree
 * @param timestamp - Unix milliseconds at the time of verification
 */
export function buildSealTbs(
  sessionId: Uint8Array,
  sealedRoot: Uint8Array,
  leafCount: number,
  timestamp: number,
): Uint8Array {
  return CBOR_ENC.encode([
    sessionId,
    sealedRoot,
    leafCount,
    timestamp > 0xffffffff ? BigInt(timestamp) : timestamp,
  ]) as Uint8Array;
}

// ─── Session outcome notification frame types ─────────────────────────────────
// These are wire-format events sent from the directory to clients over the
// signaling channel. They cross process boundaries and belong in protocol-types.

export interface SessionAbandoned {
  type: "session_abandoned";
  session_id: Uint8Array; // 16 bytes
}

/**
 * M1 session_sealed frame (single-key directory signature).
 * Refused in M2 clients per SESSION-005 SI-003.
 * @deprecated Use SessionSealedFrost instead in M2+.
 */
export interface SessionSealedSingle {
  type: "session_sealed";
  signature_type: "single";
  session_id: Uint8Array;          // 16 bytes
  sealed_root: Uint8Array;         // 32-byte final Merkle root
  directory_signature: Uint8Array; // 64-byte Ed25519 over canonical CBOR([session_id, sealed_root, close_timestamp])
  close_timestamp: number;         // Unix ms
  legibility?: SealLegibility;     // M7-SESSION-004: receipt-not-assent + frontiers + final_message
}

/**
 * M2 session_sealed frame (FROST-notarized ceremony signature).
 * SESSION-005: seal_type is 'frost' when the FROST ceremony completes.
 */
export interface SessionSealedFrost {
  type: "session_sealed";
  signature_type: "frost";
  session_id: Uint8Array;          // 16 bytes
  sealed_root: Uint8Array;         // 32-byte final Merkle root
  frost_signature: Uint8Array;     // 64-byte combined FROST signature over seal TBS
  signer_pubkey: Uint8Array;       // 32-byte initiator primary_pubkey (group public key)
  close_timestamp: number;         // Unix ms
  leaf_count?: number;             // total leaves in the sealed tree (SESSION-005 H-003)
  legibility?: SealLegibility;     // M7-SESSION-004: receipt-not-assent + frontiers + final_message
}

/** Discriminated union: M2 sends SessionSealedFrost; old M1 wire format is SessionSealedSingle. */
export type SessionSealed = SessionSealedSingle | SessionSealedFrost;

// ─── Seal certificate legibility (M7-SESSION-004) ─────────────────────────────
//
// POSTMORTEM Part 3 (C-1 / C-2 / C-6, all SETTLED). The seal certificate gains a
// first-class, machine-readable `legibility` object stating that its signatures
// attest RECEIPT — not assent — and publishing each party's content-frontier, a
// per-attestation live-vs-recovered marker, and whether the final message was
// answered. A signature over a hash chain can prove exactly three things — these
// bytes existed, in this order, delivered to/from me — and is cryptographically
// INCAPABLE of proving agreement. "Sealed" must never be read as "agreed".
//
// These properties are DERIVED by the directory at seal time from the leaves it
// already verifies (the signed last_seen_seq, sender pubkeys, sequence numbers)
// and the receipt-not-assent constant; they are carried on this wire frame and
// persisted CLIENT-SIDE in SQLite. No new persisted directory column is added.

/**
 * Per-attestation marker.
 *   'live'      — the participant produced their SEAL acknowledgement leaf
 *                 contemporaneously in this ceremony (full-bilateral / present-party).
 *   'absent'    — the participant produced no acknowledgement (counterparty ABSENT;
 *                 populated by the unilateral-notarization flow, Workstream A).
 *   'recovered' — the acknowledgement was added post-hoc on return (populated by the
 *                 bilateral-upgrade flow, Workstream C).
 */
export type AttestationMode = "live" | "recovered" | "absent";

/**
 * Canonical, human-readable receipt-not-assent disclaimer carried on every seal
 * certificate. Constant — the receipt-not-assent property is not session-specific.
 */
export const SEAL_RECEIPT_DISCLAIMER =
  "This certificate attests faithful receipt, integrity, and ordering of the " +
  "transcript. No signature in this certificate implies agreement to, or assent " +
  "to, the contents of any message. Agreement is always a separate, explicit act " +
  "(its own signed reply). A sealed transcript is a receipt, never a record of agreement.";

export interface SealLegibilityParticipant {
  /** 32-byte K_local pubkey of this participant. */
  pubkey: Uint8Array;
  /**
   * The highest counterparty sequence number this party PROVABLY received —
   * the maximum signed last_seen_seq across that party's OWN signed leaves.
   * Tree sequence numbers greater than this were merely sent/committed, not
   * provably received by this party.
   */
  content_frontier_seq: number;
  /** The highest sequence number this party authored. */
  last_authored_seq: number;
  /** Per-attestation live-vs-recovered-vs-absent marker. */
  attestation_mode: AttestationMode;
}

export interface SealLegibilityFinalMessage {
  /** 32-byte pubkey of the author of the highest-sequence content (non-control) leaf. */
  sender_pubkey: Uint8Array;
  /** Sequence number of that final content leaf. */
  seq: number;
  /**
   * false => the final-message-unanswered case: composition + submission is
   * proven, receipt by the counterparty is not. A malicious tail
   * ("…you agreed to send me $1000") reads as delivered-but-unanswered.
   */
  answered: boolean;
}

/**
 * Reader-facing legibility object attached to the SessionSealed certificate.
 * Built by the directory at seal time; persisted client-side; exposed intact to
 * any reader (human, agent, arbitrator). NO field asserts, implies, or can be
 * parsed as agreement; `implies_assent` is always the literal `false`.
 */
export interface SealLegibility {
  attests: "receipt";
  implies_assent: false;
  disclaimer: string;
  participants: SealLegibilityParticipant[];
  final_message: SealLegibilityFinalMessage;
}

export type SealRejectionReason =
  | "merkle_root_mismatch"
  | "leaf_signature_invalid"
  | "prev_root_chain_broken"
  | "causal_chain_violated"
  | "content_hash_mismatch"
  | "seal_leaves_invalid"
  | "seal_signature_invalid";

export interface SessionSealRejected {
  type: "session_seal_rejected";
  session_id: Uint8Array; // 16 bytes
  reason: SealRejectionReason;
}

/**
 * seal_verified: directory → seal initiator, after all three verification passes pass.
 * Tells the initiator: "I've verified the tree — coordinate the FROST ceremony now."
 * Per SESSION-005 step 4 in the seal ceremony flow.
 */
export interface SealVerified {
  type: "seal_verified";
  session_id: Uint8Array;  // 16 bytes
  sealed_root: Uint8Array; // 32-byte final Merkle root (recomputed by directory)
  leaf_count: number;      // total leaves in the verified tree
  timestamp: number;       // Unix ms (used in FROST TBS)
}

// ─── End session outcome notification frame types ─────────────────────────────

/**
 * Compute the genesis prev_root for a two-party CELLO session.
 *
 * @param pubkeyA - K_local pubkey of participant A (32 bytes)
 * @param pubkeyB - K_local pubkey of participant B (32 bytes)
 * @param sessionId - session_id from the directory (16 bytes)
 * @param sessionTimestampMs - session_timestamp in milliseconds since Unix epoch
 * @returns 32-byte genesis prev_root (SHA-256 output)
 */
export function computeGenesisPrevRoot(
  pubkeyA: Uint8Array,
  pubkeyB: Uint8Array,
  sessionId: Uint8Array,
  sessionTimestampMs: number | bigint,
): Uint8Array {
  const a = Buffer.from(pubkeyA);
  const b = Buffer.from(pubkeyB);

  const [min, max] = Buffer.compare(a, b) <= 0 ? [a, b] : [b, a];

  const tsBe = Buffer.alloc(8);
  tsBe.writeBigUInt64BE(typeof sessionTimestampMs === "bigint" ? sessionTimestampMs : BigInt(sessionTimestampMs));

  return new Uint8Array(
    createHash("sha256")
      .update(min)
      .update(max)
      .update(sessionId)
      .update(tsBe)
      .digest()
  );
}
