/**
 * session.ts — session wire types and their to-be-signed encodings.
 *
 * SessionAssignment: shared wire type used by directory (sender), client (receiver),
 * and relay (verifier). Lives here so client can import it without touching @cello-protocol/directory.
 *
 * Every SessionAssignment is FROST-signed: `directory_signature` carries the 64-byte combined FROST
 * output, and `signer_pubkey` (32 bytes) is the initiator's primary_pubkey (group FROST key),
 * embedded so the counterparty can verify without a separate directory round-trip. There is no
 * other signature type.
 *
 * FROST TBS for session establishment (RFC 9591, domain separation per CONTEXT.md):
 *   context: "cello-frost-session-establishment-v1"
 *   tbs: canonical CBOR of the 13-field statement — see buildSessionEstablishmentTbs
 *   framing: <context>\0<tbs_cbor>
 *   Note: signer_pubkey is NOT in the TBS — it is derived from DKG and embedded in the frame.
 *
 * SealPayload: canonical CBOR of [session_id, final_root, close_timestamp, "PENDING"].
 * content_hash = SHA-256(0x02 || SealPayload) — 0x02 is LEAF_KIND_CTRL.
 *
 * ⚠️ THIS LINE SAID `0x00` AND THE PRODUCER USES `0x02`. Found by review of `DOD-M15-SEALWIRE-1`
 * bullets 3+4. It is the header of the file that DEFINES this payload, so anyone building a second
 * verifier from it builds one whose hash never matches — and they would look for the fault in their
 * own code, because the definition said otherwise.
 *
 * computeGenesisPrevRoot: deterministic genesis prev_root for a two-party session.
 *
 * Formula:
 *   SHA-256(min(A_pubkey, B_pubkey) || max(A_pubkey, B_pubkey) || session_id || timestamp_be8)
 *
 * Pubkeys are sorted bytewise-lexicographically (Buffer.compare).
 * timestamp_be8 is the session_timestamp encoded as an 8-byte big-endian unsigned integer
 * (milliseconds since Unix epoch). Raw byte concatenation — no CBOR at this boundary,
 * which would introduce width ambiguity on the timestamp encoding.
 *
 * Per FIPS 180-4 (SHA-256).
 *
 * buildSessionEstablishmentTbs is exported from protocol-types so that BOTH the directory
 * (signer) and the client (verifier) use identical canonical CBOR encoding. Any encoding
 * drift causes silent verification failures.
 *
 * buildSealTbs: FROST TBS for a conversation seal.
 * FROST TBS fields: [session_id, sealed_root, leaf_count, timestamp]
 * Context string: "cello-frost-seal-v1" (per CONTEXT.md)
 * Both sides (directory as signer, client as verifier) must use the same encoding.
 * Per RFC 9591 (FROST), RFC 8949 (CBOR canonical), FIPS 180-4 (SHA-256).
 */

import { createHash } from "node:crypto";
import { decode as cborDecode } from "cbor-x";
import { encodeCbor } from "./cbor.js";


// ─── SessionAssignment (shared wire type) ─────────────────────────────────────

export interface ParticipantInfo {
  pubkey: Uint8Array;    // 32-byte K_local pubkey
}

export interface RelayEndpointInfo {
  peer_id: string;
  multiaddrs: string[];
}

/**
 * FROST-signed session assignment — the only kind. `signer_pubkey` is the initiator's group public
 * key (primary_pubkey from DKG), embedded so the counterparty can verify without a directory
 * round-trip.
 */
export interface SessionAssignment {
  session_id: Uint8Array;           // 16 bytes, CSPRNG
  participant_a: ParticipantInfo;
  participant_b: ParticipantInfo;
  relay_endpoint: RelayEndpointInfo;
  directory_endpoint: RelayEndpointInfo; // client dials directory for session_sealed events
  session_timestamp: number;        // Unix ms
  directory_pubkey: Uint8Array;     // 32-byte directory identity pubkey
  directory_signature: Uint8Array;  // 64-byte combined FROST signature over TBS
  signer_pubkey: Uint8Array;        // 32-byte FROST group public key of the initiator
  // The per-node directory signature over the relay TBS ([session_id, participant_a, participant_b,
  // session_timestamp, (initiator_peer_id, counterparty_peer_id)]). Distinct from
  // `directory_signature` (the FROST session-establishment sig authorizing the peer↔peer session):
  // this authorizes the RELAY ASSIGNMENT. The client carries it to its chosen relay (a
  // `client_record_assignment` frame), which verifies it against any consortium directory pubkey.
  // Absent on direct-mode sessions (no relay), hence optional.
  relay_directory_signature?: Uint8Array; // 64-byte per-node directory sig over the relay TBS
  // Session-layer transport peer IDs and mode — required, and all inside the signed TBS.
  initiator_session_peer_id: string;       // libp2p session node Peer ID of initiator
  initiator_session_addrs: string[];       // multiaddrs of initiator's session node
  counterparty_session_peer_id: string;    // libp2p session node Peer ID of counterparty
  counterparty_session_addrs: string[];    // multiaddrs of counterparty's session node
  transport_mode: 'direct' | 'relay';      // whether session uses direct P2P or relay-mediated transport
  // 017-TBS — both inside the directory-signed TBS. `false` and `""` are VALUES, not absences.
  high_stakes: boolean;    // the session's tier, forwarded so the TARGET can see what it is held to
  prior_relay_id: string;  // on a resume, the relay that witnessed up to the handover; "" when fresh
  /**
   * 069-ORDERPROOF — the assigned relay's ACK-SIGNING pubkey, hex. `""` on a direct session.
   *
   * ⚠️ **THIS IS THE ANCHOR FOR EVERY RELAY ORDERING ATTESTATION IN THE SESSION.** It is inside the
   * directory-signed TBS (the 13-field layout), so a participant verifying the relay's signature
   * over a leaf's position checks it against a key the relay did not supply. Verifying against
   * `relay_id` on the ack frame instead — which is what the client did before this order — checks a
   * key against itself and proves only that the frame is internally consistent.
   *
   * NOT the same key as `relay_endpoint.peer_id`, which is the relay's libp2p transport identity.
   */
  relay_id: string;

  /**
   * 038-KEYBIND, extended by M9D 002-PQKEYS — the fields that let each party PLACE the other's keys:
   * the group key (seal trust anchor), the ML-DSA key (post-quantum signature twin) and the ML-KEM key
   * (what content sealed to that party is encapsulated to).
   *
   * ALL REQUIRED. A directory that cannot fill one refuses to broker (`counterparty_keys_unavailable`).
   * The type cannot stop a hostile directory sending a frame without one, so the verifiers still
   * check presence at runtime and refuse BY NAME — `verifyKeyBinding` returns `key_binding_missing`
   * / `key_binding_pq_missing` before it looks at anything else, instead of collapsing into "the
   * assignment was malformed", the one message an operator cannot act on. There is no code path that
   * proceeds without them.
   *
   * ─── Why they are safe to carry outside the directory's signature ────────────────────────────
   *
   * Every other unsigned field on this frame is a liability: a MITM can change it and nothing
   * breaks. These are the opposite. Each binding is signed by a participant's own K_local AND ML-DSA
   * key over all four of that participant's keys (`buildKeyBindingTbs`), so a directory that alters
   * any key or signature produces a binding that fails verification, and one that strips a field
   * produces a refusal.
   *
   * ⚠️ WHAT THIS DOES NOT COVER, said plainly: the ML-DSA half is checked under the ML-DSA key the
   * same binding introduces, so against a quantum attacker who can forge K_local's Ed25519 signature
   * the binding is self-certifying. `007-PQBUNDLE` closes that by putting a digest of both parties'
   * keys into the establishment statement FROST and T directories sign.
   */

  /** 64-byte Ed25519 signature by `participant_a`'s K_local over participant_a's v2 binding TBS. */
  participant_a_key_binding: Uint8Array;
  /** 2420-byte ML-DSA-44 signature by participant_a's ML-DSA key over the same TBS. */
  participant_a_key_binding_pq: Uint8Array;
  /** participant_a's 1312-byte ML-DSA-44 public key. */
  participant_a_ml_dsa_pubkey: Uint8Array;
  /** participant_a's 1184-byte ML-KEM-768 public key. */
  participant_a_ml_kem_pubkey: Uint8Array;

  /**
   * `participant_b`'s 32-byte FROST group public key. Carried so the INITIATOR learns the
   * responder's group key too — without it the initiator could not verify a responder-first seal.
   */
  participant_b_primary_pubkey: Uint8Array;
  /** 64-byte Ed25519 signature by `participant_b`'s K_local over participant_b's v2 binding TBS. */
  participant_b_key_binding: Uint8Array;
  /** 2420-byte ML-DSA-44 signature by participant_b's ML-DSA key over the same TBS. */
  participant_b_key_binding_pq: Uint8Array;
  /** participant_b's 1312-byte ML-DSA-44 public key. */
  participant_b_ml_dsa_pubkey: Uint8Array;
  /** participant_b's 1184-byte ML-KEM-768 public key. */
  participant_b_ml_kem_pubkey: Uint8Array;
}

// ─── Session establishment TBS builder ────────────────────────────────────────

/**
 * Build the FROST to-be-signed bytes for session establishment — ONE layout, 13 fields, all
 * required.
 *
 * Exported from protocol-types so BOTH the directory (signer) and the client (verifier) use
 * identical canonical CBOR encoding. Any drift would silently break verification.
 *
 * TBS = canonical CBOR([session_id, pubA, pubB, genesis_prev_root, timestamp,
 *   initiatorSessionPeerId, JSON.stringify(initiatorSessionAddrs.slice().sort()),
 *   counterpartySessionPeerId, JSON.stringify(counterpartySessionAddrs.slice().sort()),
 *   transportMode, highStakes, priorRelayId, relayId])
 *
 * Every field is an always-present VALUE: `highStakes` false is an answer, `priorRelayId` is "" on a
 * fresh session, `relayId` is "" on a direct one. The shorter 5/10/12-field layouts for directories
 * and clients that predated each field are gone (M9D purge) — an assignment missing a field is
 * malformed, never verified under a smaller statement.
 *
 * Per CONTEXT.md: tagUint8Array: false. Timestamp encoded as BigInt when > 0xffffffff.
 * Address arrays are sorted and JSON-stringified for canonical ordering.
 *
 * `relayId` (069-ORDERPROOF) is the assigned relay's ACK-SIGNING pubkey — the key its ordering
 * attestations verify under; `relay_endpoint.peer_id` is a different key and sits outside these
 * bytes. `highStakes` and `priorRelayId` (017-TBS) are here so the TARGET sees the tier it is held to
 * and a new relay learns who witnessed the conversation before, from the directory's signature.
 */
export function buildSessionEstablishmentTbs(
  sessionId: Uint8Array,
  pubA: Uint8Array,
  pubB: Uint8Array,
  genesisPrevRoot: Uint8Array,
  timestamp: number | bigint,
  initiatorSessionPeerId: string,
  initiatorSessionAddrs: string[],
  counterpartySessionPeerId: string,
  counterpartySessionAddrs: string[],
  transportMode: 'direct' | 'relay',
  highStakes: boolean,
  priorRelayId: string,
  relayId: string,
): Uint8Array {
  const tsEncoded = typeof timestamp === "bigint" || timestamp > 0xffffffff ? BigInt(timestamp) : timestamp;
  return encodeCbor([
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
    highStakes,
    priorRelayId,
    relayId,
  ]) as Uint8Array;
}

// ─── SealPayload ──────────────────────────────────────────────────────────────

/**
 * SEAL control payload carried as the content_bytes of a ctrl leaf.
 * Canonical CBOR encoding: [session_id, final_root, close_timestamp, "PENDING"].
 */
export interface SealPayload {
  session_id: Uint8Array;   // 16 bytes — matches the session
  final_root: Uint8Array;   // 32-byte Merkle root at the time of SEAL signing
  close_timestamp: number;  // Unix ms
  attestation: "PENDING";   // the only value the wire format admits today
}

/**
 * Encode a SealPayload as canonical CBOR: [session_id, final_root, close_timestamp, "PENDING"].
 * Per RFC 8949 §4.2.1.
 */
export function encodeSealPayload(payload: SealPayload): Uint8Array {
  return encodeCbor([
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

// ─── buildSealTbs ─────────────────────────────────────────────────────────────

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
  return encodeCbor([
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
 * DOD-M12B-ABANDON-NOTIFY-1 — peer-to-peer notice: "I have force-abandoned this session."
 *
 * A DIFFERENT FRAME ON A DIFFERENT RAIL from `SessionAbandoned` above, and named so nobody reaches
 * for the wrong decoder. That one is directory→client over signaling and carries 16 raw bytes; this
 * one is peer→peer over `/cello/content/1.0.0` and carries the hex session id the content path uses
 * throughout. Reusing the `session_abandoned` type string for both is what this name avoids.
 *
 * Purely advisory. It tells the receiver to stop calling — it does NOT end their session, because
 * a party must not be able to deny its counterparty the unilateral seal by hanging up. The receiver
 * pins it to the Noise-authenticated counterparty before acting.
 */
export interface SessionAbandonedNotice {
  type: "session_abandoned_notice";
  /** Hex session id, matching every other frame on the content stream. */
  session_id: string;
  correlation_id?: string;
}

/**
 * session_sealed frame carrying the FROST-notarized ceremony signature — the only kind of seal.
 */
export interface SessionSealed {
  type: "session_sealed";
  session_id: Uint8Array;          // 16 bytes
  sealed_root: Uint8Array;         // 32-byte final Merkle root
  frost_signature: Uint8Array;     // 64-byte combined FROST signature over seal TBS
  signer_pubkey: Uint8Array;       // 32-byte initiator primary_pubkey (group public key)
  close_timestamp: number;         // Unix ms
  leaf_count: number;              // total leaves in the sealed tree (signed)
  legibility: SealLegibility;      // frontiers + attestation modes + final_message (bound into the signed bytes)
}

// ─── Seal certificate legibility ──────────────────────────────────────────────
//
// The seal certificate carries a machine-readable `legibility` object publishing each
// party's content-frontier, a per-attestation live-vs-recovered marker, and whether
// the final message was answered. What the signatures prove: these bytes existed, in
// this order, delivered to and from these parties, unaltered. The certificate states
// that and stays neutral on what the conversation means (settled 2026-09-14).
//
// These properties are DERIVED by the directory at seal time from the leaves it
// already verifies (the signed last_seen_seq, sender pubkeys, sequence numbers)
// and the wording constant; they are carried on this wire frame and
// persisted CLIENT-SIDE in SQLite. No persisted directory column backs them.

/**
 * Per-attestation marker.
 *   'live'      — the participant produced their SEAL acknowledgement leaf
 *                 contemporaneously in this ceremony (full-bilateral / present-party).
 *   'absent'    — the participant produced no acknowledgement (counterparty ABSENT;
 *                 set by the unilateral-notarization flow).
 *   'recovered' — the acknowledgement was added post-hoc on return (set by the
 *                 bilateral-upgrade flow).
 */
export type AttestationMode = "live" | "recovered" | "absent";

/**
 * What every seal certificate attests, in words (settled 2026-09-14). NEUTRAL on agreement: a
 * seal may later be offered as evidence of one, so the certificate states what took place and
 * nothing about what it means. Not part of the signed legibility bytes.
 */
export const SEAL_RECEIPT_DISCLAIMER =
  "Attests that this conversation took place between these two agents, in this order, unaltered.";

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
 * any reader (human, agent, arbitrator). It is neutral on agreement: no field
 * says the conversation is an agreement, and none says it is not.
 */
export interface SealLegibility {
  attests: "receipt";
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
  | "seal_signature_invalid"
  /**
   * DOD-M15-SEALPARTIES-1: fewer than two participants carried their own signed transcript root, so
   * a bilateral seal had at most one party's approval. Distinct from `merkle_root_mismatch` because
   * it sends the reader somewhere else entirely — a counterparty build or a relay that dropped the
   * field, not two transcripts to compare.
   */
  | "seal_approval_missing"
  /**
   * DOD-M15-SEALPARTIES-1: both participants approved, and approved DIFFERENT transcripts. This is
   * the one that DOES mean "compare notes with your counterparty".
   */
  | "seal_parties_disagree"
  /**
   * M9D 002-PQKEYS: the refusing node holds no group key for the seal initiator, so it cannot
   * FROST-sign. A seal is FROST-signed or not issued; another node holding the profile can seal.
   */
  | "seal_signer_key_unavailable";

export interface SessionSealRejected {
  type: "session_seal_rejected";
  session_id: Uint8Array; // 16 bytes
  reason: SealRejectionReason;
  /**
   * DOD-M15-SEALPARTIES-1: the sentence that says which thing was wrong — which leaf, which party,
   * which of two roots. The `reason` selects the remedy; this is what makes the remedy actionable.
   * Absent when the refusing node had nothing more specific to say.
   */
  detail?: string;
}

/**
 * seal_verified: directory → seal initiator, after all three verification passes pass.
 * Tells the initiator: "I've verified the tree — coordinate the FROST ceremony now."
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

/** Domain tag for the anchored chain start, so it can never collide with any other hash in the protocol. */
const CHAIN_ANCHOR_DOMAIN = Buffer.from("cello/chain-anchor/v1", "utf8");

/**
 * The first link of a session's hash chain: the genesis prev_root bound to the directory's FROST
 * signature over the session establishment.
 *
 * Without this the opening ceremony was verified and then dropped — the chain began from a value
 * anyone holding the two keys, the id and the timestamp could compute, so only the seal end was
 * bookended. Folding the signature in means the chain's first link exists only for a session the
 * consortium actually established, and the directory re-checks it at seal time.
 *
 * The signature cannot go into `computeGenesisPrevRoot` itself: that value is inside the bytes the
 * signature covers.
 *
 * Formula: SHA-256("cello/chain-anchor/v1" || genesis_prev_root(32) || frost_signature(64))
 */
export function computeChainAnchor(genesisPrevRoot: Uint8Array, frostSignature: Uint8Array): Uint8Array {
  if (genesisPrevRoot.length !== 32) throw new Error(`computeChainAnchor: genesis must be 32 bytes, got ${genesisPrevRoot.length}`);
  if (frostSignature.length !== 64) throw new Error(`computeChainAnchor: signature must be 64 bytes, got ${frostSignature.length}`);
  return new Uint8Array(createHash("sha256").update(CHAIN_ANCHOR_DOMAIN).update(genesisPrevRoot).update(frostSignature).digest());
}
