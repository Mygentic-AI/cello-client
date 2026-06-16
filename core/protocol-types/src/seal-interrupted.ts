/**
 * M7-SESSION-001 — Seal-Interrupted Protocol Types
 *
 * Types for the bilateral seal-interrupted flow:
 *   1. SealInterruptedRequest: initiator → counterparty via directory signaling
 *   2. SealInterruptedAck: counterparty → initiator with signed control leaf
 *   3. SealInterruptedRejection: counterparty → initiator (declined)
 *   4. SealInterruptedLeaf: the SEAL-INTERRUPTED control leaf structure
 *
 * These are signaling-layer frames routed via the directory pass-through.
 * The directory does not validate payloads — it only routes by target pubkey.
 *
 * Design authority: outline.md §Resolved Design Questions Q4.
 * session_interrupted is relay-originated, not a seal. No auto-seal on receipt.
 * The seal-interrupted flow is operator-initiated bilateral agreement.
 *
 * Leaf construction (implementation_notes):
 *   - leafCount in the leaf DEFINITION = message leaves at interruption (before SEAL-INTERRUPTED appended)
 *   - After appending: total leaf count = leafCountAtInterruption + 1
 *   - merkleRootAtInterruption = root AFTER appending the SEAL-INTERRUPTED leaf
 *   - FROST TBS leaf_count = leafCountAtInterruption + 1 (same as total after appending)
 */

// ─── SealInterruptedLeaf ─────────────────────────────────────────────────────

/**
 * SEAL-INTERRUPTED control leaf — a new Merkle control leaf type.
 * Both sides produce one of these before the FROST seal ceremony.
 * Signed by the producing agent's K_local.
 */
export interface SealInterruptedLeaf {
  type: "SEAL_INTERRUPTED";
  /** Hex-encoded session identifier */
  sessionId: string;
  /** Number of message leaves at interruption (before this leaf is appended) */
  leafCount: number;
  /** Hex-encoded Merkle root AFTER appending this SEAL-INTERRUPTED leaf */
  merkleRootAtInterruption: string;
  /** Unix ms timestamp when the leaf was constructed */
  timestamp: number;
  /** Hex-encoded K_local public key of the signing agent */
  signerPubkey: string;
  /** Hex-encoded Ed25519 signature over the canonical leaf content */
  signature: string;
}

// ─── Signaling frame types ───────────────────────────────────────────────────

/**
 * SealInterruptedRequest: initiator → counterparty via directory signaling.
 * Sent when an operator calls cello_close_session on an interrupted session.
 */
export interface SealInterruptedRequest {
  type: "seal_interrupted_request";
  sessionId: string;
  initiatorPubkey: string;
  counterpartyPubkey: string;
  leafCountAtInterruption: number;
  /**
   * Hex-encoded Merkle root the initiator computed at interruption. The
   * initiator's client (the holder of the session Merkle tree) supplies this;
   * the daemon itself does not compute Merkle roots. Carried so the counterparty
   * co-signs over the same root. Empty string when the initiator's client did not
   * supply one (the bilateral commitment then binds leafCount only).
   */
  merkleRootAtInterruption: string;
  /**
   * Liveness nonce. The counterparty MUST echo this back in its ack so the
   * initiator can reject a stale or replayed response (L-2).
   */
  nonce: string;
}

/**
 * SealInterruptedAck: counterparty → initiator via directory signaling.
 * Contains the counterparty's signed SEAL-INTERRUPTED leaf.
 */
export interface SealInterruptedAck {
  type: "seal_interrupted_ack";
  sessionId: string;
  /**
   * Hex-encoded K_local public key of the original initiator. The directory's
   * signaling decoder routes the reply back by looking up this pubkey, so it is
   * REQUIRED on the wire (the directory does not infer it from session state).
   */
  initiatorPubkey: string;
  /**
   * The nonce from the originating SealInterruptedRequest, echoed verbatim. The
   * initiator rejects the ack if this does not match the nonce it sent (L-2).
   */
  nonce: string;
  sealInterruptedLeaf: SealInterruptedLeaf;
}

/**
 * SealInterruptedRejection: counterparty → initiator via directory signaling.
 * The counterparty declines the seal-interrupted request.
 */
export interface SealInterruptedRejection {
  type: "seal_interrupted_rejection";
  sessionId: string;
  /**
   * Hex-encoded K_local public key of the original initiator. The directory's
   * signaling decoder routes the reply back by looking up this pubkey, so it is
   * REQUIRED on the wire (the directory does not infer it from session state).
   */
  initiatorPubkey: string;
  reason: string;
}

/**
 * SessionInterruptedFrame: relay → client control frame.
 * Relay-originated when a participant disconnects mid-session.
 * NOT a seal — no Merkle root, no FROST ceremony.
 */
export interface SessionInterruptedFrame {
  type: "session_interrupted";
  sessionId: string;
  reason: "peer_disconnected" | "timeout";
}

/**
 * Union of seal-interrupted signaling message types.
 * Used by the directory pass-through and the daemon frame handler.
 */
export type SealInterruptedSignalingMessage =
  | SealInterruptedRequest
  | SealInterruptedAck
  | SealInterruptedRejection;
