/**
 * CELLO-M7-REMOVE-001 (DOD-REMOVE-2) — agent revocation wire shapes + canonical TBS.
 *
 * Removal is recorded at the directory as an APPEND-ONLY, SELF-SIGNED revocation fact (design log
 * §5 removal = revocation-not-erasure; §13 guardrail #5). The agent signs a canonical "to-be-signed"
 * byte string with its OWN K_local (Ed25519, RFC 8032); the directory verifies it against the agent's
 * registered K_local before appending, and the signature is stored so ANY sovereign node can
 * re-verify the fact independently (AC-002).
 *
 * The TBS is keyed by the DIRECTORY-known agent_id (agent_profiles.agent_id), never a pubkey
 * (guardrail #1 — pubkeys rotate). The k_local_pubkey bound in the TBS is the directory-RESOLVED
 * registered key (the verifier never trusts a client-supplied key).
 *
 * Cross-repo (M7-WIRE-001 convention): the directory keeps a BYTE-IDENTICAL local copy of
 * buildAgentRevocationTbs until a publish ships this helper to it; a drift-guard test + the live spine
 * (sign here / verify there) catch any divergence.
 */

import { Encoder } from "cbor-x";

// Same config as session.ts buildSessionEstablishmentTbs — tagUint8Array:false so byte strings encode
// as definite-length CBOR byte strings (stable, encoder-independent layout).
const CBOR_ENC = new Encoder({ tagUint8Array: false });

/** Domain separation tag — bound as the first TBS field so a revocation signature can never be
 *  replayed as any other CELLO signature (and vice-versa). */
export const AGENT_REVOCATION_DOMAIN = "CELLO-REVOKE-v1";

/**
 * Canonical to-be-signed bytes for an agent revocation. Field order is LOAD-BEARING — both the
 * signer (daemon) and the verifier (directory, and any re-verifying node) must produce identical
 * bytes. All fields are recoverable from the stored agent_revocations row + agent_profiles, so the
 * fact stays re-verifiable forever.
 */
export function buildAgentRevocationTbs(
  agentId: string,
  kLocalPubkeyHex: string,
  epochId: string,
  reason: string,
  revokedAt: number | bigint,
): Uint8Array {
  const tsEncoded = typeof revokedAt === "bigint" || revokedAt > 0xffffffff ? BigInt(revokedAt) : revokedAt;
  return CBOR_ENC.encode([
    AGENT_REVOCATION_DOMAIN,
    agentId,
    kLocalPubkeyHex,
    epochId,
    reason,
    tsEncoded,
  ]) as Uint8Array;
}

// ─── Wire frames (client → directory, on the authenticated /cello/signaling/1.0.0 stream) ────────

/**
 * Client asks the directory to record a revocation of its OWN agent. Sent on the K_local-authenticated
 * signaling stream; `signature` is over buildAgentRevocationTbs(agent_id, <registered k_local_pubkey>,
 * epoch_id ?? "", reason ?? "", revoked_at), signed by the agent's K_local.
 */
export interface RevokeAgentRequest {
  type: "revoke_agent";
  /** The DIRECTORY-assigned agent_id (agent_profiles.agent_id) being revoked. */
  agent_id: string;
  /** Optional key-epoch id (nullable in the agent_revocations row). */
  epoch_id?: string;
  /** Optional informational reason (e.g. "voluntary"). Never carries secrets. */
  reason?: string;
  /** Revocation timestamp (ms since epoch) — stored as BIGINT revoked_at. */
  revoked_at: number;
  /** Hex Ed25519 signature over the canonical TBS, by the agent's own K_local. */
  signature: string;
}

/** Directory confirms the revocation was verified and appended (idempotent — also returned if it was
 *  already recorded). */
export interface AgentRevocationAck {
  type: "agent_revocation_ack";
  agent_id: string;
}

/** Directory refuses to record the revocation. Nothing is written (SI-001). */
export interface AgentRevocationError {
  type: "agent_revocation_error";
  reason: AgentRevocationErrorReason;
  agent_id?: string;
}

export type AgentRevocationErrorReason =
  | "unknown_agent" // no agent_profiles row for agent_id
  | "not_self_authorized" // the authenticated stream key is not the agent's own registered K_local
  | "signature_invalid" // the signature does not verify against the registered K_local
  | "malformed" // missing/invalid fields in the request
  | "persist_failed"; // verified, but the durable write failed — caller should defer + retry
