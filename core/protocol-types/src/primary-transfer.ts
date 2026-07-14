/**
 * CELLO Primary/Standby Transfer Wire Types
 *
 * Design: docs/planning/user-stories/m8c/M8C-PRIMARY-DESIGN.md (Decision 4).
 * Mirrors registration.ts's DKG protocol shape exactly — CELLO has no cross-node RPC/consensus
 * anywhere; "exactly one Primary" is enforced by the SAME pattern DKG already uses: the daemon
 * (client) dials each of T-of-N directory nodes holding the agent's FROST shares directly, and
 * each node independently verifies + records the claim locally. There is no directory-to-directory
 * frame here — only client-to-directory, repeated per node.
 *
 * Protocol flow
 * ─────────────────────────────────────────────────────────────────────────────
 * Primary-transfer flow (on the authenticated /cello/signaling/1.0.0 stream, once per
 * directory node the daemon dials):
 *
 * CLIENT (new Primary) → DIRECTORY (one node):
 *   1. Client sends primary_transfer_request { k_local_pubkey, new_daemon_id, old_daemon_id,
 *      nonce, timestamp, release_signature }. release_signature is a REAL FROST threshold
 *      signature (core/crypto's participateInCeremony, context CONTEXT_PRIMARY_RELEASE — see
 *      core/crypto/src/frost/types.ts) produced by the OLD Primary over canonical-bytes
 *      (k_local_pubkey, new_daemon_id, old_daemon_id, nonce, timestamp). This is NOT a K_local
 *      signature (both daemons share K_local after pairing, per Decision 1 — a K_local signature
 *      cannot distinguish which physical device produced it). A FROST signature under this
 *      context can ONLY be produced by a device that currently holds the agent's FROST share —
 *      exactly the property that distinguishes a genuine old Primary from a Standby that never
 *      received the share (Decision 3).
 *
 * DIRECTORY validates (per node, independently):
 *   a. old_daemon_id matches THIS node's own currently-recorded primary_holder.holding_daemon_id
 *      → else primary_transfer_error { reason: "not_registered" } (a stale/wrong claim about who
 *      is releasing is rejected before any cryptographic check)
 *   b. release_signature verifies via verifySignature(release_signature, tbs, CONTEXT_PRIMARY_RELEASE,
 *      primary_pubkey) against THIS node's own recorded primary_pubkey for k_local_pubkey → else
 *      primary_transfer_error { reason: "release_not_verified" }
 *   c. nonce not already consumed at this node (single-use, mirrors the pre-auth capability's
 *      consumed_at pattern) → else primary_transfer_error { reason: "nonce_reused" }
 *   d. timestamp within a bounded freshness window (replay defense) → else
 *      primary_transfer_error { reason: "stale_request" }
 *
 * DIRECTORY on success (this node only):
 *   - Upserts its own local primary_holder row: holding_daemon_id = new_daemon_id,
 *     last_attested_at = now()
 *   - Sends primary_transfer_ack { node_id } — the daemon tallies acks per Decision 4; T-of-N acks
 *     is what "transfer complete" means, never a cross-node signal
 *
 * CLIENT tallies primary_transfer_ack across its T-of-N dial attempts (mirrors exactly how it
 * already tallies DKG-round successes when driving DKG per-node) and does not proceed to resume as
 * Primary (attempt a FROST ceremony, accept new sessions) until T acks are collected.
 *
 * Ceremony-gate check (separate, existing FROST signing-request path, extended): a directory node
 * refuses to let a ceremony proceed through its own participation unless the requesting
 * connection's daemon_id matches that node's own primary_holder.holding_daemon_id.
 *
 * Security invariants:
 *   SI-001: release_signature MUST be a real FROST threshold signature under CONTEXT_PRIMARY_RELEASE
 *     (verified against the node's own recorded primary_pubkey) — NEVER a K_local signature or any
 *     signature a Standby (K_local-holder, non-share-holder) could produce.
 *   SI-002: nonce is single-use per node (replay defense, mirrors the existing pre-auth capability
 *     `consumed_at` pattern already proven in production).
 *   SI-003: this frame set carries NO secret material — no FROST share, no K_local seed. The share
 *     itself is never transmitted to the directory (M8C-PRIMARY-DESIGN Decision 3); the directory
 *     only ever sees a threshold signature it can verify, never anything it could use to forge one.
 *   SI-004: old_daemon_id is checked against this node's OWN recorded holder before any
 *     cryptographic verification — an attacker cannot substitute a fabricated old_daemon_id and
 *     hope the signature check alone catches it (defense in depth, cheap check first).
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { encodeCbor } from "./cbor.js";


/** Domain separation tag — bound as the first TBS field so a primary-transfer release signature
 *  can never be replayed as any other CELLO signature (and vice-versa) even before FROST's own
 *  CONTEXT_PRIMARY_RELEASE domain separation is applied — belt and suspenders, matching the
 *  existing AGENT_REVOCATION_DOMAIN convention (revocation.ts). */
export const PRIMARY_TRANSFER_DOMAIN = "CELLO-PRIMARY-TRANSFER-v1";

/**
 * Canonical to-be-signed bytes for a primary-transfer release attestation (M8C-PRIMARY-DESIGN
 * Decision 3). Field order is LOAD-BEARING — both the signer (the old Primary daemon,
 * via participateInCeremony) and every verifier (each directory node, via verifySignature) must
 * produce IDENTICAL bytes, or verification never succeeds regardless of whether the ceremony
 * itself was genuine. Mirrors buildAgentRevocationTbs's exact structure (revocation.ts).
 */
export function buildPrimaryTransferTbs(
  kLocalPubkeyHex: string,
  newDaemonId: string,
  oldDaemonId: string,
  nonce: string,
  timestamp: number | bigint,
): Uint8Array {
  // Past 0xffffffff, cbor-x encodes a JS `number` as an IEEE float64 (`fb`), not a uint64 (`1b`) —
  // so a MILLISECOND timestamp (Date.now() ≈ 1.77e12, which is what a caller will reach for) would
  // be hashed as a float, and any non-cbor-x verifier would compute different TBS bytes and reject a
  // genuine transfer. buildSealTbs (session.ts:160,271) and buildAgentRevocationTbs
  // (revocation.ts:39) both carry this coercion; this builder shipped without it.
  //
  // Safe to add now: there is no client-side sender yet (`primary_transfer_request` has no producer
  // in cello-client), so no signature exists over these bytes, and every timestamp below 2^32
  // encodes byte-identically to before.
  const tsEncoded = typeof timestamp === "bigint" || timestamp > 0xffffffff ? BigInt(timestamp) : timestamp;
  return encodeCbor([
    PRIMARY_TRANSFER_DOMAIN,
    kLocalPubkeyHex,
    newDaemonId,
    oldDaemonId,
    nonce,
    tsEncoded,
  ]) as Uint8Array;
}

// ─── Direction: client → directory (repeated once per T-of-N node dialed) ────

/**
 * Step 1: the new Primary attests a transfer to one directory node. Sent on that node's
 * authenticated signaling stream. The daemon repeats this per node it dials.
 */
export interface PrimaryTransferRequest {
  type: "primary_transfer_request";
  /** Hex-encoded K_local public key (32 bytes) — the shared identity both daemons hold. */
  k_local_pubkey: string;
  /** Fresh per-device UUID identifying the daemon CLAIMING Primary status. */
  new_daemon_id: string;
  /** The per-device UUID of the daemon RELINQUISHING Primary status. */
  old_daemon_id: string;
  /**
   * Hex-encoded 64-byte FROST threshold signature (core/crypto's participateInCeremony, context
   * CONTEXT_PRIMARY_RELEASE) over canonical-bytes(k_local_pubkey, new_daemon_id, old_daemon_id,
   * nonce, timestamp), produced by the OLD Primary. Verified via verifySignature(...,
   * CONTEXT_PRIMARY_RELEASE, primary_pubkey) — proves genuine possession of the FROST share at
   * release time (SI-001). NOT a K_local signature — see the module doc above for why.
   */
  release_signature: string;
  /** Single-use nonce (SI-002) — mirrors the existing pre-auth capability pattern. */
  nonce: string;
  /** Unix ms timestamp — bounds replay window (freshness check, not itself the security boundary). */
  timestamp: number;
}

// ─── Direction: directory → client ───────────────────────────────────────────

/**
 * This node has recorded new_daemon_id as the current Primary holder for k_local_pubkey. This is
 * a PER-NODE acknowledgment, never a cross-node commit signal — the client tallies these across
 * its T-of-N dial attempts (M8C-PRIMARY-DESIGN Decision 4).
 */
export interface PrimaryTransferAck {
  type: "primary_transfer_ack";
  /** The stable manifest label of the node that accepted (e.g. "us-east-1"). */
  node_id: string;
}

/**
 * This node rejected the transfer request. SI-001/SI-002/SI-004/freshness failures all surface
 * here with a distinct, named reason — never a generic failure.
 *
 * `internal_error` is distinct from the four PERMANENT rejections: it means "this node could not
 * complete the request due to a transient/infrastructure fault (DB unavailable, persist failed),
 * NOT that the claim was invalid — retry may succeed." The new-Primary daemon tallying T-of-N acks
 * must treat it as retriable, not as a genuine holder-mismatch that would (wrongly) drop this node
 * from the quorum tally and fail an otherwise-valid transfer.
 */
export interface PrimaryTransferError {
  type: "primary_transfer_error";
  reason: "release_not_verified" | "nonce_reused" | "stale_request" | "not_registered" | "internal_error";
}
