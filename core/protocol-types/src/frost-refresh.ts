/**
 * FROST Proactive Share Resharing (PSS) Wire Frame Types — M8B DOD-REFRESH-1.
 *
 * Exchanged on /cello/frost/1.0.0 streams during a proactive share refresh: every current shareholder
 * (the client + each directory node) adds a zero-constant-term polynomial δ_i to its share, rotating all
 * shares to a new epoch while keeping the group public key (commitments[0]) UNCHANGED. A share captured in
 * epoch e is useless in e+1. Crypto core: `@cello-protocol/crypto` frost-resharing.ts (Herzberg et al.
 * 1995; RFC 9591 Appendix C VSS commitments).
 *
 * Unlike DKG (3 interdependent rounds), a refresh contribution is generated INDEPENDENTLY (δ_i is a fresh
 * random zero-constant polynomial that does not depend on any other party), so the protocol is TWO rounds,
 * client-coordinated:
 *
 *   Round 1 (contribute): client asks each node to generate its refresh contribution for the NEW epoch
 *            → each node returns { fromId, commitment[] (C[0]=identity), subShares{ j → δ_i(j) } }
 *   Round 2 (apply):      client distributes the AGREED contribution set — to node j it sends, for every
 *            contributor i, { fromId:i, commitment:C_i, subShares:{ j → δ_i(j) } } (j's sub-share ONLY;
 *            other parties' sub-shares are NOT disclosed) → each node verifies the full roster + Feldman-
 *            checks each sub-share + applies → stores its NEW-epoch share and returns its shareCommitment.
 *
 * The client is the single uniform relay: it collects ONE commitment per party in Round 1 and distributes
 * the IDENTICAL commitment set to every node in Round 2, which structurally prevents a directory from
 * equivocating (the agent's own client node is the trusted aggregator). The coordinator verifies every
 * node returns the SAME shareCommitment (= the unchanged group key) before accepting, and a post-refresh
 * verification signature confirms the rotated shares are coherent (no divergence) before the epoch advances.
 *
 * DISTINCT from DKG frames (frost_dkg_round{1,2,3}) and signing frames (frost_commit/sign_*).
 *
 * Crypto reference: RFC 9591 (FROST / VSS), RFC 8032 (Ed25519).
 */

// ─── Shared data shape ──────────────────────────────────────────────────────────

/**
 * One party's refresh contribution. Mirrors `RefreshContribution` in @cello-protocol/crypto.
 * In Round 1 responses, `subShares` carries δ_i(j) for EVERY participant j (the contributor produced them
 * all). In Round 2 requests, the client narrows each contribution's `subShares` to ONLY the recipient
 * node's entry, so a node never sees sub-shares addressed to other parties.
 */
export interface FrostRefreshContribution {
  /** The contributing party's FROST identifier (32-byte LE scalar hex). */
  fromId: string;
  /** Feldman VSS commitments C[k] = a_k·G, length T. C[0] is the curve identity (zero constant term). */
  commitment: Uint8Array[];
  /** δ_i(j) per participant identifier j (32-byte LE scalar). Round 1: all j. Round 2: only the recipient. */
  subShares: Record<string, Uint8Array>;
}

// ─── Round 1 — contribute ─────────────────────────────────────────────────────

/**
 * Client → Directory: generate this node's refresh contribution for the NEW epoch.
 * The node MUST already hold a share for `fromEpochId` (the epoch being refreshed); it generates a fresh
 * zero-constant polynomial over `participantIds` and returns its contribution. No share is rotated yet.
 */
export interface FrostRefreshRound1Request {
  type: "frost_refresh_round1_request";
  /** Hex-encoded K_local public key. */
  agentPubkey: string;
  /** The epoch being refreshed FROM, e.g. "${agentPubkey}:epoch:1" (the node must hold this share). */
  fromEpochId: string;
  /** The epoch being refreshed TO, e.g. "${agentPubkey}:epoch:2". */
  toEpochId: string;
  /** Threshold parameters of the group (min = T, max = participants + 1). */
  signers: { min: number; max: number };
  /** Every shareholder's FROST identifier (client + all directory nodes) — the agreed full roster. */
  participantIds: string[];
}

export interface FrostRefreshRound1ResponseOk {
  type: "frost_refresh_round1_response";
  ok: true;
  /** The node's contribution: commitment (C[0]=identity) + δ(j) for every participant j. */
  contribution: FrostRefreshContribution;
}

export interface FrostRefreshRound1ResponseErr {
  type: "frost_refresh_round1_response";
  ok: false;
  reason:
    | "source_epoch_not_held" // node has no share for fromEpochId — nothing to refresh
    | "already_in_progress" // a refresh for this agent/epoch is already running
    | "agent_suspended" // refusing to refresh a suspended/burned agent
    | "internal_error";
}

export type FrostRefreshRound1Response = FrostRefreshRound1ResponseOk | FrostRefreshRound1ResponseErr;

// ─── Round 2 — apply ──────────────────────────────────────────────────────────

/**
 * Client → Directory: deliver the AGREED full contribution set so the node can apply the refresh.
 * `contributions` contains one entry per participant (the complete roster); each entry's `subShares`
 * carries ONLY this node's sub-share δ_i(thisNode). The node verifies completeness + Feldman-checks each
 * sub-share, then computes its new share s'_j = s_j + Σ_i δ_i(j), stores it under `toEpochId`, advances its
 * current epoch, and returns its resulting group-key commitment (which must be UNCHANGED).
 */
export interface FrostRefreshRound2Request {
  type: "frost_refresh_round2_request";
  agentPubkey: string;
  fromEpochId: string;
  toEpochId: string;
  signers: { min: number; max: number };
  /** Every shareholder's identifier — the node verifies the contribution set matches this exactly. */
  participantIds: string[];
  /** The full agreed contribution set; each entry's subShares holds only the receiving node's sub-share. */
  contributions: FrostRefreshContribution[];
}

export interface FrostRefreshRound2ResponseOk {
  type: "frost_refresh_round2_response";
  ok: true;
  /**
   * The node's group public key after applying the refresh — 32-byte Ed25519 point (commitments[0]).
   * The coordinator verifies every node (and the client) returns the SAME value AND that it equals the
   * pre-refresh group key. Any mismatch aborts the refresh (the old epoch stays current).
   */
  shareCommitment: Uint8Array;
}

export interface FrostRefreshRound2ResponseErr {
  type: "frost_refresh_round2_response";
  ok: false;
  reason:
    | "incomplete_roster" // contributions did not cover every participant exactly
    | "vss_check_failed" // a sub-share was inconsistent with its commitment, or a non-zero constant term
    | "source_epoch_not_held"
    | "agent_suspended"
    | "internal_error";
}

export type FrostRefreshRound2Response = FrostRefreshRound2ResponseOk | FrostRefreshRound2ResponseErr;

// ─── Union types ──────────────────────────────────────────────────────────────

export type FrostRefreshRequest = FrostRefreshRound1Request | FrostRefreshRound2Request;

export type FrostRefreshResponse = FrostRefreshRound1Response | FrostRefreshRound2Response;
