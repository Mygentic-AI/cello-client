/**
 * CELLO Registration Wire Types — REG-001
 *
 * Phase P — Pseudocode
 * ─────────────────────────────────────────────────────────────────────────────
 * Registration flow (CELLO-REG-001):
 *
 * CLIENT → DIRECTORY (on existing authenticated /cello/signaling/1.0.0 stream):
 *   1. Client generates a 32-byte ML-DSA-44 seed via mlDsaGenerateSeed() and its provider via
 *      mlDsaProviderFromSeed() (NIST FIPS 204; the seed is what is persisted)
 *      and a 64-byte ML-KEM-768 seed via mlKemGenerateSeed(), and PERSISTS both before step 2
 *      (M9D 002-PQKEYS)
 *   2. Client sends register_request { phone_stub, k_local_pubkey, ml_dsa_pubkey, ml_kem_pubkey }
 *
 * DIRECTORY validates:
 *   a. phone_stub non-empty → else register_error { reason: 'invalid_verification' }
 *   b. k_local_pubkey not already in AgentProfile → else register_error { reason: 'already_registered' }
 *   c. SHA-256(phone_stub) not already in any AgentProfile.phone_stub_hash → else register_error { reason: 'phone_already_claimed' }
 *   d. Must be authenticated (signaling_auth_ok) → else register_error { reason: 'not_authenticated' }
 *
 * DIRECTORY triggers FROST DKG:
 *   - Calls bootstrapKeyShares for this agent (test path: createInProcessStubs in NODE_ENV=test)
 *   - In production: real DKG over /cello/frost/1.0.0 streams
 *   - Waits for DKG to complete and primary_pubkey to be derived
 *   - If DKG fails / below threshold → register_error { reason: 'dkg_failed' }
 *
 * CLIENT → DIRECTORY (after local DKG participation):
 *   3. Client runs runNetworkDkg (or createInProcessStubs in test) → primary_pubkey
 *      (this said bootstrapNetworkKeyShares until 2026-09-07; that was the trustedDealer
 *      test shortcut, which threw outside NODE_ENV=test and has now been deleted as dead)
 *   4. Client sends dkg_complete { primary_pubkey, key_binding, key_binding_pq } — the v2 binding
 *      over all four keys, signed by K_local and by the ML-DSA key
 *
 * DIRECTORY verifies dkg_complete:
 *   - Checks primary_pubkey is consistent with the commitments stored during DKG
 *   - If mismatch → register_error { reason: 'dkg_verification_failed' }
 *   - Verifies BOTH binding signatures (verifyKeyBinding) against the signaling-authenticated K_local
 *   - If either fails → register_error { reason: 'key_binding_refused', detail: <KeyBindingRefusal> },
 *     and no profile is stored
 *
 * DIRECTORY on success:
 *   - Generates 16-byte CSPRNG agent_id
 *   - Stores AgentProfile { k_local_pubkey, primary_pubkey, ml_dsa_pubkey, ml_kem_pubkey, key_binding,
 *     key_binding_pq, phone_stub_hash: SHA-256(phone_stub), ... } — the PQ keys are never rewritten
 *   - NEVER stores raw phone_stub (SI-001)
 *   - Sends register_success { agent_id, primary_pubkey }
 *
 * CLIENT on register_success:
 *   - Stores RegistrationState locally
 *   - register() returns RegistrationState
 *   - Subsequent register() calls return { error: 'already_registered' }
 *
 * Phone stub SHA-256: per FIPS 180-4
 * ML-DSA keypair: per NIST FIPS 204 (ML-DSA-44, 1312-byte public key)
 * primary_pubkey: derived from FROST DKG ceremony (RFC 9591)
 *
 * Security invariants:
 *   SI-001: phone_stub raw value NEVER stored, logged, or returned in any error
 *   SI-002: no profile created without successful FROST DKG with verified primary_pubkey
 *   SI-003: FROST DKG shares NEVER appear in wire messages, logs, profiles, or API responses
 *   SI-004: register_request rejected with not_authenticated if auth not completed
 * ─────────────────────────────────────────────────────────────────────────────
 */

// ─── Direction: client → directory ───────────────────────────────────────────

/**
 * Step 1: Client requests registration. Sent on the authenticated signaling stream.
 * SI-004: The stream must have completed signaling_auth_ok before this frame is processed.
 */
export interface RegisterRequest {
  type: "register_request";
  /** Phone stub — validated non-empty by directory. Raw value NEVER persisted. */
  phone_stub: string;
  /** Hex-encoded K_local public key (32 bytes) */
  k_local_pubkey: string;
  /** Hex-encoded ML-DSA-44 public key (1312 bytes, NIST FIPS 204) */
  ml_dsa_pubkey: string;
  /**
   * M9D 002-PQKEYS. Hex-encoded ML-KEM-768 public key (1184 bytes, NIST FIPS 203) — what content
   * sealed to this agent is encapsulated to. Minted and persisted on this machine BEFORE this frame
   * is sent, and fixed for the life of the agent.
   */
  ml_kem_pubkey: string;
  /**
   * M8B quorum registration: nodeIds (stable manifest labels, e.g. "us-east-1") of the consortium
   * directory nodes the client resolved / can reach right now (its live roster). The directory picks the
   * DKG quorum Q from this set ∩ its own signed manifest, requiring |Q| ≥ T = majority(N) = floor(N/2)+1.
   * Absent on the local single-node path (no manifest).
   */
  reachable_node_ids?: string[];
  /** True when this identity is a broadcast channel (publish-only; never converses).
   *  Immutable after registration. Omitted entirely for ordinary agents. */
  channel?: true;
  /** Hex-encoded 32-byte pubkey of the administering agent. REQUIRED when channel is set;
   *  must be absent otherwise. Immutable after registration. */
  admin_pubkey?: string;
  /**
   * How this channel admits readers. Only meaningful with `channel`, and must be absent otherwise.
   *
   * ⚠️ **WITHOUT THIS A PUBLIC CHANNEL COULD NOT EXIST.** The relay decides whether a fetch needs
   * the group key, and the only thing it can ask is the directory's channel identity. With no
   * `access` there, it fell back to the least privileged reading — `open`, meaning a key is
   * required — so the `public` branch was reachable only from a test fixture. 017 raised this in a
   * code comment naming order 019; it was never written into 019's text, so it fell between orders
   * and was still missing after 020.
   *
   * Absent means `open`, which is what every channel registered before this shipped already is.
   */
  access?: "public" | "open" | "invite_only";
}

/**
 * Step 2: Client completes local DKG and sends primary_pubkey.
 * Sent after client receives the DKG material and derives the group public key.
 * primary_pubkey is derived from FROST commitments (RFC 9591).
 */
export interface DkgComplete {
  type: "dkg_complete";
  /** Hex-encoded FROST group public key (32 bytes). Derived from DKG commitments. */
  primary_pubkey: string;
  /**
   * 038-KEYBIND. Hex-encoded 64-byte Ed25519 signature by this agent's K_local over the key-binding
   * TBS (`buildKeyBindingTbs`) under `CONTEXT_KEY_BINDING`.
   *
   * THIS FRAME IS THE ONLY MOMENT IT CAN BE MADE. At agent creation the group key does not exist
   * yet; after registration the DKG is over. This is the one point where both keys are on the
   * machine together, and no re-DKG is ever needed to produce it again — the group key is preserved
   * across key refresh, so it is signed once for the life of the agent.
   *
   * The directory stores it and serves it on every session assignment. It cannot forge one (it
   * holds no K_local) and it cannot swap one (the binding names the identity it belongs to).
   *
   * M9D 002-PQKEYS: the signed bytes are the v2 TBS naming all four keys — K_local, the group key,
   * the ML-DSA key and the ML-KEM key (`buildKeyBindingTbs`).
   */
  key_binding: string;
  /**
   * M9D 002-PQKEYS. Hex-encoded 2420-byte ML-DSA-44 signature by this agent's ML-DSA key over the
   * SAME v2 TBS, under `cello-mldsa-key-binding-v1`. The directory refuses the registration unless
   * both this and `key_binding` verify.
   */
  key_binding_pq: string;
}

// ─── Direction: directory → client ───────────────────────────────────────────

/**
 * Directory authorizes the client to open DKG streams.
 * Sent on the signaling stream after register_request is validated (steps 1–3 pass).
 * Client opens /cello/frost/1.0.0 streams to each directory node and runs the DKG rounds.
 * RFC 9591 §5 (FROST DKG), sent before client opens DKG streams.
 */
export interface DkgReady {
  type: "dkg_ready";
  /** Epoch ID for this DKG instance: "${k_local_pubkey}:epoch:1" */
  epochId: string;
  /**
   * M8B quorum: the size of the DKG quorum Q the directory picked (directory nodes = |Q|; total FROST
   * participants = |Q| + 1 client). The directory sets this to |R ∩ manifest| from the client's
   * `reachable_node_ids`. The client already knows Q's identities (Q == its resolved roster), so only the
   * count crosses the wire — the client validates `roster.length === participants` (which also catches
   * manifest version skew) before fanning the DKG.
   */
  participants: number;
  /** Minimum threshold for signing (T = majority(N) = floor(N/2)+1, counts the client). */
  threshold: number;
}

/**
 * Directory confirms successful registration.
 * primary_pubkey here is the canonical value stored in the AgentProfile.
 */
export interface RegisterSuccess {
  type: "register_success";
  /** Hex-encoded 16-byte CSPRNG agent ID */
  agent_id: string;
  /** Hex-encoded FROST group public key (32 bytes) — confirms what directory stored */
  primary_pubkey: string;
  /**
   * DOD-M15-SEALPARTIES-1 Part 0 — the relay credential for the agent that has just registered.
   *
   * The token normally rides `signaling_auth_ok`, but a registering agent opens its signaling
   * stream in order TO register (the DKG runs over it), so that auth happens while the directory
   * still has no profile for the key and correctly issues nothing. A healthy stream never
   * re-authenticates, so this is the first — and often the only — moment the answer changes.
   *
   * Absent when the directory could not mint one; registration still succeeded, and the agent
   * picks a token up on its next signaling reconnect.
   */
  online_token?: Uint8Array;
  /** Echoed by the directory when the profile was stored with channel = true. A client
   *  registering a channel MUST refuse success without this echo. */
  channel?: true;
  /**
   * M16 024-CREATE: the two relay multiaddrs the directory picked for this CHANNEL from its own
   * relay pool. Nobody types a relay — the directory chooses two DISTINCT relays at registration
   * and returns them here, and the client records them as the channel's relays. Present only for a
   * channel registration; a pool with fewer than two relays refuses the registration rather than
   * returning one.
   */
  relays?: string[];
}

/**
 * Directory rejects registration.
 * SI-001: reason field NEVER carries raw phone_stub.
 *
 * `already_registered` carries the stored profile's keys so the client can reconstruct its state —
 * all REQUIRED on that variant (M9D 002-PQKEYS: no optional post-quantum fields). Every other reason
 * carries none of them.
 */
export type RegisterError = RegisterErrorAlreadyRegistered | RegisterErrorOther;

export interface RegisterErrorAlreadyRegistered {
  type: "register_error";
  reason: "already_registered";
  agent_id: string;
  primary_pubkey: string;
  /** Hex ML-DSA-44 public key the directory holds for this agent (1312 bytes). */
  ml_dsa_pubkey: string;
  /** Hex ML-KEM-768 public key the directory holds for this agent (1184 bytes). */
  ml_kem_pubkey: string;
}

export interface RegisterErrorOther {
  type: "register_error";
  reason: Exclude<RegisterErrorReason, "already_registered">;
  /** For `key_binding_refused`: the `KeyBindingRefusal` naming which check failed. */
  detail?: string;
}

export type RegisterErrorReason =
  | "already_registered"     // same k_local_pubkey already has a profile
  | "phone_already_claimed"  // SHA-256(phone_stub) matches an existing profile
  | "invalid_verification"   // phone_stub is empty or otherwise invalid
  | "dkg_failed"             // FROST DKG below threshold or ceremony failure
  | "not_authenticated"      // register_request arrived before signaling_auth_ok
  | "dkg_verification_failed" // primary_pubkey from dkg_complete doesn't match DKG commitments
  | "invalid_channel_registration" // channel/admin_pubkey fields malformed or inconsistent
  | "key_binding_refused";   // M9D 002-PQKEYS: the v2 binding's Ed25519 or ML-DSA signature did not verify

// ─── AgentProfile (stored in DirectoryStore) ────────────────────────────────

/**
 * Stored profile for a registered agent.
 * Created only after successful FROST DKG (SI-002).
 * phone_stub_hash = SHA-256(phone_stub) per FIPS 180-4 — raw phone_stub never stored (SI-001).
 */
export interface AgentProfile {
  /** Hex-encoded K_local public key (32 bytes) — primary lookup key */
  k_local_pubkey: string;
  /** Hex-encoded FROST group public key (32 bytes) */
  primary_pubkey: string;
  /** Hex-encoded ML-DSA-44 public key (1312 bytes, FIPS 204) */
  ml_dsa_pubkey: string;
  /** M9D 002-PQKEYS. Hex-encoded ML-KEM-768 public key (1184 bytes, FIPS 203). Immutable. */
  ml_kem_pubkey: string;
  /** Hex SHA-256(phone_stub) — 32 bytes per FIPS 180-4. Raw phone_stub NEVER stored. */
  phone_stub_hash: string;
  /** Extensible agent profile data — empty in M3 */
  profile: Record<string, unknown>;
  /** Unix ms timestamp of registration */
  registered_at: number;
  /** Profile status */
  status: "active";
  /** Hex-encoded 16-byte CSPRNG agent ID */
  agent_id: string;
  /**
   * 038-KEYBIND, v2 since M9D 002-PQKEYS. Hex 64-byte Ed25519 signature by this agent's K_local over
   * the v2 TBS naming all four keys, taken from `dkg_complete`.
   *
   * The directory VERIFIES it at registration (with `key_binding_pq`) and refuses to store a profile
   * whose binding fails, then serves it on every session assignment. It can neither produce nor alter
   * one, because the signers are keys no directory holds — the only thing it can do is withhold it,
   * and both clients refuse a session assignment that arrives without one.
   */
  key_binding: string;
  /** M9D 002-PQKEYS. Hex 2420-byte ML-DSA-44 signature over the same v2 TBS. Required. */
  key_binding_pq: string;
  /** True when this identity is a broadcast channel. Immutable. */
  channel: boolean;
  /** Hex admin pubkey when channel === true; "" otherwise. Immutable. */
  admin_pubkey: string;
  /**
   * M16 021-WAKE: how this channel admits readers, when `channel === true`. Immutable.
   *
   * ⚠️ **OPTIONAL ON THE TYPE, AND ABSENT MEANS `open`.** `open` still requires the group key to
   * fetch; `public` does not. So an unstated access takes the MORE private reading.
   */
  channel_access?: "public" | "open" | "invite_only";
}

// ─── RegistrationState (stored locally by client) ────────────────────────────

/**
 * Local registration state persisted by the client after register_success.
 * Returned by CelloClient.register().
 */
export interface RegistrationState {
  /** Hex-encoded 16-byte agent ID from the directory */
  agent_id: string;
  /** Hex-encoded FROST group public key (32 bytes) */
  primary_pubkey: string;
  /** Hex-encoded ML-DSA-44 public key (1312 bytes) */
  ml_dsa_pubkey: string;
  /** M9D 002-PQKEYS. Hex-encoded ML-KEM-768 public key (1184 bytes) */
  ml_kem_pubkey: string;
  /** Unix ms timestamp of registration */
  registered_at: number;
  /** Registration status */
  status: "active";
}
