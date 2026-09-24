/**
 * Daemon registration persistence — CELLO-M7-REGISTRATION.
 *
 * The seam the RegistrationManager persists through: each agent's post-quantum identity (ML-DSA and
 * ML-KEM seeds), FROST key share and registration state. The one implementation is
 * `DbRegistrationPersistence` (db-identity-store.ts), which writes the agent's row in the SQLCipher
 * `agents` table. CELLO keeps secrets in SQLCipher only.
 *
 * M9D 002-PQKEYS deleted the file-backed implementation that wrote the ML-DSA secret as hex into a
 * plaintext JSON file. No production code constructed it.
 *
 * The FROST signing share (SI-001) and the post-quantum seeds (SI-002) must never appear in a log
 * event.
 */

// ─── Loaded record shapes (returned by load* on restart) ─────────────────────

export interface RegistrationStateRecord {
  agentId: string;
  primaryPubkey: string;
  mlDsaPubkey: string;
  /** M9D 002-PQKEYS: the ML-KEM-768 public key the directory registered (hex, 1184 bytes). */
  mlKemPubkey: string;
  registeredAt: number;
  status: string;
  /**
   * 038-KEYBIND. Hex 64-byte Ed25519 signature by this agent's K_local over the v2 key-binding TBS
   * (all four keys, M9D 002-PQKEYS). Null for an agent whose row predates the column.
   *
   * ⚠️ **WRITTEN, AND READ BY NOTHING YET** — said plainly rather than implied, because the careful
   * null-handling around it otherwise reads as a decision some caller acts on, and no caller
   * exists. The live copy is the one on the DIRECTORY's profile, which is what rides on every
   * session assignment; this is the agent's own record of what it signed, kept so a future
   * re-upload does not have to re-derive it from a value a directory supplied.
   */
  keyBinding: string | null;
  /** M9D 002-PQKEYS: the ML-DSA half of the v2 binding (hex, 2420 bytes). Null only for a row with no binding. */
  keyBindingPq: string | null;
  /**
   * M16: true when this identity is a broadcast channel. Recorded at registration from what the
   * directory ECHOED, never changed. False for an ordinary agent and for a record written without it.
   */
  channel: boolean;
  /** M16: hex pubkey of the agent that administers this channel; "" when `channel` is false. */
  adminPubkey: string;
}

/**
 * M9D 002-PQKEYS — an agent's post-quantum identity: the two seeds and the public keys they derive.
 * Written before `register_request` is sent, fixed for the life of the agent, never regenerated.
 * Losing either seed means registering a new identity, the same as losing K_local.
 */
export interface PqIdentityRecord {
  /** 32-byte FIPS 204 seed ξ. */
  mlDsaSeed: Uint8Array;
  /** Hex ML-DSA-44 public key (1312 bytes). */
  mlDsaPubkey: string;
  /** 64-byte FIPS 203 seed d‖z. */
  mlKemSeed: Uint8Array;
  /** Hex ML-KEM-768 public key (1184 bytes). */
  mlKemPubkey: string;
}

/**
 * What is stored for the post-quantum identity, AS STORED — each half independently, because a row
 * holding one seed and not the other is a fault the caller must name, not a shape to paper over.
 */
export interface StoredPqIdentity {
  mlDsaSeed: Uint8Array | null;
  mlDsaPubkey: string | null;
  mlKemSeed: Uint8Array | null;
  mlKemPubkey: string | null;
}

export interface FrostKeyShareRecord {
  epochId: string;
  primaryPubkey: string;
  identifier: string;
  signingShare: Uint8Array;
  threshold: number;
  participants: number;
  commitmentsCbor: Uint8Array;
  verifyingSharesCbor: Uint8Array;
  dkgMethod: string;
  /** M8B quorum: the directory nodeIds (Q) the DKG ran among; a restored signer targets these. */
  directoryNodeIds?: string[];
}

/**
 * The agent→user linkage captured at registration. The pre-authorization ticket
 * (issued by the CELLO Operations Agent) binds this agent to a user; recording it
 * here is the M7 "capture-now-or-lose-it" requirement — *using* the link (trust
 * signals that attach to the user) is future trust-layer work.
 */
export interface AgentUserLinkRecord {
  agentId: string;
  preAuthToken: string;
  linkedAt: number;
}

/**
 * Narrow persistence seam consumed by the daemon's RegistrationManager. Exactly
 * the three persist operations the registration flow performs, plus the matching
 * load operations needed to rehydrate an already-registered agent on restart.
 */
export interface DaemonRegistrationPersistence {
  /**
   * M9D 002-PQKEYS. Persist the post-quantum identity BEFORE registration is attempted. The ML-DSA
   * half is written first, then the ML-KEM half, so a failure names which one did not land
   * (`ml_dsa_persist_failed` / `ml_kem_persist_failed` in the thrown message).
   */
  persistPqIdentity(record: PqIdentityRecord): Promise<void>;
  persistRegistrationState(opts: {
    agentId: string;
    primaryPubkey: string;
    mlDsaPubkey: string;
    mlKemPubkey: string;
    registeredAt: number;
    /**
     * 038-KEYBIND. The binding minted at the tail of registration, hex. Persisted BESIDE the share
     * because it is the same kind of artifact: produced once, for the life of the agent, from key
     * material that is only ever together on this machine.
     */
    keyBinding: string;
    /** M9D 002-PQKEYS: the ML-DSA half of the v2 binding, hex. */
    keyBindingPq: string;
    /** M16: set only for a channel the directory echoed as one. Absent means an ordinary agent. */
    channel?: boolean;
    adminPubkey?: string;
  }): Promise<void>;
  persistFrostKeyShare(opts: {
    epochId: string;
    primaryPubkey: string;
    identifier: string;
    signingShare: Uint8Array;
    threshold: number;
    participants: number;
    commitmentsCbor: Uint8Array;
    verifyingSharesCbor: Uint8Array;
    dkgMethod: "trusted_dealer" | "network_dkg";
    /** M8B quorum: the directory nodeIds (Q) the DKG ran among; a restored signer targets these. */
    directoryNodeIds?: string[];
  }): Promise<void>;

  loadRegistrationState(): Promise<RegistrationStateRecord | null>;
  loadPqIdentity(): Promise<StoredPqIdentity>;
  loadActiveFrostKeyShare(): Promise<FrostKeyShareRecord | null>;
}

/**
 * M16: the channel facts of a registration write, checked. A channel without an admin is refused,
 * and so is any write that would CHANGE the facts already recorded for a registered identity:
 * `channel` and `adminPubkey` are fixed at registration. Writing the same facts again is allowed.
 */
export function checkChannelFacts(
  incoming: { channel?: boolean; adminPubkey?: string },
  existing: { channel: boolean; adminPubkey: string } | null,
): { channel: boolean; adminPubkey: string } {
  const channel = incoming.channel === true;
  const adminPubkey = channel ? (incoming.adminPubkey ?? "") : "";
  if (channel && adminPubkey === "") {
    throw new Error("invalid_channel_registration: a channel must name its admin pubkey");
  }
  if (existing && (existing.channel !== channel || existing.adminPubkey !== adminPubkey)) {
    throw new Error(
      `channel_fields_immutable: this identity is registered with channel=${existing.channel}` +
        `${existing.channel ? ` and admin ${existing.adminPubkey}` : ""}; a registration write cannot change that`,
    );
  }
  return { channel, adminPubkey };
}
