/**
 * CELLO-PERSIST-024 — Client State Persistence Layer
 *
 * Provides structured DB operations for persisting and loading client state
 * using the V2 SQLCipher schema. All methods operate on the structured tables
 * (not the deprecated client_store KV table).
 *
 * Security invariants:
 *   SI-001: signing_share MUST NOT appear in any log event or error message.
 *   SI-002: secret_key_blob MUST NOT appear in any log event or error message.
 *   SI-003: db_key is never stored — derived at runtime from K_local via HKDF.
 *   SI-004: relay_ack_receipts is append-only (INSERT OR IGNORE).
 */

import type { Logger } from "@cello-protocol/interfaces";
import type { SQLCipherClientStore } from "./sqlcipher-client-store.js";
import type { SignalRequirementPolicy, SignalRequirement } from "./connection-policy.js";
import type { SessionRecord } from "./types.js";

// ─── Types for DB rows ──────────────────────────────────────────────────────

export interface FrostKeyShareRow {
  agent_pubkey: string;
  epoch_id: string;
  primary_pubkey: string;
  identifier: string;
  signing_share: Buffer | Uint8Array;
  threshold: number;
  participants: number;
  commitments_cbor: Buffer | Uint8Array;
  verifying_shares_cbor: Buffer | Uint8Array;
  dkg_method: string;
  is_active: number;
}

export interface MlDsaKeypairRow {
  agent_pubkey: string;
  ml_dsa_pubkey: string;
  secret_key_blob: Buffer | Uint8Array;
  algorithm: string;
}

export interface RegistrationStateRow {
  agent_pubkey: string;
  agent_id: string;
  primary_pubkey: string;
  ml_dsa_pubkey: string;
  registered_at: number;
  status: string;
}

export interface ConnectionRow {
  connection_id: string;
  agent_pubkey: string;
  counterparty_pubkey: string;
  counterparty_primary_pubkey: string;
  counterparty_ml_dsa_pubkey: string;
  established_at: number;
  status: string;
  profile_unchecked: number;
}

export interface ConnectionPolicyRow {
  agent_pubkey: string;
  mode: string;
  review_mode: string;
}

export interface ConnectionPolicyRequirementRow {
  agent_pubkey: string;
  position: number;
  signal_type: string;
  condition_json: string;
}

export interface SessionRow {
  session_id: string;
  agent_pubkey: string;
  counterparty_pubkey: Buffer | Uint8Array;
  counterparty_peer_id: string;
  counterparty_multiaddrs: string;
  relay_peer_id: string;
  relay_multiaddrs: string;
  directory_peer_id: string;
  directory_multiaddrs: string;
  directory_pubkey: Buffer | Uint8Array;
  genesis_prev_root: Buffer | Uint8Array;
  last_seen_seq: number;
  last_sent_seq: number;
  next_expected_seq: number;
  status: string;
  desynchronized: number;
  leaf_count: number;
  sealed_root: Buffer | Uint8Array | null;
  seal_type: string | null;
  close_timestamp: number | null;
  frost_signature: Buffer | Uint8Array | null;
  signer_pubkey: Buffer | Uint8Array | null;
  directory_signature: Buffer | Uint8Array | null;
}

export interface SessionTreeLeafRow {
  session_id: string;
  agent_pubkey: string;
  leaf_index: number;
  leaf_kind: string;
  s2_cbor: Buffer | Uint8Array;
  sequence_number: number;
}

export interface PeerRow {
  agent_pubkey: string;
  peer_pubkey_hex: string;
  peer_id: string;
  multiaddrs: string;
}

export interface PendingHashRow {
  id: number;
  agent_pubkey: string;
  session_id: string;
  hash_hex: string;
  enqueued_at: number;
}

export interface DecidedConnectionRequestRow {
  request_id: string;
  agent_pubkey: string;
  decision: string;
}

export interface PendingConnectionRequestRow {
  request_id: string;
  agent_pubkey: string;
  from_pubkey: string;
  package_cbor: Buffer | Uint8Array;
  round: number;
}

// ─── Persistence operations ─────────────────────────────────────────────────

export interface ClientStatePersistenceOptions {
  store: SQLCipherClientStore;
  agentPubkey: string;
  keyFilePath: string;
  logger: Logger;
}

/**
 * Client state persistence layer.
 *
 * Provides type-safe methods for persisting and loading all durable state
 * from the V2 structured SQLCipher schema.
 */
export class ClientStatePersistence {
  readonly #store: SQLCipherClientStore;
  readonly #agentPubkey: string;
  readonly #keyFilePath: string;
  readonly #logger: Logger;

  constructor(opts: ClientStatePersistenceOptions) {
    this.#store = opts.store;
    this.#agentPubkey = opts.agentPubkey;
    this.#keyFilePath = opts.keyFilePath;
    this.#logger = opts.logger;
  }

  // ─── Agent registration ─────────────────────────────────────────────────────

  /** Upsert the agent row (called on every startup). */
  async upsertAgent(): Promise<void> {
    await this.#store.run(
      `INSERT INTO agents (pubkey, key_file_path, last_seen_at)
       VALUES (?, ?, datetime('now'))
       ON CONFLICT(pubkey) DO UPDATE SET last_seen_at = datetime('now')`,
      [this.#agentPubkey, this.#keyFilePath],
    );
  }

  // ─── FROST key shares ───────────────────────────────────────────────────────

  /** Persist a FROST key share after DKG completes. */
  async persistFrostKeyShare(opts: {
    epochId: string;
    primaryPubkey: string;
    identifier: string;
    signingShare: Uint8Array;
    threshold: number;
    participants: number;
    commitmentsCbor: Uint8Array;
    verifyingSharesCbor: Uint8Array;
    dkgMethod: "trusted_dealer" | "network_dkg";
  }): Promise<void> {
    // Deactivate any existing active share
    await this.#store.run(
      `UPDATE frost_key_shares SET is_active = 0 WHERE agent_pubkey = ? AND is_active = 1`,
      [this.#agentPubkey],
    );
    // Insert the new active share
    await this.#store.run(
      `INSERT OR REPLACE INTO frost_key_shares
       (agent_pubkey, epoch_id, primary_pubkey, identifier, signing_share, threshold, participants,
        commitments_cbor, verifying_shares_cbor, dkg_method, is_active, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, datetime('now'))`,
      [
        this.#agentPubkey, opts.epochId, opts.primaryPubkey, opts.identifier,
        Buffer.from(opts.signingShare), opts.threshold, opts.participants,
        Buffer.from(opts.commitmentsCbor), Buffer.from(opts.verifyingSharesCbor),
        opts.dkgMethod,
      ],
    );
    // SI-001: signing_share MUST NOT appear in log
    this.#logger.info("client.frost.share.persisted", {
      agentPubkey: this.#agentPubkey,
      epochId: opts.epochId,
      threshold: opts.threshold,
      participants: opts.participants,
      dkgMethod: opts.dkgMethod,
    });
  }

  /** Load the active FROST key share for this agent. */
  async loadActiveFrostKeyShare(): Promise<FrostKeyShareRow | undefined> {
    return this.#store.getRow<FrostKeyShareRow>(
      `SELECT * FROM frost_key_shares WHERE agent_pubkey = ? AND is_active = 1`,
      [this.#agentPubkey],
    );
  }

  // ─── ML-DSA keypairs ────────────────────────────────────────────────────────

  /** Persist an ML-DSA keypair after registration. */
  async persistMlDsaKeypair(opts: {
    mlDsaPubkey: string;
    secretKeyBlob: Uint8Array;
  }): Promise<void> {
    await this.#store.run(
      `INSERT OR REPLACE INTO ml_dsa_keypairs (agent_pubkey, ml_dsa_pubkey, secret_key_blob, created_at)
       VALUES (?, ?, ?, datetime('now'))`,
      [this.#agentPubkey, opts.mlDsaPubkey, Buffer.from(opts.secretKeyBlob)],
    );
    // SI-002: secret_key_blob MUST NOT appear in log
    this.#logger.info("client.mldsa.keypair.persisted", {
      agentPubkey: this.#agentPubkey,
      mlDsaPubkey: opts.mlDsaPubkey,
    });
  }

  /** Load the ML-DSA keypair for this agent. */
  async loadMlDsaKeypair(): Promise<MlDsaKeypairRow | undefined> {
    return this.#store.getRow<MlDsaKeypairRow>(
      `SELECT * FROM ml_dsa_keypairs WHERE agent_pubkey = ?`,
      [this.#agentPubkey],
    );
  }

  // ─── Registration state ─────────────────────────────────────────────────────

  /** Persist registration state after successful register(). */
  async persistRegistrationState(opts: {
    agentId: string;
    primaryPubkey: string;
    mlDsaPubkey: string;
    registeredAt: number;
  }): Promise<void> {
    await this.#store.run(
      `INSERT OR REPLACE INTO registration_state
       (agent_pubkey, agent_id, primary_pubkey, ml_dsa_pubkey, registered_at, status, created_at)
       VALUES (?, ?, ?, ?, ?, 'active', datetime('now'))`,
      [this.#agentPubkey, opts.agentId, opts.primaryPubkey, opts.mlDsaPubkey, opts.registeredAt],
    );
    this.#logger.info("client.registration.persisted", {
      agentPubkey: this.#agentPubkey,
      agentId: opts.agentId,
      primaryPubkey: opts.primaryPubkey,
    });
  }

  /** Load registration state for this agent. */
  async loadRegistrationState(): Promise<RegistrationStateRow | undefined> {
    return this.#store.getRow<RegistrationStateRow>(
      `SELECT * FROM registration_state WHERE agent_pubkey = ?`,
      [this.#agentPubkey],
    );
  }

  // ─── Connections ────────────────────────────────────────────────────────────

  /** Persist a connection record. */
  async persistConnection(opts: {
    connectionId: string;
    counterpartyPubkey: string;
    counterpartyPrimaryPubkey?: string;
    counterpartyMlDsaPubkey?: string;
    establishedAt: number;
    profileUnchecked?: boolean;
  }): Promise<void> {
    await this.#store.run(
      `INSERT OR REPLACE INTO connections
       (connection_id, agent_pubkey, counterparty_pubkey, counterparty_primary_pubkey,
        counterparty_ml_dsa_pubkey, established_at, status, profile_unchecked, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'active', ?, datetime('now'))`,
      [
        opts.connectionId, this.#agentPubkey, opts.counterpartyPubkey,
        opts.counterpartyPrimaryPubkey ?? '', opts.counterpartyMlDsaPubkey ?? '',
        opts.establishedAt, opts.profileUnchecked ? 1 : 0,
      ],
    );
    this.#logger.info("client.connection.persisted", {
      agentPubkey: this.#agentPubkey,
      connectionId: opts.connectionId,
      counterpartyPubkey: opts.counterpartyPubkey,
    });
  }

  /** Load all connections for this agent. */
  async loadConnections(): Promise<ConnectionRow[]> {
    return this.#store.allRows<ConnectionRow>(
      `SELECT * FROM connections WHERE agent_pubkey = ?`,
      [this.#agentPubkey],
    );
  }

  // ─── Connection policy ──────────────────────────────────────────────────────

  /** Persist connection policy (upsert mode + requirements in a single transaction). */
  async persistConnectionPolicy(policy: SignalRequirementPolicy): Promise<void> {
    await this.#store.run("BEGIN");
    try {
      await this.#store.run(
        `INSERT OR REPLACE INTO connection_policy (agent_pubkey, mode, review_mode, updated_at)
         VALUES (?, ?, ?, datetime('now'))`,
        [this.#agentPubkey, policy.mode, policy.review_mode],
      );
      // Delete existing requirements
      await this.#store.run(
        `DELETE FROM connection_policy_requirements WHERE agent_pubkey = ?`,
        [this.#agentPubkey],
      );
      // Insert new requirements in position order
      for (let i = 0; i < policy.requirements.length; i++) {
        const req = policy.requirements[i];
        await this.#store.run(
          `INSERT INTO connection_policy_requirements (agent_pubkey, position, signal_type, condition_json)
           VALUES (?, ?, ?, ?)`,
          [this.#agentPubkey, i, req.signal_type, JSON.stringify(req.condition)],
        );
      }
      await this.#store.run("COMMIT");
    } catch (err) {
      await this.#store.run("ROLLBACK").catch(() => {});
      throw err;
    }
    this.#logger.info("client.policy.persisted", {
      agentPubkey: this.#agentPubkey,
      mode: policy.mode,
      reviewMode: policy.review_mode,
      requirementCount: policy.requirements.length,
    });
  }

  /** Load connection policy for this agent. */
  async loadConnectionPolicy(): Promise<SignalRequirementPolicy | undefined> {
    const policyRow = await this.#store.getRow<ConnectionPolicyRow>(
      `SELECT * FROM connection_policy WHERE agent_pubkey = ?`,
      [this.#agentPubkey],
    );
    if (!policyRow) return undefined;

    const reqRows = await this.#store.allRows<ConnectionPolicyRequirementRow>(
      `SELECT * FROM connection_policy_requirements WHERE agent_pubkey = ? ORDER BY position ASC`,
      [this.#agentPubkey],
    );
    const requirements: SignalRequirement[] = reqRows.map((r) => ({
      signal_type: r.signal_type as SignalRequirement["signal_type"],
      condition: JSON.parse(r.condition_json),
    }));

    return {
      mode: policyRow.mode as SignalRequirementPolicy["mode"],
      review_mode: policyRow.review_mode as SignalRequirementPolicy["review_mode"],
      requirements,
    };
  }

  // ─── Sessions ───────────────────────────────────────────────────────────────

  /** Persist a session record. */
  async persistSession(sessionIdHex: string, record: SessionRecord): Promise<void> {
    await this.#store.run(
      `INSERT OR REPLACE INTO sessions
       (session_id, agent_pubkey, counterparty_pubkey, counterparty_peer_id,
        counterparty_multiaddrs, relay_peer_id, relay_multiaddrs, directory_peer_id,
        directory_multiaddrs, directory_pubkey, genesis_prev_root,
        last_seen_seq, last_sent_seq, next_expected_seq, status, desynchronized,
        leaf_count, sealed_root, seal_type, close_timestamp, frost_signature,
        signer_pubkey, directory_signature, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
      [
        sessionIdHex, this.#agentPubkey,
        Buffer.from(record.counterparty_pubkey),
        record.counterparty_peer_id,
        JSON.stringify(record.counterparty_multiaddrs),
        record.relay_endpoint.peer_id,
        JSON.stringify(record.relay_endpoint.multiaddrs),
        record.directory_endpoint.peer_id,
        JSON.stringify(record.directory_endpoint.multiaddrs),
        Buffer.from(record.directory_pubkey),
        Buffer.from(record.genesis_prev_root),
        record.last_seen_seq, record.last_sent_seq, record.next_expected_seq,
        record.status, record.desynchronized ? 1 : 0,
        record.local_tree_leaves.length,
        record.sealed_root ? Buffer.from(record.sealed_root) : null,
        record.seal_type ?? null,
        record.close_timestamp ?? null,
        record.frost_signature ? Buffer.from(record.frost_signature) : null,
        record.signer_pubkey ? Buffer.from(record.signer_pubkey) : null,
        record.directory_signature ? Buffer.from(record.directory_signature) : null,
      ],
    );
    this.#logger.info("client.session.persisted", {
      agentPubkey: this.#agentPubkey,
      sessionId: sessionIdHex,
      counterpartyPubkey: Buffer.from(record.counterparty_pubkey).toString("hex"),
      status: record.status,
    });
  }

  /** Load all sessions for this agent. */
  async loadSessions(): Promise<SessionRow[]> {
    return this.#store.allRows<SessionRow>(
      `SELECT * FROM sessions WHERE agent_pubkey = ?`,
      [this.#agentPubkey],
    );
  }

  // ─── Session tree leaves ────────────────────────────────────────────────────

  /** Persist a single session tree leaf. */
  async persistSessionTreeLeaf(opts: {
    sessionIdHex: string;
    leafIndex: number;
    leafKind: "msg" | "ctrl";
    s2Cbor: Uint8Array;
    sequenceNumber: number;
  }): Promise<void> {
    const result = await this.#store.run(
      `INSERT OR IGNORE INTO session_tree_leaves
       (session_id, agent_pubkey, leaf_index, leaf_kind, s2_cbor, sequence_number, accepted_at)
       VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`,
      [
        opts.sessionIdHex, this.#agentPubkey, opts.leafIndex,
        opts.leafKind, Buffer.from(opts.s2Cbor), opts.sequenceNumber,
      ],
    );
    // MED-3: INSERT OR IGNORE silently drops duplicates. Warn so duplicates are observable.
    if (result.changes === 0) {
      this.#logger.warn("client.leaf.duplicate", {
        agentPubkey: this.#agentPubkey,
        sessionId: opts.sessionIdHex,
        leafIndex: opts.leafIndex,
      });
    } else {
      this.#logger.debug("client.leaf.persisted", {
        agentPubkey: this.#agentPubkey,
        sessionId: opts.sessionIdHex,
        leafIndex: opts.leafIndex,
        leafKind: opts.leafKind,
        sequenceNumber: opts.sequenceNumber,
      });
    }
  }

  /** Load all leaves for a session in order. */
  async loadSessionTreeLeaves(sessionIdHex: string): Promise<SessionTreeLeafRow[]> {
    return this.#store.allRows<SessionTreeLeafRow>(
      `SELECT * FROM session_tree_leaves WHERE session_id = ? AND agent_pubkey = ? ORDER BY leaf_index ASC`,
      [sessionIdHex, this.#agentPubkey],
    );
  }

  // ─── Peers ──────────────────────────────────────────────────────────────────

  /** Persist a peer record. */
  async persistPeer(opts: {
    peerPubkeyHex: string;
    peerId: string;
    multiaddrs: string[];
  }): Promise<void> {
    await this.#store.run(
      `INSERT OR REPLACE INTO peers (agent_pubkey, peer_pubkey_hex, peer_id, multiaddrs, updated_at)
       VALUES (?, ?, ?, ?, datetime('now'))`,
      [this.#agentPubkey, opts.peerPubkeyHex, opts.peerId, JSON.stringify(opts.multiaddrs)],
    );
    this.#logger.info("client.peer.persisted", {
      agentPubkey: this.#agentPubkey,
      peerPubkeyHex: opts.peerPubkeyHex,
      peerId: opts.peerId,
    });
  }

  /** Load all peers for this agent. */
  async loadPeers(): Promise<PeerRow[]> {
    return this.#store.allRows<PeerRow>(
      `SELECT * FROM peers WHERE agent_pubkey = ?`,
      [this.#agentPubkey],
    );
  }

  // ─── Pending hashes ─────────────────────────────────────────────────────────

  /** Persist a pending hash entry. */
  async persistPendingHash(opts: {
    sessionId: string;
    hashHex: string;
    enqueuedAt: number;
  }): Promise<void> {
    await this.#store.run(
      `INSERT OR IGNORE INTO pending_hashes (agent_pubkey, session_id, hash_hex, enqueued_at)
       VALUES (?, ?, ?, ?)`,
      [this.#agentPubkey, opts.sessionId, opts.hashHex, opts.enqueuedAt],
    );
  }

  /** Remove a pending hash after ACK is stored. */
  async removePendingHash(sessionId: string, hashHex: string): Promise<void> {
    await this.#store.run(
      `DELETE FROM pending_hashes WHERE agent_pubkey = ? AND session_id = ? AND hash_hex = ?`,
      [this.#agentPubkey, sessionId, hashHex],
    );
  }

  /** Load all pending hashes for this agent. */
  async loadPendingHashes(): Promise<PendingHashRow[]> {
    return this.#store.allRows<PendingHashRow>(
      `SELECT * FROM pending_hashes WHERE agent_pubkey = ? ORDER BY id ASC`,
      [this.#agentPubkey],
    );
  }

  // ─── Relay ACK receipts (SI-004: INSERT OR IGNORE, append-only) ────────────

  /** Persist a relay ACK receipt. SI-004: INSERT OR IGNORE — first ACK wins. */
  async persistRelayAckReceipt(opts: {
    hashHex: string;
    sessionId: string;
    relayId: string;
    relayPubkeyHex: string;
    sequenceNumber: number;
    relayTimestamp: number;
    signatureHex: string;
  }): Promise<{ isDuplicate: boolean }> {
    const result = await this.#store.run(
      `INSERT OR IGNORE INTO relay_ack_receipts
       (hash_hex, agent_pubkey, session_id, relay_id, relay_pubkey_hex,
        sequence_number, relay_timestamp, signature_hex, acked_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
      [
        opts.hashHex, this.#agentPubkey, opts.sessionId, opts.relayId,
        opts.relayPubkeyHex, opts.sequenceNumber, opts.relayTimestamp, opts.signatureHex,
      ],
    );
    const isDuplicate = result.changes === 0;
    if (isDuplicate) {
      this.#logger.warn("client.relay.ack.duplicate", {
        agentPubkey: this.#agentPubkey,
        hashHex: opts.hashHex,
        sessionId: opts.sessionId,
      });
    }
    return { isDuplicate };
  }

  // ─── Known relays ───────────────────────────────────────────────────────────

  /** Cache a relay pubkey. */
  async persistKnownRelay(relayId: string, relayPubkeyHex: string, source: string): Promise<void> {
    await this.#store.run(
      `INSERT OR REPLACE INTO known_relays (relay_id, relay_pubkey_hex, source, last_seen_at)
       VALUES (?, ?, ?, datetime('now'))`,
      [relayId, relayPubkeyHex, source],
    );
    this.#logger.debug("client.relay.pubkey.cached", {
      agentPubkey: this.#agentPubkey,
      relayId,
    });
  }

  /** Look up a cached relay pubkey. */
  async lookupKnownRelay(relayId: string): Promise<string | undefined> {
    const row = await this.#store.getRow<{ relay_pubkey_hex: string }>(
      `SELECT relay_pubkey_hex FROM known_relays WHERE relay_id = ?`,
      [relayId],
    );
    return row?.relay_pubkey_hex;
  }

  // ─── Pending connection requests ────────────────────────────────────────────

  /** Persist a pending inbound connection request. */
  async persistPendingConnectionRequest(opts: {
    requestId: string;
    fromPubkey: string;
    packageCbor: Uint8Array;
    round: number;
  }): Promise<void> {
    await this.#store.run(
      `INSERT OR REPLACE INTO pending_connection_requests
       (request_id, agent_pubkey, from_pubkey, package_cbor, round)
       VALUES (?, ?, ?, ?, ?)`,
      [opts.requestId, this.#agentPubkey, opts.fromPubkey, Buffer.from(opts.packageCbor), opts.round],
    );
  }

  /** Remove from pending and insert into decided (atomic — wrapped in a transaction). */
  async decidePendingConnectionRequest(requestId: string, decision: "accepted" | "rejected" | "more_disclosure"): Promise<void> {
    // CRIT-2: Both operations must be atomic. A crash between DELETE and INSERT would leave
    // the request invisible on restart (not in pending, not in decided), enabling double-decision
    // on relay replay.
    await this.#store.run("BEGIN");
    try {
      await this.#store.run(
        `DELETE FROM pending_connection_requests WHERE request_id = ? AND agent_pubkey = ?`,
        [requestId, this.#agentPubkey],
      );
      await this.#store.run(
        `INSERT OR IGNORE INTO decided_connection_requests (request_id, agent_pubkey, decision)
         VALUES (?, ?, ?)`,
        [requestId, this.#agentPubkey, decision],
      );
      await this.#store.run("COMMIT");
    } catch (err) {
      await this.#store.run("ROLLBACK").catch(() => {});
      throw err;
    }
  }

  /** Load pending connection requests. */
  async loadPendingConnectionRequests(): Promise<PendingConnectionRequestRow[]> {
    return this.#store.allRows<PendingConnectionRequestRow>(
      `SELECT * FROM pending_connection_requests WHERE agent_pubkey = ?`,
      [this.#agentPubkey],
    );
  }

  /** Load decided connection request IDs. */
  async loadDecidedConnectionRequests(): Promise<DecidedConnectionRequestRow[]> {
    return this.#store.allRows<DecidedConnectionRequestRow>(
      `SELECT * FROM decided_connection_requests WHERE agent_pubkey = ?`,
      [this.#agentPubkey],
    );
  }

  // ─── Endorsements & Attestations ────────────────────────────────────────────

  /** Load non-expired endorsements. */
  async loadEndorsements(nowMs: number): Promise<Array<Record<string, unknown>>> {
    return this.#store.allRows(
      `SELECT * FROM endorsements WHERE agent_pubkey = ? AND expires_at > ?`,
      [this.#agentPubkey, nowMs],
    );
  }

  /** Load non-expired attestations. */
  async loadAttestations(nowMs: number): Promise<Array<Record<string, unknown>>> {
    return this.#store.allRows(
      `SELECT * FROM attestations WHERE agent_pubkey = ? AND expires_at > ?`,
      [this.#agentPubkey, nowMs],
    );
  }

  // ─── Backup metadata ────────────────────────────────────────────────────────

  /** Persist backup metadata. */
  async persistBackupMetadata(opts: {
    completedAt: string;
    destinationUrl: string;
    checksum: string;
  }): Promise<void> {
    await this.#store.run(
      `INSERT OR REPLACE INTO backup_metadata (agent_pubkey, completed_at, destination_url, checksum, updated_at)
       VALUES (?, ?, ?, ?, datetime('now'))`,
      [this.#agentPubkey, opts.completedAt, opts.destinationUrl, opts.checksum],
    );
  }

  /** Load backup metadata. */
  async loadBackupMetadata(): Promise<{ destination_url: string; checksum: string; completed_at: string } | undefined> {
    return this.#store.getRow(
      `SELECT destination_url, checksum, completed_at FROM backup_metadata WHERE agent_pubkey = ?`,
      [this.#agentPubkey],
    );
  }

  // ─── Startup state loading ──────────────────────────────────────────────────

  /**
   * Load all durable state from DB and emit the batch summary event.
   * Returns counts and booleans for client.startup.state.loaded.
   */
  async loadStartupState(): Promise<{
    hasFrostShare: boolean;
    hasMlDsaKeypair: boolean;
    hasRegistration: boolean;
    hasPolicy: boolean;
    connectionCount: number;
    sessionCount: number;
    leafCount: number;
    pendingHashCount: number;
    frostShare: FrostKeyShareRow | undefined;
    mlDsaKeypair: MlDsaKeypairRow | undefined;
    registrationState: RegistrationStateRow | undefined;
    connectionPolicy: SignalRequirementPolicy | undefined;
    connections: ConnectionRow[];
    sessions: SessionRow[];
    peers: PeerRow[];
    pendingHashes: PendingHashRow[];
    decidedRequests: DecidedConnectionRequestRow[];
    pendingConnectionRequests: PendingConnectionRequestRow[];
    endorsements: Array<Record<string, unknown>>;
    attestations: Array<Record<string, unknown>>;
  }> {
    const frostShare = await this.loadActiveFrostKeyShare();
    const mlDsaKeypair = await this.loadMlDsaKeypair();
    const registrationState = await this.loadRegistrationState();
    const connectionPolicy = await this.loadConnectionPolicy();
    const connections = await this.loadConnections();
    const sessions = await this.loadSessions();
    const peers = await this.loadPeers();
    const pendingHashes = await this.loadPendingHashes();
    const decidedRequests = await this.loadDecidedConnectionRequests();
    const pendingConnectionRequests = await this.loadPendingConnectionRequests();
    const endorsements = await this.loadEndorsements(Date.now());
    const attestations = await this.loadAttestations(Date.now());

    // Count total leaves
    let leafCount = 0;
    for (const s of sessions) {
      leafCount += s.leaf_count;
    }

    const result = {
      hasFrostShare: frostShare !== undefined,
      hasMlDsaKeypair: mlDsaKeypair !== undefined,
      hasRegistration: registrationState !== undefined,
      hasPolicy: connectionPolicy !== undefined,
      connectionCount: connections.length,
      sessionCount: sessions.length,
      leafCount,
      pendingHashCount: pendingHashes.length,
      frostShare,
      mlDsaKeypair,
      registrationState,
      connectionPolicy,
      connections,
      sessions,
      peers,
      pendingHashes,
      decidedRequests,
      pendingConnectionRequests,
      endorsements,
      attestations,
    };

    this.#logger.info("client.startup.state.loaded", {
      agentPubkey: this.#agentPubkey,
      connectionCount: result.connectionCount,
      sessionCount: result.sessionCount,
      leafCount: result.leafCount,
      pendingHashCount: result.pendingHashCount,
      hasFrostShare: result.hasFrostShare,
      hasMlDsaKeypair: result.hasMlDsaKeypair,
      hasRegistration: result.hasRegistration,
      hasPolicy: result.hasPolicy,
    });

    return result;
  }
}
