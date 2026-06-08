/**
 * client-startup.ts — PERSIST-024: loadClientStartupState
 *
 * Extracted from CelloClientImpl.loadPersistedState to keep client.ts under AC-005 line budget.
 * Loads all durable state from the SQLCipher DB and populates in-memory state via the
 * StartupContext interface.
 *
 * Security invariants:
 *   SI-001: signing_share bytes never appear in any log event.
 *   SI-002: secret_key_blob bytes never appear in any log event.
 *
 * Crypto refs: RFC 9591 (FROST), NIST FIPS 204 (ML-DSA-44)
 */

import { decode } from "cbor-x";
import { InMemoryMlDsaKeyProvider } from "@cello-protocol/crypto";
import { storeDkgResult } from "@cello-protocol/crypto/frost/frost-threshold-signer.js";
import { FrostThresholdSigner } from "@cello-protocol/crypto/frost/frost-threshold-signer.js";
import type { IThresholdSigner, MlDsaKeyProvider } from "@cello-protocol/crypto";
import type { CelloNode } from "@cello-protocol/transport";
import type { RegistrationState, ClientConnectionRecord } from "@cello-protocol/protocol-types";
import type { Logger } from "@cello-protocol/interfaces";
import type { ClientStatePersistence } from "./client-state-persistence.js";
import type { SessionRecord, PeerEntry } from "./types.js";
import type { SignalRequirementPolicy } from "./connection-policy.js";
import type { ReviewQueueItem } from "./connection-manager.js";
import { NetworkDirectoryNode } from "./network-directory-node.js";

/**
 * Narrow interface providing access to the facade's mutable state and manager callbacks
 * needed during startup state restoration.
 */
export interface StartupContext {
  // Infrastructure (read)
  readonly node: CelloNode;
  readonly logger: Logger;
  readonly persistence: ClientStatePersistence;
  // Facade state setters
  getDirectoryEndpoint(): { peer_id: string; multiaddrs: string[] } | null;
  getThresholdSigner(): IThresholdSigner | undefined;
  setThresholdSigner(signer: IThresholdSigner): void;
  getMyPubkeyHex(): string | null;
  setMyPubkeyHex(hex: string): void;
  setRegistrationState(state: RegistrationState): void;
  setMlDsaProvider(provider: MlDsaKeyProvider): void;
  addConnection(connectionId: string, record: ClientConnectionRecord): void;
  addConnectionByPeer(counterpartyPubkey: string, connectionId: string): void;
  addProfileUncheckedPeer(pubkey: string): void;
  setConnectionPolicy(policy: SignalRequirementPolicy): void;
  addPeer(peerPubkeyHex: string, entry: PeerEntry): void;
  hasPeer(peerPubkeyHex: string): boolean;
  setEndorsements(endorsements: Array<Record<string, unknown>>): void;
  setAttestations(attestations: Array<Record<string, unknown>>): void;
  setLoadedPendingHashes(hashes: Array<{ sessionId: string; hashHex: string; enqueuedAt: number }>): void;
  // Manager callbacks
  getSessionById(sessionIdHex: string): SessionRecord | undefined;
  setSession(sessionIdHex: string, record: SessionRecord): void;
  initSessionMessageQueue(sessionIdHex: string): void;
  getMyPrimaryPubkey(): Uint8Array | null;
  setMyPrimaryPubkey(pubkey: Uint8Array): void;
  restoreDecidedRequest(requestId: string): void;
  restorePendingInboundRequest(opts: { connection_request_id: string; from_pubkey: string; package_cbor: Uint8Array; round: number }): void;
  restoreReviewQueueItem(item: ReviewQueueItem): void;
}

/**
 * Load all durable state from the SQLCipher DB and populate in-memory state.
 * Called by CelloClientImpl.loadPersistedState() after SQLCipher store opens.
 *
 * Returns the pending hashes loaded from the DB for the composition root to enqueue.
 */
export async function loadClientStartupState(ctx: StartupContext): Promise<void> {
  const p = ctx.persistence;
  const state = await p.loadStartupState();

  // ── 1. FROST key share ────────────────────────────────────────────────────
  if (state.frostShare) {
    const row = state.frostShare;
    const signingShareBytes = row.signing_share instanceof Buffer
      ? new Uint8Array(row.signing_share)
      : new Uint8Array(row.signing_share as Uint8Array);
    const frostSecret = { identifier: row.identifier, signingShare: signingShareBytes };

    let commitments: Uint8Array[] = [];
    let verifyingShares: Record<string, Uint8Array> = {};
    try {
      const commitmentsCborBytes = row.commitments_cbor instanceof Buffer
        ? row.commitments_cbor
        : Buffer.from(row.commitments_cbor as Uint8Array);
      const decodedCommitments = decode(commitmentsCborBytes) as unknown;
      if (Array.isArray(decodedCommitments)) {
        commitments = decodedCommitments.map((c: unknown) =>
          c instanceof Uint8Array ? c : Buffer.isBuffer(c) ? new Uint8Array(c as Buffer) : new Uint8Array(0)
        );
      }
      const verifyingSharesCborBytes = row.verifying_shares_cbor instanceof Buffer
        ? row.verifying_shares_cbor
        : Buffer.from(row.verifying_shares_cbor as Uint8Array);
      const decodedVerifyingShares = decode(verifyingSharesCborBytes) as unknown;
      if (decodedVerifyingShares && typeof decodedVerifyingShares === "object" && !Array.isArray(decodedVerifyingShares)) {
        for (const [k, v] of Object.entries(decodedVerifyingShares as Record<string, unknown>)) {
          verifyingShares[k] = v instanceof Uint8Array ? v : Buffer.isBuffer(v) ? new Uint8Array(v as Buffer) : new Uint8Array(0);
        }
      }
    } catch {
      ctx.logger.error("client.frost.share.load.failed", {
        agentPubkey: row.agent_pubkey,
        reason: "cbor_deserialize_failed",
      });
      return;
    }

    const frostPublic = {
      signers: { min: row.threshold, max: row.participants + 1 },
      commitments,
      verifyingShares,
    };

    const myPubkeyHex = row.agent_pubkey;
    try {
      // SI-001: storeDkgResult does not log the secret
      storeDkgResult(myPubkeyHex, frostSecret as import("@noble/curves/abstract/frost.js").FrostSecret, frostPublic as import("@noble/curves/abstract/frost.js").FrostPublic);
    } catch {
      ctx.logger.error("client.frost.share.load.failed", {
        agentPubkey: myPubkeyHex,
        reason: "storeDkgResult_failed",
      });
      return;
    }

    // Reconstruct FrostThresholdSigner if not already set.
    // AC-003 (DX-001): directoryNodeStubs MUST be populated from the current directoryEndpoint.
    if (!ctx.getThresholdSigner()) {
      let directoryNodeStubsForSigner: NetworkDirectoryNode[] | undefined;
      const directoryEndpoint = ctx.getDirectoryEndpoint();
      if (directoryEndpoint) {
        const stub = new NetworkDirectoryNode({
          id: directoryEndpoint.peer_id,
          node: ctx.node,
          directoryPeerId: directoryEndpoint.peer_id,
          directoryMultiaddrs: directoryEndpoint.multiaddrs,
          logger: ctx.logger,
        });
        stub.setBootstrapContext(myPubkeyHex, `${myPubkeyHex}:epoch:1`);
        directoryNodeStubsForSigner = [stub];
      }
      ctx.setThresholdSigner(new FrostThresholdSigner(
        {
          threshold: row.threshold,
          participants: row.participants,
          directoryNodeStubs: directoryNodeStubsForSigner,
        },
        Buffer.from(myPubkeyHex, "hex"),
      ));
    }

    if (commitments.length > 0 && !ctx.getMyPrimaryPubkey()) {
      ctx.setMyPrimaryPubkey(new Uint8Array(commitments[0]!));
    }

    ctx.logger.info("client.frost.share.loaded", {
      agentPubkey: myPubkeyHex,
      epochId: row.epoch_id,
      threshold: row.threshold,
      participants: row.participants,
    });
  }

  // HIGH-3: emit alarm when registration exists but no FROST share found
  if (!state.frostShare && state.registrationState) {
    ctx.logger.error("client.frost.share.missing", {
      agentPubkey: state.registrationState.agent_pubkey,
      reason: "no_active_share_in_db",
    });
  }

  // ── 2. ML-DSA keypair ─────────────────────────────────────────────────────
  if (state.mlDsaKeypair) {
    const row = state.mlDsaKeypair;
    try {
      const secretKeyBlob = row.secret_key_blob instanceof Buffer
        ? new Uint8Array(row.secret_key_blob)
        : new Uint8Array(row.secret_key_blob as Uint8Array);
      const mlDsaPubkeyBytes = Buffer.from(row.ml_dsa_pubkey, "hex");
      // SI-002: InMemoryMlDsaKeyProvider does not log secret key
      ctx.setMlDsaProvider(new InMemoryMlDsaKeyProvider(mlDsaPubkeyBytes, secretKeyBlob));
      ctx.logger.info("client.mldsa.keypair.loaded", {
        agentPubkey: row.agent_pubkey,
        mlDsaPubkey: row.ml_dsa_pubkey,
      });
    } catch (err: unknown) {
      ctx.logger.error("client.mldsa.load.failed", {
        agentPubkey: row.agent_pubkey,
        reason: err instanceof Error ? err.message : String(err),
      });
    }
  }

  // ── 3. Registration state ─────────────────────────────────────────────────
  if (state.registrationState) {
    const row = state.registrationState;
    ctx.setRegistrationState({
      agent_id: row.agent_id,
      primary_pubkey: row.primary_pubkey,
      ml_dsa_pubkey: row.ml_dsa_pubkey,
      registered_at: row.registered_at,
      status: "active",
    });
    ctx.logger.info("client.registration.loaded", {
      agentPubkey: row.agent_pubkey,
      agentId: row.agent_id,
      status: row.status,
    });
  }

  // ── 4. Connections ────────────────────────────────────────────────────────
  for (const row of state.connections) {
    const record: ClientConnectionRecord = {
      connection_id: row.connection_id,
      counterparty_primary_pubkey: row.counterparty_primary_pubkey ?? "",
      counterparty_ml_dsa_pubkey: row.counterparty_ml_dsa_pubkey ?? "",
      counterparty_pubkey: row.counterparty_pubkey,
      established_at: row.established_at,
      status: row.status as "active",
    };
    ctx.addConnection(row.connection_id, record);
    ctx.addConnectionByPeer(row.counterparty_pubkey, row.connection_id);
    if (row.profile_unchecked) {
      ctx.addProfileUncheckedPeer(row.counterparty_pubkey);
    }
  }

  // ── 5. Connection policy ──────────────────────────────────────────────────
  if (state.connectionPolicy) {
    ctx.setConnectionPolicy(state.connectionPolicy);
  }

  // ── 6. Sessions + leaves ──────────────────────────────────────────────────
  for (const row of state.sessions) {
    const sessionIdHex = row.session_id;
    if (ctx.getSessionById(sessionIdHex)) continue;

    const leaves = await p.loadSessionTreeLeaves(sessionIdHex);
    const localTreeLeaves: SessionRecord["local_tree_leaves"] = leaves.map((l) => ({
      kind: l.leaf_kind as "msg" | "ctrl",
      s2_cbor: l.s2_cbor instanceof Buffer
        ? new Uint8Array(l.s2_cbor)
        : new Uint8Array(l.s2_cbor as Uint8Array),
    }));

    const counterpartyPubkey = row.counterparty_pubkey instanceof Buffer
      ? new Uint8Array(row.counterparty_pubkey)
      : new Uint8Array(row.counterparty_pubkey as Uint8Array);
    const directoryPubkey = row.directory_pubkey instanceof Buffer
      ? new Uint8Array(row.directory_pubkey)
      : new Uint8Array(row.directory_pubkey as Uint8Array);
    const genesisPrevRoot = row.genesis_prev_root instanceof Buffer
      ? new Uint8Array(row.genesis_prev_root)
      : new Uint8Array(row.genesis_prev_root as Uint8Array);

    let counterpartyMultiaddrs: string[] = [];
    let relayMultiaddrs: string[] = [];
    let directoryMultiaddrs: string[] = [];
    try { counterpartyMultiaddrs = JSON.parse(row.counterparty_multiaddrs) as string[]; } catch { /* ignore */ }
    try { relayMultiaddrs = JSON.parse(row.relay_multiaddrs) as string[]; } catch { /* ignore */ }
    try { directoryMultiaddrs = JSON.parse(row.directory_multiaddrs) as string[]; } catch { /* ignore */ }

    const record: SessionRecord = {
      session_id: Buffer.from(sessionIdHex, "hex"),
      counterparty_pubkey: counterpartyPubkey,
      counterparty_peer_id: row.counterparty_peer_id,
      counterparty_multiaddrs: counterpartyMultiaddrs,
      relay_endpoint: { peer_id: row.relay_peer_id, multiaddrs: relayMultiaddrs },
      directory_endpoint: { peer_id: row.directory_peer_id, multiaddrs: directoryMultiaddrs },
      directory_pubkey: directoryPubkey,
      genesis_prev_root: genesisPrevRoot,
      last_seen_seq: row.last_seen_seq,
      last_sent_seq: row.last_sent_seq,
      next_expected_seq: row.next_expected_seq,
      status: row.status as SessionRecord["status"],
      desynchronized: row.desynchronized !== 0,
      local_tree_leaves: localTreeLeaves,
      sealed_root: row.sealed_root
        ? (row.sealed_root instanceof Buffer ? new Uint8Array(row.sealed_root) : new Uint8Array(row.sealed_root as Uint8Array))
        : undefined,
      seal_type: row.seal_type as SessionRecord["seal_type"] ?? undefined,
      close_timestamp: row.close_timestamp ?? undefined,
      frost_signature: row.frost_signature
        ? (row.frost_signature instanceof Buffer ? new Uint8Array(row.frost_signature) : new Uint8Array(row.frost_signature as Uint8Array))
        : undefined,
      signer_pubkey: row.signer_pubkey
        ? (row.signer_pubkey instanceof Buffer ? new Uint8Array(row.signer_pubkey) : new Uint8Array(row.signer_pubkey as Uint8Array))
        : undefined,
      directory_signature: row.directory_signature
        ? (row.directory_signature instanceof Buffer ? new Uint8Array(row.directory_signature) : new Uint8Array(row.directory_signature as Uint8Array))
        : undefined,
    };

    ctx.setSession(sessionIdHex, record);
    ctx.initSessionMessageQueue(sessionIdHex);

    // HIGH-4: emit alarm when loaded leaf count doesn't match sessions.leaf_count
    if (leaves.length !== row.leaf_count) {
      ctx.logger.error("client.session.leaves.mismatch", {
        agentPubkey: row.agent_pubkey,
        sessionId: sessionIdHex,
        expectedLeafCount: row.leaf_count,
        actualLeafCount: leaves.length,
      });
    }
  }

  // ── 7. Peers ──────────────────────────────────────────────────────────────
  for (const row of state.peers) {
    if (!ctx.hasPeer(row.peer_pubkey_hex)) {
      let multiaddrs: string[] = [];
      try { multiaddrs = JSON.parse(row.multiaddrs) as string[]; } catch { /* ignore */ }
      ctx.addPeer(row.peer_pubkey_hex, { peerId: row.peer_id, multiaddrs, connected: false });
    }
  }

  // ── 8. Decided requests ───────────────────────────────────────────────────
  for (const row of state.decidedRequests) {
    ctx.restoreDecidedRequest(row.request_id);
  }

  // ── 9. Pending connection requests ────────────────────────────────────────
  for (const row of state.pendingConnectionRequests) {
    const packageCbor = row.package_cbor instanceof Buffer
      ? new Uint8Array(row.package_cbor)
      : new Uint8Array(row.package_cbor as Uint8Array);
    ctx.restorePendingInboundRequest({
      connection_request_id: row.request_id,
      from_pubkey: row.from_pubkey,
      package_cbor: packageCbor,
      round: row.round,
    });
    ctx.restoreReviewQueueItem({
      connection_request_id: row.request_id,
      from_pubkey: row.from_pubkey,
      report: {
        verdict: "pending_agent_review" as const,
        policy_summary: {
          mode: "unknown",
          review_mode: "inference" as const,
          requirements_met: [],
          requirements_unmet: [],
        },
        package_summary: {
          pseudonym_label: "",
          endorsement_count: 0,
          attestation_types: [],
          pseudonym_age_days: 0,
          registration_age_days: 0,
          is_provisional: false,
        },
        is_round_2: row.round > 1,
      },
      package_cbor: packageCbor,
      sender_registered_at: 0,
      sender_is_provisional: false,
    });
  }

  // ── 10. Endorsements and attestations (MED-4) ────────────────────────────
  if (state.endorsements.length > 0) {
    ctx.setEndorsements(state.endorsements);
  }
  if (state.attestations.length > 0) {
    ctx.setAttestations(state.attestations);
  }

  // HIGH-3: set myPubkeyHex from registration state if sessions were loaded
  if (!ctx.getMyPubkeyHex() && state.registrationState) {
    ctx.setMyPubkeyHex(state.registrationState.agent_pubkey);
  }

  // PERSIST-024 FINDING-4: store loaded pending hashes for caller consumption
  ctx.setLoadedPendingHashes(state.pendingHashes.map((row) => ({
    sessionId: row.session_id,
    hashHex: row.hash_hex,
    enqueuedAt: row.enqueued_at,
  })));

  // M-5: upsertAgent at the END of startup
  await p.upsertAgent();

  // PERSIST-024 FINDING-3: emit client.startup.state.loaded AFTER all in-memory structures populated
  ctx.logger.info("client.startup.state.loaded", {
    agentPubkey: ctx.getMyPubkeyHex() ?? state.registrationState?.agent_pubkey ?? "unknown",
    connectionCount: state.connectionCount,
    sessionCount: state.sessionCount,
    leafCount: state.leafCount,
    pendingHashCount: state.pendingHashCount,
    hasFrostShare: state.hasFrostShare,
    hasMlDsaKeypair: state.hasMlDsaKeypair,
    hasRegistration: state.hasRegistration,
    hasPolicy: state.hasPolicy,
  });
}
