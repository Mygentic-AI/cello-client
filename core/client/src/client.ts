/**
 * CELLO Client — CelloClientImpl facade.
 *
 * Domain logic is delegated to manager classes:
 *   RegistrationManager, ConnectionManager, SignalingManager,
 *   RelayStreamManager, SealManager, SessionManager.
 * Parse helpers live in session-assignment-parser.ts.
 * Startup restore logic lives in client-startup.ts.
 */

import * as lp from "it-length-prefixed";
import {
  buildEnvelope, serializeEnvelope, deserializeEnvelope, validateEnvelope,
} from "@cello-protocol/protocol-types";
import type { IThresholdSigner } from "@cello-protocol/crypto";
import { CELLO_PROTOCOL_ID, CELLO_CONTENT_PROTOCOL_ID } from "@cello-protocol/transport";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";
import type { SessionAssignment, RegistrationState } from "@cello-protocol/protocol-types";
import type {
  CelloClient, PeerEntry, ReceivedEnvelope, SendResult, SessionRecord,
  ReceiveAssignmentResult, ReceivedMessage, SendMessageResult, SessionAssignmentEvent,
  InitiateSessionResult,
} from "./types.js";
import type { Logger } from "@cello-protocol/interfaces";
import type { ClientStatePersistence } from "./client-state-persistence.js";
import type { AgentHashQueue } from "./agent-hash-queue.js";
import { RegistrationManager } from "./registration-manager.js";
import type { RegistrationContext } from "./registration-manager.js";
import { ConnectionManager } from "./connection-manager.js";
import type { ConnectionContext } from "./connection-manager.js";
import { SignalingManager } from "./signaling-manager.js";
import type { SignalingContext } from "./signaling-manager.js";
import { RelayStreamManager } from "./relay-stream-manager.js";
import type { RelayStreamContext } from "./relay-stream-manager.js";
import { SealManager } from "./seal-manager.js";
import type { SealContext } from "./seal-manager.js";
import { SessionManager } from "./session-manager.js";
import type { SessionContext } from "./session-manager.js";
import { loadClientStartupState } from "./client-startup.js";
import type { StartupContext } from "./client-startup.js";
import { mapSessionRequestErrorFrame } from "./session-assignment-parser.js";
import { dispatchSignalingFrame } from "./frame-dispatch.js";

// ─── SESSION-006 reconnect constants ─────────────────────────────────────────

/** Default reconnect timeout: 60 seconds per SESSION-006 AC-003. */
const DEFAULT_RECONNECT_TIMEOUT_MS = 60_000;

/**
 * SESSION-005: default timeout waiting for directory seal_verified + client FROST ceremony + session_sealed.
 * After bilateral SEAL exchange, if no session_sealed arrives within this window,
 * cello_close_session returns seal_type: 'bilateral'.
 */
const DEFAULT_SEAL_FROST_TIMEOUT_MS = 15_000;

// ─── CelloClientImpl ─────────────────────────────────────────────────────────

class CelloClientImpl implements CelloClient {
  readonly #node: CelloNode;
  readonly #keyProvider: KeyProvider;
  readonly #contentGraceMs: number;
  /** SESSION-006: max ms to attempt relay reconnect before giving up. */
  readonly #reconnectTimeoutMs: number;
  /** SESSION-005: optional FROST threshold signer for seal ceremony coordination. */
  #thresholdSigner: IThresholdSigner | undefined;
  /** SESSION-005: seal-frost-timeout in ms (default 15s). */
  readonly #sealFrostTimeoutMs: number;
  #myPubkeyHex: string | null = null;

  // peer_pubkey_hex → PeerEntry
  readonly #peers = new Map<string, PeerEntry>();

  // sender_pubkey_hex → FIFO queue of received envelopes
  readonly #receiveQueues = new Map<string, ReceivedEnvelope[]>();

  // ordered arrival list for peekAll()
  readonly #arrivalLog: Array<{ senderPubkeyHex: string; envelope: ReceivedEnvelope }> = [];

  // Optional callback invoked after each successful inbound enqueue
  readonly #onMessageQueued: ((senderPubkeyHex: string) => void) | undefined;

  /** Configured directory endpoint (required for initiateSession). ADAPTER-003. */
  #directoryEndpoint: { peer_id: string; multiaddrs: string[] } | null;

  /** PERSIST-024: In-memory endorsement/attestation caches */
  #endorsements: Array<Record<string, unknown>> = [];
  #attestations: Array<Record<string, unknown>> = [];

  /** PERSIST-024 FINDING-4: pending hashes loaded on startup */
  #loadedPendingHashes: Array<{ sessionId: string; hashHex: string; enqueuedAt: number }> = [];

  // ─── Managers (extracted method groups) ──────────────────────────────────────
  readonly #registrationManager: RegistrationManager;
  readonly #connectionManager: ConnectionManager;
  readonly #signalingManager: SignalingManager;
  readonly #relayStreamManager: RelayStreamManager;
  readonly #sealManager: SealManager;
  readonly #sessionManager: SessionManager;

  // ─── PERSIST-014: Logger (injected, defaults to no-op) ───────────────────────
  readonly #logger: Logger;

  // ─── PERSIST-024: Client state persistence (optional) ────────────────────────
  #persistence: ClientStatePersistence | null = null;

  // ─── PERSIST-024 AC-008: Hash queue for relay resubmission (optional) ────────
  #hashQueue: AgentHashQueue | null = null;

  /** Counter incremented each time evaluateConnectionPackage is called (trackEvaluateCount=true). */
  _evaluateCallCount = 0;

  constructor(
    node: CelloNode,
    keyProvider: KeyProvider,
    onMessageQueued?: (senderPubkeyHex: string) => void,
    contentGraceMs = 30_000,
    reconnectTimeoutMs = DEFAULT_RECONNECT_TIMEOUT_MS,
    thresholdSigner?: IThresholdSigner,
    sealFrostTimeoutMs = DEFAULT_SEAL_FROST_TIMEOUT_MS,
    directoryEndpoint: { peer_id: string; multiaddrs: string[] } | null = null,
    mlDsaKeyFile?: string,
    connectionPolicy?: import("./connection-policy.js").SignalRequirementPolicy,
    connectionTimeoutMs = 300_000,
    round2TimeoutMs = 120_000,
    trackEvaluateCount = false,
    whitelist: string[] = [],
    onConnectionPendingReview?: (event: import("@cello-protocol/protocol-types").ConnectionRequestInbound) => void,
    crossCheckDirectoryOnInbound = false,
    logger?: Logger,
    persistence?: ClientStatePersistence,
  ) {
    this.#node = node;
    this.#keyProvider = keyProvider;
    this.#onMessageQueued = onMessageQueued;
    this.#contentGraceMs = contentGraceMs;
    this.#reconnectTimeoutMs = reconnectTimeoutMs;
    this.#thresholdSigner = thresholdSigner;
    this.#sealFrostTimeoutMs = sealFrostTimeoutMs;
    this.#directoryEndpoint = directoryEndpoint;
    this.#logger = logger ?? { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };
    this.#persistence = persistence ?? null;

    // ─── Build managers — order matters: SealManager before contexts that reference it ──
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const self = this;

    // RegistrationManager — owns #registrationState, #mlDsaProvider
    const regCtx: RegistrationContext = {
      get node() { return self.#node; },
      get keyProvider() { return self.#keyProvider; },
      get logger() { return self.#logger; },
      get persistence() { return self.#persistence; },
      get mlDsaKeyFile() { return mlDsaKeyFile; },
      getMyPubkeyHex: () => self.#myPubkeyHex,
      setMyPubkeyHex: (hex: string) => { self.#myPubkeyHex = hex; },
      getDirectoryEndpoint: () => self.#directoryEndpoint,
      getThresholdSigner: () => self.#thresholdSigner,
      setThresholdSigner: (signer: IThresholdSigner) => { self.#thresholdSigner = signer; },
      getMyPrimaryPubkey: () => self.#sealManager.getMyPrimaryPubkey(),
      setMyPrimaryPubkey: (pubkey: Uint8Array) => { self.#sealManager.setMyPrimaryPubkey(new Uint8Array(pubkey)); },
      getPersistentSignalingStream: () => self.#signalingManager.getPersistentSignalingStream(),
      openPersistentSignalingStream: () => self.#openPersistentSignalingStream(),
      setPendingDkgReadyResolve: (resolve) => { self.#signalingManager.setPendingDkgReadyResolve(resolve); },
      setPendingRegisterResolve: (resolve) => { self.#signalingManager.setPendingRegisterResolve(resolve); },
    };
    this.#registrationManager = new RegistrationManager(regCtx);

    // ConnectionManager — owns connections, policy, handlers, unchecked peers
    const connCtx: ConnectionContext = {
      get logger() { return self.#logger; },
      get persistence() { return self.#persistence; },
      get connectionTimeoutMs() { return connectionTimeoutMs; },
      get round2TimeoutMs() { return round2TimeoutMs; },
      get trackEvaluateCount() { return trackEvaluateCount; },
      get whitelist() { return whitelist; },
      get crossCheckDirectoryOnInbound() { return crossCheckDirectoryOnInbound; },
      getPersistentSignalingStream: () => self.#signalingManager.getPersistentSignalingStream(),
      openPersistentSignalingStream: () => self.#openPersistentSignalingStream(),
      incrementEvaluateCallCount: () => { self._evaluateCallCount++; },
    };
    this.#connectionManager = new ConnectionManager(connCtx, {
      connectionPolicy,
      onConnectionPendingReview,
    });

    // SignalingManager — owns persistent stream + all pending resolvers
    const sigCtx: SignalingContext = {
      get node() { return self.#node; },
      get keyProvider() { return self.#keyProvider; },
      get logger() { return self.#logger; },
      getMyPubkeyHex: () => self.#myPubkeyHex,
      setMyPubkeyHex: (hex: string) => { self.#myPubkeyHex = hex; },
      getDirectoryEndpoint: () => self.#directoryEndpoint,
      getDirectoryStream: (sessionIdHex) => self.#relayStreamManager.getDirectoryStream(sessionIdHex),
      setDirectoryStream: (sessionIdHex, stream) => { self.#relayStreamManager.setDirectoryStream(sessionIdHex, stream); },
      deleteDirectoryStream: (sessionIdHex) => { self.#relayStreamManager.deleteDirectoryStream(sessionIdHex); },
      getPendingConnectionResolverCount: () => self.#connectionManager.pendingConnectionRequestResolverCount,
      dispatchSignalingFrame: (stream, frame) => { self.#dispatchSignalingFrame(stream, frame); },
      onSignalingStreamClosed: (stream) => { self.#onSignalingStreamClosed(stream); },
      // initiateSession dependencies
      getConnectionIdForPeer: (hex) => self.#connectionManager.getConnectionIdForPeer(hex),
      hasConnectionPolicy: () => self.#connectionManager.hasConnectionPolicy(),
      receiveSessionAssignment: (assignment, myPubkey) => self.receiveSessionAssignment(assignment, myPubkey),
      getSession: (sessionIdHex) => self.#sessionManager.getSession(sessionIdHex),
    };
    this.#signalingManager = new SignalingManager(sigCtx);

    // SessionManager
    const sessionCtx: SessionContext = {
      get logger() { return self.#logger; },
      get persistence() { return self.#persistence; },
      get keyProvider() { return self.#keyProvider; },
      get node() { return self.#node; },
      getMyPubkeyHex: () => self.#myPubkeyHex,
      setMyPubkeyHex: (hex) => { self.#myPubkeyHex = hex; },
      getThresholdSigner: () => self.#thresholdSigner,
      getPersistentSignalingStream: () => self.#signalingManager.getPersistentSignalingStream(),
      initRelaySession: (sessionIdHex) => { self.#relayStreamManager.initSession(sessionIdHex); },
      runRelayStreamReader: (sessionIdHex, stream, myPubkeyHex, iter) => {
        self.#relayStreamManager.runRelayStreamReader(sessionIdHex, stream, myPubkeyHex, iter);
      },
      performRelayAuth: (stream, myPubkey) => self.#relayStreamManager.performRelayAuth(stream, myPubkey),
      handleContentStream: (stream) => { void self.#relayStreamManager.handleContentStream(stream); },
      connectDirectorySignalingStream: (sessionIdHex, assignment, myPubkey) =>
        self.#signalingManager.connectDirectorySignalingStream(sessionIdHex, assignment, myPubkey),
      getRelayStream: (sessionIdHex) => self.#relayStreamManager.getRelayStream(sessionIdHex),
    };
    this.#sessionManager = new SessionManager(sessionCtx);

    // SealManager
    const sealCtx: SealContext = {
      get logger() { return self.#logger; },
      get persistence() { return self.#persistence; },
      get keyProvider() { return self.#keyProvider; },
      getMyPubkeyHex: () => self.#myPubkeyHex,
      getThresholdSigner: () => self.#thresholdSigner,
      getSession: (sessionIdHex) => self.#sessionManager.getSession(sessionIdHex),
      getSessions: () => self.#sessionManager.getSessions(),
      getOwnPendingContent: (sessionIdHex) => self.#sessionManager.getOwnPendingContent(sessionIdHex),
      getPendingAckResolver: (sessionIdHex) => self.#sessionManager.getPendingAckResolver(sessionIdHex),
      setPendingAckResolver: (sessionIdHex, resolve) => { self.#sessionManager.setPendingAckResolver(sessionIdHex, resolve); },
      deletePendingAckResolver: (sessionIdHex) => { self.#sessionManager.deletePendingAckResolver(sessionIdHex); },
      getPersistentSignalingStream: () => self.#signalingManager.getPersistentSignalingStream(),
      setPersistentSignalingStream: (stream) => { self.#signalingManager.setPersistentSignalingStream(stream); },
      setPersistentSignalingIter: (iter) => { self.#signalingManager.setPersistentSignalingIter(iter); },
      openPersistentSignalingStream: () => self.#openPersistentSignalingStream(),
      getRelayStream: (sessionIdHex) => self.#relayStreamManager.getRelayStream(sessionIdHex),
      getDirectoryStream: (sessionIdHex) => self.#relayStreamManager.getDirectoryStream(sessionIdHex),
      enqueueSessionSealedEvent: (sessionIdHex, sealedRoot, closeTimestamp) => {
        self.#sessionManager.enqueueSessionSealedEvent(sessionIdHex, sealedRoot, closeTimestamp);
      },
      sendContentFrame: (session, content, contentHash) => self.#sessionManager.sendContentFrame(session, content, contentHash),
      waitForOwnEcho: (sessionIdHex, seqNum) => self.#sessionManager.waitForOwnEcho(sessionIdHex, seqNum),
      performGapFillReconciliation: (sessionIdHex, fromSeq, toSeq, correlationId) =>
        self.#relayStreamManager.performGapFillReconciliation(sessionIdHex, fromSeq, toSeq, correlationId),
    };
    this.#sealManager = new SealManager(sealCtx, this.#sealFrostTimeoutMs);

    // RelayStreamManager
    const relayCtx: RelayStreamContext = {
      get node() { return self.#node; },
      get keyProvider() { return self.#keyProvider; },
      get logger() { return self.#logger; },
      get persistence() { return self.#persistence; },
      get contentGraceMs() { return self.#contentGraceMs; },
      get reconnectTimeoutMs() { return self.#reconnectTimeoutMs; },
      get hashQueue() { return self.#hashQueue; },
      getMyPubkeyHex: () => self.#myPubkeyHex,
      getSession: (sessionIdHex) => self.#sessionManager.getSession(sessionIdHex),
      getSessions: () => self.#sessionManager.getSessions(),
      getPendingAckResolver: (sessionIdHex) => self.#sessionManager.getPendingAckResolver(sessionIdHex),
      setPendingAckResolver: (sessionIdHex, resolve) => { self.#sessionManager.setPendingAckResolver(sessionIdHex, resolve); },
      deletePendingAckResolver: (sessionIdHex) => { self.#sessionManager.deletePendingAckResolver(sessionIdHex); },
      getOwnPendingContent: (sessionIdHex) => self.#sessionManager.getOwnPendingContent(sessionIdHex),
      getOwnEchoResolvers: (sessionIdHex) => self.#sessionManager.getOwnEchoResolvers(sessionIdHex),
      getOutboundQueue: (sessionIdHex) => self.#sessionManager.getOutboundQueue(sessionIdHex),
      enqueueReceivedMessage: (sessionIdHex, message) => { self.#sessionManager.enqueueReceivedMessage(sessionIdHex, message); },
      wakeReceiveWaiters: (sessionIdHex) => { self.#sessionManager.wakeReceiveWaiters(sessionIdHex); },
      enqueueSessionSealedEvent: (sessionIdHex, sealedRoot, closeTimestamp) => {
        self.#sessionManager.enqueueSessionSealedEvent(sessionIdHex, sealedRoot, closeTimestamp);
      },
      handleSealVerified: (sessionIdHex, frame) => { void self.#sealManager.handleSealVerified(sessionIdHex, frame); },
      handleSessionFrostSealed: (sessionIdHex, frame) => { self.#sealManager.handleSessionFrostSealed(sessionIdHex, frame); },
      handleSealRejectedTreeMismatch: (sessionIdHex, frame) => { self.#sealManager.handleSealRejectedTreeMismatch(sessionIdHex, frame); },
      handleSealUnilateralConfirmed: (sessionIdHex, frame) => { self.#sealManager.handleSealUnilateralConfirmed(sessionIdHex, frame); },
      handleSealUnilateralNotification: (sessionIdHex, frame) => { self.#sealManager.handleSealUnilateralNotification(sessionIdHex, frame); },
      handleDirectorySessionSealed: (sessionIdHex, frame, directoryPubkey) => {
        self.#sealManager.handleDirectorySessionSealed(sessionIdHex, frame, directoryPubkey);
      },
      handleDirectorySessionSealRejected: (sessionIdHex, frame) => {
        self.#sealManager.handleDirectorySessionSealRejected(sessionIdHex, frame);
      },
      onRelayDisconnected: (sessionIdHex, myPubkeyHex) => {
        const session = self.#sessionManager.getSession(sessionIdHex);
        if (!session) return;
        if (session.desynchronized) return;
        if (session.status === "transport_lost") return;
        if (session.status === "sealing" || session.status === "sealed" || session.status === "seal_rejected" || session.status === "seal_deferred") return;
        session.status = "transport_lost";
        void self.#persistence?.persistSession(sessionIdHex, session);
        const ackResolve = self.#sessionManager.getPendingAckResolver(sessionIdHex);
        if (ackResolve) {
          self.#sessionManager.deletePendingAckResolver(sessionIdHex);
          ackResolve({ ok: false, reason: "transport_unavailable" });
        }
        void self.#relayStreamManager.reconnectRelayStream(sessionIdHex, myPubkeyHex);
      },
    };
    this.#relayStreamManager = new RelayStreamManager(relayCtx);
  }

  /**
   * SESSION-005: Set the FROST primary_pubkey for this client.
   */
  setPrimaryPubkey(primaryPubkey: Uint8Array): void {
    this.#sealManager.setMyPrimaryPubkey(new Uint8Array(primaryPubkey));
  }

  /** PERSIST-024: Restore all durable state from SQLCipher. */
  async loadPersistedState(): Promise<void> {
    if (!this.#persistence) return;
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const self = this;
    const startupCtx: StartupContext = {
      get node() { return self.#node; },
      get logger() { return self.#logger; },
      get persistence() { return self.#persistence!; },
      getDirectoryEndpoint: () => self.#directoryEndpoint,
      getThresholdSigner: () => self.#thresholdSigner,
      setThresholdSigner: (signer) => { self.#thresholdSigner = signer; },
      getMyPubkeyHex: () => self.#myPubkeyHex,
      setMyPubkeyHex: (hex) => { self.#myPubkeyHex = hex; },
      setRegistrationState: (state) => { self.#registrationManager.setRegistrationState(state); },
      setMlDsaProvider: (provider) => { self.#registrationManager.setMlDsaProvider(provider); },
      addConnection: (id, record) => { self.#connectionManager.addConnection(id, record); },
      addConnectionByPeer: (pubkey, id) => { self.#connectionManager.addConnectionByPeer(pubkey, id); },
      addProfileUncheckedPeer: (pubkey) => { self.#connectionManager.addProfileUncheckedPeer(pubkey); },
      setConnectionPolicy: (policy) => { self.#connectionManager.setPolicy(policy); },
      addPeer: (hex, entry) => { self.#peers.set(hex, entry); },
      hasPeer: (hex) => self.#peers.has(hex),
      setEndorsements: (e) => { self.#endorsements = e; },
      setAttestations: (a) => { self.#attestations = a; },
      setLoadedPendingHashes: (hashes) => { self.#loadedPendingHashes = hashes; },
      getSessionById: (id) => self.#sessionManager.getSession(id),
      setSession: (id, record) => { self.#sessionManager.setSession(id, record); },
      initSessionMessageQueue: (id) => { self.#sessionManager.initSessionMessageQueue(id); },
      getMyPrimaryPubkey: () => self.#sealManager.getMyPrimaryPubkey(),
      setMyPrimaryPubkey: (pubkey) => { self.#sealManager.setMyPrimaryPubkey(pubkey); },
      restoreDecidedRequest: (id) => { self.#connectionManager.restoreDecidedRequest(id); },
      restorePendingInboundRequest: (opts) => { self.#connectionManager.restorePendingInboundRequest(opts); },
      restoreReviewQueueItem: (opts) => { self.#connectionManager.restoreReviewQueueItem(opts); },
    };
    await loadClientStartupState(startupCtx);
  }

  /**
   * PERSIST-024 FINDING-4: Return the pending hashes loaded during startup.
   */
  getLoadedPendingHashes(): Array<{ sessionId: string; hashHex: string; enqueuedAt: number }> {
    return this.#loadedPendingHashes;
  }

  /**
   * PERSIST-024 AC-008: Set the AgentHashQueue to use for relay resubmission.
   */
  setHashQueue(queue: AgentHashQueue): void {
    this.#hashQueue = queue;
  }

  /**
   * AC-003 (DX-001): Set directory endpoint after construction.
   */
  setDirectoryEndpoint(endpoint: { peer_id: string; multiaddrs: string[] }): void {
    this.#directoryEndpoint = endpoint;
  }

  /**
   * AC-003 (DX-001): Wire threshold signer after construction.
   */
  setThresholdSigner(signer: IThresholdSigner): void {
    this.#thresholdSigner = signer;
  }

  /**
   * PERSIST-024: Wire persistence layer after construction.
   */
  setPersistence(persistence: ClientStatePersistence): void {
    this.#persistence = persistence;
  }

  addPeer(peerPubkeyHex: string, peerId: string, multiaddrs: string[]): void {
    this.#peers.set(peerPubkeyHex, { peerId, multiaddrs, connected: true });
    if (this.#persistence) {
      void this.#persistence.persistPeer({ peerPubkeyHex, peerId, multiaddrs });
    }
  }

  async send(peerPubkeyHex: string, content: Uint8Array): Promise<SendResult> {
    const entry = this.#peers.get(peerPubkeyHex);
    if (!entry) {
      return { delivered: false, reason: "peer_not_connected" };
    }

    const buildResult = await buildEnvelope(content, this.#keyProvider, Date.now());
    if (!buildResult.ok) {
      if (buildResult.error.reason === "content_too_large") {
        return { delivered: false, reason: "content_too_large" };
      }
      return { delivered: false, reason: "connection_lost" };
    }

    const bytes = serializeEnvelope(buildResult.envelope);
    return this.#sendBytes(entry.peerId, bytes, buildResult.envelope.content_hash);
  }

  async openRawStream(peerPubkeyHex: string): Promise<Stream> {
    const entry = this.#peers.get(peerPubkeyHex);
    if (!entry) throw new Error(`peer_not_connected: ${peerPubkeyHex}`);
    return this.#node.newStream(entry.peerId, CELLO_PROTOCOL_ID);
  }

  async openContentStreamByPeerId(peerId: string): Promise<Stream> {
    return this.#node.newStream(peerId, CELLO_CONTENT_PROTOCOL_ID);
  }

  injectLeafDeliver(sessionIdHex: string, frame: Record<string, unknown>): void {
    this.#relayStreamManager.injectLeafDeliver(sessionIdHex, frame);
  }

  injectRelayDisconnect(sessionIdHex: string): void { this.#relayStreamManager.injectRelayDisconnect(sessionIdHex); }

  injectTestSession(
    sessionIdHex: string,
    sessionId: Uint8Array,
    myPubkeyHex: string,
    directoryPubkey: Uint8Array,
    status: SessionRecord["status"] = "active",
    opts?: { isInitiator?: boolean },
  ): void {
    const genesis_prev_root = new Uint8Array(32);
    const counterpartyPubkey = new Uint8Array(32);
    const record: SessionRecord = {
      session_id: sessionId,
      counterparty_pubkey: counterpartyPubkey,
      counterparty_peer_id: "",
      counterparty_multiaddrs: [],
      relay_endpoint: { peer_id: "", multiaddrs: [] },
      directory_endpoint: { peer_id: "", multiaddrs: [] },
      directory_pubkey: directoryPubkey,
      genesis_prev_root,
      last_seen_seq: 0,
      last_sent_seq: 0,
      status,
      local_tree_leaves: [],
      next_expected_seq: 1,
      desynchronized: false,
    };
    this.#sessionManager.setSession(sessionIdHex, record);
    if (!this.#myPubkeyHex) {
      this.#myPubkeyHex = myPubkeyHex;
    }
    if (opts?.isInitiator) {
      this.#sealManager.markSealInitiated(sessionIdHex);
      this.#sealManager.markFrostCeremonyParticipant(sessionIdHex);
    }
  }

  injectDirectoryFrame(sessionIdHex: string, frame: Record<string, unknown>): void {
    const session = this.#sessionManager.getSession(sessionIdHex);
    if (!session) throw new Error(`injectDirectoryFrame: session not found: ${sessionIdHex}`);
    if (frame["type"] === "session_sealed") {
      this.#sealManager.handleDirectorySessionSealed(sessionIdHex, frame, session.directory_pubkey);
    } else if (frame["type"] === "session_seal_rejected") {
      this.#sealManager.handleDirectorySessionSealRejected(sessionIdHex, frame);
    } else if (frame["type"] === "seal_rejected_tree_mismatch") {
      this.#sealManager.handleSealRejectedTreeMismatch(sessionIdHex, frame);
    } else if (frame["type"] === "seal_unilateral_confirmed") {
      this.#sealManager.handleSealUnilateralConfirmed(sessionIdHex, frame);
    } else if (frame["type"] === "seal_unilateral_notification") {
      this.#sealManager.handleSealUnilateralNotification(sessionIdHex, frame);
    } else if (frame["type"] === "seal_verified") {
      void this.#sealManager.handleSealVerified(sessionIdHex, frame);
    } else if (frame["type"] === "session_frost_sealed") {
      this.#sealManager.handleSessionFrostSealed(sessionIdHex, frame);
    }
  }

  async sendRaw(peerPubkeyHex: string, bytes: Uint8Array): Promise<SendResult> {
    const entry = this.#peers.get(peerPubkeyHex);
    if (!entry) {
      return { delivered: false, reason: "peer_not_connected" };
    }
    return this.#sendBytes(entry.peerId, bytes, undefined);
  }

  async #sendBytes(
    peerId: string,
    bytes: Uint8Array,
    contentHash: Uint8Array | undefined
  ): Promise<SendResult> {
    let stream: Stream;
    try {
      stream = await this.#node.newStream(peerId, CELLO_PROTOCOL_ID);
    } catch (err) {
      const reason = isStructuredError(err, "node_stopped") ? "transport_not_started"
        : "peer_unreachable";
      return { delivered: false, reason };
    }

    try {
      stream.send(lp.encode.single(bytes));
      await stream.close();

      try {
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        for await (const _ of lp.decode(stream)) { /* drain */ }
      } catch { /* read side error */ }

      if (stream.status === "reset" || stream.status === "aborted") {
        return { delivered: false, reason: "remote_rejected" };
      }

      const hashHex = contentHash
        ? Buffer.from(contentHash).toString("hex")
        : "";
      return { delivered: true, contentHash: hashHex };
    } catch (err) {
      return { delivered: false, reason: mapSendError(err) };
    }
  }

  // ─── SESSION-002 ─────────────────────────────────────────────────────────────

  async receiveSessionAssignment(
    assignment: SessionAssignment,
    myPubkey: Uint8Array,
  ): Promise<ReceiveAssignmentResult> {
    return this.#sessionManager.receiveSessionAssignment(assignment, myPubkey);
  }

  listSessions(): SessionRecord[] {
    return this.#sessionManager.listSessions();
  }

  async sendMessage(sessionIdHex: string, content: Uint8Array): Promise<SendMessageResult> {
    return this.#sessionManager.sendMessage(sessionIdHex, content);
  }

  receiveMessage(sessionIdHex: string): ReceivedMessage | null {
    return this.#sessionManager.receiveMessage(sessionIdHex);
  }

  receiveAnyMessage(): { sessionIdHex: string; message: ReceivedMessage } | null {
    return this.#sessionManager.receiveAnyMessage();
  }

  async receiveSessionMessageAsync(sessionIdHex: string, timeoutMs: number): Promise<ReceivedMessage | null> {
    return this.#sessionManager.receiveSessionMessageAsync(sessionIdHex, timeoutMs);
  }

  async receiveMessageAsync(timeoutMs: number): Promise<
    | (ReceivedMessage & { sessionIdHex: string })
    | { type: "timeout" }
  > {
    return this.#sessionManager.receiveMessageAsync(timeoutMs);
  }

  async initiateSessionSeal(sessionIdHex: string): Promise<{ ok: true } | { ok: false; reason: string }> {
    return this.#sealManager.initiateSessionSeal(sessionIdHex);
  }

  async initiateUnilateralSeal(
    sessionIdHex: string,
  ): Promise<
    | { ok: true; sealed_root: Uint8Array; sealed_at: number }
    | { ok: false; reason: "too_early"; remaining_seconds: number }
    | { ok: false; reason: string }
  > {
    return this.#sealManager.initiateUnilateralSeal(sessionIdHex);
  }

  closeSession(sessionIdHex: string): void {
    const ackResolve = this.#sessionManager.getPendingAckResolver(sessionIdHex);
    if (ackResolve) {
      this.#sessionManager.deletePendingAckResolver(sessionIdHex);
      ackResolve({ ok: false, reason: "session_closed" });
    }
    this.#sessionManager.closeSession(sessionIdHex);
    this.#relayStreamManager.closeSession(sessionIdHex);
    this.#sealManager.closeSession(sessionIdHex);
  }

  // ─── MSG-002 handlers ─────────────────────────────────────────────────────────

  async registerHandler(): Promise<void> {
    await this.#node.handle(CELLO_PROTOCOL_ID, (stream) => {
      void this.#handleInbound(stream);
    });

    if (this.#directoryEndpoint && !this.#signalingManager.getPersistentSignalingStream()) {
      await this.#openPersistentSignalingStream().catch(() => {});
    }
  }

  async announceToDirectory(): Promise<void> {
    if (this.#directoryEndpoint && !this.#signalingManager.getPersistentSignalingStream()) {
      await this.#openPersistentSignalingStream().catch(() => {});
    }
  }

  // ─── REG-001: Agent registration ─────────────────────────────────────────────

  async register(phoneStub: string = "", preAuthToken?: string): Promise<RegistrationState | { error: string }> {
    return this.#registrationManager.register(phoneStub, preAuthToken);
  }

  async #handleInbound(stream: Stream): Promise<void> {
    let payload: Uint8Array | undefined;
    let timeoutFired = false;

    const readFrame = async (): Promise<void> => {
      for await (const chunk of lp.decode(stream)) {
        payload = (chunk as unknown as { slice(): Uint8Array }).slice();
        return;
      }
    };

    let timerId: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<void>((_, reject) => {
      timerId = setTimeout(() => {
        timeoutFired = true;
        reject(new Error("truncated_frame: read timeout"));
      }, 5_000);
    });

    try {
      await Promise.race([readFrame(), timeout]);
      clearTimeout(timerId);
    } catch {
      clearTimeout(timerId);
      stream.abort(new Error(timeoutFired ? "truncated_frame: read timeout" : "truncated_frame: stream error"));
      return;
    }

    if (!payload) {
      stream.abort(new Error("truncated_frame: no frame received"));
      return;
    }

    const deserResult = deserializeEnvelope(payload);
    if (!deserResult.ok) {
      stream.abort(new Error(`malformed_envelope: ${deserResult.error.reason}`));
      return;
    }

    const validateResult = validateEnvelope(deserResult.envelope);
    if (!validateResult.ok) {
      stream.abort(new Error(`validation_failed: ${validateResult.error.reason}`));
      return;
    }

    const senderHex = Buffer.from(deserResult.envelope.sender_pubkey).toString("hex");
    const received: ReceivedEnvelope = {
      content: deserResult.envelope.content,
      senderPubkey: deserResult.envelope.sender_pubkey,
      contentHash: deserResult.envelope.content_hash,
      timestamp: deserResult.envelope.timestamp,
    };

    if (!this.#receiveQueues.has(senderHex)) {
      this.#receiveQueues.set(senderHex, []);
    }
    this.#receiveQueues.get(senderHex)!.push(received);
    this.#arrivalLog.push({ senderPubkeyHex: senderHex, envelope: received });
    this.#onMessageQueued?.(senderHex);

    await stream.close().catch(() => {});
  }

  receive(senderPubkeyHex: string): ReceivedEnvelope | null {
    const queue = this.#receiveQueues.get(senderPubkeyHex);
    if (!queue || queue.length === 0) return null;
    return queue.shift()!;
  }

  peekAll(): Array<{ senderPubkeyHex: string; envelope: ReceivedEnvelope }> {
    return [...this.#arrivalLog];
  }

  onSessionAssignment(handler: (event: SessionAssignmentEvent) => void): void {
    this.#sessionManager.setOnSessionAssignmentHandler(handler);
  }

  // ─── CONNREQ-002: Connection methods ──────────────────────────────────────────

  onConnectionEstablished(handler: (event: import("@cello-protocol/protocol-types").ConnectionEstablished) => void): void {
    this.#connectionManager.onConnectionEstablished(handler);
  }

  onDisclosureRequested(handler: (event: import("@cello-protocol/protocol-types").DisclosureRequestInbound) => void): void {
    this.#connectionManager.onDisclosureRequested(handler);
  }

  listConnections(): import("@cello-protocol/protocol-types").ClientConnectionRecord[] {
    return this.#connectionManager.listConnections();
  }

  getRegistrationState(): import("@cello-protocol/protocol-types").RegistrationState | null {
    return this.#registrationManager.getRegistrationState();
  }

  getMlDsaProvider(): import("@cello-protocol/crypto").MlDsaKeyProvider | null {
    return this.#registrationManager.getMlDsaProvider();
  }

  setPolicy(policy: import("./connection-policy.js").SignalRequirementPolicy): void {
    this.#connectionManager.setPolicy(policy);
    if (this.#persistence) {
      void this.#persistence.persistConnectionPolicy(policy);
    }
  }

  getPolicy(): import("./connection-policy.js").SignalRequirementPolicy {
    return this.#connectionManager.getPolicy();
  }

  getDirectoryPeerId(): string | null {
    return this.#directoryEndpoint?.peer_id ?? null;
  }

  hasConnection(counterpartyPubkeyHex: string): string | null {
    return this.#connectionManager.hasConnection(counterpartyPubkeyHex);
  }

  async acceptConnection(connectionRequestId: string): Promise<
    | { accepted: true; connection_id: string }
    | { error: { reason: "no_pending_request" | "already_decided" } }
  > {
    return this.#connectionManager.acceptConnection(connectionRequestId);
  }

  async rejectConnection(connectionRequestId: string, reason?: string): Promise<
    | { rejected: true }
    | { error: { reason: "no_pending_request" | "already_decided" } }
  > {
    return this.#connectionManager.rejectConnection(connectionRequestId, reason);
  }

  async requestMoreDisclosure(connectionRequestId: string, requestedItems: unknown[]): Promise<
    | { request_sent: true }
    | { error: { reason: "no_pending_request" | "already_decided" | "max_rounds_reached" } }
  > {
    return this.#connectionManager.requestMoreDisclosure(connectionRequestId, requestedItems);
  }

  async awaitConnectionRequest(timeoutMs = 30_000): Promise<
    | {
        type: "pending_review";
        connection_request_id: string;
        from_pubkey: string;
        report: Extract<import("./connection-policy.js").ConnectionReport, { verdict: "pending_agent_review" }>;
      }
    | { type: "timeout" }
  > {
    return this.#connectionManager.awaitConnectionRequest(timeoutMs);
  }

  async cello_request_connection(opts: {
    target_pubkey: string;
    package_cbor: Uint8Array;
    dialTimeoutMs?: number;
    sendTimeoutMs?: number;
    waitTimeoutMs?: number;
  }): Promise<
    | { result: "established"; connection_id: string }
    | { result: "rejected"; reason: string }
    | { result: "insufficient"; unmet_requirements: unknown[] }
    | { result: "disclosure_requested"; connection_request_id: string; requested_items: unknown[] }
    | { result: "timeout"; stage: "dial" | "send" | "wait" }
    | { result: "error"; reason: string }
  > {
    return this.#connectionManager.cello_request_connection(opts);
  }

  async cello_respond_to_disclosure_request(opts: {
    connection_request_id: string;
    package_cbor: Uint8Array;
  }): Promise<
    | { result: "established"; connection_id: string }
    | { result: "rejected"; reason: string }
    | { result: "insufficient"; unmet_requirements: unknown[] }
    | { result: "timeout" }
    | { result: "error"; reason: string }
  > {
    return this.#connectionManager.cello_respond_to_disclosure_request(opts);
  }

  async cello_request_more_disclosure(opts: {
    connection_request_id: string;
    requested_items: unknown[];
  }): Promise<{ error: "max_rounds_reached" } | { ok: true }> {
    return this.#connectionManager.cello_request_more_disclosure(opts);
  }

  async reconnectDirectory(): Promise<boolean> {
    return this.#signalingManager.reconnectDirectory();
  }

  async getRelayPublicKey(relayId: string): Promise<string | undefined> {
    const pubkeyHex = await this.#signalingManager.getRelayPublicKey(relayId);
    if (pubkeyHex && this.#persistence) {
      void this.#persistence.persistKnownRelay(relayId, pubkeyHex, "directory");
    }
    return pubkeyHex;
  }

  _injectPendingConnectionRequest(opts: {
    connection_request_id: string;
    from_pubkey: string;
    package_cbor: Uint8Array;
    round: number;
  }): void {
    this.#connectionManager._injectPendingConnectionRequest(opts);
  }

  _injectConnectionFrame(frame: Record<string, unknown>): void {
    this.#connectionManager._injectConnectionFrame(frame);
  }

  /**
   * CONNREQ-003 TEST-ONLY: current size of the pending resolver Map.
   */
  get _pendingConnectionRequestResolverCount(): number {
    return this.#connectionManager.pendingConnectionRequestResolverCount;
  }

  // ─── ADAPTER-003: initiateSession ──────────────────────────────────────────

  initiateSession(
    targetPubkeyHex: string,
    opts?: { directoryPeerId?: string; directoryMultiaddr?: string; timeoutMs?: number },
  ): Promise<InitiateSessionResult> {
    return this.#signalingManager.initiateSession(targetPubkeyHex, opts);
  }

  #openPersistentSignalingStream(directoryPeerId?: string, directoryMultiaddr?: string): Promise<boolean> {
    return this.#signalingManager.openPersistentSignalingStream(directoryPeerId, directoryMultiaddr);
  }

  /** Routes decoded signaling frames to the appropriate manager. */
  #dispatchSignalingFrame(stream: Stream, frame: Record<string, unknown>): void {
    dispatchSignalingFrame(stream, frame, {
      signalingManager: this.#signalingManager,
      connectionManager: this.#connectionManager,
      sealManager: this.#sealManager,
      sessionManager: this.#sessionManager,
      logger: this.#logger,
      getMyPubkeyHex: () => this.#myPubkeyHex,
      receiveSessionAssignment: (assignment, myPubkey) => this.receiveSessionAssignment(assignment, myPubkey),
    });
  }

  /**
   * Called by SignalingManager when the persistent signaling stream reader exits.
   * Handles seal reconnect scheduling (seal/seal_deferred sessions).
   */
  #onSignalingStreamClosed(_stream: Stream): void {
    // Unblock pending connection resolvers
    this.#connectionManager.unblockAllOnStreamClose();

    // If any session is sealing or seal_deferred, schedule reconnect
    const pendingSealSessions = Array.from(this.#sessionManager.getSessions().entries())
      .filter(([, s]) => s.status === "sealing" || s.status === "seal_deferred")
      .map(([id]) => id);
    if (pendingSealSessions.length > 0 && this.#directoryEndpoint) {
      this.#logger.info("seal.stream.closed.reconnect.scheduled", {
        pendingSealSessions,
        correlationId: "stream-close",
      });
      setTimeout(() => void this.#openPersistentSignalingStream(), 200);
    }
  }
}

// ─── Re-export parse helpers ──────────────────────────────────────────────────
export { mapSessionRequestErrorFrame };

// ─── Factory ─────────────────────────────────────────────────────────────────

export function createClient(
  node: CelloNode,
  keyProvider: KeyProvider,
  opts?: {
    onMessageQueued?: (senderPubkeyHex: string) => void;
    contentGraceMs?: number;
    reconnectTimeoutMs?: number;
    thresholdSigner?: IThresholdSigner;
    sealFrostTimeoutMs?: number;
    directoryEndpoint?: { peer_id: string; multiaddrs: string[] };
    mlDsaKeyFile?: string;
    connectionPolicy?: import("./connection-policy.js").SignalRequirementPolicy;
    connectionTimeoutMs?: number;
    round2TimeoutMs?: number;
    trackEvaluateCount?: boolean;
    whitelist?: string[];
    onConnectionPendingReview?: (event: import("@cello-protocol/protocol-types").ConnectionRequestInbound) => void;
    crossCheckDirectoryOnInbound?: boolean;
    logger?: Logger;
    persistence?: ClientStatePersistence;
  }
): CelloClient & {
  sendRaw(peerPubkeyHex: string, bytes: Uint8Array): Promise<SendResult>;
  openRawStream(peerPubkeyHex: string): Promise<Stream>;
  openContentStreamByPeerId(peerId: string): Promise<Stream>;
  setPrimaryPubkey(primaryPubkey: Uint8Array): void;
  injectDirectoryFrame(sessionIdHex: string, frame: Record<string, unknown>): void;
  injectLeafDeliver(sessionIdHex: string, frame: Record<string, unknown>): void;
  injectRelayDisconnect(sessionIdHex: string): void;
  injectTestSession(sessionIdHex: string, sessionId: Uint8Array, myPubkeyHex: string, directoryPubkey: Uint8Array, status?: SessionRecord["status"], opts?: { isInitiator?: boolean }): void;
  listConnections(): import("@cello-protocol/protocol-types").ClientConnectionRecord[];
  cello_request_connection(opts: { target_pubkey: string; package_cbor: Uint8Array; dialTimeoutMs?: number; sendTimeoutMs?: number; waitTimeoutMs?: number }): Promise<
    | { result: "established"; connection_id: string }
    | { result: "rejected"; reason: string }
    | { result: "insufficient"; unmet_requirements: unknown[] }
    | { result: "disclosure_requested"; connection_request_id: string; requested_items: unknown[] }
    | { result: "timeout"; stage: "dial" | "send" | "wait" }
    | { result: "error"; reason: string }
  >;
  cello_respond_to_disclosure_request(opts: { connection_request_id: string; package_cbor: Uint8Array }): Promise<
    | { result: "established"; connection_id: string }
    | { result: "rejected"; reason: string }
    | { result: "insufficient"; unmet_requirements: unknown[] }
    | { result: "timeout" }
    | { result: "error"; reason: string }
  >;
  cello_request_more_disclosure(opts: { connection_request_id: string; requested_items: unknown[] }): Promise<{ error: "max_rounds_reached" } | { ok: true }>;
  onConnectionEstablished(handler: (event: import("@cello-protocol/protocol-types").ConnectionEstablished) => void): void;
  onDisclosureRequested(handler: (event: import("@cello-protocol/protocol-types").DisclosureRequestInbound) => void): void;
  reconnectDirectory(): Promise<boolean>;
  initiateUnilateralSeal(sessionIdHex: string): Promise<
    | { ok: true; sealed_root: Uint8Array; sealed_at: number }
    | { ok: false; reason: "too_early"; remaining_seconds: number }
    | { ok: false; reason: string }
  >;
  _injectPendingConnectionRequest(opts: { connection_request_id: string; from_pubkey: string; package_cbor: Uint8Array; round: number }): void;
  _injectConnectionFrame(frame: Record<string, unknown>): void;
  _pendingConnectionRequestResolverCount: number;
  _evaluateCallCount: number;
  loadPersistedState(): Promise<void>;
  getLoadedPendingHashes(): Array<{ sessionId: string; hashHex: string; enqueuedAt: number }>;
  announceToDirectory(): Promise<void>;
} {
  return new CelloClientImpl(
    node,
    keyProvider,
    opts?.onMessageQueued,
    opts?.contentGraceMs,
    opts?.reconnectTimeoutMs,
    opts?.thresholdSigner,
    opts?.sealFrostTimeoutMs,
    opts?.directoryEndpoint ?? null,
    opts?.mlDsaKeyFile,
    opts?.connectionPolicy,
    opts?.connectionTimeoutMs,
    opts?.round2TimeoutMs,
    opts?.trackEvaluateCount,
    opts?.whitelist,
    opts?.onConnectionPendingReview,
    opts?.crossCheckDirectoryOnInbound,
    opts?.logger,
    opts?.persistence,
  ) as unknown as CelloClient & {
    sendRaw(peerPubkeyHex: string, bytes: Uint8Array): Promise<SendResult>;
    openRawStream(peerPubkeyHex: string): Promise<Stream>;
    openContentStreamByPeerId(peerId: string): Promise<Stream>;
    setPrimaryPubkey(primaryPubkey: Uint8Array): void;
    injectDirectoryFrame(sessionIdHex: string, frame: Record<string, unknown>): void;
    injectLeafDeliver(sessionIdHex: string, frame: Record<string, unknown>): void;
    injectRelayDisconnect(sessionIdHex: string): void;
    injectTestSession(sessionIdHex: string, sessionId: Uint8Array, myPubkeyHex: string, directoryPubkey: Uint8Array, status?: SessionRecord["status"], opts?: { isInitiator?: boolean }): void;
    listConnections(): import("@cello-protocol/protocol-types").ClientConnectionRecord[];
    cello_request_connection(opts: { target_pubkey: string; package_cbor: Uint8Array; dialTimeoutMs?: number; sendTimeoutMs?: number; waitTimeoutMs?: number }): Promise<
      | { result: "established"; connection_id: string }
      | { result: "rejected"; reason: string }
      | { result: "insufficient"; unmet_requirements: unknown[] }
      | { result: "disclosure_requested"; connection_request_id: string; requested_items: unknown[] }
      | { result: "timeout"; stage: "dial" | "send" | "wait" }
      | { result: "error"; reason: string }
    >;
    cello_respond_to_disclosure_request(opts: { connection_request_id: string; package_cbor: Uint8Array }): Promise<
      | { result: "established"; connection_id: string }
      | { result: "rejected"; reason: string }
      | { result: "insufficient"; unmet_requirements: unknown[] }
      | { result: "timeout" }
      | { result: "error"; reason: string }
    >;
    cello_request_more_disclosure(opts: { connection_request_id: string; requested_items: unknown[] }): Promise<{ error: "max_rounds_reached" } | { ok: true }>;
    onConnectionEstablished(handler: (event: import("@cello-protocol/protocol-types").ConnectionEstablished) => void): void;
    onDisclosureRequested(handler: (event: import("@cello-protocol/protocol-types").DisclosureRequestInbound) => void): void;
    reconnectDirectory(): Promise<boolean>;
    initiateUnilateralSeal(sessionIdHex: string): Promise<
      | { ok: true; sealed_root: Uint8Array; sealed_at: number }
      | { ok: false; reason: "too_early"; remaining_seconds: number }
      | { ok: false; reason: string }
    >;
    _injectPendingConnectionRequest(opts: { connection_request_id: string; from_pubkey: string; package_cbor: Uint8Array; round: number }): void;
    _injectConnectionFrame(frame: Record<string, unknown>): void;
    _pendingConnectionRequestResolverCount: number;
    _evaluateCallCount: number;
    loadPersistedState(): Promise<void>;
    getLoadedPendingHashes(): Array<{ sessionId: string; hashHex: string; enqueuedAt: number }>;
    announceToDirectory(): Promise<void>;
  };
}

// ─── Error helpers ────────────────────────────────────────────────────────────

function isStructuredError(err: unknown, reason: string): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    "reason" in err &&
    (err as Record<string, unknown>).reason === reason
  );
}

function mapSendError(err: unknown): "remote_rejected" | "connection_lost" | "peer_unreachable" | "transport_not_started" {
  if (isStructuredError(err, "node_stopped")) return "transport_not_started";
  if (isStructuredError(err, "connection_lost")) return "connection_lost";
  if (isStructuredError(err, "protocol_not_supported")) return "peer_unreachable";
  const msg = err instanceof Error ? err.message : String(err);
  if (msg.includes("reset") || msg.includes("aborted")) return "remote_rejected";
  return "connection_lost";
}
