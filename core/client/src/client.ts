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
import { parseSessionAssignment, mapSessionRequestErrorFrame } from "./session-assignment-parser.js";

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

  // Note: session, relay-stream, and seal state are owned by their respective managers.

  // ─── ADAPTER-003: persistent directory signaling stream ────────────────────

  /** Configured directory endpoint (required for initiateSession). ADAPTER-003. */
  #directoryEndpoint: { peer_id: string; multiaddrs: string[] } | null;

  /** Single persistent signaling stream shared across all session_request outbound calls
   * and inbound session_assignment / session_sealed events. ADAPTER-003. */
  #persistentSignalingStream: Stream | null = null;
  #persistentSignalingIter: AsyncIterator<Uint8Array> | null = null;

  /** Pending resolver for the in-flight session_request → session_assignment/error.
   * At most one session_request is in-flight at a time per signaling stream.
   * Receives the raw decoded CBOR frame (session_assignment or session_request_error). */
  #pendingSessionRequestResolve: ((frame: Record<string, unknown>) => void) | null = null;

  /** In-flight promise for #openPersistentSignalingStream — prevents concurrent open attempts. */
  #openingSignalingStream: Promise<boolean> | null = null;

  // Note: seal state (sealFrostResolvers, sealVerifiedData, frostCeremonyParticipant,
  // sealInitiatedSessions, pendingUnilateralSealResolve, myPrimaryPubkey) is owned by SealManager.

  // ─── REG-001: Registration state ────────────────────────────────────────────

  /** Cached registration state — set after a successful register() call. */
  #registrationState: RegistrationState | null = null;

  /** Pending resolver for register_success / register_error from directory. */
  #pendingRegisterResolve: ((frame: Record<string, unknown>) => void) | null = null;
  /** Pending resolver for dkg_ready from directory (part of register flow). */
  #pendingDkgReadyResolve: ((frame: Record<string, unknown>) => void) | null = null;
  // Note: #pendingUnilateralSealResolve moved to SealManager.

  /** Optional path for persisting the ML-DSA keypair (FileMlDsaKeyProvider). REG-001 AC-010. */
  readonly #mlDsaKeyFile: string | undefined;

  /** ML-DSA key provider stored after successful register() call. Used to sign ConnectionPackages. CELLO-MCP-003. */
  #mlDsaProvider: import("@cello-protocol/crypto").MlDsaKeyProvider | null = null;

  // ─── CONNREQ-002: Connection state ────────────────────────────────────────────

  /** connection_id → ClientConnectionRecord */
  readonly #connections = new Map<string, import("@cello-protocol/protocol-types").ClientConnectionRecord>();
  /** counterparty_pubkey_hex → connection_id (for fast lookup by peer) */
  readonly #connectionsByPeer = new Map<string, string>();

  /** Connection policy for evaluating inbound connection_request_inbound frames. Mutable via setPolicy(). */
  #connectionPolicy: import("./connection-policy.js").SignalRequirementPolicy | undefined;
  /** Overall connection timeout in ms (default 300s). Injected for tests. */
  readonly #connectionTimeoutMs: number;
  /** Round 2 silence timeout in ms (default 120s). Injected for tests. */
  readonly #round2TimeoutMs: number;
  /** If true, expose _evaluateCallCount on the instance for test assertions. */
  readonly #trackEvaluateCount: boolean;
  /** Whitelist: sender pubkeys that bypass evaluateConnectionPackage. */
  readonly #whitelist: string[];
  /** Callback fired when an inbound connection_request_inbound is queued for agent review. */
  readonly #onConnectionPendingReview: ((event: import("@cello-protocol/protocol-types").ConnectionRequestInbound) => void) | undefined;
  /** DB-003: if true, attempt cross-check of sender's ml_dsa_pubkey on inbound requests. */
  readonly #crossCheckDirectoryOnInbound: boolean;
  /** DB-003: peers whose connection was accepted without successful cross-check. */
  readonly #profileUncheckedPeers = new Set<string>();

  /** Counter incremented each time evaluateConnectionPackage is called (trackEvaluateCount=true). */
  _evaluateCallCount = 0;

  /** Callback fired when a connection_established event arrives. */
  #onConnectionEstablishedHandler: ((event: import("@cello-protocol/protocol-types").ConnectionEstablished) => void) | undefined;
  /** Callback fired when a disclosure_request_inbound arrives. */
  #onDisclosureRequestedHandler: ((event: import("@cello-protocol/protocol-types").DisclosureRequestInbound) => void) | undefined;

  // Connection request resolver state moved to ConnectionManager

  /**
   * CONNREQ-003: TEST-ONLY escape hatch exposing resolver map size for memory-leak assertions.
   * Read by connreq-003 tests via (client as any)._pendingConnectionRequestResolverCount.
   */
  get _pendingConnectionRequestResolverCount(): number {
    return this.#connectionManager.pendingConnectionRequestResolverCount;
  }

  // Connection request await/inbound/review/decided state moved to ConnectionManager

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
  // Set by the composition root via setHashQueue() after loadPersistedState().
  // Populated from pending_hashes DB table. Resubmission occurs on relay reconnect.
  #hashQueue: AgentHashQueue | null = null;

  // ─── PERSIST-024: In-memory endorsement/attestation caches ───────────────────
  #endorsements: Array<Record<string, unknown>> = [];
  #attestations: Array<Record<string, unknown>> = [];

  // ─── PERSIST-024 FINDING-4: pending hashes loaded on startup ────────────────
  // These are populated by loadPersistedState() from the DB pending_hashes table.
  // The caller (composition root) is responsible for passing them to AgentHashQueue
  // so they are resubmitted to the relay on reconnect (AC-008).
  // Access via getLoadedPendingHashes() after loadPersistedState() returns.
  #loadedPendingHashes: Array<{ sessionId: string; hashHex: string; enqueuedAt: number }> = [];

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
    this.#mlDsaKeyFile = mlDsaKeyFile;
    this.#connectionPolicy = connectionPolicy;
    this.#connectionTimeoutMs = connectionTimeoutMs;
    this.#round2TimeoutMs = round2TimeoutMs;
    this.#trackEvaluateCount = trackEvaluateCount;
    this.#whitelist = whitelist;
    this.#onConnectionPendingReview = onConnectionPendingReview;
    this.#crossCheckDirectoryOnInbound = crossCheckDirectoryOnInbound;
    this.#logger = logger ?? { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };
    this.#persistence = persistence ?? null;

    // Wire up RegistrationManager with narrow context interface
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const self = this;
    const regCtx: RegistrationContext = {
      get node() { return self.#node; },
      get keyProvider() { return self.#keyProvider; },
      get logger() { return self.#logger; },
      get persistence() { return self.#persistence; },
      get mlDsaKeyFile() { return self.#mlDsaKeyFile; },
      getMyPubkeyHex: () => self.#myPubkeyHex,
      setMyPubkeyHex: (hex: string) => { self.#myPubkeyHex = hex; },
      getDirectoryEndpoint: () => self.#directoryEndpoint,
      getThresholdSigner: () => self.#thresholdSigner,
      setThresholdSigner: (signer: IThresholdSigner) => { self.#thresholdSigner = signer; },
      getRegistrationState: () => self.#registrationState,
      setRegistrationState: (state: RegistrationState | null) => { self.#registrationState = state; },
      getMlDsaProvider: () => self.#mlDsaProvider,
      setMlDsaProvider: (provider: import("@cello-protocol/crypto").MlDsaKeyProvider | null) => { self.#mlDsaProvider = provider; },
      getMyPrimaryPubkey: () => self.#sealManager.getMyPrimaryPubkey(),
      setMyPrimaryPubkey: (pubkey: Uint8Array) => { self.#sealManager.setMyPrimaryPubkey(new Uint8Array(pubkey)); },
      getPersistentSignalingStream: () => self.#persistentSignalingStream,
      openPersistentSignalingStream: () => self.#openPersistentSignalingStream(),
      setPendingDkgReadyResolve: (resolve) => { self.#pendingDkgReadyResolve = resolve; },
      setPendingRegisterResolve: (resolve) => { self.#pendingRegisterResolve = resolve; },
    };
    this.#registrationManager = new RegistrationManager(regCtx);

    // Wire up ConnectionManager with narrow context interface
    const connCtx: ConnectionContext = {
      get logger() { return self.#logger; },
      get persistence() { return self.#persistence; },
      get connectionTimeoutMs() { return self.#connectionTimeoutMs; },
      get round2TimeoutMs() { return self.#round2TimeoutMs; },
      get trackEvaluateCount() { return self.#trackEvaluateCount; },
      get whitelist() { return self.#whitelist; },
      get crossCheckDirectoryOnInbound() { return self.#crossCheckDirectoryOnInbound; },
      get connectionPolicy() { return self.#connectionPolicy; },
      get onConnectionPendingReview() { return self.#onConnectionPendingReview; },
      get onConnectionEstablishedHandler() { return self.#onConnectionEstablishedHandler; },
      get onDisclosureRequestedHandler() { return self.#onDisclosureRequestedHandler; },
      getPersistentSignalingStream: () => self.#persistentSignalingStream,
      openPersistentSignalingStream: () => self.#openPersistentSignalingStream(),
      getConnectionsByPeer: () => self.#connectionsByPeer,
      getConnections: () => self.#connections,
      getProfileUncheckedPeers: () => self.#profileUncheckedPeers,
      incrementEvaluateCallCount: () => { self._evaluateCallCount++; },
    };
    this.#connectionManager = new ConnectionManager(connCtx);

    // Wire up SignalingManager with narrow context interface
    const sigCtx: SignalingContext = {
      get node() { return self.#node; },
      get keyProvider() { return self.#keyProvider; },
      get logger() { return self.#logger; },
      getMyPubkeyHex: () => self.#myPubkeyHex,
      setMyPubkeyHex: (hex: string) => { self.#myPubkeyHex = hex; },
      getDirectoryEndpoint: () => self.#directoryEndpoint,
      getPersistentSignalingStream: () => self.#persistentSignalingStream,
      setPersistentSignalingStream: (stream) => { self.#persistentSignalingStream = stream; },
      setPersistentSignalingIter: (iter) => { self.#persistentSignalingIter = iter; },
      getOpeningSignalingStream: () => self.#openingSignalingStream,
      setOpeningSignalingStream: (p) => { self.#openingSignalingStream = p; },
      getDirectoryStream: (sessionIdHex) => self.#relayStreamManager.getDirectoryStream(sessionIdHex),
      setDirectoryStream: (sessionIdHex, stream) => { self.#relayStreamManager.setDirectoryStream(sessionIdHex, stream); },
      deleteDirectoryStream: (sessionIdHex) => { self.#relayStreamManager.deleteDirectoryStream(sessionIdHex); },
      hasPendingSessionRequest: () => self.#pendingSessionRequestResolve !== null,
      hasPendingRegister: () => self.#pendingRegisterResolve !== null,
      hasPendingDkgReady: () => self.#pendingDkgReadyResolve !== null,
      getPendingConnectionResolverCount: () => self.#connectionManager.pendingConnectionRequestResolverCount,
      dispatchSignalingFrame: (stream, frame) => { self.#dispatchSignalingFrame(stream, frame); },
      onSignalingStreamClosed: (stream) => { self.#onSignalingStreamClosed(stream); },
      // initiateSession dependencies
      getConnectionIdForPeer: (hex) => self.#connectionsByPeer.get(hex),
      hasConnectionPolicy: () => self.#connectionPolicy !== undefined,
      getPendingSessionRequestResolve: () => self.#pendingSessionRequestResolve,
      setPendingSessionRequestResolve: (r) => { self.#pendingSessionRequestResolve = r; },
      receiveSessionAssignment: (assignment, myPubkey) => self.receiveSessionAssignment(assignment, myPubkey),
      getSession: (sessionIdHex) => self.#sessionManager.getSession(sessionIdHex),
    };
    this.#signalingManager = new SignalingManager(sigCtx);

    // Wire up SessionManager with thin context interface
    // (managers are wired before any method is called — lazy callbacks are safe)
    const sessionCtx: SessionContext = {
      get logger() { return self.#logger; },
      get persistence() { return self.#persistence; },
      get keyProvider() { return self.#keyProvider; },
      get node() { return self.#node; },
      getMyPubkeyHex: () => self.#myPubkeyHex,
      setMyPubkeyHex: (hex) => { self.#myPubkeyHex = hex; },
      getThresholdSigner: () => self.#thresholdSigner,
      getPersistentSignalingStream: () => self.#persistentSignalingStream,
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

    // Wire up SealManager with thin context interface
    const sealCtx: SealContext = {
      get logger() { return self.#logger; },
      get persistence() { return self.#persistence; },
      get keyProvider() { return self.#keyProvider; },
      getMyPubkeyHex: () => self.#myPubkeyHex,
      getThresholdSigner: () => self.#thresholdSigner,
      // From SessionManager (lazy — safe since managers are wired before any method is called)
      getSession: (sessionIdHex) => self.#sessionManager.getSession(sessionIdHex),
      getSessions: () => self.#sessionManager.getSessions(),
      getOwnPendingContent: (sessionIdHex) => self.#sessionManager.getOwnPendingContent(sessionIdHex),
      getPendingAckResolver: (sessionIdHex) => self.#sessionManager.getPendingAckResolver(sessionIdHex),
      setPendingAckResolver: (sessionIdHex, resolve) => { self.#sessionManager.setPendingAckResolver(sessionIdHex, resolve); },
      deletePendingAckResolver: (sessionIdHex) => { self.#sessionManager.deletePendingAckResolver(sessionIdHex); },
      // From SignalingManager
      getPersistentSignalingStream: () => self.#persistentSignalingStream,
      setPersistentSignalingStream: (stream) => { self.#persistentSignalingStream = stream; },
      setPersistentSignalingIter: (iter) => { self.#persistentSignalingIter = iter; },
      openPersistentSignalingStream: () => self.#openPersistentSignalingStream(),
      // From RelayStreamManager
      getRelayStream: (sessionIdHex) => self.#relayStreamManager.getRelayStream(sessionIdHex),
      getDirectoryStream: (sessionIdHex) => self.#relayStreamManager.getDirectoryStream(sessionIdHex),
      // Callbacks into SessionManager
      enqueueSessionSealedEvent: (sessionIdHex, sealedRoot, closeTimestamp) => {
        self.#sessionManager.enqueueSessionSealedEvent(sessionIdHex, sealedRoot, closeTimestamp);
      },
      sendContentFrame: (session, content, contentHash) => self.#sessionManager.sendContentFrame(session, content, contentHash),
      waitForOwnEcho: (sessionIdHex, seqNum) => self.#sessionManager.waitForOwnEcho(sessionIdHex, seqNum),
      // Callback into RelayStreamManager
      performGapFillReconciliation: (sessionIdHex, fromSeq, toSeq, correlationId) =>
        self.#relayStreamManager.performGapFillReconciliation(sessionIdHex, fromSeq, toSeq, correlationId),
    };
    this.#sealManager = new SealManager(sealCtx, this.#sealFrostTimeoutMs);

    // Wire up RelayStreamManager with thin context interface
    const relayCtx: RelayStreamContext = {
      get node() { return self.#node; },
      get keyProvider() { return self.#keyProvider; },
      get logger() { return self.#logger; },
      get persistence() { return self.#persistence; },
      get contentGraceMs() { return self.#contentGraceMs; },
      get reconnectTimeoutMs() { return self.#reconnectTimeoutMs; },
      get hashQueue() { return self.#hashQueue; },
      getMyPubkeyHex: () => self.#myPubkeyHex,
      // From SessionManager (lazy — safe since managers are wired before any method is called)
      getSession: (sessionIdHex) => self.#sessionManager.getSession(sessionIdHex),
      getSessions: () => self.#sessionManager.getSessions(),
      getPendingAckResolver: (sessionIdHex) => self.#sessionManager.getPendingAckResolver(sessionIdHex),
      setPendingAckResolver: (sessionIdHex, resolve) => { self.#sessionManager.setPendingAckResolver(sessionIdHex, resolve); },
      deletePendingAckResolver: (sessionIdHex) => { self.#sessionManager.deletePendingAckResolver(sessionIdHex); },
      getOwnPendingContent: (sessionIdHex) => self.#sessionManager.getOwnPendingContent(sessionIdHex),
      getOwnEchoResolvers: (sessionIdHex) => self.#sessionManager.getOwnEchoResolvers(sessionIdHex),
      getOutboundQueue: (sessionIdHex) => self.#sessionManager.getOutboundQueue(sessionIdHex),
      // Delivery callbacks into SessionManager
      enqueueReceivedMessage: (sessionIdHex, message) => { self.#sessionManager.enqueueReceivedMessage(sessionIdHex, message); },
      wakeReceiveWaiters: (sessionIdHex) => { self.#sessionManager.wakeReceiveWaiters(sessionIdHex); },
      enqueueSessionSealedEvent: (sessionIdHex, sealedRoot, closeTimestamp) => {
        self.#sessionManager.enqueueSessionSealedEvent(sessionIdHex, sealedRoot, closeTimestamp);
      },
      // Seal callbacks (lazy)
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
      // Reconnect callback
      onRelayDisconnected: (sessionIdHex, myPubkeyHex) => {
        const session = self.#sessionManager.getSession(sessionIdHex);
        if (!session) return;
        if (session.desynchronized) return;
        if (session.status === "transport_lost") return;
        // Sealing/sealed/seal_rejected/seal_deferred: relay close expected; do not clobber status.
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
   * Call after bootstrapKeyShares to register the group public key.
   * Used for verifying incoming session_sealed FROST signatures when this client
   * is the seal initiator.
   */
  setPrimaryPubkey(primaryPubkey: Uint8Array): void {
    this.#sealManager.setMyPrimaryPubkey(new Uint8Array(primaryPubkey));
  }

  /** PERSIST-024: Restore all durable state from SQLCipher. Implementation in client-startup.ts. */
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
      setRegistrationState: (state) => { self.#registrationState = state; },
      setMlDsaProvider: (provider) => { self.#mlDsaProvider = provider; },
      addConnection: (id, record) => { self.#connections.set(id, record); },
      addConnectionByPeer: (pubkey, id) => { self.#connectionsByPeer.set(pubkey, id); },
      addProfileUncheckedPeer: (pubkey) => { self.#profileUncheckedPeers.add(pubkey); },
      setConnectionPolicy: (policy) => { self.#connectionPolicy = policy; },
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
   *
   * Call after loadPersistedState() to retrieve hashes that were pending relay
   * submission when the agent last shut down. The composition root must pass these
   * to AgentHashQueue.enqueue() so they are resubmitted to the relay on reconnect.
   *
   * Returns an empty array if loadPersistedState() has not yet been called, if
   * no persistence is configured, or if no hashes were pending.
   */
  getLoadedPendingHashes(): Array<{ sessionId: string; hashHex: string; enqueuedAt: number }> {
    return this.#loadedPendingHashes;
  }

  /**
   * PERSIST-024 AC-008: Set the AgentHashQueue to use for relay resubmission.
   *
   * Called by the composition root after loadPersistedState() and after calling
   * queue.loadPending(client.getLoadedPendingHashes()). On relay reconnect,
   * #reconnectRelayStream will drain the queue for the reconnected session.
   */
  setHashQueue(queue: AgentHashQueue): void {
    this.#hashQueue = queue;
  }

  /**
   * AC-003 (DX-001): Set directory endpoint after construction (composition root pattern).
   * Called by cello-mcp.ts background task before loadPersistedState() so that
   * loadPersistedState() can populate directoryNodeStubs in the reconstructed FrostThresholdSigner.
   */
  setDirectoryEndpoint(endpoint: { peer_id: string; multiaddrs: string[] }): void {
    this.#directoryEndpoint = endpoint;
  }

  /**
   * AC-003 (DX-001): Wire threshold signer after construction.
   * Called by cello-mcp.ts background task only when the agent is not yet registered
   * (bootstrap ran). Registered agents reconstruct the signer from DB in loadPersistedState().
   */
  setThresholdSigner(signer: IThresholdSigner): void {
    this.#thresholdSigner = signer;
  }

  /**
   * PERSIST-024: Wire persistence layer after construction.
   * Called by cello-mcp.ts background task after SQLCipher store opens.
   */
  setPersistence(persistence: ClientStatePersistence): void {
    this.#persistence = persistence;
  }

  addPeer(peerPubkeyHex: string, peerId: string, multiaddrs: string[]): void {
    this.#peers.set(peerPubkeyHex, { peerId, multiaddrs, connected: true });
    // PERSIST-024: persist peer to DB
    if (this.#persistence) {
      void this.#persistence.persistPeer({ peerPubkeyHex, peerId, multiaddrs });
    }
  }

  async send(peerPubkeyHex: string, content: Uint8Array): Promise<SendResult> {
    // Step 1: registry lookup
    const entry = this.#peers.get(peerPubkeyHex);
    if (!entry) {
      return { delivered: false, reason: "peer_not_connected" };
    }

    // Step 2: build envelope — catches content_too_large before any I/O
    const buildResult = await buildEnvelope(content, this.#keyProvider, Date.now());
    if (!buildResult.ok) {
      if (buildResult.error.reason === "content_too_large") {
        return { delivered: false, reason: "content_too_large" };
      }
      return { delivered: false, reason: "connection_lost" };
    }

    // Step 3: serialize
    const bytes = serializeEnvelope(buildResult.envelope);

    return this.#sendBytes(entry.peerId, bytes, buildResult.envelope.content_hash);
  }

  // Internal test escape: open a raw stream directly to peer without building an envelope.
  // Used by AC-012 to write truncated/malformed bytes.
  async openRawStream(peerPubkeyHex: string): Promise<Stream> {
    const entry = this.#peers.get(peerPubkeyHex);
    if (!entry) throw new Error(`peer_not_connected: ${peerPubkeyHex}`);
    return this.#node.newStream(entry.peerId, CELLO_PROTOCOL_ID);
  }

  // Internal test escape: open a raw content protocol stream to peer by peerId string.
  // Used by AC-003 to inject tampered content frames directly.
  async openContentStreamByPeerId(peerId: string): Promise<Stream> {
    return this.#node.newStream(peerId, CELLO_CONTENT_PROTOCOL_ID);
  }

  // Internal test escape: directly feed a leaf_deliver frame into the relay stream handler.
  // Used by AC-004 through AC-008 to inject adversarial frames without a compromised relay.
  injectLeafDeliver(sessionIdHex: string, frame: Record<string, unknown>): void {
    this.#relayStreamManager.injectLeafDeliver(sessionIdHex, frame);
  }

  // Internal test escape: trigger relay disconnect handling for a session.
  // Used by SESSION-006 tests to simulate relay stream drop without a real network event.
  injectRelayDisconnect(sessionIdHex: string): void { this.#relayStreamManager.injectRelayDisconnect(sessionIdHex); }

  // Internal test escape: inject a minimal session record directly into #sessions.
  // Bypasses receiveSessionAssignment (which requires a real relay) for unit tests
  // that need to test session_sealed, FROST verification, etc. without a relay.
  // TEST-ONLY: only intended for use in unit tests; not exposed in the CelloClient type.
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
    // M-001: mark as seal-initiated and FROST ceremony participant so #handleFrostSealed
    // uses own primary_pubkey for verification.
    if (opts?.isInitiator) {
      this.#sealManager.markSealInitiated(sessionIdHex);
      this.#sealManager.markFrostCeremonyParticipant(sessionIdHex);
    }
  }

  // Internal test escape: directly feed a session_sealed, session_seal_rejected,
  // seal_verified, or session_frost_sealed frame into the directory stream handler —
  // bypasses the real directory signaling stream so tests can inject adversarial frames.
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

  // Internal: open stream, write LP-framed bytes, await close type.
  // Exposed as sendRaw for test injection of tampered envelopes.
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
    // Step 4: open stream
    let stream: Stream;
    try {
      stream = await this.#node.newStream(peerId, CELLO_PROTOCOL_ID);
    } catch (err) {
      // node_stopped → transport issue; connection_lost from newStream means no prior
      // connection to this peer (= unreachable); protocol error also = unreachable
      const reason = isStructuredError(err, "node_stopped") ? "transport_not_started"
        : "peer_unreachable";
      return { delivered: false, reason };
    }

    try {
      // Step 5: write LP-framed bytes
      stream.send(lp.encode.single(bytes));

      // Step 6: half-close write side
      await stream.close();

      // Step 7: drain read side — the close type tells us the outcome
      try {
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        for await (const _ of lp.decode(stream)) {
          // Receiver never sends data — drain any unexpected bytes and discard
        }
      } catch {
        // Read side error — check stream status to classify
      }

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

  /**
   * Process a SessionAssignment pushed by the directory.
   * SESSION-002 AC-002, AC-003, AC-004, AC-005, SI-003.
   *
   * Crypto refs:
   *   Ed25519 verification: RFC 8032
   *   SHA-256: FIPS 180-4
   */
  async receiveSessionAssignment(
    assignment: SessionAssignment,
    myPubkey: Uint8Array,
  ): Promise<ReceiveAssignmentResult> {
    return this.#sessionManager.receiveSessionAssignment(assignment, myPubkey);
  }

  listSessions(): SessionRecord[] {
    return this.#sessionManager.listSessions();
  }

  // ─── MSG-004 implementation ──────────────────────────────────────────────────

  async sendMessage(sessionIdHex: string, content: Uint8Array): Promise<SendMessageResult> {
    return this.#sessionManager.sendMessage(sessionIdHex, content);
  }

  receiveMessage(sessionIdHex: string): ReceivedMessage | null {
    return this.#sessionManager.receiveMessage(sessionIdHex);
  }

  receiveAnyMessage(): { sessionIdHex: string; message: ReceivedMessage } | null {
    return this.#sessionManager.receiveAnyMessage();
  }

  // ─── SESSION-007: async blocking receive ─────────────────────────────────────

  async receiveSessionMessageAsync(sessionIdHex: string, timeoutMs: number): Promise<ReceivedMessage | null> {
    return this.#sessionManager.receiveSessionMessageAsync(sessionIdHex, timeoutMs);
  }

  async receiveMessageAsync(timeoutMs: number): Promise<
    | (ReceivedMessage & { sessionIdHex: string })
    | { type: "timeout" }
  > {
    return this.#sessionManager.receiveMessageAsync(timeoutMs);
  }


  // ─── SESSION-003: seal ceremony ──────────────────────────────────────────────

  async initiateSessionSeal(sessionIdHex: string): Promise<{ ok: true } | { ok: false; reason: string }> {
    return this.#sealManager.initiateSessionSeal(sessionIdHex);
  }

  // PERSIST-015: send seal_unilateral to the directory after delivery_grace_seconds elapses.
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
    // Unblock any pending ack resolver before deleting from SessionManager
    const ackResolve = this.#sessionManager.getPendingAckResolver(sessionIdHex);
    if (ackResolve) {
      this.#sessionManager.deletePendingAckResolver(sessionIdHex);
      ackResolve({ ok: false, reason: "session_closed" });
    }
    // Delegate cleanup to each owning manager
    this.#sessionManager.closeSession(sessionIdHex);
    this.#relayStreamManager.closeSession(sessionIdHex);
    this.#sealManager.closeSession(sessionIdHex);
  }

  // ─── MSG-002 handlers ─────────────────────────────────────────────────────────

  async registerHandler(): Promise<void> {
    await this.#node.handle(CELLO_PROTOCOL_ID, (stream) => {
      void this.#handleInbound(stream);
    });

    // ADAPTER-003: if a directory endpoint is configured, pre-authenticate now.
    // This registers this client's stream with the directory so the directory can
    // deliver inbound session_assignment frames (participant B role) without waiting
    // for this client to call initiateSession first.
    // Awaited here so that by the time registerHandler returns, the stream is established
    // and the directory knows this client is reachable.
    // Best-effort: failure is non-fatal (stream will be re-opened on first initiateSession call).
    if (this.#directoryEndpoint && !this.#persistentSignalingStream) {
      await this.#openPersistentSignalingStream().catch(() => {
        // Ignore failure — stream will be opened lazily on first initiateSession call
      });
    }
  }

  /**
   * Open the persistent signaling stream to the directory if not already open.
   * Call this after setDirectoryEndpoint() to announce presence to the directory.
   * Safe to call multiple times — no-op if stream is already open.
   * Best-effort: failure is non-fatal.
   */
  async announceToDirectory(): Promise<void> {
    if (this.#directoryEndpoint && !this.#persistentSignalingStream) {
      await this.#openPersistentSignalingStream().catch(() => {});
    }
  }

  // ─── REG-001: Agent registration ─────────────────────────────────────────────

  /** REG-001: Register this agent with the directory. Delegates to RegistrationManager. */
  async register(phoneStub: string = "", preAuthToken?: string): Promise<RegistrationState | { error: string }> {
    return this.#registrationManager.register(phoneStub, preAuthToken);
  }

  async #handleInbound(stream: Stream): Promise<void> {
    // Read one LP frame, with a 5s wall-clock timeout as a safety net.
    // DecoderOptions has no signal field — timeout is enforced by racing the
    // read promise against a timer that aborts the stream externally.
    let payload: Uint8Array | undefined;
    let timeoutFired = false;

    const readFrame = async (): Promise<void> => {
      for await (const chunk of lp.decode(stream)) {
        payload = (chunk as unknown as { slice(): Uint8Array }).slice();
        return; // got one frame
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

    // CBOR parse
    const deserResult = deserializeEnvelope(payload);
    if (!deserResult.ok) {
      stream.abort(new Error(`malformed_envelope: ${deserResult.error.reason}`));
      return;
    }

    // Full validation: struct → content_hash recompute → signature
    const validateResult = validateEnvelope(deserResult.envelope);
    if (!validateResult.ok) {
      stream.abort(new Error(`validation_failed: ${validateResult.error.reason}`));
      return;
    }

    // Enqueue
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

    // Clean close — signals delivered:true to sender
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

  /**
   * Register a handler for connection_established events.
   * CONNREQ-002: fires on both the sender and the target when a connection is created.
   */
  onConnectionEstablished(handler: (event: import("@cello-protocol/protocol-types").ConnectionEstablished) => void): void {
    this.#onConnectionEstablishedHandler = handler;
  }

  /**
   * Register a handler for disclosure_request_inbound events (Round 2 notification for sender).
   * CONNREQ-002: fires on the sender when the target requests more disclosure.
   */
  onDisclosureRequested(handler: (event: import("@cello-protocol/protocol-types").DisclosureRequestInbound) => void): void {
    this.#onDisclosureRequestedHandler = handler;
  }

  /**
   * Return all active connection records for this client.
   * CONNREQ-002: used by the MCP tool layer and tests.
   */
  listConnections(): import("@cello-protocol/protocol-types").ClientConnectionRecord[] {
    return [...this.#connections.values()];
  }

  /**
   * Return the cached registration state, or null if not yet registered.
   * CELLO-MCP-003.
   */
  getRegistrationState(): import("@cello-protocol/protocol-types").RegistrationState | null {
    return this.#registrationState;
  }

  /**
   * Return the ML-DSA key provider stored after successful register(), or null.
   * Used by the MCP server to build ConnectionPackages. CELLO-MCP-003.
   * SI-001: This returns the key PROVIDER (sign/getPublicKey), not raw secret bytes.
   */
  getMlDsaProvider(): import("@cello-protocol/crypto").MlDsaKeyProvider | null {
    return this.#mlDsaProvider;
  }

  /**
   * Set the connection policy. Replaces any previously configured policy.
   * CELLO-MCP-003.
   */
  setPolicy(policy: import("./connection-policy.js").SignalRequirementPolicy): void {
    this.#connectionPolicy = policy;
    // PERSIST-024: persist policy to DB
    if (this.#persistence) {
      void this.#persistence.persistConnectionPolicy(policy);
    }
  }

  /**
   * Return the current connection policy. Returns default open/deterministic if none configured.
   * CELLO-MCP-003.
   */
  getPolicy(): import("./connection-policy.js").SignalRequirementPolicy {
    return this.#connectionPolicy ?? { mode: "open", review_mode: "deterministic", requirements: [] };
  }

  /** Return the configured directory peer ID, or null if no directory endpoint was provided. */
  getDirectoryPeerId(): string | null {
    return this.#directoryEndpoint?.peer_id ?? null;
  }

  /**
   * Check if a connection exists with the given counterparty pubkey.
   * Returns the connection_id if found, null otherwise.
   * CELLO-MCP-003.
   */
  hasConnection(counterpartyPubkeyHex: string): string | null {
    return this.#connectionsByPeer.get(counterpartyPubkeyHex) ?? null;
  }

  /**
   * Accept a pending inbound connection request (inference review mode).
   * Sends connection_response { verdict: 'accept' } to the directory.
   * The directory then pushes connection_established to both parties.
   * CELLO-MCP-003.
   */
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

  /**
   * Reconnect the persistent directory signaling stream and re-authenticate.
   * Called after a client reconnects and wants the directory to deliver queued
   * connection requests (CONNREQ-002 DB-001).
   */
  async reconnectDirectory(): Promise<boolean> {
    return this.#signalingManager.reconnectDirectory();
  }

  /** FEDERATION-003 AC-004: Look up a relay's registered public key from the directory. */
  async getRelayPublicKey(relayId: string): Promise<string | undefined> {
    const pubkeyHex = await this.#signalingManager.getRelayPublicKey(relayId);
    // PERSIST-024: cache in known_relays so lookupRelayPubkey can serve from DB
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

  // ─── CONNREQ-002: B-side inbound request handler (delegated to ConnectionManager) ──

  async #handleInboundConnectionRequest(frame: Record<string, unknown>): Promise<void> {
    return this.#connectionManager.handleInboundConnectionRequest(frame);
  }

  async #handleDisclosureResponse(frame: Record<string, unknown>): Promise<void> {
    return this.#connectionManager.handleDisclosureResponse(frame);
  }


  // ─── ADAPTER-003: initiateSession ──────────────────────────────────────────

  /** ADAPTER-003: Delegate to SignalingManager. SI-002: K_local never in frames or logs. */
  initiateSession(
    targetPubkeyHex: string,
    opts?: { directoryPeerId?: string; directoryMultiaddr?: string; timeoutMs?: number },
  ): Promise<InitiateSessionResult> {
    return this.#signalingManager.initiateSession(targetPubkeyHex, opts);
  }

  /** Delegate to SignalingManager — opens and authenticates the persistent directory signaling stream. */
  #openPersistentSignalingStream(directoryPeerId?: string, directoryMultiaddr?: string): Promise<boolean> {
    return this.#signalingManager.openPersistentSignalingStream(directoryPeerId, directoryMultiaddr);
  }

  /**
   * FrameDispatcher.dispatchSignalingFrame — called by SignalingManager's reader loop
   * for each decoded frame from the persistent or per-session signaling stream.
   *
   * Per-session directory stream frames have `__session_id_hex` and `__directory_pubkey`
   * injected by SignalingManager.#runDirectoryStreamReader so the session context is
   * available without re-parsing from the wire.
   */
  #dispatchSignalingFrame(stream: Stream, frame: Record<string, unknown>): void {
    // Per-session directory stream shortcut fields
    const injectedSessionIdHex = typeof frame["__session_id_hex"] === "string"
      ? frame["__session_id_hex"] : null;
    const injectedDirectoryPubkey = frame["__directory_pubkey"] instanceof Uint8Array
      ? frame["__directory_pubkey"]
      : Buffer.isBuffer(frame["__directory_pubkey"])
        ? new Uint8Array(frame["__directory_pubkey"] as Buffer) : null;

    if (frame["type"] === "session_assignment" || frame["type"] === "session_request_error") {
      const resolve = this.#pendingSessionRequestResolve;
      if (resolve) {
        this.#pendingSessionRequestResolve = null;
        resolve(frame);
      } else if (frame["type"] === "session_assignment") {
        const rawAssignment = frame["assignment"] as Record<string, unknown> | undefined;
        if (rawAssignment) {
          const assignment = parseSessionAssignment(rawAssignment);
          if (assignment && this.#myPubkeyHex) {
            const myPubkey = Buffer.from(this.#myPubkeyHex, "hex");
            void this.receiveSessionAssignment(assignment, myPubkey);
          }
        }
      }
    } else if (frame["type"] === "session_sealed") {
      const sessionIdHex = injectedSessionIdHex ?? (() => {
        const raw = frame["session_id"];
        const sid = raw instanceof Uint8Array ? raw : Buffer.isBuffer(raw) ? new Uint8Array(raw as Buffer) : null;
        return sid ? Buffer.from(sid).toString("hex") : null;
      })();
      if (sessionIdHex) {
        const session = this.#sessionManager.getSession(sessionIdHex);
        if (session) {
          const dirPubkey = injectedDirectoryPubkey ?? session.directory_pubkey;
          this.#sealManager.handleDirectorySessionSealed(sessionIdHex, frame, dirPubkey);
        }
      }
    } else if (frame["type"] === "session_seal_rejected") {
      const sessionIdHex = injectedSessionIdHex ?? (() => {
        const raw = frame["session_id"];
        const sid = raw instanceof Uint8Array ? raw : Buffer.isBuffer(raw) ? new Uint8Array(raw as Buffer) : null;
        return sid ? Buffer.from(sid).toString("hex") : null;
      })();
      if (sessionIdHex) this.#sealManager.handleDirectorySessionSealRejected(sessionIdHex, frame);
    } else if (frame["type"] === "seal_rejected_tree_mismatch") {
      const sessionIdHex = injectedSessionIdHex ?? (() => {
        const raw = frame["session_id"];
        const sid = raw instanceof Uint8Array ? raw : Buffer.isBuffer(raw) ? new Uint8Array(raw as Buffer) : null;
        return sid ? Buffer.from(sid).toString("hex") : null;
      })();
      if (sessionIdHex) this.#sealManager.handleSealRejectedTreeMismatch(sessionIdHex, frame);
    } else if (frame["type"] === "seal_unilateral_confirmed") {
      const sessionIdHex = injectedSessionIdHex ?? (() => {
        const raw = frame["session_id"];
        const sid = raw instanceof Uint8Array ? raw : Buffer.isBuffer(raw) ? new Uint8Array(raw as Buffer) : null;
        return sid ? Buffer.from(sid).toString("hex") : null;
      })();
      if (sessionIdHex) this.#sealManager.handleSealUnilateralConfirmed(sessionIdHex, frame);
      this.#sealManager.resolvePendingUnilateralSeal(frame);
    } else if (frame["type"] === "seal_unilateral_notification") {
      const sessionIdHex = injectedSessionIdHex ?? (() => {
        const raw = frame["session_id"];
        const sid = raw instanceof Uint8Array ? raw : Buffer.isBuffer(raw) ? new Uint8Array(raw as Buffer) : null;
        return sid ? Buffer.from(sid).toString("hex") : null;
      })();
      if (sessionIdHex) this.#sealManager.handleSealUnilateralNotification(sessionIdHex, frame);
    } else if (frame["type"] === "seal_unilateral_too_early") {
      const sessionIdHex = injectedSessionIdHex ?? (() => {
        const raw = frame["session_id"];
        const sid = raw instanceof Uint8Array ? raw : Buffer.isBuffer(raw) ? new Uint8Array(raw as Buffer) : null;
        return sid ? Buffer.from(sid).toString("hex") : null;
      })();
      if (sessionIdHex) {
        const remainingSeconds = typeof frame["remaining_seconds"] === "number" ? frame["remaining_seconds"] : 0;
        this.#logger.warn("session.unilateral.too.early", { sessionId: sessionIdHex, remainingSeconds });
      }
      this.#sealManager.resolvePendingUnilateralSeal(frame);
    } else if (frame["type"] === "seal_verified") {
      const sessionIdHex = injectedSessionIdHex ?? (() => {
        const raw = frame["session_id"];
        const sid = raw instanceof Uint8Array ? raw : Buffer.isBuffer(raw) ? new Uint8Array(raw as Buffer) : null;
        return sid ? Buffer.from(sid).toString("hex") : null;
      })();
      if (sessionIdHex) void this.#sealManager.handleSealVerified(sessionIdHex, frame);
    } else if (frame["type"] === "session_frost_sealed") {
      const sessionIdHex = injectedSessionIdHex ?? (() => {
        const raw = frame["session_id"];
        const sid = raw instanceof Uint8Array ? raw : Buffer.isBuffer(raw) ? new Uint8Array(raw as Buffer) : null;
        return sid ? Buffer.from(sid).toString("hex") : null;
      })();
      if (sessionIdHex) this.#sealManager.handleSessionFrostSealed(sessionIdHex, frame);
    } else if (frame["type"] === "ceremony_request") {
      void this.#sealManager.handleCeremonyRequest(stream, frame);
    } else if (frame["type"] === "dkg_ready") {
      const resolve = this.#pendingDkgReadyResolve;
      if (resolve) {
        this.#pendingDkgReadyResolve = null;
        resolve(frame);
      }
    } else if (frame["type"] === "register_success" || frame["type"] === "register_error") {
      const dkgResolve = this.#pendingDkgReadyResolve;
      if (dkgResolve) {
        this.#pendingDkgReadyResolve = null;
        dkgResolve(frame);
      }
      const resolve = this.#pendingRegisterResolve;
      if (resolve) {
        this.#pendingRegisterResolve = null;
        resolve(frame);
      }
    } else if (
      frame["type"] === "connection_established" ||
      frame["type"] === "connection_rejected" ||
      frame["type"] === "connection_insufficient" ||
      frame["type"] === "connection_request_error" ||
      frame["type"] === "disclosure_request_inbound"
    ) {
      this.#connectionManager.routeConnectionFrame(frame);
    } else if (frame["type"] === "connection_request_inbound") {
      void this.#handleInboundConnectionRequest(frame);
    } else if (frame["type"] === "disclosure_response_inbound") {
      void this.#handleDisclosureResponse(frame);
    }
  }

  /**
   * FrameDispatcher.onSignalingStreamClosed — called by SignalingManager when the
   * persistent signaling stream reader loop exits (stream closed or error).
   */
  #onSignalingStreamClosed(stream: Stream): void {
    // Clear persistent stream ref if it's still the same stream
    if (this.#persistentSignalingStream === stream) {
      this.#persistentSignalingStream = null;
      this.#persistentSignalingIter = null;
    }

    // Unblock pending register() (dkg_ready phase)
    const dkgReadyResolve = this.#pendingDkgReadyResolve;
    if (dkgReadyResolve) {
      this.#pendingDkgReadyResolve = null;
      dkgReadyResolve({ type: "register_error", reason: "stream_closed" });
    }

    // Unblock pending register() (register_success phase)
    const regResolve = this.#pendingRegisterResolve;
    if (regResolve) {
      this.#pendingRegisterResolve = null;
      regResolve({ type: "register_error", reason: "stream_closed" });
    }

    // Unblock pending session_request
    const sessionResolve = this.#pendingSessionRequestResolve;
    if (sessionResolve) {
      this.#pendingSessionRequestResolve = null;
      sessionResolve({ type: "session_request_error", reason: "directory_unreachable" });
    }

    // CONNREQ-003: unblock all pending connection request resolvers
    this.#connectionManager.unblockAllOnStreamClose();

    // If any session is sealing or seal_deferred, schedule reconnect so directory can
    // drain its seal_verified notification queue and the FROST ceremony can complete.
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

// ─── Re-export parse helpers (implementations moved to session-assignment-parser.ts) ──
export { mapSessionRequestErrorFrame };

// ─── Factory ─────────────────────────────────────────────────────────────────

export function createClient(
  node: CelloNode,
  keyProvider: KeyProvider,
  opts?: {
    onMessageQueued?: (senderPubkeyHex: string) => void;
    contentGraceMs?: number;
    /** SESSION-006: ms to attempt relay reconnect before giving up. Default: 60000. */
    reconnectTimeoutMs?: number;
    /** SESSION-004/SESSION-005: optional FROST threshold signer for initiator role and seal ceremony coordination. */
    thresholdSigner?: IThresholdSigner;
    /** SESSION-005: ms to wait for FROST seal after bilateral exchange. Default: 15000. */
    sealFrostTimeoutMs?: number;
    /** ADAPTER-003: directory endpoint for initiateSession. */
    directoryEndpoint?: { peer_id: string; multiaddrs: string[] };
    /** REG-001: path for persisting ML-DSA-44 keypair. If set, FileMlDsaKeyProvider.load() is used. */
    mlDsaKeyFile?: string;
    /** CONNREQ-002: connection policy for evaluating inbound connection_request_inbound frames. */
    connectionPolicy?: import("./connection-policy.js").SignalRequirementPolicy;
    /** CONNREQ-002: overall connection timeout in ms. Default: 300000. */
    connectionTimeoutMs?: number;
    /** CONNREQ-002: Round 2 silence timeout in ms. Default: 120000. */
    round2TimeoutMs?: number;
    /** CONNREQ-002: if true, expose _evaluateCallCount on the instance for test assertions. */
    trackEvaluateCount?: boolean;
    /** CONNREQ-002: sender pubkeys that bypass evaluateConnectionPackage. */
    whitelist?: string[];
    /** CONNREQ-002: callback fired when an inbound connection_request_inbound is queued for agent review. */
    onConnectionPendingReview?: (event: import("@cello-protocol/protocol-types").ConnectionRequestInbound) => void;
    /** DB-003: attempt cross-check of sender's ml_dsa_pubkey on inbound requests. */
    crossCheckDirectoryOnInbound?: boolean;
    /** PERSIST-014: injected logger for observability events. */
    logger?: Logger;
    /** PERSIST-024: optional persistence layer for structured SQLCipher state. */
    persistence?: ClientStatePersistence;
  }
): CelloClient & {
  sendRaw(peerPubkeyHex: string, bytes: Uint8Array): Promise<SendResult>;
  openRawStream(peerPubkeyHex: string): Promise<Stream>;
  openContentStreamByPeerId(peerId: string): Promise<Stream>;
  /** SESSION-005: register the client's FROST primary_pubkey for seal verification. */
  setPrimaryPubkey(primaryPubkey: Uint8Array): void;
  injectDirectoryFrame(sessionIdHex: string, frame: Record<string, unknown>): void;
  injectLeafDeliver(sessionIdHex: string, frame: Record<string, unknown>): void;
  injectRelayDisconnect(sessionIdHex: string): void;
  /** TEST-ONLY: register a minimal session record without a real relay connection. */
  injectTestSession(sessionIdHex: string, sessionId: Uint8Array, myPubkeyHex: string, directoryPubkey: Uint8Array, status?: SessionRecord["status"], opts?: { isInitiator?: boolean }): void;
  /** CONNREQ-002: list active connection records. */
  listConnections(): import("@cello-protocol/protocol-types").ClientConnectionRecord[];
  /** CONNREQ-002 / AC-008 (DX-001): send connection_request to target B and await final outcome.
   * Per-stage timeouts: dialTimeoutMs (stage 'dial'), sendTimeoutMs (stage 'send'),
   * waitTimeoutMs (stage 'wait'). Timeout result includes the stage that fired. */
  cello_request_connection(opts: { target_pubkey: string; package_cbor: Uint8Array; dialTimeoutMs?: number; sendTimeoutMs?: number; waitTimeoutMs?: number }): Promise<
    | { result: "established"; connection_id: string }
    | { result: "rejected"; reason: string }
    | { result: "insufficient"; unmet_requirements: unknown[] }
    | { result: "disclosure_requested"; connection_request_id: string; requested_items: unknown[] }
    | { result: "timeout"; stage: "dial" | "send" | "wait" }
    | { result: "error"; reason: string }
  >;
  /** CONNREQ-002: respond to disclosure_request (Round 2 sender side). */
  cello_respond_to_disclosure_request(opts: { connection_request_id: string; package_cbor: Uint8Array }): Promise<
    | { result: "established"; connection_id: string }
    | { result: "rejected"; reason: string }
    | { result: "insufficient"; unmet_requirements: unknown[] }
    | { result: "timeout" }
    | { result: "error"; reason: string }
  >;
  /** CONNREQ-002: request more disclosure from sender (Round 2, target side). */
  cello_request_more_disclosure(opts: { connection_request_id: string; requested_items: unknown[] }): Promise<{ error: "max_rounds_reached" } | { ok: true }>;
  /** CONNREQ-002: register connection_established event handler. */
  onConnectionEstablished(handler: (event: import("@cello-protocol/protocol-types").ConnectionEstablished) => void): void;
  /** CONNREQ-002: register disclosure_request_inbound event handler (sender side). */
  onDisclosureRequested(handler: (event: import("@cello-protocol/protocol-types").DisclosureRequestInbound) => void): void;
  /** CONNREQ-002: reconnect the persistent directory signaling stream. */
  reconnectDirectory(): Promise<boolean>;
  /** PERSIST-015: send seal_unilateral to directory after delivery_grace_seconds. */
  initiateUnilateralSeal(sessionIdHex: string): Promise<
    | { ok: true; sealed_root: Uint8Array; sealed_at: number }
    | { ok: false; reason: "too_early"; remaining_seconds: number }
    | { ok: false; reason: string }
  >;
  /** TEST-ONLY: inject a pending inbound connection request into state. */
  _injectPendingConnectionRequest(opts: { connection_request_id: string; from_pubkey: string; package_cbor: Uint8Array; round: number }): void;
  /**
   * CONNREQ-003 TEST-ONLY: route a synthetic connection outcome frame through the
   * resolver Map — used by SI-001 adversarial test to verify cross-target isolation.
   */
  _injectConnectionFrame(frame: Record<string, unknown>): void;
  /** CONNREQ-003 TEST-ONLY: current size of the pending resolver Map. */
  _pendingConnectionRequestResolverCount: number;
  /** TEST-ONLY: evaluate call counter (only incremented when trackEvaluateCount=true). */
  _evaluateCallCount: number;
  /** PERSIST-024: load all durable state from the SQLCipher DB and populate in-memory state. */
  loadPersistedState(): Promise<void>;
  /** PERSIST-024: return hashes pending relay resubmission after loadPersistedState(). */
  getLoadedPendingHashes(): Array<{ sessionId: string; hashHex: string; enqueuedAt: number }>;
  /** Open the persistent signaling stream to the directory if not already open. Call after setDirectoryEndpoint(). */
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
    /** PERSIST-015: send seal_unilateral to directory after delivery_grace_seconds. */
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
