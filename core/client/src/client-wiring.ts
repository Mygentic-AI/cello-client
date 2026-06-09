/**
 * client-wiring.ts — Manager context object builders for CelloClientImpl.
 *
 * Extracted from the CelloClientImpl constructor to keep client.ts under the
 * 600-line AC budget. Each build* function constructs the narrow context
 * interface required by the corresponding manager.
 *
 * All context objects use lazy closures so that cross-manager references
 * resolve at call-time — this is safe because by the time any method is
 * invoked, all managers have been assigned on the facade.
 */

import type { IThresholdSigner } from "@cello-protocol/crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";
import type { Logger } from "@cello-protocol/interfaces";
import type { ClientStatePersistence } from "./client-state-persistence.js";
import type { AgentHashQueue } from "./agent-hash-queue.js";
import type { RegistrationContext } from "./registration-manager.js";
import { RegistrationManager } from "./registration-manager.js";
import type { ConnectionContext } from "./connection-manager.js";
import { ConnectionManager } from "./connection-manager.js";
import type { SignalingContext } from "./signaling-manager.js";
import { SignalingManager } from "./signaling-manager.js";
import type { SessionContext } from "./session-manager.js";
import { SessionManager } from "./session-manager.js";
import type { SealContext } from "./seal-manager.js";
import { SealManager } from "./seal-manager.js";
import type { RelayStreamContext } from "./relay-stream-manager.js";
import { RelayStreamManager } from "./relay-stream-manager.js";
import type { SessionAssignment } from "@cello-protocol/protocol-types";
import type { ReceiveAssignmentResult, PeerEntry, SessionRecord } from "./types.js";
import type { StartupContext } from "./client-startup.js";

// ─── Facade access surface ────────────────────────────────────────────────────

/**
 * The wiring surface of CelloClientImpl — every field and method that the
 * context-builder functions need to close over. Using this interface lets the
 * builders live in a separate module without importing the concrete class.
 */
export interface ClientWiringSurface {
  // Infrastructure (read-only after construction)
  readonly node: CelloNode;
  readonly keyProvider: KeyProvider;
  readonly logger: Logger;
  readonly contentGraceMs: number;
  readonly reconnectTimeoutMs: number;
  readonly sealFrostTimeoutMs: number;

  // Mutable shared state
  persistence: ClientStatePersistence | null;
  hashQueue: AgentHashQueue | null;
  thresholdSigner: IThresholdSigner | undefined;
  myPubkeyHex: string | null;
  directoryEndpoint: { peer_id: string; multiaddrs: string[] } | null;
  evaluateCallCount: number;

  // Managers (assigned during construction — accessed lazily via closures)
  registrationManager: RegistrationManager;
  connectionManager: ConnectionManager;
  signalingManager: SignalingManager;
  relayStreamManager: RelayStreamManager;
  sealManager: SealManager;
  sessionManager: SessionManager;

  // Facade-private state (needed for startup restore)
  peers: Map<string, PeerEntry>;
  endorsements: Array<Record<string, unknown>>;
  attestations: Array<Record<string, unknown>>;
  loadedPendingHashes: Array<{ sessionId: string; hashHex: string; enqueuedAt: number }>;

  // Methods the context objects delegate back to the facade
  openPersistentSignalingStream(directoryPeerId?: string, directoryMultiaddr?: string): Promise<boolean>;
  dispatchSignalingFrame(stream: Stream, frame: Record<string, unknown>): void;
  onSignalingStreamClosed(stream: Stream): void;
  receiveSessionAssignment(assignment: SessionAssignment, myPubkey: Uint8Array): Promise<ReceiveAssignmentResult>;
}

// ─── Per-manager context builders ────────────────────────────────────────────

/** Build the RegistrationContext for RegistrationManager. */
export function buildRegistrationContext(
  f: ClientWiringSurface,
  mlDsaKeyFile: string | undefined,
): RegistrationContext {
  return {
    get node() { return f.node; },
    get keyProvider() { return f.keyProvider; },
    get logger() { return f.logger; },
    get persistence() { return f.persistence; },
    get mlDsaKeyFile() { return mlDsaKeyFile; },
    getMyPubkeyHex: () => f.myPubkeyHex,
    setMyPubkeyHex: (hex) => { f.myPubkeyHex = hex; },
    getDirectoryEndpoint: () => f.directoryEndpoint,
    getThresholdSigner: () => f.thresholdSigner,
    setThresholdSigner: (signer) => { f.thresholdSigner = signer; },
    getMyPrimaryPubkey: () => f.sealManager.getMyPrimaryPubkey(),
    setMyPrimaryPubkey: (pubkey) => { f.sealManager.setMyPrimaryPubkey(new Uint8Array(pubkey)); },
    getPersistentSignalingStream: () => f.signalingManager.getPersistentSignalingStream(),
    openPersistentSignalingStream: () => f.openPersistentSignalingStream(),
    setPendingDkgReadyResolve: (r) => { f.signalingManager.setPendingDkgReadyResolve(r); },
    setPendingRegisterResolve: (r) => { f.signalingManager.setPendingRegisterResolve(r); },
  };
}

/** Build the ConnectionContext for ConnectionManager. */
export function buildConnectionContext(
  f: ClientWiringSurface,
  connectionTimeoutMs: number,
  round2TimeoutMs: number,
  trackEvaluateCount: boolean,
  whitelist: string[],
  crossCheckDirectoryOnInbound: boolean,
): ConnectionContext {
  return {
    get logger() { return f.logger; },
    get persistence() { return f.persistence; },
    get connectionTimeoutMs() { return connectionTimeoutMs; },
    get round2TimeoutMs() { return round2TimeoutMs; },
    get trackEvaluateCount() { return trackEvaluateCount; },
    get whitelist() { return whitelist; },
    get crossCheckDirectoryOnInbound() { return crossCheckDirectoryOnInbound; },
    getPersistentSignalingStream: () => f.signalingManager.getPersistentSignalingStream(),
    openPersistentSignalingStream: () => f.openPersistentSignalingStream(),
    incrementEvaluateCallCount: () => { f.evaluateCallCount++; },
  };
}

/** Build the SignalingContext for SignalingManager. */
export function buildSignalingContext(f: ClientWiringSurface): SignalingContext {
  return {
    get node() { return f.node; },
    get keyProvider() { return f.keyProvider; },
    get logger() { return f.logger; },
    getMyPubkeyHex: () => f.myPubkeyHex,
    setMyPubkeyHex: (hex) => { f.myPubkeyHex = hex; },
    getDirectoryEndpoint: () => f.directoryEndpoint,
    getDirectoryStream: (id) => f.relayStreamManager.getDirectoryStream(id),
    setDirectoryStream: (id, s) => { f.relayStreamManager.setDirectoryStream(id, s); },
    deleteDirectoryStream: (id) => { f.relayStreamManager.deleteDirectoryStream(id); },
    getPendingConnectionResolverCount: () => f.connectionManager.pendingConnectionRequestResolverCount,
    dispatchSignalingFrame: (stream, frame) => { f.dispatchSignalingFrame(stream, frame); },
    onSignalingStreamClosed: (stream) => { f.onSignalingStreamClosed(stream); },
    getConnectionIdForPeer: (hex) => f.connectionManager.getConnectionIdForPeer(hex),
    hasConnectionPolicy: () => f.connectionManager.hasConnectionPolicy(),
    receiveSessionAssignment: (a, p) => f.receiveSessionAssignment(a, p),
    getSession: (id) => f.sessionManager.getSession(id),
  };
}

/** Build the SessionContext for SessionManager. */
export function buildSessionContext(f: ClientWiringSurface): SessionContext {
  return {
    get logger() { return f.logger; },
    get persistence() { return f.persistence; },
    get keyProvider() { return f.keyProvider; },
    get node() { return f.node; },
    getMyPubkeyHex: () => f.myPubkeyHex,
    setMyPubkeyHex: (hex) => { f.myPubkeyHex = hex; },
    getThresholdSigner: () => f.thresholdSigner,
    getPersistentSignalingStream: () => f.signalingManager.getPersistentSignalingStream(),
    initRelaySession: (id) => { f.relayStreamManager.initSession(id); },
    runRelayStreamReader: (id, stream, myPubkeyHex, iter) => {
      f.relayStreamManager.runRelayStreamReader(id, stream, myPubkeyHex, iter);
    },
    performRelayAuth: (stream, myPubkey) => f.relayStreamManager.performRelayAuth(stream, myPubkey),
    handleContentStream: (stream) => { void f.relayStreamManager.handleContentStream(stream); },
    connectDirectorySignalingStream: (id, assignment, myPubkey) =>
      f.signalingManager.connectDirectorySignalingStream(id, assignment, myPubkey),
    getRelayStream: (id) => f.relayStreamManager.getRelayStream(id),
    setRelayStream: (id, stream) => f.relayStreamManager.setRelayStream(id, stream),
  };
}

/** Build the SealContext for SealManager. */
export function buildSealContext(f: ClientWiringSurface): SealContext {
  return {
    get logger() { return f.logger; },
    get persistence() { return f.persistence; },
    get keyProvider() { return f.keyProvider; },
    getMyPubkeyHex: () => f.myPubkeyHex,
    getThresholdSigner: () => f.thresholdSigner,
    getSession: (id) => f.sessionManager.getSession(id),
    getSessions: () => f.sessionManager.getSessions(),
    getOwnPendingContent: (id) => f.sessionManager.getOwnPendingContent(id),
    getPendingAckResolver: (id) => f.sessionManager.getPendingAckResolver(id),
    setPendingAckResolver: (id, r) => { f.sessionManager.setPendingAckResolver(id, r); },
    deletePendingAckResolver: (id) => { f.sessionManager.deletePendingAckResolver(id); },
    getPersistentSignalingStream: () => f.signalingManager.getPersistentSignalingStream(),
    setPersistentSignalingStream: (s) => { f.signalingManager.setPersistentSignalingStream(s); },
    setPersistentSignalingIter: (it) => { f.signalingManager.setPersistentSignalingIter(it); },
    openPersistentSignalingStream: () => f.openPersistentSignalingStream(),
    getRelayStream: (id) => f.relayStreamManager.getRelayStream(id),
    getDirectoryStream: (id) => f.relayStreamManager.getDirectoryStream(id),
    enqueueSessionSealedEvent: (id, root, ts) => {
      f.sessionManager.enqueueSessionSealedEvent(id, root, ts);
    },
    sendContentFrame: (session, content, hash) =>
      f.sessionManager.sendContentFrame(session, content, hash),
    waitForOwnEcho: (id, seq) => f.sessionManager.waitForOwnEcho(id, seq),
    performGapFillReconciliation: (id, from, to, corrId) =>
      f.relayStreamManager.performGapFillReconciliation(id, from, to, corrId),
  };
}

/** Build the RelayStreamContext for RelayStreamManager. */
export function buildRelayStreamContext(f: ClientWiringSurface): RelayStreamContext {
  return {
    get node() { return f.node; },
    get keyProvider() { return f.keyProvider; },
    get logger() { return f.logger; },
    get persistence() { return f.persistence; },
    get contentGraceMs() { return f.contentGraceMs; },
    get reconnectTimeoutMs() { return f.reconnectTimeoutMs; },
    get hashQueue() { return f.hashQueue; },
    getMyPubkeyHex: () => f.myPubkeyHex,
    getSession: (id) => f.sessionManager.getSession(id),
    getSessions: () => f.sessionManager.getSessions(),
    getPendingAckResolver: (id) => f.sessionManager.getPendingAckResolver(id),
    setPendingAckResolver: (id, r) => { f.sessionManager.setPendingAckResolver(id, r); },
    deletePendingAckResolver: (id) => { f.sessionManager.deletePendingAckResolver(id); },
    getOwnPendingContent: (id) => f.sessionManager.getOwnPendingContent(id),
    getOwnEchoResolvers: (id) => f.sessionManager.getOwnEchoResolvers(id),
    getOutboundQueue: (id) => f.sessionManager.getOutboundQueue(id),
    enqueueReceivedMessage: (id, msg) => { f.sessionManager.enqueueReceivedMessage(id, msg); },
    wakeReceiveWaiters: (id) => { f.sessionManager.wakeReceiveWaiters(id); },
    enqueueSessionSealedEvent: (id, root, ts) => {
      f.sessionManager.enqueueSessionSealedEvent(id, root, ts);
    },
    handleSealVerified: (id, frame) => { void f.sealManager.handleSealVerified(id, frame); },
    handleSessionFrostSealed: (id, frame) => { f.sealManager.handleSessionFrostSealed(id, frame); },
    handleSealRejectedTreeMismatch: (id, frame) => { f.sealManager.handleSealRejectedTreeMismatch(id, frame); },
    handleSealUnilateralConfirmed: (id, frame) => { f.sealManager.handleSealUnilateralConfirmed(id, frame); },
    handleSealUnilateralNotification: (id, frame) => { f.sealManager.handleSealUnilateralNotification(id, frame); },
    handleDirectorySessionSealed: (id, frame, dirPubkey) => {
      f.sealManager.handleDirectorySessionSealed(id, frame, dirPubkey);
    },
    handleDirectorySessionSealRejected: (id, frame) => {
      f.sealManager.handleDirectorySessionSealRejected(id, frame);
    },
    onRelayDisconnected: (sessionIdHex, myPubkeyHex) => {
      const session = f.sessionManager.getSession(sessionIdHex);
      if (!session) return;
      if (session.desynchronized) return;
      if (session.status === "transport_lost") return;
      if (
        session.status === "sealing" ||
        session.status === "sealed" ||
        session.status === "seal_rejected" ||
        session.status === "seal_deferred"
      ) return;
      session.status = "transport_lost";
      void f.persistence?.persistSession(sessionIdHex, session);
      const ackResolve = f.sessionManager.getPendingAckResolver(sessionIdHex);
      if (ackResolve) {
        f.sessionManager.deletePendingAckResolver(sessionIdHex);
        ackResolve({ ok: false, reason: "transport_unavailable" });
      }
      void f.relayStreamManager.reconnectRelayStream(sessionIdHex, myPubkeyHex);
    },
  };
}

// ─── Manager factory ──────────────────────────────────────────────────────────

/** Construction options that are used by multiple managers but are not facade fields. */
export interface ManagerConstructionOpts {
  mlDsaKeyFile?: string;
  connectionPolicy?: import("./connection-policy.js").SignalRequirementPolicy;
  connectionTimeoutMs: number;
  round2TimeoutMs: number;
  trackEvaluateCount: boolean;
  whitelist: string[];
  onConnectionPendingReview?: (event: import("@cello-protocol/protocol-types").ConnectionRequestInbound) => void;
  crossCheckDirectoryOnInbound: boolean;
}

/**
 * Construct all six managers using the facade surface.
 * Must be called after all facade fields are assigned (so lazy closures are safe).
 * Assigns each manager to the corresponding field on the facade.
 */
export function buildManagers(
  f: ClientWiringSurface,
  opts: ManagerConstructionOpts,
): void {
  f.registrationManager = new RegistrationManager(buildRegistrationContext(f, opts.mlDsaKeyFile));
  f.connectionManager = new ConnectionManager(
    buildConnectionContext(f, opts.connectionTimeoutMs, opts.round2TimeoutMs, opts.trackEvaluateCount, opts.whitelist, opts.crossCheckDirectoryOnInbound),
    { connectionPolicy: opts.connectionPolicy, onConnectionPendingReview: opts.onConnectionPendingReview },
  );
  f.signalingManager = new SignalingManager(buildSignalingContext(f));
  f.sessionManager = new SessionManager(buildSessionContext(f));
  f.sealManager = new SealManager(buildSealContext(f), f.sealFrostTimeoutMs);
  f.relayStreamManager = new RelayStreamManager(buildRelayStreamContext(f));
}

// ─── Startup context builder ───────────────────────────────────────────────────

/**
 * Build the StartupContext for loadClientStartupState.
 * Extracted from CelloClientImpl.loadPersistedState to keep client.ts under 600 lines.
 */
export function buildStartupContext(f: ClientWiringSurface): StartupContext {
  return {
    get node() { return f.node; },
    get logger() { return f.logger; },
    get persistence() { return f.persistence!; },
    getDirectoryEndpoint: () => f.directoryEndpoint,
    getThresholdSigner: () => f.thresholdSigner,
    setThresholdSigner: (s) => { f.thresholdSigner = s; },
    getMyPubkeyHex: () => f.myPubkeyHex,
    setMyPubkeyHex: (hex) => { f.myPubkeyHex = hex; },
    setRegistrationState: (s) => { f.registrationManager.setRegistrationState(s); },
    setMlDsaProvider: (p) => { f.registrationManager.setMlDsaProvider(p); },
    addConnection: (id, rec) => { f.connectionManager.addConnection(id, rec); },
    addConnectionByPeer: (pk, id) => { f.connectionManager.addConnectionByPeer(pk, id); },
    addProfileUncheckedPeer: (pk) => { f.connectionManager.addProfileUncheckedPeer(pk); },
    setConnectionPolicy: (pol) => { f.connectionManager.setPolicy(pol); },
    addPeer: (hex, entry) => { f.peers.set(hex, entry); },
    hasPeer: (hex) => f.peers.has(hex),
    setEndorsements: (e) => { f.endorsements = e; },
    setAttestations: (a) => { f.attestations = a; },
    setLoadedPendingHashes: (h) => { f.loadedPendingHashes = h; },
    getSessionById: (id) => f.sessionManager.getSession(id),
    setSession: (id, rec) => { f.sessionManager.setSession(id, rec); },
    initSessionMessageQueue: (id) => { f.sessionManager.initSessionMessageQueue(id); },
    getMyPrimaryPubkey: () => f.sealManager.getMyPrimaryPubkey(),
    setMyPrimaryPubkey: (pk) => { f.sealManager.setMyPrimaryPubkey(pk); },
    restoreDecidedRequest: (id) => { f.connectionManager.restoreDecidedRequest(id); },
    restorePendingInboundRequest: (opts) => { f.connectionManager.restorePendingInboundRequest(opts); },
    restoreReviewQueueItem: (opts) => { f.connectionManager.restoreReviewQueueItem(opts); },
  };
}

// ─── Test injection helpers ────────────────────────────────────────────────────

/**
 * Build and inject a synthetic SessionRecord for test isolation.
 * Extracted from CelloClientImpl.injectTestSession.
 */
export function injectTestSession(
  f: ClientWiringSurface,
  sessionIdHex: string,
  sessionId: Uint8Array,
  myPubkeyHex: string,
  directoryPubkey: Uint8Array,
  status: SessionRecord["status"] = "active",
  opts?: { isInitiator?: boolean },
): void {
  const record: SessionRecord = {
    session_id: sessionId,
    counterparty_pubkey: new Uint8Array(32),
    counterparty_peer_id: "",
    counterparty_multiaddrs: [],
    relay_endpoint: { peer_id: "", multiaddrs: [] },
    directory_endpoint: { peer_id: "", multiaddrs: [] },
    directory_pubkey: directoryPubkey,
    genesis_prev_root: new Uint8Array(32),
    last_seen_seq: 0, last_sent_seq: 0, status,
    local_tree_leaves: [], next_expected_seq: 1, desynchronized: false,
  };
  f.sessionManager.setSession(sessionIdHex, record);
  if (!f.myPubkeyHex) f.myPubkeyHex = myPubkeyHex;
  if (opts?.isInitiator) {
    f.sealManager.markSealInitiated(sessionIdHex);
    f.sealManager.markFrostCeremonyParticipant(sessionIdHex);
  }
}

/**
 * Route a directory frame to the appropriate SealManager handler.
 * Extracted from CelloClientImpl.injectDirectoryFrame.
 */
export function injectDirectoryFrame(
  f: ClientWiringSurface,
  sessionIdHex: string,
  frame: Record<string, unknown>,
): void {
  const session = f.sessionManager.getSession(sessionIdHex);
  if (!session) throw new Error(`injectDirectoryFrame: session not found: ${sessionIdHex}`);
  if (frame["type"] === "session_sealed") {
    f.sealManager.handleDirectorySessionSealed(sessionIdHex, frame, session.directory_pubkey);
  } else if (frame["type"] === "session_seal_rejected") {
    f.sealManager.handleDirectorySessionSealRejected(sessionIdHex, frame);
  } else if (frame["type"] === "seal_rejected_tree_mismatch") {
    f.sealManager.handleSealRejectedTreeMismatch(sessionIdHex, frame);
  } else if (frame["type"] === "seal_unilateral_confirmed") {
    f.sealManager.handleSealUnilateralConfirmed(sessionIdHex, frame);
  } else if (frame["type"] === "seal_unilateral_notification") {
    f.sealManager.handleSealUnilateralNotification(sessionIdHex, frame);
  } else if (frame["type"] === "seal_verified") {
    void f.sealManager.handleSealVerified(sessionIdHex, frame);
  } else if (frame["type"] === "session_frost_sealed") {
    f.sealManager.handleSessionFrostSealed(sessionIdHex, frame);
  }
}
