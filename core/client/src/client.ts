/**
 * CELLO Client — CelloClientImpl facade.
 * Domain logic delegated to RegistrationManager, ConnectionManager, SignalingManager,
 * RelayStreamManager, SealManager, SessionManager.
 * Wiring: client-wiring.ts | Helpers: client-send-helpers.ts, client-startup.ts.
 */

import {
  buildEnvelope, serializeEnvelope,
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
import { ConnectionManager } from "./connection-manager.js";
import { SignalingManager } from "./signaling-manager.js";
import { RelayStreamManager } from "./relay-stream-manager.js";
import { SealManager } from "./seal-manager.js";
import { SessionManager } from "./session-manager.js";
import { loadClientStartupState } from "./client-startup.js";
import { mapSessionRequestErrorFrame } from "./session-assignment-parser.js";
import { dispatchSignalingFrame } from "./frame-dispatch.js";
import {
  buildManagers, buildStartupContext, injectTestSession as doInjectTestSession,
  injectDirectoryFrame as doInjectDirectoryFrame,
} from "./client-wiring.js";
import type { ClientWiringSurface } from "./client-wiring.js";
import { sendBytesViaNode, handleInboundEnvelope } from "./client-send-helpers.js";

// ─── SESSION-006 reconnect constants ─────────────────────────────────────────

/** Default reconnect timeout: 60 seconds per SESSION-006 AC-003. */
const DEFAULT_RECONNECT_TIMEOUT_MS = 60_000;

/** SESSION-005: seal + FROST timeout; cello_close_session falls back to 'bilateral' on expiry. */
const DEFAULT_SEAL_FROST_TIMEOUT_MS = 15_000;

// ─── Extended return type (used by createClient and the inner cast) ───────────

/** Full public surface exposed by createClient — CelloClient + test/escape-hatch methods. */
export type ClientExtended = CelloClient & {
  sendRaw(peerPubkeyHex: string, bytes: Uint8Array): Promise<SendResult>;
  openRawStream(peerPubkeyHex: string): Promise<Stream>;
  openContentStreamByPeerId(peerId: string): Promise<Stream>;
  setPrimaryPubkey(primaryPubkey: Uint8Array): void;
  injectDirectoryFrame(sessionIdHex: string, frame: Record<string, unknown>): void;
  injectLeafDeliver(sessionIdHex: string, frame: Record<string, unknown>): void;
  injectRelayDisconnect(sessionIdHex: string): void;
  injectTestSession(
    sessionIdHex: string,
    sessionId: Uint8Array,
    myPubkeyHex: string,
    directoryPubkey: Uint8Array,
    status?: SessionRecord["status"],
    opts?: { isInitiator?: boolean },
  ): void;
  listConnections(): import("@cello-protocol/protocol-types").ClientConnectionRecord[];
  cello_request_connection(opts: {
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
  >;
  cello_respond_to_disclosure_request(opts: {
    connection_request_id: string;
    package_cbor: Uint8Array;
  }): Promise<
    | { result: "established"; connection_id: string }
    | { result: "rejected"; reason: string }
    | { result: "insufficient"; unmet_requirements: unknown[] }
    | { result: "timeout" }
    | { result: "error"; reason: string }
  >;
  cello_request_more_disclosure(opts: {
    connection_request_id: string;
    requested_items: unknown[];
  }): Promise<{ error: "max_rounds_reached" } | { ok: true }>;
  onConnectionEstablished(handler: (event: import("@cello-protocol/protocol-types").ConnectionEstablished) => void): void;
  onDisclosureRequested(handler: (event: import("@cello-protocol/protocol-types").DisclosureRequestInbound) => void): void;
  reconnectDirectory(): Promise<boolean>;
  initiateUnilateralSeal(sessionIdHex: string): Promise<
    | { ok: true; sealed_root: Uint8Array; sealed_at: number }
    | { ok: false; reason: "too_early"; remaining_seconds: number }
    | { ok: false; reason: string }
  >;
  _injectPendingConnectionRequest(opts: {
    connection_request_id: string;
    from_pubkey: string;
    package_cbor: Uint8Array;
    round: number;
  }): void;
  _injectConnectionFrame(frame: Record<string, unknown>): void;
  _pendingConnectionRequestResolverCount: number;
  _evaluateCallCount: number;
  loadPersistedState(): Promise<void>;
  getLoadedPendingHashes(): Array<{ sessionId: string; hashHex: string; enqueuedAt: number }>;
  announceToDirectory(): Promise<void>;
};

// ─── CelloClientImpl ──────────────────────────────────────────────────────────

class CelloClientImpl implements CelloClient, ClientWiringSurface {
  // ─── ClientWiringSurface fields (TypeScript private — accessed by client-wiring.ts) ─
  readonly node: CelloNode;
  readonly keyProvider: KeyProvider;
  readonly contentGraceMs: number;
  readonly reconnectTimeoutMs: number;
  readonly sealFrostTimeoutMs: number;

  thresholdSigner: IThresholdSigner | undefined;
  myPubkeyHex: string | null = null;
  directoryEndpoint: { peer_id: string; multiaddrs: string[] } | null;
  persistence: ClientStatePersistence | null = null;
  hashQueue: AgentHashQueue | null = null;
  evaluateCallCount = 0;

  registrationManager!: RegistrationManager;
  connectionManager!: ConnectionManager;
  signalingManager!: SignalingManager;
  relayStreamManager!: RelayStreamManager;
  sealManager!: SealManager;
  sessionManager!: SessionManager;

  // ─── PERSIST-014: Logger (injected, defaults to no-op) ───────────────────────
  readonly logger: Logger;

  // ─── Startup-surface fields (accessed by buildStartupContext in client-wiring.ts) ──
  readonly peers = new Map<string, PeerEntry>();
  endorsements: Array<Record<string, unknown>> = [];
  attestations: Array<Record<string, unknown>> = [];
  loadedPendingHashes: Array<{ sessionId: string; hashHex: string; enqueuedAt: number }> = [];

  // ─── Facade-only fields (not in any interface) ──────────────────────────────
  private readonly receiveQueues = new Map<string, ReceivedEnvelope[]>();
  private readonly arrivalLog: Array<{ senderPubkeyHex: string; envelope: ReceivedEnvelope }> = [];
  private readonly onMessageQueued: ((senderPubkeyHex: string) => void) | undefined;

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
    this.node = node;
    this.keyProvider = keyProvider;
    this.onMessageQueued = onMessageQueued;
    this.contentGraceMs = contentGraceMs;
    this.reconnectTimeoutMs = reconnectTimeoutMs;
    this.thresholdSigner = thresholdSigner;
    this.sealFrostTimeoutMs = sealFrostTimeoutMs;
    this.directoryEndpoint = directoryEndpoint;
    this.logger = logger ?? { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };
    this.persistence = persistence ?? null;
    buildManagers(this, {
      mlDsaKeyFile,
      connectionPolicy,
      connectionTimeoutMs,
      round2TimeoutMs,
      trackEvaluateCount,
      whitelist,
      onConnectionPendingReview,
      crossCheckDirectoryOnInbound,
    });
  }

  // ─── ClientWiringSurface method implementations ───────────────────────────

  openPersistentSignalingStream(directoryPeerId?: string, directoryMultiaddr?: string): Promise<boolean> {
    return this.signalingManager.openPersistentSignalingStream(directoryPeerId, directoryMultiaddr);
  }

  dispatchSignalingFrame(stream: Stream, frame: Record<string, unknown>): void {
    dispatchSignalingFrame(stream, frame, {
      signalingManager: this.signalingManager,
      connectionManager: this.connectionManager,
      sealManager: this.sealManager,
      sessionManager: this.sessionManager,
      logger: this.logger,
      getMyPubkeyHex: () => this.myPubkeyHex,
      receiveSessionAssignment: (a, p) => this.receiveSessionAssignment(a, p),
    });
  }

  onSignalingStreamClosed(_stream: Stream): void {
    this.connectionManager.unblockAllOnStreamClose();
    const pendingSealSessions = Array.from(this.sessionManager.getSessions().entries())
      .filter(([, s]) => s.status === "sealing" || s.status === "seal_deferred")
      .map(([id]) => id);
    if (pendingSealSessions.length > 0 && this.directoryEndpoint) {
      this.logger.info("seal.stream.closed.reconnect.scheduled", {
        pendingSealSessions,
        correlationId: "stream-close",
      });
      setTimeout(() => void this.openPersistentSignalingStream(), 200);
    }
  }

  // ─── Lifecycle ───────────────────────────────────────────────────────────────

  /** SESSION-005: Set the FROST primary_pubkey for this client. */
  setPrimaryPubkey(primaryPubkey: Uint8Array): void {
    this.sealManager.setMyPrimaryPubkey(new Uint8Array(primaryPubkey));
  }

  /** PERSIST-024: Restore all durable state from SQLCipher. */
  async loadPersistedState(): Promise<void> {
    if (!this.persistence) return;
    await loadClientStartupState(buildStartupContext(this));
  }

  /** PERSIST-024 FINDING-4: Return the pending hashes loaded during startup. */
  getLoadedPendingHashes(): Array<{ sessionId: string; hashHex: string; enqueuedAt: number }> {
    return this.loadedPendingHashes;
  }

  /** PERSIST-024 AC-008: Set the AgentHashQueue for relay resubmission. */
  setHashQueue(queue: AgentHashQueue): void {
    this.hashQueue = queue;
  }

  /** AC-003 (DX-001): Set directory endpoint after construction. */
  setDirectoryEndpoint(endpoint: { peer_id: string; multiaddrs: string[] }): void {
    this.directoryEndpoint = endpoint;
  }

  /** AC-003 (DX-001): Wire threshold signer after construction. */
  setThresholdSigner(signer: IThresholdSigner): void {
    this.thresholdSigner = signer;
  }

  /** PERSIST-024: Wire persistence layer after construction. */
  setPersistence(persistence: ClientStatePersistence): void {
    this.persistence = persistence;
  }

  addPeer(peerPubkeyHex: string, peerId: string, multiaddrs: string[]): void {
    this.peers.set(peerPubkeyHex, { peerId, multiaddrs, connected: true });
    if (this.persistence) {
      void this.persistence.persistPeer({ peerPubkeyHex, peerId, multiaddrs });
    }
  }

  // ─── Send / receive ────────────────────────────────────────────────────────

  async send(peerPubkeyHex: string, content: Uint8Array): Promise<SendResult> {
    const entry = this.peers.get(peerPubkeyHex);
    if (!entry) return { delivered: false, reason: "peer_not_connected" };
    const buildResult = await buildEnvelope(content, this.keyProvider, Date.now());
    if (!buildResult.ok) {
      return { delivered: false, reason: buildResult.error.reason === "content_too_large" ? "content_too_large" : "connection_lost" };
    }
    return sendBytesViaNode(this.node, entry.peerId, serializeEnvelope(buildResult.envelope), buildResult.envelope.content_hash);
  }

  async sendRaw(peerPubkeyHex: string, bytes: Uint8Array): Promise<SendResult> {
    const entry = this.peers.get(peerPubkeyHex);
    if (!entry) return { delivered: false, reason: "peer_not_connected" };
    return sendBytesViaNode(this.node, entry.peerId, bytes, undefined);
  }

  async openRawStream(peerPubkeyHex: string): Promise<Stream> {
    const entry = this.peers.get(peerPubkeyHex);
    if (!entry) throw new Error(`peer_not_connected: ${peerPubkeyHex}`);
    return this.node.newStream(entry.peerId, CELLO_PROTOCOL_ID);
  }

  async openContentStreamByPeerId(peerId: string): Promise<Stream> {
    return this.node.newStream(peerId, CELLO_CONTENT_PROTOCOL_ID);
  }

  private handleInbound(stream: Stream): Promise<void> {
    return handleInboundEnvelope(stream, this.receiveQueues, this.arrivalLog, this.onMessageQueued);
  }

  receive(senderPubkeyHex: string): ReceivedEnvelope | null {
    const queue = this.receiveQueues.get(senderPubkeyHex);
    if (!queue || queue.length === 0) return null;
    return queue.shift()!;
  }

  peekAll(): Array<{ senderPubkeyHex: string; envelope: ReceivedEnvelope }> {
    return [...this.arrivalLog];
  }

  // ─── Handler registration ─────────────────────────────────────────────────

  async registerHandler(): Promise<void> {
    await this.node.handle(CELLO_PROTOCOL_ID, (stream) => { void this.handleInbound(stream); });
    if (this.directoryEndpoint && !this.signalingManager.getPersistentSignalingStream()) {
      await this.openPersistentSignalingStream().catch(() => {});
    }
  }

  async announceToDirectory(): Promise<void> {
    if (this.directoryEndpoint && !this.signalingManager.getPersistentSignalingStream()) {
      await this.openPersistentSignalingStream().catch(() => {});
    }
  }

  // ─── Registration ─────────────────────────────────────────────────────────

  async register(phoneStub = "", preAuthToken?: string): Promise<RegistrationState | { error: string }> {
    return this.registrationManager.register(phoneStub, preAuthToken);
  }

  // ─── Session delegates ────────────────────────────────────────────────────

  async receiveSessionAssignment(assignment: SessionAssignment, myPubkey: Uint8Array): Promise<ReceiveAssignmentResult> {
    return this.sessionManager.receiveSessionAssignment(assignment, myPubkey);
  }

  listSessions(): SessionRecord[] { return this.sessionManager.listSessions(); }

  async sendMessage(sessionIdHex: string, content: Uint8Array): Promise<SendMessageResult> {
    return this.sessionManager.sendMessage(sessionIdHex, content);
  }

  receiveMessage(sessionIdHex: string): ReceivedMessage | null {
    return this.sessionManager.receiveMessage(sessionIdHex);
  }

  receiveAnyMessage(): { sessionIdHex: string; message: ReceivedMessage } | null {
    return this.sessionManager.receiveAnyMessage();
  }

  async receiveSessionMessageAsync(sessionIdHex: string, timeoutMs: number): Promise<ReceivedMessage | null> {
    return this.sessionManager.receiveSessionMessageAsync(sessionIdHex, timeoutMs);
  }

  async receiveMessageAsync(timeoutMs: number): Promise<
    | (ReceivedMessage & { sessionIdHex: string })
    | { type: "timeout" }
  > {
    return this.sessionManager.receiveMessageAsync(timeoutMs);
  }

  onSessionAssignment(handler: (event: SessionAssignmentEvent) => void): void {
    this.sessionManager.setOnSessionAssignmentHandler(handler);
  }

  // ─── Seal delegates ───────────────────────────────────────────────────────

  async initiateSessionSeal(sessionIdHex: string): Promise<{ ok: true } | { ok: false; reason: string }> {
    return this.sealManager.initiateSessionSeal(sessionIdHex);
  }

  async initiateUnilateralSeal(sessionIdHex: string): Promise<
    | { ok: true; sealed_root: Uint8Array; sealed_at: number }
    | { ok: false; reason: "too_early"; remaining_seconds: number }
    | { ok: false; reason: string }
  > {
    return this.sealManager.initiateUnilateralSeal(sessionIdHex);
  }

  closeSession(sessionIdHex: string): void {
    const ackResolve = this.sessionManager.getPendingAckResolver(sessionIdHex);
    if (ackResolve) {
      this.sessionManager.deletePendingAckResolver(sessionIdHex);
      ackResolve({ ok: false, reason: "session_closed" });
    }
    this.sessionManager.closeSession(sessionIdHex);
    this.relayStreamManager.closeSession(sessionIdHex);
    this.sealManager.closeSession(sessionIdHex);
  }

  // ─── Connection delegates ─────────────────────────────────────────────────

  onConnectionEstablished(handler: (event: import("@cello-protocol/protocol-types").ConnectionEstablished) => void): void {
    this.connectionManager.onConnectionEstablished(handler);
  }

  onDisclosureRequested(handler: (event: import("@cello-protocol/protocol-types").DisclosureRequestInbound) => void): void {
    this.connectionManager.onDisclosureRequested(handler);
  }

  listConnections(): import("@cello-protocol/protocol-types").ClientConnectionRecord[] {
    return this.connectionManager.listConnections();
  }

  hasConnection(counterpartyPubkeyHex: string): string | null {
    return this.connectionManager.hasConnection(counterpartyPubkeyHex);
  }

  setPolicy(policy: import("./connection-policy.js").SignalRequirementPolicy): void {
    this.connectionManager.setPolicy(policy);
    if (this.persistence) void this.persistence.persistConnectionPolicy(policy);
  }

  getPolicy(): import("./connection-policy.js").SignalRequirementPolicy {
    return this.connectionManager.getPolicy();
  }

  getDirectoryPeerId(): string | null { return this.directoryEndpoint?.peer_id ?? null; }

  getRegistrationState(): RegistrationState | null {
    return this.registrationManager.getRegistrationState();
  }

  getMlDsaProvider(): import("@cello-protocol/crypto").MlDsaKeyProvider | null {
    return this.registrationManager.getMlDsaProvider();
  }

  async acceptConnection(connectionRequestId: string): Promise<
    | { accepted: true; connection_id: string }
    | { error: { reason: "no_pending_request" | "already_decided" } }
  > {
    return this.connectionManager.acceptConnection(connectionRequestId);
  }

  async rejectConnection(connectionRequestId: string, reason?: string): Promise<
    | { rejected: true }
    | { error: { reason: "no_pending_request" | "already_decided" } }
  > {
    return this.connectionManager.rejectConnection(connectionRequestId, reason);
  }

  async requestMoreDisclosure(connectionRequestId: string, requestedItems: unknown[]): Promise<
    | { request_sent: true }
    | { error: { reason: "no_pending_request" | "already_decided" | "max_rounds_reached" } }
  > {
    return this.connectionManager.requestMoreDisclosure(connectionRequestId, requestedItems);
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
    return this.connectionManager.awaitConnectionRequest(timeoutMs);
  }

  async cello_request_connection(opts: {
    target_pubkey: string; package_cbor: Uint8Array; dialTimeoutMs?: number;
    sendTimeoutMs?: number; waitTimeoutMs?: number;
  }): Promise<
    | { result: "established"; connection_id: string }
    | { result: "rejected"; reason: string }
    | { result: "insufficient"; unmet_requirements: unknown[] }
    | { result: "disclosure_requested"; connection_request_id: string; requested_items: unknown[] }
    | { result: "timeout"; stage: "dial" | "send" | "wait" }
    | { result: "error"; reason: string }
  > {
    return this.connectionManager.cello_request_connection(opts);
  }

  async cello_respond_to_disclosure_request(opts: {
    connection_request_id: string; package_cbor: Uint8Array;
  }): Promise<
    | { result: "established"; connection_id: string }
    | { result: "rejected"; reason: string }
    | { result: "insufficient"; unmet_requirements: unknown[] }
    | { result: "timeout" }
    | { result: "error"; reason: string }
  > {
    return this.connectionManager.cello_respond_to_disclosure_request(opts);
  }

  async cello_request_more_disclosure(opts: {
    connection_request_id: string; requested_items: unknown[];
  }): Promise<{ error: "max_rounds_reached" } | { ok: true }> {
    return this.connectionManager.cello_request_more_disclosure(opts);
  }

  // ─── Signaling delegates ───────────────────────────────────────────────────

  async reconnectDirectory(): Promise<boolean> { return this.signalingManager.reconnectDirectory(); }

  initiateSession(
    targetPubkeyHex: string,
    opts?: { directoryPeerId?: string; directoryMultiaddr?: string; timeoutMs?: number },
  ): Promise<InitiateSessionResult> {
    return this.signalingManager.initiateSession(targetPubkeyHex, opts);
  }

  async getRelayPublicKey(relayId: string): Promise<string | undefined> {
    const pubkeyHex = await this.signalingManager.getRelayPublicKey(relayId);
    if (pubkeyHex && this.persistence) void this.persistence.persistKnownRelay(relayId, pubkeyHex, "directory");
    return pubkeyHex;
  }

  // ─── Test injection methods ───────────────────────────────────────────────

  injectLeafDeliver(sessionIdHex: string, frame: Record<string, unknown>): void {
    this.relayStreamManager.injectLeafDeliver(sessionIdHex, frame);
  }

  injectRelayDisconnect(sessionIdHex: string): void {
    this.relayStreamManager.injectRelayDisconnect(sessionIdHex);
  }

  injectTestSession(
    sessionIdHex: string, sessionId: Uint8Array, myPubkeyHex: string,
    directoryPubkey: Uint8Array, status: SessionRecord["status"] = "active",
    opts?: { isInitiator?: boolean },
  ): void {
    doInjectTestSession(this, sessionIdHex, sessionId, myPubkeyHex, directoryPubkey, status, opts);
  }

  injectDirectoryFrame(sessionIdHex: string, frame: Record<string, unknown>): void {
    doInjectDirectoryFrame(this, sessionIdHex, frame);
  }

  _injectPendingConnectionRequest(opts: {
    connection_request_id: string; from_pubkey: string; package_cbor: Uint8Array; round: number;
  }): void {
    this.connectionManager._injectPendingConnectionRequest(opts);
  }

  _injectConnectionFrame(frame: Record<string, unknown>): void {
    this.connectionManager._injectConnectionFrame(frame);
  }

  get _pendingConnectionRequestResolverCount(): number {
    return this.connectionManager.pendingConnectionRequestResolverCount;
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
): ClientExtended {
  return new CelloClientImpl(
    node, keyProvider,
    opts?.onMessageQueued, opts?.contentGraceMs, opts?.reconnectTimeoutMs,
    opts?.thresholdSigner, opts?.sealFrostTimeoutMs, opts?.directoryEndpoint ?? null,
    opts?.mlDsaKeyFile, opts?.connectionPolicy, opts?.connectionTimeoutMs,
    opts?.round2TimeoutMs, opts?.trackEvaluateCount, opts?.whitelist,
    opts?.onConnectionPendingReview, opts?.crossCheckDirectoryOnInbound,
    opts?.logger, opts?.persistence,
  ) as unknown as ClientExtended;
}
