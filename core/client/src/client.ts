/**
 * CELLO Client — client.ts (MSG-002, SESSION-002)
 *
 * CelloClientImpl: peer registry, send path, inbound stream handler,
 * and receive queue for the M0 one-shot message exchange protocol.
 * SESSION-002 additions: receiveSessionAssignment, listSessions.
 *
 * PSEUDOCODE (Phase P):
 *
 * send(peerPubkeyHex, content):
 *   1. Look up peerPubkeyHex → peer_not_connected if absent
 *   2. buildEnvelope(content, keyProvider, Date.now()) → content_too_large if rejected
 *   3. serializeEnvelope → bytes
 *   4. node.newStream(peerId, CELLO_PROTOCOL_ID):
 *      - structured error → peer_unreachable or connection_lost
 *   5. stream.send(lp.encode.single(bytes))
 *   6. stream.close() — half-close write side
 *   7. Drain read side (for await lp.decode(stream)):
 *      - clean EOF → delivered:true
 *      - stream.status === 'reset' → remote_rejected
 *      - transport error → connection_lost
 *
 * inbound handler (stream):
 *   1. AbortController with 5s timeout
 *   2. Read one LP frame via lp.decode(stream) — abort if timeout fires
 *   3. deserializeEnvelope(payload) → malformed_envelope + stream.abort on error
 *   4. validateEnvelope(envelope) → stream.abort on error
 *   5. enqueue to receiveQueue keyed by sender_pubkey hex
 *   6. stream.close() — clean close signals delivered:true to sender
 *
 * sendRaw(peerPubkeyHex, bytes) [internal, exposed for tests]:
 *   Open stream, write raw bytes as single LP frame, await close type.
 *   Used by tests to inject tampered envelopes.
 *
 * receiveSessionAssignment(assignment, myPubkey):
 *   SESSION-002 AC-002, AC-003, AC-004, AC-005, SI-003
 *   SESSION-004 changes: replace M1 Ed25519 verify with FROST verify path.
 *
 *   SESSION-004 pseudocode (Phase P rev2):
 *   RFC 9591 (FROST), RFC 8032 (Ed25519), FIPS 180-4 (SHA-256)
 *
 *   1. Check signature_type (SESSION-004 SI-003, AC-003):
 *      if assignment.signature_type === 'single':
 *        return { ok:false, reason:"unsupported_signature_type" }
 *        // Hard cut — even if the single-key sig itself verifies (SI-003 is absolute)
 *        // No session record is created (SI-003). No I/O is attempted.
 *
 *   2. Determine role and verification key (SESSION-004 AC-007):
 *      isInitiator = (Buffer.from(myPubkey).equals(Buffer.from(pubA)))
 *      if isInitiator:
 *        // CRITICAL-1 FIX: initiator MUST have a thresholdSigner injected.
 *        // There is NO fallback to assignment.signer_pubkey — that is frame-provided
 *        // and attacker-controlled. Absence of a signer is a hard error.
 *        if this.#thresholdSigner is null:
 *          return { ok:false, reason:"frost_signer_not_configured" }
 *        verifyKey = this.#thresholdSigner.getPrimaryPubkey()  // HIGH-4: on IThresholdSigner
 *      else:
 *        // Counterparty: use signer_pubkey embedded in the frame (A's primary_pubkey)
 *        // TypeScript discriminated union guarantees signer_pubkey is present for 'frost' frames
 *        verifyKey = assignment.signer_pubkey  // guaranteed non-undefined by type system
 *
 *   3. Compute genesis_prev_root (same as M1):
 *      genesis_prev_root = computeGenesisPrevRoot(pubA, pubB, session_id, session_timestamp)
 *
 *   4. Build session establishment TBS (HIGH-5: uses buildSessionEstablishmentTbs from protocol-types):
 *      tbs = buildSessionEstablishmentTbs(session_id, pubA, pubB, genesis_prev_root, session_timestamp)
 *
 *   5. Verify FROST signature (SESSION-004 AC-002, SI-001):
 *      //  Use FrostThresholdSigner.verifySignature() which handles framing internally:
 *      //    framedMsg = <context>\0<tbs>  (domain separation per CONTEXT.md)
 *      //  OR use ed25519_FROST.verify(sig, frameMessage(context, tbs), verifyKey) directly
 *      //  The client imports ed25519_FROST from @noble/curves/ed25519 (not from @cello-protocol/crypto)
 *      //  to keep the verify path independent from any signer state.
 *      framedMsg = frameMessage(CONTEXT_SESSION_ESTABLISHMENT, tbs)  // context\0tbs
 *      isValid = ed25519_FROST.verify(assignment.directory_signature, framedMsg, verifyKey)
 *      if !isValid:
 *        return { ok:false, reason:"frost_signature_invalid" }
 *        // Never accept a tampered signature (SI-001 absolute)
 *
 *   6-9. (same as M1: content handler, relay auth, counterparty dial, store session)
 *
 * IMPORTANT NOTE on CelloClientImpl constructor and createClient factory changes:
 *   - Add optional #thresholdSigner: IThresholdSigner | null field
 *   - createClient accepts optional thresholdSigner in opts
 *   - No @cello-protocol/directory import — IThresholdSigner comes from @cello-protocol/crypto
 *
 * IMPORTANT NOTE on ReceiveAssignmentResult (IMPORTANT-9):
 *   Add 'frost_signature_invalid' | 'unsupported_signature_type' | 'frost_signer_not_configured'
 *   to the reason union in types.ts
 *
 *   1. Build TBS = CBOR([session_id, participant_a.pubkey, participant_b.pubkey, session_timestamp])
 *   2. Verify Ed25519(TBS, assignment.directory_pubkey, assignment.directory_signature) [M1, REMOVED in M2]
 *      → { ok:false, reason:"directory_signature_invalid" } if fails
 *   3. Determine counterparty: if myPubkey == participant_a.pubkey then counterparty = B, else A
 *   4. Compute genesis_prev_root = computeGenesisPrevRoot(pubA, pubB, session_id, session_timestamp)
 *      per FIPS 180-4 / SESSION-002
 *   5. Register /cello/content/1.0.0 handler on node (if not yet registered)
 *   6. Dial relay on /cello/relay/1.0.0, complete challenge-response auth:
 *      a. Read relay_auth_challenge frame
 *      b. Compute authMsg = SHA-256("CELLO-RELAY-AUTH-v1" || nonce || myPubkey)  [RFC 8032, FIPS 180-4]
 *      c. Sign authMsg with keyProvider → signature
 *      d. Send relay_auth_response{pubkey, signature}
 *      → { ok:false, reason:"relay_auth_failed" } or "relay_auth_error" on failure
 *   7. Dial counterparty on /cello/content/1.0.0
 *      → { ok:false, reason:"dial_counterparty_failed" } if unreachable
 *   8. Store SessionRecord with status:"active", last_seen_seq:0
 *   9. Return { ok:true, sessionId }
 */

import { createHash } from "node:crypto";
import { Encoder, decode } from "cbor-x";
import * as lp from "it-length-prefixed";
import {
  buildEnvelope, serializeEnvelope, deserializeEnvelope, validateEnvelope,
  computeGenesisPrevRoot, encodeSealPayload, buildSessionEstablishmentTbs, buildSealTbs,
} from "@cello-protocol/protocol-types";
import type { Structure2 } from "@cello-protocol/protocol-types";
import { verify, buildMerkleTree, merkleRoot, verifyFrostSignature, CONTEXT_SESSION_ESTABLISHMENT, InMemoryMlDsaKeyProvider } from "@cello-protocol/crypto";
import { storeDkgResult } from "@cello-protocol/crypto/frost/frost-threshold-signer.js";
import type { LeafInput, IThresholdSigner } from "@cello-protocol/crypto";
import { CELLO_PROTOCOL_ID, CELLO_CONTENT_PROTOCOL_ID } from "@cello-protocol/transport";
import { NetworkDirectoryNode } from "./network-directory-node.js";
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
import { FrostThresholdSigner } from "@cello-protocol/crypto/frost/frost-threshold-signer.js";
import { RegistrationManager } from "./registration-manager.js";
import type { RegistrationContext } from "./registration-manager.js";
import { ConnectionManager } from "./connection-manager.js";
import type { ConnectionContext } from "./connection-manager.js";
import { SignalingManager } from "./signaling-manager.js";
import type { SignalingContext } from "./signaling-manager.js";
import { RelayStreamManager } from "./relay-stream-manager.js";
import type { RelayStreamContext } from "./relay-stream-manager.js";

const RELAY_PROTOCOL_ID = "/cello/relay/1.0.0";
const DEFAULT_INITIATE_TIMEOUT_MS = 30_000;
const CBOR_ENC = new Encoder({ tagUint8Array: false });

function toU8Safe(v: unknown): Uint8Array | null {
  if (v instanceof Uint8Array) return v;
  if (Buffer.isBuffer(v)) return new Uint8Array(v as Buffer);
  return null;
}

// ─── MSG-004 pending cross-check state ───────────────────────────────────────

interface Structure1Fields {
  last_seen_seq: number;
  timestamp: number | bigint;
}

interface PendingS2Entry {
  s2: Structure2;
  s2_cbor: Uint8Array;
  s1_fields: Structure1Fields;
  leaf_kind: number;
  sequence_number: number;
  content_hash: Uint8Array;
  is_own_send: boolean;
  arrived_at: number;
  timer_handle: ReturnType<typeof setTimeout>;
  echo_resolve?: () => void;
}

interface PendingContentEntry {
  content_bytes: Uint8Array;
  arrived_at: number;
}

interface ReadyEntry {
  s2: Structure2;
  s2_cbor: Uint8Array;
  s1_fields: Structure1Fields;
  leaf_kind: number;
  content_bytes: Uint8Array;
  is_own_send: boolean;
  echo_resolve?: () => void;
}

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

  // Callback for inbound session assignments (participant B role). MCP-002.
  #onSessionAssignmentHandler: ((event: SessionAssignmentEvent) => void) | undefined;

  // session_id_hex → SessionRecord (SESSION-002)
  readonly #sessions = new Map<string, SessionRecord>();

  // track whether content handler has been registered on this node
  #contentHandlerRegistered = false;

  // ─── MSG-004 per-session state ──────────────────────────────────────────────

  // session_id_hex → persistent relay stream
  readonly #relayStreams = new Map<string, Stream>();

  // session_id_hex → Promise<void> chain for outbound serialization
  readonly #outboundQueues = new Map<string, Promise<void>>();

  // session_id_hex → pending ack resolver (sequence_number → ack data)
  readonly #pendingAckResolvers = new Map<string, (ack: { ok: true; sequence_number: number } | { ok: false; reason: string }) => void>();

  // session_id_hex → highest seq# received from relay (tracks relay delivery order independently
  // of cross-check completion; used for sequence gap/replay detection)
  readonly #relayRecvSeq = new Map<string, number>();

  // session_id_hex → fully-ready cross-checks keyed by seqNum, awaiting in-order processing
  readonly #readyQueue = new Map<string, Map<number, ReadyEntry>>();

  // session_id_hex → pending S2 entries keyed by content_hash_hex
  readonly #pendingS2 = new Map<string, Map<string, PendingS2Entry>>();

  // session_id_hex → pending content entries keyed by content_hash_hex (counterparty-sent content)
  readonly #pendingContent = new Map<string, Map<string, PendingContentEntry>>();

  // session_id_hex → own-send pre-buffered content keyed by content_hash_hex
  // Kept separate from #pendingContent to avoid collision when both sides send identical bytes.
  readonly #ownPendingContent = new Map<string, Map<string, PendingContentEntry>>();

  // session_id_hex → set of content_hash_hex values from tampered frames (declared hash ≠ computed)
  // If a subsequent S2 arrives claiming the same hash, it immediately desync's (content_hash_mismatch).
  readonly #tamperedContentClaims = new Map<string, Set<string>>();

  // session_id_hex → own_echo_resolvers (sequence_number → resolve fn)
  readonly #ownEchoResolvers = new Map<string, Map<number, () => void>>();

  // session_id_hex → FIFO queue of ReceivedMessage (for receiveMessage)
  readonly #sessionMessageQueues = new Map<string, ReceivedMessage[]>();

  // FIFO arrival order across all sessions: { sessionIdHex, message }
  readonly #anyMessageQueue: Array<{ sessionIdHex: string; message: ReceivedMessage }> = [];

  // SESSION-007: wake resolvers for receiveSessionMessageAsync (per-session) and receiveMessageAsync (any-session)
  readonly #receiveWaiters = new Map<string, Set<() => void>>();
  readonly #receiveAnyWaiters = new Set<() => void>();

  // session_id_hex → directory signaling stream (SESSION-003)
  readonly #directoryStreams = new Map<string, Stream>();

  // SESSION-006: track whether a reconnect loop is already running per session
  readonly #reconnectInProgress = new Set<string>();

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

  // session_id_hex → Promise: set when the initiator SEAL echo is expected (SESSION-003)
  // Allows non-initiator auto-response to know when its own SEAL echo confirms the seal
  readonly #sealInitiatedSessions = new Set<string>();

  // session_id_hex: set when THIS client received seal_verified and ran the FROST ceremony.
  // Guards #handleFrostSealed to use #myPrimaryPubkey for verification (anti-substitution).
  // Distinct from #sealInitiatedSessions: a concurrent-close counterparty can call
  // initiateSessionSeal but is NOT the FROST ceremony participant.
  readonly #frostCeremonyParticipant = new Set<string>();

  // SESSION-005: session_id_hex → resolve fn for seal-frost-timeout Promise
  // The Promise resolves when session_sealed arrives; if it times out first, seal_type = 'bilateral'.
  readonly #sealFrostResolvers = new Map<string, () => void>();

  // PERSIST-014: session_id_hex → resolve callback for pending gap-fill requests
  readonly #pendingGapFillResolvers = new Map<string, (result: { ok: true; leaves: unknown[] } | { ok: false; reason: string }) => void>();

  // SESSION-005: session_id_hex → { leafCount, timestamp } from seal_verified frame.
  // Stored so #handleFrostSealed can use the authoritative values even if local_tree_leaves
  // is incomplete due to a sequence_causal_inconsistency desync race.
  readonly #sealVerifiedData = new Map<string, { leafCount: number; timestamp: number }>();

  // SESSION-005: track the primary_pubkey for this client (set after bootstrapKeyShares)
  #myPrimaryPubkey: Uint8Array | null = null;

  // ─── REG-001: Registration state ────────────────────────────────────────────

  /** Cached registration state — set after a successful register() call. */
  #registrationState: RegistrationState | null = null;

  /** Pending resolver for register_success / register_error from directory. */
  #pendingRegisterResolve: ((frame: Record<string, unknown>) => void) | null = null;
  /** Pending resolver for dkg_ready from directory (part of register flow). */
  #pendingDkgReadyResolve: ((frame: Record<string, unknown>) => void) | null = null;
  /** Pending resolver for seal_unilateral_confirmed / seal_unilateral_too_early (PERSIST-015). */
  #pendingUnilateralSealResolve: ((frame: Record<string, unknown>) => void) | null = null;

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
      getMyPrimaryPubkey: () => self.#myPrimaryPubkey,
      setMyPrimaryPubkey: (pubkey: Uint8Array) => { self.#myPrimaryPubkey = new Uint8Array(pubkey); },
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
      getDirectoryStreams: () => self.#directoryStreams,
      hasPendingSessionRequest: () => self.#pendingSessionRequestResolve !== null,
      hasPendingRegister: () => self.#pendingRegisterResolve !== null,
      hasPendingDkgReady: () => self.#pendingDkgReadyResolve !== null,
      getPendingConnectionResolverCount: () => self.#connectionManager.pendingConnectionRequestResolverCount,
      dispatchSignalingFrame: (stream, frame) => { self.#dispatchSignalingFrame(stream, frame); },
      onSignalingStreamClosed: (stream) => { self.#onSignalingStreamClosed(stream); },
    };
    this.#signalingManager = new SignalingManager(sigCtx);

    // Wire up RelayStreamManager with narrow context interface
    const relayCtx: RelayStreamContext = {
      get node() { return self.#node; },
      get keyProvider() { return self.#keyProvider; },
      get logger() { return self.#logger; },
      get persistence() { return self.#persistence; },
      get contentGraceMs() { return self.#contentGraceMs; },
      get reconnectTimeoutMs() { return self.#reconnectTimeoutMs; },
      get hashQueue() { return self.#hashQueue; },
      getMyPubkeyHex: () => self.#myPubkeyHex,
      getSession: (sessionIdHex) => self.#sessions.get(sessionIdHex),
      getSessions: () => self.#sessions,
      getRelayStream: (sessionIdHex) => self.#relayStreams.get(sessionIdHex),
      setRelayStream: (sessionIdHex, stream) => { self.#relayStreams.set(sessionIdHex, stream); },
      deleteRelayStream: (sessionIdHex) => { self.#relayStreams.delete(sessionIdHex); },
      getRelayRecvSeq: (sessionIdHex) => self.#relayRecvSeq.get(sessionIdHex),
      setRelayRecvSeq: (sessionIdHex, seq) => { self.#relayRecvSeq.set(sessionIdHex, seq); },
      deleteRelayRecvSeq: (sessionIdHex) => { self.#relayRecvSeq.delete(sessionIdHex); },
      getPendingAckResolver: (sessionIdHex) => self.#pendingAckResolvers.get(sessionIdHex),
      setPendingAckResolver: (sessionIdHex, resolve) => { self.#pendingAckResolvers.set(sessionIdHex, resolve); },
      deletePendingAckResolver: (sessionIdHex) => { self.#pendingAckResolvers.delete(sessionIdHex); },
      getReadyQueue: (sessionIdHex) => self.#readyQueue.get(sessionIdHex),
      setReadyQueue: (sessionIdHex, queue) => { self.#readyQueue.set(sessionIdHex, queue); },
      deleteReadyQueue: (sessionIdHex) => { self.#readyQueue.delete(sessionIdHex); },
      getPendingS2: (sessionIdHex) => self.#pendingS2.get(sessionIdHex),
      setPendingS2: (sessionIdHex, map) => { self.#pendingS2.set(sessionIdHex, map); },
      deletePendingS2: (sessionIdHex) => { self.#pendingS2.delete(sessionIdHex); },
      getPendingContent: (sessionIdHex) => self.#pendingContent.get(sessionIdHex),
      setPendingContent: (sessionIdHex, map) => { self.#pendingContent.set(sessionIdHex, map); },
      deletePendingContent: (sessionIdHex) => { self.#pendingContent.delete(sessionIdHex); },
      getOwnPendingContent: (sessionIdHex) => self.#ownPendingContent.get(sessionIdHex),
      setOwnPendingContent: (sessionIdHex, map) => { self.#ownPendingContent.set(sessionIdHex, map); },
      deleteOwnPendingContent: (sessionIdHex) => { self.#ownPendingContent.delete(sessionIdHex); },
      getTamperedContentClaims: (sessionIdHex) => self.#tamperedContentClaims.get(sessionIdHex),
      setTamperedContentClaims: (sessionIdHex, set) => { self.#tamperedContentClaims.set(sessionIdHex, set); },
      deleteTamperedContentClaims: (sessionIdHex) => { self.#tamperedContentClaims.delete(sessionIdHex); },
      getOwnEchoResolvers: (sessionIdHex) => self.#ownEchoResolvers.get(sessionIdHex),
      setOwnEchoResolvers: (sessionIdHex, map) => { self.#ownEchoResolvers.set(sessionIdHex, map); },
      deleteOwnEchoResolvers: (sessionIdHex) => { self.#ownEchoResolvers.delete(sessionIdHex); },
      getSessionMessageQueue: (sessionIdHex) => self.#sessionMessageQueues.get(sessionIdHex),
      setSessionMessageQueue: (sessionIdHex, queue) => { self.#sessionMessageQueues.set(sessionIdHex, queue); },
      deleteSessionMessageQueue: (sessionIdHex) => { self.#sessionMessageQueues.delete(sessionIdHex); },
      getAnyMessageQueue: () => self.#anyMessageQueue,
      getReconnectInProgress: () => self.#reconnectInProgress,
      getPendingGapFillResolver: (sessionIdHex) => self.#pendingGapFillResolvers.get(sessionIdHex),
      setPendingGapFillResolver: (sessionIdHex, resolve) => { self.#pendingGapFillResolvers.set(sessionIdHex, resolve); },
      deletePendingGapFillResolver: (sessionIdHex) => { self.#pendingGapFillResolvers.delete(sessionIdHex); },
      getDirectoryStream: (sessionIdHex) => self.#directoryStreams.get(sessionIdHex),
      getOutboundQueue: (sessionIdHex) => self.#outboundQueues.get(sessionIdHex),
      // Callbacks
      onRelayDisconnected: (sessionIdHex, myPubkeyHex) => {
        const session = self.#sessions.get(sessionIdHex);
        if (!session) return;
        if (session.desynchronized) return;
        if (session.status === "transport_lost") return;
        // Sealing/sealed/seal_rejected/seal_deferred: relay close expected; do not clobber status.
        if (session.status === "sealing" || session.status === "sealed" || session.status === "seal_rejected" || session.status === "seal_deferred") return;
        session.status = "transport_lost";
        void self.#persistence?.persistSession(sessionIdHex, session);
        const ackResolve = self.#pendingAckResolvers.get(sessionIdHex);
        if (ackResolve) {
          self.#pendingAckResolvers.delete(sessionIdHex);
          ackResolve({ ok: false, reason: "transport_unavailable" });
        }
        void self.#relayStreamManager.reconnectRelayStream(sessionIdHex, myPubkeyHex);
      },
      wakeReceiveWaiters: (sessionIdHex) => { self.#wakeReceiveWaiters(sessionIdHex); },
      enqueueSessionSealedEvent: (sessionIdHex, sealedRoot, closeTimestamp) => {
        self.#enqueueSessionSealedEvent(sessionIdHex, sealedRoot, closeTimestamp);
      },
      handleSealVerified: (sessionIdHex, frame) => { void self.#handleSealVerified(sessionIdHex, frame); },
      handleSessionFrostSealed: (sessionIdHex, frame) => { self.#handleSessionFrostSealed(sessionIdHex, frame); },
      handleSealRejectedTreeMismatch: (sessionIdHex, frame) => { self.#handleSealRejectedTreeMismatch(sessionIdHex, frame); },
      handleSealUnilateralConfirmed: (sessionIdHex, frame) => { self.#handleSealUnilateralConfirmed(sessionIdHex, frame); },
      handleSealUnilateralNotification: (sessionIdHex, frame) => { self.#handleSealUnilateralNotification(sessionIdHex, frame); },
      handleDirectorySessionSealed: (sessionIdHex, frame, directoryPubkey) => {
        self.#handleDirectorySessionSealed(sessionIdHex, frame, directoryPubkey);
      },
      handleDirectorySessionSealRejected: (sessionIdHex, frame) => {
        self.#handleDirectorySessionSealRejected(sessionIdHex, frame);
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
    this.#myPrimaryPubkey = new Uint8Array(primaryPubkey);
  }

  /**
   * PERSIST-024: Load all durable state from the SQLCipher DB and populate in-memory state.
   *
   * Pseudocode:
   *   1. Call persistence.loadStartupState() — emits client.startup.state.loaded
   *   2. Restore FROST key share → call storeDkgResult to populate module-level key store;
   *      reconstruct FrostThresholdSigner with same config used at registration
   *   3. Restore ML-DSA keypair → reconstruct InMemoryMlDsaKeyProvider
   *   4. Restore registration state → populate #registrationState
   *   5. Restore connections → populate #connections and #connectionsByPeer
   *   6. Restore connection policy → populate #connectionPolicy
   *   7. Restore sessions → populate #sessions; load leaves per session
   *   8. Restore peers → populate #peers
   *   9. Restore decided requests → populate #decidedRequests
   *
   * Security invariants:
   *   SI-001: signing_share bytes never appear in any log event.
   *   SI-002: secret_key_blob bytes never appear in any log event.
   *
   * Crypto refs: RFC 9591 (FROST), NIST FIPS 204 (ML-DSA-44)
   */
  async loadPersistedState(): Promise<void> {
    const p = this.#persistence;
    if (!p) return;

    const state = await p.loadStartupState();

    // ── 1. FROST key share ────────────────────────────────────────────────────
    if (state.frostShare) {
      const row = state.frostShare;
      // Reconstruct FrostSecret: { identifier, signingShare }
      const signingShareBytes = row.signing_share instanceof Buffer
        ? new Uint8Array(row.signing_share)
        : new Uint8Array(row.signing_share as Uint8Array);
      const frostSecret = { identifier: row.identifier, signingShare: signingShareBytes };

      // Reconstruct FrostPublic: { signers, commitments, verifyingShares }
      // commitments_cbor is CBOR-encoded Uint8Array[]; verifying_shares_cbor is CBOR-encoded Record<string, Uint8Array>
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
        // HIGH-2: emit correct error event and return early — do not call storeDkgResult
        // with broken/empty data, which would corrupt the module-level key store.
        this.#logger.error("client.frost.share.load.failed", {
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
        this.#logger.error("client.frost.share.load.failed", {
          agentPubkey: myPubkeyHex,
          reason: "storeDkgResult_failed",
        });
        return;
      }

      // Reconstruct FrostThresholdSigner (config only — secret is in module-level store).
      // AC-003 (DX-001): directoryNodeStubs MUST be populated from the current directoryEndpoint
      // so that the signer can participate in FROST signing ceremonies (round-trip frames
      // to directory via libp2p). Without directoryNodeStubs, the signer can verify but cannot
      // participate in ceremonies — causing directory_below_threshold on session initiation.
      if (!this.#thresholdSigner) {
        let directoryNodeStubsForSigner: NetworkDirectoryNode[] | undefined;
        if (this.#directoryEndpoint) {
          const stub = new NetworkDirectoryNode({
            id: this.#directoryEndpoint.peer_id,
            node: this.#node,
            directoryPeerId: this.#directoryEndpoint.peer_id,
            directoryMultiaddrs: this.#directoryEndpoint.multiaddrs,
          });
          stub.setBootstrapContext(myPubkeyHex, `${myPubkeyHex}:epoch:1`);
          directoryNodeStubsForSigner = [stub];
        }
        this.#thresholdSigner = new FrostThresholdSigner(
          {
            threshold: row.threshold,
            participants: row.participants,
            directoryNodeStubs: directoryNodeStubsForSigner,
          },
          Buffer.from(myPubkeyHex, "hex"),
        );
      }

      // Set primary_pubkey from stored commitments[0]
      if (commitments.length > 0 && !this.#myPrimaryPubkey) {
        this.#myPrimaryPubkey = new Uint8Array(commitments[0]!);
      }

      // HIGH-1: emit success event after FROST share loaded
      this.#logger.info("client.frost.share.loaded", {
        agentPubkey: myPubkeyHex,
        epochId: row.epoch_id,
        threshold: row.threshold,
        participants: row.participants,
      });
    }

    // HIGH-3: emit alarm when registration exists but no FROST share found
    if (!state.frostShare && state.registrationState) {
      this.#logger.error("client.frost.share.missing", {
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
        this.#mlDsaProvider = new InMemoryMlDsaKeyProvider(mlDsaPubkeyBytes, secretKeyBlob);
        // HIGH-1: emit success event after ML-DSA keypair loaded
        this.#logger.info("client.mldsa.keypair.loaded", {
          agentPubkey: row.agent_pubkey,
          mlDsaPubkey: row.ml_dsa_pubkey,
        });
      } catch (err: unknown) {
        // Story specifies level: error for this event
        this.#logger.error("client.mldsa.load.failed", {
          agentPubkey: row.agent_pubkey,
          reason: err instanceof Error ? err.message : String(err),
        });
      }
    }

    // ── 3. Registration state ─────────────────────────────────────────────────
    if (state.registrationState) {
      const row = state.registrationState;
      this.#registrationState = {
        agent_id: row.agent_id,
        primary_pubkey: row.primary_pubkey,
        ml_dsa_pubkey: row.ml_dsa_pubkey,
        registered_at: row.registered_at,
        status: "active",
      };
      // HIGH-1: emit success event after registration state loaded
      this.#logger.info("client.registration.loaded", {
        agentPubkey: row.agent_pubkey,
        agentId: row.agent_id,
        status: row.status,
      });
    }

    // ── 4. Connections ────────────────────────────────────────────────────────
    for (const row of state.connections) {
      if (!this.#connections.has(row.connection_id)) {
        const record: import("@cello-protocol/protocol-types").ClientConnectionRecord = {
          connection_id: row.connection_id,
          counterparty_primary_pubkey: row.counterparty_primary_pubkey ?? "",
          counterparty_ml_dsa_pubkey: row.counterparty_ml_dsa_pubkey ?? "",
          counterparty_pubkey: row.counterparty_pubkey,
          established_at: row.established_at,
          status: row.status as "active",
        };
        this.#connections.set(row.connection_id, record);
        this.#connectionsByPeer.set(row.counterparty_pubkey, row.connection_id);
        if (row.profile_unchecked) {
          this.#profileUncheckedPeers.add(row.counterparty_pubkey);
        }
      }
    }

    // ── 5. Connection policy ──────────────────────────────────────────────────
    if (state.connectionPolicy) {
      this.#connectionPolicy = state.connectionPolicy;
    }

    // ── 6. Sessions + leaves ──────────────────────────────────────────────────
    for (const row of state.sessions) {
      const sessionIdHex = row.session_id;
      if (this.#sessions.has(sessionIdHex)) continue;

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

      this.#sessions.set(sessionIdHex, record);
      this.#sessionMessageQueues.set(sessionIdHex, []);

      // HIGH-4: emit alarm when loaded leaf count doesn't match sessions.leaf_count
      if (leaves.length !== row.leaf_count) {
        this.#logger.error("client.session.leaves.mismatch", {
          agentPubkey: row.agent_pubkey,
          sessionId: sessionIdHex,
          expectedLeafCount: row.leaf_count,
          actualLeafCount: leaves.length,
        });
      }
    }

    // ── 7. Peers ──────────────────────────────────────────────────────────────
    for (const row of state.peers) {
      if (!this.#peers.has(row.peer_pubkey_hex)) {
        let multiaddrs: string[] = [];
        try { multiaddrs = JSON.parse(row.multiaddrs) as string[]; } catch { /* ignore */ }
        this.#peers.set(row.peer_pubkey_hex, { peerId: row.peer_id, multiaddrs, connected: false });
      }
    }

    // ── 8. Decided requests ───────────────────────────────────────────────────
    for (const row of state.decidedRequests) {
      this.#connectionManager.restoreDecidedRequest(row.request_id);
    }

    // ── 9. Pending connection requests ────────────────────────────────────────
    for (const row of state.pendingConnectionRequests) {
      const packageCbor = row.package_cbor instanceof Buffer
        ? new Uint8Array(row.package_cbor)
        : new Uint8Array(row.package_cbor as Uint8Array);
      // Populate ConnectionManager#pendingInboundRequests so acceptConnection/rejectConnection work
      this.#connectionManager.restorePendingInboundRequest({
        connection_request_id: row.request_id,
        from_pubkey: row.from_pubkey,
        package_cbor: packageCbor,
        round: row.round,
      });
      // Populate ConnectionManager#pendingReviewQueue so awaitConnectionRequest() returns it.
      // Reconstruct a minimal pending_agent_review report — the full policy evaluation
      // result is not persisted, only the package_cbor. The agent review UI only needs
      // the connection_request_id, from_pubkey, and package_cbor to make a decision.
      const restoredReport: Extract<import("./connection-policy.js").ConnectionReport, { verdict: "pending_agent_review" }> = {
        verdict: "pending_agent_review",
        policy_summary: {
          mode: "unknown",
          review_mode: "inference",
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
      };
      this.#connectionManager.restoreReviewQueueItem({
        connection_request_id: row.request_id,
        from_pubkey: row.from_pubkey,
        report: restoredReport,
        package_cbor: packageCbor,
        sender_registered_at: 0,
        sender_is_provisional: false,
      });
    }

    // ── 10. Endorsements and attestations (MED-4) ────────────────────────────────
    if (state.endorsements.length > 0) {
      this.#endorsements = state.endorsements;
    }
    if (state.attestations.length > 0) {
      this.#attestations = state.attestations;
    }

    // ── HIGH-3: set #myPubkeyHex from registration state if sessions were loaded ──
    // #myPubkeyHex is used in #sendMessageLocked with a non-null assertion.
    // It is set during receiveSessionAssignment but never set during startup load.
    // If the agent restarts with active sessions and calls sendMessage before any
    // new session assignment, it would crash on the non-null assertion.
    if (!this.#myPubkeyHex && state.registrationState) {
      this.#myPubkeyHex = state.registrationState.agent_pubkey;
    }

    // ── PERSIST-024 FINDING-4: store loaded pending hashes for caller consumption ──
    // The caller (composition root) must pass these to AgentHashQueue so they are
    // resubmitted to the relay on reconnect (AC-008). CelloClientImpl does not hold
    // an AgentHashQueue directly — that is a composition-root concern.
    this.#loadedPendingHashes = state.pendingHashes.map((row) => ({
      sessionId: row.session_id,
      hashHex: row.hash_hex,
      enqueuedAt: row.enqueued_at,
    }));

    // M-5: upsertAgent at the END of startup so last_seen_at only reflects a fully successful boot.
    await p.upsertAgent();

    // PERSIST-024 FINDING-3: emit client.startup.state.loaded AFTER all in-memory structures
    // are populated. AC-013 requires this event to fire only after the full startup sequence.
    // The event is not emitted by loadStartupState() (which only loads DB rows).
    this.#logger.info("client.startup.state.loaded", {
      agentPubkey: this.#myPubkeyHex ?? state.registrationState?.agent_pubkey ?? "unknown",
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
    this.#sessions.set(sessionIdHex, record);
    if (!this.#myPubkeyHex) {
      this.#myPubkeyHex = myPubkeyHex;
    }
    // M-001: mark as seal-initiated and FROST ceremony participant so #handleFrostSealed
    // uses own primary_pubkey for verification.
    if (opts?.isInitiator) {
      this.#sealInitiatedSessions.add(sessionIdHex);
      this.#frostCeremonyParticipant.add(sessionIdHex);
    }
  }

  // Internal test escape: directly feed a session_sealed, session_seal_rejected,
  // seal_verified, or session_frost_sealed frame into the directory stream handler —
  // bypasses the real directory signaling stream so tests can inject adversarial frames.
  injectDirectoryFrame(sessionIdHex: string, frame: Record<string, unknown>): void {
    const session = this.#sessions.get(sessionIdHex);
    if (!session) throw new Error(`injectDirectoryFrame: session not found: ${sessionIdHex}`);
    if (frame["type"] === "session_sealed") {
      this.#handleDirectorySessionSealed(sessionIdHex, frame, session.directory_pubkey);
    } else if (frame["type"] === "session_seal_rejected") {
      this.#handleDirectorySessionSealRejected(sessionIdHex, frame);
    } else if (frame["type"] === "seal_rejected_tree_mismatch") {
      this.#handleSealRejectedTreeMismatch(sessionIdHex, frame);
    } else if (frame["type"] === "seal_unilateral_confirmed") {
      this.#handleSealUnilateralConfirmed(sessionIdHex, frame);
    } else if (frame["type"] === "seal_unilateral_notification") {
      this.#handleSealUnilateralNotification(sessionIdHex, frame);
    } else if (frame["type"] === "seal_verified") {
      void this.#handleSealVerified(sessionIdHex, frame);
    } else if (frame["type"] === "session_frost_sealed") {
      this.#handleSessionFrostSealed(sessionIdHex, frame);
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
    const { session_id, session_timestamp } = assignment;
    const pubA = assignment.participant_a.pubkey;
    const pubB = assignment.participant_b.pubkey;

    // SESSION-004 Step 1: Check signature_type (SI-003, AC-003)
    // M1 'single' frames are hard-refused in M2 — even if the single-key sig verifies.
    if (assignment.signature_type === "single") {
      return { ok: false, reason: "unsupported_signature_type" };
    }

    // SESSION-004 Step 2: Determine role and verification key (AC-007)
    const myPubkeyHex = Buffer.from(myPubkey).toString("hex");
    const pubAHex = Buffer.from(pubA).toString("hex");
    const isInitiator = myPubkeyHex === pubAHex;

    let verifyKey: Uint8Array;
    if (isInitiator) {
      // CRITICAL-1: initiator MUST have a thresholdSigner injected.
      // Falling back to assignment.signer_pubkey (frame-provided) would be attacker-controlled.
      if (!this.#thresholdSigner) {
        return { ok: false, reason: "frost_signer_not_configured" };
      }
      verifyKey = this.#thresholdSigner.getPrimaryPubkey();
    } else {
      // Counterparty (B): use signer_pubkey from the frame (A's primary_pubkey).
      // TypeScript discriminated union guarantees signer_pubkey is present for 'frost' frames.
      verifyKey = assignment.signer_pubkey;
    }

    // SESSION-004 Step 3: Build TBS and verify FROST signature (AC-002, SI-001)
    // TBS = canonical CBOR([session_id, pubA, pubB, genesis_prev_root, session_timestamp])
    // buildSessionEstablishmentTbs imported from protocol-types (HIGH-5: single source of truth)
    const genesis_prev_root_for_tbs = computeGenesisPrevRoot(pubA, pubB, session_id, session_timestamp);
    const tbs = buildSessionEstablishmentTbs(session_id, pubA, pubB, genesis_prev_root_for_tbs, session_timestamp);

    // Verify FROST signature with domain separation (context\0tbs framing)
    if (!verifyFrostSignature(assignment.directory_signature, tbs, CONTEXT_SESSION_ESTABLISHMENT, verifyKey)) {
      return { ok: false, reason: "frost_signature_invalid" };
    }

    // Step 4: Determine counterparty
    const counterparty = isInitiator ? assignment.participant_b : assignment.participant_a;

    // genesis_prev_root was already computed above for TBS — reuse it
    const genesis_prev_root = genesis_prev_root_for_tbs;

    // Step 4: Register content protocol handler on this node (if not already registered).
    // Set the flag before awaiting handle() to prevent concurrent calls from both registering.
    if (!this.#contentHandlerRegistered) {
      this.#contentHandlerRegistered = true;
      try {
        await this.#node.handle(CELLO_CONTENT_PROTOCOL_ID, (stream) => {
          void this.#relayStreamManager.handleContentStream(stream);
        });
      } catch {
        // Already registered by a concurrent call — safe to ignore.
      }
    }

    // Step 5: Dial relay on /cello/relay/1.0.0 and complete challenge-response auth (AC-003)
    const relayPeerId = assignment.relay_endpoint.peer_id;
    const relayMultiaddr = assignment.relay_endpoint.multiaddrs[0];

    if (relayMultiaddr) {
      try {
        await this.#node.dial(relayMultiaddr);
      } catch {
        // Connection may already exist — proceed
      }
    }

    let relayStream: Stream;
    try {
      relayStream = await this.#node.newStream(relayPeerId, RELAY_PROTOCOL_ID);
    } catch {
      return { ok: false, reason: "relay_auth_error" };
    }

    // Auth challenge-response
    // Read relay_auth_challenge, respond with relay_auth_response
    // Signature: Ed25519(SHA-256("CELLO-RELAY-AUTH-v1" || nonce || myPubkey), keyProvider) per RFC 8032, FIPS 180-4
    let relayIter: AsyncIterator<Uint8Array>;
    try {
      const authResult = await this.#relayStreamManager.performRelayAuth(relayStream, myPubkey);
      if (!authResult.ok) {
        return { ok: false, reason: authResult.reason };
      }
      relayIter = authResult.iter;
    } catch {
      return { ok: false, reason: "relay_auth_error" };
    }

    // Step 6: Dial counterparty on /cello/content/1.0.0 (AC-004)
    // Best-effort: counterparty may not yet be listening. Session is stored as active
    // regardless — the content stream will be re-established on first message.
    try {
      const counterpartyMultiaddr = counterparty.multiaddrs[0];
      if (counterpartyMultiaddr) {
        try {
          await this.#node.dial(counterpartyMultiaddr);
        } catch {
          // Already connected or not yet reachable — proceed
        }
      }
      const contentStream = await this.#node.newStream(counterparty.peer_id, CELLO_CONTENT_PROTOCOL_ID);
      // Close gracefully — content stream will be re-established per message in M1
      contentStream.close().catch(() => {});
    } catch {
      // Counterparty not yet listening — store session as active anyway.
      // Content connection will be established when first message is sent.
    }

    // Step 7: Store session record (AC-004)
    const sessionIdHex = Buffer.from(session_id).toString("hex");
    const record: SessionRecord = {
      session_id,
      counterparty_pubkey: counterparty.pubkey,
      counterparty_peer_id: counterparty.peer_id,
      counterparty_multiaddrs: counterparty.multiaddrs,
      relay_endpoint: {
        peer_id: assignment.relay_endpoint.peer_id,
        multiaddrs: assignment.relay_endpoint.multiaddrs,
      },
      directory_endpoint: {
        peer_id: assignment.directory_endpoint.peer_id,
        multiaddrs: assignment.directory_endpoint.multiaddrs,
      },
      directory_pubkey: assignment.directory_pubkey,
      genesis_prev_root,
      last_seen_seq: 0,
      last_sent_seq: 0,
      status: "active",
      local_tree_leaves: [],
      next_expected_seq: 1,
      desynchronized: false,
    };
    this.#sessions.set(sessionIdHex, record);
    // PERSIST-024: persist session to DB
    if (this.#persistence) {
      void this.#persistence.persistSession(sessionIdHex, record);
    }

    // Store the relay stream and start the persistent reader loop (MSG-004)
    this.#relayStreams.set(sessionIdHex, relayStream);
    this.#relayRecvSeq.set(sessionIdHex, 0);
    this.#readyQueue.set(sessionIdHex, new Map());
    this.#pendingS2.set(sessionIdHex, new Map());
    this.#pendingContent.set(sessionIdHex, new Map());
    this.#ownPendingContent.set(sessionIdHex, new Map());
    this.#tamperedContentClaims.set(sessionIdHex, new Set());
    this.#ownEchoResolvers.set(sessionIdHex, new Map());
    this.#sessionMessageQueues.set(sessionIdHex, []);

    // Cache myPubkeyHex for the stream reader (same key across all sessions on this client)
    if (!this.#myPubkeyHex) this.#myPubkeyHex = myPubkeyHex;

    this.#relayStreamManager.runRelayStreamReader(sessionIdHex, relayStream, myPubkeyHex, relayIter);

    // Fire inbound session handler if this client is participant B (session was initiated
    // by a remote peer). MCP-002: cello_await_session uses this to populate its queue.
    // myPubkeyHex !== pubAHex means we are B (the non-initiator).
    if (myPubkeyHex !== pubAHex && this.#onSessionAssignmentHandler) {
      this.#onSessionAssignmentHandler({
        sessionIdHex: sessionIdHex,
        counterpartyPubkeyHex: Buffer.from(counterparty.pubkey).toString("hex"),
        genesisPrevRootHex: Buffer.from(genesis_prev_root).toString("hex"),
      });
    }

    // ADAPTER-003: if the persistent signaling stream is already open (e.g. opened by
    // initiateSession), it handles session_sealed/seal_rejected events for all sessions.
    // Only open a per-session stream when the persistent stream is not available.
    if (!this.#persistentSignalingStream) {
      void this.#signalingManager.connectDirectorySignalingStream(sessionIdHex, assignment, myPubkey);
    }

    return { ok: true, sessionId: session_id };
  }

  listSessions(): SessionRecord[] {
    return Array.from(this.#sessions.values());
  }

  // ─── MSG-004 implementation ──────────────────────────────────────────────────

  async sendMessage(sessionIdHex: string, content: Uint8Array): Promise<SendMessageResult> {
    // Per-session outbound serialization queue: next send not started until echo received
    const prev = this.#outboundQueues.get(sessionIdHex) ?? Promise.resolve();
    let release!: () => void;
    const next = new Promise<void>((r) => { release = r; });
    this.#outboundQueues.set(sessionIdHex, prev.then(() => next));
    await prev;
    try {
      return await this.#sendMessageLocked(sessionIdHex, content);
    } finally {
      release();
    }
  }

  async #sendMessageLocked(sessionIdHex: string, content: Uint8Array): Promise<SendMessageResult> {
    const session = this.#sessions.get(sessionIdHex);
    if (!session) return { ok: false, reason: "session_not_found" };
    if (session.desynchronized) return { ok: false, reason: "session_desynchronized" };
    if (session.status === "sealing" || session.status === "sealed" || session.status === "seal_deferred" || session.status === "seal_rejected") return { ok: false, reason: "session_sealed" };
    // SESSION-006 AC-001/AC-003: transport_lost means relay stream is gone or being reconnected
    if (session.status === "transport_lost") return { ok: false, reason: "transport_unavailable" };

    const relayStream = this.#relayStreams.get(sessionIdHex);
    if (!relayStream || relayStream.status !== "open") {
      return { ok: false, reason: "transport_unavailable" };
    }

    // content_hash = SHA-256(0x00 || content) per MERKLE-001
    const contentHash = new Uint8Array(
      createHash("sha256").update(new Uint8Array([0x00])).update(content).digest()
    );

    // Build Structure 1 TBS: [1, content_hash, myPubkey, session_id, last_seen_seq, timestamp]
    const myPubkeyHex = this.#myPubkeyHex!;
    const myPubkeyBytes = Buffer.from(myPubkeyHex, "hex");
    const tbs = CBOR_ENC.encode([
      1,
      contentHash,
      myPubkeyBytes,
      session.session_id,
      session.last_seen_seq,
      Date.now(),
    ]) as Uint8Array;
    const signature = await this.#keyProvider.sign(tbs);

    // Submit hash_submit to relay on the persistent relay stream
    const hashSubmitFrame = CBOR_ENC.encode({
      type: "hash_submit",
      session_id: session.session_id,
      leaf_kind: 0x00,
      structure1_cbor: tbs,
      sender_signature: signature,
    }) as Uint8Array;

    // Pre-buffer own content in a separate map so the echo cross-check finds it immediately.
    // The sender won't receive a content_frame for its own messages (it sent to counterparty,
    // not to itself). Using a separate map from #pendingContent avoids collision when both
    // participants send identical byte payloads in the same session.
    const contentHashHex = Buffer.from(contentHash).toString("hex");
    this.#ownPendingContent.get(sessionIdHex)?.set(contentHashHex, {
      content_bytes: content,
      arrived_at: Date.now(),
    });

    // PERSIST-024 AC-008: Persist pending hash BEFORE relay submission (SI-001 of PERSIST-012).
    // The entry is removed after the ACK is confirmed. This ensures crash recovery can detect
    // un-ACKed hashes and resubmit them on relay reconnect.
    const enqueuedAt = Date.now();
    if (this.#persistence) {
      void this.#persistence.persistPendingHash({ sessionId: sessionIdHex, hashHex: contentHashHex, enqueuedAt });
    }

    // Set up ack resolver before sending to avoid race with fast relay.
    // The outbound queue guarantees at most one in-flight send per session.
    // Guard here so a queue bug causes an immediate throw rather than a silent orphan.
    if (this.#pendingAckResolvers.has(sessionIdHex)) {
      throw new Error(`[cello-client] ack resolver already set for session ${sessionIdHex}; outbound queue invariant violated`);
    }
    let ackResolve!: (v: { ok: true; sequence_number: number } | { ok: false; reason: string }) => void;
    const ackPromise = new Promise<{ ok: true; sequence_number: number } | { ok: false; reason: string }>(
      (r) => { ackResolve = r; }
    );
    this.#pendingAckResolvers.set(sessionIdHex, ackResolve);

    try {
      relayStream.send(lp.encode.single(hashSubmitFrame));
    } catch {
      this.#pendingAckResolvers.delete(sessionIdHex);
      this.#ownPendingContent.get(sessionIdHex)?.delete(contentHashHex);
      // Remove the pending hash entry — the submission never reached the relay
      if (this.#persistence) {
        void this.#persistence.removePendingHash(sessionIdHex, contentHashHex);
      }
      return { ok: false, reason: "transport_unavailable" };
    }

    const ack = await ackPromise;
    if (!ack.ok) {
      // Relay rejected — remove the pending hash entry
      if (this.#persistence) {
        void this.#persistence.removePendingHash(sessionIdHex, contentHashHex);
      }
      return { ok: false, reason: "relay_rejected" };
    }
    const mySeq = ack.sequence_number;

    // PERSIST-024 AC-008: Relay ACKed — remove from pending_hashes (relay has stored the hash).
    if (this.#persistence) {
      void this.#persistence.removePendingHash(sessionIdHex, contentHashHex);
    }

    // Send content to counterparty on /cello/content/1.0.0
    // Best-effort: if content path fails, the receiver's 30s grace timer will desync
    const sess2 = this.#sessions.get(sessionIdHex);
    if (sess2 && !sess2.desynchronized) {
      void this.#sendContentFrame(sess2, content, contentHash);
    }

    // Wait for our own echoed leaf_deliver (unblocks when crossCheckDelivery fires echo_resolve)
    await this.#waitForOwnEcho(sessionIdHex, mySeq);

    // Re-check desync: desync() fires the resolver to unblock, but send must still fail
    const sess3 = this.#sessions.get(sessionIdHex);
    if (!sess3 || sess3.desynchronized) return { ok: false, reason: "session_desynchronized" };

    return { ok: true };
  }

  async #sendContentFrame(session: SessionRecord, content: Uint8Array, contentHash: Uint8Array): Promise<void> {
    const counterpartyPeerId = session.counterparty_peer_id;
    try {
      // Dial counterparty if not connected
      const multiaddr = session.counterparty_multiaddrs[0];
      if (multiaddr) {
        try { await this.#node.dial(multiaddr); } catch { /* already connected */ }
      }
      const contentStream = await this.#node.newStream(counterpartyPeerId, CELLO_CONTENT_PROTOCOL_ID);
      const frame = CBOR_ENC.encode({
        type: "content_frame",
        session_id: session.session_id,
        content_hash: contentHash,
        content_bytes: content,
      }) as Uint8Array;
      contentStream.send(lp.encode.single(frame));
      await contentStream.close();
    } catch {
      // Content path failure is silent; 30s grace timer fires if receiver doesn't get content
    }
  }

  async #waitForOwnEcho(sessionIdHex: string, seqNum: number): Promise<void> {
    return new Promise<void>((resolve) => {
      const resolvers = this.#ownEchoResolvers.get(sessionIdHex);
      if (resolvers) {
        resolvers.set(seqNum, resolve);
      } else {
        resolve(); // session was closed
      }
    });
  }

  receiveMessage(sessionIdHex: string): ReceivedMessage | null {
    const queue = this.#sessionMessageQueues.get(sessionIdHex);
    if (!queue || queue.length === 0) return null;
    return queue.shift()!;
  }

  receiveAnyMessage(): { sessionIdHex: string; message: ReceivedMessage } | null {
    return this.#anyMessageQueue.shift() ?? null;
  }

  // ─── SESSION-007: async blocking receive ─────────────────────────────────────
  //
  // Pseudocode for receiveMessageAsync(timeoutMs):
  //   1. Check #anyMessageQueue — if non-empty, dequeue and return immediately.
  //   2. Register a wake resolver in #receiveAnyWaiters.
  //   3. Race: wait for wakeUp() signal vs. setTimeout(timeoutMs).
  //   4. On wake: dequeue from #anyMessageQueue. Also dequeue from per-session queue.
  //   5. On timeout: return { type: 'timeout' }.
  //
  // Pseudocode for receiveSessionMessageAsync(sessionIdHex, timeoutMs):
  //   1. Check #sessionMessageQueues[sessionIdHex] — if non-empty, dequeue and return immediately.
  //   2. Register a wake resolver in #receiveWaiters[sessionIdHex].
  //   3. Race: wait for wakeUp() signal vs. setTimeout(timeoutMs).
  //   4. On wake: dequeue from #sessionMessageQueues. If empty (spurious wake), repeat from step 2.
  //   5. On timeout: clean up resolver, return null.
  //   6. On return: compute otherSessionsPending, log session.receive.pending_hint if non-empty.
  //
  // Pseudocode for #wakeReceiveWaiters(sessionIdHex):
  //   1. Fire all resolvers in #receiveWaiters[sessionIdHex].
  //   2. Fire all resolvers in #receiveAnyWaiters.
  //   (Resolvers clear themselves on fire to avoid double-wake.)
  //
  // Pseudocode for #computeOtherSessionsPending(excludeSessionIdHex):
  //   1. For each entry in #sessionMessageQueues, skip excluded session.
  //   2. Collect sessionIdHex values where queue.length > 0.
  //   3. Return collected array.
  //
  // Pseudocode for #enqueueSessionSealedEvent(sessionIdHex, sealedRoot, closeTimestamp):
  //   1. Log session.sealed.received with {sessionId, sealedRoot (hex), closeTimestamp, checkpointStatus, correlationId}.
  //   2. Build lifecycle event: { type: "session_sealed", sessionIdHex, sealedRoot, closeTimestamp, checkpointStatus: "pending" }.
  //   3. Enqueue to #sessionMessageQueues[sessionIdHex] (create queue if missing).
  //   4. Enqueue to #anyMessageQueue.
  //   5. Call #wakeReceiveWaiters(sessionIdHex).

  #computeOtherSessionsPending(excludeSessionIdHex: string): string[] {
    const pending: string[] = [];
    for (const [sid, queue] of this.#sessionMessageQueues.entries()) {
      if (sid !== excludeSessionIdHex && queue.length > 0) {
        pending.push(sid);
      }
    }
    return pending;
  }

  #wakeReceiveWaiters(sessionIdHex: string): void {
    // Wake per-session waiters
    const sessionWaiters = this.#receiveWaiters.get(sessionIdHex);
    if (sessionWaiters) {
      for (const resolve of sessionWaiters) resolve();
      sessionWaiters.clear();
    }
    // Wake any-session waiters
    for (const resolve of this.#receiveAnyWaiters) resolve();
    this.#receiveAnyWaiters.clear();
  }

  async receiveSessionMessageAsync(sessionIdHex: string, timeoutMs: number): Promise<ReceivedMessage | null> {
    const deadline = Date.now() + timeoutMs;

    while (true) {
      // Check queue first (fast path: already has messages)
      const queue = this.#sessionMessageQueues.get(sessionIdHex);
      if (queue && queue.length > 0) {
        const item = queue.shift()!;
        // Remove from #anyMessageQueue as well to keep in sync
        const idx = this.#anyMessageQueue.findIndex(
          (e) => e.sessionIdHex === sessionIdHex && e.message === item
        );
        if (idx !== -1) this.#anyMessageQueue.splice(idx, 1);
        // Attach otherSessionsPending
        const pending = this.#computeOtherSessionsPending(sessionIdHex);
        const result = pending.length > 0 ? { ...item, otherSessionsPending: pending } : item;
        if (pending.length > 0) {
          this.#logger.info("session.receive.pending_hint", {
            currentSessionId: sessionIdHex,
            pendingSessionCount: pending.length,
            correlationId: sessionIdHex,
          });
        }
        return result;
      }

      const remaining = deadline - Date.now();
      if (remaining <= 0) return null;

      // Register wake resolver and race against timeout
      await new Promise<void>((resolve) => {
        let set = this.#receiveWaiters.get(sessionIdHex);
        if (!set) {
          set = new Set();
          this.#receiveWaiters.set(sessionIdHex, set);
        }
        set.add(resolve);
        setTimeout(() => {
          // Remove resolver if timeout fires before wake
          this.#receiveWaiters.get(sessionIdHex)?.delete(resolve);
          resolve();
        }, remaining);
      });
    }
  }

  async receiveMessageAsync(timeoutMs: number): Promise<
    | (ReceivedMessage & { sessionIdHex: string })
    | { type: "timeout" }
  > {
    const deadline = Date.now() + timeoutMs;

    while (true) {
      // Check any-session queue first (fast path)
      if (this.#anyMessageQueue.length > 0) {
        const entry = this.#anyMessageQueue.shift()!;
        // Remove from per-session queue as well
        const perSession = this.#sessionMessageQueues.get(entry.sessionIdHex);
        if (perSession) {
          const idx = perSession.indexOf(entry.message);
          if (idx !== -1) perSession.splice(idx, 1);
        }
        // Attach otherSessionsPending
        const pending = this.#computeOtherSessionsPending(entry.sessionIdHex);
        const result = pending.length > 0
          ? { ...entry.message, sessionIdHex: entry.sessionIdHex, otherSessionsPending: pending }
          : { ...entry.message, sessionIdHex: entry.sessionIdHex };
        if (pending.length > 0) {
          this.#logger.info("session.receive.pending_hint", {
            currentSessionId: entry.sessionIdHex,
            pendingSessionCount: pending.length,
            correlationId: entry.sessionIdHex,
          });
        }
        return result;
      }

      const remaining = deadline - Date.now();
      if (remaining <= 0) return { type: "timeout" };

      // Register wake resolver and race against timeout
      await new Promise<void>((resolve) => {
        this.#receiveAnyWaiters.add(resolve);
        setTimeout(() => {
          this.#receiveAnyWaiters.delete(resolve);
          resolve();
        }, remaining);
      });
    }
  }

  #enqueueSessionSealedEvent(
    sessionIdHex: string,
    sealedRoot: Uint8Array,
    closeTimestamp: number,
  ): void {
    // Use sessionIdHex as correlationId — minted at session initiation, unique per session flow.
    const correlationId = sessionIdHex;
    this.#logger.info("session.sealed.received", {
      sessionId: sessionIdHex,
      sealedRoot: Buffer.from(sealedRoot).toString("hex"),
      closeTimestamp,
      checkpointStatus: "pending",
      correlationId,
    });
    const lifecycleEvent: ReceivedMessage = {
      type: "session_sealed",
      sessionIdHex,
      sealedRoot: new Uint8Array(sealedRoot),
      closeTimestamp,
      checkpointStatus: "pending",
    };
    let queue = this.#sessionMessageQueues.get(sessionIdHex);
    if (!queue) {
      queue = [];
      this.#sessionMessageQueues.set(sessionIdHex, queue);
    }
    queue.push(lifecycleEvent);
    this.#anyMessageQueue.push({ sessionIdHex, message: lifecycleEvent });
    this.#wakeReceiveWaiters(sessionIdHex);
  }

  // ─── SESSION-003: seal ceremony ──────────────────────────────────────────────

  async initiateSessionSeal(sessionIdHex: string): Promise<{ ok: true } | { ok: false; reason: string }> {
    const session = this.#sessions.get(sessionIdHex);
    if (!session) return { ok: false, reason: "session_not_found" };
    if (session.status !== "active") return { ok: false, reason: "session_not_active" };

    // Fix 1: ensure the signaling stream is alive before mutating session state.
    // The directory replies (seal_verified / session_frost_sealed) on this stream.
    // If the stream dropped silently (libp2p TCP idle disconnect), the reply is lost,
    // the 15-second FROST timeout fires, and the session permanently ends as seal_deferred.
    // Reconnecting first guarantees the directory's response lands on a live reader loop.
    // Status mutation is deferred until after reconnect succeeds to avoid a sealing-stuck
    // crash window (if the process restarts between the persist and the rollback, the session
    // would be permanently unresealable).
    if (!this.#persistentSignalingStream || this.#persistentSignalingStream.status !== "open") {
      const correlationId = Buffer.from(session.session_id).toString("hex");
      this.#logger.info("seal.reconnect.attempted", { sessionId: sessionIdHex, correlationId });
      this.#persistentSignalingStream = null;
      this.#persistentSignalingIter = null;
      const opened = await this.#openPersistentSignalingStream();
      if (!opened || !this.#persistentSignalingStream) {
        return { ok: false, reason: "directory_unreachable" };
      }
      // Re-validate after the async reconnect: a concurrent caller may have already
      // mutated session status while this call was awaiting the stream open.
      // TypeScript narrows session.status to "active" at this point (line 1732 guard), but
      // async suspension means the actual value may have changed — re-read via a typed cast.
      // Mirror the guard at #sendMessageLocked: sealing/sealed/seal_deferred/seal_rejected → "session_sealed".
      const statusNow = (session as SessionRecord).status;
      if (statusNow === "sealing" || statusNow === "sealed" || statusNow === "seal_deferred" || statusNow === "seal_rejected") {
        return { ok: false, reason: "session_sealed" };
      }
      if (statusNow !== "active") return { ok: false, reason: "session_not_active" };
    }

    session.status = "sealing";
    this.#sealInitiatedSessions.add(sessionIdHex);
    // CRIT-1: persist sealing status
    void this.#persistence?.persistSession(sessionIdHex, session);

    const result = await this.#submitSealLeaf(sessionIdHex, session, "initiator");
    if (!result.ok) return result;

    // SESSION-005: if a threshold signer is configured, wait for the FROST seal ceremony.
    // The directory runs verification and FROST ceremony; if it doesn't reply within
    // sealFrostTimeoutMs, this is a bilateral seal (directory unreachable).
    // Without a threshold signer (M1 compatibility), return immediately —
    // the M1 single-key seal notification will arrive asynchronously.
    if (this.#thresholdSigner) {
      const sealReceived = new Promise<void>((resolve) => {
        this.#sealFrostResolvers.set(sessionIdHex, resolve);
      });

      const timeout = new Promise<void>((resolve) =>
        setTimeout(resolve, this.#sealFrostTimeoutMs)
      );

      await Promise.race([sealReceived, timeout]);

      // Clean up resolver
      this.#sealFrostResolvers.delete(sessionIdHex);

      // Check if session_sealed arrived (status would be 'sealed' by now)
      const sess = this.#sessions.get(sessionIdHex);
      if (sess && sess.status === "sealing") {
        // Timeout elapsed without session_sealed — bilateral fallback (DB-001)
        sess.status = "seal_deferred";
        sess.seal_type = "bilateral";
        // M-003: store the verified timestamp so #handleSessionFrostSealed can reconstruct
        // the exact TBS if the directory later completes the deferred FROST ceremony.
        const sealVerifiedEntry = this.#sealVerifiedData.get(sessionIdHex);
        if (sealVerifiedEntry) {
          sess.close_timestamp = sealVerifiedEntry.timestamp;
        }
        // CRIT-1: persist seal_deferred status
        void this.#persistence?.persistSession(sessionIdHex, sess);
      }
    }

    return { ok: true };
  }

  // PERSIST-015: send seal_unilateral to the directory after delivery_grace_seconds elapses.
  async initiateUnilateralSeal(
    sessionIdHex: string,
  ): Promise<
    | { ok: true; sealed_root: Uint8Array; sealed_at: number }
    | { ok: false; reason: "too_early"; remaining_seconds: number }
    | { ok: false; reason: string }
  > {
    const session = this.#sessions.get(sessionIdHex);
    if (!session) return { ok: false, reason: "session_not_found" };
    if (session.status !== "active" && session.status !== "sealing") {
      return { ok: false, reason: "session_not_active" };
    }

    if (!this.#persistentSignalingStream || this.#persistentSignalingStream.status !== "open") {
      this.#persistentSignalingStream = null;
      this.#persistentSignalingIter = null;
      const opened = await this.#openPersistentSignalingStream();
      if (!opened || !this.#persistentSignalingStream) {
        return { ok: false, reason: "directory_unreachable" };
      }
    }

    const localRoot = this.#computeLocalRoot(session) ?? session.genesis_prev_root;
    const reportedSeq = session.next_expected_seq - 1;

    const frame = CBOR_ENC.encode({
      type: "seal_unilateral",
      session_id: session.session_id,
      reported_root: localRoot,
      reported_seq: reportedSeq,
    }) as Uint8Array;

    this.#persistentSignalingStream.send(lp.encode.single(frame));

    const UNILATERAL_TIMEOUT_MS = 15_000;
    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
    const responseFrame = await Promise.race<Record<string, unknown>>([
      new Promise<Record<string, unknown>>((resolve) => {
        this.#pendingUnilateralSealResolve = resolve;
      }),
      new Promise<Record<string, unknown>>((resolve) => {
        timeoutHandle = setTimeout(() => {
          this.#pendingUnilateralSealResolve = null;
          resolve({ type: "seal_unilateral_error", reason: "timeout" });
        }, UNILATERAL_TIMEOUT_MS);
      }),
    ]);
    clearTimeout(timeoutHandle);

    if (responseFrame["type"] === "seal_unilateral_confirmed") {
      const sealedRootRaw = responseFrame["sealed_root"];
      const sealedRoot = sealedRootRaw instanceof Uint8Array ? sealedRootRaw
        : Buffer.isBuffer(sealedRootRaw) ? new Uint8Array(sealedRootRaw as Buffer)
        : new Uint8Array(32);
      const sealedAt = typeof responseFrame["sealed_at"] === "number" ? responseFrame["sealed_at"] : Date.now();
      return { ok: true, sealed_root: sealedRoot, sealed_at: sealedAt };
    }

    if (responseFrame["type"] === "seal_unilateral_too_early") {
      const remainingSeconds = typeof responseFrame["remaining_seconds"] === "number"
        ? responseFrame["remaining_seconds"] : 0;
      return { ok: false, reason: "too_early", remaining_seconds: remainingSeconds };
    }

    return { ok: false, reason: (responseFrame["reason"] as string | undefined) ?? "unknown" };
  }

  async #submitSealLeaf(
    sessionIdHex: string,
    session: SessionRecord,
    _role: "initiator" | "responder",
  ): Promise<{ ok: true } | { ok: false; reason: string }> {
    const relayStream = this.#relayStreams.get(sessionIdHex);
    if (!relayStream || relayStream.status !== "open") {
      return { ok: false, reason: "transport_unavailable" };
    }

    // Compute current local tree root (R_tail for initiator, root-after-initiator-SEAL for responder)
    const finalRoot = session.local_tree_leaves.length === 0
      ? session.genesis_prev_root
      : (() => {
          const inputs: LeafInput[] = session.local_tree_leaves.map(l => ({
            kind: l.kind,
            data: l.s2_cbor,
          }));
          return merkleRoot(buildMerkleTree(inputs));
        })();

    const close_timestamp = Date.now();
    const sealPayload = encodeSealPayload({
      session_id: session.session_id,
      final_root: finalRoot,
      close_timestamp,
      attestation: "PENDING",
    });

    // content_hash = SHA-256(0x02 || seal_payload) — ctrl leaf kind byte is 0x02
    const contentHash = new Uint8Array(
      createHash("sha256").update(new Uint8Array([0x02])).update(sealPayload).digest()
    );

    const myPubkeyHex = this.#myPubkeyHex!;
    const myPubkeyBytes = Buffer.from(myPubkeyHex, "hex");

    const tbs = CBOR_ENC.encode([
      1,
      contentHash,
      myPubkeyBytes,
      session.session_id,
      session.last_seen_seq,
      close_timestamp,
    ]) as Uint8Array;
    const signature = await this.#keyProvider.sign(tbs);

    const hashSubmitFrame = CBOR_ENC.encode({
      type: "hash_submit",
      session_id: session.session_id,
      leaf_kind: 0x02,
      structure1_cbor: tbs,
      sender_signature: signature,
    }) as Uint8Array;

    const contentHashHex = Buffer.from(contentHash).toString("hex");
    this.#ownPendingContent.get(sessionIdHex)?.set(contentHashHex, {
      content_bytes: sealPayload,
      arrived_at: Date.now(),
    });

    if (this.#pendingAckResolvers.has(sessionIdHex)) {
      return { ok: false, reason: "ack_resolver_conflict" };
    }
    let ackResolve!: (v: { ok: true; sequence_number: number } | { ok: false; reason: string }) => void;
    const ackPromise = new Promise<{ ok: true; sequence_number: number } | { ok: false; reason: string }>(
      (r) => { ackResolve = r; }
    );
    this.#pendingAckResolvers.set(sessionIdHex, ackResolve);

    try {
      relayStream.send(lp.encode.single(hashSubmitFrame));
    } catch {
      this.#pendingAckResolvers.delete(sessionIdHex);
      this.#ownPendingContent.get(sessionIdHex)?.delete(contentHashHex);
      return { ok: false, reason: "transport_unavailable" };
    }

    const ack = await ackPromise;
    if (!ack.ok) return { ok: false, reason: "relay_rejected" };

    const mySeq = ack.sequence_number;

    // Send SEAL payload as content_frame to counterparty so they can cross-check
    const sess2 = this.#sessions.get(sessionIdHex);
    if (sess2 && !sess2.desynchronized) {
      void this.#sendContentFrame(sess2, sealPayload, contentHash);
    }

    // Wait for own echo
    await this.#waitForOwnEcho(sessionIdHex, mySeq);

    const sess3 = this.#sessions.get(sessionIdHex);
    if (!sess3 || sess3.desynchronized) return { ok: false, reason: "session_desynchronized" };

    return { ok: true };
  }

  // ─── Directory signaling stream (SESSION-003) ────────────────────────────────

  #handleDirectorySessionSealed(
    sessionIdHex: string,
    frame: Record<string, unknown>,
    directoryPubkey: Uint8Array,
  ): void {
    const session = this.#sessions.get(sessionIdHex);
    if (!session) return;

    const signatureType = frame["signature_type"];

    // If this client has a threshold signer (M2 mode), enforce FROST-only.
    if (this.#thresholdSigner) {
      // SI-003: reject M1-era single-key seal notarizations in M2 mode
      if (signatureType === "single") {
        console.warn(`[cello-client] unsupported_signature_type: single on session ${sessionIdHex}`);
        return;
      }
      if (signatureType !== "frost") {
        // Unknown signature_type — ignore
        return;
      }
      this.#handleFrostSealed(sessionIdHex, frame, session);
    } else {
      // M1 compatibility mode: no threshold signer — verify directory_signature
      this.#handleSingleSealed(sessionIdHex, frame, directoryPubkey, session);
    }
  }

  /** No-threshold-signer path: handles both 'single' (Ed25519 dir sig) and 'frost' seal frames. */
  #handleSingleSealed(
    sessionIdHex: string,
    frame: Record<string, unknown>,
    directoryPubkey: Uint8Array,
    session: SessionRecord,
  ): void {
    const signatureType = frame["signature_type"];
    const sealedRootRaw = frame["sealed_root"];
    const sealedRoot = sealedRootRaw instanceof Uint8Array ? sealedRootRaw
      : Buffer.isBuffer(sealedRootRaw) ? new Uint8Array(sealedRootRaw as Buffer) : null;
    const ctRaw = frame["close_timestamp"];
    const closeTimestamp = typeof ctRaw === "number" ? ctRaw : typeof ctRaw === "bigint" ? Number(ctRaw) : null;
    const sidRaw = frame["session_id"];
    const sessionId = sidRaw instanceof Uint8Array ? sidRaw
      : Buffer.isBuffer(sidRaw) ? new Uint8Array(sidRaw as Buffer) : null;

    if (!sealedRoot || sealedRoot.length !== 32) return;
    if (closeTimestamp === null) return;
    if (!sessionId) return;

    if (signatureType === "frost") {
      // FROST seal received by an M1 client (no threshold signer).
      // Verify using the signer_pubkey embedded in the frame (initiator's primary_pubkey).
      const frostSigRaw = frame["frost_signature"];
      const frostSig = frostSigRaw instanceof Uint8Array ? frostSigRaw
        : Buffer.isBuffer(frostSigRaw) ? new Uint8Array(frostSigRaw as Buffer) : null;
      const signerPubkeyRaw = frame["signer_pubkey"];
      const signerPubkey = signerPubkeyRaw instanceof Uint8Array ? signerPubkeyRaw
        : Buffer.isBuffer(signerPubkeyRaw) ? new Uint8Array(signerPubkeyRaw as Buffer) : null;
      if (!frostSig || frostSig.length !== 64) return;
      if (!signerPubkey || signerPubkey.length !== 32) return;

      // Use sealVerifiedData if available (responder also gets seal_verified when M2 initiator),
      // else fall back to local_tree_leaves.length.
      const sealVerifiedEntry = this.#sealVerifiedData.get(sessionIdHex);
      const leafCount = sealVerifiedEntry?.leafCount ?? session.local_tree_leaves.length;
      const tbs = buildSealTbs(sessionId, sealedRoot, leafCount, closeTimestamp);

      if (!verifyFrostSignature(frostSig, tbs, "cello-frost-seal-v1", signerPubkey)) {
        console.warn(`[cello-client] frost_signature_invalid on session_sealed: ${sessionIdHex}`);
        return;
      }

      session.status = "sealed";
      session.sealed_root = sealedRoot;
      session.frost_signature = frostSig;
      session.signer_pubkey = signerPubkey;
      session.seal_type = "frost";
      session.close_timestamp = closeTimestamp;
      this.#sealVerifiedData.delete(sessionIdHex);
      // CRIT-1: persist sealed state
      void this.#persistence?.persistSession(sessionIdHex, session);
      // SESSION-007: enqueue lifecycle event for blocked cello_receive callers.
      this.#enqueueSessionSealedEvent(sessionIdHex, sealedRoot, closeTimestamp);
    } else {
      // M1 single-key: verify directory_signature against pinned directory pubkey
      const dirSigRaw = frame["directory_signature"];
      const dirSig = dirSigRaw instanceof Uint8Array ? dirSigRaw
        : Buffer.isBuffer(dirSigRaw) ? new Uint8Array(dirSigRaw as Buffer) : null;
      if (!dirSig || dirSig.length !== 64) return;

      // SI-005 (M1): verify directory signature against pinned directory pubkey
      const tbs = CBOR_ENC.encode([
        sessionId,
        sealedRoot,
        closeTimestamp > 0xffffffff ? BigInt(closeTimestamp) : closeTimestamp,
      ]) as Uint8Array;

      if (!verify(directoryPubkey, tbs, dirSig)) {
        console.warn(`[cello-client] directory_signature_invalid on session_sealed: ${sessionIdHex}`);
        return;
      }

      session.status = "sealed";
      session.sealed_root = sealedRoot;
      session.directory_signature = dirSig;
      session.close_timestamp = closeTimestamp;
      // CRIT-1: persist sealed state
      void this.#persistence?.persistSession(sessionIdHex, session);
      // SESSION-007: enqueue lifecycle event for blocked cello_receive callers.
      this.#enqueueSessionSealedEvent(sessionIdHex, sealedRoot, closeTimestamp);
    }

    // Resolve the seal-frost-timeout waiter
    this.#sealFrostResolvers.get(sessionIdHex)?.();
  }

  /** M2 FROST seal verification. */
  #handleFrostSealed(
    sessionIdHex: string,
    frame: Record<string, unknown>,
    session: SessionRecord,
  ): void {
    const sealedRootRaw = frame["sealed_root"];
    const sealedRoot = sealedRootRaw instanceof Uint8Array ? sealedRootRaw
      : Buffer.isBuffer(sealedRootRaw) ? new Uint8Array(sealedRootRaw as Buffer) : null;
    const frostSigRaw = frame["frost_signature"];
    const frostSig = frostSigRaw instanceof Uint8Array ? frostSigRaw
      : Buffer.isBuffer(frostSigRaw) ? new Uint8Array(frostSigRaw as Buffer) : null;
    const signerPubkeyRaw = frame["signer_pubkey"];
    const signerPubkey = signerPubkeyRaw instanceof Uint8Array ? signerPubkeyRaw
      : Buffer.isBuffer(signerPubkeyRaw) ? new Uint8Array(signerPubkeyRaw as Buffer) : null;
    const ctRaw = frame["close_timestamp"];
    const closeTimestamp = typeof ctRaw === "number" ? ctRaw : typeof ctRaw === "bigint" ? Number(ctRaw) : null;
    const sidRaw = frame["session_id"];
    const sessionId = sidRaw instanceof Uint8Array ? sidRaw
      : Buffer.isBuffer(sidRaw) ? new Uint8Array(sidRaw as Buffer) : null;
    const leafCountRaw = frame["leaf_count"];
    // Prefer stored sealVerifiedData so we use the same leafCount that was used during
    // the FROST ceremony, even if local_tree_leaves is incomplete due to a desync race.
    const sealVerifiedEntry = this.#sealVerifiedData.get(sessionIdHex);
    const leafCount = typeof leafCountRaw === "number" ? leafCountRaw
      : (sealVerifiedEntry?.leafCount ?? session.local_tree_leaves.length);
    const resolvedCloseTimestamp = closeTimestamp ?? sealVerifiedEntry?.timestamp ?? null;

    if (!sealedRoot || sealedRoot.length !== 32) return;
    if (!frostSig || frostSig.length !== 64) return;
    if (!signerPubkey || signerPubkey.length !== 32) return;
    if (resolvedCloseTimestamp === null) return;
    if (!sessionId) return;

    const tbs = buildSealTbs(sessionId, sealedRoot, leafCount, resolvedCloseTimestamp);

    // Determine verification key.
    // Use #myPrimaryPubkey only if this client ran the FROST ceremony (received seal_verified).
    // #frostCeremonyParticipant is set by #handleSealVerified before the ceremony runs —
    // a concurrent-close counterparty (in #sealInitiatedSessions but NOT #frostCeremonyParticipant)
    // must use signerPubkey from the frame (the actual initiator's key).
    const isFrostInitiator = this.#frostCeremonyParticipant.has(sessionIdHex);
    let verifyKey: Uint8Array;
    if (isFrostInitiator) {
      if (!this.#myPrimaryPubkey) {
        console.warn(`[cello-client] no primary_pubkey set on initiator for session ${sessionIdHex}`);
        return;
      }
      verifyKey = this.#myPrimaryPubkey;
    } else {
      verifyKey = signerPubkey;
    }

    // SI-001: verify FROST signature before transitioning to sealed.
    if (!this.#thresholdSigner!.verifySignature(frostSig, tbs, "cello-frost-seal-v1", verifyKey)) {
      console.warn(`[cello-client] seal_signature_invalid on session ${sessionIdHex}`);
      return;
    }

    session.status = "sealed";
    session.sealed_root = sealedRoot;
    session.frost_signature = frostSig;
    session.signer_pubkey = signerPubkey;
    session.seal_type = "frost";
    session.close_timestamp = resolvedCloseTimestamp;
    this.#sealVerifiedData.delete(sessionIdHex);
    // CRIT-1: persist sealed state
    void this.#persistence?.persistSession(sessionIdHex, session);
    // SESSION-007: enqueue lifecycle event for blocked cello_receive callers.
    this.#enqueueSessionSealedEvent(sessionIdHex, sealedRoot, resolvedCloseTimestamp);

    // Resolve the seal-frost-timeout waiter so initiateSessionSeal returns promptly
    this.#sealFrostResolvers.get(sessionIdHex)?.();
  }

  #handleDirectorySessionSealRejected(sessionIdHex: string, _frame: Record<string, unknown>): void {
    const session = this.#sessions.get(sessionIdHex);
    if (!session) return;
    session.status = "seal_rejected";
    void this.#persistence?.persistSession(sessionIdHex, session);
    // Also resolve the seal-frost-timeout waiter so initiateSessionSeal doesn't wait for the timeout
    this.#sealFrostResolvers.get(sessionIdHex)?.();
  }

  /**
   * PERSIST-014: Handle seal_rejected_tree_mismatch from the directory.
   * Determines if this client is the behind party and initiates gap-fill reconciliation.
   */
  #handleSealRejectedTreeMismatch(sessionIdHex: string, frame: Record<string, unknown>): void {
    const session = this.#sessions.get(sessionIdHex);
    if (!session) return;

    const partyASequence = typeof frame["party_a_sequence"] === "number" ? frame["party_a_sequence"] : 0;
    const partyBSequence = typeof frame["party_b_sequence"] === "number" ? frame["party_b_sequence"] : 0;

    // Determine this client's local sequence (highest seq in its Merkle tree).
    // next_expected_seq is 1-indexed: the next seq the relay will assign, so local highest = next - 1.
    const mySequence = session.next_expected_seq - 1;
    const aheadSequence = Math.max(partyASequence, partyBSequence);

    if (mySequence >= aheadSequence) {
      // We are NOT the behind party — wait for the behind party to reconcile and retry
      return;
    }

    // We are the behind party — initiate gap-fill reconciliation
    const gapSize = aheadSequence - mySequence;
    const correlationId = Buffer.from(session.session_id).toString("hex") + "-" + Date.now().toString(36);

    this.#logger.info("session.reconciliation.started", {
      sessionId: sessionIdHex,
      gapSize,
      fromSequence: mySequence,
      toSequence: aheadSequence,
      correlationId,
    });

    void this.#relayStreamManager.performGapFillReconciliation(sessionIdHex, mySequence, aheadSequence, correlationId);
  }


  /**
   * PERSIST-015: Handle seal_unilateral_confirmed from the directory.
   * The submitting party receives this when the unilateral seal succeeds.
   */
  #handleSealUnilateralConfirmed(sessionIdHex: string, frame: Record<string, unknown>): void {
    const session = this.#sessions.get(sessionIdHex);
    if (!session) return;

    const sealedRootRaw = frame["sealed_root"];
    const sealedRoot = sealedRootRaw instanceof Uint8Array ? sealedRootRaw
      : Buffer.isBuffer(sealedRootRaw) ? new Uint8Array(sealedRootRaw as Buffer) : null;

    session.status = "sealed";
    if (sealedRoot) session.sealed_root = sealedRoot;
    session.seal_type = "unilateral";
    session.close_timestamp = typeof frame["sealed_at"] === "number" ? frame["sealed_at"] : Date.now();
    // CRIT-1: persist sealed state
    void this.#persistence?.persistSession(sessionIdHex, session);

    const correlationId = Buffer.from(session.session_id).toString("hex");
    this.#logger.info("session.sealed", {
      sessionId: sessionIdHex,
      sealType: "UNILATERAL",
      rootHash: sealedRoot ? Buffer.from(sealedRoot).toString("hex") : "unknown",
      correlationId,
    });

    // SESSION-007: enqueue lifecycle event for blocked cello_receive callers.
    if (sealedRoot) {
      this.#enqueueSessionSealedEvent(sessionIdHex, sealedRoot, session.close_timestamp ?? Date.now());
    }

    // Resolve the FROST ceremony waiter only if a bilateral seal was in-flight for this session.
    // The unilateral and FROST paths are mutually exclusive once the session seals — resolving an
    // absent FROST waiter is harmless (map miss returns undefined), but resolving a present one
    // spuriously would confuse the bilateral seal flow. Guard on whether the session was actually
    // in sealing state via the FROST path before the unilateral confirmation arrived.
    if (this.#sealInitiatedSessions.has(sessionIdHex)) {
      this.#sealFrostResolvers.get(sessionIdHex)?.();
    }
  }

  /**
   * PERSIST-015: Handle seal_unilateral_notification from the directory.
   * The absent party receives this on reconnect — verifies sealed root against local state.
   */
  #handleSealUnilateralNotification(sessionIdHex: string, frame: Record<string, unknown>): void {
    let session = this.#sessions.get(sessionIdHex);
    if (!session) {
      // Absent party reconnecting after session was sealed without them — create a minimal
      // sealed session record so the notification is observable via listSessions().
      const sessionIdRaw = frame["session_id"];
      const sessionId = sessionIdRaw instanceof Uint8Array ? sessionIdRaw
        : Buffer.isBuffer(sessionIdRaw) ? new Uint8Array(sessionIdRaw as Buffer)
        : Buffer.from(sessionIdHex, "hex");
      // Build the stub as sealed from the start — no transient "active" state visible to readers.
      // Fields like counterparty_pubkey and directory_pubkey are zeroed because the absent party
      // does not have session state; #computeLocalRoot handles the empty-leaves case explicitly.
      const stub: SessionRecord = {
        session_id: sessionId,
        counterparty_pubkey: new Uint8Array(32),
        counterparty_peer_id: "",
        counterparty_multiaddrs: [],
        relay_endpoint: { peer_id: "", multiaddrs: [] },
        directory_endpoint: { peer_id: "", multiaddrs: [] },
        directory_pubkey: new Uint8Array(32),
        genesis_prev_root: new Uint8Array(32),
        last_seen_seq: 0,
        last_sent_seq: 0,
        status: "sealed",
        seal_type: "unilateral",
        local_tree_leaves: [],
        next_expected_seq: 1,
        desynchronized: false,
      };
      this.#sessions.set(sessionIdHex, stub);
      session = stub;
    }

    const sealedRootRaw = frame["sealed_root"];
    const sealedRoot = sealedRootRaw instanceof Uint8Array ? sealedRootRaw
      : Buffer.isBuffer(sealedRootRaw) ? new Uint8Array(sealedRootRaw as Buffer) : null;

    session.status = "sealed";
    if (sealedRoot) session.sealed_root = sealedRoot;
    session.seal_type = "unilateral";
    session.close_timestamp = typeof frame["sealed_at"] === "number" ? frame["sealed_at"] : Date.now();
    // CRIT-1: persist sealed state
    void this.#persistence?.persistSession(sessionIdHex, session);

    // SESSION-007: enqueue lifecycle event for blocked cello_receive callers.
    if (sealedRoot) {
      this.#enqueueSessionSealedEvent(sessionIdHex, sealedRoot, session.close_timestamp);
    }

    // AC-004: Verify sealed root against local Merkle state
    const localRoot = this.#computeLocalRoot(session);

    if (localRoot == null) {
      // Cannot verify — no local leaves received yet; log distinctly rather than as mismatch
      this.#logger.info("session.unilateral.no.local.state", {
        sessionId: sessionIdHex,
        correlationId: sessionIdHex,
      });
      return;
    }

    const match = sealedRoot != null && Buffer.from(localRoot).equals(Buffer.from(sealedRoot));

    if (match) {
      this.#logger.info("session.unilateral.verified", {
        sessionId: sessionIdHex,
        match: true,
        correlationId: sessionIdHex,
      });
    } else {
      this.#logger.warn("session.unilateral.mismatch", {
        sessionId: sessionIdHex,
        localRoot: Buffer.from(localRoot).toString("hex"),
        sealedRoot: sealedRoot ? Buffer.from(sealedRoot).toString("hex") : "null",
        correlationId: sessionIdHex,
      });
    }
  }

  /**
   * PERSIST-015: Compute the local Merkle root from the session's accepted leaves.
   */
  #computeLocalRoot(session: SessionRecord): Uint8Array | null {
    if (!session.local_tree_leaves || session.local_tree_leaves.length === 0) return null;
    const leafInputs: LeafInput[] = session.local_tree_leaves.map((l) => ({
      kind: l.kind,
      data: l.s2_cbor,
    }));
    const tree = buildMerkleTree(leafInputs);
    return merkleRoot(tree);
  }

  /**
   * SESSION-005: Handle seal_verified event from the directory.
   * The directory has verified the Merkle tree; the initiator must now coordinate
   * the FROST ceremony and return the combined signature.
   */
  async #handleSealVerified(sessionIdHex: string, frame: Record<string, unknown>): Promise<void> {
    const session = this.#sessions.get(sessionIdHex);
    if (!session) return;
    if (!this.#thresholdSigner) return; // no FROST signer — bilateral only

    const sealedRootRaw = frame["sealed_root"];
    const sealedRoot = sealedRootRaw instanceof Uint8Array ? sealedRootRaw
      : Buffer.isBuffer(sealedRootRaw) ? new Uint8Array(sealedRootRaw as Buffer) : null;
    const sidRaw = frame["session_id"];
    const sessionId = sidRaw instanceof Uint8Array ? sidRaw
      : Buffer.isBuffer(sidRaw) ? new Uint8Array(sidRaw as Buffer) : null;
    const leafCountRaw = frame["leaf_count"];
    const leafCount = typeof leafCountRaw === "number" ? leafCountRaw : null;
    const tsRaw = frame["timestamp"];
    const timestamp = typeof tsRaw === "number" ? tsRaw : typeof tsRaw === "bigint" ? Number(tsRaw) : null;

    if (!sealedRoot || !sessionId || leafCount === null || timestamp === null) return;

    // Store for #handleFrostSealed so it can use the authoritative leafCount/timestamp
    // even if local_tree_leaves is incomplete due to a desync race.
    this.#sealVerifiedData.set(sessionIdHex, { leafCount, timestamp });
    // Mark this client as the FROST ceremony participant so #handleFrostSealed uses
    // #myPrimaryPubkey for verification (anti-substitution guard).
    this.#frostCeremonyParticipant.add(sessionIdHex);

    const tbs = buildSealTbs(sessionId, sealedRoot, leafCount, timestamp);

    // Participate in the FROST seal ceremony as coordinator
    const ceremonyId = `seal:${sessionIdHex}`;
    let result;
    try {
      result = await this.#thresholdSigner.participateInCeremony(
        ceremonyId,
        tbs,
        "cello-frost-seal-v1",
      );
    } catch {
      // Ceremony failed — bilateral fallback; do not send seal_frost_signature
      return;
    }

    if (!result.ok) {
      // DB-002: ceremony failed (threshold not met) — bilateral fallback
      return;
    }

    // Send seal_frost_signature to directory.
    // Prefer the per-session directory stream; fall back to the persistent signaling stream
    // (which is used when receiveSessionAssignment detects a persistent stream is already open).
    const dirStream = this.#directoryStreams.get(sessionIdHex);
    const sendStream = (dirStream && dirStream.status === "open") ? dirStream : this.#persistentSignalingStream;
    if (!sendStream) return;

    const sealFrostSigFrame = CBOR_ENC.encode({
      type: "seal_frost_signature",
      session_id: sessionId,
      frost_signature: result.signature,
    }) as Uint8Array;

    try {
      sendStream.send(lp.encode.single(sealFrostSigFrame));
    } catch {
      // Stream closed — bilateral fallback
    }
  }

  /**
   * Handle ceremony_request from the directory.
   * The directory sends this when a session_request requires a FROST ceremony but
   * the directory is not the coordinator. The client runs participateInCeremony
   * and sends back a ceremony_result with the combined signature.
   */
  async #handleCeremonyRequest(
    stream: Stream,
    frame: Record<string, unknown>,
  ): Promise<void> {
    this.#logger.debug("frost.ceremony.debug", { message: `handleCeremonyRequest: thresholdSigner=${this.#thresholdSigner ? "SET" : "NULL"}` });
    if (!this.#thresholdSigner) {
      this.#logger.debug("frost.ceremony.debug", { message: `handleCeremonyRequest: ABORT thresholdSigner is null — sending null ceremony_result` });
      const ceremonyId = frame["ceremony_id"] as string | undefined;
      if (ceremonyId) {
        stream.send(lp.encode.single(CBOR_ENC.encode({ type: "ceremony_result", ceremony_id: ceremonyId, signature: null })));
      }
      return;
    }

    const ceremonyId = frame["ceremony_id"] as string | undefined;
    const tbsRaw = frame["tbs"];
    const tbs = tbsRaw instanceof Uint8Array ? tbsRaw
      : Buffer.isBuffer(tbsRaw) ? new Uint8Array(tbsRaw as Buffer) : null;
    const context = frame["context"] as string | undefined;

    this.#logger.debug("frost.ceremony.debug", { message: `handleCeremonyRequest: ceremonyId=${ceremonyId?.slice(0,16)} tbs=${tbs ? `Uint8Array(${tbs.length})` : "NULL"} context=${context}` });

    if (!ceremonyId || !tbs || !context) {
      this.#logger.debug("frost.ceremony.debug", { message: `handleCeremonyRequest: ABORT missing fields ceremonyId=${!!ceremonyId} tbs=${!!tbs} context=${!!context}` });
      return;
    }

    try {
      this.#logger.debug("frost.ceremony.debug", { message: `handleCeremonyRequest: calling participateInCeremony` });
      const result = await this.#thresholdSigner.participateInCeremony(
        ceremonyId,
        tbs,
        context as import("@cello-protocol/crypto/frost/types.js").FrostContext,
      );
      this.#logger.debug("frost.ceremony.debug", { message: `handleCeremonyRequest: participateInCeremony returned ok=${result.ok} reason=${!result.ok ? (result as { error: { reason: string } }).error?.reason : "N/A"}` });

      const sig = result.ok ? result.signature : null;
      stream.send(lp.encode.single(CBOR_ENC.encode({
        type: "ceremony_result",
        ceremony_id: ceremonyId,
        signature: sig ? new Uint8Array(sig) : null,
      })));
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.#logger.debug("frost.ceremony.debug", { message: `handleCeremonyRequest: CAUGHT ERROR: ${msg}` });
      stream.send(lp.encode.single(CBOR_ENC.encode({
        type: "ceremony_result",
        ceremony_id: ceremonyId,
        signature: null,
      })));
    }
  }

  /**
   * SESSION-005: Handle session_frost_sealed event — deferred FROST seal completed.
   * Sent by the directory when a previously deferred seal ceremony completes.
   * Updates the session from seal_deferred/bilateral to sealed/frost.
   */
  #handleSessionFrostSealed(sessionIdHex: string, frame: Record<string, unknown>): void {
    const session = this.#sessions.get(sessionIdHex);
    if (!session) return;

    const sealedRootRaw = frame["sealed_root"];
    const sealedRoot = sealedRootRaw instanceof Uint8Array ? sealedRootRaw
      : Buffer.isBuffer(sealedRootRaw) ? new Uint8Array(sealedRootRaw as Buffer) : null;
    const frostSigRaw = frame["frost_signature"];
    const frostSig = frostSigRaw instanceof Uint8Array ? frostSigRaw
      : Buffer.isBuffer(frostSigRaw) ? new Uint8Array(frostSigRaw as Buffer) : null;
    const signerPubkeyRaw = frame["signer_pubkey"];
    const signerPubkey = signerPubkeyRaw instanceof Uint8Array ? signerPubkeyRaw
      : Buffer.isBuffer(signerPubkeyRaw) ? new Uint8Array(signerPubkeyRaw as Buffer) : null;
    const sidRaw = frame["session_id"];
    const sessionId = sidRaw instanceof Uint8Array ? sidRaw
      : Buffer.isBuffer(sidRaw) ? new Uint8Array(sidRaw as Buffer) : null;

    if (!sealedRoot || frostSig === null || !signerPubkey || !sessionId) return;
    if (!frostSig || frostSig.length !== 64) return;
    if (!signerPubkey || signerPubkey.length !== 32) return;

    if (!this.#thresholdSigner) return;

    // Prefer stored sealVerifiedData leafCount (same as #handleFrostSealed) so verification
    // uses the count from the FROST ceremony even if local_tree_leaves is incomplete.
    const sealVerifiedEntry = this.#sealVerifiedData.get(sessionIdHex);
    const leafCount = sealVerifiedEntry?.leafCount ?? session.local_tree_leaves.length;
    // M-003: close_timestamp must be set (stored during bilateral fallback from seal_verified).
    // Without it we cannot reconstruct the exact TBS and verification would be unsound.
    const closeTimestamp = session.close_timestamp ?? sealVerifiedEntry?.timestamp;
    if (closeTimestamp === undefined) {
      console.warn(`[cello-client] session_frost_sealed: no close_timestamp for ${sessionIdHex}, cannot verify TBS`);
      return;
    }
    const tbs = buildSealTbs(sessionId, sealedRoot, leafCount, closeTimestamp);

    const isFrostInitiator = this.#frostCeremonyParticipant.has(sessionIdHex);
    let verifyKey: Uint8Array;
    if (isFrostInitiator) {
      if (!this.#myPrimaryPubkey) return;
      verifyKey = this.#myPrimaryPubkey;
    } else {
      verifyKey = signerPubkey;
    }

    if (!this.#thresholdSigner.verifySignature(frostSig, tbs, "cello-frost-seal-v1", verifyKey)) {
      console.warn(`[cello-client] session_frost_sealed: seal_signature_invalid on session ${sessionIdHex}`);
      return;
    }

    // AC-004: update session from bilateral to frost
    session.status = "sealed";
    session.sealed_root = sealedRoot;
    session.frost_signature = frostSig;
    session.signer_pubkey = signerPubkey;
    session.seal_type = "frost";
    // CRIT-1: persist sealed state
    void this.#persistence?.persistSession(sessionIdHex, session);
  }

  closeSession(sessionIdHex: string): void {
    this.#sessions.delete(sessionIdHex);
    const ackResolve = this.#pendingAckResolvers.get(sessionIdHex);
    if (ackResolve) {
      this.#pendingAckResolvers.delete(sessionIdHex);
      ackResolve({ ok: false, reason: "session_closed" });
    }
    this.#relayRecvSeq.delete(sessionIdHex);
    this.#readyQueue.delete(sessionIdHex);
    this.#pendingS2.delete(sessionIdHex);
    this.#pendingContent.delete(sessionIdHex);
    this.#ownPendingContent.delete(sessionIdHex);
    this.#tamperedContentClaims.delete(sessionIdHex);
    this.#ownEchoResolvers.delete(sessionIdHex);
    this.#sessionMessageQueues.delete(sessionIdHex);
    this.#outboundQueues.delete(sessionIdHex);
    this.#sealInitiatedSessions.delete(sessionIdHex);
    this.#frostCeremonyParticipant.delete(sessionIdHex);
    // Resolve seal-frost-timeout waiter so initiateSessionSeal doesn't hang
    this.#sealFrostResolvers.get(sessionIdHex)?.();
    this.#sealFrostResolvers.delete(sessionIdHex);
    this.#sealVerifiedData.delete(sessionIdHex);
    const stream = this.#relayStreams.get(sessionIdHex);
    if (stream) {
      this.#relayStreams.delete(sessionIdHex);
      stream.abort(new Error("session_closed"));
    }
    const dirStream = this.#directoryStreams.get(sessionIdHex);
    if (dirStream) {
      this.#directoryStreams.delete(sessionIdHex);
      dirStream.abort(new Error("session_closed"));
    }
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

  /**
   * Register this agent with the directory.
   *
   * REG-001 Phase P pseudocode:
   *   1. If already registered, return { error: 'already_registered' }
   *   2. Generate (or load) ML-DSA-44 keypair (NIST FIPS 204)
   *      - If #mlDsaKeyFile is set: FileMlDsaKeyProvider.load(path) — persists with 0o600
   *      - Otherwise: mlDsaKeygen() → InMemoryMlDsaKeyProvider
   *   3. Open (or reuse) persistent signaling stream (auth handled inside)
   *   4. Get myPubkeyHex (Ed25519 K_local)
   *   5. Send register_request { phone_stub, k_local_pubkey, ml_dsa_pubkey } on signaling stream
   *   5a. Await dkg_ready { epochId, participants, threshold } (routed by signaling reader)
   *   5b. Run real FROST DKG ceremony over /cello/frost/1.0.0 streams (RFC 9591)
   *       - Create NetworkDirectoryNode for each directory peer
   *       - runNetworkDkg(agentPubkey, { threshold, participants, directoryNodes })
   *       - Stores client share via storeDkgResult in frost-threshold-signer
   *   5c. Send dkg_complete { primary_pubkey } on signaling stream
   *   6. Await register_success or register_error (routed by #runPersistentSignalingReader)
   *      - register_error → return { error: reason }
   *      - register_success → build RegistrationState and cache it
   *   7. Return RegistrationState
   *
   * Crypto refs: NIST FIPS 204 (ML-DSA-44), RFC 9591 (FROST), FIPS 180-4 (SHA-256)
   */
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
    this.#onSessionAssignmentHandler = handler;
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

  /**
   * FEDERATION-003 AC-004: Look up a relay's registered public key from the directory.
   *
   * Opens a one-shot signaling stream, authenticates, sends relay_pubkey_request,
   * and returns the public_key_hex for the given relayId.
   *
   * DB-002: If the directory is unreachable, returns undefined. The caller is responsible
   * for retry logic (the hash submission stays in the pending queue).
   *
   * Pseudocode (Phase P):
   *   1. Require directoryEndpoint — return undefined if not configured.
   *   2. Dial directory and open signaling stream.
   *   3. Authenticate: read signaling_auth_challenge, sign SHA-256("CELLO-DIR-AUTH-v1" || nonce || pubkey),
   *      send signaling_auth_response. Read signaling_auth_ok.  RFC 8032, FIPS 180-4.
   *   4. Send relay_pubkey_request { type, relay_id }.
   *   5. Read relay_pubkey_response { type, public_key_hex } or relay_pubkey_error { type, reason }.
   *   6. On relay_pubkey_response: return public_key_hex.
   *   7. On relay_pubkey_error or any failure: return undefined.
   *
   * @param relayId - hex encoding of the relay's Ed25519 public key
   * @returns the relay's registered public_key_hex, or undefined if not found / unreachable
   */
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

  /**
   * Send a `session_request` over the persistent directory signaling stream and await
   * the `session_assignment` or error response.
   *
   * PSEUDOCODE (Phase P — ADAPTER-003):
   *
   * initiateSession(targetPubkeyHex, opts):
   *   1. If no #directoryEndpoint configured → return { ok: false, reason: 'directory_unreachable' }
   *   2. Ensure #myPubkeyHex is set (read from keyProvider if not yet set)
   *   3. Open persistent signaling stream if not already open (DB-001: single retry on failure)
   *      If stream still cannot be opened → return { ok: false, reason: 'directory_unreachable' }
   *   4. Encode session_request frame inline using CBOR (no @cello-protocol/directory import):
   *        CBOR({ type: "session_request", target_pubkey: Buffer.from(targetPubkeyHex, 'hex') })
   *      SI-001: only target_pubkey, no extra fields, no key material
   *   5. Create response Promise:
   *        Create resolve fn, store in #pendingSessionRequestResolve
   *   6. Send frame on #persistentSignalingStream
   *   7. Race: response Promise vs timeout (opts.timeoutMs ?? DEFAULT_INITIATE_TIMEOUT_MS)
   *   8. On timeout:
   *        Clear #pendingSessionRequestResolve
   *        Return { ok: false, reason: 'timeout' }
   *   9. On session_request_error frame:
   *        reason = frame['reason'] ('target_offline' | 'relay_unavailable')
   *        Return { ok: false, reason }
   *  10. On session_assignment frame:
   *        Decode assignment fields from frame['assignment']
   *        Call receiveSessionAssignment(assignment, myPubkey)
   *        If ok:true → return { ok: true, sessionId, genesisPrevRoot }
   *        If ok:false → return { ok: false, reason: 'directory_unreachable' }
   *
   * SI-002: K_local private key never appears in frame, response, or log output.
   *         keyProvider.getPublicKey() returns only the public key.
   */
  async initiateSession(
    targetPubkeyHex: string,
    opts?: {
      /** Directory peer ID to connect to (overrides configured directoryEndpoint). */
      directoryPeerId?: string;
      /** Directory multiaddr for initial dial (overrides configured directoryEndpoint). */
      directoryMultiaddr?: string;
      /** Timeout in ms. Default: 30_000. */
      timeoutMs?: number;
    },
  ): Promise<InitiateSessionResult> {
    const timeoutMs = opts?.timeoutMs ?? DEFAULT_INITIATE_TIMEOUT_MS;

    // SESSION-006: check local connections map before touching the signaling stream.
    // If we have a connection policy configured (M3 mode), require a connection.
    // If no connection policy (M2 mode), skip the gate.
    const connectionId = this.#connectionsByPeer.get(targetPubkeyHex);
    if (this.#connectionPolicy !== undefined && !connectionId) {
      return { ok: false, reason: "no_connection" } as InitiateSessionResult;
    }

    if (!this.#directoryEndpoint && !opts?.directoryPeerId) {
      return { ok: false, reason: "directory_unreachable" };
    }

    // Ensure myPubkeyHex is set (needed for receiveSessionAssignment)
    if (!this.#myPubkeyHex) {
      const pubkey = await this.#keyProvider.getPublicKey();
      this.#myPubkeyHex = Buffer.from(pubkey).toString("hex");
    }
    const myPubkey = Buffer.from(this.#myPubkeyHex, "hex");

    // Open persistent signaling stream if not already open (DB-001)
    if (!this.#persistentSignalingStream) {
      const opened = await this.#openPersistentSignalingStream(opts?.directoryPeerId, opts?.directoryMultiaddr);
      if (!opened) {
        const retried = await this.#openPersistentSignalingStream(opts?.directoryPeerId, opts?.directoryMultiaddr);
        if (!retried) {
          return { ok: false, reason: "directory_unreachable" };
        }
      }
    }

    // SESSION-006: session_request frame includes connection_id if we have one
    // Encoded inline with raw CBOR — no import from @cello-protocol/directory
    const targetPubkeyBytes = Buffer.from(targetPubkeyHex, "hex");
    const sessionRequestPayload: Record<string, unknown> = {
      type: "session_request",
      target_pubkey: new Uint8Array(targetPubkeyBytes),
    };
    if (connectionId) {
      sessionRequestPayload["connection_id"] = connectionId;
    }
    const sessionRequestFrame = CBOR_ENC.encode(sessionRequestPayload) as Uint8Array;

    // Set up Promise that resolves when the directory responds
    let responseResolve!: (frame: Record<string, unknown>) => void;
    const responsePromise = new Promise<Record<string, unknown>>((resolve) => {
      responseResolve = resolve;
    });
    this.#pendingSessionRequestResolve = responseResolve;

    try {
      this.#persistentSignalingStream!.send(lp.encode.single(sessionRequestFrame));
    } catch {
      this.#pendingSessionRequestResolve = null;
      return { ok: false, reason: "directory_unreachable" };
    }

    // Race: directory response vs timeout
    let responseFrame: Record<string, unknown> | null = null;
    let timedOut = false;
    await Promise.race([
      responsePromise.then((f) => { responseFrame = f; }),
      new Promise<void>((resolve) =>
        setTimeout(() => { timedOut = true; resolve(); }, timeoutMs)
      ),
    ]);

    if (timedOut) {
      this.#pendingSessionRequestResolve = null;
      return { ok: false, reason: "timeout" };
    }

    const frame = responseFrame!;

    if (frame["type"] === "session_request_error") {
      return mapSessionRequestErrorFrame(frame);
    }

    if (frame["type"] === "session_assignment") {
      const rawAssignment = frame["assignment"] as Record<string, unknown> | undefined;
      if (!rawAssignment) return { ok: false, reason: "directory_unreachable" };

      const assignment = parseSessionAssignment(rawAssignment);
      if (!assignment) return { ok: false, reason: "directory_unreachable" };

      const result = await this.receiveSessionAssignment(assignment, myPubkey);
      if (!result.ok) {
        return { ok: false, reason: "directory_unreachable" };
      }

      const sessionIdHex = Buffer.from(result.sessionId).toString("hex");
      const record = this.#sessions.get(sessionIdHex);
      if (!record) return { ok: false, reason: "directory_unreachable" };

      return {
        ok: true,
        sessionId: result.sessionId,
        genesisPrevRoot: record.genesis_prev_root,
      };
    }

    return { ok: false, reason: "directory_unreachable" };
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
        const session = this.#sessions.get(sessionIdHex);
        if (session) {
          const dirPubkey = injectedDirectoryPubkey ?? session.directory_pubkey;
          this.#handleDirectorySessionSealed(sessionIdHex, frame, dirPubkey);
        }
      }
    } else if (frame["type"] === "session_seal_rejected") {
      const sessionIdHex = injectedSessionIdHex ?? (() => {
        const raw = frame["session_id"];
        const sid = raw instanceof Uint8Array ? raw : Buffer.isBuffer(raw) ? new Uint8Array(raw as Buffer) : null;
        return sid ? Buffer.from(sid).toString("hex") : null;
      })();
      if (sessionIdHex) this.#handleDirectorySessionSealRejected(sessionIdHex, frame);
    } else if (frame["type"] === "seal_rejected_tree_mismatch") {
      const sessionIdHex = injectedSessionIdHex ?? (() => {
        const raw = frame["session_id"];
        const sid = raw instanceof Uint8Array ? raw : Buffer.isBuffer(raw) ? new Uint8Array(raw as Buffer) : null;
        return sid ? Buffer.from(sid).toString("hex") : null;
      })();
      if (sessionIdHex) this.#handleSealRejectedTreeMismatch(sessionIdHex, frame);
    } else if (frame["type"] === "seal_unilateral_confirmed") {
      const sessionIdHex = injectedSessionIdHex ?? (() => {
        const raw = frame["session_id"];
        const sid = raw instanceof Uint8Array ? raw : Buffer.isBuffer(raw) ? new Uint8Array(raw as Buffer) : null;
        return sid ? Buffer.from(sid).toString("hex") : null;
      })();
      if (sessionIdHex) this.#handleSealUnilateralConfirmed(sessionIdHex, frame);
      const unilateralResolve = this.#pendingUnilateralSealResolve;
      if (unilateralResolve) {
        this.#pendingUnilateralSealResolve = null;
        unilateralResolve(frame);
      }
    } else if (frame["type"] === "seal_unilateral_notification") {
      const sessionIdHex = injectedSessionIdHex ?? (() => {
        const raw = frame["session_id"];
        const sid = raw instanceof Uint8Array ? raw : Buffer.isBuffer(raw) ? new Uint8Array(raw as Buffer) : null;
        return sid ? Buffer.from(sid).toString("hex") : null;
      })();
      if (sessionIdHex) this.#handleSealUnilateralNotification(sessionIdHex, frame);
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
      const unilateralResolve = this.#pendingUnilateralSealResolve;
      if (unilateralResolve) {
        this.#pendingUnilateralSealResolve = null;
        unilateralResolve(frame);
      }
    } else if (frame["type"] === "seal_verified") {
      const sessionIdHex = injectedSessionIdHex ?? (() => {
        const raw = frame["session_id"];
        const sid = raw instanceof Uint8Array ? raw : Buffer.isBuffer(raw) ? new Uint8Array(raw as Buffer) : null;
        return sid ? Buffer.from(sid).toString("hex") : null;
      })();
      if (sessionIdHex) void this.#handleSealVerified(sessionIdHex, frame);
    } else if (frame["type"] === "session_frost_sealed") {
      const sessionIdHex = injectedSessionIdHex ?? (() => {
        const raw = frame["session_id"];
        const sid = raw instanceof Uint8Array ? raw : Buffer.isBuffer(raw) ? new Uint8Array(raw as Buffer) : null;
        return sid ? Buffer.from(sid).toString("hex") : null;
      })();
      if (sessionIdHex) this.#handleSessionFrostSealed(sessionIdHex, frame);
    } else if (frame["type"] === "ceremony_request") {
      void this.#handleCeremonyRequest(stream, frame);
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
    const pendingSealSessions = Array.from(this.#sessions.entries())
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

// ─── Stream iterator helpers ──────────────────────────────────────────────────

// ─── ADAPTER-003: parseSessionAssignment ─────────────────────────────────────

/**
 * Decode a raw CBOR-decoded object (from frame["assignment"]) into a typed SessionAssignment.
 * Returns null if any required field is missing or malformed.
 *
 * The object is already decoded by cbor-x from the outer frame — this function just
 * validates and casts the fields. No @cello-protocol/directory import needed.
 *
 * Wire shape (from encodeSessionAssignment in directory-frames.ts):
 *   {
 *     session_id: Uint8Array (16),
 *     participant_a: { pubkey: Uint8Array (32), peer_id: string, multiaddrs: string[] },
 *     participant_b: { pubkey: Uint8Array (32), peer_id: string, multiaddrs: string[] },
 *     relay_endpoint: { peer_id: string, multiaddrs: string[] },
 *     directory_endpoint: { peer_id: string, multiaddrs: string[] },
 *     session_timestamp: number,
 *     directory_pubkey: Uint8Array (32),
 *     directory_signature: Uint8Array (64),
 *   }
 */
function parseSessionAssignment(raw: Record<string, unknown>): SessionAssignment | null {
  const sessionId = toU8Safe(raw["session_id"]);
  if (!sessionId || sessionId.length !== 16) return null;

  const dirPubkey = toU8Safe(raw["directory_pubkey"]);
  if (!dirPubkey || dirPubkey.length !== 32) return null;

  const dirSig = toU8Safe(raw["directory_signature"]);
  if (!dirSig || dirSig.length !== 64) return null;

  const tsRaw = raw["session_timestamp"];
  const sessionTimestamp = typeof tsRaw === "number" ? tsRaw
    : typeof tsRaw === "bigint" ? Number(tsRaw) : null;
  if (sessionTimestamp === null) return null;

  const participantA = parseParticipantInfo(raw["participant_a"]);
  if (!participantA) return null;

  const participantB = parseParticipantInfo(raw["participant_b"]);
  if (!participantB) return null;

  const relayEndpoint = parseEndpointInfo(raw["relay_endpoint"]);
  if (!relayEndpoint) return null;

  const directoryEndpoint = parseEndpointInfo(raw["directory_endpoint"]);
  if (!directoryEndpoint) return null;

  const sigType = typeof raw["signature_type"] === "string" ? raw["signature_type"] : "single";

  if (sigType === "frost") {
    const signerPubkey = toU8Safe(raw["signer_pubkey"]);
    if (!signerPubkey || signerPubkey.length !== 32) return null;
    return {
      session_id: sessionId,
      participant_a: participantA,
      participant_b: participantB,
      relay_endpoint: relayEndpoint,
      directory_endpoint: directoryEndpoint,
      session_timestamp: sessionTimestamp,
      directory_pubkey: dirPubkey,
      directory_signature: dirSig,
      signature_type: "frost" as const,
      signer_pubkey: signerPubkey,
    };
  }

  return {
    session_id: sessionId,
    participant_a: participantA,
    participant_b: participantB,
    relay_endpoint: relayEndpoint,
    directory_endpoint: directoryEndpoint,
    session_timestamp: sessionTimestamp,
    directory_pubkey: dirPubkey,
    directory_signature: dirSig,
    signature_type: "single" as const,
  };
}

function parseParticipantInfo(raw: unknown): import("@cello-protocol/protocol-types").ParticipantInfo | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  const pubkey = toU8Safe(r["pubkey"]);
  if (!pubkey || pubkey.length !== 32) return null;
  const peerId = typeof r["peer_id"] === "string" ? r["peer_id"] : null;
  if (!peerId) return null;
  const multiaddrs = parseStringArray(r["multiaddrs"]);
  if (!multiaddrs) return null;
  return { pubkey, peer_id: peerId, multiaddrs };
}

function parseEndpointInfo(raw: unknown): import("@cello-protocol/protocol-types").RelayEndpointInfo | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  const peerId = typeof r["peer_id"] === "string" ? r["peer_id"] : null;
  if (!peerId) return null;
  const multiaddrs = parseStringArray(r["multiaddrs"]);
  if (!multiaddrs) return null;
  return { peer_id: peerId, multiaddrs };
}

function parseStringArray(v: unknown): string[] | null {
  if (!Array.isArray(v)) return null;
  if (!v.every((x) => typeof x === "string")) return null;
  return v as string[];
}

// ─── Session request error mapping ───────────────────────────────────────────

/**
 * Map a raw decoded session_request_error frame to an InitiateSessionResult.
 * Exported for direct unit testing (AC-005, AC-006).
 * The frame must have type === "session_request_error".
 */
export function mapSessionRequestErrorFrame(
  frame: Record<string, unknown>,
): import("./types.js").InitiateSessionResult {
  const reason = frame["reason"];
  if (reason === "target_offline") return { ok: false, reason: "target_offline" };
  if (reason === "relay_unavailable") return { ok: false, reason: "relay_unavailable" };
  if (reason === "frost_signer_not_configured") return { ok: false, reason: "frost_signer_not_configured" };
  if (reason === "directory_below_threshold") return { ok: false, reason: "directory_below_threshold" };
  if (reason === "ceremony_timeout") return { ok: false, reason: "ceremony_timeout" };
  if (reason === "ceremony_exhausted") return { ok: false, reason: "ceremony_exhausted" };
  if (reason === "ceremony_conflict") return { ok: false, reason: "ceremony_conflict" };
  if (reason === "no_connection") return { ok: false, reason: "no_connection" };
  if (reason === "connection_id_required") return { ok: false, reason: "no_connection" };
  return { ok: false, reason: "directory_unreachable" };
}

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
