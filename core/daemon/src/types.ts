/**
 * CELLO Daemon IPC Types
 *
 * IPC framing: JSON-newline-delimited over Unix domain socket.
 * Requests: {id, method, params}
 * Responses: {id, result} or {id, error: {code, message, guidance}}
 */

import type {
  IManifestProvider,
  IManifestVersionStore,
  IManifestPollScheduler,
  IDirectoryChallengeVerifier,
  ConnectResult,
  IAutoNatService,
} from "@cello-protocol/transport";
import type { TransportDialer, SessionNegotiator } from "./transport-selector.js";

// Re-export manifest interfaces for consumers of the daemon package
export type {
  IManifestProvider,
  IManifestVersionStore,
  IManifestPollScheduler,
  IDirectoryChallengeVerifier,
};

// Type-only import (erased at runtime — no circular dependency at load time).
import type { DirectoryEndpoint } from "./signaling-connect.js";

// --- Logger interface (injected, never imported directly) ---

export interface Logger {
  debug(event: string, context: Record<string, unknown>): void;
  info(event: string, context: Record<string, unknown>): void;
  warn(event: string, context: Record<string, unknown>): void;
  error(event: string, context: Record<string, unknown>): void;
}

// --- Lock file ---

export interface LockFileContent {
  pid: number;
  socketPath: string;
  version: string;
}

// --- IPC protocol ---

export interface IpcRequest {
  id: string;
  method: string;
  params?: Record<string, unknown>;
}

export interface IpcResponseOk {
  id: string;
  result: unknown;
}

export interface IpcResponseError {
  id: string;
  error: {
    code: string;
    message: string;
    guidance: string;
  };
}

export type IpcResponse = IpcResponseOk | IpcResponseError;

// Notifications are server-initiated frames that don't correlate to a request.
// They use a distinct shape so clients never confuse them with responses.
export interface IpcNotification {
  notification: string;
  data?: Record<string, unknown>;
}

export type IpcFrame = IpcResponse | IpcNotification;

// --- Session node sentinel ---

/**
 * Sentinel agentName used for the standing receiver node before any agent
 * transitions to Online. The IPC socket opens after initialize() completes,
 * so no agent can call cello_start_agent before the standing receiver exists.
 */
export const STANDING_RECEIVER_AGENT_NAME = "__standing_receiver__" as const;

// --- Agent state ---

export type AgentState = "registered" | "online" | "current" | "load_failed";

export interface AgentInfo {
  name: string;
  state: AgentState;
  pubkey?: string;
  error?: string;
  /**
   * M8B F14: whether THIS agent currently has an armed standing receiver. Populated on the
   * cello_status surface (getStatus) so a deaf agent — online but unable to accept inbound
   * sessions — is visible per-agent, not hidden behind the daemon-level ANY-agent aggregate.
   */
  standing_receiver_ready?: boolean;
}

// --- Connection state ---

export type ConnectionStatus = "verified" | "stale" | "gone" | "unverified";

export interface ConnectionInfo {
  counterpartyPubkey: string;
  status: ConnectionStatus;
}

// --- Status response ---

export type DirectorySignalingState = "connected" | "reconnecting" | "lost";

export interface DaemonStatusResponse {
  daemon: "running";
  directory_signaling: DirectorySignalingState;
  agents: AgentInfo[];
  connections: ConnectionInfo[];
  /**
   * True when the standing receiver node is listening and ready to accept the
   * next inbound session. Set to true by SessionNodeManager.initialize() during
   * daemon startup (before the IPC socket opens). DAEMON-002 AC-002.
   */
  standing_receiver_ready: boolean;
  /**
   * Total count of retry_queue entries across all sessions.
   * Always present as integer >= 0. DAEMON-003 AC-009.
   */
  retryQueueDepth: number;
  /**
   * M7-SESSION-001 AC-007: interrupted sessions from SQLite.
   * Always present (empty array if none). Never undefined or omitted.
   */
  interrupted_sessions: InterruptedSessionInfo[];
  /**
   * M8B F16: ACTIVE sessions with their direct-path counterparty liveness, so a
   * counterparty-gone session is visible to the operator instead of looking identical
   * to a quiet-but-healthy one. Always present (empty array if none).
   */
  active_sessions: ActiveSessionInfo[];
}

/** M8B F16: one active session's status row (see DaemonStatusResponse.active_sessions). */
export interface ActiveSessionInfo {
  sessionId: string;
  agentName: string;
  counterpartyPubkey: string;
  /** Direct-path counterparty liveness; 'unknown' before any session-node observation. */
  liveness: "alive" | "gone" | "unknown";
}

// --- Daemon configuration ---

export interface DaemonConfig {
  celloDir: string;
  socketPath: string;
  lockFilePath: string;
  maxConnections: number;
  version: string;
  logger: Logger;
  /**
   * M7-MANIFEST-002: manifest loading and verification.
   * When provided, startDaemon() calls manifestProvider.loadAndVerify() at startup.
   * When absent, manifest loading is skipped (backward compat for DAEMON-001 tests).
   *
   * Production: requires manifestRootKeys (non-empty array) and manifestThreshold (>= 1).
   * The bundled consortium-manifest.json is NOT shipped in the npm package — operators
   * must supply their own manifest path via FileManifestProvider(path).
   */
  manifestProvider?: IManifestProvider;
  /**
   * M7-MANIFEST-002: officer root keys for manifest signature verification.
   * Required when manifestProvider is provided.
   */
  manifestRootKeys?: readonly string[];
  /**
   * M7-MANIFEST-002: officer threshold for manifest signature verification.
   * Required when manifestProvider is provided.
   */
  manifestThreshold?: number;
  /**
   * M7-MANIFEST-002: version store for monotonicity enforcement.
   * When absent, monotonicity check is skipped.
   */
  manifestVersionStore?: IManifestVersionStore;
  /**
   * M7-MANIFEST-002: poll scheduler for background manifest refresh.
   * When absent, polling is disabled.
   */
  manifestPollScheduler?: IManifestPollScheduler;
  /**
   * CELLO-M7-CONN-001 (DOD-CONN-3): base URL for the daemon-level HTTP manifest poll
   * (`${directoryHttpUrl}/manifest`). The poll moved off the keystone signaling stream
   * to unauthenticated HTTP and runs even with zero agents. Defaults to
   * resolveDirectoryUrl(process.env). Tests inject an in-process server URL.
   */
  directoryHttpUrl?: string;
  /**
   * M7-MANIFEST-002: challenge verifier for directory step-5 identity proof.
   * When absent, directory challenge verification is skipped.
   */
  challengeVerifier?: IDirectoryChallengeVerifier;
  /**
   * M7-SIGNAL-001: injectable connect function for directory signaling stream.
   * When absent, a stub that always rejects (directory_signaling_not_configured) is used.
   * Production: performs the full 7-step directory handshake.
   *
   * Tests inject a fake signalingConnect directly. Production leaves this undefined
   * and supplies directoryEndpointResolver instead (see below), so startDaemon can
   * build the real connect wired to its own loaded-agent identity.
   */
  signalingConnect?: () => Promise<ConnectResult>;
  /**
   * M7 Keystone (Part 1): resolves the directory endpoint to dial (GET /bootstrap).
   * When signalingConnect is absent and this is present, startDaemon builds the
   * production signalingConnect from this resolver + the daemon's primary agent
   * identity. Ignored when signalingConnect is provided directly.
   */
  directoryEndpointResolver?: () => Promise<DirectoryEndpoint | null>;
  /**
   * CELLO-M7-DAEMON-004: injectable session-node factory for the composition root.
   * When absent, the production factory (real libp2p via createNode) is used.
   * Tests inject a controllable factory to exercise the send/receive/tree path
   * without the real transport stack — the same adapter-injection pattern
   * DAEMON-002 established for ISessionNodeFactory.
   */
  sessionNodeFactory?: import("./session-node-manager.js").ISessionNodeFactory;
  /**
   * CELLO-M7-MSG-001 (AC-004/AC-005): park target for the startup flush of un-acked
   * content. On startup — BEFORE the IPC socket opens — the daemon drains retry_queue
   * entries still awaiting a `persisted` delivery ACK and re-parks each to the relay
   * store-and-forward queue via this function (the crash backstop, D-d). The function
   * performs the encrypted relay deposit and is the natural emitter of
   * content.park.deposited (it holds the recipient context).
   *
   * Re-home (Option A): this is supplied by the daemon's OWN send path — the daemon
   * owns the session core, so it constructs the relay-deposit function natively (NOT a
   * hosted CelloClient / RelayStreamManager). When absent (a daemon started without the
   * content send path, or unit tests), the startup flush is a documented no-op
   * (content.park.flush.deferred at WARN) and the durable awaiting entries remain queued
   * for the next startup that has a park target.
   */
  contentParkFn?: import("./retry-queue.js").ParkFn;
  /**
   * CELLO-M7-MSG-001 (AC-001/AC-003): the TTF (time-to-flush) window, in ms, the
   * sender waits for a `persisted` delivery ACK before handing un-acked content to the
   * park backstop. Default 20_000 (Part-4 proposed 10–30s band). Tests inject a small
   * value to drive TTF expiry deterministically.
   */
  contentTtfMs?: number;
  /**
   * CELLO-M7-TRANSPORT-001: low-level dialer backing the transport selector in
   * production environments (dev/staging/production). Wraps a CelloNode (direct +
   * relay circuit dial) and the daemon relay registry. Required for production
   * CELLO_ENV; for 'local'/'test' the composition root uses an in-process stub.
   */
  transportDialer?: TransportDialer;
  /**
   * CELLO-M7-TRANSPORT-001: AutoNAT service adapter backing dialability detection
   * in production environments. Wraps the standing-receiver node's libp2p AutoNAT
   * observable. For 'local'/'test' the composition root uses a stub (dialable=false).
   */
  autoNatService?: IAutoNatService;
  /**
   * CELLO-M7-TRANSPORT-001: directory session negotiation adapter (WIRE-001/
   * SIGNAL-001). cello_initiate_session calls negotiate() to obtain the
   * FROST-signed SessionAssignment, then drives the transport selector to dial the
   * counterparty (AC-005/AC-006/AC-008/AC-010c). When absent, cello_initiate_session
   * reports directory_signaling_not_configured — it does NOT crash, proving the
   * transport adapters are wired.
   */
  sessionNegotiator?: SessionNegotiator;
  /**
   * CELLO-M7-TRANSPORT-001: returns this daemon's relay circuit address (from the
   * relay registry populated at directory connection) for the SessionAssignment
   * advertised address when the standing receiver is NOT dialable (AC-004). When
   * absent, an empty advertised relay address is used (the negotiator supplies the
   * real one in production).
   */
  getRelayCircuitAddress?: () => string;
}

// --- Session node types ---

/**
 * Maximum number of concurrent session nodes per daemon.
 * Outline.md §Resource Caps, DAEMON-002 AC-006.
 */
export const MAX_SESSION_NODES = 32;

/**
 * Status of a session persisted in SQLite.
 *
 * - active: live session with a transport node.
 * - interrupted: relay/daemon detected the session was cut short; eligible for
 *   the operator-initiated seal-interrupted bilateral flow.
 * - seal_interrupted_pending: both parties have produced and exchanged signed
 *   SEAL-INTERRUPTED leaves (a verified bilateral commitment), but the FROST
 *   threshold notarization has NOT been performed. This is a non-terminal state
 *   — it is explicitly NOT 'sealed'. See daemon.ts handleSealInterruptedFlow and
 *   the H-1 audit note for what blocks the threshold seal.
 * - sealed: a real FROST threshold notarization completed. Only the normal
 *   (non-interrupted) close path produces this today.
 */
export type SessionStatus =
  | "active"
  | "sealed"
  | "interrupted"
  | "seal_interrupted_pending";

export interface SessionRecord {
  session_id: string;
  agent_name: string;
  counterparty_pubkey: string;
  status: SessionStatus;
  created_at: number;
  updated_at: number;
  /** M7-SESSION-001: leaf count at interruption. 0 if not yet set. */
  message_count: number;
  /** M7-SESSION-001: ISO 8601 timestamp of interruption. Null if not yet set. */
  interrupted_at: string | null;
  /**
   * M7 legibility-TBS-binding: the counterparty's FROST primary (group) pubkey hex, from the
   * SessionAssignment's signer_pubkey. The responder verifies the bilateral seal signature against
   * it. Null when this party initiated (it verifies against its own primary).
   */
  counterparty_primary_pubkey?: string | null;
}

/** M7-SESSION-001: An interrupted session entry in the cello status response. */
export interface InterruptedSessionInfo {
  sessionId: string;
  agentName: string;
  counterpartyPubkey: string;
  messageCount: number;
  interruptedAt: string;
}

/**
 * cello_list_sessions: one session in the discovery list for the current agent.
 * Covers every status (active, sealed, interrupted, seal_interrupted_pending) so
 * the by-id reads (cello_get_transcript / cello_get_sealed_receipt) have a source
 * for their session ids. Timestamps are ISO 8601; interruptedAt is null unless the
 * session is/was interrupted.
 */
export interface SessionListEntry {
  sessionId: string;
  agentName: string;
  counterpartyPubkey: string;
  status: SessionStatus;
  /** Operator-facing bucket derived from status + messageCount: open | closed | failed. */
  category: "open" | "closed" | "failed";
  messageCount: number;
  createdAt: string;
  updatedAt: string;
  interruptedAt: string | null;
}

/**
 * Result of a session listing (cello_list_sessions / the daemon-wide `list_sessions`). `sessions`
 * is already filtered + capped at `limit`; `totalMatched` is how many matched the filter before the
 * cap, so the caller can tell the operator "showing 50 of 312".
 */
export interface SessionListResponse {
  ok: true;
  filter: "open" | "closed" | "failed" | "all";
  limit: number;
  totalMatched: number;
  sessions: SessionListEntry[];
}

// --- Error codes ---

export const ErrorCodes = {
  DAEMON_LOCK_STALE_REMOVED: "daemon_lock_stale_removed",
  DAEMON_SOCKET_BIND_FAILED: "daemon_socket_bind_failed",
  AGENT_LOAD_FAILED: "agent_load_failed",
  IPC_CONNECTION_LIMIT: "ipc_connection_limit",
  CONNECTION_VALIDATION_TIMEOUT: "connection_validation_timeout",
  DIRECTORY_UNREACHABLE_AT_LOGIN: "directory_unreachable_at_login",
  MAX_SESSIONS_REACHED: "max_sessions_reached",
  SESSION_NODE_CREATION_FAILED: "session_node_creation_failed",
  STANDING_RECEIVER_UNAVAILABLE: "standing_receiver_unavailable",
} as const;
