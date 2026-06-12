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
} from "@cello-protocol/transport";

// Re-export manifest interfaces for consumers of the daemon package
export type {
  IManifestProvider,
  IManifestVersionStore,
  IManifestPollScheduler,
  IDirectoryChallengeVerifier,
};

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
   * M7-MANIFEST-002: challenge verifier for directory step-5 identity proof.
   * When absent, directory challenge verification is skipped.
   */
  challengeVerifier?: IDirectoryChallengeVerifier;
}

// --- Session node types ---

/**
 * Maximum number of concurrent session nodes per daemon.
 * Outline.md §Resource Caps, DAEMON-002 AC-006.
 */
export const MAX_SESSION_NODES = 32;

/** Status of a session persisted in SQLite. */
export type SessionStatus = "active" | "sealed" | "interrupted";

export interface SessionRecord {
  session_id: string;
  agent_name: string;
  counterparty_pubkey: string;
  status: SessionStatus;
  created_at: number;
  updated_at: number;
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
