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
import type { SecurityGatewayClient } from "@cello-protocol/gateway";

// Re-export for daemon consumers (the composition root supplies the impl).
export type { SecurityGatewayClient };

// Re-export manifest interfaces for consumers of the daemon package
export type {
  IManifestProvider,
  IManifestVersionStore,
  IManifestPollScheduler,
  IDirectoryChallengeVerifier,
};

// Type-only import (erased at runtime — no circular dependency at load time).
import type { DirectoryEndpoint } from "./signaling-connect.js";
import type { TelegramBotClient } from "./telegram-bot-client.js";

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
   * Whether THIS agent currently has an armed standing receiver. Populated on the
   * cello_status surface (getStatus) so a deaf agent — online but unable to accept inbound
   * sessions — is visible per-agent, not hidden behind the daemon-level ANY-agent aggregate.
   */
  standing_receiver_ready?: boolean;
  /**
   * Whether THIS agent is the current (selected) agent for the requesting connection. Kept SEPARATE
   * from `state` — `state` must not overload the value "current", or two equally healthy agents read
   * as different readiness levels. A selected agent reads `state: "online"` + `selected: true`.
   */
  selected?: boolean;
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
  // No `connections` field: an always-empty placeholder conveys nothing and reads as a mock. The
  // ConnectionInfo type stays exported as the shape connected-client visibility will populate;
  // per-connection state lives in perConnectionState.
  /**
   * True when the standing receiver node is listening and ready to accept the
   * next inbound session. Set to true by SessionNodeManager.initialize() during
   * daemon startup, before the IPC socket opens.
   */
  standing_receiver_ready: boolean;
  /**
   * Total count of retry_queue entries across all sessions.
   * Always present as integer >= 0.
   */
  retryQueueDepth: number;
  /**
   * Interrupted sessions from SQLite.
   * Always present (empty array if none). Never undefined or omitted.
   */
  interrupted_sessions: InterruptedSessionInfo[];
  /**
   * ACTIVE sessions with their direct-path counterparty liveness, so a
   * counterparty-gone session is visible to the operator instead of looking identical
   * to a quiet-but-healthy one. Always present (empty array if none).
   */
  active_sessions: ActiveSessionInfo[];
}

/** One active session's status row (see DaemonStatusResponse.active_sessions). */
export interface ActiveSessionInfo {
  sessionId: string;
  agentName: string;
  counterpartyPubkey: string;
  /** Direct-path counterparty liveness; 'unknown' before any session-node observation. */
  liveness: "alive" | "gone" | "unknown";
  /** DOD-SESSION-NAME-1: this agent's own label for the session; null when unnamed. */
  sessionName: string | null;
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
   * Manifest loading and verification.
   * When provided, startDaemon() calls manifestProvider.loadAndVerify() at startup.
   * When absent, manifest loading is skipped.
   *
   * Production: requires manifestRootKeys (non-empty array) and manifestThreshold (>= 1).
   * The bundled consortium-manifest.json is NOT shipped in the npm package — operators
   * must supply their own manifest path via FileManifestProvider(path).
   */
  manifestProvider?: IManifestProvider;
  /**
   * Officer root keys for manifest signature verification.
   * Required when manifestProvider is provided.
   */
  manifestRootKeys?: readonly string[];
  /**
   * Officer threshold for manifest signature verification.
   * Required when manifestProvider is provided.
   */
  manifestThreshold?: number;
  /**
   * Version store for monotonicity enforcement.
   * When absent, monotonicity check is skipped.
   */
  manifestVersionStore?: IManifestVersionStore;
  /**
   * Poll scheduler for background manifest refresh.
   * When absent, polling is disabled.
   */
  manifestPollScheduler?: IManifestPollScheduler;
  /**
   * Base URL for the daemon-level HTTP manifest poll (`${directoryHttpUrl}/manifest`). The poll runs
   * over unauthenticated HTTP, NOT the keystone signaling stream, so it keeps running with zero
   * agents. Defaults to resolveDirectoryUrl(process.env). Tests inject an in-process server URL.
   */
  directoryHttpUrl?: string;
  /**
   * Challenge verifier for directory step-5 identity proof.
   * When absent, directory challenge verification is skipped.
   */
  challengeVerifier?: IDirectoryChallengeVerifier;
  /**
   * Injectable connect function for the directory signaling stream.
   * When absent, a stub that always rejects (directory_signaling_not_configured) is used.
   * Production: performs the full 7-step directory handshake.
   *
   * Tests inject a fake signalingConnect directly. Production leaves this undefined
   * and supplies directoryEndpointResolver instead (see below), so startDaemon can
   * build the real connect wired to its own loaded-agent identity.
   */
  signalingConnect?: () => Promise<ConnectResult>;
  /**
   * Resolves the directory endpoint to dial (GET /bootstrap).
   * When signalingConnect is absent and this is present, startDaemon builds the
   * production signalingConnect from this resolver + the daemon's primary agent
   * identity. Ignored when signalingConnect is provided directly.
   */
  directoryEndpointResolver?: () => Promise<DirectoryEndpoint | null>;
  /**
   * Injectable session-node factory for the composition root.
   * When absent, the production factory (real libp2p via createNode) is used.
   * Tests inject a controllable factory to exercise the send/receive/tree path
   * without the real transport stack.
   */
  sessionNodeFactory?: import("./session-node-manager.js").ISessionNodeFactory;
  /**
   * Park target for the startup flush of un-acked content. On startup — BEFORE the IPC
   * socket opens — the daemon drains retry_queue entries still awaiting a `persisted`
   * delivery ACK and re-parks each to the relay store-and-forward queue via this function
   * (the crash backstop). The function performs the encrypted relay deposit and is the
   * natural emitter of content.park.deposited (it holds the recipient context).
   *
   * It is supplied by the daemon's OWN send path — the daemon owns the session core, so it
   * constructs the relay-deposit function natively (never a hosted CelloClient /
   * RelayStreamManager). When absent (a daemon started without the content send path, or
   * unit tests), the startup flush is a no-op (content.park.flush.deferred at WARN) and the
   * durable awaiting entries remain queued for the next startup that has a park target.
   */
  contentParkFn?: import("./retry-queue.js").ParkFn;
  /**
   * The TTF (time-to-flush) window, in ms, the sender waits for a `persisted` delivery ACK
   * before handing un-acked content to the park backstop. Default 20_000. Tests inject a
   * small value to drive TTF expiry deterministically.
   */
  contentTtfMs?: number;
  /**
   * Low-level dialer backing the transport selector in
   * production environments (dev/staging/production). Wraps a CelloNode (direct +
   * relay circuit dial) and the daemon relay registry. Required for production
   * CELLO_ENV; for 'local'/'test' the composition root uses an in-process stub.
   */
  transportDialer?: TransportDialer;
  /**
   * AutoNAT service adapter backing dialability detection
   * in production environments. Wraps the standing-receiver node's libp2p AutoNAT
   * observable. For 'local'/'test' the composition root uses a stub (dialable=false).
   */
  autoNatService?: IAutoNatService;
  /**
   * Directory session negotiation adapter. cello_initiate_session calls negotiate() to
   * obtain the FROST-signed SessionAssignment, then drives the transport selector to dial
   * the counterparty. When absent, cello_initiate_session reports
   * directory_signaling_not_configured — it does NOT crash.
   */
  sessionNegotiator?: SessionNegotiator;
  /**
   * Returns this daemon's relay circuit address (from the relay registry populated at
   * directory connection) for the SessionAssignment advertised address when the standing
   * receiver is NOT dialable. When absent, an empty advertised relay address is used (the
   * negotiator supplies the real one in production).
   */
  getRelayCircuitAddress?: () => string;
  /**
   * Injectable Telegram Bot API client (test override — production uses HttpTelegramBotClient,
   * constructed from telegram_settings once configured via setTelegramSettings). Absent = the
   * Telegram doorbell is inert (no poller starts) until settings exist.
   */
  telegramBotClient?: TelegramBotClient;
  /**
   * The security gateway client. Every outbound message is screened in cello_send before
   * sessionNodeManager.sendContent; every inbound message is screened in the inbound funnel
   * before it enters the receive buffer. The daemon holds ONLY this narrow interface — all
   * detection lives in the separate gateway program.
   *
   * REQUIRED (INV-9, M9C-D10). It was optional, defaulting to `PassthroughGatewayClient`, and
   * because no production caller ever set it, every shipped daemon screened NOTHING while
   * announcing that the gateway was connected. An optional field with a permissive default made
   * the invariant hold by CONVENTION while the comment claimed it held by construction. Now the
   * compiler asks. A caller that genuinely wants no screening — a test — passes
   * `new PassthroughGatewayClient()` and thereby says so out loud.
   */
  securityGateway: SecurityGatewayClient;
  /**
   * DOD-REGISTRY-1: Ed25519 pubkey (hex) for verifying the type registry inner signature.
   * Build-time pinned. When absent, the registry poll is disabled (all types unclassified).
   */
  registryPubkey?: string;
  /**
   * DOD-REGISTRY-1: poll scheduler for background registry refresh.
   * When absent (or registryPubkey absent), registry polling is disabled.
   */
  registryPollScheduler?: import("@cello-protocol/transport").IManifestPollScheduler;
}

// --- Session node types ---

/**
 * Maximum number of concurrent session nodes per daemon.
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
 *   — it is explicitly NOT 'sealed'. See daemon.ts handleSealInterruptedFlow for what
 *   blocks the threshold seal.
 * - sealed: a real FROST threshold notarization completed. Only the normal
 *   (non-interrupted) close path produces this today.
 */
export type SessionStatus =
  | "active"
  | "sealed"
  | "interrupted"
  | "seal_interrupted_pending"
  // A locally-terminal state for a half-open session that can never be bilaterally sealed — set by a
  // force-abandon (cello_close_session { force }) or the dead-half-open reaper. No FROST notarization
  // (there is nothing to notarize on a dead handshake); it just leaves the open list.
  | "abandoned";

export interface SessionRecord {
  session_id: string;
  /**
   * The STABLE key this row is scoped by. Every `sessions` query joins on this, never on
   * `agent_name`.
   */
  agent_id: string;
  /**
   * DISPLAY ONLY. Joined in from the `agents` table (its single source of truth) — it is NOT a column
   * of `sessions`, precisely so a rename cannot leave a stale copy behind. Never put it in a
   * PRIMARY KEY, a JOIN predicate, or a WHERE-match: a retire FREES the name for reuse, so it does
   * not identify an agent across the retired boundary.
   */
  agent_name: string;
  counterparty_pubkey: string;
  status: SessionStatus;
  created_at: number;
  updated_at: number;
  /** Leaf count at interruption. 0 if not yet set. */
  message_count: number;
  /** ISO 8601 timestamp of interruption. Null if not yet set. */
  interrupted_at: string | null;
  /**
   * The counterparty's FROST primary (group) pubkey hex, from the
   * SessionAssignment's signer_pubkey. The responder verifies the bilateral seal signature against
   * it. Null when this party initiated (it verifies against its own primary).
   */
  counterparty_primary_pubkey?: string | null;
  /**
   * DOD-SESSION-NAME-1: this agent's own human-readable label for the session. Null when unnamed,
   * and unnamed MEANS something (see the column comment in session-node-manager). Local and
   * cosmetic — it reaches no wire structure.
   */
  session_name?: string | null;
}

/** An interrupted session entry in the cello status response. */
export interface InterruptedSessionInfo {
  sessionId: string;
  agentName: string;
  counterpartyPubkey: string;
  messageCount: number;
  interruptedAt: string;
  /** DOD-SESSION-NAME-1: this agent's own label for the session; null when unnamed. */
  sessionName: string | null;
}

/**
 * cello_sessions: one session in the discovery list for the current agent.
 * Covers every status (active, sealed, interrupted, seal_interrupted_pending) so
 * the by-id reads (cello_transcript / cello_sealed_receipt) have a source for their
 * session ids. Timestamps are ISO 8601; interruptedAt is null unless the session
 * is/was interrupted.
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
  /** The resolved display label (pet name ?? offered ?? fingerprint). */
  who: string;
  whoKnown: boolean;
  /**
   * DOD-SESSION-NAME-1: this agent's own label for the session, or null when unnamed.
   *
   * Returned ALONGSIDE sessionId, never instead of it — the id is what you paste into the next
   * command. Null is a value with meaning: a session that closed cleanly through an agent usually
   * has a name, so an unnamed closed one is a hint it did not.
   */
  sessionName: string | null;
}

/**
 * Result of a session listing (cello_sessions / the daemon-wide `list_sessions`). `sessions`
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
