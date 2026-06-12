/**
 * CELLO Daemon IPC Types
 *
 * IPC framing: JSON-newline-delimited over Unix domain socket.
 * Requests: {id, method, params}
 * Responses: {id, result} or {id, error: {code, message, guidance}}
 */

// --- Logger interface (injected, never imported directly) ---

export interface Logger {
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
}

// --- Daemon configuration ---

export interface DaemonConfig {
  celloDir: string;
  socketPath: string;
  lockFilePath: string;
  maxConnections: number;
  version: string;
  logger: Logger;
}

// --- Error codes ---

export const ErrorCodes = {
  DAEMON_LOCK_STALE_REMOVED: "daemon_lock_stale_removed",
  DAEMON_SOCKET_BIND_FAILED: "daemon_socket_bind_failed",
  AGENT_LOAD_FAILED: "agent_load_failed",
  IPC_CONNECTION_LIMIT: "ipc_connection_limit",
  CONNECTION_VALIDATION_TIMEOUT: "connection_validation_timeout",
  DIRECTORY_UNREACHABLE_AT_LOGIN: "directory_unreachable_at_login",
} as const;
