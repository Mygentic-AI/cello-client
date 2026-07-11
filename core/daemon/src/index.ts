export type {
  Logger,
  LockFileContent,
  IpcRequest,
  IpcResponse,
  IpcResponseOk,
  IpcResponseError,
  IpcNotification,
  IpcFrame,
  AgentState,
  AgentInfo,
  ConnectionStatus,
  ConnectionInfo,
  DirectorySignalingState,
  DaemonStatusResponse,
  DaemonConfig,
  IManifestProvider,
  IManifestVersionStore,
  IManifestPollScheduler,
  IDirectoryChallengeVerifier,
} from "./types.js";
export { ErrorCodes } from "./types.js";

export { startDaemon, type DaemonHandle } from "./daemon.js";
export { readLock, acquireLock, removeLock, isProcessAlive } from "./lock-file.js";
export { loadAgents, type LoadedAgent, type FailedAgent, type AgentLoadResult } from "./agent-loader.js";
export { createIpcServer, type IpcServer, type IpcHandler, type IpcServerConfig, type IpcDisconnectHandler } from "./ipc-server.js";
export { connectToDaemon, type IpcClient, IpcError } from "./ipc-client.js";
export { connectOrStart, type ConnectResult } from "./connect-or-start.js";
export { RetryQueue, type RetryQueueEntry, type ResendFn, type ResendResult, RETRY_QUEUE_CAP } from "./retry-queue.js";
export { NonceDedupStore, NONCE_DEDUP_CAP } from "./nonce-dedup.js";

// CELLO-M7-TRANSPORT-001: direct-P2P transport selection with relay fallback + dcutr
export {
  TransportSelector,
  LocalTransportSelectorStub,
  TRANSPORT_ERROR,
  DEFAULT_DIRECT_DIAL_TIMEOUT_MS,
  selectAdvertisedAddress,
} from "./transport-selector.js";
export type {
  ITransportSelector,
  TransportResult,
  TransportDialer,
  TransportDialOptions,
  AdvertisedAddress,
} from "./transport-selector.js";

// M7-MANIFEST-002: manifest loading, verification, and polling
export { FileManifestProvider } from "./manifest-loader.js";
export { RandomizedPollScheduler, ImmediatePollScheduler } from "./manifest-poll-scheduler.js";
export { InMemoryManifestVersionStore } from "./manifest-version-store.js";
export { DbManifestVersionStore } from "./manifest-version-store-db.js";
export { ManifestDirectoryChallengeVerifier, TestDirectoryChallengeVerifier } from "./challenge-verifier.js";

// DOD-ONBOARD-HELP-1 §2b — the ONE vocabulary (capability → {cli, mcp}). Exported so the CLI
// registry and the connect shim's audit test derive their names from the SAME table the daemon
// renders its guidance from, instead of three lists of literals that drift.
export {
  DUAL_SURFACE_VERBS,
  MCP_ONLY_TOOLS,
  NON_TOOL_IDENTIFIERS,
  DEAD_CLI_VERBS,
  RENAMED_AWAY_TOOLS,
  knownToolNames,
  toCliGuidance,
  renderForSurface,
  type DualSurfaceVerb,
  type ClientSurface,
} from "./vocabulary.js";
