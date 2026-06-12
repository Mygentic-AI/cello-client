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

// M7-MANIFEST-002: manifest loading, verification, and polling
export { FileManifestProvider } from "./manifest-loader.js";
export { RandomizedPollScheduler, ImmediatePollScheduler } from "./manifest-poll-scheduler.js";
export { InMemoryManifestVersionStore } from "./manifest-version-store.js";
export { FileManifestVersionStore } from "./manifest-version-store-file.js";
export { ManifestDirectoryChallengeVerifier, TestDirectoryChallengeVerifier } from "./challenge-verifier.js";
