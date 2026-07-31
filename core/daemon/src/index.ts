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
// PassthroughGatewayClient is at `@cello-protocol/daemon/testing`, not here (DOD-M9B-WIRE-1).
export { ErrorCodes } from "./types.js";

export { startDaemon, type DaemonHandle } from "./daemon.js";
export { readLock, acquireLock, removeLock, removeLockIfOwned, isProcessAlive } from "./lock-file.js";
export {
  acquireSingletonLock,
  probeSingletonLock,
  DaemonAlreadyRunningError,
  SINGLETON_LOCK_FILENAME,
  type SingletonLock,
} from "./singleton-lock.js";
export { loadAgents, type LoadedAgent, type FailedAgent, type AgentLoadResult } from "./agent-loader.js";
export { createIpcServer, type IpcServer, type IpcHandler, type IpcServerConfig, type IpcDisconnectHandler } from "./ipc-server.js";
export { connectToDaemon, type IpcClient, IpcError } from "./ipc-client.js";
export { connectOrStart, type ConnectResult } from "./connect-or-start.js";
export { RetryQueue, type RetryQueueEntry, type ResendFn, type ResendResult, RETRY_QUEUE_CAP } from "./retry-queue.js";
export { NonceDedupStore, NONCE_DEDUP_CAP } from "./nonce-dedup.js";

// Direct-P2P transport selection with relay fallback + dcutr
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

// Manifest loading, verification, and polling
export { FileManifestProvider } from "./manifest-loader.js";
export { RandomizedPollScheduler, ImmediatePollScheduler } from "./manifest-poll-scheduler.js";
export { InMemoryManifestVersionStore } from "./manifest-version-store.js";
export { DbManifestVersionStore } from "./manifest-version-store-db.js";
export { ManifestDirectoryChallengeVerifier, TestDirectoryChallengeVerifier } from "./challenge-verifier.js";

// DOD-REGISTRY-1: type registry (client-side poll + classification)
export { TypeRegistry, type TypeClassification, type UnclassifiedType, type TypeLookupResult, type RegistryDocument } from "./type-registry.js";
export { DbRegistryVersionStore, type IRegistryVersionStore } from "./registry-version-store-db.js";
export { pollRegistryOverHttp, startRegistryPoll, type RegistryPollOutcome, type RegistryPollFailureReason } from "./registry-poll.js";

// The ONE vocabulary (capability → {cli, mcp}). Exported so the CLI registry and the connect shim's
// audit test derive their names from the SAME table the daemon renders its guidance from, instead of
// three lists of literals that drift.
export {
  DUAL_SURFACE_VERBS,
  MCP_ONLY_TOOLS,
  NON_TOOL_IDENTIFIERS,
  DEAD_CLI_VERBS,
  deadCliVerbPattern,
  RENAMED_AWAY_TOOLS,
  knownToolNames,
  toCliGuidance,
  renderForSurface,
  type DualSurfaceVerb,
  type ClientSurface,
} from "./vocabulary.js";

// The FROST/DKG directory-node client. It lives in the daemon because the daemon is the only process
// that runs a ceremony, and the daemon never imports @cello-protocol/client. Exported so
// trustless-cello's directory tests can drive a real DKG against a real directory.
export {
  NetworkDirectoryNode,
  bootstrapNetworkKeyShares,
  runNetworkDkg,
  runNetworkRefresh,
} from "./network-directory-node.js";
export type { FrostAuthSigner } from "./network-directory-node.js";
