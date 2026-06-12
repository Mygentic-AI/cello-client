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
} from "./types.js";
export { ErrorCodes } from "./types.js";

export { startDaemon, type DaemonHandle } from "./daemon.js";
export { readLock, acquireLock, removeLock, isProcessAlive } from "./lock-file.js";
export { loadAgents, type LoadedAgent, type FailedAgent, type AgentLoadResult } from "./agent-loader.js";
export { createIpcServer, type IpcServer, type IpcHandler, type IpcServerConfig } from "./ipc-server.js";
export { connectToDaemon, type IpcClient, IpcError } from "./ipc-client.js";
export { connectOrStart, type ConnectResult } from "./connect-or-start.js";
