/**
 * CELLO Daemon process — the long-running background service.
 *
 * Pseudocode:
 * 1. startDaemon(config):
 *    a. Load agents from ~/.cello/agents/ (or legacy ~/.cello/key)
 *    b. Acquire lock file atomically
 *    c. Start IPC server on Unix domain socket
 *    d. Register method handlers (status, shutdown)
 *    e. Log daemon.started event
 *    f. Set up SIGTERM/SIGINT handlers for graceful shutdown
 *    g. Stub directory connection validation (mark all connections as 'unverified')
 *
 * 2. shutdown(reason):
 *    a. Log daemon.stopped event
 *    b. Stop IPC server (finishes in-flight, sends shutdown frame)
 *    c. Remove lock file
 *    d. Exit 0
 */

import { mkdir } from "node:fs/promises";
import type {
  DaemonConfig,
  DaemonStatusResponse,
  AgentInfo,
  ConnectionInfo,
} from "./types.js";
import { loadAgents, type LoadedAgent } from "./agent-loader.js";
import { acquireLock, removeLock } from "./lock-file.js";
import { createIpcServer, type IpcServer, type IpcHandler } from "./ipc-server.js";

export interface DaemonHandle {
  stop(reason: string): Promise<void>;
  getStatus(): DaemonStatusResponse;
}

export async function startDaemon(config: DaemonConfig): Promise<DaemonHandle> {
  const { celloDir, socketPath, lockFilePath, maxConnections, version, logger } = config;

  // Ensure the cello directory exists
  await mkdir(celloDir, { recursive: true });

  // Ensure the socket parent directory exists
  const socketDir = socketPath.substring(0, socketPath.lastIndexOf("/"));
  if (socketDir) {
    await mkdir(socketDir, { recursive: true });
  }

  // Load agent identities
  const loadedAgents = await loadAgents(celloDir, logger);

  // Acquire lock file
  await acquireLock(lockFilePath, {
    pid: process.pid,
    socketPath,
    version,
  });

  // Build agent state (all start in 'registered' state — no auto-start)
  const agents: AgentInfo[] = loadedAgents.map((a: LoadedAgent) => ({
    name: a.name,
    state: "registered" as const,
    pubkey: a.pubkey,
  }));

  // Stub: all connections marked as 'unverified' until SIGNAL-001 implements
  // the directory signaling stream
  const connections: ConnectionInfo[] = [];

  // Build status response factory
  function getStatus(): DaemonStatusResponse {
    return {
      daemon: "running",
      // Stub: no directory signaling stream yet (SIGNAL-001 scope)
      directory_signaling: "lost",
      agents,
      connections,
    };
  }

  // Register IPC handlers
  const handlers = new Map<string, IpcHandler>();

  handlers.set("status", async () => {
    return getStatus();
  });

  let shutdownPromise: Promise<void> | null = null;
  handlers.set("shutdown", async () => {
    // Trigger graceful shutdown but respond first
    if (!shutdownPromise) {
      shutdownPromise = stop("logout_requested");
    }
    return { acknowledged: true };
  });

  // Create and start IPC server
  const ipcServer: IpcServer = createIpcServer(
    { socketPath, maxConnections, logger },
    handlers,
  );

  await ipcServer.start();

  // Log daemon.started
  logger.info("daemon.started", {
    pid: process.pid,
    ipcSocketPath: socketPath,
    agentCount: agents.length,
  });

  // Graceful shutdown
  async function stop(reason: string): Promise<void> {
    logger.info("daemon.stopped", { pid: process.pid, reason });
    await ipcServer.stop();
    await removeLock(lockFilePath, logger);
  }

  return { stop, getStatus };
}
