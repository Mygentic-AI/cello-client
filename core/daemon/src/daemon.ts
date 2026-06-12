/**
 * CELLO Daemon process — the long-running background service.
 *
 * Pseudocode:
 * 1. startDaemon(config):
 *    a. Load agents from ~/.cello/agents/ (or legacy ~/.cello/key)
 *    b. Acquire lock file atomically
 *    c. Initialize SessionNodeManager (creates standing receiver, detects interrupted sessions)
 *    d. Start IPC server on Unix domain socket
 *    e. Register method handlers (status, shutdown)
 *    f. Log daemon.started event
 *    g. Set up SIGTERM/SIGINT handlers for graceful shutdown
 *    h. Stub directory connection validation (mark all connections as 'unverified')
 *
 * 2. shutdown(reason):
 *    a. Log daemon.stopped event
 *    b. Call SessionNodeManager.gracefulShutdown() (marks sessions interrupted)
 *    c. Stop IPC server (finishes in-flight, sends shutdown frame)
 *    d. Remove lock file
 *    e. Exit 0
 */

import { mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import type {
  DaemonConfig,
  DaemonStatusResponse,
  AgentInfo,
  ConnectionInfo,
} from "./types.js";
import { loadAgents } from "./agent-loader.js";
import { acquireLock, removeLock } from "./lock-file.js";
import { createIpcServer, type IpcServer, type IpcHandler } from "./ipc-server.js";
import { SessionNodeManager } from "./session-node-manager.js";
import { createNode } from "@cello-protocol/transport";
import type { ISessionNodeFactory, SessionNodeConfig } from "./session-node-manager.js";

export interface DaemonHandle {
  stop(reason: string): Promise<void>;
  getStatus(): DaemonStatusResponse;
}

// Minimal no-op KeyProvider stub for session nodes.
// Session nodes don't need signing keys — libp2p generates its own fresh
// transport keypair internally. The KeyProvider interface is required by
// createNode but is never called on session nodes.
const SESSION_NODE_KEY_STUB = {
  getPublicKey: () => Promise.resolve(new Uint8Array(32)),
  sign: (_data: Uint8Array) => Promise.resolve(new Uint8Array(64)),
};

// Production session node factory — wraps createNode from @cello-protocol/transport
class ProductionSessionNodeFactory implements ISessionNodeFactory {
  async createNode(config: SessionNodeConfig) {
    return createNode({
      keyProvider: SESSION_NODE_KEY_STUB,
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      connectionGater: config.connectionGater,
    });
  }
}

export async function startDaemon(config: DaemonConfig): Promise<DaemonHandle> {
  const { celloDir, socketPath, lockFilePath, maxConnections, version, logger } = config;

  // Ensure the cello directory exists
  await mkdir(celloDir, { recursive: true });

  // Ensure the socket parent directory exists
  await mkdir(dirname(socketPath), { recursive: true });

  // Load agent identities
  const { loaded: loadedAgents, failed: failedAgents } = await loadAgents(celloDir, logger);

  // Acquire lock file
  await acquireLock(lockFilePath, {
    pid: process.pid,
    socketPath,
    version,
  });

  // Build agent state (all start in 'registered' state — no auto-start)
  const agents: AgentInfo[] = [
    ...loadedAgents.map((a) => ({
      name: a.name,
      state: "registered" as const,
      pubkey: a.pubkey,
    })),
    ...failedAgents.map((a) => ({
      name: a.name,
      state: "load_failed" as const,
      error: a.error,
    })),
  ];

  // Stub: all connections marked as 'unverified' until SIGNAL-001 implements
  // the directory signaling stream
  const connections: ConnectionInfo[] = [];

  // Initialize SessionNodeManager (DAEMON-002: composition root — AC-011).
  // This runs before the IPC socket opens so:
  //   1. The standing receiver is ready before any cello_await_session call.
  //   2. Interrupted session detection runs before any tool call can race.
  const sessionNodeManager = new SessionNodeManager({
    factory: new ProductionSessionNodeFactory(),
    logger,
    dbPath: join(celloDir, "sessions.db"),
  });
  await sessionNodeManager.initialize();

  // Build status response factory
  function getStatus(): DaemonStatusResponse {
    return {
      daemon: "running",
      // Per CONTEXT.md: from the moment the daemon first attempts a directory
      // connection (at startup), any non-connected state is 'reconnecting'
      directory_signaling: "reconnecting",
      agents,
      connections,
      standing_receiver_ready: sessionNodeManager.getStandingReceiverReady(),
    };
  }

  // Register IPC handlers
  const handlers = new Map<string, IpcHandler>();

  handlers.set("status", async () => {
    return getStatus();
  });

  let shutdownPromise: Promise<void> | null = null;
  handlers.set("shutdown", async () => {
    if (!shutdownPromise) {
      shutdownPromise = stop("logout_requested").catch((err: unknown) => {
        logger.error("daemon.shutdown.failed", {
          error: err instanceof Error ? err.message : String(err),
        });
      });
    }
    return { acknowledged: true };
  });

  // Create and start IPC server
  const ipcServer: IpcServer = createIpcServer(
    { socketPath, maxConnections, logger },
    handlers,
  );

  try {
    await ipcServer.start();
  } catch (err: unknown) {
    await removeLock(lockFilePath, logger);
    throw err;
  }

  // Log daemon.login.validation.complete (stub — all unverified until SIGNAL-001)
  logger.info("daemon.login.validation.complete", {
    verifiedCount: 0,
    staleCount: 0,
    goneCount: 0,
  });

  // Log daemon.started
  logger.info("daemon.started", {
    pid: process.pid,
    ipcSocketPath: socketPath,
    agentCount: loadedAgents.length,
  });

  // Graceful shutdown
  async function stop(reason: string): Promise<void> {
    logger.info("daemon.stopped", { pid: process.pid, reason });
    // Gracefully mark active sessions interrupted (AC-009) before stopping IPC
    await sessionNodeManager.gracefulShutdown();
    await ipcServer.stop();
    await removeLock(lockFilePath, logger);
  }

  return { stop, getStatus };
}
