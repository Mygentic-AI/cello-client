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
import { RetryQueue } from "./retry-queue.js";
import { NonceDedupStore } from "./nonce-dedup.js";
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

  // DAEMON-003: Initialize RetryQueue and NonceDedupStore (AC-008).
  // Both use the same SQLite DB as the SessionNodeManager (daemon.db equivalent).
  // loadFromDb() must complete BEFORE IPC socket opens (AC-007).
  const retryQueue = new RetryQueue(sessionNodeManager.getDb(), logger);
  retryQueue.loadFromDb();

  const nonceDedupStore = new NonceDedupStore(sessionNodeManager.getDb(), logger);
  nonceDedupStore.loadFromDb();

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
      retryQueueDepth: retryQueue.getTotalDepth(),
    };
  }

  // Register IPC handlers
  const handlers = new Map<string, IpcHandler>();

  handlers.set("status", async () => {
    return getStatus();
  });

  // DAEMON-003 IPC handlers: queue_failed_send and check_nonce (AC-010)
  handlers.set("queue_failed_send", async (params) => {
    const sessionId = params?.sessionId as string | undefined;
    const nonceHex = params?.nonce as string | undefined;
    const contentHex = params?.content as string | undefined;
    if (!sessionId || !nonceHex || !contentHex) {
      return { error: "missing_params", guidance: "Provide sessionId, nonce (hex), and content (hex)." };
    }
    const nonce = Buffer.from(nonceHex, "hex");
    const content = Buffer.from(contentHex, "hex");
    retryQueue.enqueue(sessionId, nonce, content);
    return { queued: true, queueDepth: retryQueue.getSessionDepth(sessionId) };
  });

  handlers.set("check_nonce", async (params) => {
    const sessionId = params?.sessionId as string | undefined;
    const nonceHex = params?.nonce as string | undefined;
    const senderPubkeyHex = params?.senderPubkey as string | undefined;
    if (!sessionId || !nonceHex || !senderPubkeyHex) {
      return { error: "missing_params", guidance: "Provide sessionId, nonce (hex), and senderPubkey (hex)." };
    }
    const nonce = Buffer.from(nonceHex, "hex");
    const senderPubkey = Buffer.from(senderPubkeyHex, "hex");
    const duplicate = nonceDedupStore.checkAndAdd(sessionId, nonce, senderPubkey);
    return { duplicate };
  });

  // DAEMON-003: drain_session IPC handler — triggered on peer reconnect.
  // The client calls this when a session stream is re-established. The sendFn
  // is provided as a callback mechanism: the daemon serializes each message
  // back to the client via a per-entry IPC response, and the client resends
  // over the live stream. For the daemon-internal case (peer reconnect detected
  // by SessionNodeManager), the drain is triggered directly.
  handlers.set("drain_session", async (params) => {
    const sessionId = params?.sessionId as string | undefined;
    if (!sessionId) {
      return { error: "missing_params", guidance: "Provide sessionId." };
    }
    const entries = retryQueue.getSessionEntries(sessionId);
    return { pendingCount: entries.length, entries: entries.map(e => ({ nonce: e.nonceHex, content: Buffer.from(e.contentBlob).toString("hex") })) };
  });

  let shutdownPromise: Promise<void> | null = null;
  handlers.set("shutdown", async () => {
    if (!shutdownPromise) {
      shutdownPromise = stop("logout_requested").catch((err: unknown) => {
        logger.error("daemon.shutdown.failed", {
          signal: "logout",
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
