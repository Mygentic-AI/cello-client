/**
 * CELLO Daemon process — the long-running background service.
 *
 * Pseudocode:
 * 1. startDaemon(config):
 *    a. M7-MANIFEST-002: Load and verify consortium manifest (BEFORE any directory connection)
 *       - On signature failure: log error, skip connection
 *       - On expiry: log directory.auth.manifest.expired at ERROR, skip connection
 *       - On version rollback: log directory.auth.manifest.version.rollback at ERROR
 *       - On success: log directory.auth.manifest.verified at INFO
 *    b. Load agents from ~/.cello/agents/ (or legacy ~/.cello/key)
 *    c. Acquire lock file atomically
 *    d. Initialize SessionNodeManager (creates standing receiver, detects interrupted sessions)
 *    e. Start IPC server on Unix domain socket
 *    f. Register method handlers (status, shutdown)
 *    g. Log daemon.started event (with manifestVerified field)
 *    h. Set up SIGTERM/SIGINT handlers for graceful shutdown
 *    i. Start background manifest polling (if pollScheduler provided and manifest verified)
 *
 * 2. shutdown(reason):
 *    a. Cancel manifest poll scheduler
 *    b. Log daemon.stopped event
 *    c. Call SessionNodeManager.gracefulShutdown() (marks sessions interrupted)
 *    d. Stop IPC server (finishes in-flight, sends shutdown frame)
 *    e. Remove lock file
 *    f. Exit 0
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
import { createNode, SignalingManager, InMemorySignalingOutboundQueue } from "@cello-protocol/transport";
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
  const {
    celloDir, socketPath, lockFilePath, maxConnections, version, logger,
    manifestProvider, manifestRootKeys, manifestThreshold,
    manifestVersionStore, manifestPollScheduler,
  } = config;

  // M7-MANIFEST-002: Load and verify consortium manifest BEFORE any directory connection.
  //
  // Pseudocode for manifest loading:
  //   1. If manifestProvider is configured:
  //      a. Call manifestProvider.loadAndVerify(rootKeys, threshold).
  //      b. Check validity window: not_before <= now < expires.
  //      c. Check version monotonicity (if manifestVersionStore is provided).
  //      d. On success: log directory.auth.manifest.verified.
  //      e. On failure: log error event, set directory_signaling to 'reconnecting'.
  //   2. If manifestProvider is absent: skip (backward compat for DAEMON-001 tests).
  let manifestVerified = false;

  if (manifestProvider && manifestRootKeys && manifestThreshold !== undefined) {
    try {
      const manifest = await manifestProvider.loadAndVerify(manifestRootKeys, manifestThreshold);

      // Check validity window: not_before <= now < expires
      const now = new Date();
      const notBefore = new Date(manifest.not_before);
      const expiresAt = new Date(manifest.expires);

      if (now < notBefore) {
        logger.error("directory.auth.manifest.not.yet.valid", {
          manifestVersion: manifest.version,
          notBefore: manifest.not_before,
        });
      } else if (expiresAt <= now) {
        logger.error("directory.auth.manifest.expired", {
          manifestVersion: manifest.version,
          expiresAt: manifest.expires,
        });
      } else {
        // Check version monotonicity if version store is provided
        if (manifestVersionStore) {
          const lastSeen = await manifestVersionStore.getLastSeenVersion();
          if (lastSeen !== null && manifest.version < lastSeen) {
            logger.error("directory.auth.manifest.version.rollback", {
              manifestVersion: manifest.version,
              lastSeenVersion: lastSeen,
            });
          } else {
            await manifestVersionStore.persistVersion(manifest.version);
            manifestVerified = true;
            logger.info("directory.auth.manifest.verified", {
              manifestVersion: manifest.version,
              signerCount: manifest.signatures.length,
            });
          }
        } else {
          manifestVerified = true;
          logger.info("directory.auth.manifest.verified", {
            manifestVersion: manifest.version,
            signerCount: manifest.signatures.length,
          });
        }
      }
    } catch (err: unknown) {
      logger.error("directory.auth.manifest.load.failed", {
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

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
  // Returns pending entry metadata (nonces only — SI-002 forbids content in IPC frames).
  // The actual drain+delivery is triggered separately when a real sendFn is available.
  handlers.set("drain_session", async (params) => {
    const sessionId = params?.sessionId as string | undefined;
    if (!sessionId) {
      return { error: "missing_params", guidance: "Provide sessionId." };
    }
    const depth = retryQueue.getSessionDepth(sessionId);
    const entries = retryQueue.getSessionEntries(sessionId);
    return { pendingCount: depth, nonces: entries.map(e => e.nonceHex) };
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
    manifestVerified,
  });

  // M7-MANIFEST-002: Start background manifest polling if scheduler is provided and manifest verified.
  if (manifestPollScheduler && manifestVerified) {
    if (manifestProvider && manifestVersionStore && config.challengeVerifier) {
      const outboundQueue = new InMemorySignalingOutboundQueue();
      const signalingManager = new SignalingManager({
        challengeVerifier: config.challengeVerifier,
        pollScheduler: manifestPollScheduler,
        manifestVersionStore,
        manifestProvider,
        outboundQueue,
        logger,
        correlationId: `daemon-startup-${version}`,
        rootKeys: manifestRootKeys!,
        threshold: manifestThreshold!,
      });
      signalingManager.startPolling();
    } else {
      // Minimal path: scheduler present but full deps not yet wired.
      manifestPollScheduler.scheduleNext(async () => {
        logger.info("directory.auth.manifest.poll.scheduled", {});
      });
    }
  }

  // Graceful shutdown
  async function stop(reason: string): Promise<void> {
    // Cancel any pending manifest poll timer
    if (manifestPollScheduler) {
      manifestPollScheduler.cancel();
    }
    logger.info("daemon.stopped", { pid: process.pid, reason });
    // Gracefully mark active sessions interrupted (AC-009) before stopping IPC
    await sessionNodeManager.gracefulShutdown();
    await ipcServer.stop();
    await removeLock(lockFilePath, logger);
  }

  return { stop, getStatus };
}
