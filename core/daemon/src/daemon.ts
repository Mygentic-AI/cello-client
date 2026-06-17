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
import { randomUUID } from "node:crypto";
import { dirname, join } from "node:path";
import type {
  DaemonConfig,
  DaemonStatusResponse,
  AgentInfo,
  ConnectionInfo,
  InterruptedSessionInfo,
} from "./types.js";
import { loadAgents } from "./agent-loader.js";
import { acquireLock, removeLock } from "./lock-file.js";
import { createIpcServer, type IpcServer, type IpcHandler } from "./ipc-server.js";
import { SessionNodeManager } from "./session-node-manager.js";
import { RetryQueue } from "./retry-queue.js";
import { NonceDedupStore } from "./nonce-dedup.js";
import { NotificationDispatcher } from "./notification-dispatcher.js";
import { createNode, SignalingManager, type ConnectResult, type CelloNode } from "@cello-protocol/transport";
import { createSignalingConnect, type SignalingAuthIdentity } from "./signaling-connect.js";
import { RegistrationManager } from "./registration-manager.js";
import { DaemonRegistrationContext } from "./registration-context.js";
import { FileRegistrationPersistence } from "./registration-persistence.js";
import { verify as ed25519Verify } from "@cello-protocol/crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { SealInterruptedLeaf } from "@cello-protocol/protocol-types";
import type { ISessionNodeFactory, SessionNodeConfig } from "./session-node-manager.js";

/**
 * M7-SESSION-001 (H-1): canonical byte encoding of a SEAL-INTERRUPTED leaf for
 * Ed25519 signing/verification. Field order is fixed and deterministic. Both the
 * initiator and the responder, and the verifier, MUST use exactly this encoding —
 * any drift causes silent signature-verification failure.
 */
function canonicalSealInterruptedLeafBytes(leaf: {
  type: string;
  sessionId: string;
  leafCount: number;
  merkleRootAtInterruption: string;
  timestamp: number;
  signerPubkey: string;
}): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({
      type: leaf.type,
      sessionId: leaf.sessionId,
      leafCount: leaf.leafCount,
      merkleRootAtInterruption: leaf.merkleRootAtInterruption,
      timestamp: leaf.timestamp,
      signerPubkey: leaf.signerPubkey,
    }),
  );
}

/**
 * M7-SESSION-001 (H-1): construct and K_local-sign a SEAL-INTERRUPTED leaf.
 * The private key never leaves keyProvider — only the Ed25519 signature is returned.
 */
async function buildSignedSealInterruptedLeaf(
  keyProvider: KeyProvider,
  opts: {
    sessionId: string;
    leafCount: number;
    merkleRootAtInterruption: string;
    signerPubkeyHex: string;
  },
): Promise<SealInterruptedLeaf> {
  const partial = {
    type: "SEAL_INTERRUPTED" as const,
    sessionId: opts.sessionId,
    leafCount: opts.leafCount,
    merkleRootAtInterruption: opts.merkleRootAtInterruption,
    timestamp: Date.now(),
    signerPubkey: opts.signerPubkeyHex,
  };
  const sig = await keyProvider.sign(canonicalSealInterruptedLeafBytes(partial));
  return { ...partial, signature: Buffer.from(sig).toString("hex") };
}

export interface DaemonHandle {
  stop(reason: string): Promise<void>;
  getStatus(): DaemonStatusResponse;
  /**
   * AC-016 test hook: exposes the session node manager so integration tests can
   * call registerRelayStream directly and verify the composition root is wired.
   * Not part of the production API surface.
   */
  getSessionNodeManager(): SessionNodeManager;
  /**
   * M7 Action 2: the live directory-facing libp2p node (or null when signaling is not
   * connected). Registration's FROST DKG and future ceremonies open streams to the
   * directory on this node. Consumers must gate use on signaling being connected AND
   * always null-check the result: there is a brief window during stream death where the
   * reference is already cleared (null) while signalingManager.status still reads
   * "connected". Null is the safe direction (never a tearing-down node); do not assume
   * non-null just because status is connected.
   */
  getDirectoryNode(): CelloNode | null;
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
    signalingConnect, challengeVerifier, directoryEndpointResolver,
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
  // M7 Keystone: the version of the verified manifest, surfaced in ConnectResult.
  // Stays 0 when no manifestProvider is configured (the M6 backward-compat path).
  let verifiedManifestVersion = 0;

  // ADV-006 + ADV-008: If manifestProvider is set, manifestRootKeys and a positive
  // manifestThreshold are required. Fail loudly on misconfiguration rather than
  // silently proceeding unverified.
  if (manifestProvider && (!manifestRootKeys || !manifestThreshold || manifestThreshold <= 0)) {
    throw new Error(
      "DaemonConfig: manifestProvider requires manifestRootKeys (non-empty) and manifestThreshold (positive integer >= 1)",
    );
  }

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
            verifiedManifestVersion = manifest.version;
            logger.info("directory.auth.manifest.verified", {
              manifestVersion: manifest.version,
              signerCount: manifest.signatures.length,
            });
          }
        } else {
          manifestVerified = true;
          verifiedManifestVersion = manifest.version;
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

  // ADV-002: When manifestProvider is configured (opt-in mode) and verification
  // failed, the daemon must refuse to proceed. Operators who configure
  // manifestProvider have opted into manifest enforcement.
  if (manifestProvider && !manifestVerified) {
    throw new Error(
      "Manifest verification failed. The daemon cannot start with an unverified manifest when manifestProvider is configured. " +
      "Check the logs for the specific failure reason (manifest_signature_invalid, manifest_expired, or manifest_version_rollback).",
    );
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

  // M7-SESSION-001 (H-1): retain each agent's K_local signing key so the daemon
  // can produce K_local-signed SEAL-INTERRUPTED leaves (both as initiator and as
  // the bilateral responder). The KeyProvider keeps the private scalar internal —
  // only signatures leave it.
  const keyProviders = new Map<string, import("@cello-protocol/crypto").KeyProvider>();
  for (const a of loadedAgents) {
    keyProviders.set(a.name, a.keyProvider);
  }

  // Stub: all connections marked as 'unverified' until connection validation is wired
  const connections: ConnectionInfo[] = [];

  // M7-SIGNAL-001: Instantiate SignalingManager — owns directory signaling stream lifecycle.
  const defaultConnect = async (): Promise<ConnectResult> => {
    throw new Error("directory_signaling_not_configured");
  };

  // M7 Keystone (Part 1): resolve the agent identity that authenticates the
  // directory signaling stream. The daemon's directory-facing node is one per
  // daemon, so the keystone authenticates as the PRIMARY agent (first successfully
  // loaded). Returns null when no agent is registered yet → connect() throws
  // no_agent_identity and the SignalingManager stays reconnecting until one exists
  // (registration, Action 2, brings the first identity).
  //
  // NOTE (multi-agent, Action 2+): per-agent directory operations under distinct
  // identities are out of keystone scope. This establishes the directory door.
  // L4: sort by name so the "primary" agent is STABLE across restarts — readdir
  // order (agent-loader) is platform-dependent and unsorted, which would otherwise
  // let the authenticating identity change between daemon restarts.
  const primaryAgent = [...loadedAgents].sort((a, b) => a.name.localeCompare(b.name))[0];
  const getAuthIdentity = (): SignalingAuthIdentity | null => {
    if (!primaryAgent) return null;
    return { keyProvider: primaryAgent.keyProvider, pubkeyHex: primaryAgent.pubkey };
  };

  // Production builds signalingConnect from the bootstrap resolver + agent identity.
  // Tests inject signalingConnect directly (takes precedence). Neither → defaultConnect
  // (DAEMON-001 backward-compat). challengeVerifier is left to the caller: when absent,
  // step-6 directory verification is skipped — the M6 path that connected and ran the
  // full DKG/seal pipeline.
  // M7 Action 2: the daemon holds a reference to the live directory-facing node so
  // registration's FROST DKG (NetworkDirectoryNode) — and future ceremonies/seal — can
  // open streams to the directory on the SAME node. createSignalingConnect sets it via
  // publishNode on a successful connect and clears it (null) when the stream closes.
  // Consumers MUST gate use on signalingManager.status === "connected".
  let directoryNode: CelloNode | null = null;
  const getDirectoryNode = (): CelloNode | null => directoryNode;

  const resolvedConnect: () => Promise<ConnectResult> =
    signalingConnect ??
    (directoryEndpointResolver
      ? createSignalingConnect({
          getDirectoryEndpoint: directoryEndpointResolver,
          getAuthIdentity,
          logger,
          challengeVerifier,
          getManifestVersion: () => verifiedManifestVersion,
          publishNode: (n) => {
            directoryNode = n;
          },
        })
      : defaultConnect);

  // H1: a long-running daemon must ride out directory outages — notably the
  // 25-30 min multi-region directory deploy. The transport default of 10 reconnect
  // attempts (~5 min with default backoff) transitions the manager to terminal
  // "lost" mid-deploy, with no public way to re-enter the loop — the daemon would
  // never recover without a cello logout/login. Use an effectively-unbounded attempt
  // budget with a capped backoff so it keeps retrying and reconnects within
  // ~maxBackoffMs of the directory returning. (Availability is a first-class invariant.)
  //
  // L3: challengeVerifier is NOT passed here — the dialer (createSignalingConnect)
  // performs step-6 verification itself, matching #doOpen. The manager's copy would
  // be dead (processStep5Frame is only invoked inside connect()).
  const signalingManager = new SignalingManager({
    connect: resolvedConnect,
    logger,
    maxReconnectAttempts: Number.MAX_SAFE_INTEGER,
    maxBackoffMs: 30_000,
  });

  // Per-connection state: tracks which agent is "current" for each IPC connection.
  // Key = connectionId (assigned by IPC server), Value = current agent name or null.
  const perConnectionState = new Map<string, { currentAgent: string | null; clientType: string }>();

  // Set of agents currently in "online" state (transitioned via cello_start_agent)
  const onlineAgents = new Set<string>();

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

  // Build agent list from this connection's perspective
  function getAgentsForConnection(connectionId: string): AgentInfo[] {
    const connState = perConnectionState.get(connectionId);
    const currentAgent = connState?.currentAgent ?? null;

    return agents
      .filter((a) => a.state !== "load_failed")
      .map((a) => {
        let state: AgentInfo["state"];
        if (a.name === currentAgent && onlineAgents.has(a.name)) {
          state = "current";
        } else if (onlineAgents.has(a.name)) {
          state = "online";
        } else {
          state = "registered";
        }
        return { name: a.name, state, pubkey: a.pubkey };
      });
  }

  // M7-SESSION-001 AC-006/AC-007 (and M-1 PULL): build the interrupted_sessions
  // array from SQLite. Shared by both getStatus() (daemon-wide) and the
  // cello_status MCP handler (per-connection) so live MCP clients see the same
  // interrupted sessions a CLI `cello status` would.
  function buildInterruptedSessions(): InterruptedSessionInfo[] {
    const interruptedRows = sessionNodeManager.getSessionsByStatus("interrupted");
    return interruptedRows.map((row) => ({
      sessionId: row.session_id,
      agentName: row.agent_name,
      counterpartyPubkey: row.counterparty_pubkey,
      messageCount: row.message_count ?? 0,
      interruptedAt: row.interrupted_at ?? new Date(row.updated_at).toISOString(),
    }));
  }

  // Build status response factory
  function getStatus(): DaemonStatusResponse {
    // M7-SESSION-001 AC-006/AC-007: surface interrupted sessions
    const interrupted_sessions: InterruptedSessionInfo[] = buildInterruptedSessions();

    return {
      daemon: "running",
      directory_signaling: signalingManager.status,
      agents,
      connections,
      standing_receiver_ready: sessionNodeManager.getStandingReceiverReady(),
      retryQueueDepth: retryQueue.getTotalDepth(),
      interrupted_sessions,
    };
  }

  // Register IPC handlers
  const handlers = new Map<string, IpcHandler>();

  handlers.set("status", async (_params, _connectionId) => {
    return getStatus();
  });

  // ─── MCP-001: ipc.connect handler ───
  // Registers the connection's clientType and returns the connectionId.
  handlers.set("ipc.connect", async (params, connectionId) => {
    const clientType = (params?.clientType as string) ?? "cli";
    perConnectionState.set(connectionId, { currentAgent: null, clientType });
    // MCP-002: Register connection with notification dispatcher
    notificationDispatcher.registerConnection(connectionId);
    // Re-log with correct clientType (overrides the default "cli" from handleConnection)
    logger.info("daemon.ipc.connected", { connectionId, clientType });
    return { connectionId };
  });

  // ─── MCP-001: cello_start_agent handler ───
  handlers.set("cello_start_agent", async (params, _connectionId) => {
    const name = params?.name as string | undefined;
    if (!name) {
      return { ok: false, reason: "missing_params", guidance: "Provide 'name' parameter with the agent name to start." };
    }
    const agent = agents.find((a) => a.name === name);
    if (!agent || agent.state === "load_failed") {
      return { ok: false, reason: "agent_not_found", guidance: `Agent '${name}' does not exist. Run 'cello login' to register agents, or check agent names with cello_list_agents.` };
    }
    if (onlineAgents.has(name)) {
      // Idempotent — already online, no event
      return { ok: true };
    }
    onlineAgents.add(name);
    logger.info("agent.online", { agentName: name, agentPubkey: agent.pubkey ?? "" });
    // MCP-002: Broadcast agent_state_changed to ALL connections
    notificationDispatcher.dispatchAgentStateChanged(name, "online", "started");
    return { ok: true };
  });

  // ─── MCP-001: cello_stop_agent handler ───
  handlers.set("cello_stop_agent", async (params, _connectionId) => {
    const name = params?.name as string | undefined;
    if (!name) {
      return { ok: false, reason: "missing_params", guidance: "Provide 'name' parameter with the agent name to stop." };
    }
    const agent = agents.find((a) => a.name === name);
    if (!agent || agent.state === "load_failed") {
      return { ok: false, reason: "agent_not_found", guidance: `Agent '${name}' does not exist. Check agent names with cello_list_agents.` };
    }
    if (!onlineAgents.has(name)) {
      // Idempotent — already registered/offline, no event
      return { ok: true };
    }
    onlineAgents.delete(name);
    logger.info("agent.offline", { agentName: name, reason: "stopped" });
    // MCP-002: Broadcast agent_state_changed to ALL connections
    notificationDispatcher.dispatchAgentStateChanged(name, "offline", "stopped");

    // Clear current agent for all connections that had this agent as current
    for (const [connId, state] of perConnectionState) {
      if (state.currentAgent === name) {
        state.currentAgent = null;
        notificationDispatcher.setCurrentAgent(connId, null);
        notificationDispatcher.dispatchAgentCurrentChanged(connId, name, null);
        logger.info("agent.current.switched", { connectionId: connId, fromAgent: name, toAgent: null });
      }
    }
    return { ok: true };
  });

  // ─── MCP-001: cello_use_agent handler ───
  handlers.set("cello_use_agent", async (params, connectionId) => {
    const name = params?.name as string | undefined;
    if (!name) {
      return { ok: false, reason: "missing_params", guidance: "Provide 'name' parameter with the agent name to use." };
    }
    const agent = agents.find((a) => a.name === name);
    if (!agent || agent.state === "load_failed") {
      return { ok: false, reason: "agent_not_found", guidance: `Agent '${name}' does not exist. Check agent names with cello_list_agents.` };
    }
    if (!onlineAgents.has(name)) {
      return { ok: false, reason: "agent_not_online", guidance: `Agent '${name}' exists but is not online. Call cello_start_agent('${name}') first to bring it online, then retry cello_use_agent.` };
    }
    const connState = perConnectionState.get(connectionId);
    if (!connState) {
      return { ok: false, reason: "connection_not_registered", guidance: "Send ipc.connect frame before calling agent tools." };
    }
    if (connState.currentAgent === name) {
      return { ok: false, reason: "agent_already_current", guidance: `Agent '${name}' is already the current agent for this connection. No action needed — you can proceed with session operations.` };
    }
    const fromAgent = connState.currentAgent;
    connState.currentAgent = name;
    // MCP-002: Update dispatcher's routing table and send notification to this connection only
    notificationDispatcher.setCurrentAgent(connectionId, name);
    notificationDispatcher.dispatchAgentCurrentChanged(connectionId, fromAgent, name);
    logger.info("agent.current.switched", { connectionId, fromAgent, toAgent: name });
    return { ok: true };
  });

  // ─── MCP-001: cello_list_agents handler ───
  handlers.set("cello_list_agents", async (_params, connectionId) => {
    return { agents: getAgentsForConnection(connectionId) };
  });

  // ─── M7-REGISTRATION (Action 2): cello_register handler ───
  // Registers a LOADED agent (one with a K_local `key` under ~/.cello/agents/<name>/)
  // with the directory: ML-DSA keygen → register_request → FROST DKG → register_success,
  // persisting the ML-DSA keypair, FROST share, registration state, and agent→user link.
  // Always invoked with a pre-authorization ticket from the CELLO Operations Agent.
  const registrationGuidance = (reason: string): string => {
    switch (reason) {
      case "already_registered":
        return "This agent is already registered with the directory. No action needed.";
      case "directory_unreachable":
        return "The directory signaling stream is not connected (or its bootstrap endpoint could not be resolved). Wait for directory_signaling to show connected in cello status, then retry.";
      case "dkg_failed":
        return "The FROST DKG ceremony with the directory failed. This usually means the directory rejected the pre-authorization token or a node was unavailable mid-ceremony. Verify the preAuthToken is valid/unused and retry.";
      case "timeout":
        return "The directory did not respond within the registration timeout. Retry once directory_signaling is connected.";
      default:
        return `Registration failed: ${reason}. Check the daemon logs (registration.* events) and that the preAuthToken is valid.`;
    }
  };

  handlers.set("cello_register", async (params, _connectionId) => {
    const name = params?.agent as string | undefined;
    const preAuthToken = params?.preAuthToken as string | undefined;
    const phoneStub = (params?.phoneStub as string | undefined) ?? "";
    if (!name) {
      return { ok: false, reason: "missing_params", guidance: "Provide 'agent' (the agent name to register) and 'preAuthToken' (the pre-authorization ticket from the CELLO Operations Agent)." };
    }
    if (!preAuthToken) {
      return { ok: false, reason: "missing_preauth_token", guidance: "Registration requires a 'preAuthToken' issued by the CELLO Operations Agent (Telegram). Obtain one, then retry cello_register." };
    }
    const keyProvider = keyProviders.get(name);
    if (!keyProvider) {
      return { ok: false, reason: "agent_not_found", guidance: `Agent '${name}' has no local K_local key loaded. Its key must exist at ~/.cello/agents/${name}/key before registration — create it and restart the daemon, then retry cello_register.` };
    }
    if (!directoryEndpointResolver) {
      return { ok: false, reason: "directory_unreachable", guidance: "The daemon has no directory endpoint resolver configured, so it cannot reach the directory to register." };
    }

    // Resolve the directory endpoint once for this registration (the context's
    // getDirectoryEndpoint is synchronous; the daemon's resolver is async with a
    // last-known-good fallback). The endpoint is stable for the duration of one
    // registration — if it changed mid-flow the DKG streams would break anyway.
    const ep = await directoryEndpointResolver();
    if (!ep || !ep.multiaddr) {
      // FROST DKG must dial the directory's /cello/frost/1.0.0 — a dialable
      // multiaddr is required (DirectoryEndpoint.multiaddr is optional for the
      // already-connected signaling case, but registration needs to open streams).
      return { ok: false, reason: "directory_unreachable", guidance: "Could not resolve a dialable directory bootstrap endpoint (GET /bootstrap). Check CELLO_DIRECTORY_URL and network connectivity, then retry." };
    }
    const directoryEndpoint = { peer_id: ep.peerId, multiaddrs: [ep.multiaddr] };

    const persistence = new FileRegistrationPersistence({ agentDir: join(celloDir, "agents", name), logger });
    const ctx = new DaemonRegistrationContext({
      signaling: signalingManager,
      getDirectoryNode,
      getDirectoryEndpoint: () => directoryEndpoint,
      keyProvider,
      persistence,
      logger,
    });
    try {
      const result = await new RegistrationManager(ctx).register(phoneStub, preAuthToken);
      if ("error" in result) {
        logger.warn("registration.failed", { agentName: name, reason: result.error });
        return { ok: false, reason: result.error, guidance: registrationGuidance(result.error) };
      }
      // Capture-now-or-lose-it: persist the agent→user link (using it is future trust-layer work).
      await persistence.persistAgentUserLink({ agentId: result.agent_id, preAuthToken, linkedAt: Date.now() });
      logger.info("registration.succeeded", { agentName: name, agentId: result.agent_id, primaryPubkey: result.primary_pubkey });
      return { ok: true, agent_id: result.agent_id, primary_pubkey: result.primary_pubkey };
    } finally {
      ctx.dispose();
    }
  });

  // M7-SESSION-001: tracks seal-interrupted flows currently in progress.
  // Prevents duplicate concurrent seal-interrupted attempts for the same session (AC-011).
  const sealInterruptedInProgress = new Set<string>();

  // ─── MCP-001: cello_status (per-connection perspective) ───
  handlers.set("cello_status", async (_params, connectionId) => {
    return {
      daemon: "running",
      directory_signaling: signalingManager.status,
      agents: getAgentsForConnection(connectionId),
      connections,
      // M-1 PULL: live MCP clients must see interrupted sessions too, exactly as
      // the daemon-wide getStatus() surfaces them.
      interrupted_sessions: buildInterruptedSessions(),
    };
  });

  // ─── MCP-001: no_current_agent guard for session tools ───
  const SESSION_TOOLS_REQUIRING_AGENT = [
    "cello_send",
    "cello_receive",
    "cello_receive_session",
    "cello_initiate_session",
    "cello_await_session",
    "cello_list_sessions",
  ];

  const NO_CURRENT_AGENT_RESPONSE = {
    ok: false,
    reason: "no_current_agent",
    guidance: "No current agent is set for this connection. Call cello_start_agent to bring an agent online, then call cello_use_agent to set it as the current agent for this connection.",
  };

  for (const tool of SESSION_TOOLS_REQUIRING_AGENT) {
    handlers.set(tool, async (_params, connectionId) => {
      const connState = perConnectionState.get(connectionId);
      if (!connState || !connState.currentAgent) {
        return NO_CURRENT_AGENT_RESPONSE;
      }
      // Stub: actual session tool routing will be implemented in DAEMON-002/SIGNAL-001
      return { ok: false, reason: "not_implemented", guidance: `Session tool '${tool}' routing is not yet implemented in the daemon. This will be available after the session node manager is wired to the IPC layer.` };
    });
  }

  // ─── M7-SESSION-001: cello_close_session ────────────────────────────────────
  // M7 error discipline: each distinct failure cause produces a distinct error code.
  // AC-010: session_already_sealed
  // AC-011: seal_interrupted_in_progress
  // AC-012: seal_interrupted_counterparty_unavailable
  // AC-013: seal_interrupted_rejected_by_counterparty
  // DB-001: signaling_reconnecting
  // SI-001: no auto-seal on session_interrupted receipt; operator must call explicitly
  handlers.set("cello_close_session", async (params, connectionId) => {
    const connState = perConnectionState.get(connectionId);
    if (!connState || !connState.currentAgent) {
      return NO_CURRENT_AGENT_RESPONSE;
    }

    const sessionId = params?.sessionId as string | undefined;
    if (!sessionId) {
      return {
        ok: false,
        reason: "missing_params",
        guidance: "Provide 'sessionId' parameter with the hex session ID to close.",
      };
    }

    const record = sessionNodeManager.getSessionRecord(sessionId);
    if (!record) {
      return {
        ok: false,
        reason: "session_not_found",
        guidance: "No session found with this ID. Check cello_list_sessions for active and interrupted sessions.",
      };
    }

    // AC-010: already sealed
    if (record.status === "sealed") {
      return {
        ok: false,
        reason: "session_already_sealed",
        guidance: "This session is already sealed. No further action is needed — check cello_list_sessions to view its sealed record and the FROST notarization.",
      };
    }

    // AC-011: seal-interrupted already in progress
    if (sealInterruptedInProgress.has(sessionId)) {
      return {
        ok: false,
        reason: "seal_interrupted_in_progress",
        guidance: "A seal-interrupted attempt is already in progress for this session. Wait for session.interrupted.sealed to appear in the daemon logs before retrying. Do not call cello_close_session again until the current attempt completes or times out.",
      };
    }

    // DB-001: signaling stream reconnecting
    if (record.status === "interrupted" && signalingManager.status === "reconnecting") {
      return {
        ok: false,
        reason: "signaling_reconnecting",
        guidance: "The directory signaling stream is reconnecting. Wait for directory_signaling to show connected in cello status before initiating seal-interrupted. The daemon reconnects automatically — no manual intervention required.",
      };
    }

    // AC-012 / AC-013: seal-interrupted bilateral flow for interrupted sessions.
    // BLOCKING-1 fix: await the flow synchronously so the caller receives the real result
    // (counterparty_unavailable, rejected_by_counterparty, or sealed).
    // The sealInterruptedInProgress Set still guards concurrent calls (AC-011).
    if (record.status === "interrupted") {
      // H-1: the Merkle root at interruption is held by the client (the daemon
      // does not maintain the session Merkle tree). The client supplies it here
      // so both parties co-sign over the same root. Absent → empty string, in
      // which case the bilateral commitment binds leafCount only.
      const merkleRootAtInterruption =
        typeof params?.merkleRootAtInterruption === "string" ? params.merkleRootAtInterruption : "";
      sealInterruptedInProgress.add(sessionId);
      const correlationId = randomUUID();
      try {
        return await handleSealInterruptedFlow(sessionId, record, correlationId, merkleRootAtInterruption);
      } finally {
        sealInterruptedInProgress.delete(sessionId);
      }
    }

    // Active session — normal (non-interrupted) close not yet implemented
    return {
      ok: false,
      reason: "not_implemented",
      guidance: "cello_close_session for active sessions is not yet implemented. Use this tool on interrupted sessions (status: 'interrupted') to initiate the seal-interrupted flow.",
    };
  });

  // ─── MCP-001: stubs for tools registered in cello-mcp.ts but not yet implemented ───
  // These return not_implemented (same as session tools) so LLMs get consistent guidance.
  for (const tool of ["cello_backup", "cello_restore", "cello_get_sealed_receipt", "cello_get_inclusion_proof"]) {
    handlers.set(tool, async (_params, _connectionId) => {
      return { ok: false, reason: "not_implemented", guidance: `'${tool}' is not yet implemented in the daemon. This feature will be available in a future milestone.` };
    });
  }

  // DAEMON-003 IPC handlers: queue_failed_send and check_nonce (AC-010)
  handlers.set("queue_failed_send", async (params, _connectionId) => {
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

  handlers.set("check_nonce", async (params, _connectionId) => {
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
  handlers.set("drain_session", async (params, _connectionId) => {
    const sessionId = params?.sessionId as string | undefined;
    if (!sessionId) {
      return { error: "missing_params", guidance: "Provide sessionId." };
    }
    const depth = retryQueue.getSessionDepth(sessionId);
    const entries = retryQueue.getSessionEntries(sessionId);
    return { pendingCount: depth, nonces: entries.map(e => e.nonceHex) };
  });

  // MCP-002: Test-only handler to emit session lifecycle events.
  // Guarded by CELLO_ENV=test — never available in production.
  if (process.env["CELLO_ENV"] === "test") {
  handlers.set("__test_emit_session_event", async (params, _connectionId) => {
    const type = params?.type as string | undefined;
    const sessionId = params?.sessionId as string | undefined;
    const agentName = params?.agentName as string | undefined;
    const counterpartyPubkey = (params?.counterpartyPubkey as string) ?? null;

    if (!type || !sessionId || !agentName) {
      return { error: "missing_params", guidance: "Provide type, sessionId, and agentName." };
    }

    if (type === "created") {
      const sessionPeerId = (params?.sessionPeerId as string) ?? "";
      const correlationId = (params?.correlationId as string) ?? "";
      logger.info("session.node.created", { sessionId, agentName, sessionPeerId, correlationId });
      notificationDispatcher.dispatchSessionStateChanged(agentName, sessionId, "created", counterpartyPubkey);
    } else if (type === "destroyed") {
      const state = (params?.state as string) ?? "interrupted";
      const reason = (params?.reason as string) ?? state;
      logger.info("session.node.destroyed", { sessionId, agentName, reason });
      notificationDispatcher.dispatchSessionStateChanged(agentName, sessionId, state, counterpartyPubkey);
    }

    return { ok: true };
  });
  } // end CELLO_ENV=test guard

  // ─── M7-SESSION-001 (H-1): seal-interrupted bilateral RESPONDER ────────────
  //
  // A PERSISTENT inbound handler (registered once, below) that reacts to inbound
  // `seal_interrupted_request` frames from a counterparty. It validates local
  // state, K_local-signs this node's SEAL-INTERRUPTED leaf (co-signing the same
  // Merkle root the initiator sent), echoes the nonce, includes initiatorPubkey
  // for directory routing, persists the responder side of the commitment, moves
  // the session to 'seal_interrupted_pending', and returns a seal_interrupted_ack.
  // On any inconsistent local state it returns a seal_interrupted_rejection.
  async function handleInboundSealInterruptedRequest(frame: Record<string, unknown>): Promise<void> {
    const correlationId = randomUUID();
    const sessionId = typeof frame["sessionId"] === "string" ? frame["sessionId"] : null;
    const initiatorPubkey = typeof frame["initiatorPubkey"] === "string" ? frame["initiatorPubkey"] : null;
    const counterpartyPubkey = typeof frame["counterpartyPubkey"] === "string" ? frame["counterpartyPubkey"] : null;
    const leafCountReq = typeof frame["leafCountAtInterruption"] === "number" ? frame["leafCountAtInterruption"] : null;
    const merkleRootReq = typeof frame["merkleRootAtInterruption"] === "string" ? frame["merkleRootAtInterruption"] : "";
    const nonce = typeof frame["nonce"] === "string" ? frame["nonce"] : null;

    // Cannot even route a rejection without sessionId + initiatorPubkey.
    if (!sessionId || !initiatorPubkey || !counterpartyPubkey || nonce === null || leafCountReq === null) {
      logger.warn("session.interrupted.request.malformed", {
        correlationId,
        hasSessionId: sessionId !== null,
        hasInitiatorPubkey: initiatorPubkey !== null,
      });
      return;
    }

    const reject = async (reason: string): Promise<void> => {
      await signalingManager.sendRaw({
        type: "seal_interrupted_rejection",
        sessionId,
        initiatorPubkey,
        reason,
      });
      logger.warn("session.interrupted.request.rejected", { sessionId, reason, correlationId });
    };

    const localRecord = sessionNodeManager.getSessionRecord(sessionId);
    if (!localRecord) { await reject("session_not_found"); return; }
    // Only an interrupted session is eligible — never re-process a sealed or
    // already-pending one (and never an active one).
    if (localRecord.status !== "interrupted") { await reject("session_not_interrupted"); return; }
    // The request must be addressed to one of our agents (counterpartyPubkey is
    // OUR pubkey from the initiator's perspective).
    const localAgent = agents.find((a) => a.pubkey === counterpartyPubkey);
    if (!localAgent) { await reject("unknown_counterparty"); return; }
    // From our perspective the initiator is our counterparty.
    if (localRecord.counterparty_pubkey !== initiatorPubkey) { await reject("initiator_mismatch"); return; }
    // SI-002/AC-008: leaf-count agreement against our own state.
    if ((localRecord.message_count ?? 0) !== leafCountReq) { await reject("leaf_count_mismatch"); return; }

    const kp = keyProviders.get(localAgent.name);
    if (!kp) { await reject("signing_key_unavailable"); return; }

    // Co-sign our SEAL-INTERRUPTED leaf over the same Merkle root the initiator sent.
    // C-1: the daemon holds no session Merkle tree, so the responder cannot compute
    // its own root — it echoes the initiator-supplied merkleRootReq back unchanged.
    // The meaningful bilateral check at this layer is the leaf-count comparison above
    // (against our OWN message_count); true Merkle-root agreement is a deferred
    // FROST-seal concern (see the H-1 SCOPE note).
    const ownLeaf = await buildSignedSealInterruptedLeaf(kp, {
      sessionId,
      leafCount: localRecord.message_count ?? 0,
      merkleRootAtInterruption: merkleRootReq,
      signerPubkeyHex: counterpartyPubkey,
    });

    // Persist the responder side of the bilateral commitment. The responder never
    // receives the initiator's leaf in this request→ack protocol, so it records
    // only its own signed leaf plus the agreed root; the full both-leaves artifact
    // lives on the initiator side. Advances status interrupted → seal_interrupted_pending.
    sessionNodeManager.persistSealInterruptedCommitment({
      sessionId,
      role: "responder",
      ownLeaf,
      counterpartyLeaf: null,
      merkleRoot: merkleRootReq,
      nonce,
    });

    const ack = {
      type: "seal_interrupted_ack",
      sessionId,
      initiatorPubkey,
      nonce,
      sealInterruptedLeaf: ownLeaf,
    };
    const sendResult = await signalingManager.sendRaw(ack);
    if (!sendResult.ok) {
      logger.error("session.interrupted.ack.send.failed", {
        sessionId,
        agentName: localAgent.name,
        reason: sendResult.reason,
        correlationId,
      });
      return;
    }
    logger.info("session.interrupted.responder.acked", {
      sessionId,
      agentName: localAgent.name,
      leafCount: localRecord.message_count ?? 0,
      correlationId,
    });
  }

  // Register the persistent responder. This is a REAL registered handler (not a
  // test-only path): it fires for every inbound seal_interrupted_request.
  signalingManager.registerInboundHandler((frame) => {
    if (frame["type"] !== "seal_interrupted_request") return;
    void handleInboundSealInterruptedRequest(frame);
  });

  // M7-SESSION-001 AC-008 (H-1): seal-interrupted bilateral INITIATOR flow.
  //
  // Pseudocode:
  //   1. Check signaling status — if reconnecting, return signaling_reconnecting (DB-001).
  //   2. K_local-sign our OWN SEAL-INTERRUPTED leaf.
  //   3. Send SealInterruptedRequest (with nonce + merkleRoot) via directory signaling.
  //   4. Wait for SealInterruptedAck or SealInterruptedRejection (timeout: 30s).
  //   5. On ack: verify the echoed nonce (L-2); cross-check counterparty leafCount
  //      and merkleRoot against our own (SI-002/AC-008); verify the counterparty's
  //      Ed25519 leaf signature against the expected pubkey (SI-002).
  //   6. On all verified: persist the bilateral commitment and mark the session
  //      'seal_interrupted_pending' — NOT 'sealed'.
  //   7. On any failure: log session.interrupted.seal.failed, leave status 'interrupted'.
  //
  // ⚠️ H-1 SCOPE — what is and is NOT done here:
  //   What IS done (real, verifiable): both parties produce and exchange real
  //   K_local Ed25519-signed SEAL-INTERRUPTED leaves over an agreed {leafCount,
  //   merkleRoot}; the initiator verifies the signature, nonce, and cross-checks;
  //   the verified bilateral commitment is persisted; the session advances to the
  //   NON-TERMINAL 'seal_interrupted_pending' state.
  //   What is NOT done (the FROST threshold notarization) and WHY it is blocked:
  //     - core/daemon does NOT depend on core/client, where SealManager and
  //       FrostThresholdSigner live; adding that dependency risks a cycle and is
  //       deep architectural surgery.
  //     - the daemon holds no FrostThresholdSigner instance and no directory FROST
  //       ceremony client.
  //     - the daemon holds NO session Merkle tree (it tracks only message_count),
  //       so it cannot itself compute or independently verify the Merkle root — the
  //       root must be supplied by the client. The responder in particular has no
  //       synchronous client interaction to obtain its own root; it echoes the
  //       initiator-supplied root back in its leaf rather than computing one.
  //   Consequence for cross-checking (C-1): Merkle-root agreement is NOT verified
  //   at this daemon leaf-exchange layer. The leafCount agreement (responder vs its
  //   own SQLite message_count, and initiator vs its own ownLeafCount) is the
  //   bilateral check available here. True Merkle-root agreement is verified at the
  //   FROST seal step against the directory-held tree, which is deferred. We still
  //   persist the initiator-supplied merkleRootAtInterruption in the artifacts table
  //   because it is the value the eventual FROST seal will use — but the daemon does
  //   not, and cannot, independently verify it.
  //   Per the audit instruction, we therefore STOP at the persisted bilateral
  //   commitment under 'seal_interrupted_pending' rather than fake a completed seal.
  //   Wiring the real FROST seal requires injecting a SealManager adapter from a
  //   composition root that constructs the client alongside the daemon.
  // Result type for handleSealInterruptedFlow — maps to the MCP tool response shape.
  type SealFlowResult =
    | { ok: true; sessionId: string; status: "seal_interrupted_pending" }
    | { ok: false; reason: string; guidance: string };

  async function handleSealInterruptedFlow(
    sessionId: string,
    record: import("./types.js").SessionRecord,
    correlationId: string,
    merkleRootAtInterruption: string,
  ): Promise<SealFlowResult> {
    const nonce = randomUUID();

    // Retrieve the agent's own pubkey from the agent list
    // (the agent_name stored in the session record identifies which agent was in session)
    const agent = agents.find((a) => a.name === record.agent_name);
    const myPubkeyHex = agent?.pubkey ?? "";
    const counterpartyPubkey = record.counterparty_pubkey;
    const ownLeafCount = record.message_count ?? 0;

    // DB-001: check signaling status before attempting to send
    if (signalingManager.status === "reconnecting") {
      logger.error("session.interrupted.seal.failed", {
        sessionId,
        agentName: record.agent_name,
        reason: "signaling_reconnecting",
        error: "directory_signaling_reconnecting",
        correlationId,
      });
      return {
        ok: false,
        reason: "signaling_reconnecting",
        guidance: "The directory signaling stream is reconnecting. Wait for directory_signaling to show connected in cello status before initiating seal-interrupted. The daemon reconnects automatically — no manual intervention required.",
      };
    }

    // H-1: construct and K_local-sign our OWN SEAL-INTERRUPTED leaf before sending.
    const myKeyProvider = keyProviders.get(record.agent_name);
    if (!myKeyProvider) {
      logger.error("session.interrupted.seal.failed", {
        sessionId,
        agentName: record.agent_name,
        reason: "signing_key_unavailable",
        error: "no_key_provider_for_agent",
        correlationId,
      });
      return {
        ok: false,
        reason: "signing_key_unavailable",
        guidance: "The signing key for the agent that owned this session could not be loaded. Confirm the agent's key file exists under ~/.cello/agents and restart the daemon.",
      };
    }
    const ownLeaf = await buildSignedSealInterruptedLeaf(myKeyProvider, {
      sessionId,
      leafCount: ownLeafCount,
      merkleRootAtInterruption,
      signerPubkeyHex: myPubkeyHex,
    });

    // Send SealInterruptedRequest via directory signaling
    const request = {
      type: "seal_interrupted_request",
      sessionId,
      initiatorPubkey: myPubkeyHex,
      counterpartyPubkey,
      leafCountAtInterruption: ownLeafCount,
      merkleRootAtInterruption,
      nonce,
    };

    const sendResult = await signalingManager.sendRaw(request);
    if (!sendResult.ok) {
      logger.error("session.interrupted.seal.failed", {
        sessionId,
        agentName: record.agent_name,
        reason: "seal_interrupted_counterparty_unavailable",
        error: sendResult.reason,
        correlationId,
      });
      return {
        ok: false,
        reason: "seal_interrupted_counterparty_unavailable",
        guidance: "The counterparty is not currently reachable to complete the seal-interrupted flow. Retry when the counterparty is online — check their connection status via cello_list_connections.",
      };
    }

    // Wait for counterparty ack/rejection via registered inbound handler
    const SEAL_INTERRUPTED_TIMEOUT_MS = 30_000;
    type AckResult =
      | { type: "seal_interrupted_ack"; sealInterruptedLeaf: Record<string, unknown>; nonce: string | null }
      | { type: "seal_interrupted_rejection"; reason: string }
      | { type: "timeout" };

    const ackResult = await new Promise<AckResult>((resolve) => {
      const timeoutHandle = setTimeout(() => {
        unregister();
        resolve({ type: "timeout" });
      }, SEAL_INTERRUPTED_TIMEOUT_MS);

      const unregister = signalingManager.registerInboundHandler((frame) => {
        if (frame.type !== "seal_interrupted_ack" && frame.type !== "seal_interrupted_rejection") {
          return;
        }
        if (typeof frame.sessionId !== "string" || frame.sessionId !== sessionId) return;

        clearTimeout(timeoutHandle);
        unregister();

        if (frame.type === "seal_interrupted_ack") {
          resolve({
            type: "seal_interrupted_ack",
            sealInterruptedLeaf: (frame.sealInterruptedLeaf as Record<string, unknown>) ?? {},
            nonce: typeof frame.nonce === "string" ? frame.nonce : null,
          });
        } else {
          resolve({
            type: "seal_interrupted_rejection",
            reason: typeof frame.reason === "string" ? frame.reason : "unknown",
          });
        }
      });
    });

    if (ackResult.type === "timeout") {
      logger.error("session.interrupted.seal.failed", {
        sessionId,
        agentName: record.agent_name,
        reason: "seal_interrupted_counterparty_unavailable",
        error: "seal_interrupted_response_timeout",
        correlationId,
      });
      return {
        ok: false,
        reason: "seal_interrupted_counterparty_unavailable",
        guidance: "The counterparty is not currently reachable to complete the seal-interrupted flow. Retry when the counterparty is online — check their connection status via cello_list_connections.",
      };
    }

    if (ackResult.type === "seal_interrupted_rejection") {
      logger.error("session.interrupted.seal.failed", {
        sessionId,
        agentName: record.agent_name,
        reason: "seal_interrupted_rejected_by_counterparty",
        error: ackResult.reason,
        correlationId,
      });
      return {
        ok: false,
        reason: "seal_interrupted_rejected_by_counterparty",
        guidance: "The counterparty rejected the seal-interrupted request. This may indicate their session state is inconsistent. Ask the counterparty to check their interrupted sessions via cello status on their end.",
      };
    }

    // ackResult.type === "seal_interrupted_ack"
    {
      const leaf = ackResult.sealInterruptedLeaf;

      // L-2: the counterparty MUST echo the exact nonce we sent. A missing or
      // mismatched nonce indicates a stale or replayed response — reject it.
      if (ackResult.nonce !== nonce) {
        logger.error("session.interrupted.seal.failed", {
          sessionId,
          agentName: record.agent_name,
          reason: "seal_interrupted_nonce_mismatch",
          error: "ack nonce did not match the request nonce",
          correlationId,
        });
        return {
          ok: false,
          reason: "seal_interrupted_nonce_mismatch",
          guidance: "The counterparty's acknowledgement did not echo the expected nonce. This indicates a stale or replayed response. The session remains interrupted — retry cello_close_session.",
        };
      }

      // C-1 / SI-002 / AC-008: leafCount agreement is the ONE bilateral check
      // available at this layer. We compare the counterparty's returned leafCount
      // against our OWN message_count — a genuinely independent value — so a real
      // divergence in session length is caught here.
      //
      // Merkle-root agreement is NOT verified at the daemon leaf-exchange layer
      // because the daemon holds no session Merkle tree. The responder does not
      // independently compute a root; it echoes the initiator-supplied
      // merkleRootAtInterruption back in its leaf, so comparing the returned root
      // against our own would always be true for an honest network and could only
      // ever fire on wire corruption — never on real divergence. We therefore do
      // NOT perform that comparison rather than claim a guarantee we cannot provide.
      // True Merkle-root agreement is verified at the FROST seal step against the
      // directory-held tree, which is deferred (see the H-1 SCOPE note above).
      const cpLeafCount = typeof leaf.leafCount === "number" ? leaf.leafCount : null;
      if (cpLeafCount !== ownLeafCount) {
        logger.error("session.interrupted.seal.failed", {
          sessionId,
          agentName: record.agent_name,
          reason: "seal_interrupted_leaf_count_mismatch",
          error: `counterparty leafCount ${String(cpLeafCount)} != own leafCount ${ownLeafCount}`,
          correlationId,
        });
        return {
          ok: false,
          reason: "seal_interrupted_leaf_count_mismatch",
          guidance: "The counterparty's recorded message count at interruption does not match ours. The two sides have divergent session histories and cannot form a bilateral commitment. Compare cello status on both ends before retrying.",
        };
      }

      // SI-002: verify counterparty's K_local Ed25519 signature on the SEAL-INTERRUPTED leaf.
      // The leaf.signerPubkey must match the expected counterparty pubkey (record.counterparty_pubkey).
      // Canonical leaf content to verify: JSON.stringify({type, sessionId, leafCount,
      //   merkleRootAtInterruption, timestamp, signerPubkey}) — deterministic field ordering.
      let sigVerified = false;
      try {
        const signerPubkeyHex = typeof leaf.signerPubkey === "string" ? leaf.signerPubkey : null;
        const signatureHex = typeof leaf.signature === "string" ? leaf.signature : null;
        if (!signerPubkeyHex || !signatureHex) {
          throw new Error("leaf missing signerPubkey or signature");
        }
        // SI-002: signerPubkey must match the expected counterparty
        if (signerPubkeyHex !== record.counterparty_pubkey) {
          throw new Error(`leaf signerPubkey ${signerPubkeyHex.slice(0, 16)} does not match counterparty ${record.counterparty_pubkey.slice(0, 16)}`);
        }
        const canonicalLeaf = {
          type: leaf.type,
          sessionId: leaf.sessionId,
          leafCount: leaf.leafCount,
          merkleRootAtInterruption: leaf.merkleRootAtInterruption,
          timestamp: leaf.timestamp,
          signerPubkey: leaf.signerPubkey,
        };
        const leafBytes = new TextEncoder().encode(JSON.stringify(canonicalLeaf));
        const pubkeyBytes = new Uint8Array(Buffer.from(signerPubkeyHex, "hex"));
        const sigBytes = new Uint8Array(Buffer.from(signatureHex, "hex"));
        sigVerified = ed25519Verify(pubkeyBytes, leafBytes, sigBytes);
      } catch (verifyErr: unknown) {
        logger.error("session.interrupted.seal.failed", {
          sessionId,
          agentName: record.agent_name,
          reason: "seal_interrupted_leaf_signature_invalid",
          error: verifyErr instanceof Error ? verifyErr.message : String(verifyErr),
          correlationId,
        });
        return {
          ok: false,
          reason: "seal_interrupted_leaf_signature_invalid",
          guidance: "The counterparty's SEAL-INTERRUPTED leaf signature could not be verified. The seal flow has been aborted. The session remains interrupted — retry cello_close_session after confirming the counterparty is using a compatible version.",
        };
      }

      if (!sigVerified) {
        logger.error("session.interrupted.seal.failed", {
          sessionId,
          agentName: record.agent_name,
          reason: "seal_interrupted_leaf_signature_invalid",
          error: "Ed25519 signature verification failed on SEAL-INTERRUPTED leaf",
          correlationId,
        });
        return {
          ok: false,
          reason: "seal_interrupted_leaf_signature_invalid",
          guidance: "The counterparty's SEAL-INTERRUPTED leaf signature did not verify. The seal flow has been aborted. The session remains interrupted — retry cello_close_session after confirming the counterparty is using a compatible version.",
        };
      }

      // H-1: signature + nonce + cross-checks all passed. We have a VERIFIED
      // bilateral commitment (both K_local-signed leaves over the same
      // {leafCount, merkleRoot}). Persist BOTH leaves and advance the session to
      // the NON-TERMINAL 'seal_interrupted_pending' state. We do NOT write
      // 'sealed' — the FROST threshold notarization has not run (see the H-1
      // SCOPE note above for exactly what blocks it).
      const advanced = sessionNodeManager.persistSealInterruptedCommitment({
        sessionId,
        role: "initiator",
        ownLeaf,
        counterpartyLeaf: leaf,
        merkleRoot: merkleRootAtInterruption,
        nonce,
      });
      if (!advanced) {
        logger.error("session.interrupted.seal.failed", {
          sessionId,
          agentName: record.agent_name,
          reason: "seal_interrupted_persist_failed",
          error: "session row was not in 'interrupted' state at commit time",
          correlationId,
        });
        return {
          ok: false,
          reason: "seal_interrupted_persist_failed",
          guidance: "The bilateral commitment could not be persisted because the session was no longer in the interrupted state. Re-check cello status — it may already be pending or sealed.",
        };
      }
      logger.info("session.interrupted.pending", {
        sessionId,
        agentName: record.agent_name,
        leafCount: ownLeafCount,
        correlationId,
      });
      return { ok: true, sessionId, status: "seal_interrupted_pending" };
    }
  }

  let shutdownPromise: Promise<void> | null = null;
  handlers.set("shutdown", async (_params, _connectionId) => {
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

  // MCP-002: Instantiate NotificationDispatcher (wired to IPC server)
  const notificationDispatcher = new NotificationDispatcher({
    logger,
    sendNotification: (connectionId, notification) => ipcServer.sendNotification(connectionId, notification),
    getConnectionIds: () => ipcServer.getConnectionIds(),
  });

  // M7-SESSION-001 (M-1 PUSH): now that the dispatcher exists, wire the session
  // node manager so that an active→interrupted transition pushes a
  // session_state_changed notification to live MCP clients. Setter injection is
  // used because the dispatcher is constructed AFTER the SessionNodeManager
  // (it depends on the IPC server), so constructor injection would be circular.
  sessionNodeManager.setOnSessionStateChanged((agentName, sessionId, state, counterpartyPubkey) => {
    notificationDispatcher.dispatchSessionStateChanged(agentName, sessionId, state, counterpartyPubkey);
  });

  // MCP-001: Clean up per-connection state when a connection disconnects
  // MCP-002: Also unregister from notification dispatcher
  ipcServer.onDisconnect((connectionId) => {
    perConnectionState.delete(connectionId);
    notificationDispatcher.unregisterConnection(connectionId);
  });

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

  // M7-MANIFEST-002: Background manifest polling.
  // TODO(SIGNAL-001): Wire real SignalingManager here when SIGNAL-001 integrates the
  // signaling stream. The poll scheduler + outbound queue need a live signaling stream
  // to deliver manifest_poll_request frames. Until then, polling is deferred.
  if (manifestPollScheduler && manifestVerified) {
    logger.debug("directory.auth.manifest.poll.deferred", {
      reason: "signaling_stream_not_yet_wired",
    });
  }

  // Graceful shutdown
  async function stop(reason: string): Promise<void> {
    // Cancel any pending manifest poll timer
    if (manifestPollScheduler) {
      manifestPollScheduler.cancel();
    }
    logger.info("daemon.stopped", { pid: process.pid, reason });
    // Stop SignalingManager (flushes pending ops with shutdown error, cancels reconnect loop)
    await signalingManager.stop();
    // Gracefully mark active sessions interrupted (AC-009) before stopping IPC
    await sessionNodeManager.gracefulShutdown();
    await ipcServer.stop();
    await removeLock(lockFilePath, logger);
  }

  function getSessionNodeManager(): SessionNodeManager {
    return sessionNodeManager;
  }

  return { stop, getStatus, getSessionNodeManager, getDirectoryNode };
}
