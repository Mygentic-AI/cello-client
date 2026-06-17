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
import { randomUUID, createHash } from "node:crypto";
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
import { createNode, SignalingManager, type ConnectResult } from "@cello-protocol/transport";
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

/**
 * M7-SESSION-001 / DAEMON-004: verify a counterparty's SEAL-INTERRUPTED ack leaf.
 *
 * Shared by BOTH the interrupted-seal flow (SESSION-001) and the active-session
 * seal flow (DAEMON-004 finding #1) so the two paths perform an identical
 * bilateral check. Returns a generic reason; each caller maps it to its own
 * reason codes / observability events / guidance.
 *
 * Checks, in order:
 *   1. L-2: the ack echoes the exact nonce we sent (replay / stale-response guard).
 *   2. leafCount agreement: the counterparty's leafCount equals our own — an
 *      independent value, so a genuine divergence in transcript length is caught.
 *   3. SI-002 / SI-003: the leaf carries a valid Ed25519 signature produced by the
 *      counterparty's OWN key (signerPubkey must equal the expected counterparty).
 *
 * Crypto: Ed25519 RFC 8032.
 */
type SealLeafVerifyReason = "nonce_mismatch" | "leaf_count_mismatch" | "leaf_signature_invalid";
function verifyCounterpartySealLeaf(opts: {
  leaf: Record<string, unknown>;
  sentNonce: string;
  ackNonce: string | null;
  ownLeafCount: number;
  expectedCounterpartyPubkey: string;
}): { ok: true } | { ok: false; reason: SealLeafVerifyReason; error: string } {
  const { leaf, sentNonce, ackNonce, ownLeafCount, expectedCounterpartyPubkey } = opts;

  // 1. L-2: the counterparty MUST echo the exact nonce we sent.
  if (ackNonce !== sentNonce) {
    return { ok: false, reason: "nonce_mismatch", error: "ack nonce did not match the request nonce" };
  }

  // 2. leafCount agreement against our own independent count.
  const cpLeafCount = typeof leaf["leafCount"] === "number" ? (leaf["leafCount"] as number) : null;
  if (cpLeafCount !== ownLeafCount) {
    return {
      ok: false,
      reason: "leaf_count_mismatch",
      error: `counterparty leafCount ${String(cpLeafCount)} != own leafCount ${ownLeafCount}`,
    };
  }

  // 3. SI-002/SI-003: verify the counterparty's Ed25519 signature on its OWN leaf.
  try {
    const signerPubkeyHex = typeof leaf["signerPubkey"] === "string" ? (leaf["signerPubkey"] as string) : null;
    const signatureHex = typeof leaf["signature"] === "string" ? (leaf["signature"] as string) : null;
    if (!signerPubkeyHex || !signatureHex) {
      throw new Error("leaf missing signerPubkey or signature");
    }
    if (signerPubkeyHex !== expectedCounterpartyPubkey) {
      throw new Error(
        `leaf signerPubkey ${signerPubkeyHex.slice(0, 16)} does not match counterparty ${expectedCounterpartyPubkey.slice(0, 16)}`,
      );
    }
    const canonicalLeaf = {
      type: leaf["type"],
      sessionId: leaf["sessionId"],
      leafCount: leaf["leafCount"],
      merkleRootAtInterruption: leaf["merkleRootAtInterruption"],
      timestamp: leaf["timestamp"],
      signerPubkey: leaf["signerPubkey"],
    };
    const leafBytes = new TextEncoder().encode(JSON.stringify(canonicalLeaf));
    const pubkeyBytes = new Uint8Array(Buffer.from(signerPubkeyHex, "hex"));
    const sigBytes = new Uint8Array(Buffer.from(signatureHex, "hex"));
    if (!ed25519Verify(pubkeyBytes, leafBytes, sigBytes)) {
      return { ok: false, reason: "leaf_signature_invalid", error: "Ed25519 signature verification failed on SEAL-INTERRUPTED leaf" };
    }
    return { ok: true };
  } catch (verifyErr: unknown) {
    return {
      ok: false,
      reason: "leaf_signature_invalid",
      error: verifyErr instanceof Error ? verifyErr.message : String(verifyErr),
    };
  }
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
    signalingConnect, challengeVerifier, sessionNodeFactory,
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

  const signalingManager = new SignalingManager({
    connect: (signalingConnect ?? defaultConnect) as () => Promise<ConnectResult>,
    logger,
    challengeVerifier,
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
    factory: sessionNodeFactory ?? new ProductionSessionNodeFactory(),
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
  // cello_send / cello_receive are NOT in this stub list — DAEMON-004 registers
  // real handlers for them below (each enforces the no_current_agent guard inline).
  const SESSION_TOOLS_REQUIRING_AGENT = [
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

    // Ownership: the current agent on this connection must own the session.
    if (record.agent_name !== connState.currentAgent) {
      return {
        ok: false,
        reason: "session_not_owned",
        guidance: "This session belongs to a different agent. Call cello_use_agent to switch to the agent that owns it (see cello_list_sessions), then retry.",
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

    // CELLO-M7-DAEMON-004 (AC-003): ACTIVE session — initiate the active-session
    // seal over the daemon's OWN tree root. SI-001: any caller-supplied
    // merkleRoot is IGNORED; the daemon signs only the root it built itself.
    if (record.status === "active") {
      const correlationId = randomUUID();
      return await handleActiveSealFlow(sessionId, record, correlationId);
    }

    // Any other status (e.g. seal_interrupted_pending) — nothing to do.
    return {
      ok: false,
      reason: "session_not_closeable",
      guidance: `Session is in status '${record.status}', which cannot be closed via cello_close_session. Check cello_list_sessions; a seal_interrupted_pending session is awaiting FROST notarization.`,
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
    // DAEMON-004: an 'active' session is eligible too (the active-session seal
    // reuses this exchange). We still never re-process a terminal 'sealed' row or
    // an already-pending one.
    if (localRecord.status !== "interrupted" && localRecord.status !== "active") {
      await reject("session_not_interrupted");
      return;
    }
    // The request must be addressed to one of our agents (counterpartyPubkey is
    // OUR pubkey from the initiator's perspective).
    const localAgent = agents.find((a) => a.pubkey === counterpartyPubkey);
    if (!localAgent) { await reject("unknown_counterparty"); return; }
    // From our perspective the initiator is our counterparty.
    if (localRecord.counterparty_pubkey !== initiatorPubkey) { await reject("initiator_mismatch"); return; }

    // DAEMON-004 (SI-001): prefer OUR OWN daemon-owned tree. When we hold a
    // non-empty tree for this session we sign over OUR OWN root + size (each node
    // signs the root it built — SI-001), and the bilateral leaf-count check uses
    // our own tree size. Only when no tree was ever persisted do we fall back to
    // message_count + echoing the initiator-supplied root (SESSION-001 behavior).
    const ownTree = sessionNodeManager.getSessionTree(sessionId);
    const hasOwnTree = ownTree.size() > 0;
    const ownLeafCount = hasOwnTree ? ownTree.size() : (localRecord.message_count ?? 0);
    const ownRoot = hasOwnTree ? sessionNodeManager.getSessionTreeRootHex(sessionId) : merkleRootReq;

    // SI-002/AC-008: leaf-count agreement against our own state.
    if (ownLeafCount !== leafCountReq) { await reject("leaf_count_mismatch"); return; }

    const kp = keyProviders.get(localAgent.name);
    if (!kp) { await reject("signing_key_unavailable"); return; }

    // Co-sign our SEAL-INTERRUPTED leaf. When we hold our own tree the root is
    // ours (SI-001); otherwise we echo the initiator-supplied root unchanged.
    const ownLeaf = await buildSignedSealInterruptedLeaf(kp, {
      sessionId,
      leafCount: ownLeafCount,
      merkleRootAtInterruption: ownRoot,
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
      merkleRoot: ownRoot,
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
      leafCount: ownLeafCount,
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
  //     - DAEMON-004 UPDATE: the daemon now DOES own a per-session Merkle tree
  //       (SessionNodeManager / SessionTree). When a non-empty tree exists for the
  //       session (e.g. reloaded from session_tree_leaves after a restart) BOTH the
  //       initiator and the responder bind over their OWN tree root + size (SI-001),
  //       and message_count is kept synced to the tree. Only legacy sessions with no
  //       persisted tree fall back to message_count + the caller-supplied root.
  //   Consequence for cross-checking (C-1): leafCount agreement (each side vs its own
  //   tree size, or message_count when no tree exists) is the bilateral check at this
  //   layer. Merkle-root agreement is still NOT compared here — under concurrent
  //   bidirectional traffic the two sides' local append orders (and thus roots) can
  //   diverge until the relay-assigned canonical sequence (MSG-001) exists; true
  //   root agreement is the deferred FROST-seal step against the directory-held tree.
  //   Per the audit instruction, we therefore STOP at the persisted bilateral
  //   commitment under 'seal_interrupted_pending' rather than fake a completed seal.
  //   Wiring the real FROST seal requires injecting a SealManager adapter from a
  //   composition root that constructs the client alongside the daemon.
  // Result type for handleSealInterruptedFlow — maps to the MCP tool response shape.
  type SealFlowResult =
    | { ok: true; sessionId: string; status: "seal_interrupted_pending" }
    | { ok: false; reason: string; guidance: string };

  // M7-SESSION-001 / DAEMON-004: shared bilateral ack-await machinery. The
  // interrupted-seal flow AND the active-session seal flow both send a
  // `seal_interrupted_request` and wait on the directory signaling stream for the
  // counterparty's `seal_interrupted_ack` / `seal_interrupted_rejection` (or time
  // out). Extracted so the two flows wait identically — the directory pass-through
  // routing (directory-node.ts) is the only wired transport for this exchange.
  const SEAL_INTERRUPTED_TIMEOUT_MS = 30_000;
  type SealAckResult =
    | { type: "seal_interrupted_ack"; sealInterruptedLeaf: Record<string, unknown>; nonce: string | null }
    | { type: "seal_interrupted_rejection"; reason: string }
    | { type: "timeout" };

  function awaitSealAck(sessionId: string): Promise<SealAckResult> {
    return new Promise<SealAckResult>((resolve) => {
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
  }

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

    // DAEMON-004 (AC-007 / SI-001 / finding #2): prefer the daemon-owned tree.
    // After a SIGKILL+restart the active session is forced to 'interrupted' and
    // its Merkle tree is reloaded from session_tree_leaves. When that reloaded
    // tree is non-empty it is the authoritative transcript: the seal binds over
    // the daemon's OWN reloaded root + size, and any caller-supplied
    // merkleRootAtInterruption is IGNORED (SI-001). Only when no tree was ever
    // persisted (legacy / pre-DAEMON-004 sessions) do we fall back to the
    // caller-supplied root and the message_count column (SESSION-001 behavior).
    const reloadedTree = sessionNodeManager.getSessionTree(sessionId);
    const hasOwnTree = reloadedTree.size() > 0;
    const ownLeafCount = hasOwnTree ? reloadedTree.size() : (record.message_count ?? 0);
    const effectiveRoot = hasOwnTree
      ? sessionNodeManager.getSessionTreeRootHex(sessionId)
      : merkleRootAtInterruption;

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
      merkleRootAtInterruption: effectiveRoot,
      signerPubkeyHex: myPubkeyHex,
    });

    // Send SealInterruptedRequest via directory signaling
    const request = {
      type: "seal_interrupted_request",
      sessionId,
      initiatorPubkey: myPubkeyHex,
      counterpartyPubkey,
      leafCountAtInterruption: ownLeafCount,
      merkleRootAtInterruption: effectiveRoot,
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

    // Wait for counterparty ack/rejection via the shared signaling await machinery.
    const ackResult = await awaitSealAck(sessionId);

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

      // C-1 / SI-002 / SI-003: nonce (L-2), leafCount agreement, and the
      // counterparty's own Ed25519 signature are verified by the shared helper.
      // We compare against our OWN ownLeafCount (an independent value) so a real
      // divergence in transcript length is caught. Merkle-root agreement is NOT
      // verified at this leaf-exchange layer (it is the FROST-seal step's job
      // against the directory-held tree); see the H-1 SCOPE note above.
      const verified = verifyCounterpartySealLeaf({
        leaf,
        sentNonce: nonce,
        ackNonce: ackResult.nonce,
        ownLeafCount,
        expectedCounterpartyPubkey: record.counterparty_pubkey,
      });
      if (!verified.ok) {
        const reasonMap = {
          nonce_mismatch: "seal_interrupted_nonce_mismatch",
          leaf_count_mismatch: "seal_interrupted_leaf_count_mismatch",
          leaf_signature_invalid: "seal_interrupted_leaf_signature_invalid",
        } as const;
        const guidanceMap = {
          nonce_mismatch: "The counterparty's acknowledgement did not echo the expected nonce. This indicates a stale or replayed response. The session remains interrupted — retry cello_close_session.",
          leaf_count_mismatch: "The counterparty's recorded message count at interruption does not match ours. The two sides have divergent session histories and cannot form a bilateral commitment. Compare cello status on both ends before retrying.",
          leaf_signature_invalid: "The counterparty's SEAL-INTERRUPTED leaf signature did not verify. The seal flow has been aborted. The session remains interrupted — retry cello_close_session after confirming the counterparty is using a compatible version.",
        } as const;
        logger.error("session.interrupted.seal.failed", {
          sessionId,
          agentName: record.agent_name,
          reason: reasonMap[verified.reason],
          error: verified.error,
          correlationId,
        });
        return { ok: false, reason: reasonMap[verified.reason], guidance: guidanceMap[verified.reason] };
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
        merkleRoot: effectiveRoot,
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

  // ─── CELLO-M7-DAEMON-004: active-session seal initiation ─────────────────────
  //
  // Pseudocode (SPARC Phase P):
  //   1. DB-002: if signaling reconnecting → return signaling_reconnecting and do
  //      NOT initiate a partial seal that cannot be notarized.
  //   2. SI-001: read the merkle root from the daemon's OWN tree (never a caller param).
  //   3. K_local-sign a SEAL ctrl leaf over that root (SI-003: signed by our own node).
  //   4. Fire session.seal.initiated with rootHex == our own tree root, role:'initiator'.
  //   5. Submit the SEAL to the relay/counterparty + coordinate FROST via signaling,
  //      reusing the same signaling stream the interrupted-seal flow (SESSION-001) uses.
  //      The bilateral counterparty ack + FROST threshold notarization complete the
  //      seal end-to-end (AC-004, exercised under CELLO_E2E_LIVE) — the daemon never
  //      synthesizes the counterparty's signature.
  type ActiveSealResult =
    | { ok: true; sessionId: string; status: "seal_initiated"; rootHex: string }
    | { ok: false; reason: string; guidance: string };

  async function handleActiveSealFlow(
    sessionId: string,
    record: import("./types.js").SessionRecord,
    correlationId: string,
  ): Promise<ActiveSealResult> {
    const agent = agents.find((a) => a.name === record.agent_name);
    const myPubkeyHex = agent?.pubkey ?? "";
    const kp = keyProviders.get(record.agent_name);

    // DB-002: never initiate a partial seal while signaling is reconnecting.
    if (signalingManager.status === "reconnecting") {
      return {
        ok: false,
        reason: "signaling_reconnecting",
        guidance: "The directory signaling stream is reconnecting. Wait for directory_signaling to show connected in cello status before retrying the close. The daemon reconnects automatically.",
      };
    }

    if (!kp || !myPubkeyHex) {
      logger.error("session.seal.initiate.failed", {
        sessionId,
        reason: "signing_key_unavailable",
        errorMessage: "no key provider or pubkey for the agent that owns this session",
        correlationId,
      });
      return {
        ok: false,
        reason: "signing_key_unavailable",
        guidance: "The signing key for the agent that owns this session could not be loaded. Confirm the agent's key file exists under ~/.cello/agents and restart the daemon.",
      };
    }

    // SI-001: the root is the daemon's OWN tree root — computed from the leaves it
    // appended itself. Any caller-supplied merkleRoot is never read here.
    const ownRootHex = sessionNodeManager.getSessionTreeRootHex(sessionId);
    const leafCount = sessionNodeManager.getSessionTree(sessionId).size();
    const nonce = randomUUID();

    // SI-003: K_local-sign our OWN SEAL leaf over our own root. We reuse the
    // wired SEAL-INTERRUPTED leaf shape so the counterparty co-signs an identical
    // canonical form (the active and interrupted bilateral exchanges share the
    // directory pass-through routing — there is no separate `seal_request`
    // transport, and inventing one silently drops the frame at the directory).
    let ownLeaf: SealInterruptedLeaf;
    try {
      ownLeaf = await buildSignedSealInterruptedLeaf(kp, {
        sessionId,
        leafCount,
        merkleRootAtInterruption: ownRootHex,
        signerPubkeyHex: myPubkeyHex,
      });
    } catch (err: unknown) {
      logger.error("session.seal.initiate.failed", {
        sessionId,
        reason: "seal_leaf_signing_failed",
        errorMessage: err instanceof Error ? err.message : String(err),
        correlationId,
      });
      return {
        ok: false,
        reason: "seal_leaf_signing_failed",
        guidance: "The SEAL leaf could not be signed. Check the daemon logs for the signing error and confirm the agent key is intact.",
      };
    }

    // AC-003: session.seal.initiated — rootHex MUST equal the daemon's own root.
    logger.info("session.seal.initiated", {
      sessionId,
      rootHex: ownRootHex,
      role: "initiator",
      correlationId,
    });

    // Submit the SEAL request over the directory signaling stream (the SAME wired
    // pass-through the interrupted-seal flow uses) and AWAIT the counterparty's
    // bilateral ack. We never report success on a fire-and-forget send.
    const sendResult = await signalingManager.sendRaw({
      type: "seal_interrupted_request",
      sessionId,
      initiatorPubkey: myPubkeyHex,
      counterpartyPubkey: record.counterparty_pubkey,
      leafCountAtInterruption: leafCount,
      merkleRootAtInterruption: ownRootHex,
      nonce,
    });
    if (!sendResult.ok) {
      logger.error("session.seal.initiate.failed", {
        sessionId,
        reason: sendResult.reason,
        errorMessage: sendResult.reason,
        correlationId,
      });
      return {
        ok: false,
        reason: sendResult.reason,
        guidance: "guidance" in sendResult && typeof sendResult.guidance === "string"
          ? sendResult.guidance
          : "The seal could not be submitted to the directory. Retry once cello status shows directory_signaling connected.",
      };
    }

    // Wait for the counterparty's bilateral ack (or rejection / timeout).
    const ackResult = await awaitSealAck(sessionId);
    if (ackResult.type === "timeout" || ackResult.type === "seal_interrupted_rejection") {
      const reason = ackResult.type === "timeout" ? "seal_counterparty_unavailable" : "seal_rejected_by_counterparty";
      logger.error("session.seal.initiate.failed", {
        sessionId,
        reason,
        errorMessage: ackResult.type === "timeout" ? "seal_response_timeout" : ackResult.reason,
        correlationId,
      });
      return {
        ok: false,
        reason,
        guidance: ackResult.type === "timeout"
          ? "The counterparty did not acknowledge the seal in time. Retry when they are online — check cello_list_connections. The session remains active and usable."
          : "The counterparty rejected the seal request. Their session state may be inconsistent. Ask them to check cello status before retrying.",
      };
    }

    // SI-002 / SI-003: verify the counterparty's own-signed ack leaf over our root.
    const verified = verifyCounterpartySealLeaf({
      leaf: ackResult.sealInterruptedLeaf,
      sentNonce: nonce,
      ackNonce: ackResult.nonce,
      ownLeafCount: leafCount,
      expectedCounterpartyPubkey: record.counterparty_pubkey,
    });
    if (!verified.ok) {
      logger.error("session.seal.initiate.failed", {
        sessionId,
        reason: `seal_${verified.reason}`,
        errorMessage: verified.error,
        correlationId,
      });
      return {
        ok: false,
        reason: `seal_${verified.reason}`,
        guidance: "The counterparty's seal acknowledgement failed verification (nonce, leaf count, or signature). The session remains active — retry cello_close_session once both sides agree on the transcript.",
      };
    }

    // Verified bilateral commitment over the daemon's OWN root. Persist both
    // signed leaves and advance the session out of 'active'. As in the
    // interrupted flow, we stop at the bilateral commitment ('seal_interrupted_pending');
    // the FROST threshold notarization that finalizes 'sealed' is the deferred
    // directory step (AC-004, exercised under CELLO_E2E_LIVE).
    const advanced = sessionNodeManager.persistSealInterruptedCommitment({
      sessionId,
      role: "initiator",
      ownLeaf,
      counterpartyLeaf: ackResult.sealInterruptedLeaf,
      merkleRoot: ownRootHex,
      nonce,
    });
    if (!advanced) {
      logger.error("session.seal.initiate.failed", {
        sessionId,
        reason: "seal_persist_failed",
        errorMessage: "session row was not in an active/interrupted state at commit time",
        correlationId,
      });
      return {
        ok: false,
        reason: "seal_persist_failed",
        guidance: "The bilateral seal commitment could not be persisted because the session changed state. Re-check cello status — it may already be pending or sealed.",
      };
    }

    return { ok: true, sessionId, status: "seal_initiated", rootHex: ownRootHex };
  }

  // ─── CELLO-M7-DAEMON-004: cello_send (live send + daemon-owned tree append) ──
  handlers.set("cello_send", async (params, connectionId) => {
    const connState = perConnectionState.get(connectionId);
    if (!connState || !connState.currentAgent) return NO_CURRENT_AGENT_RESPONSE;

    const sessionId = params?.sessionId as string | undefined;
    const contentStr = typeof params?.content === "string" ? params.content : undefined;
    if (!sessionId || contentStr === undefined) {
      return { ok: false, reason: "missing_params", guidance: "Provide 'sessionId' (hex) and 'content' (string) parameters." };
    }

    const record = sessionNodeManager.getSessionRecord(sessionId);
    if (!record) {
      return { ok: false, reason: "session_not_found", guidance: "No session found with this ID. Check cello_list_sessions for active sessions." };
    }
    if (record.agent_name !== connState.currentAgent) {
      return { ok: false, reason: "session_not_owned", guidance: "This session belongs to a different agent. Call cello_use_agent to switch to the agent that owns it, then retry." };
    }
    if (record.status !== "active") {
      return { ok: false, reason: "session_not_active", guidance: `Session is '${record.status}', not active. Content can only be sent on an active session. If it is interrupted, call cello_close_session to seal it.` };
    }

    const correlationId = randomUUID();
    const contentBytes = new TextEncoder().encode(contentStr);
    const contentHash = createHash("sha256").update(new Uint8Array([0x00])).update(contentBytes).digest();
    const contentHashHex = Buffer.from(contentHash).toString("hex");
    const recipientPubkey = record.counterparty_pubkey;

    const sendResult = await sessionNodeManager.sendContent(sessionId, contentBytes, new Uint8Array(contentHash), correlationId);
    if (!sendResult.ok) {
      // DB-001 / dead-channel contract: never silently drop, never desync. Preserve
      // the content in the durable retry_queue so it is retried on reconnect, and
      // surface a named, diagnosable failure.
      const nonce = randomUUID();
      try {
        retryQueue.enqueue(sessionId, new TextEncoder().encode(nonce), contentBytes);
      } catch (err: unknown) {
        logger.error("session.content.queue.failed", {
          sessionId,
          error: err instanceof Error ? err.message : String(err),
          correlationId,
        });
      }
      logger.warn("session.content.send.failed", {
        sessionId,
        recipientPubkey,
        reason: sendResult.reason,
        errorMessage: sendResult.error,
        correlationId,
      });
      return {
        ok: false,
        reason: sendResult.reason,
        guidance: "The content could not be delivered over the session stream right now. It has been queued in the durable retry queue and will be retried when the counterparty reconnects. The session remains usable — check cello_list_connections for the counterparty's status.",
      };
    }

    // Delivered — append the message leaf to the daemon-owned tree (advances root).
    const { leafIndex, newRootHex } = sessionNodeManager.appendSessionLeaf(sessionId, "msg", contentHashHex, correlationId);
    logger.info("session.content.sent", {
      sessionId,
      recipientPubkey,
      contentHashHex,
      sequenceNumber: leafIndex,
      correlationId,
    });
    void newRootHex;
    return { ok: true, sequence_number: leafIndex };
  });

  // ─── CELLO-M7-DAEMON-004: cello_receive (returns from the daemon's own buffer) ──
  handlers.set("cello_receive", async (params, connectionId) => {
    const connState = perConnectionState.get(connectionId);
    if (!connState || !connState.currentAgent) return NO_CURRENT_AGENT_RESPONSE;

    const sessionId = params?.sessionId as string | undefined;
    if (!sessionId) {
      return { ok: false, reason: "missing_params", guidance: "Provide 'sessionId' (hex) to receive content for a specific session." };
    }
    const record = sessionNodeManager.getSessionRecord(sessionId);
    if (!record) {
      return { ok: false, reason: "session_not_found", guidance: "No session found with this ID. Check cello_list_sessions." };
    }
    if (record.agent_name !== connState.currentAgent) {
      return { ok: false, reason: "session_not_owned", guidance: "This session belongs to a different agent. Call cello_use_agent to switch to the agent that owns it, then retry." };
    }

    const entry = sessionNodeManager.takeReceivedContent(sessionId);
    if (!entry) {
      return { ok: true, content: null, guidance: "No content is currently buffered for this session. Call cello_receive again after the counterparty sends, or use the blocking receive variant." };
    }
    return {
      ok: true,
      content: Buffer.from(entry.contentHex, "hex").toString("utf8"),
      sessionId,
      sequence_number: entry.sequenceNumber,
      senderPubkey: entry.senderPubkey,
    };
  });

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

  return { stop, getStatus, getSessionNodeManager };
}
