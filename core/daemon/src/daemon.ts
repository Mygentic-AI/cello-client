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
  InterruptedSessionInfo,
  ActiveSessionInfo,
  SessionListEntry,
  SessionListResponse,
  SessionRecord,
  DirectorySignalingState,
} from "./types.js";
import { loadAgents, type LoadedAgent } from "./agent-loader.js";
import { acquireLock, removeLockIfOwned } from "./lock-file.js";
import { acquireSingletonLock, type SingletonLock } from "./singleton-lock.js";
import { createIpcServer, type IpcServer, type IpcHandler } from "./ipc-server.js";
import { renderForSurface } from "./vocabulary.js";
import { SessionNodeManager } from "./session-node-manager.js";
import { TIER } from "./contacts-tier-migration.js";
import { classifySession, type SessionCategory } from "./session-category.js";
import { PassthroughGatewayClient, type SecurityGatewayClient } from "@cello-protocol/gateway";
import { RetryQueue } from "./retry-queue.js";
import { NonceDedupStore } from "./nonce-dedup.js";
import { ContentParkClient } from "./content-park-client.js";
import { NotificationDispatcher } from "./notification-dispatcher.js";
import { createNode, SignalingManager, type ConnectResult, type CelloNode } from "@cello-protocol/transport";
import { createSignalingConnect, type DirectoryEndpoint } from "./signaling-connect.js";
import { RegistrationManager } from "./registration-manager.js";
import { DaemonRegistrationContext } from "./registration-context.js";
import { DbRegistrationPersistence, DbIdentityStore } from "./db-identity-store.js";
import { DbManifestVersionStore } from "./manifest-version-store-db.js";
import type { IManifestVersionStore } from "@cello-protocol/transport";
import { generateKLocalSeed, InMemoryKeyProvider, hash as cryptoHash } from "@cello-protocol/crypto";
// CELLO-M7-MSG-001 (AC-013/AC-018): the single application content-size cap, enforced
// at the send point here (the receive point lives in the transport content decode).
import { computeGenesisPrevRoot, buildAgentRevocationTbs, MONIKER_RE, validateMoniker } from "@cello-protocol/protocol-types";
import { sealParkEnvelope } from "./park-envelope.js";
import { validateSessionName } from "./session-name.js";
import type { ISessionNodeFactory, SessionNodeConfig, RelayConnectParams } from "./session-node-manager.js";
import type { RelayAssignmentCarry } from "./session-relay-client.js";
import {
  resolveCelloEnv,
  createTransportSelector,
  isProductionVariant,
} from "./transport-composition.js";
import type { ITransportSelector, SessionNegotiator, SessionNegotiationResult } from "./transport-selector.js";
import { selectAdvertisedAddress } from "./transport-selector.js";
import { parseSessionAssignment, sessionRequestErrorReason, parseDiscoveryLookupResult, discoveryLookupErrorReason, extractOfferedMoniker, resolveOutboundMoniker } from "./session-assignment-parser.js";
import { whoLabel } from "./who-label.js";
import { classifyOnlineResult, type DiscoveryOutcome } from "./cross-node-negotiation.js";
import { wireSessionCeremonyHandler, wireSessionOfferHandler, wireSealCeremonyHandler, runAgentRefresh } from "./session-ceremony.js";
import { LocalAutoNatStub, type IAutoNatService } from "@cello-protocol/transport";
import { manifestNodesToEndpoints } from "./directory-bootstrap.js";
import { verifyStartupManifest, createConsortiumRouting } from "./consortium-bootstrap.js";
import { registerContactHandlers } from "./contact-handlers.js";
import { frameValueToHex } from "./frame-values.js";
import { createSealCoordinator, type SealCompletion, type UnilateralResult } from "./seal-coordinator.js";
import { createTelegramDoorbell } from "./telegram-doorbell.js";
import { registerSessionContentHandlers } from "./session-content-handlers.js";
import { createSealFlows } from "./seal-flows.js";
import { buildSignedSealInterruptedLeaf } from "./seal-leaf.js";


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
   * CELLO-M7-TRANSPORT-001 (AC-010): exposes the composition-root transport
   * selector so integration tests can confirm the adapter is wired (not dead
   * code) and exercise the selection path without "adapter not wired".
   */
  getTransportSelector(): ITransportSelector;
  /**
   * CELLO-M7-TRANSPORT-001 (AC-010): exposes the composition-root AutoNAT service
   * adapter (stub default dialable=false in local/test).
   */
  getAutoNatService(): IAutoNatService;
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
    // Stage-1 public reachability (M6 parity): a publicly-hosted agent (e.g. the demo
    // agent on an EIP) needs its STANDING RECEIVER — the node that accepts inbound
    // sessions from strangers — to listen on a routable interface and ANNOUNCE its
    // public address, not loopback. CELLO_LISTEN_ADDR / CELLO_ANNOUNCE_ADDRS mirror the
    // M6 env vars. Only the standing receiver picks these up; ephemeral session nodes
    // (which dial OUT and need no inbound reachability) stay on loopback.
    const isReceiver = config.nodeType === "standing_receiver";
    const listenAddr =
      isReceiver && process.env["CELLO_LISTEN_ADDR"]
        ? process.env["CELLO_LISTEN_ADDR"]
        : "/ip4/127.0.0.1/tcp/0";
    const announce =
      isReceiver && process.env["CELLO_ANNOUNCE_ADDRS"]
        ? process.env["CELLO_ANNOUNCE_ADDRS"].split(",").map((s) => s.trim()).filter(Boolean)
        : undefined;
    return createNode({
      keyProvider: SESSION_NODE_KEY_STUB,
      listenAddresses: [listenAddr],
      ...(announce ? { announceAddresses: announce } : {}),
      connectionGater: config.connectionGater,
      // CELLO-M7-TRANSPORT-001: forward the role so AutoNAT/dcutr are configured
      // correctly (session nodes get dcutr; standing receivers do not).
      nodeType: config.nodeType,
    });
  }
}

// M8C-TTL-1: receiver-side session-request TTL. CORE ships the DoD's own 24h default;
// per-agent configurability is PARKED on M9-CFG-001 (D17 — same pattern as D14/D15/D16).
export const INBOUND_SESSION_TTL_MS = 24 * 60 * 60 * 1000;

/**
 * DOD-SINGLE-DAEMON-1: take the singleton lock, and make sure it is released if startup fails
 * ANYWHERE after that point — not just on the two failure paths that happened to think of it.
 *
 * The real binary exits on a startup failure and the kernel reclaims the lock regardless, so this is
 * not a production-safety hole. It is a DIAGNOSTIC one, and a nasty kind: an in-process caller (every
 * vitest daemon, any embedder) whose startup throws — a corrupt database, a bad key, an EACCES on the
 * lock file — would leak the lock and then be told, on the next attempt in that process, "another
 * daemon is already running". The true cause is replaced by a lie, and the directory is wedged for the
 * life of the process.
 */
export async function startDaemon(config: DaemonConfig): Promise<DaemonHandle> {
  await mkdir(config.celloDir, { recursive: true });
  const singletonLock = acquireSingletonLock(config.celloDir, config.logger);
  try {
    return await startDaemonHoldingLock(config, singletonLock);
  } catch (err: unknown) {
    singletonLock.release();
    throw err;
  }
}

async function startDaemonHoldingLock(
  config: DaemonConfig,
  singletonLock: SingletonLock,
): Promise<DaemonHandle> {
  const {
    celloDir, socketPath, lockFilePath, maxConnections, version, logger,
    manifestProvider, manifestRootKeys, manifestThreshold,
    manifestVersionStore: injectedManifestVersionStore, manifestPollScheduler,
    directoryHttpUrl,
    signalingConnect, challengeVerifier, directoryEndpointResolver, sessionNodeFactory,
    sessionNegotiator, getRelayCircuitAddress, telegramBotClient: injectedTelegramBotClient,
  } = config;

  // CELLO-M7-TRANSPORT-001: composition-root selection of the transport selector.
  // Driven by CELLO_ENV; fails fast at startup (here, not at first session) when a
  // production environment is missing the required transport dialer (AC-010).
  const celloEnv = resolveCelloEnv(process.env["CELLO_ENV"]);
  const transportSelector = createTransportSelector({
    env: celloEnv,
    logger,
    transportDialer: config.transportDialer,
  });
  logger.info("transport.adapters.wired", {
    env: celloEnv,
    selector: isProductionVariant(celloEnv) ? "real" : "stub",
  });

  // ADV-006 + ADV-008 (hoisted — code-review MED): pure config validation runs BEFORE any disk side
  // effect (lock, the irreversible one-time migration, DB open). A misconfigured daemon must fail
  // before mutating state. If manifestProvider is set, manifestRootKeys + a positive threshold are
  // required.
  if (manifestProvider && (!manifestRootKeys || !manifestThreshold || manifestThreshold <= 0)) {
    throw new Error(
      "DaemonConfig: manifestProvider requires manifestRootKeys (non-empty) and manifestThreshold (positive integer >= 1)",
    );
  }

  // ── PERSIST-002: open the encrypted store FIRST (runs the one-time flat-file → SQLCipher migration
  // (AC-006) + creates the agents/manifest_state schema), under the single-instance lock. This must
  // precede the manifest verification below because the manifest version is now stored in the
  // encrypted DB (AC-008), not a manifest-version.json file. ──
  await mkdir(celloDir, { recursive: true });
  await mkdir(dirname(socketPath), { recursive: true });

  // DOD-SINGLE-DAEMON-1: the caller already took the kernel's exclusive lock (see startDaemon) —
  // BEFORE this function touches anything that assumes a single writer. A daemon that loses that race
  // never reaches here at all: it never opens the database, never registers an agent, never connects
  // to the directory. Two daemons sharing an identity is how a hash chain gets two leaves at the same
  // index, and the seal then attests to the damage.
  //
  // AC4: the advisory JSON keeps its metadata role (it is how the NEXT process learns our pid), but
  // the OS lock is what decides whether a daemon may run. This file never gates startup.
  await acquireLock(lockFilePath, { pid: process.pid, socketPath, version });

  // M9-CORE-001: one security-gateway client, shared by both seams — the outbound screen in
  // cello_send and the inbound screen inside SessionNodeManager. Absent config falls back to a
  // PassthroughGatewayClient (always-allow), so pre-M9 daemons behave exactly as before while
  // still returning a verdict (SI-001).
  const securityGateway: SecurityGatewayClient = config.securityGateway ?? new PassthroughGatewayClient();
  // M9-CORE-001 observability: announce the gateway mode at startup. The sidecar socket connects
  // lazily on the first screen, so this records which adapter is wired (sidecar vs the always-allow
  // passthrough default), not a live socket handshake.
  logger.info("security.gateway.connected", {
    mode: config.securityGateway ? "sidecar" : "passthrough",
  });

  const sessionNodeManager = new SessionNodeManager({
    factory: sessionNodeFactory ?? new ProductionSessionNodeFactory(),
    logger,
    dbPath: join(celloDir, "sessions.db"),
    contentTtfMs: config.contentTtfMs,
    autoNatProbers: () => [],
    securityGateway,
  });
  await sessionNodeManager.initialize();

  // AC-008: the manifest version store is DB-backed by default (encrypted manifest_state table). A
  // test may inject an override (e.g. InMemoryManifestVersionStore) via config.
  const manifestVersionStore: IManifestVersionStore =
    injectedManifestVersionStore ?? new DbManifestVersionStore(sessionNodeManager.getDb(), logger);

  // M7-MANIFEST-002: load and verify the consortium manifest BEFORE any directory connection.
  // The gate REPORTS; it does not decide (consortium-bootstrap.ts). The refuse below is ours
  // because only we hold the DB handle and the singleton lock a refusal has to release.
  const { manifestVerified, verifiedManifestVersion } = await verifyStartupManifest({
    manifestProvider,
    manifestRootKeys,
    manifestThreshold,
    manifestVersionStore,
    logger,
  });

  // ADV-002: an operator who configures manifestProvider has opted INTO manifest enforcement, so a
  // failed verification is fatal — never a warning we start anyway on.
  if (manifestProvider && !manifestVerified) {
    // This refuse runs AFTER the DB is open and the lock is held (the DB had to open for the
    // anti-rollback check), so release both before rethrowing — an in-process caller must not be
    // left holding the DB handle. (In production the process exits, but be tidy.)
    try { sessionNodeManager.getDb().close(); } catch { /* ignore */ }
    await removeLockIfOwned(lockFilePath, process.pid, logger).catch(() => { /* best-effort */ });
    // The singleton lock is released by startDaemon's catch — every throw out of this function goes
    // through it, so no failure path can leak the lock by forgetting.
    throw new Error(
      "Manifest verification failed. The daemon cannot start with an unverified manifest when manifestProvider is configured. " +
      "Check the logs for the specific failure reason (manifest_signature_invalid, manifest_expired, or manifest_version_rollback).",
    );
  }

  // The manifest poll starts only AFTER the refuse above — a refused startup must not leak a timer.
  const { resolveConsortiumRoster, failoverEndpointResolver, getFailoverEndpoint, stopHttpManifestPoll } =
    createConsortiumRouting({
      manifestProvider,
      manifestRootKeys,
      manifestThreshold,
      manifestVersionStore,
      manifestPollScheduler,
      directoryHttpUrl,
      directoryEndpointResolver,
      logger,
    });

  // Load agent identities from the encrypted `agents` table (PERSIST-002 AC-007 — one path).
  // (The encrypted store + lock were established above, before manifest verification.)
  const { loaded: loadedAgents, failed: failedAgents } = await loadAgents(sessionNodeManager.getDb(), logger);

  // PERSIST-002: per-agent DB-backed identity persistence. The registration handler and the
  // ceremony/seal signer-reconstruction load the FROST share (and persist the identity) through this
  // seam — the encrypted `agents` row, never a flat file.
  const getPersistence = (agentName: string): DbRegistrationPersistence =>
    new DbRegistrationPersistence({ db: sessionNodeManager.getDb(), agentName, logger });

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

  // Created HERE, not where the seal code used to sit (~2,500 lines down), because the listeners
  // are wired into every signaling manager below — and the originals were FUNCTION DECLARATIONS,
  // so hoisting silently let them be CALLED 1,900 lines before they were DEFINED. A const in their
  // place lands in the temporal dead zone and every one of those calls throws. The dependency on
  // hoisting was real, load-bearing and invisible; naming the construction point makes it explicit.
  // ─── The seal cluster (seal-coordinator.ts) ───
  // Bilateral seal, unilateral escalation, and the returning-absent-party upgrade: five pieces of
  // state and the listeners that drive them. Already seal-private; now that is enforced by a module
  // boundary rather than by convention. cello_close_session still drives the waiters directly.
  const {
    sealKey,
    sealInterruptedInProgress,
    pendingSealWaiters,
    pendingUnilateralWaiters,
    registerSealListeners,
  } = createSealCoordinator({
    logger,
    sessionNodeManager,
    getPersistence,
    getKeyProvider: (agentName: string) => keyProviders.get(agentName),
    recoverContent: (agentName: string) => autoRecoverForAgent(agentName),
  });

  // M7 DOD-SPINE-6 / MSG-001-3b: assemble the relay-witness connect params for a
  // session node from the FROST-signed assignment (relay endpoint + 16-byte session id)
  // and the acting agent's K_local. Returns undefined when the agent key or relay
  // endpoint is missing — the session then runs on the direct content path without a
  // relay witness (degraded, never blocked).
  const buildRelayConnectParams = async (
    agentName: string,
    assignment: NonNullable<ReturnType<typeof parseSessionAssignment>>,
  ): Promise<RelayConnectParams | undefined> => {
    const kp = keyProviders.get(agentName);
    const endpoint = assignment.relay_endpoint;
    if (!kp || !endpoint || !endpoint.peer_id || !endpoint.multiaddrs || endpoint.multiaddrs.length === 0) {
      return undefined;
    }
    // FED-OPTIONB-SETUP-001 (Option B): when the directory included the per-node relay-assignment
    // signature, carry the assignment so the client presents it to its chosen relay (replacing the
    // directory→relay dial). Built only for relay-mode assignments that carry relay_directory_signature;
    // absent ⇒ the client skips client_record_assignment (direct/legacy/pre-M8B).
    const relayDirSig = assignment.relay_directory_signature;
    // FED-OPTIONB-SETUP-001 (fallback-finder #1/#5): a relay-mode assignment MUST carry a
    // relay_directory_signature — the directory always signs one. If it is absent or malformed (the
    // parser dropped it to undefined) for a relay-mode session, the session silently degrades to "no
    // relay witness" and looks indistinguishable from a legitimate direct-mode session. Warn LOUD so the
    // missing/corrupt witness has a named cause (this is the only diagnosable signal on a PURE RECEIVER,
    // which never submits and so never surfaces relay_unavailable). Unwitnessed is an allowed sovereign-
    // redundancy state, but it must not be invisible.
    if (assignment.transport_mode === "relay" && !relayDirSig) {
      logger.warn("session.relay.assignment.signature.missing", {
        agentName,
        sessionId: Buffer.from(assignment.session_id).toString("hex").slice(0, 16),
        reason: "relay_mode_assignment_without_directory_signature",
      });
    }
    const carry: RelayAssignmentCarry | undefined = relayDirSig
      ? {
          participantA: assignment.participant_a.pubkey,
          participantB: assignment.participant_b.pubkey,
          sessionTimestamp: assignment.session_timestamp,
          initiatorSessionPeerId: assignment.initiator_session_peer_id,
          counterpartySessionPeerId: assignment.counterparty_session_peer_id,
          assignmentSignature: relayDirSig,
        }
      : undefined;
    return {
      relayPeerId: endpoint.peer_id,
      relayAddrs: endpoint.multiaddrs,
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      sessionIdBytes: assignment.session_id,
      assignment: carry,
    };
  };

  // M7-SIGNAL-001: Instantiate SignalingManager — owns directory signaling stream lifecycle.
  const defaultConnect = async (): Promise<ConnectResult> => {
    throw new Error("directory_signaling_not_configured");
  };

  // CELLO-M7-CONN-001 (DOD-CONN-1): the keystone is DELETED. There is no shared directory
  // connection borrowing the "primary" agent's identity. In PRODUCTION every agent operates its
  // OWN directory signaling connection authenticated as itself (getAgentSignaling / signalingFor);
  // removing any agent tears down only that agent's own connection, so the daemon never holds a
  // connection authenticated as a removed agent (the Demo1 stranding bug). A single SHARED manager
  // exists ONLY for the in-process test / backward-compat path (a single injected signalingConnect,
  // no per-agent isolation) — in production it is undefined.
  //
  // The SHARED (in-process test / pre-resolver) signaling path has no directory-facing node of its
  // own: nodes are per-agent, published by each agent's manager (getAgentSignaling → `nodeRef`).
  // There is nothing to return here, and saying so explicitly is the point.
  //
  // Consequence, and it is load-bearing: session-ceremony's hydrateShareAndStubs leaves
  // `directoryNodeStubs` UNDEFINED when getNode() is null, so FrostThresholdSigner runs with an
  // EMPTY set of counterparties and its pre-check (reachable < threshold-1) REFUSES. That is the
  // sovereign-node invariant holding — a daemon with no directory nodes must never sign alone. Do
  // NOT "fix" an empty stub set by substituting in-process stubs; that converts a refusal into a
  // forged seal. Pinned by frost.test.ts, "SOVEREIGN-NODE INVARIANT".
  const noSharedDirectoryNode = (): CelloNode | null => null;

  // H1: a long-running daemon must ride out directory outages — notably the 25-30 min multi-region
  // directory deploy. Use an effectively-unbounded reconnect budget with a capped backoff so each
  // connection keeps retrying and reconnects within ~maxBackoffMs of the directory returning.
  const sharedSignaling: SignalingManager | undefined = directoryEndpointResolver
    ? undefined
    : new SignalingManager({
        connect: signalingConnect ?? defaultConnect,
        logger,
        maxReconnectAttempts: Number.MAX_SAFE_INTEGER,
        maxBackoffMs: 30_000,
      });

  // ─── Per-agent directory signaling (CONN-001: one signaling stream per agent) ──
  // CELLO-M7-CONN-001 (DOD-CONN-1): the directory routes EVERY signaling frame —
  // dkg_complete, register_success, inbound session_assignment, seal — by the pubkey that
  // AUTHENTICATED the stream it arrived on. So each agent MUST get its OWN directory stream,
  // authenticated as itself. There is no shared "keystone" connection borrowing one agent's
  // identity. In production every agent has its own manager (built below); the only shared
  // manager is the in-process test path's `sharedSignaling`. Managers are created lazily (on
  // first registration / online / create) and kept connected for the agent's directory presence.
  interface AgentSignaling {
    signaling: SignalingManager;
    getNode: () => CelloNode | null;
  }
  const perAgentSignaling = new Map<string, AgentSignaling>();

  /**
   * Return the directory signaling stream for `agentName`, authenticated as that agent.
   * Production: a dedicated per-agent manager (created + cached on first use). Test /
   * backward-compat path (no directoryEndpointResolver): the single shared manager.
   *
   * CONN-001 (DOD-CONN-2): the per-agent manager wires BOTH registration AND inbound session
   * handlers (session_assignment / seal_interrupted_request) via wirePerAgentSessionInbound,
   * so a non-primary agent RECEIVES inbound sessions on its own stream. Attaching them to the
   * primary (keystone) only would leave every other agent unable to receive.
   */
  function getAgentSignaling(
    agentName: string,
    agentKeyProvider: import("@cello-protocol/crypto").KeyProvider,
    agentPubkeyHex: string,
  ): AgentSignaling {
    // CONN-001: test / backward-compat path — a single shared manager (no per-agent isolation;
    // a single injected signalingConnect). In production sharedSignaling is undefined and every
    // agent builds its own dedicated manager below.
    if (sharedSignaling) {
      return { signaling: sharedSignaling, getNode: noSharedDirectoryNode };
    }
    const existing = perAgentSignaling.get(agentName);
    if (existing) return existing;
    // Unreachable in practice: sharedSignaling is defined iff directoryEndpointResolver is absent, and
    // the sharedSignaling branch above already returned. This narrows the resolver for the type-checker
    // and is a defensive guard.
    if (!directoryEndpointResolver) {
      throw new Error("getAgentSignaling: no directory endpoint resolver configured (and no shared manager)");
    }
    // FINDING-4: dial through the roster-aware failover resolver so this agent's signaling
    // stream routes around a down primary node. (failoverEndpointResolver is defined here
    // because it is built iff directoryEndpointResolver is — guarded non-null just above.)
    const resolver = failoverEndpointResolver ?? directoryEndpointResolver;
    let nodeRef: CelloNode | null = null;
    const connect = createSignalingConnect({
      getDirectoryEndpoint: resolver,
      getAuthIdentity: () => ({ keyProvider: agentKeyProvider, pubkeyHex: agentPubkeyHex }),
      logger,
      challengeVerifier,
      getManifestVersion: () => verifiedManifestVersion,
      publishNode: (n) => {
        nodeRef = n;
      },
    });
    const mgr = new SignalingManager({
      connect,
      logger,
      maxReconnectAttempts: Number.MAX_SAFE_INTEGER,
      maxBackoffMs: 30_000,
      // M8C-RELAYWAKE-1: "check relay on wakeup" — every time this agent's directory signaling
      // reaches 'connected' (the first connect AND every reconnect after a drop), re-drain its
      // parked mailbox from every relay it has session history with. Without this, a message
      // parked while signaling was down (network blip, directory node restart, daemon offline)
      // is only ever discovered at the NEXT agent start, not on the reconnect that actually
      // brings the agent back — this closes that gap. Fire-and-forget; autoRecoverForAgent
      // already catches its own per-relay errors internally.
      onConnected: () => { void autoRecoverForAgent(agentName); },
    });
    const entry: AgentSignaling = { signaling: mgr, getNode: () => nodeRef };
    perAgentSignaling.set(agentName, entry);
    logger.info("agent.signaling.created", { agentName, agentPubkey: agentPubkeyHex });
    // DOD-SPINE-5: answer the directory's delegated-signing `ceremony_request` on THIS
    // agent's stream (the session FROST ceremony — the per-agent counterpart to SPINE-4's
    // registration routing). Unregistered implicitly when the manager is stopped.
    wireSessionCeremonyHandler({
      agentName,
      persistence: getPersistence(agentName),
      agentPubkeyHex,
      keyProvider: agentKeyProvider,
      getNode: entry.getNode,
      getDirectoryEndpoint: getFailoverEndpoint,
      getConsortiumEndpoints: resolveConsortiumRoster,
      signaling: mgr,
      logger,
    });
    // DOD-SPINE-7: coordinate the SEAL FROST ceremony on this agent's stream too.
    wireSealCeremonyHandler({
      agentName,
      persistence: getPersistence(agentName),
      agentPubkeyHex,
      keyProvider: agentKeyProvider,
      getNode: entry.getNode,
      getDirectoryEndpoint: getFailoverEndpoint,
      getConsortiumEndpoints: resolveConsortiumRoster,
      signaling: mgr,
      logger,
    });
    // DOD-SPINE-7: and resolve session_sealed for this agent's sessions on its own stream.
    registerSealListeners(mgr, agentName, agentPubkeyHex);
    // WIRE-002: answer the directory's session_offer on this agent's stream (advertise the
    // standing-receiver session endpoint so the assignment carries a reachable counterparty).
    wireSessionOfferHandler({
      agentName,
      getStandingReceiverEndpoint: () => sessionNodeManager.getStandingReceiverInfo(agentName),
      signaling: mgr,
      logger,
    });
    // CELLO-M8-TRUST-001: receive sealed trust signals pushed from the directory pickup queue on
    // THIS agent's stream. Open with k_local, verify the recomputed hash against the directory
    // anchor, store locally, then ACK (so the directory deletes the ciphertext). The daemon is the
    // ONLY party that can open the seal (SI-001); a hash mismatch is rejected without storing/ACKing.
    mgr.registerInboundHandler((frame) => {
      if (frame["type"] !== "trust_signal_pickup") return;
      void handleTrustSignalPickup(frame as Record<string, unknown>, agentKeyProvider, mgr, agentName);
    });
    // CELLO-M7-CONN-001 (DOD-CONN-2): inbound session_assignment + seal_interrupted_request
    // on THIS agent's own stream, so a non-primary agent receives inbound sessions (SPINE-5).
    wirePerAgentSessionInbound(mgr);
    return entry;
  }

  /** Resolve once `mgr` reaches "connected", or false on timeout. */
  async function waitForSignalingConnected(mgr: SignalingManager, timeoutMs: number): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (mgr.status !== "connected" && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 100));
    }
    return mgr.status === "connected";
  }

  /**
   * Stop and forget a dedicated per-agent signaling manager. Called when an agent's
   * registration fails terminally — otherwise the lazily-created manager (and its
   * libp2p node + effectively-unbounded reconnect loop) would keep reconnecting forever
   * for an agent that is not registered/online. No-op on the test path (the shared manager is not
   * stored in perAgentSignaling) and for agents with no dedicated manager. On a later retry,
   * getAgentSignaling re-creates it.
   */
  async function dropAgentSignaling(agentName: string): Promise<void> {
    const entry = perAgentSignaling.get(agentName);
    if (!entry) return;
    perAgentSignaling.delete(agentName);
    await entry.signaling.stop();
    logger.info("agent.signaling.dropped", { agentName });
  }

  // CONN-001: wire a manager's session/seal/offer handlers for `agent`. Used ONLY for the
  // in-process test path's shared manager — production wires these PER-AGENT in getAgentSignaling.
  function wireSharedHandlers(agent: LoadedAgent, mgr: SignalingManager): void {
    wireSessionCeremonyHandler({
      agentName: agent.name,
      persistence: getPersistence(agent.name),
      agentPubkeyHex: agent.pubkey,
      keyProvider: agent.keyProvider,
      getNode: noSharedDirectoryNode,
      getDirectoryEndpoint: getFailoverEndpoint,
      getConsortiumEndpoints: resolveConsortiumRoster,
      signaling: mgr,
      logger,
    });
    wireSealCeremonyHandler({
      agentName: agent.name,
      persistence: getPersistence(agent.name),
      agentPubkeyHex: agent.pubkey,
      keyProvider: agent.keyProvider,
      getNode: noSharedDirectoryNode,
      getDirectoryEndpoint: getFailoverEndpoint,
      getConsortiumEndpoints: resolveConsortiumRoster,
      signaling: mgr,
      logger,
    });
    wireSessionOfferHandler({
      agentName: agent.name,
      getStandingReceiverEndpoint: () => sessionNodeManager.getStandingReceiverInfo(agent.name),
      signaling: mgr,
      logger,
    });
    registerSealListeners(mgr, agent.name, agent.pubkey);
  }

  // CONN-001: the directory signaling manager that OWNS operations for `agentName`. In production
  // that is the agent's OWN per-agent manager (authenticated as itself); on the in-process test
  // path it is the single shared manager (agentName ignored). Returns undefined only when the agent
  // is not loaded in production (e.g. removed mid-flow) — callers treat that as a send failure.
  function signalingFor(agentName: string): SignalingManager | undefined {
    if (sharedSignaling) return sharedSignaling;
    const kp = keyProviders.get(agentName);
    const agent = loadedAgents.find((a) => a.name === agentName);
    if (!kp || !agent) return undefined;
    return getAgentSignaling(agentName, kp, agent.pubkey).signaling;
  }

  // CONN-001: send a frame over the OWNING agent's directory manager (per-agent in production, the
  // shared manager in tests). If the agent has no manager (e.g. removed mid-flow), return a send
  // failure rather than throw — callers already branch on `!result.ok`.
  async function sendOver(agentName: string, frame: Record<string, unknown>): Promise<{ ok: boolean; reason?: string }> {
    const mgr = signalingFor(agentName);
    if (!mgr) return { ok: false, reason: "directory_unreachable" };
    return mgr.sendRaw(frame);
  }

  // CONN-001: aggregate directory signaling status for `cello status`. Test path → the shared
  // manager's status. Production → connected if ANY online agent's connection is connected; else
  // reconnecting if any per-agent connection exists; else disconnected (no agents online → no
  // connections, which is correct — there is no shared connection to be "reconnecting").
  function directorySignalingStatus(): DirectorySignalingState {
    if (sharedSignaling) return sharedSignaling.status;
    const managers = [...perAgentSignaling.values()];
    // CONN-001 (fallback-finder MED): a single daemon-level field cannot fully represent N independent
    // per-agent connections, but it must NOT show "connected" while any agent is severed (that would
    // mask a partial directory outage — the severed agent silently never receives inbound). So report
    // "connected" ONLY when every per-agent manager is connected; otherwise "reconnecting" (degraded or
    // none). No managers (no agent online) → "reconnecting", matching pre-CONN-001 fresh-install
    // behavior. (Per-agent connection state is the future faithful surface.)
    if (managers.length === 0) return "reconnecting";
    return managers.every((m) => m.signaling.status === "connected") ? "connected" : "reconnecting";
  }

  // CONN-001: stop every directory signaling connection on shutdown — the shared test manager AND
  // every per-agent manager — so no reconnect loop is orphaned past shutdown.
  async function stopAllSignaling(): Promise<void> {
    if (sharedSignaling) { try { await sharedSignaling.stop(); } catch { /* best-effort */ } }
    for (const entry of perAgentSignaling.values()) {
      try { await entry.signaling.stop(); } catch { /* best-effort */ }
    }
  }

  // CONN-001: test path only — wire the shared manager's session/seal handlers for the first loaded
  // agent. Production wires them per-agent (getAgentSignaling). There is NO keystone identity to
  // elect and no re-election machinery: the shared test manager is never removed, and in production
  // a fresh create-agent brings up that agent's OWN connection (no shared door to elect into).
  if (sharedSignaling && loadedAgents.length > 0) {
    const first = [...loadedAgents].sort((a, b) => a.name.localeCompare(b.name))[0];
    wireSharedHandlers(first, sharedSignaling);
  }

  // CELLO-M7-CONN-001 (DOD-CONN-1, code-review HIGH): in PRODUCTION, bring up EACH loaded agent's OWN
  // directory connection at startup. A registered agent must have a directory presence whenever the
  // daemon runs — so the directory can route inbound session_assignment/seal to it (notably after a
  // restart, where login does NOT auto-start agents), and `cello status` reflects directory_signaling
  // as soon as the daemon is up. This replaces the pre-CONN-001 keystone (which connected only the
  // loaded PRIMARY at startup) with a per-agent connection for EVERY loaded agent. Idempotent with the
  // create/register/start connect (getAgentSignaling caches per agent).
  if (!sharedSignaling) {
    for (const agent of loadedAgents) {
      getAgentSignaling(agent.name, agent.keyProvider, agent.pubkey);
    }
  }

  // Per-connection state: tracks which agent is "current" for each IPC connection.
  // Key = connectionId (assigned by IPC server), Value = current agent name or null.
  // `clearedAgent` remembers a selection this connection ONCE made and that was taken away (the agent
  // was stopped or retired). It is what stops resolveCurrentAgent from quietly re-targeting the next
  // call at some other agent that happens to be online — see there.
  const perConnectionState = new Map<string, { currentAgent: string | null; clearedAgent?: string; clientType: string }>();

  // Set of agents currently in "online" state (transitioned via cello_start_agent)
  const onlineAgents = new Set<string>();

  // M8C-CURSOR-1: per-connection, per-session read cursor (read-before-write gating).
  // Distinct from message_watermarks (INBOX-1, per-AGENT delivery watermark, persisted) — this is
  // per-CONNECTION, in-memory only, and intentionally dies with the connection (a fresh connection
  // has read nothing yet, so it must catch up before it may send — the WhatsApp-group-chat model
  // for two attended sessions on one agent). Key = connectionId → sessionId → highest sequence this
  // connection has read (or authored). Absent entry = -1 (nothing read yet).
  const connectionCursors = new Map<string, Map<string, number>>();
  function getConnectionCursor(connectionId: string, sessionId: string): number {
    return connectionCursors.get(connectionId)?.get(sessionId) ?? -1;
  }
  function advanceConnectionCursor(connectionId: string, sessionId: string, seq: number): void {
    let byId = connectionCursors.get(connectionId);
    if (!byId) { byId = new Map(); connectionCursors.set(connectionId, byId); }
    const prior = byId.get(sessionId) ?? -1;
    if (seq > prior) byId.set(sessionId, seq); // monotonic — never lowers
  }
  // M8C-CURSOR-1 (cello-unit-reviewer HIGH finding, confirmed by live reproduction): a
  // received-only delivery (since_seq / live-drain cello_receive) must NOT blindly advance the
  // cursor to the max sequence it happened to see — leaf indices are shared and strictly
  // contiguous across BOTH directions (appendSessionLeaf always assigns leafCount, no gaps), so a
  // gap between the connection's actual cursor and that max can hide an unread SENT leaf authored
  // by a DIFFERENT local connection. Advancing past it would silently let this connection send
  // without ever having seen it — defeating the read-before-write guarantee (C4/C5). Only advance
  // through a CONTIGUOUS run of sequence numbers that were actually in this delivery, starting
  // right after the connection's current cursor; stop at the first gap.
  function safeCursorAdvance(connectionId: string, sessionId: string, deliveredSeqs: ReadonlySet<number>): void {
    let cursor = getConnectionCursor(connectionId, sessionId);
    while (deliveredSeqs.has(cursor + 1)) cursor += 1;
    advanceConnectionCursor(connectionId, sessionId, cursor);
  }

  /**
   * DOD-CURSOR-DURABLE-1: the same hole-safe walk, applied to the PERSISTED per-(agent, session)
   * read watermark. Used by cello_get_transcript, whose delivery covers BOTH directions.
   *
   * Walks a CONTIGUOUS run from the agent's current watermark, stopping at the first gap — for the
   * identical reason safeCursorAdvance does: leaf indices are contiguous across both directions, so
   * a gap can hide an unread RECEIVED message (e.g. a row that failed to decrypt is absent from
   * `messages`). Advancing past it would mark unseen counterparty content as read and unblock a
   * send that never saw it — defeating the very guarantee this gate exists to enforce. Monotonic:
   * advanceLastDeliveredSeq takes MAX, so this can never lower a watermark.
   */
  function safeWatermarkAdvance(agentName: string, sessionId: string, deliveredSeqs: ReadonlySet<number>): void {
    let frontier = sessionNodeManager.getLastDeliveredSeq(agentName, sessionId);
    while (deliveredSeqs.has(frontier + 1)) frontier += 1;
    if (frontier >= 0) sessionNodeManager.advanceLastDeliveredSeq(agentName, sessionId, frontier);
  }

  // M8C-AWAY-1: away response — an unattended Primary auto-answers session requests + messages
  // with the default transparent away text and queues them (the DoD's own mandated default).
  // CORE ships now; the operator-configurable custom-text / opaque-privacy-mode SWITCH is PARKED
  // on M9-CFG-001, journaled as D15 (M8C-DECISIONS.md, mirrors D14) — a genuine per-agent operator
  // preference that needs the deferred config store, whereas transparent is already the correct,
  // non-fake default this unit must ship regardless.
  // "Attended" per the design doc (2026-07-01 command-surface discussion, Agent State Model):
  // Primary + a live client session has claimed the agent via use_agent. Scanning
  // perConnectionState is cheap (a handful of connections) and needs no separate tracked state.
  function isAttended(agentName: string): boolean {
    for (const s of perConnectionState.values()) if (s.currentAgent === agentName) return true;
    return false;
  }
  const AWAY_TEXT: Record<"request" | "message", string> = {
    request: "Agent is currently away. Your session request has been received and queued.",
    message: "Agent is currently away. Your message has been received and will be read when the operator returns.",
  };
  // M8C-CONTACT-1: "unknown senders learn only 'dispatched' by default" — a single shared,
  // deliberately minimal template regardless of kind, distinct from AWAY-1's richer per-type text.
  const STRANGER_TEXT = "Dispatched.";
  // Coalescing: one away ack per (agent, session, kind) per away period — cleared when the agent
  // becomes attended again (cello_use_agent) so the NEXT away period gets a fresh ack rather than
  // staying silent forever. Known imprecision (journaled, not silent): clearing fires on ANY
  // use_agent selecting this name, even if another connection kept it attended throughout — an
  // edge case, not a correctness gap in the core "queue + one calm ack while genuinely away" promise.
  const awayAckSent = new Set<string>();
  async function sendAwayResponse(agentName: string, sessionId: string, kind: "request" | "message"): Promise<void> {
    if (isAttended(agentName)) return;
    const dedupKey = `${agentName}:${sessionId}:${kind}`;
    if (awayAckSent.has(dedupKey)) return;
    const record = sessionNodeManager.getSessionRecord(agentName, sessionId);
    if (!record || record.status !== "active") return;
    // Select the ack wording by whether the sender is a known contact — STRANGER_TEXT
    // ("Dispatched.") for unknown, AWAY_TEXT[kind] for known. The inbound accept path does NOT
    // auto-add the sender: an unattended stranger STAYS unknown across every inbound interaction.
    // Promotion requires operator engagement — an outbound initiate, a cello_send reply, or an
    // explicit contact add. This is a plain read of current contact state; nothing downstream
    // depends on its ordering.
    const isKnown = sessionNodeManager.isKnown(agentName, record.counterparty_pubkey);
    awayAckSent.add(dedupKey); // guard BEFORE the async send — concurrent arrivals must not double-ack
    try {
      // DOD-AWAY-TIER-1: resolve most-specific-first — per-contact away_message → per-tier away
      // (settings) → agent default (settings) → the system default (code, per kind). Total.
      const awayText = sessionNodeManager.resolveAwayMessage(agentName, record.counterparty_pubkey)
        ?? (isKnown ? AWAY_TEXT[kind] : STRANGER_TEXT);
      const draftBytes = new TextEncoder().encode(awayText);
      // SI (AWAY-TIER-1): an away message is now operator-configurable, i.e. an outbound DISCLOSURE.
      // Screen it on the outbound path like any content — it does NOT bypass the gateway. A block/warn
      // verdict means it is not sent (the dedup guard stays set — one screen per away period, no spam);
      // a redact verdict sends the ALTERED bytes.
      const awayVerdict = await securityGateway.screenOutbound(draftBytes, {
        direction: "outbound", agentName, sessionId, correlationId: randomUUID(),
      });
      if (awayVerdict.disposition === "block" || awayVerdict.disposition === "warn") {
        logger.info("session.away.response.screened_out", { agentName, sessionId, kind, disposition: awayVerdict.disposition });
        return;
      }
      if (awayVerdict.disposition === "redact" && awayVerdict.content === undefined) {
        logger.error("session.away.response.redact_without_content", { agentName, sessionId, kind });
        return;
      }
      const contentBytes = awayVerdict.disposition === "redact" && awayVerdict.content !== undefined
        ? new Uint8Array(awayVerdict.content)
        : draftBytes;
      const contentHash = createHash("sha256").update(new Uint8Array([0x00])).update(contentBytes).digest();
      const sendResult = await sessionNodeManager.sendContent(agentName, sessionId, contentBytes, new Uint8Array(contentHash), randomUUID());
      if (!sendResult.ok) {
        // Reviewer MEDIUM fix: a transient failure must NOT permanently silence the rest of this
        // away period — clear the guard so the next inbound arrival retries the ack.
        awayAckSent.delete(dedupKey);
        logger.warn("session.away.response.failed", { agentName, sessionId, kind, reason: sendResult.reason });
        return;
      }
      const contentHashHex = Buffer.from(contentHash).toString("hex");
      const { leafIndex } = sessionNodeManager.appendSessionLeaf(agentName, sessionId, "msg", contentHashHex, randomUUID());
      sessionNodeManager.recordTranscriptMessage(agentName, sessionId, leafIndex, "sent", contentBytes, randomUUID());
      logger.info("session.away.response.sent", { agentName, sessionId, kind, isKnown, sequenceNumber: leafIndex });
    } catch (err: unknown) {
      // Reviewer MEDIUM fix: same as above — an unexpected throw must not permanently lock out
      // future retries for the rest of this away period.
      awayAckSent.delete(dedupKey);
      logger.warn("session.away.response.failed", { agentName, sessionId, kind, error: err instanceof Error ? err.message : String(err) });
    }
  }

  // M8C-TGDOOR-1: the Telegram doorbell (telegram-doorbell.ts). Content-free by construction — the
  // module is never handed message text, so it cannot leak any (DOD-INV-CONTENTFREE), and it has no
  // session-send seam, so nothing from Telegram can enter a CELLO content path (D6).
  const {
    sendTelegramDoorbell,
    clearTelegramRung,
    startTelegramPollerIfConfigured,
    stopTelegramPoller,
  } = createTelegramDoorbell({
    logger,
    getTelegramSettings: () => sessionNodeManager.getTelegramSettings(),
    injectedClient: injectedTelegramBotClient,
  });

  // Wraps notificationDispatcher.dispatchSessionStateChanged so every call site gets the
  // Telegram state-change doorbell for free (DoD: state changes ALWAYS ring, never coalesced) —
  // one wrapper rather than hooking each of the several existing call sites individually.
  // MONIKER-4 AC2: resolve the counterparty's display label — local pet name (MONIKER-3) ??
  // offered name for this session (MONIKER-2) ?? fingerprint. Total: any failure inside
  // resolution degrades to fingerprint via whoLabel's own tiers; a label can never block a
  // doorbell (spec §8).
  function resolveWho(agentName: string, pubkeyHex: string, sessionIdHex: string): { who: string; whoKnown: boolean } {
    let localMoniker: string | null = null;
    try {
      localMoniker = sessionNodeManager.getContactMoniker(agentName, pubkeyHex);
    } catch (err: unknown) {
      logger.warn("moniker.local.read_failed", { agentName, pubkey: pubkeyHex, reason: err instanceof Error ? err.message : String(err) });
    }
    // DOD-MONIKER-6: read only the box written FOR this agent — never a co-resident agent's.
    const resolved = whoLabel({ localMoniker, offeredMoniker: offeredMonikers.get(offerKey(agentName, sessionIdHex)) ?? null, pubkeyHex });
    // `sessionId` is load-bearing for diagnosis, not decoration. `source:"offered"` is CORRECT for a
    // RECEIVER and wrong only for an INITIATOR (an initiator must never find a box — see DOD-MONIKER-6),
    // so a line cannot be judged without knowing who opened the session. Join on sessionId against
    // `session.inbound.accepted`, which names the receiver; any other agent on that session is the
    // initiator. Without this field the M8C live run produced a wrong verdict twice (journal Entry 76).
    //
    // The resolved LABEL is never logged: for an unverified offer it is an attacker-chosen string, and
    // MONIKER-2 AC2 already forbids echoing the raw value (`moniker.rejected` logs the reason, not the
    // name). `whoKnown` carries the trust bit without the payload.
    logger.debug("moniker.resolved", {
      agentName,
      sessionId: sessionIdHex,
      pubkey: pubkeyHex,
      source: resolved.source,
      whoKnown: resolved.whoKnown,
    });
    return { who: resolved.who, whoKnown: resolved.whoKnown };
  }

  function dispatchSessionStateChangedWithTelegram(
    agentName: string,
    sessionId: string,
    state: string,
    counterpartyPubkey: string | null,
  ): void {
    // MONIKER-4 AC2: stamp who/whoKnown on the counterparty-bearing frame. Resolved BEFORE the
    // offered-name drop below so a terminal state's own doorbell still shows the name.
    const who = counterpartyPubkey ? resolveWho(agentName, counterpartyPubkey, sessionId) : undefined;
    notificationDispatcher.dispatchSessionStateChanged(agentName, sessionId, state, counterpartyPubkey, who);
    void sendTelegramDoorbell(agentName, sessionId, "state_change", `Session ${state}`);
    // Reviewer HIGH fix (a60d68ed): telegramRungUnread had NO cleanup at all — a session that
    // rings once and is never read via cello_receive/since_seq (e.g. the operator only ever uses
    // cello_get_transcript, which does not advance the read watermark) left a permanent entry for
    // the life of the daemon process. Every state change is a natural point to drop it — the
    // worst case if the session is still genuinely active is one possible extra ring later, far
    // preferable to an unbounded leak (the exact class of bug fixed for TTL-1's expired-log at
    // af8a701 in this same milestone).
    clearTelegramRung(agentName, sessionId);
    // MONIKER-2 AC2b (review F1): the offered name is display material for the session's
    // lifetime only. Production emits "created", "interrupted", "counterparty_closing" through
    // this wrapper — a terminal-only check was dead code and left the map growing for the
    // daemon's lifetime (remote-fed). Drop on ANY state past "created": a prematurely dropped
    // label degrades to fingerprint, which the spec sanctions; an unbounded map does not.
    // DOD-MONIKER-6 AC3: drop only THIS agent's box — a co-resident agent's session moving on
    // must never cost this agent the caller's name.
    if (state !== "created" && offeredMonikers.delete(offerKey(agentName, sessionId))) {
      logger.debug("moniker.offer.dropped", { agentName, sessionId, state });
    }
  }



  // SessionNodeManager was constructed + initialized at the top of startDaemon (PERSIST-002 — the
  // encrypted store must open before agents load from the `agents` table). Its standing receiver +
  // interrupted-session detection are already ready here, before the IPC socket opens.

  // CELLO-M7-TRANSPORT-001: the daemon's runtime AutoNAT service is the one
  // wrapping the standing receiver node (it emits transport.autonat.result /
  // transport.autonat.unavailable and its dialability drives the SessionAssignment
  // advertised address — AC-004/AC-019). config.autoNatService is an explicit
  // override (tests); otherwise we use the standing receiver's, falling back to a
  // stub only if the standing receiver failed to come up.
  const autoNatService: IAutoNatService =
    config.autoNatService ??
    sessionNodeManager.getStandingReceiverAutoNat() ??
    new LocalAutoNatStub();

  // ─── DOD-SPINE-5: real client-side session negotiator (built internally) ──────
  // The directory already brokers `session_request` → FROST-signed `session_assignment`
  // live; the missing half was the CLIENT driver. This negotiator sends `session_request`
  // over the CURRENT agent's OWN signaling stream (so the directory routes the signed
  // assignment back to that agent — same per-agent routing SPINE-4 established), advertising
  // the standing receiver's session endpoint (WIRE-001: the directory rejects a request
  // with no initiator session Peer ID), then parses the returned assignment. Tests inject their own
  // `sessionNegotiator`; the binary gets a real one.
  // M3: a `session_assignment` frame carries no echoed request id, so two overlapping
  // initiations on ONE agent's stream would race to resolve on whichever assignment
  // arrives first — request A could complete with B's assignment. Guard with a per-agent
  // single-flight slot (genuine single-slot, as the prior comment falsely claimed). Cross-
  // agent concurrency is unaffected (separate streams). A directory-side echoed request id
  // would allow true concurrency later; this is the correct minimum.
  const negotiationInProgress = new Set<string>();

  // ─── Cross-node session establishment (Story B, item 2) ──────────────────────
  // Helpers the negotiator composes: discover the target's home from replicated presence, then run
  // the session_request over the RIGHT connection — the existing home stream when same-node, or a
  // transient VISITING connection into the target's home node when cross-node. Directories never talk
  // to each other; the client spans nodes on demand.

  const sleepMs = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

  /**
   * Issue a discovery_lookup on `signaling` and await the 3-state answer (bounded). Distinguishes,
   * for the caller's retry logic and truthful error surface:
   *  - send_failed (home stream down — TRANSPORT, never "old directory"),
   *  - timeout (no reply — old directory OR a slow/dropped reply on a new one; retry, fall back last),
   *  - error (directory DB fault — retryable, a DIRECTORY fault, not the counterparty being offline),
   *  - malformed (a reply that didn't parse — protocol anomaly, retryable, surfaced distinctly),
   *  - result (the 3-state answer).
   * Emits the mandated observability events: directory.discovery.lookup on a result,
   * directory.discovery.lookup.failed on a directory error / malformed reply.
   */
  async function runDiscoveryLookup(
    signaling: SignalingManager,
    targetHex: string,
    timeoutMs: number,
    correlationId: string,
  ): Promise<DiscoveryOutcome> {
    let resolveFrame!: (f: Record<string, unknown>) => void;
    const pending = new Promise<Record<string, unknown>>((r) => { resolveFrame = r; });
    const unregister = signaling.registerInboundHandler((frame) => {
      const t = frame["type"];
      if (t === "discovery_lookup_result" || t === "discovery_lookup_error") resolveFrame(frame);
    });
    try {
      const sent = await signaling.sendRaw({
        type: "discovery_lookup",
        target_pubkey: new Uint8Array(Buffer.from(targetHex, "hex")),
      });
      if (!sent.ok) {
        // The home stream is down — cannot look up (and today's local-only fallback would fail the
        // same way). Surface the real transport reason, not an "old directory" misdiagnosis.
        return { kind: "send_failed", reason: sent.reason ?? "signaling_unavailable" };
      }
      let timer!: ReturnType<typeof setTimeout>;
      const timeoutP = new Promise<Record<string, unknown>>((r) => { timer = setTimeout(() => r({ type: "__timeout__" }), timeoutMs); });
      const frame = await Promise.race([pending, timeoutP]);
      clearTimeout(timer);
      if (frame["type"] === "__timeout__") return { kind: "timeout" };
      if (frame["type"] === "discovery_lookup_error") {
        const reason = discoveryLookupErrorReason(frame);
        logger.warn("directory.discovery.lookup.failed", { target: targetHex.slice(0, 16), reason, correlationId });
        return { kind: "error", reason };
      }
      const parsed = parseDiscoveryLookupResult(frame);
      if (!parsed) {
        // A reply came back but did not parse — a protocol/version anomaly on a directory that DID
        // respond. Surface it distinctly from a clean directory DB error, and never as availability.
        logger.warn("directory.discovery.lookup.failed", { target: targetHex.slice(0, 16), reason: "malformed_reply", correlationId });
        return { kind: "malformed" };
      }
      logger.info("directory.discovery.lookup", {
        target: targetHex.slice(0, 16),
        state: parsed.state,
        owningNode: parsed.owningNodeIds[0] ?? null,
        correlationId,
      });
      return { kind: "result", state: parsed.state, owningNodeIds: parsed.owningNodeIds };
    } finally {
      unregister();
    }
  }

  /** Send a session_request over `signaling` and await the assignment / error (the extracted core). */
  async function runSessionRequestOverSignaling(
    signaling: SignalingManager,
    targetHex: string,
    sr: { peerId: string; addrs: string[] },
    correlationId: string,
    agentName: string,
  ): Promise<SessionNegotiationResult> {
    let resolveFrame!: (f: Record<string, unknown>) => void;
    const pending = new Promise<Record<string, unknown>>((r) => { resolveFrame = r; });
    const unregister = signaling.registerInboundHandler((frame) => {
      const t = frame["type"];
      if (t === "session_assignment" || t === "session_request_error") resolveFrame(frame);
    });
    // MONIKER-2 AC1: the outbound name rides the request (agent name, or the MONIKER-1
    // override), re-validated at offer construction (defense in depth) and OMITTED — never
    // an empty string — when absent or invalid. A failure reading it must never block the
    // session (spec §8: the label degrades, the session forms), but it is logged loudly.
    let moniker: string | undefined;
    try {
      const outboundName = new DbIdentityStore(sessionNodeManager.getDb(), logger).getOutboundName(agentName);
      moniker = resolveOutboundMoniker(outboundName);
      // Review F4: omit-not-send is the designed degradation, but an agent whose STORED name
      // fails the rule should be visible, not silently nameless on the wire.
      if (outboundName !== null && moniker === undefined) {
        logger.debug("moniker.outbound.invalid_name_omitted", { agentName, correlationId });
      }
    } catch (err: unknown) {
      logger.warn("moniker.outbound.read_failed", {
        agentName,
        reason: err instanceof Error ? err.message : String(err),
        correlationId,
      });
      moniker = undefined;
    }
    try {
      const sent = await signaling.sendRaw({
        type: "session_request",
        target_pubkey: new Uint8Array(Buffer.from(targetHex, "hex")),
        initiator_session_peer_id: sr.peerId,
        initiator_session_addrs: sr.addrs,
        wants_session_offer: true,
        ...(moniker !== undefined ? { moniker } : {}),
      });
      if (!sent.ok) {
        return { ok: false, reason: sent.reason ?? "directory_unreachable", guidance: sent.guidance ?? "Could not send session_request over the directory signaling stream." };
      }
      let timer!: ReturnType<typeof setTimeout>;
      const timeoutP = new Promise<Record<string, unknown>>((r) => { timer = setTimeout(() => r({ type: "__timeout__" }), 30_000); });
      const frame = await Promise.race([pending, timeoutP]);
      clearTimeout(timer);
      if (frame["type"] === "__timeout__") {
        return { ok: false, reason: "timeout", guidance: "The directory did not return a session assignment within 30s. Retry once cello status shows directory_signaling connected." };
      }
      if (frame["type"] === "session_request_error") {
        const reason = sessionRequestErrorReason(frame);
        return { ok: false, reason, guidance: `The directory refused the session request (${reason}). Ensure the counterparty is registered and online.` };
      }
      const raw = frame["assignment"] as Record<string, unknown> | undefined;
      const assignment = raw ? parseSessionAssignment(raw) : null;
      if (!assignment) {
        return { ok: false, reason: "assignment_parse_failed", guidance: "The directory's session_assignment was missing or malformed." };
      }
      logger.info("session.negotiate.assignment.received", { agentName, correlationId, signatureType: assignment.signature_type });
      return { ok: true, assignment };
    } finally {
      unregister();
    }
  }

  /**
   * Open a transient VISITING signaling connection into a specific directory node (the target's home /
   * broker) and wire what a cross-node initiator needs there:
   *  - the delegated-signer ceremony handler (the broker asks the initiator to co-sign the assignment
   *    over THIS connection); and
   *  - Fix #1 (cross-node seal-liveness): the seal ceremony handler + session_sealed/unilateral
   *    listeners, because for a cross-node CLOSE the broker ALSO pushes seal_verified then session_sealed
   *    over the connection the initiator holds to it. The seal FROST still runs over the agent's OWN
   *    roster (getNode: () => nodeRef) — only the control frames traverse this stream.
   * Transient and initiator-only. The caller MUST stop() it after the assignment (setup path) or after
   * the seal reaches a terminal outcome (close path).
   */
  function openVisitingConnection(
    agentName: string,
    agentKeyProvider: import("@cello-protocol/crypto").KeyProvider,
    agentPubkeyHex: string,
    endpoint: DirectoryEndpoint,
    correlationId: string,
    nodeId: string,
  ): { mgr: SignalingManager; stop: (reason: string) => Promise<void> } {
    let nodeRef: CelloNode | null = null;
    const connect = createSignalingConnect({
      getDirectoryEndpoint: () => endpoint,
      getAuthIdentity: () => ({ keyProvider: agentKeyProvider, pubkeyHex: agentPubkeyHex }),
      logger,
      challengeVerifier,
      getManifestVersion: () => verifiedManifestVersion,
      visiting: true, // cross-node item 3: the directory must NOT write presence for this connection
      publishNode: (n) => { nodeRef = n; },
    });
    // maxReconnectAttempts: 1 — a transient connection should fail fast, not reconnect-loop forever.
    const mgr = new SignalingManager({ connect, logger, maxReconnectAttempts: 1, maxBackoffMs: 3_000 });
    wireSessionCeremonyHandler({
      agentName,
      persistence: getPersistence(agentName),
      agentPubkeyHex,
      keyProvider: agentKeyProvider,
      getNode: () => nodeRef,
      getDirectoryEndpoint: getFailoverEndpoint,
      getConsortiumEndpoints: resolveConsortiumRoster,
      signaling: mgr,
      logger,
    });
    // Fix #1 (cross-node seal-liveness): a visiting connection must ALSO be able to complete the SEAL.
    // The broker (the node this visiting connection targets) pushes seal_verified then session_sealed to
    // whichever stream the initiator holds to it — for a cross-node close that is THIS visiting stream.
    // Run the seal FROST ceremony over the agent's own node (getNode: () => nodeRef, exactly as the
    // session ceremony above) and reply/resolve on this stream. Harmless on a setup-only visiting
    // connection: these frames never arrive before it is released after handoff.
    wireSealCeremonyHandler({
      agentName,
      persistence: getPersistence(agentName),
      agentPubkeyHex,
      keyProvider: agentKeyProvider,
      getNode: () => nodeRef,
      getDirectoryEndpoint: getFailoverEndpoint,
      getConsortiumEndpoints: resolveConsortiumRoster,
      signaling: mgr,
      logger,
    });
    // FIX (Seam B review): this VISITING stream used to register only the sealed + unilateral-confirmed
    // listeners. That silently lost seal receipts — the directory drains its DURABLE notification queue
    // on ANY stream that authenticates, visiting included, and deletes each row once sent. A
    // seal_unilateral_notification pushed down here hit no handler, was dropped, and its row was gone;
    // the absent party never ratified and the seal stayed unilateral forever. Every stream that can
    // carry a seal frame now gets every seal listener — and the coordinator no longer lets it be
    // wired any other way.
    registerSealListeners(mgr, agentName, agentPubkeyHex);
    logger.info("signaling.visiting.connected", { agentName, node: nodeId, correlationId });
    return {
      mgr,
      stop: async (reason: string) => {
        logger.info("signaling.visiting.released", { agentName, node: nodeId, reason, correlationId });
        await mgr.stop();
      },
    };
  }

  // Fix #1 (cross-node seal-liveness): the broker node (the counterparty's home) for each cross-node
  // session we initiated, keyed `${agentName}:${sessionIdHex}`. Set when runCrossNodeSetup establishes
  // the session; read by cello_close_session so it can re-open a visiting connection to the broker and
  // complete the seal there. The broker pushes seal_verified/session_sealed, but the initiator RELEASES
  // its visiting connection after setup — so without reconnecting, the close times out
  // (seal_unilateral_timeout) and the seal only completes whenever the daemon next happens to reconnect.
  // Presence of an entry means the session is cross-node (same-node sessions never go through
  // runCrossNodeSetup). In-memory only: a close in the SAME process (the common case) is covered; a close
  // after a daemon restart falls back to the pre-fix behavior (deferred hardening: persist on the row).
  const crossNodeBrokerBySession = new Map<string, string>();

  /**
   * Resolve `owningNodeId` through the signed manifest and run the session_request over a transient
   * visiting connection there. A node id that doesn't resolve in the roster is a hard error
   * (discovery_node_unresolvable) — never a dial to an unvalidated endpoint.
   */
  async function runCrossNodeSetup(
    agentName: string,
    agentKeyProvider: import("@cello-protocol/crypto").KeyProvider,
    agentPubkeyHex: string,
    owningNodeId: string,
    targetHex: string,
    sr: { peerId: string; addrs: string[] },
    correlationId: string,
  ): Promise<SessionNegotiationResult> {
    const roster = await resolveConsortiumRoster();
    const target = roster?.find((e) => e.nodeId === owningNodeId) ?? null;
    if (!target) {
      // Manifest MISS — the node genuinely isn't in the signed roster. A hard, non-retryable cause
      // (distinct from a reachable-but-unconnectable node below).
      logger.warn("session.crossnode.failed", { agentName, brokerNode: owningNodeId, reason: "discovery_node_unresolvable", correlationId });
      return { ok: false, reason: "discovery_node_unresolvable", guidance: `The counterparty's home node (${owningNodeId}) is not in the signed consortium manifest. It may have left the consortium.` };
    }
    logger.info("session.crossnode.initiated", { agentName, brokerNode: owningNodeId, correlationId });
    const visiting = openVisitingConnection(agentName, agentKeyProvider, agentPubkeyHex, { peerId: target.peerId, multiaddr: target.multiaddr }, correlationId, owningNodeId);
    // Track the release reason across the finally (result is block-scoped in the try).
    let releaseReason = "failure";
    try {
      if (!(await waitForSignalingConnected(visiting.mgr, 10_000))) {
        // The node RESOLVED but the visiting dial/auth didn't complete in time — a TRANSIENT
        // cross-region condition (latency, blip, cold handshake), NOT a manifest miss. Distinct
        // reason, and the caller's retry loop treats it as retryable (re-discover → retry).
        logger.warn("session.crossnode.failed", { agentName, brokerNode: owningNodeId, reason: "visiting_connection_unreachable", correlationId });
        return { ok: false, reason: "visiting_connection_unreachable", guidance: `Could not establish a visiting connection to the counterparty's home node (${owningNodeId}) within 10s. Retry.` };
      }
      const result = await runSessionRequestOverSignaling(visiting.mgr, targetHex, sr, correlationId, agentName);
      if (result.ok) {
        releaseReason = "handoff-complete";
        // Fix #1: remember the broker for this session so cello_close_session can reconnect to complete the seal.
        const brokerSessionIdHex = Buffer.from(result.assignment.session_id).toString("hex");
        crossNodeBrokerBySession.set(`${agentName}:${brokerSessionIdHex}`, owningNodeId);
        logger.info("session.crossnode.established", { agentName, brokerNode: owningNodeId, correlationId });
      } else {
        logger.warn("session.crossnode.failed", { agentName, brokerNode: owningNodeId, reason: result.reason, correlationId });
      }
      return result;
    } finally {
      await visiting.stop(releaseReason);
    }
  }

  const resolvedSessionNegotiator: SessionNegotiator = sessionNegotiator ?? {
    negotiate: async (ctx): Promise<SessionNegotiationResult> => {
      const kp = keyProviders.get(ctx.agentName);
      const agentRec = loadedAgents.find((a) => a.name === ctx.agentName);
      if (!kp || !agentRec) {
        return { ok: false, reason: "agent_not_found", guidance: `Agent '${ctx.agentName}' is not loaded on this daemon.` };
      }
      if (negotiationInProgress.has(ctx.agentName)) {
        return {
          ok: false,
          reason: "session_negotiation_in_progress",
          guidance: `Another session initiation is already in progress for agent '${ctx.agentName}'. Wait for it to finish, then retry.`,
        };
      }
      const targetHex =
        typeof ctx.params["target_pubkey"] === "string"
          ? (ctx.params["target_pubkey"] as string)
          : typeof ctx.params["counterparty_pubkey"] === "string"
            ? (ctx.params["counterparty_pubkey"] as string)
            : "";
      if (!/^[0-9a-fA-F]{64}$/.test(targetHex)) {
        return {
          ok: false,
          reason: "invalid_target_pubkey",
          guidance: "cello_initiate_session requires 'target_pubkey' as the counterparty's 32-byte hex K_local public key.",
        };
      }
      const sr = sessionNodeManager.getStandingReceiverInfo(ctx.agentName);
      if (!sr) {
        return {
          ok: false,
          reason: "standing_receiver_unavailable",
          guidance: "The standing receiver is not ready, so no initiator session endpoint can be advertised. Retry once the daemon has finished starting.",
        };
      }
      const { signaling } = getAgentSignaling(ctx.agentName, kp, agentRec.pubkey);
      if (!(await waitForSignalingConnected(signaling, 10_000))) {
        return {
          ok: false,
          reason: "directory_signaling_timeout",
          guidance: `Agent '${ctx.agentName}' could not establish its directory signaling stream within 10s. Check CELLO_DIRECTORY_URL and that the directory is reachable, then retry.`,
        };
      }

      // Single-flight claimed → the discover-first flow (one discovery + up to 3 session_request
      // attempts, possibly over a transient visiting connection) runs under ONE slot; released in
      // finally. A single directory-side echoed request id would allow true concurrency later.
      negotiationInProgress.add(ctx.agentName);
      try {
        // DISCOVER FIRST. Because identity + presence are fully replicated, the agent's OWN home
        // stream answers "where is the target?" authoritatively-enough (advisory — the target node's
        // live #streams check stays the authority; a stale answer just triggers the retry below).
        const homeNodeId = signaling.currentDirectoryNodeId;
        const backoffs = [1_000, 3_000]; // between attempts — covers re-home + replication lag
        const MAX_ATTEMPTS = 3;
        for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
          const disc: DiscoveryOutcome = await runDiscoveryLookup(signaling, targetHex, 5_000, ctx.correlationId);

          // TRANSPORT: the home stream is down — retry (it may reconnect); local-only fallback would
          // fail the same way. Exhausted → the TRUTHFUL transport reason, never a false "offline".
          if (disc.kind === "send_failed") {
            logger.warn("session.discovery.send_failed", { agentName: ctx.agentName, attempt, reason: disc.reason, correlationId: ctx.correlationId });
            if (attempt < MAX_ATTEMPTS) { await sleepMs(backoffs[attempt - 1]); continue; }
            return { ok: false, reason: "directory_unreachable", guidance: "The home directory stream is not connected, so the counterparty's location could not be looked up. Check cello status (directory_signaling), then retry." };
          }
          // NO REPLY: an old directory (predates discovery) OR a slow/dropped reply on a new one. Retry;
          // fall back to local-only behavior ONLY as a last resort (after the retries), so that a
          // single dropped reply does not misroute a reachable cross-node peer to the home node.
          if (disc.kind === "timeout") {
            logger.warn("session.discovery.no_reply", { agentName: ctx.agentName, attempt, correlationId: ctx.correlationId });
            if (attempt < MAX_ATTEMPTS) { await sleepMs(backoffs[attempt - 1]); continue; }
            logger.info("session.discovery.unsupported_fallback", { agentName: ctx.agentName, correlationId: ctx.correlationId });
            return await runSessionRequestOverSignaling(signaling, targetHex, sr, ctx.correlationId, ctx.agentName);
          }
          // DIRECTORY-SIDE lookup fault (DB error / malformed reply): RETRYABLE — but a DIRECTORY fault,
          // reported truthfully as directory_unreachable, NEVER as the counterparty being offline.
          if (disc.kind === "error" || disc.kind === "malformed") {
            logger.info("directory.discovery.lookup.retry", { agentName: ctx.agentName, attempt, kind: disc.kind, correlationId: ctx.correlationId });
            if (attempt < MAX_ATTEMPTS) { await sleepMs(backoffs[attempt - 1]); continue; }
            return { ok: false, reason: "directory_unreachable", guidance: "The directory could not resolve the counterparty's location (a directory-side lookup error) after several attempts. Retry shortly." };
          }

          // A 3-state RESULT. Route it (pure classifier).
          const action = classifyOnlineResult(disc.state, disc.owningNodeIds, homeNodeId);
          // State 3: no such agent — a bad address, not a transient outage. NO retry (distinct code).
          if (action.kind === "unknown_agent") {
            return { ok: false, reason: "unknown_agent", guidance: "No agent is registered under that public key — the counterparty address is unknown. Verify the pubkey with the counterparty's operator." };
          }
          // State 2: known but offline. Definitive — NO retry storm.
          if (action.kind === "offline") {
            return { ok: false, reason: "counterparty_offline", guidance: "The counterparty exists but is not currently online. Have its operator bring it online (cello_status), then retry." };
          }
          // Online but no owner named — transient, re-discover.
          if (action.kind === "retry") {
            logger.info("directory.discovery.lookup.retry", { agentName: ctx.agentName, attempt, kind: "online_no_owner", correlationId: ctx.correlationId });
            if (attempt < MAX_ATTEMPTS) { await sleepMs(backoffs[attempt - 1]); continue; }
            return { ok: false, reason: "counterparty_offline", guidance: "The directory reported the counterparty online but named no home node. Retry shortly." };
          }

          const result =
            action.kind === "same_node"
              // SAME-NODE: the target is on the node we're already connected to. The existing path runs
              // unchanged — ZERO visiting connections, ZERO new frames beyond the one discovery_lookup.
              ? await runSessionRequestOverSignaling(signaling, targetHex, sr, ctx.correlationId, ctx.agentName)
              // CROSS-NODE: reach into the target's home over a transient visiting connection.
              : await runCrossNodeSetup(ctx.agentName, kp, agentRec.pubkey, action.owningNodeId, targetHex, sr, ctx.correlationId);

          // RETRY triggers: (a) the broker reported target_offline (stale replicated presence or a
          // re-home between discovery and the request); (b) a transient visiting-connection failure
          // (cross-region blip). Both re-discover → retry, bounded.
          if (!result.ok && (result.reason === "target_offline" || result.reason === "visiting_connection_unreachable")) {
            logger.info("session.crossnode.stale_discovery_retry", { agentName: ctx.agentName, attempt, reason: result.reason, correlationId: ctx.correlationId });
            if (attempt < MAX_ATTEMPTS) { await sleepMs(backoffs[attempt - 1]); continue; }
            // Exhausted: keep the truthful transient-connection reason; a stale target_offline surfaces
            // as counterparty_offline (state 2).
            return result.reason === "visiting_connection_unreachable"
              ? { ok: false, reason: "visiting_connection_unreachable", guidance: "The counterparty's home node was reachable at discovery but its visiting connection could not be established after several attempts. Retry shortly." }
              : { ok: false, reason: "counterparty_offline", guidance: "The counterparty was online at discovery but not reachable at its home node after several attempts (it may be re-homing). Retry shortly." };
          }
          return result;
        }
        return { ok: false, reason: "counterparty_offline", guidance: "Session establishment did not succeed after several attempts. Retry shortly." };
      } finally {
        negotiationInProgress.delete(ctx.agentName);
      }
    },
  };

  // DAEMON-003: Initialize RetryQueue and NonceDedupStore (AC-008).
  // Both use the same SQLite DB as the SessionNodeManager (daemon.db equivalent).
  // loadFromDb() must complete BEFORE IPC socket opens (AC-007).
  const retryQueue = new RetryQueue(sessionNodeManager.getDb(), logger);
  retryQueue.loadFromDb();

  // CELLO-M7-MSG-001 (AC-001/AC-003/AC-019): wire the awaiting-ACK lifecycle's durable
  // side effects to the retry_queue. A `persisted` delivery ACK clears the durable
  // entry; a TTF expiry records the un-acked content for the crash backstop (the relay
  // park deposit itself is added in 3b). Both side effects are best-effort and never
  // throw into the content stream handler.
  // DOD-AGENT-ID-JOINKEY-1: RetryQueue owns an agent-scoped table, so it is handed the STABLE
  // agent_id. The daemon resolves the operator-facing name ONCE, here at its own boundary.
  sessionNodeManager.setAwaitingAckHooks({
    onPersisted: (agentName, sessionId, contentHashHex) => {
      retryQueue.markContentAcked(sessionNodeManager.resolveAgentId(agentName), sessionId, Buffer.from(contentHashHex, "hex"));
    },
    onTtf: (agentName, sessionId, contentHashHex, content) => {
      retryQueue.enqueueAwaitingContent(sessionNodeManager.resolveAgentId(agentName), sessionId, Buffer.from(contentHashHex, "hex"), content);
    },
  });

  // MSG-001-3b (2b): the LIVE content-park deposit. On a not-confirmed send (direct delivery
  // failed, or TTF with no `persisted` ACK) the session manager calls this with the recipient +
  // the session's relay endpoint; we seal the content to the recipient (E2E — the relay never sees
  // plaintext, INV-3) and deposit it to that relay's store-and-forward mailbox via the standing
  // receiver node. The recipient pulls + recovers it at the witnessed sequence (R1) on next online.
  sessionNodeManager.setContentParkHook(async ({ agentName, sessionId, recipientPubkeyHex, relayPeerId, relayAddrs, contentHashHex, content, structure1Cbor, structure2Cbor }) => {
    const node = sessionNodeManager.getStandingReceiverNode();
    if (!node) {
      const reason = "standing_receiver_unavailable";
      logger.warn("content.park.deposit.failed", { sessionId, contentHash: contentHashHex, reason });
      // DOD-LEAVEMSG-1 (reviewer HIGH fix): return the typed failure, never resolve as if this
      // were a success — #parkContent's caller (sendContent) shapes a live "dispatched to relay"
      // response from this, and a silently-resolved void here would report a message as safely
      // parked when nothing was ever deposited.
      return { ok: false, reason };
    }
    // SEC-1: sign the entry as the SENDING agent. Without a key we cannot produce an envelope the
    // recipient will accept, so fail LOUD rather than depositing something that will be refused on
    // recovery (a deposit the recipient must reject is worse than no deposit — it looks delivered).
    const senderKp = keyProviders.get(agentName);
    if (!senderKp) {
      const reason = "signing_key_unavailable";
      logger.warn("content.park.deposit.failed", { agentName, sessionId, contentHash: contentHashHex, reason });
      return { ok: false, reason };
    }
    const recipientPubkey = Buffer.from(recipientPubkeyHex, "hex");
    const contentHashBytes = Buffer.from(contentHashHex, "hex");
    logger.info("content.park.signed", { agentName, sessionId, contentHash: contentHashHex });
    // DOD-MSG-4 (2b): seal the ORDERING ENVELOPE (content + the relay's signed Structure2), not bare
    // content, so the parked entry is self-ordering on recover. The relay still holds only ciphertext.
    // SEC-1: sealParkEnvelope is the SOLE producer — it signs (sender's K_local, over the
    // session/recipient/content binding) and seals in one place, so the two park sites cannot drift
    // apart on what gets signed.
    const ciphertext = await sealParkEnvelope({
      signer: senderKp,
      sessionIdHex: sessionId,
      recipientPubkey,
      contentHash: contentHashBytes,
      content,
      structure1Cbor,
      structure2Cbor,
    });
    const client = new ContentParkClient({ relayPeerId, relayAddrs: [...relayAddrs], logger });
    const res = await client.deposit(node, {
      recipientPubkey,
      contentHash: Buffer.from(contentHashHex, "hex"),
      sessionId: Buffer.from(sessionId, "hex"),
      ciphertext,
    });
    if (res.ok) {
      logger.info("content.park.deposited", { sessionId, contentHash: contentHashHex, recipientPubkey: recipientPubkeyHex.slice(0, 16) });
      return { ok: true };
    }
    logger.warn("content.park.deposit.failed", { sessionId, contentHash: contentHashHex, reason: res.reason });
    return { ok: false, reason: res.reason ?? "relay_deposit_failed" };
  });

  // CELLO-M7-MSG-001 (AC-004/AC-005, D-d): startup flush of locally-persisted un-acked
  // content (the crash backstop). Runs HERE — before the IPC socket opens, consistent
  // with DAEMON-003 startup loading (AC-007) — so a sender that crashed before its TTF
  // park confirmed re-parks its un-acked content to the relay store-and-forward queue on
  // restart. Best-effort: a failed park stays queued (drainAwaitingToPark does not evict
  // on failure), to be retried at the next startup flush or reconnect.
  //
  // Re-home note (Option A): the park target (config.contentParkFn) is supplied natively
  // by the daemon's own send path — NOT by a hosted CelloClient. When it is absent (e.g.
  // a daemon started without the content send path wired, or unit tests), the flush is a
  // documented no-op (content.park.flush.deferred at WARN) and the durable awaiting
  // entries simply remain queued for the next startup that has a park target.
  // MSG-2 startup-flush park target: seal + deposit an un-acked awaiting entry sourced from
  // PERSISTED session state (the in-memory entry is gone after a restart). Same seal + deposit
  // as the live hook above; the endpoint + recipient come from the sessions row.
  const startupParkFn: import("./retry-queue.js").ParkFn = async (entry) => {
    // The durable row carries the OWNING agent's stable id. Resolve it back to a name for the
    // name-addressed session/standing-receiver lookups. A retired owner resolves fine and then has no
    // standing receiver, so the park fails loudly below rather than silently re-parking as someone else.
    const ownerName = sessionNodeManager.agentNameForId(entry.agentId);
    if (ownerName === null) return { parked: false, error: "owning_agent_not_found" };
    const ep = sessionNodeManager.getPersistedRelayEndpoint(ownerName, entry.sessionId);
    const record = sessionNodeManager.getSessionRecord(ownerName, entry.sessionId);
    if (!ep) return { parked: false, error: "no_persisted_relay_endpoint" };
    if (!record?.counterparty_pubkey) return { parked: false, error: "no_counterparty" };
    // DOD-LOOP-1: the re-park must originate from the session's OWNING agent (the original
    // sender), so use THAT agent's standing-receiver node — not "any" agent's. Post-DOD-LOOP-1 the
    // owning agent's SR exists only once it is online, which is why the native flush is
    // (re-)triggered per-agent on agent-online (see flushAwaitingContent / cello_start_agent), not
    // only at pre-IPC startup when no agent is online yet.
    const node = sessionNodeManager.getStandingReceiverNode(record.agent_name);
    if (!node) return { parked: false, error: "standing_receiver_unavailable" };
    // SEC-1: the crash backstop must sign too — an unsigned re-park would be REFUSED on recovery,
    // which would turn the message-loss backstop into a message-loss cause. This is why the SEC-1
    // signature binds to the sender's own K_local and NOT to the relay's ordering record: the
    // ordering record is not persisted in retry_queue (see below) and so cannot be reproduced here,
    // but the KEY can — the owning agent still holds it after a crash. Hence: NO schema migration.
    const senderKp = keyProviders.get(ownerName);
    if (!senderKp) return { parked: false, error: "signing_key_unavailable" };
    const recipientPubkey = Buffer.from(record.counterparty_pubkey, "hex");
    const contentHashBytes = Buffer.from(entry.contentHashHex, "hex");
    logger.info("content.park.signed", { agentName: ownerName, sessionId: entry.sessionId, contentHash: entry.contentHashHex, source: "startup_flush" });
    // DOD-MSG-4 (2b): seal the envelope shape too (content only — the durable awaiting queue does not
    // persist the ordering record, so a crash-backstop re-park recovers in arrival order; the common
    // live-park path above carries the full Structure2). Keeps ONE envelope format on the recover side.
    // SEC-1: same sole producer as the live hook — the backstop signs from the persisted
    // (sessionId, recipient, contentHash), which is why it survives a crash with NO schema migration.
    const ciphertext = await sealParkEnvelope({
      signer: senderKp,
      sessionIdHex: entry.sessionId,
      recipientPubkey,
      contentHash: contentHashBytes,
      content: entry.contentBlob,
    });
    const client = new ContentParkClient({ relayPeerId: ep.relayPeerId, relayAddrs: [...ep.relayAddrs], logger });
    const res = await client.deposit(node, {
      recipientPubkey,
      contentHash: Buffer.from(entry.contentHashHex, "hex"),
      sessionId: Buffer.from(entry.sessionId, "hex"),
      ciphertext,
    });
    if (res.ok) {
      logger.info("content.park.deposited", { sessionId: entry.sessionId, contentHash: entry.contentHashHex, source: "startup_flush" });
      return { parked: true };
    }
    return { parked: false, error: res.reason ?? "deposit_failed" };
  };

  // Re-park un-acked awaiting content to the relay store-and-forward queue. Runs once pre-IPC
  // (the crash backstop) and again per-agent when an agent comes online — because post-DOD-LOOP-1
  // the native `startupParkFn` needs the OWNING agent's standing receiver, which exists only once
  // that agent is online. `filterAgentName` scopes the drain to one agent's sessions on the agent-
  // online re-run; with no filter it attempts all (the pre-IPC pass / injected-target test path).
  async function flushAwaitingContent(filterAgentName?: string): Promise<void> {
    // DOD-AGENT-ID-JOINKEY-1: the queue is keyed by the STABLE agent_id, but the caller (and the
    // human-readable log) speak the NAME. Resolve once here; log the name, filter by the id.
    const filterAgentId = filterAgentName !== undefined
      ? sessionNodeManager.resolveAgentId(filterAgentName)
      : undefined;
    const all = retryQueue.getAwaitingSessions();
    const sessions = filterAgentId === undefined
      ? all
      : all.filter((s) => s.agentId === filterAgentId);
    if (sessions.length === 0) return;
    const parkFn = config.contentParkFn ?? startupParkFn;
    if (!parkFn) {
      const pendingCount = sessions.reduce((n, s) => n + retryQueue.getAwaitingDepth(s.agentId, s.sessionId), 0);
      logger.warn("content.park.flush.deferred", {
        sessionCount: sessions.length,
        pendingCount,
        reason: "no_content_park_target",
      });
      return;
    }
    let parkedTotal = 0;
    for (const s of sessions) {
      try {
        parkedTotal += await retryQueue.drainAwaitingToPark(s.agentId, s.sessionId, parkFn);
      } catch (err: unknown) {
        logger.error("content.park.flush.failed", {
          sessionId: s.sessionId,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
    logger.info("content.park.flush.completed", {
      sessionCount: sessions.length,
      parkedCount: parkedTotal,
      ...(filterAgentName !== undefined ? { agentName: filterAgentName } : {}),
    });
  }

  await flushAwaitingContent();

  const nonceDedupStore = new NonceDedupStore(sessionNodeManager.getDb(), logger);
  nonceDedupStore.loadFromDb();

  // Build agent list from this connection's perspective
  function getAgentsForConnection(connectionId: string): AgentInfo[] {
    const connState = perConnectionState.get(connectionId);
    const currentAgent = connState?.currentAgent ?? null;

    return agents
      .filter((a) => a.state !== "load_failed")
      .map((a) => {
        // `state` reports READINESS only (online vs registered); selection is a SEPARATE `selected`
        // flag. Never fold selection into `state` — a selected agent is not at a different level of
        // readiness than a second healthy online agent.
        const online = onlineAgents.has(a.name);
        const state: AgentInfo["state"] = online ? "online" : "registered";
        const selected = online && a.name === currentAgent;
        return {
          name: a.name,
          state,
          selected,
          pubkey: a.pubkey,
          // M8B F14 (fix 5): per-agent standing-receiver readiness on the MCP surface
          // (cello_status / cello_list_agents), so a deaf agent is visible to the operator.
          standing_receiver_ready: sessionNodeManager.getStandingReceiverReady(a.name),
        };
      });
  }

  // M7-SESSION-001 AC-006/AC-007 (and M-1 PULL): build the interrupted_sessions
  // array from SQLite. Shared by both getStatus() (daemon-wide) and the
  // cello_status MCP handler (per-connection) so live MCP clients see the same
  // interrupted sessions a CLI `cello status` would.
  // `cello status` is a health snapshot, not a session archive. It surfaces ONLY genuinely
  // RESUMABLE sessions (interrupted with messages exchanged) — never failed inits (interrupted,
  // 0 messages — a dead handshake), which classify as "failed" and would otherwise accumulate
  // unbounded and confuse. The list is also capped; the full, queryable history is `cello sessions`
  // / cello_list_sessions (with filter + limit flags).
  const STATUS_RESUMABLE_CAP = 10;
  function buildInterruptedSessions(): InterruptedSessionInfo[] {
    return sessionNodeManager
      .getSessionsByStatus("interrupted")
      .filter((row) => (row.message_count ?? 0) > 0) // resumable only — drop failed 0-message inits
      .slice(0, STATUS_RESUMABLE_CAP)
      .map((row) => ({
        sessionId: row.session_id,
        agentName: row.agent_name,
        counterpartyPubkey: row.counterparty_pubkey,
        messageCount: row.message_count ?? 0,
        interruptedAt: row.interrupted_at ?? new Date(row.updated_at).toISOString(),
        // DOD-SESSION-NAME-1 (AC-A11): an interrupted session is one you may want to resume or seal
        // — the name is how you tell which one it was.
        sessionName: row.session_name ?? null,
      }));
  }

  // CC-5/F21: reap dead half-open sessions on READ (compute-on-read, like reapExpiredInboundSessions —
  // no background timer). A session the standing receiver opened from an inbound offer the initiator
  // ABANDONED stays "active" forever (the counterparty never joins), clutters the open/active lists, and
  // its normal close fires an unsealable bilateral seal. Mark such a session terminal ("abandoned") once
  // it is PROVABLY dead: counterparty never established (liveness != "alive" AND 0 RECEIVED messages —
  // message_count alone counts our own auto-"Dispatched." ack, so it is NOT the signal) + age past the
  // grace TTL (a genuinely fresh session still setting up must survive).
  // CC-10 (live 2026-07-08 Phase-2 block): scan 'interrupted' too, not just 'active'. A daemon restart
  // flips dead half-opens to 'interrupted'; those classify as "failed" (invisible in every list) yet
  // still count toward the unknown-sender acceptance bound (D18 deliberately counts 'interrupted') — so
  // a stranger whose first handshakes died was silently locked out FOREVER. Reaping only 0-RECEIVED
  // ghosts keeps D18 intact: the disconnect-evasion attacker's sessions always carry received content.
  const HALF_OPEN_TTL_MS = Number(process.env["CELLO_HALF_OPEN_TTL_MS"]) || 5 * 60 * 1000;
  function reapDeadHalfOpenSessions(agentName?: string): void {
    const now = Date.now();
    const candidates = [...sessionNodeManager.getSessionsByStatus("active"), ...sessionNodeManager.getSessionsByStatus("interrupted")];
    for (const row of candidates) {
      if (agentName !== undefined && row.agent_name !== agentName) continue;
      if (now - row.created_at <= HALF_OPEN_TTL_MS) continue; // too young — may just be setting up
      if (sessionNodeManager.getSessionLiveness(row.agent_name, row.session_id) === "alive") continue; // live
      if (sessionNodeManager.countReceivedMessages(row.agent_name, row.session_id) > 0) continue; // counterparty spoke
      // Non-awaited: abandonSession flips the DB status synchronously (before its first await), so THIS
      // read reflects it; the async node teardown finishes in the background. CC-10 reviewer LOW: only
      // log "reaped" if the status flip actually wrote — a swallowed write failure already logs
      // session.status.write.failed, and reporting success over it would hide a still-counting ghost.
      void sessionNodeManager.abandonSession(row.agent_name, row.session_id)
        .then((flipped) => {
          if (flipped) {
            logger.info("session.half_open.reaped", { agentName: row.agent_name, sessionId: row.session_id, priorStatus: row.status, ageMs: now - row.created_at });
          }
        })
        .catch((err: unknown) => {
          logger.warn("session.half_open.reap.failed", { agentName: row.agent_name, sessionId: row.session_id, reason: err instanceof Error ? err.message : String(err) });
        });
    }
  }

  // M8B F16: per-session liveness for ACTIVE sessions, shared by both status surfaces
  // ("status" for the CLI, "cello_status" for MCP). The signal (session.liveness.changed,
  // tracked in the node manager) existed but nothing consumed it — a dead counterparty
  // was invisible to the operator.
  function buildActiveSessions(): ActiveSessionInfo[] {
    reapDeadHalfOpenSessions(); // CC-5/F21: drop provably-dead half-open sessions before surfacing active ones
    return sessionNodeManager.getSessionsByStatus("active").map((row) => ({
      sessionId: row.session_id,
      agentName: row.agent_name,
      counterpartyPubkey: row.counterparty_pubkey,
      liveness: sessionNodeManager.getSessionLiveness(row.agent_name, row.session_id),
      sessionName: row.session_name ?? null, // DOD-SESSION-NAME-1 (AC-A11)
    }));
  }

  // Build status response factory
  function getStatus(): DaemonStatusResponse {
    // M7-SESSION-001 AC-006/AC-007: surface interrupted sessions
    const interrupted_sessions: InterruptedSessionInfo[] = buildInterruptedSessions();

    return {
      daemon: "running",
      directory_signaling: directorySignalingStatus(),
      // M8B F14 (fix 5): per-agent standing-receiver readiness, so a deaf agent (online but
      // no armed receiver) is visible in cello_status instead of hiding behind the ANY-agent
      // aggregate below (kept for backward compatibility).
      // CC-8 (F5 parity): the CLI `cello status` surface must show online vs registered like the MCP
      // cello_status does. The stored `a.state` is stale — it stays "registered" even when the agent is
      // online, because startAgentInternal only adds to onlineAgents and never mutates the record — so
      // derive readiness from onlineAgents here, exactly as getAgentsForConnection (F5) already does for
      // the MCP surface. A load_failed agent keeps its state so a broken agent stays visible as broken.
      // (No `selected` here: this is the daemon-wide surface; selection is a per-connection concept and
      // the CLI opens an ephemeral connection that never runs cello_use_agent — see M8C-DECISIONS D24.)
      agents: agents.map((a) => {
        const online = onlineAgents.has(a.name);
        const state: AgentInfo["state"] = a.state === "load_failed" ? "load_failed" : online ? "online" : "registered";
        return {
          ...a,
          state,
          standing_receiver_ready: sessionNodeManager.getStandingReceiverReady(a.name),
        };
      }),
      standing_receiver_ready: sessionNodeManager.getStandingReceiverReady(),
      retryQueueDepth: retryQueue.getTotalDepth(),
      interrupted_sessions,
      // M8B F16: per-session liveness so a counterparty-gone session is visible.
      active_sessions: buildActiveSessions(),
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
  // M8C-AUTOSTART-1 (A2): the shared start path. Extracted from cello_start_agent so cello_use_agent
  // can AUTO-START an offline agent through the exact same code (idempotent, same signaling +
  // standing-receiver setup, same agent_state_changed event) — never a divergent shim-side retry.
  // Permissive by design (D12): an agent that exists goes online regardless of directory
  // registration state (online-without-registration is an established contract). Returns a
  // structured failure so callers can surface agent_start_failed with a real reason + guidance.
  function startAgentInternal(name: string): { ok: true } | { ok: false; reason: string; guidance: string } {
    const agent = agents.find((a) => a.name === name);
    if (!agent || agent.state === "load_failed") {
      return { ok: false, reason: "agent_not_found", guidance: `Agent '${name}' does not exist. Run 'cello login' to register agents, or check agent names with cello_agents.` };
    }
    if (onlineAgents.has(name)) {
      // Idempotent — already online, no event
      return { ok: true };
    }
    onlineAgents.add(name);
    // CELLO-M7-CONN-001 (DOD-CONN-2, code-review HIGH): the "online" transition establishes THIS
    // agent's OWN directory signaling connection (the documented getAgentSignaling "online" trigger),
    // so the directory has a stream to push inbound session_assignment / seal_interrupted_request to.
    // Without this, a started receiver agent sitting in cello_await_session (notably after a daemon
    // restart, where login does NOT auto-start agents) would have no stream and never receive inbound —
    // a regression of the pre-CONN-001 keystone, which connected the primary at startup. Lazy +
    // idempotent (getAgentSignaling reuses an existing manager); the test path returns the shared one.
    const startKp = keyProviders.get(name);
    if (startKp && agent.pubkey) {
      getAgentSignaling(name, startKp, agent.pubkey);
      logger.info("agent.directory.connection.initiated", { agentName: name, agentPubkey: agent.pubkey });
    }
    // DOD-LOOP-1: each online agent gets its OWN standing receiver, so two agents on one daemon
    // (loopback) never contend for a single one. Fire-and-forget (initiate/accept also ensure on
    // demand); never let it throw out of the handler. Once the SR is up, re-park any of THIS
    // agent's un-acked awaiting content (the crash backstop — its node was unavailable at the
    // pre-IPC startup flush because no agent was online yet).
    // The standing-receiver ensure + sender re-park; a rejection here is a standing-receiver failure.
    void sessionNodeManager.ensureStandingReceiverForAgent(name)
      .then(() => flushAwaitingContent(name))
      .catch((err: unknown) => {
        logger.warn("session.standing_receiver.ensure.failed", { agentName: name, reason: err instanceof Error ? err.message : String(err) });
      })
      // DOD-MSG-4 (auto-recover-on-reconnect): RECEIVER drains its parked mailbox from every relay it
      // has sessions on (symmetric to the sender re-park). Its own stage so a failure is labelled
      // correctly (review #4), not as a standing-receiver error. autoRecoverForAgent catches per-relay
      // errors internally, so this .catch is a backstop only.
      .then(() => autoRecoverForAgent(name))
      .catch((err: unknown) => {
        logger.warn("content.recover.auto.failed", { agentName: name, reason: err instanceof Error ? err.message : String(err) });
      });
    logger.info("agent.online", { agentName: name, agentPubkey: agent.pubkey ?? "" });
    // MCP-002: Broadcast agent_state_changed to ALL connections
    notificationDispatcher.dispatchAgentStateChanged(name, "online", "started");
    return { ok: true };
  }

  // M8C-AUTOSTART-1 (F18): resolve which agent an agent-defaulting tool should act on for this
  // connection: an explicit { agent } wins; else the connection's current agent; else — when EXACTLY one
  // agent is online daemon-wide — that sole agent (removes the "why did it forget my agent" moment
  // after a /mcp reconnect). Two-or-more online with none selected stays ambiguous → null (the
  // caller returns no_current_agent), because guessing between peers would misroute.
  /**
   * Which agent does this call act as?
   *
   * An explicit { agent } wins, then this connection's selection. Only with NEITHER does the daemon fall back
   * to the sole online agent — a convenience for a caller that never chose, where "the online one"
   * cannot mean anyone else.
   *
   * The fallback is REFUSED for a connection whose selection was taken away (`clearedAgent`): it
   * chose an agent, that agent was stopped or retired, and the choice is gone. Falling back there
   * silently re-targets the next call at whoever else happens to be online — the caller asked for
   * alice, alice was stopped, and the work lands on bob reporting success. A lost intent is not the
   * same as no intent, and it must fail loud (no_current_agent) rather than be guessed at.
   */
  function resolveCurrentAgent(connState: { currentAgent: string | null; clearedAgent?: string } | undefined, explicitAgent?: string): string | null {
    if (explicitAgent) return explicitAgent;
    if (connState?.currentAgent) return connState.currentAgent;
    if (connState?.clearedAgent) return null;
    if (onlineAgents.size === 1) return [...onlineAgents][0];
    return null;
  }

  // ─── MCP-001: cello_start_agent handler ───
  // Bring a registered agent online WITHOUT claiming it as this connection's current agent.
  handlers.set("cello_start_agent", async (params, _connectionId) => {
    const name = params?.name as string | undefined;
    if (!name) {
      return { ok: false, reason: "missing_params", guidance: "Provide 'name' parameter with the agent name to start." };
    }
    return startAgentInternal(name);
  });

  // ─── PERSIST-002 (AC-004): cello_create_agent handler ───
  // The explicit agent-creation path: generate a fresh K_local seed, write it as an `agents` row in
  // the encrypted DB (NO key file), and wire the agent into the live daemon so it can be registered
  // and used WITHOUT a restart. Creation is explicit — cello_start_agent never auto-creates on a typo.
  handlers.set("cello_create_agent", async (params, _connectionId) => {
    const name = validateMoniker(params?.name);
    if (name === null) {
      return { ok: false, reason: "invalid_agent_name", guidance: `Provide a 'name' (1-64 chars: letters, digits, '-' or '_'; regex ${MONIKER_RE.source}) for the new agent.` };
    }
    const store = new DbIdentityStore(sessionNodeManager.getDb(), logger);
    if (store.hasActiveAgent(name) || agents.some((a) => a.name === name)) {
      return { ok: false, reason: "agent_already_exists", guidance: `Agent '${name}' already exists. Choose a different name, or see cello_agents.` };
    }
    let pubkeyHex: string;
    let agentId: string;
    try {
      const seed = generateKLocalSeed();
      const keyProvider = new InMemoryKeyProvider(seed);
      pubkeyHex = Buffer.from(await keyProvider.getPublicKey()).toString("hex");
      // SI-001: createAgent stores the seed in the encrypted DB and logs only the pubkey + agent_id.
      agentId = store.createAgent(name, seed, pubkeyHex);
      // Runtime-add: make the agent immediately registrable/usable (the register handler resolves
      // identity from keyProviders/loadedAgents; per-agent signaling is created lazily on register).
      keyProviders.set(name, keyProvider);
      const loaded: LoadedAgent = { name, pubkey: pubkeyHex, keyProvider };
      loadedAgents.push(loaded);
      agents.push({ name, state: "registered", pubkey: pubkeyHex });
      // CELLO-M7-CONN-001 (DOD-CONN-1, supersedes ONBOARD-001 keystone election): on a fresh install
      // the daemon started with zero agents, so there were no directory connections. Bring up THIS
      // agent's OWN directory connection now (production: getAgentSignaling creates + connects a
      // dedicated manager authenticated as this agent; the directory door becomes active with no
      // restart). There is no shared keystone to elect into. In the test path getAgentSignaling returns
      // the already-present shared manager (no-op).
      getAgentSignaling(name, keyProvider, pubkeyHex);
      // "initiated" not "established": getAgentSignaling starts the connection but does not await it
      // (the SignalingManager emits directory.signaling.connected when it actually authenticates).
      logger.info("agent.directory.connection.initiated", { agentName: name, agentPubkey: pubkeyHex });
    } catch (err: unknown) {
      logger.error("persist.identity.persist.failed", { agentName: name, error: err instanceof Error ? err.message : String(err) });
      return { ok: false, reason: "agent_create_failed", guidance: "Could not create the agent. Check the daemon log and that the CELLO directory is writable, then retry." };
    }
    // Creation is not an online/offline transition — the agent appears (cello_list_agents) but is
    // not online until cello_start_agent. Just record it.
    logger.info("agent.created", { agentName: name, agentId, agentPubkey: pubkeyHex });
    return { ok: true, name, pubkey: pubkeyHex, agentId };
  });

  // ─── CELLO-M7-REMOVE-001 (DOD-REMOVE-1): cello_remove_agent handler ───
  // RETIRE-AND-KEEP: flip the agent's local row to state='retired' (its row, keys, and history are
  // KEPT for accountability — never hard-deleted, SI-002) and FREE the human name for reuse. Purge the
  // retired identity from the live runtime so it stops operating and the name is immediately available
  // to a NEW `cello_create_agent`. One-way. (DEC-4: the signed DIRECTORY revocation is DOD-REMOVE-2 —
  // not built here; this unit is the local record shape only.)
  // CELLO-M7-REMOVE-001 (DOD-REMOVE-2): build + self-sign an agent revocation and submit it to the
  // directory on the agent's K_local-authenticated signaling stream. Self-authorized — the directory
  // verifies the signature against the agent's registered K_local before appending. Best-effort: returns
  // { recorded:false, reason } if the directory is unreachable / rejects (DB-001 — the caller still
  // applies the one-way local retire and surfaces a distinct status).
  async function submitAgentRevocation(opts: {
    agentName: string;
    signer: import("@cello-protocol/crypto").KeyProvider;
    kLocalPubkeyHex: string;
    regAgentId: string;
  }): Promise<{ recorded: boolean; reason?: string }> {
    const { agentName, signer, kLocalPubkeyHex, regAgentId } = opts;
    const epochId = "";
    const reason = "voluntary";
    const revokedAt = Date.now();
    const tbs = buildAgentRevocationTbs(regAgentId, kLocalPubkeyHex, epochId, reason, revokedAt);
    const sigHex = Buffer.from(await signer.sign(tbs)).toString("hex");

    // If the agent has no live signaling (e.g. a re-push of an already-retired agent), getAgentSignaling
    // lazily creates a dedicated manager — drop it again afterwards so we don't leak a reconnect loop.
    const hadSignaling = perAgentSignaling.has(agentName);
    const { signaling } = getAgentSignaling(agentName, signer, kLocalPubkeyHex);
    // createdSignaling is true only when this call lazily created a NEW per-agent manager (production);
    // on the shared test path perAgentSignaling stays empty, so it is false and dropAgentSignaling no-ops.
    const createdSignaling = !hadSignaling && perAgentSignaling.has(agentName);
    try {
      const connected = await waitForSignalingConnected(signaling, 10_000);
      if (!connected) return { recorded: false, reason: "directory_unreachable" };
      let resolveFrame!: (f: Record<string, unknown>) => void;
      const pending = new Promise<Record<string, unknown>>((r) => { resolveFrame = r; });
      // Match the reply by agent_id so a revocation on a shared signaling stream is never cross-wired.
      const unregister = signaling.registerInboundHandler((frame) => {
        const t = frame["type"];
        if ((t === "agent_revocation_ack" || t === "agent_revocation_error") && frame["agent_id"] === regAgentId) resolveFrame(frame);
      });
      try {
        const sent = await signaling.sendRaw({ type: "revoke_agent", agent_id: regAgentId, epoch_id: epochId, reason, revoked_at: revokedAt, signature: sigHex });
        if (!sent.ok) return { recorded: false, reason: sent.reason ?? "directory_unreachable" };
        let timer!: ReturnType<typeof setTimeout>;
        const timeoutP = new Promise<Record<string, unknown>>((r) => { timer = setTimeout(() => r({ type: "__timeout__" }), 15_000); });
        const frame = await Promise.race([pending, timeoutP]);
        clearTimeout(timer);
        if (frame["type"] === "__timeout__") return { recorded: false, reason: "timeout" };
        if (frame["type"] === "agent_revocation_error") return { recorded: false, reason: String(frame["reason"] ?? "rejected") };
        logger.info("agent.revocation.submitted", { agentName, agentId: regAgentId });
        return { recorded: true };
      } finally {
        unregister();
      }
    } finally {
      if (createdSignaling) {
        await dropAgentSignaling(agentName).catch((err) => {
          logger.warn("agent.revocation.signaling_teardown_failed", { agentName, error: err instanceof Error ? err.message : String(err) });
        });
      }
    }
  }

  handlers.set("cello_remove_agent", async (params, _connectionId) => {
    const name = validateMoniker(params?.name);
    if (name === null) {
      return { ok: false, reason: "invalid_agent_name", guidance: `Provide the 'name' of the agent to remove (1-64 chars: letters, digits, '-' or '_'; regex ${MONIKER_RE.source}).` };
    }
    const store = new DbIdentityStore(sessionNodeManager.getDb(), logger);
    // The active row (a fresh removal) OR the most-recent retired row (a DB-001 re-push). Captured BEFORE
    // any retire — the active-only accessors filter retired rows out once state is flipped.
    const target = store.getAgentForRevocation(name);
    if (!target) {
      return { ok: false, reason: "agent_not_found", guidance: `No agent named '${name}'. Check cello_agents.` };
    }
    const wasActive = target.state !== "retired";
    const agentId = target.localAgentId;

    // An already-retired agent that was never registered has nothing to do — no local retire (one-way,
    // already done) and no directory revocation to push. Treat a repeat removal as agent_not_found (a
    // tombstone is never re-retired). A retired agent WITH a directory id falls through to the DB-001
    // re-push below.
    if (!wasActive && !target.regAgentId) {
      return { ok: false, reason: "agent_not_found", guidance: `No active agent named '${name}'. Removal is one-way; '${name}' is already retired.` };
    }

    // DOD-REMOVE-2: build + self-sign + submit the directory revocation. Done for a fresh removal AND a
    // re-push of an already-retired agent (DB-001). Skipped only if the agent was never registered (no
    // directory-known id to revoke). The signer is re-derived from the kept K_local seed, so it works
    // even for an already-retired agent whose runtime keyProvider was purged.
    let directoryRevocation: "recorded" | "deferred" | "skipped" = "skipped";
    let revocationReason: string | undefined;
    if (target.regAgentId) {
      const signer = new InMemoryKeyProvider(target.kLocalSeed);
      const kLocalPubkeyHex = Buffer.from(await signer.getPublicKey()).toString("hex");
      const res = await submitAgentRevocation({ agentName: name, signer, kLocalPubkeyHex, regAgentId: target.regAgentId });
      directoryRevocation = res.recorded ? "recorded" : "deferred";
      revocationReason = res.reason;
      if (!res.recorded) {
        logger.error("agent.removal.failed", { agentName: name, error: res.reason ?? "directory_unreachable" });
      } else {
        logger.info("agent.revocation.recorded", { agentId: target.regAgentId });
      }
    } else if (target.state === "registered") {
      // Anomaly (fallback-finder MEDIUM): the agent is locally marked registered but has no
      // directory-known id, so the revocation cannot be pushed. Do NOT report the benign "never
      // registered" — surface it loudly so a registered-but-unrevocable agent is visible.
      revocationReason = "registered_without_directory_id";
      logger.error("agent.removal.failed", { agentName: name, error: "registered_without_directory_id" });
    }

    // Local retire (one-way) + runtime purge — only for a fresh removal. An already-retired re-push does
    // not re-retire (and has nothing loaded to purge).
    if (wasActive) {
      store.retireAgent(name);
      // Tear down the retired identity's live runtime so it can no longer receive or re-authenticate.
      // AWAITED + LOGGED on failure (review HIGH-1 / fallback-finder MEDIUM): a teardown that didn't
      // happen must be visible.
      if (onlineAgents.has(name)) {
        onlineAgents.delete(name);
        await sessionNodeManager.removeStandingReceiverForAgent(name).catch((err) => {
          logger.warn("agent.removal.receiver_teardown_failed", { agentName: name, agentId, error: err instanceof Error ? err.message : String(err) });
        });
      }
      // Stop+forget the retired agent's dedicated per-agent signaling manager (review HIGH-1).
      await dropAgentSignaling(name).catch((err) => {
        logger.warn("agent.removal.signaling_teardown_failed", { agentName: name, agentId, error: err instanceof Error ? err.message : String(err) });
      });
      keyProviders.delete(name);
      const li = loadedAgents.findIndex((a) => a.name === name);
      if (li >= 0) loadedAgents.splice(li, 1);
      const ai = agents.findIndex((a) => a.name === name);
      if (ai >= 0) agents.splice(ai, 1);
      // CELLO-M7-CONN-001 (DOD-CONN-1): no keystone to clear — the agent's OWN per-agent directory
      // connection was already torn down above (dropAgentSignaling). Removing any agent disturbs only
      // its own connection; no other agent's connection, and no shared "keystone", is affected. This is
      // the fix for the Demo1 bug (the keystone lingered authenticated as the removed agent).
      logger.info("agent.directory.connection.dropped", { agentName: name, agentId, reason: "agent_removed" });
      // Drop the retired agent as any connection's current agent.
      for (const [connId, state] of perConnectionState) {
        if (state.currentAgent === name) {
          state.currentAgent = null;
          state.clearedAgent = name; // this connection HAD an intent; do not guess a replacement
          notificationDispatcher.setCurrentAgent(connId, null);
          notificationDispatcher.dispatchAgentCurrentChanged(connId, name, null);
        }
      }
      // agent.removal.retired (observability): never log key material — only the name + agent_id.
      logger.info("agent.removal.retired", { agentName: name, agentId });
      notificationDispatcher.dispatchAgentStateChanged(name, "offline", "removed");
    }

    const baseLine = wasActive
      ? "Agent retired. This is one-way: its identity and history are kept for accountability, but it can no longer connect. The name is now free to reuse with cello create-agent."
      : "Agent was already retired locally.";
    const dirLine =
      directoryRevocation === "recorded"
        ? " A signed revocation was recorded at the directory — peers will see it as revoked."
        : directoryRevocation === "deferred"
          ? ` The directory could NOT be reached to record the revocation (${revocationReason ?? "directory_unreachable"}) — peers do not yet see it as revoked. Re-run 'cello remove-agent ${name}' when the directory is reachable to push it.`
          : revocationReason === "registered_without_directory_id"
            ? " WARNING: this agent appears registered but has no directory id recorded locally, so its revocation could NOT be pushed — peers may still see it as reachable. Check the daemon logs (agent.removal.failed)."
            : " It was never registered with a directory, so there is no directory revocation to record.";
    return { ok: true, name, agentId, oneWay: true, directoryRevocation, guidance: baseLine + dirLine };
  });

  // ─── MCP-001: cello_stop_agent handler ───
  handlers.set("cello_stop_agent", async (params, _connectionId) => {
    const name = params?.name as string | undefined;
    if (!name) {
      return { ok: false, reason: "missing_params", guidance: "Provide 'name' parameter with the agent name to stop." };
    }
    const agent = agents.find((a) => a.name === name);
    if (!agent || agent.state === "load_failed") {
      return { ok: false, reason: "agent_not_found", guidance: `Agent '${name}' does not exist. Check agent names with cello_agents.` };
    }
    if (!onlineAgents.has(name)) {
      // Idempotent — already registered/offline, no event
      return { ok: true };
    }
    onlineAgents.delete(name);
    // DOD-LOOP-1: tear down this agent's standing receiver (fire-and-forget, never throws out).
    void sessionNodeManager.removeStandingReceiverForAgent(name).catch(() => { /* best-effort */ });
    logger.info("agent.offline", { agentName: name, reason: "stopped" });
    // MCP-002: Broadcast agent_state_changed to ALL connections
    notificationDispatcher.dispatchAgentStateChanged(name, "offline", "stopped");

    // Clear current agent for all connections that had this agent as current
    for (const [connId, state] of perConnectionState) {
      if (state.currentAgent === name) {
        state.currentAgent = null;
        state.clearedAgent = name; // this connection HAD an intent; do not guess a replacement
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
      return { ok: false, reason: "agent_not_found", guidance: `Agent '${name}' does not exist. Create it with 'cello create-agent ${name}', register it, then retry — or check names with cello_agents.` };
    }
    const connState = perConnectionState.get(connectionId);
    if (!connState) {
      return { ok: false, reason: "connection_not_registered", guidance: "Send ipc.connect frame before calling agent tools." };
    }
    // M8C-AUTOSTART-1 (A1): auto-start the agent if it is not online, so the incantation collapses
    // to `login → use_agent` (no separate cello_start_agent). On a start failure, return a
    // structured agent_start_failed and leave the current selection UNCHANGED — no half-selected
    // state (A3). cello_start_agent stays available for bring-online-without-claiming.
    if (!onlineAgents.has(name)) {
      logger.info("agent.autostart.attempted", { connectionId, agentName: name });
      const startRes = startAgentInternal(name);
      if (!startRes.ok) {
        // Structured failure envelope (D6). Today `startAgentInternal` is permissive (D12) and its
        // only failure — agent_not_found — is already caught by the existence pre-check above, so
        // this branch is currently unreachable. It is the RESERVED structured-failure surface for
        // when auto-start gains a synchronous failure mode (e.g. D12's reverse: a bounded
        // waitForSignalingConnected making `directory_unreachable` a real start failure). Kept so
        // that extension surfaces the reason + guidance here with the selection left unchanged.
        // See M8C-DECISIONS D12 + BUILD-JOURNAL Entry 8.
        logger.warn("agent.autostart.failed", { connectionId, agentName: name, reason: startRes.reason });
        return {
          ok: false,
          reason: "agent_start_failed",
          start_reason: startRes.reason,
          guidance: `Could not start agent '${name}' to select it: ${startRes.guidance} Your current agent is unchanged.`,
        };
      }
    }
    if (connState.currentAgent === name) {
      return { ok: false, reason: "agent_already_current", guidance: `Agent '${name}' is already the current agent for this connection. No action needed — you can proceed with session operations.` };
    }
    const fromAgent = connState.currentAgent;
    connState.currentAgent = name;
    // A fresh choice supersedes any earlier one that was taken away. Without this a connection that
    // ever had an agent stopped under it would be refused the sole-online fallback forever, even
    // after the operator selected again.
    delete connState.clearedAgent;
    // M8C-AWAY-1: this agent just became attended — clear its away-ack dedup entries so the NEXT
    // away period (after this attended stretch ends) gets a fresh ack instead of staying silent.
    for (const key of Array.from(awayAckSent)) {
      if (key.startsWith(`${name}:`)) awayAckSent.delete(key);
    }
    // MCP-002: Update dispatcher's routing table and send notification to this connection only
    notificationDispatcher.setCurrentAgent(connectionId, name);
    notificationDispatcher.dispatchAgentCurrentChanged(connectionId, fromAgent, name);
    logger.info("agent.current.switched", { connectionId, fromAgent, toAgent: name });
    // M8C-AUTOSTART-1 (A3, D12): not_registered is a NON-BLOCKING warning — the agent is selected
    // and usable locally, but it cannot establish directory sessions until registered. Surface the
    // next step (ONBOARD-NEXTSTEP style) without stranding the selection. One-row read.
    const result: Record<string, unknown> = { ok: true };
    try {
      const reg = await new DbRegistrationPersistence({ db: sessionNodeManager.getDb(), agentName: name, logger }).loadRegistrationState();
      if (!reg || reg.status !== "active") {
        result["warning"] = "not_registered";
        result["warning_guidance"] = `Agent '${name}' is now selected but is not registered with the directory — run 'cello register-agent ${name}' to enable sessions with peers. Run 'cello status' to watch registration complete.`;
      }
    } catch (err: unknown) {
      // A failed registration read must not break selection (the agent IS selected). Log the real
      // reason, and surface a softer `registration_unknown` warning so the operator's surface is NOT
      // falsely clean — we could not confirm registration, so don't imply it is fine (Finding 3).
      logger.warn("agent.registration.read.failed", { agentName: name, reason: err instanceof Error ? err.message : String(err) });
      result["warning"] = "registration_unknown";
      result["warning_guidance"] = `Agent '${name}' is selected, but its registration status could not be read — run 'cello status' to check whether it is registered with the directory.`;
    }
    return result;
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
  // Single-flight guard (M1): the directory's registration reply frames
  // (dkg_ready / register_success / register_error) carry NO agent identifier, so
  // two concurrent registrations over the one shared directory signaling stream
  // would each arm a resolver and both receive the same reply — cross-wiring the
  // ceremonies. Serialize registration daemon-wide (it is a rare, once-per-agent,
  // human-initiated operation). This is the registration analogue of the
  // sealInterruptedInProgress guard, but global rather than per-key because the
  // frames are not agent-tagged.
  let registrationInProgress = false;

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
      return { ok: false, reason: "missing_preauth_token", guidance: "Registration requires a 'preAuthToken' issued by the CELLO Operations Agent (Telegram). Obtain one, then retry 'cello register-agent'." };
    }
    const keyProvider = keyProviders.get(name);
    if (!keyProvider) {
      return { ok: false, reason: "agent_not_found", guidance: `Agent '${name}' does not exist. Create it first with 'cello create-agent ${name}', then retry 'cello register-agent'.` };
    }
    if (!directoryEndpointResolver) {
      return { ok: false, reason: "directory_unreachable", guidance: "The daemon has no directory endpoint resolver configured, so it cannot reach the directory to register." };
    }
    // M1: claim the single-flight slot synchronously (no await between the check
    // and the set) so two concurrent calls cannot both proceed.
    if (registrationInProgress) {
      return { ok: false, reason: "registration_already_in_progress", guidance: "Another agent registration is already in progress on this daemon. Registration runs one at a time because the directory's reply frames are not agent-tagged. Wait for it to finish (check the daemon logs for registration.succeeded/failed), then retry." };
    }
    registrationInProgress = true;
    try {
      // Resolve the directory endpoint once for this registration (the context's
      // getDirectoryEndpoint is synchronous; the daemon's resolver is async).
      // FINDING-4 scope note: this uses the PRIMARY resolver directly (not the roster-aware
      // failover resolver — registration is deliberately out of FINDING-4's "signaling +
      // ceremony" scope). Because that primary is now built with staleFallback:false (so the
      // failover wrapper sees a dead primary as null), a transient /bootstrap blip here resolves
      // to null → directory_unreachable rather than riding through on a stale last-known-good;
      // registration is a rare, manual, retryable op, so failing fast (retry) is acceptable. With
      // a manifest configured the DKG fans out over the independently-probed roster regardless of
      // this endpoint. The endpoint is stable for one registration — if it changed mid-flow the
      // DKG streams would break anyway.
      const ep = await directoryEndpointResolver();
      if (!ep || !ep.multiaddr) {
        // FROST DKG must dial the directory's /cello/frost/1.0.0 — a dialable
        // multiaddr is required (DirectoryEndpoint.multiaddr is optional for the
        // already-connected signaling case, but registration needs to open streams).
        return { ok: false, reason: "directory_unreachable", guidance: "Could not resolve a dialable directory bootstrap endpoint (GET /bootstrap). Check CELLO_DIRECTORY_URL and network connectivity, then retry." };
      }
      const directoryEndpoint = { peer_id: ep.peerId, multiaddrs: [ep.multiaddr] };

      // Multi-agent: register over THIS agent's own directory signaling stream (authed
      // as this agent), so the directory routes its dkg_complete/register_success back
      // to it. CONN-001: every agent has its own dedicated stream (no shared keystone). The
      // DKG's FROST streams open on this agent's directory node.
      const agentRecord = loadedAgents.find((a) => a.name === name);
      const agentPubkeyHex = agentRecord?.pubkey ?? Buffer.from(await keyProvider.getPublicKey()).toString("hex");
      const { signaling: agentSignaling, getNode: agentGetNode } = getAgentSignaling(name, keyProvider, agentPubkeyHex);

      // A non-primary agent's stream connects lazily — wait for it before the DKG
      // (RegistrationManager returns directory_unreachable if signaling isn't connected).
      const signalingConnected = await waitForSignalingConnected(agentSignaling, 10_000);
      if (!signalingConnected) {
        // Distinct cause → distinct code (M7 error discipline): this is specifically the
        // per-agent signaling stream failing to come up in time, not a missing/unresolvable
        // directory endpoint. Drop the manager so it doesn't reconnect forever for an
        // unregistered agent (it is re-created on the next cello_register).
        await dropAgentSignaling(name);
        return {
          ok: false,
          reason: "directory_signaling_timeout",
          guidance: `Agent '${name}' could not establish its directory signaling stream within 10s. Check CELLO_DIRECTORY_URL and that the directory is reachable, then retry 'cello register-agent'.`,
        };
      }

      const persistence = getPersistence(name);
      // DOD-DKG-1: resolve the full consortium roster from the VERIFIED manifest so the DKG fans
      // across all N directory nodes. Re-resolved here (ceremony time) for fresh failover
      // coordinates. NULL when NO manifest is configured (→ single-node DKG, M6/M7 back-compat);
      // a (possibly EMPTY) array when a manifest IS configured. The null-vs-empty distinction is
      // load-bearing: an empty roster (consortium configured but unreachable) must REFUSE in
      // registration-manager, NOT downgrade to single-node (code-reviewer B1 / fallback-finder).
      const currentManifest = manifestProvider?.getCurrentManifest();
      const consortiumRoster = currentManifest
        ? await manifestNodesToEndpoints(currentManifest.nodes, { logger })
        : null;
      const ctx = new DaemonRegistrationContext({
        signaling: agentSignaling,
        getDirectoryNode: agentGetNode,
        getDirectoryEndpoint: () => directoryEndpoint,
        getConsortiumEndpoints: () => consortiumRoster,
        keyProvider,
        persistence,
        logger,
      });
      try {
        const result = await new RegistrationManager(ctx).register(phoneStub, preAuthToken);
        if ("error" in result) {
          logger.warn("registration.failed", { agentName: name, reason: result.error });
          // Terminal failure for THIS agent — drop its dedicated signaling manager so it
          // does not reconnect forever for an unregistered agent (re-created on retry).
          await dropAgentSignaling(name);
          return { ok: false, reason: result.error, guidance: registrationGuidance(result.error) };
        }
        // PERSIST-002 (AC-013): the identity row (K_local + share + ML-DSA + registration) is durably
        // committed at this point (RegistrationManager awaits the persist before returning success).
        // SI-001: never log a secret — only the agent name + PUBLIC key.
        logger.info("persist.identity.persisted", { agentName: name, agentPubkey: agentPubkeyHex });
        // CC-2 (2026-07-07): registration succeeded — arm this agent's standing receiver NOW so a
        // brand-new agent can receive inbound immediately. Without this the agent reports
        // standing_receiver_ready:false and cannot receive until the operator restarts (logout/login),
        // so a fresh registration looks broken. Uses the SAME idempotent path login and cello_use_agent
        // arm through (startAgentInternal → onlineAgents + directory signaling + ensureStandingReceiver +
        // agent_state_changed). A start failure must NOT fail the (already durably persisted)
        // registration — surface it as a warning and let the operator recover via login.
        const armResult = startAgentInternal(name);
        if (!armResult.ok) {
          logger.warn("registration.standing_receiver.arm_failed", { agentName: name, reason: armResult.reason });
        } else {
          // arm_INITIATED, not armed: startAgentInternal returns ok once the agent is online + signaling
          // is up, but ensureStandingReceiverForAgent runs fire-and-forget (its own failure emits
          // session.standing_receiver.ensure.failed) — so this event marks the start, not readiness.
          logger.info("registration.standing_receiver.arm_initiated", { agentName: name });
        }
        // Capture-now-or-lose-it: persist the agent→user link (using it is future
        // trust-layer work). L1: the agent is already registered at this point —
        // a link-write failure must NOT be reported as a registration failure.
        // Surface it as a non-fatal warning so the operator knows the link wasn't
        // captured (re-registering with the same token re-attempts it).
        try {
          await persistence.persistAgentUserLink({ agentId: result.agent_id, preAuthToken, linkedAt: Date.now() });
          logger.info("registration.succeeded", { agentName: name, agentId: result.agent_id, primaryPubkey: result.primary_pubkey });
          return { ok: true, agent_id: result.agent_id, primary_pubkey: result.primary_pubkey };
        } catch (linkErr: unknown) {
          logger.warn("registration.user_link.capture_failed", {
            agentName: name,
            agentId: result.agent_id,
            error: linkErr instanceof Error ? linkErr.message : String(linkErr),
          });
          logger.info("registration.succeeded", { agentName: name, agentId: result.agent_id, primaryPubkey: result.primary_pubkey });
          return {
            ok: true,
            agent_id: result.agent_id,
            primary_pubkey: result.primary_pubkey,
            warning: "agent_user_link_not_captured",
          };
        }
      } finally {
        ctx.dispose();
      }
    } finally {
      registrationInProgress = false;
    }
  });


  // ─── M8B DOD-REFRESH-1: cello_refresh_shares — proactive share refresh / epoch rollover ───
  handlers.set("cello_refresh_shares", async (params, connectionId) => {
    const connState = perConnectionState.get(connectionId);
    const agentName = resolveCurrentAgent(connState, params?.agent as string | undefined); // M8C-AUTOSTART-1 F18: sole-online fallback
    if (!agentName) {
      // Not an MCP tool — the CLI is the only real caller, and its gesture is the POSITIONAL
      // `cello refresh <name>`, not a JSON param. The old text said "pass { name }", which stopped
      // working at the rename and never worked on this surface anyway. cello_use_agent stays: it is
      // the other real remedy, and renderForSurface rewrites it to `cello use-agent` for a CLI caller.
      return { ok: false, reason: "no_current_agent", guidance: "Name the agent: cello refresh <name>. Or select one for this connection with cello_use_agent." };
    }
    const loaded = loadedAgents.find((a) => a.name === agentName);
    if (!loaded) {
      return { ok: false, reason: "agent_not_found", guidance: `No agent named '${agentName}'. Create + register it first.` };
    }
    // The refresh ceremony reaches the consortium over the agent's signaling node — ensure it is up.
    const entry = getAgentSignaling(agentName, loaded.keyProvider, loaded.pubkey);
    const connected = await waitForSignalingConnected(entry.signaling, 15_000);
    if (!connected) {
      return { ok: false, reason: "directory_unreachable", guidance: "The agent's directory signaling is not connected; start the agent and retry." };
    }
    const result = await runAgentRefresh({
      agentName,
      persistence: getPersistence(agentName),
      agentPubkeyHex: loaded.pubkey,
      keyProvider: loaded.keyProvider,
      getNode: entry.getNode,
      getDirectoryEndpoint: getFailoverEndpoint,
      getConsortiumEndpoints: resolveConsortiumRoster,
      signaling: entry.signaling,
      logger,
    });
    if (!result.ok) {
      return { ok: false, reason: result.reason, guidance: "Share refresh did not complete — see the daemon log (refresh.ceremony.*) for the cause." };
    }
    return { ok: true, epoch: result.toEpochN, primary_pubkey: result.primaryPubkey, verifying_shares_digest: result.verifyingSharesDigest };
  });

  // ─── M8B DOD-RELAYSIG-1: cello_get_relay_receipts — the agent's stored relay ordering receipts ───
  handlers.set("cello_get_relay_receipts", async (params, connectionId) => {
    const connState = perConnectionState.get(connectionId);
    const agentName = resolveCurrentAgent(connState, params?.agent as string | undefined); // M8C-AUTOSTART-1 F18: sole-online fallback
    if (!agentName) {
      // Not an MCP tool either — same reasoning as cello_refresh_shares above.
      return { ok: false, reason: "no_current_agent", guidance: "Name the agent: cello relay-receipts <name>. Or select one for this connection with cello_use_agent." };
    }
    const loaded = loadedAgents.find((a) => a.name === agentName);
    if (!loaded) {
      return { ok: false, reason: "agent_not_found", guidance: `No agent named '${agentName}'.` };
    }
    const sessionIdHex = typeof params?.session_id === "string" ? (params.session_id as string) : undefined;
    const receipts = sessionNodeManager.getRelayReceipts(loaded.pubkey, sessionIdHex).map((r) => ({
      hash_hex: r.hashHex,
      session_id: r.sessionIdHex,
      relay_id: r.relayId,
      sequence_number: r.sequenceNumber,
      timestamp: r.timestamp,
      signature_hex: r.signatureHex,
    }));
    return { ok: true, receipts };
  });

  // ─── MCP-001: cello_status (per-connection perspective) ───
  handlers.set("cello_status", async (_params, connectionId) => {
    return {
      daemon: "running",
      directory_signaling: directorySignalingStatus(),
      agents: getAgentsForConnection(connectionId),
      // M-1 PULL: live MCP clients must see interrupted sessions too, exactly as
      // the daemon-wide getStatus() surfaces them.
      interrupted_sessions: buildInterruptedSessions(),
      // M8B F16: per-session liveness on the MCP surface too.
      active_sessions: buildActiveSessions(),
    };
  });

  // ─── MCP-001: no_current_agent guard for session tools ───
  // cello_send / cello_receive are NOT in this stub list — DAEMON-004 registers
  // real handlers for them below (each enforces the no_current_agent guard inline).
  // NOTE: cello_await_session is NOT in this stub list — Seam 2 registers a real
  // handler for it below (inbound session establishment), with its own inline
  // no_current_agent guard.
  // The list below is an (empty) extension point: a tool that needs only the plain no_current_agent
  // guard, with no handler of its own, is registered here.
  //
  // Do not add an "accept" or "join" tool — CELLO has no such step. Inbound sessions are
  // auto-accepted by the standing receiver.
  const SESSION_TOOLS_REQUIRING_AGENT: string[] = [];

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

  // ─── CELLO-M7-TRANSPORT-001: cello_initiate_session ─────────────────────────
  // Direct-P2P-by-default transport selection (AC-005/AC-006/AC-008/AC-010c).
  // Flow:
  //   1. Require a current agent.
  //   2. Mint a correlationId for the whole session-establishment flow.
  //   3. Read the standing receiver's AutoNAT dialability → choose the advertised
  //      address (direct when dialable, relay circuit otherwise — AC-004/AC-019).
  //   4. Negotiate the FROST-signed SessionAssignment via the directory
  //      (sessionNegotiator — WIRE-001/SIGNAL-001). When no negotiator is wired,
  //      return directory_signaling_not_configured (graceful — the transport
  //      adapters ARE wired; this proves it does not crash with "adapter not wired").
  //   5. Drive the transport selector to dial the counterparty using the
  //      assignment's authoritative transport_mode (SI-001). Map the TransportResult
  //      to the MCP response.
  handlers.set("cello_initiate_session", async (params, connectionId) => {
    const connState = perConnectionState.get(connectionId);
    // CC-3 / M8C-AUTOSTART-1 F18: resolve the target agent — explicit { agent } wins, else this
    // connection's current agent, else the sole online agent (removes the no_current_agent papercut
    // after a /mcp reconnect when exactly one agent is online). 2+ online with none selected → null.
    const agentName = resolveCurrentAgent(connState, params?.agent as string | undefined);
    if (!agentName) {
      return NO_CURRENT_AGENT_RESPONSE;
    }
    const correlationId = randomUUID();

    // AC-004/AC-019: the advertised address is chosen from the standing receiver's
    // current dialability. Not dialable (or AutoNAT unavailable) → relay circuit.
    const dialability = autoNatService.getDialability();
    const relayCircuitAddr = getRelayCircuitAddress ? getRelayCircuitAddress() : "";
    const advertisedAddress = selectAdvertisedAddress(dialability, relayCircuitAddr);

    // resolvedSessionNegotiator is always defined (the daemon builds a real internal
    // negotiator when none is injected), so directory_signaling_not_configured no longer
    // fires on the live binary — session_request is actually negotiated with the directory.
    const negotiation = await resolvedSessionNegotiator.negotiate({
      agentName,
      correlationId,
      advertisedAddress,
      params: params ?? {},
    });
    if (!negotiation.ok) {
      return { ok: false, reason: negotiation.reason, guidance: negotiation.guidance };
    }

    // SI-001: the selector consumes the assignment's signed transport_mode as the
    // sole dial authority — never inferred from address format.
    const assignment = negotiation.assignment;

    // M8B F13: validate-what-you-receive at the trust boundary. When the responder cannot
    // proceed it aborts SILENTLY (session-ceremony.ts wireSessionOfferHandler sends nothing)
    // and the directory folds an EMPTY counterparty endpoint into the FROST-signed
    // assignment. Accepting that assignment produced a false ok:true + a phantom session
    // whose failure only surfaced on the first cello_send. Reject it HERE — before any
    // local session state exists — covering every cause of a missing accept (abort,
    // offline, crash, timeout) without needing a directory change.
    if (!assignment.counterparty_session_peer_id) {
      logger.warn("session.initiate.counterparty_unavailable", {
        sessionId: Buffer.from(assignment.session_id).toString("hex"),
        agentName,
        correlationId,
      });
      return {
        ok: false,
        reason: "counterparty_unavailable",
        guidance: "The counterparty did not accept the session offer (it may be offline or unable to receive). No session was established. Verify the counterparty agent is online (its operator can check cello_status), then retry cello_initiate_session.",
      };
    }

    const result = await transportSelector.dial(assignment, { correlationId });
    const sessionId = Buffer.from(assignment.session_id).toString("hex");

    if (!result.ok) {
      // Terminal: both direct and relay failed (AC-008). Pass the error through.
      return { ok: false, reason: result.reason, guidance: result.guidance };
    }

    // SEAM (initiate → DAEMON-004 session-core): transport is now established, but the
    // session does not yet exist in the daemon's session-core. Without this, initiate
    // would set up a connection no session can use and a subsequent cello_send would
    // report session_not_found. Create the DAEMON-004 session node + DB row, bound (via
    // its connection gater) to the counterparty's negotiated session peer id, so the
    // session is queryable and usable (cello_send / cello_receive / cello_close_session).
    //
    // NOTE (seam 1b, next): the session node N_A created here does NOT yet share the
    // connection that transportSelector.dial established on the separate transportDialer
    // node — so its content newStream cannot ride that link until the dial is routed
    // THROUGH N_A. Tracked as the dialer/session-node reconciliation; this seam only
    // establishes that initiate creates the session-core session.
    // The initiator's session row must record WHO this session is with, so an interrupted
    // initiator session surfaces its counterparty at next login (DOD-INT-1). The public
    // tool param is `target_pubkey` (the counterparty's K_local) — the same field the
    // negotiator reads above; `counterparty_pubkey` is the legacy fallback. Reading only
    // the legacy field stored an EMPTY counterparty on every initiator session.
    const counterpartyPubkey =
      typeof params?.target_pubkey === "string"
        ? params.target_pubkey
        : typeof params?.counterparty_pubkey === "string"
          ? params.counterparty_pubkey
          : "";
    const counterpartyPeerId = assignment.counterparty_session_peer_id ?? "";
    // M7 DOD-SPINE-6 / MSG-001-3b: relay witness params from the FROST-signed assignment
    // + this agent's K_local. N_A connects to the relay and submits message-leaf hashes.
    const relayParams = await buildRelayConnectParams(agentName, assignment);
    const created = await sessionNodeManager.createSessionNode(
      sessionId,
      agentName,
      counterpartyPubkey,
      counterpartyPeerId,
      correlationId,
      // Reuse the standing receiver as N_A so its peer id matches the session endpoint the
      // negotiator advertised — the counterparty's gater admits the dial (WIRE-002).
      true,
      relayParams,
    );
    if (!created.ok) {
      return { ok: false, reason: created.reason, guidance: created.guidance };
    }

    // SEAM 1b: the session node N_A must hold the connection its content stream rides — so
    // dial the counterparty THROUGH N_A. The counterparty's advertised SESSION addresses are
    // the source of truth for dialability (a NATed node advertises a relay-circuit address; a
    // directly-reachable one — localhost or a public addr — advertises a direct multiaddr), so
    // attempt the dial whenever the assignment carries counterparty session addrs, regardless
    // of the transport_mode LABEL (the local selector stub labels everything "relay" even when
    // the addrs are directly dialable). A failure is NOT fatal: per the dead-channel contract,
    // the session stays active and a later cello_send queues the content in the durable retry
    // queue until a route exists (the relay-park path is MSG-001-3b).
    const counterpartyAddrs = assignment.counterparty_session_addrs ?? [];
    if (counterpartyAddrs.length > 0) {
      const connected = await sessionNodeManager.connectToCounterparty(agentName, sessionId, counterpartyAddrs);
      if (!connected.ok) {
        logger.warn("session.initiate.connect.failed", {
          sessionId,
          reason: connected.reason,
          error: connected.error,
          transportMode: assignment.transport_mode,
          correlationId,
        });
      }
    }

    // M8C-CONTACT-1 (D6): "initiating a session to X adds X" — pin at the pubkey the negotiator
    // actually used (not re-resolved later). DOD-TIER-4 AC3: a deliberate outbound initiate makes the
    // counterparty KNOWN, provenance 'initiated'. (Not WHITELISTED — auto-accept stays an explicit
    // cello_contact_set_tier act, design §1.)
    sessionNodeManager.addContact(agentName, counterpartyPubkey, undefined, "initiated", TIER.KNOWN);

    // AC-007: the session is usable immediately upon (relay) connection — the dcutr
    // upgrade runs in the background and is intentionally NOT awaited here.
    return { ok: true, sessionId, transportMode: result.mode, correlationId };
  });

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
    // CC-3 / M8C-AUTOSTART-1 F18: explicit { agent } > this connection's current > sole online agent.
    const agentName = resolveCurrentAgent(connState, params?.agent as string | undefined);
    if (!agentName) {
      return NO_CURRENT_AGENT_RESPONSE;
    }

    // round-2 BLOCKING: the public IPC contract field is snake_case `session_id`
    // (this is what cello-mcp.ts forwards verbatim through IpcProxy, matching the
    // rest of the public MCP tool surface — target_pubkey, content_hash, timeout_ms).
    // Reading camelCase `sessionId` here meant every real proxy invocation produced
    // undefined → missing_params. Consume the field the producer actually sends.
    const sessionId = params?.session_id as string | undefined;
    if (!sessionId) {
      return {
        ok: false,
        reason: "missing_params",
        guidance: "Provide 'session_id' parameter with the hex session ID to close.",
      };
    }

    // DOD-SESSION-NAME-1 (AC-A6): THE NAME MUST NEVER BREAK THE CLOSE. A close is a seal ceremony
    // and the seal is the valuable thing — a notarized receipt both parties keep. So a bad name is
    // refused HERE, before any of it starts: not half-closed-then-failed, and not silently dropped
    // and sealed anyway. Validate, then close. The name is a sticky note; it does not get a vote on
    // whether the notarization happens.
    const nameCheck = validateSessionName(params?.session_name);
    if (!nameCheck.ok) {
      logger.warn("session.name.rejected", {
        // agentId, not agentName — session.name.set/.cleared key on agentId (AC-A16), and an
        // operator correlating rejections against sets on two different keys gets nothing.
        agentId: sessionNodeManager.resolveAgentId(agentName), sessionId, reason: nameCheck.reason, source: "close",
        nameLength: typeof params?.session_name === "string" ? (params.session_name as string).length : null,
      });
      return { ok: false, reason: nameCheck.reason, guidance: nameCheck.guidance };
    }

    // DOD-LOOP-1: scope the lookup to the current agent — the composite (agent, session_id) key IS
    // the ownership scope. A session_id owned only by a DIFFERENT agent does not exist in this
    // agent's namespace (returns null → session_not_found), which is correct for loopback (two
    // agents can hold the same session_id on one daemon).
    const record = sessionNodeManager.getSessionRecord(agentName, sessionId);
    if (!record) {
      return {
        ok: false,
        reason: "session_not_found",
        guidance: "No session found with this ID. Check cello_sessions for active and interrupted sessions.",
      };
    }

    // Ownership: redundant now that the lookup is agent-scoped (record.agent_name === currentAgent),
    // kept as a defensive invariant.
    if (record.agent_name !== agentName) {
      return {
        ok: false,
        reason: "session_not_owned",
        guidance: "This session belongs to a different agent. Call cello_use_agent to switch to the agent that owns it (see cello_sessions), then retry.",
      };
    }

    // DOD-SESSION-NAME-1 (AC-A7): the name is written HERE — once, on the way in — rather than at
    // each of the terminal exits (bilateral seal, unilateral seal, force-abandon). Threading it
    // through all of them is how one silently ends up without it, and a name dropped on the very
    // path where it is most useful (a force-abandoned ghost is the session you most want to identify
    // later) is a defect nothing would fail on.
    //
    // It sits ABOVE the status gates deliberately. A name is not close-scoped: renaming is legal in
    // ANY status (AC-A9), sealed included. Below the already-sealed gate, a RETRIED close carrying a
    // name — the seal completed but the agent's call was interrupted, so it calls again — would be
    // answered "already sealed, no further action is needed" and the name would be silently dropped,
    // on exactly the path where the agent believes it just named the session.
    //
    // Writing it before the close COMPLETES is safe for the same reason: if the seal below fails, the
    // operator has a named open session — a state they could produce with cello_name_session anyway.
    // Nothing about the name gates, delays, or alters the ceremony.
    if (nameCheck.value !== null) {
      sessionNodeManager.setSessionName(agentName, sessionId, nameCheck.value);
      logger.info("session.name.set", {
        agentId: record.agent_id, sessionId, nameLength: nameCheck.value.length, source: "close",
      });
    }

    // AC-010: already sealed
    if (record.status === "sealed") {
      return {
        ok: false,
        reason: "session_already_sealed",
        // A name given here WAS applied (above) — say so, rather than let "no further action is
        // needed" imply the name went nowhere.
        ...(nameCheck.value !== null ? { session_name: nameCheck.value } : {}),
        guidance: nameCheck.value !== null
          ? "This session is already sealed, so it was not closed again — but the name you gave WAS applied. Check cello_sessions to view its sealed record and the FROST notarization."
          : "This session is already sealed. No further action is needed — check cello_sessions to view its sealed record and the FROST notarization.",
      };
    }

    // An ABANDONED session is TERMINAL, and a close without --force must say so rather than try to
    // seal it. The already-abandoned early-return below lives INSIDE the force branch, so a plain
    // `cello close-session <abandoned-id>` fell through to the seal flow and fired a bilateral seal
    // ceremony at a counterparty that, by definition, was never there — the exact unsealable hang
    // that force exists to escape, re-entered from the other side. Found by the unit reviewer on this
    // diff; pre-existing, fixed here rather than left for someone to hit in the dark.
    // Scoped to the NON-force path: `force` on an already-abandoned session stays idempotent
    // (ok:true / already_abandoned, below) — that contract is tested and must not change.
    if (record.status === "abandoned" && params?.force !== true) {
      return {
        ok: false,
        reason: "session_abandoned",
        guidance: "This session was force-abandoned — it is terminal and has no counterparty to seal with, so it cannot be closed. It is already off the open list; check cello_sessions.",
      };
    }

    // CC-5/F21 terminal-escape: force-abandon a session that can never be bilaterally sealed — a
    // half-open handshake the counterparty never joined, whose normal close fires a seal the absent/
    // rejecting counterparty can't complete (seal_interrupted_rejected_by_counterparty / timeout). Marks
    // it locally-terminal ("abandoned") with NO seal, so it leaves the open list. Additive: placed BEFORE
    // the seal branches, it never touches the seal flow. Owner-scoped (the lookup above is agent-scoped)
    // and idempotent. NOT for a healthy session — a normal close (no force) still seals so both parties
    // get a notarized receipt; force is the escape hatch for a provably unsealable ghost.
    if (params?.force === true) {
      if (record.status === "abandoned") {
        return { ok: true, status: "abandoned", reason: "already_abandoned", guidance: "This session was already force-abandoned." };
      }
      await sessionNodeManager.abandonSession(record.agent_name, sessionId);
      logger.info("session.force_abandoned", { agentName: record.agent_name, sessionId, priorStatus: record.status });
      return {
        ok: true,
        status: "abandoned",
        reason: "force_abandoned",
        guidance: `Session ${sessionId} was force-abandoned — marked terminal locally with no bilateral seal. Use force only for a half-open session that cannot be sealed; a normal close (no force) still attempts the seal so both parties get a notarized receipt.`,
      };
    }

    // AC-011: seal-interrupted already in progress
    if (sealInterruptedInProgress.has(sealKey(record.agent_name, sessionId))) {
      return {
        ok: false,
        reason: "seal_interrupted_in_progress",
        guidance: "A seal-interrupted attempt is already in progress for this session. Wait for session.interrupted.sealed to appear in the daemon logs before retrying. Do not call cello_close_session again until the current attempt completes or times out.",
      };
    }

    // DB-001: signaling stream reconnecting
    if (record.status === "interrupted" && signalingFor(record.agent_name)?.status === "reconnecting") {
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
      sealInterruptedInProgress.add(sealKey(record.agent_name, sessionId));
      const correlationId = randomUUID();
      try {
        return await handleSealInterruptedFlow(sessionId, record, correlationId, merkleRootAtInterruption);
      } finally {
        sealInterruptedInProgress.delete(sealKey(record.agent_name, sessionId));
      }
    }

    // CELLO-M7-DAEMON-004 (AC-003): ACTIVE session — initiate the active-session
    // seal over the daemon's OWN tree root. SI-001: any caller-supplied
    // merkleRoot is IGNORED; the daemon signs only the root it built itself.
    //
    // round-2 finding #4: the active path must take the SAME concurrency guard as
    // the interrupted path (the top-of-handler check at sealInterruptedInProgress.has
    // rejects re-entry). Without adding to the set here, two concurrent active closes
    // would both send a seal_interrupted_request and both await acks (double seal).
    if (record.status === "active") {
      sealInterruptedInProgress.add(sealKey(record.agent_name, sessionId));
      const correlationId = randomUUID();
      // Fix #1 (cross-node seal-liveness): if this session was brokered by another node, the seal_verified
      // + session_sealed frames are pushed by that BROKER — but the initiator released its visiting
      // connection after setup, so on the home stream they never arrive and close times out. Re-open a
      // transient visiting connection to the broker (seal-capable — openVisitingConnection now wires the
      // seal handlers) for the duration of the seal, then release it in finally. Same-node sessions have
      // no entry here and use the home stream unchanged.
      let sealBrokerConn: { stop: (reason: string) => Promise<void> } | null = null;
      try {
        const brokerNodeForSeal = crossNodeBrokerBySession.get(`${record.agent_name}:${sessionId}`);
        if (brokerNodeForSeal) {
          const sealKp = keyProviders.get(record.agent_name);
          if (!sealKp) {
            // Fallback-finder #1: never skip the cross-node reconnect silently — without a key provider
            // we cannot open the broker connection, so the seal will revert to the pre-fix timeout. Log
            // WHY so it is not indistinguishable from a normal counterparty-didn't-close timeout.
            logger.warn("session.seal.broker.no_keyprovider", { agentName: record.agent_name, brokerNode: brokerNodeForSeal, correlationId });
          } else {
            const sealPubHex = Buffer.from(await sealKp.getPublicKey()).toString("hex");
            const roster = await resolveConsortiumRoster();
            const brokerTarget = roster?.find((e) => e.nodeId === brokerNodeForSeal) ?? null;
            if (!brokerTarget) {
              logger.warn("session.seal.broker.unresolved", { agentName: record.agent_name, brokerNode: brokerNodeForSeal, correlationId });
            } else {
              const conn = openVisitingConnection(record.agent_name, sealKp, sealPubHex, { peerId: brokerTarget.peerId, multiaddr: brokerTarget.multiaddr }, correlationId, brokerNodeForSeal);
              if (await waitForSignalingConnected(conn.mgr, 10_000)) {
                sealBrokerConn = conn;
                logger.info("session.seal.broker.reconnected", { agentName: record.agent_name, brokerNode: brokerNodeForSeal, correlationId });
              } else {
                await conn.stop("seal-broker-unreachable");
                logger.warn("session.seal.broker.unreachable", { agentName: record.agent_name, brokerNode: brokerNodeForSeal, correlationId });
              }
            }
          }
        }
        // M7 DOD-SPINE-7: relay-mediated bilateral seal. Submit our SEAL ctrl leaf to the
        // relay witness; when the counterparty ALSO closes, the relay's #maybeProcessSeal
        // fires → directory processSeal rebuilds + verifies the signed chain → FROST
        // notarization → session_sealed to BOTH parties. Register the waiter BEFORE
        // submitting so the notification can never race ahead of us.
        let resolveSeal!: (completion: SealCompletion) => void;
        const sealedP = new Promise<SealCompletion>((r) => { resolveSeal = r; });
        pendingSealWaiters.set(sealKey(record.agent_name, sessionId), resolveSeal);
        const submit = await sessionNodeManager.submitSealLeaf(record.agent_name, sessionId, correlationId);
        // M7-UPGRADE-002: the auto-acknowledge path may have already submitted THIS party's
        // responder SEAL leaf (it won the race against this explicit close). That is success, not
        // failure — keep the waiter registered and fall through to await session_sealed (the
        // auto-ack's submission drives the same bilateral seal).
        if (!submit.ok && submit.reason !== "responder_seal_already_submitted") {
          pendingSealWaiters.delete(sealKey(record.agent_name, sessionId));
          if (submit.reason === "relay_unavailable") {
            // No relay witness for this session (direct/interrupted) — fall back to the
            // directory-mediated bilateral-ack seal.
            return await handleActiveSealFlow(sessionId, record, correlationId);
          }
          return {
            ok: false,
            reason: submit.reason,
            guidance: "The SEAL leaf could not be submitted to the relay witness. Retry once the relay is reachable (cello status).",
          };
        }
        // Both parties must close for the directory to notarize. Await session_sealed; a
        // timeout means the counterparty has not closed yet (our leaf is recorded — the
        // session seals when they call cello_close_session). CELLO_SEAL_BILATERAL_TIMEOUT_MS
        // tunes how long to wait for the counterparty before escalating to a unilateral seal.
        const bilateralTimeoutMs = Number(process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"]) || 30_000;
        let timer!: ReturnType<typeof setTimeout>;
        const timeoutP = new Promise<null>((r) => { timer = setTimeout(() => r(null), bilateralTimeoutMs); });
        const sealedCompletion = await Promise.race([sealedP, timeoutP]);
        clearTimeout(timer);
        pendingSealWaiters.delete(sealKey(record.agent_name, sessionId));
        if (sealedCompletion !== null) {
          logger.info("session.seal.completed", { sessionId, sealedRoot: sealedCompletion.rootHex, role: "bilateral", correlationId });
          crossNodeBrokerBySession.delete(`${record.agent_name}:${sessionId}`); // Fix #1 review: evict on terminal seal success (a FAILED close keeps the entry so a retry can still reconnect).
          // M7-SESSION-004 (AC-006): return the legibility certificate on the seal completion so
          // a reader gets it on the same surface that proves the seal — receipt-not-assent,
          // per-party frontiers, attestation modes, and final_message.answered.
          return { ok: true, sealed_root: sealedCompletion.rootHex, legibility: sealedCompletion.legibility };
        }

        // M8B FINDING-1: `responder_seal_already_submitted` has two producers — (a) the auto-ack
        // path submitted our leaf because the COUNTERPARTY's SEAL arrived, or (b) our OWN earlier
        // close submitted it and the counterparty never co-closed. The result now carries the
        // first submit's reportedRootHex/sequenceNumber, so a retry close can still escalate to a
        // unilateral seal (case b — the live-deadlock path). We deliberately do NOT distinguish
        // (a) from (b) client-side: the bilateral wait above already gave case (a) its window, and
        // the directory's grace/already-sealed gates arbitrate a redundant seal_unilateral — that
        // is the sovereign-node-correct shape. Only when the not-ok result carries NO root (the
        // first submit is still in flight) is "pending" the honest terminal answer here.
        const escalation = submit.ok
          ? { reportedRootHex: submit.reportedRootHex, sequenceNumber: submit.sequenceNumber }
          : submit.reason === "responder_seal_already_submitted" &&
              typeof submit.reportedRootHex === "string" &&
              typeof submit.sequenceNumber === "number"
            ? { reportedRootHex: submit.reportedRootHex, sequenceNumber: submit.sequenceNumber }
            : null;
        if (!escalation) {
          return {
            ok: false,
            reason: "seal_pending_bilateral",
            guidance: "Your SEAL leaf is recorded (auto-acknowledged) and the bilateral seal is completing, but it did not finalize within the wait window. Check cello status and the daemon logs; retry cello_close_session if the session remains unsealed.",
          };
        }

        // SESSION-002 (DOD-SEAL): the counterparty did not co-close. Escalate to a UNILATERAL
        // seal — submit a seal_unilateral request carrying our reported_root (the content-hash
        // root the directory rebuilds from the relay chain and verifies). The directory enforces
        // the delivery-grace gate; if grace has not elapsed it replies seal_unilateral_too_early.
        let resolveUni!: (r: UnilateralResult) => void;
        const uniP = new Promise<UnilateralResult>((r) => { resolveUni = r; });
        pendingUnilateralWaiters.set(sessionId, resolveUni);
        // FED-OPTIONB-SEAL-001 (Option B): carry the full leaf chain (both parties) + the relay receipts so
        // the directory rebuilds + verifies the tree OFFLINE — no directory→relay getSealLeaves dial. The
        // store is keyed by the agent's K_local pubkey (the same key the relay client recorded under).
        const sealAgentKp = keyProviders.get(record.agent_name);
        const sealAgentPubkeyHex = sealAgentKp ? Buffer.from(await sealAgentKp.getPublicKey()).toString("hex") : "";
        const sealCarry = sealAgentPubkeyHex ? sessionNodeManager.getSealCarry(sealAgentPubkeyHex, sessionId) : [];
        const seal_leaves = sealCarry.map((l) => ({
          sequence_number: l.sequenceNumber,
          leaf_kind: l.leafKind,
          structure2_cbor: l.structure2Cbor,
          structure1_cbor: l.structure1Cbor,
          // Relay receipt (present only for the present party's OWN leaves — the seq-pinning teeth).
          relay_id: l.relayId,
          relay_timestamp: l.relayTimestamp,
          relay_signature: l.relaySignatureHex ? new Uint8Array(Buffer.from(l.relaySignatureHex, "hex")) : undefined,
        }));
        const sent = await sendOver(record.agent_name, {
          type: "seal_unilateral",
          session_id: new Uint8Array(Buffer.from(sessionId, "hex")),
          reported_root: new Uint8Array(Buffer.from(escalation.reportedRootHex, "hex")),
          reported_seq: escalation.sequenceNumber,
          seal_leaves,
        });
        if (!sent.ok) {
          pendingUnilateralWaiters.delete(sessionId);
          return {
            ok: false,
            reason: "seal_unilateral_send_failed",
            guidance: "The unilateral seal request could not be sent to the directory. Check the directory connection (cello status) and retry cello_close_session.",
          };
        }
        let uniTimer!: ReturnType<typeof setTimeout>;
        const uniTimeoutP = new Promise<UnilateralResult>((r) => {
          uniTimer = setTimeout(() => r({ ok: false, reason: "seal_unilateral_timeout" }), 30_000);
        });
        const uniResult = await Promise.race([uniP, uniTimeoutP]);
        clearTimeout(uniTimer);
        pendingUnilateralWaiters.delete(sessionId);
        if (uniResult.ok) {
          logger.info("session.seal.completed", { sessionId, sealedRoot: uniResult.sealedRootHex, role: "unilateral", correlationId });
          crossNodeBrokerBySession.delete(`${record.agent_name}:${sessionId}`); // Fix #1 review: evict on terminal seal success (a FAILED close keeps the entry so a retry can still reconnect).
          // M8B FINDING-3 (cascade-2): return the legibility certificate inline — same shape as the
          // bilateral close (AC-006) — so the operator gets the receipt on the surface that proves
          // the seal, not just a bare root. It is also persisted (above) for cello_get_sealed_receipt.
          return {
            ok: true,
            sealed_root: uniResult.sealedRootHex,
            seal_type: "unilateral",
            ...(uniResult.legibility !== undefined ? { legibility: uniResult.legibility } : {}),
          };
        }
        if (uniResult.reason === "seal_unilateral_too_early") {
          // F20: tell the operator WHEN the unilateral seal becomes available, not just "later".
          const when =
            typeof uniResult.remainingSeconds === "number"
              ? `A unilateral seal becomes available in ~${uniResult.remainingSeconds}s. `
              : "";
          return {
            ok: false,
            reason: "seal_counterparty_pending",
            guidance: `Your SEAL leaf is recorded, but the counterparty has not closed and the directory's delivery-grace window has not yet elapsed, so a unilateral seal is not yet allowed. ${when}Retry cello_close_session after the grace period, or once the counterparty closes.`,
          };
        }
        return {
          ok: false,
          reason: uniResult.reason,
          guidance: "The unilateral seal did not complete (the directory could not verify the reported root, or the certificate failed verification). Confirm your messages reached the relay (cello_sessions) before retrying cello_close_session.",
        };
      } finally {
        // Fix #1: release the transient broker seal-connection (best-effort; the seal result stands).
        if (sealBrokerConn) {
          try { await sealBrokerConn.stop("seal-complete"); }
          catch (err: unknown) { logger.warn("session.seal.broker.release_failed", { sessionId, reason: err instanceof Error ? err.message : String(err) }); }
        }
        sealInterruptedInProgress.delete(sealKey(record.agent_name, sessionId));
      }
    }

    // Any other status (e.g. seal_interrupted_pending) — nothing to do.
    return {
      ok: false,
      reason: "session_not_closeable",
      guidance: `Session is in status '${record.status}', which cannot be closed via cello_close_session. Check cello_sessions; a seal_interrupted_pending session is awaiting FROST notarization.`,
    };
  });

  // ─── MCP-001: stubs for tools registered in cello-mcp.ts but not yet implemented ───
  // These return not_implemented (same as session tools) so LLMs get consistent guidance.
  for (const tool of ["cello_backup", "cello_restore", "cello_get_inclusion_proof"]) {
    handlers.set(tool, async (_params, _connectionId) => {
      return { ok: false, reason: "not_implemented", guidance: `'${tool}' is not yet implemented in the daemon. This feature will be available in a future milestone.` };
    });
  }

  // ─── M7-SESSION-004 (AC-005/AC-006): read the sealed certificate's legibility ───
  // The cert-read surface: returns the receipt-not-assent certificate for a sealed session —
  // per-party content frontiers, attestation modes, and whether the final message was answered.
  // Reads the PERSISTED record, so it works after a daemon restart and from a DIFFERENT process
  // than the one that built the certificate (an arbitrator reading the receiving side). The
  // legibility states, as a first-class machine-readable property, that a signature attests
  // receipt — never assent (implies_assent: false); a malicious unanswered tail reads as
  // delivered-but-unanswered (final_message.answered: false), never agreed.
  handlers.set("cello_get_sealed_receipt", async (params, connectionId) => {
    // cello-mcp forwards this as { session_id } (snake_case, matching the other session tools).
    const sessionId = params?.["session_id"] as string | undefined;
    if (!sessionId || typeof sessionId !== "string") {
      return { ok: false, reason: "missing_session_id", guidance: "Provide the session_id (hex) of the sealed session. Check cello_sessions for sealed sessions." };
    }
    // DOD-LOOP-1: the certificate is keyed by (agent, session_id) — read the current agent's.
    const connState = perConnectionState.get(connectionId);
    // CC-3 / M8C-AUTOSTART-1 F18: resolve the target agent — explicit { agent } wins, else this
    // connection's current agent, else the sole online agent (removes the no_current_agent papercut
    // after a /mcp reconnect when exactly one agent is online). 2+ online with none selected → null.
    const agentName = resolveCurrentAgent(connState, params?.agent as string | undefined);
    if (!agentName) {
      return NO_CURRENT_AGENT_RESPONSE;
    }
    const cert = sessionNodeManager.getSealCertificate(agentName, sessionId);
    if (cert) {
      // DOD-SESSION-NAME-1 (AC-A12): echo the name so the output is self-describing — you already
      // hold the id, so the name is free context. It is display only: nothing in the certificate,
      // the sealed root, or the legibility object is derived from it.
      const sessionName = sessionNodeManager.getSessionRecord(agentName, sessionId)?.session_name ?? null;
      return { ok: true, session_id: sessionId, session_name: sessionName, sealed_root: cert.sealed_root, legibility: cert.legibility };
    }
    // M8C-INBOX-1 (F4): the single `sealed_receipt_not_found` conflated four distinct causes, so a
    // caller could not tell a typo from a not-sealed-yet session from a wrong-agent selection.
    // Split them (full session ids on cello_list_sessions / cello_status already let a pasted id match).
    if (sessionNodeManager.getSessionRecord(agentName, sessionId)) {
      // The session is THIS agent's — it simply has no seal certificate yet.
      return {
        ok: false,
        reason: "not_sealed_yet",
        guidance: "This session exists but is not sealed yet. Close it with cello_close_session and confirm it reports sealed (or wait for the counterparty to co-seal), then retry.",
      };
    }
    // Owned by a DIFFERENT loaded agent → the caller has the wrong current agent selected.
    const owner = loadedAgents.find((a) => a.name !== agentName && sessionNodeManager.getSessionRecord(a.name, sessionId));
    if (owner) {
      return {
        ok: false,
        reason: "wrong_agent",
        guidance: `This session belongs to agent '${owner.name}', not the current agent '${agentName}'. Call cello_use_agent('${owner.name}') then retry cello_sealed_receipt.`,
      };
    }
    // A truncated paste: the id is a strict prefix of one of this agent's real session ids.
    const truncated = sessionNodeManager
      .getSessionsForAgent(agentName)
      .some((s) => s.session_id.startsWith(sessionId) && s.session_id.length > sessionId.length);
    if (truncated) {
      return {
        ok: false,
        reason: "session_id_too_short",
        guidance: "That looks like a truncated session id. cello_sessions and cello status show the FULL id — copy the complete id and retry.",
      };
    }
    return {
      ok: false,
      reason: "unknown_session",
      guidance: "No session with this id belongs to the current agent. Run cello_sessions to see the full ids of this agent's sessions.",
    };
  });

  // DOD-LOG-1 (PERSIST-LOG-001): read the durable, decrypted conversation transcript for a session —
  // the readable sent+received messages in canonical-sequence order, recovered AFTER a daemon restart
  // (not just the opaque hash chain). The plaintext is decrypted from the encrypted-at-rest store here,
  // in the daemon; the relay/directory never held it (INV-3).
  handlers.set("cello_get_transcript", async (params, connectionId) => {
    const sessionId = params?.["session_id"] as string | undefined;
    if (!sessionId || typeof sessionId !== "string") {
      return { ok: false, reason: "missing_session_id", guidance: "Provide the session_id (hex) whose transcript to read. See cello_sessions." };
    }
    const connState = perConnectionState.get(connectionId);
    // CC-3 / M8C-AUTOSTART-1 F18: explicit { agent } > this connection's current > sole online agent.
    const agentName = resolveCurrentAgent(connState, params?.agent as string | undefined);
    if (!agentName) {
      return NO_CURRENT_AGENT_RESPONSE;
    }
    const { messages, undecryptable } = sessionNodeManager.readTranscript(agentName, sessionId);
    // undecryptable > 0 means some rows failed GCM auth (tamper / wrong key) — surfaced, not hidden,
    // so the reader can tell a real gap from an empty transcript.
    // M8C-CURSOR-1: this is the ONLY reader that covers BOTH directions (sent + received), so it's
    // the correct general catch-up path — e.g. a second attended connection on the same agent
    // catching up on a message a DIFFERENT local connection sent (since_seq is received-only and
    // would never surface it). Route through safeCursorAdvance rather than trusting the raw max —
    // reviewer HIGH finding (aa5928e2/a9099571): recordTranscriptMessage swallows a DB write
    // failure without rolling back the tree's leaf count, so a hole in `messages` is possible in
    // principle; the contiguous-run walk refuses to vault the cursor past such a hole even here.
    const deliveredSeqs = new Set(messages.map((m) => m.sequence));
    safeCursorAdvance(connectionId, sessionId, deliveredSeqs);
    // DOD-CURSOR-DURABLE-1 (AC3): reading the full history IS reading — so this must advance the
    // PERSISTED watermark too, not just this connection's in-memory cursor. Previously it advanced
    // only the cursor, which made the gate's own guidance ("call cello_get_transcript, then retry")
    // a dead end for any stateless client: a fresh process reads the transcript, exits, and the next
    // process still presents an unread count. Same contiguous-run safety as the cursor — never vault
    // past a gap (an undecryptable row is absent from `messages`, so the walk stops there and those
    // messages correctly stay unread).
    safeWatermarkAdvance(agentName, sessionId, deliveredSeqs);
    // DOD-SESSION-NAME-1 (AC-A12): the name rides along so a transcript dump says what it is of.
    const transcriptName = sessionNodeManager.getSessionRecord(agentName, sessionId)?.session_name ?? null;
    return { ok: true, session_id: sessionId, session_name: transcriptName, messages, undecryptable };
  });

  // cello_list_sessions: the discovery surface — every persisted session for the
  // current agent (active, interrupted, sealed, seal_interrupted_pending), newest
  // updated first. This is where cello_get_transcript / cello_get_sealed_receipt
  // get their session ids; without it those by-id reads have no starting point,
  // and the guidance strings that point here ("See cello_list_sessions") dead-end.
  // Read from the persisted SQLite store, so it works after a daemon restart and
  // from a fresh MCP connection (no in-memory session-node required).
  // Classify → filter → cap a set of session rows into a SessionListResponse. Shared by the
  // per-agent MCP surface (cello_list_sessions) and the daemon-wide CLI surface (list_sessions),
  // so the operator-facing categories (open/closed/failed) and the default cap never drift.
  // Default filter = "open" (live/resumable only — the common case); default limit bounds the
  // response so a long-lived agent's history can't balloon it. `all` includes failed/closed.
  const DEFAULT_LIST_LIMIT = 50;
  const MAX_LIST_LIMIT = 500;
  function selectSessions(
    rows: SessionRecord[],
    params: Record<string, unknown> | undefined,
  ): SessionListResponse {
    const rawFilter = typeof params?.filter === "string" ? params.filter : "open";
    const filter: SessionListResponse["filter"] =
      rawFilter === "closed" || rawFilter === "failed" || rawFilter === "all" ? rawFilter : "open";
    let limit = Number(params?.limit);
    if (!Number.isFinite(limit) || limit < 1) limit = DEFAULT_LIST_LIMIT;
    limit = Math.min(Math.floor(limit), MAX_LIST_LIMIT);

    const classified = rows.map((row) => {
      const messageCount = row.message_count ?? 0;
      const category: SessionCategory = classifySession(row.status, messageCount);
      return { row, messageCount, category };
    });
    const matched =
      filter === "all" ? classified : classified.filter((c) => c.category === filter);
    const sessions: SessionListEntry[] = matched.slice(0, limit).map(({ row, messageCount, category }) => ({
      sessionId: row.session_id,
      // DOD-SESSION-NAME-1 (AC-A13): SECOND, immediately after the id — not last. Every list surface
      // renders as JSON, and JSON.stringify preserves insertion order, so key position IS layout: at
      // the end of the entry the name prints ~11 lines below the id it belongs to, and scanning a
      // 50-session dump for "which one was the deploy" is the exact problem this column exists to
      // solve. Alongside the id, never instead of it — the id is what you paste into the next command.
      sessionName: row.session_name ?? null,
      agentName: row.agent_name,
      counterpartyPubkey: row.counterparty_pubkey,
      // MONIKER-5 AC1: the same resolution the doorbell uses — pet name ?? offered ?? fingerprint.
      ...resolveWho(row.agent_name, row.counterparty_pubkey, row.session_id),
      status: row.status,
      category,
      messageCount,
      createdAt: new Date(row.created_at).toISOString(),
      updatedAt: new Date(row.updated_at).toISOString(),
      // interrupted_at is the canonical ISO interruption stamp; null for any
      // session that was never interrupted (active/sealed).
      interruptedAt: row.interrupted_at ?? null,
    }));
    return { ok: true, filter, limit, totalMatched: matched.length, sessions };
  }

  // cello_list_sessions (MCP, per current agent): the discovery surface for the by-id reads
  // (cello_get_transcript / cello_get_sealed_receipt). Accepts { filter?: open|closed|failed|all,
  // limit?: number } — defaults to open + DEFAULT_LIST_LIMIT so failed/dead handshakes don't drown
  // the live ones. Read from persisted SQLite, so it survives a daemon restart / fresh connection.
  handlers.set("cello_list_sessions", async (params, connectionId) => {
    const connState = perConnectionState.get(connectionId);
    // CC-3 / M8C-AUTOSTART-1 F18: explicit { agent } > this connection's current > sole online agent.
    const agentName = resolveCurrentAgent(connState, params?.agent as string | undefined);
    if (!agentName) {
      return NO_CURRENT_AGENT_RESPONSE;
    }
    reapDeadHalfOpenSessions(agentName); // CC-5/F21: drop provably-dead half-open sessions before listing
    return selectSessions(
      sessionNodeManager.getSessionsForAgent(agentName),
      params as Record<string, unknown> | undefined,
    );
  });

  // ─── DOD-SESSION-NAME-1: cello_name_session — set or clear THIS agent's label for a session ───
  // Set-or-clear-by-null, mirroring cello_contact_set_moniker. Works in ANY status: naming a
  // long-sealed session for archival clarity is the point of the tool, not an edge case. The only
  // scope is ownership — the (agent_id, session_id) row must be this agent's, which for the loopback
  // case correctly means each of the operator's two agents renames only its OWN row.
  handlers.set("cello_name_session", async (params, connectionId) => {
    const connState = perConnectionState.get(connectionId);
    const agentName = resolveCurrentAgent(connState, params?.agent as string | undefined);
    if (!agentName) return NO_CURRENT_AGENT_RESPONSE;

    const sessionId = params?.session_id as string | undefined;
    // `session_name` must be PRESENT (null is how you clear it) — an omitted key is a caller that
    // forgot the argument, not a caller asking to clear. Same distinction cello_contact_set_moniker
    // draws with its `"moniker" in params` check.
    if (!sessionId || !params || !("session_name" in params)) {
      return {
        ok: false,
        reason: "missing_params",
        guidance: "Provide 'session_id' (hex) and 'session_name' — a string to name the session, or null to clear it.",
      };
    }

    const check = validateSessionName(params.session_name);
    if (!check.ok) {
      logger.warn("session.name.rejected", {
        agentId: sessionNodeManager.resolveAgentId(agentName), sessionId, reason: check.reason, source: "rename",
        nameLength: typeof params.session_name === "string" ? params.session_name.length : null,
      });
      return { ok: false, reason: check.reason, guidance: check.guidance };
    }

    const written = sessionNodeManager.setSessionName(agentName, sessionId, check.value);
    if (!written) {
      // The UPDATE matched no row: this agent holds no session with that id. Fail loud rather than
      // report a success for a write that landed nowhere.
      return {
        ok: false,
        reason: "session_not_found",
        guidance: "No session with this ID belongs to this agent. Check cello_sessions for its sessions and their IDs.",
      };
    }

    // AC-A16: the LENGTH, never the text. A session name carries the subject of a private
    // conversation ("Acquisition of Northwind Traders"), and daemon logs are not confidential.
    const agentId = sessionNodeManager.getSessionRecord(agentName, sessionId)?.agent_id;
    if (check.value === null) {
      logger.info("session.name.cleared", { agentId, sessionId, source: "rename" });
    } else {
      logger.info("session.name.set", { agentId, sessionId, nameLength: check.value.length, source: "rename" });
    }
    return { ok: true, session_id: sessionId, session_name: check.value };
  });

  // list_sessions (daemon-wide, for the `cello sessions` CLI which has no current agent): same
  // filter/limit semantics, across ALL agents.
  handlers.set("list_sessions", async (params) => {
    return selectSessions(
      sessionNodeManager.getAllSessions(),
      params as Record<string, unknown> | undefined,
    );
  });

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

  // CELLO-M7-MSG-001 (AC-004/AC-005): the send path records un-acked content here when
  // its TTF timer fires, so a crash before the relay park confirms is recoverable at the
  // next startup flush. Stored in the SAME retry_queue table (awaiting_ack = 1).
  handlers.set("enqueue_awaiting_content", async (params, connectionId) => {
    const sessionId = params?.sessionId as string | undefined;
    const contentHashHex = params?.contentHash as string | undefined;
    const contentHex = params?.content as string | undefined;
    if (!sessionId || !contentHashHex || !contentHex) {
      return { error: "missing_params", guidance: "Provide sessionId, contentHash (hex), and content (hex)." };
    }
    // DOD-LOOP-1: awaiting content is keyed by the OWNING agent. Prefer an explicit agentName param;
    // fall back to the connection's current agent.
    // DOD-AGENT-ID-JOINKEY-1: the old `?? ""` fell back to an EMPTY-STRING agent, silently merging
    // every unaddressed caller's awaiting content into one nameless queue. There is no such agent.
    const agentName = (params?.agentName as string | undefined)
      ?? perConnectionState.get(connectionId)?.currentAgent;
    if (!agentName) {
      return { error: "no_current_agent", guidance: "Select an agent with cello_use_agent, or pass agentName." };
    }
    const agentId = sessionNodeManager.resolveAgentId(agentName);
    retryQueue.enqueueAwaitingContent(agentId, sessionId, Buffer.from(contentHashHex, "hex"), Buffer.from(contentHex, "hex"));
    return { queued: true, awaitingDepth: retryQueue.getAwaitingDepth(agentId, sessionId) };
  });

  // CELLO-M7-MSG-001: a `persisted` delivery ACK (or a confirmed park) clears the durable
  // awaiting-ACK entry so the startup flush does not re-park already-delivered content.
  handlers.set("mark_content_acked", async (params, connectionId) => {
    const sessionId = params?.sessionId as string | undefined;
    const contentHashHex = params?.contentHash as string | undefined;
    if (!sessionId || !contentHashHex) {
      return { error: "missing_params", guidance: "Provide sessionId and contentHash (hex)." };
    }
    const agentName = (params?.agentName as string | undefined)
      ?? perConnectionState.get(connectionId)?.currentAgent;
    if (!agentName) {
      return { error: "no_current_agent", guidance: "Select an agent with cello_use_agent, or pass agentName." };
    }
    const agentId = sessionNodeManager.resolveAgentId(agentName);
    retryQueue.markContentAcked(agentId, sessionId, Buffer.from(contentHashHex, "hex"));
    return { acked: true, awaitingDepth: retryQueue.getAwaitingDepth(agentId, sessionId) };
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

  // MSG-001-3b: content-park deposit/pull IPC handlers. These drive the daemon's
  // ContentParkClient directly so the daemon↔relay store-and-forward transport can be
  // proven (J-CONTENT increment 1) before the send/receive-path integration. The relay
  // multiaddr (with /p2p/<peerId>) comes from the session assignment's relay endpoint;
  // dials run from the standing receiver (open-gater) node.
  const parseRelayPeer = (multiaddr: string | undefined): { peerId: string; addr: string } | null => {
    if (!multiaddr) return null;
    const peerId = multiaddr.split("/p2p/")[1];
    return peerId ? { peerId, addr: multiaddr } : null;
  };

  handlers.set("content_park_deposit", async (params, _connectionId) => {
    const relay = parseRelayPeer(params?.relayMultiaddr as string | undefined);
    const recipientPubkey = params?.recipientPubkey as string | undefined;
    const contentHash = params?.contentHash as string | undefined;
    const sessionId = params?.sessionId as string | undefined;
    const ciphertext = params?.ciphertext as string | undefined;
    if (!relay || !recipientPubkey || !contentHash || !sessionId || !ciphertext) {
      return { ok: false, reason: "missing_params", guidance: "Provide relayMultiaddr (with /p2p/<peerId>), recipientPubkey, contentHash, sessionId, ciphertext — all hex." };
    }
    const node = sessionNodeManager.getStandingReceiverNode();
    if (!node) return { ok: false, reason: "standing_receiver_unavailable", guidance: "The daemon's standing receiver is not ready yet; retry after startup." };
    const client = new ContentParkClient({ relayPeerId: relay.peerId, relayAddrs: [relay.addr], logger });
    return await client.deposit(node, {
      recipientPubkey: Buffer.from(recipientPubkey, "hex"),
      contentHash: Buffer.from(contentHash, "hex"),
      sessionId: Buffer.from(sessionId, "hex"),
      ciphertext: Buffer.from(ciphertext, "hex"),
    });
  });

  handlers.set("content_park_pull", async (params, _connectionId) => {
    const relay = parseRelayPeer(params?.relayMultiaddr as string | undefined);
    const recipientPubkey = params?.recipientPubkey as string | undefined;
    if (!relay || !recipientPubkey) {
      return { ok: false, reason: "missing_params", guidance: "Provide relayMultiaddr (with /p2p/<peerId>) and recipientPubkey (hex)." };
    }
    // The recipient must be a local agent — its K_local signs the relay's auth challenge.
    const recipientAgent = agents.find((a) => a.pubkey === recipientPubkey);
    if (!recipientAgent) return { ok: false, reason: "agent_not_found", guidance: "No local agent matches recipientPubkey; only the recipient can pull its own parked content." };
    const kp = keyProviders.get(recipientAgent.name);
    if (!kp) return { ok: false, reason: "signing_key_unavailable", guidance: `Signing key for '${recipientAgent.name}' is not loaded.` };
    const node = sessionNodeManager.getStandingReceiverNode();
    if (!node) return { ok: false, reason: "standing_receiver_unavailable", guidance: "The daemon's standing receiver is not ready yet; retry after startup." };
    const client = new ContentParkClient({ relayPeerId: relay.peerId, relayAddrs: [relay.addr], logger });
    const entries = await client.pull(node, Buffer.from(recipientPubkey, "hex"), kp);
    return {
      ok: true,
      entries: entries.map((e) => ({ contentHash: e.contentHashHex, sessionId: e.sessionIdHex, ciphertext: Buffer.from(e.ciphertext).toString("hex") })),
    };
  });

  // MSG-001-3b (increment 3): RECOVER parked content. Pulls the recipient's parked entries,
  // decrypts each IN-DAEMON (openContentSeal — the relay never sees plaintext), and routes the
  // plaintext through ingestReceivedContent — the SAME inbound chokepoint as a direct receive
  // (M9 single-funnel AC). The content completes the recipient's transcript view of an already-
  // witnessed message so it can be read (cello_receive) and the session bilaterally sealed
  // (DOD-INT-2). This is content-completion, NOT a resumption — the session stays interrupted.
  // DOD-MSG-4: pull a recipient agent's parked mailbox from ONE relay and recover each entry through
  // the inbound funnel (decode envelope → verify+order the signed Structure2 → ingest). Shared by the
  // explicit IPC handler and the auto-recover-on-reconnect trigger below.
  async function recoverParkedFromRelay(
    recipientAgent: { name: string; pubkey?: string },
    relayPeerId: string,
    relayAddrs: string[],
  ): Promise<
    | { ok: true; recovered: number; pulled: number; refused: number; refusals: Array<{ contentHash: string; sessionId: string; reason: string }> }
    | { ok: false; reason: string }
  > {
    const kp = keyProviders.get(recipientAgent.name);
    if (!kp) return { ok: false, reason: "signing_key_unavailable" };
    if (!kp.openContentSeal) return { ok: false, reason: "cannot_unseal" };
    const node = sessionNodeManager.getStandingReceiverNode();
    if (!node) return { ok: false, reason: "standing_receiver_unavailable" };
    const recipientPubkey = recipientAgent.pubkey ?? "";
    const client = new ContentParkClient({ relayPeerId, relayAddrs, logger });
    const entries = await client.pull(node, Buffer.from(recipientPubkey, "hex"), kp);
    let recovered = 0;
    // SEC-1 / review M2: a REFUSED entry must not vanish behind `ok:true`. Report it — an operator
    // seeing {ok:true, pulled:3, recovered:0} would otherwise have three messages evaporate with the
    // only explanation buried in the daemon log. This is both the injection signal and, given the
    // deliberate no-tolerant-window rollout, the lagging-peer signal.
    const refusals: Array<{ contentHash: string; sessionId: string; reason: string }> = [];
    // AC7: one correlationId per recover flow, threaded through every event it emits.
    const correlationId = randomUUID();
    for (const e of entries) {
      const unsealed = await kp.openContentSeal(e.ciphertext);
      if (!unsealed) {
        logger.warn("content.recover.unseal_failed", { sessionId: e.sessionIdHex, contentHash: e.contentHashHex });
        continue;
      }
      // SEC-1: authenticate THEN ingest — fused in recoverParkedEntry, which is now the ONLY way
      // parked content can enter the transcript. It verifies the sender's signature over
      // (session_id, recipient_pubkey, content_hash) and that the signer is this session's
      // counterparty, and it still verifies + records the DOD-MSG-4 ordering record when present.
      // Relay deposit is unauthenticated and the seal is anonymous, so WITHOUT this gate anyone
      // holding the recipient's public key — the relay above all — could inject content that gets
      // attributed to the honest counterparty and then notarized by the bilateral seal.
      const contentHashBytes = Buffer.from(e.contentHashHex, "hex");
      const ingest = await sessionNodeManager.recoverParkedEntry(
        recipientAgent.name,
        e.sessionIdHex,
        Buffer.from(recipientPubkey, "hex"),
        unsealed,
        contentHashBytes,
        correlationId,
      );
      if (ingest.ok && ingest.held) {
        // DOD-MSG-4 (review finding #4): a held entry is NOT yet an appended leaf — its sequence is
        // the FUTURE canonical index, not a completed recovery. Do not count it as recovered; log it
        // distinctly so the tally reflects leaves actually written, not content still queued in memory.
        logger.info("content.recover.held", { sessionId: e.sessionIdHex, contentHash: e.contentHashHex, canonicalSeq: ingest.sequenceNumber });
      } else if (ingest.ok && ingest.screenedOut) {
        // M9 (code-review LOW-3): a terminal-screened recovered entry IS durably leafed (so it must be
        // confirm-deleted, below) but was NEVER delivered to the agent — do not count it as a delivered
        // recovery, and log it distinctly so observability separates "delivered" from "leafed-but-screened".
        logger.info("content.recover.screened_out", { sessionId: e.sessionIdHex, contentHash: e.contentHashHex, sequenceNumber: ingest.sequenceNumber });
        try {
          await client.confirm(node, Buffer.from(recipientPubkey, "hex"), contentHashBytes, kp);
        } catch (err: unknown) {
          logger.warn("content.recover.confirm.failed", { sessionId: e.sessionIdHex, contentHash: e.contentHashHex, error: err instanceof Error ? err.message : String(err) });
        }
      } else if (ingest.ok) {
        // DOD-MSG-4 (review #3): count leaves ACTUALLY written — the directly-ingested leaf PLUS any
        // held out-of-order entries this ingest unblocked (appendedCount), not just 1.
        recovered += ingest.appendedCount ?? 1;
        logger.info("content.recovered", { sessionId: e.sessionIdHex, contentHash: e.contentHashHex, sequenceNumber: ingest.sequenceNumber });
        // Delete-on-confirm (review #1): the entry is now durably ingested (a fresh leaf, or a dedup
        // of one already present), so confirm-delete it from the relay mailbox. The relay is
        // delete-on-CONFIRM, not delete-on-pull — without this the queue never drains and every
        // reconnect re-pulls the whole history. Held entries are deliberately NOT confirmed (not yet
        // durable). Best-effort: a failed confirm leaves the entry to be re-pulled + deduped next time.
        try {
          await client.confirm(node, Buffer.from(recipientPubkey, "hex"), contentHashBytes, kp);
        } catch (err: unknown) {
          logger.warn("content.recover.confirm.failed", { sessionId: e.sessionIdHex, contentHash: e.contentHashHex, error: err instanceof Error ? err.message : String(err) });
        }
      } else {
        // SEC-1 (M2): carry the refusal out to the caller, not just to the log. Deliberately still
        // NOT confirm-deleted — a forgery must not be able to evict itself from the mailbox, and a
        // genuine v1-peer message must not be destroyed by our refusing it.
        refusals.push({ contentHash: e.contentHashHex, sessionId: e.sessionIdHex, reason: ingest.reason });
        logger.warn("content.recover.ingest_failed", { sessionId: e.sessionIdHex, contentHash: e.contentHashHex, reason: ingest.reason, correlationId });
      }
    }
    return { ok: true, recovered, pulled: entries.length, refused: refusals.length, refusals };
  }

  // DOD-MSG-4 (auto-recover-on-reconnect): when an agent comes online, drain its parked mailbox from
  // every relay it has sessions on — symmetric to the SENDER's flushAwaitingContent. Without this,
  // nothing in production pulls a recipient's store-and-forward mailbox and parked content is never
  // delivered. Best-effort; a relay miss is retried on the next agent-online.
  async function autoRecoverForAgent(agentName: string): Promise<void> {
    const agent = agents.find((a) => a.name === agentName);
    if (!agent?.pubkey) return;
    const relays = sessionNodeManager.getAgentRelayEndpoints(agentName);
    if (relays.length === 0) return;
    let total = 0;
    let failed = 0;
    for (const r of relays) {
      try {
        const res = await recoverParkedFromRelay(agent, r.relayPeerId, r.relayAddrs);
        if (res.ok) {
          total += res.recovered;
        } else {
          // Review #2: a non-ok result (signing_key_unavailable / cannot_unseal /
          // standing_receiver_unavailable) was previously silent — log the reason so a run where
          // every relay failed is distinguishable from "nothing was parked".
          failed++;
          logger.warn("content.recover.auto.relay_failed", { agentName, relayPeerId: r.relayPeerId, reason: res.reason });
        }
      } catch (err: unknown) {
        failed++;
        logger.warn("content.recover.auto.failed", { agentName, relayPeerId: r.relayPeerId, error: err instanceof Error ? err.message : String(err) });
      }
    }
    // Emit the completion event UNCONDITIONALLY — not only when total > 0 — so a clean "nothing
    // parked" run is observable, and distinct from an all-failed run.
    logger.info("content.recover.auto.completed", { agentName, recovered: total, relayCount: relays.length, failedRelays: failed });
  }

  handlers.set("content_park_recover", async (params, _connectionId) => {
    const relay = parseRelayPeer(params?.relayMultiaddr as string | undefined);
    const recipientPubkey = params?.recipientPubkey as string | undefined;
    if (!relay || !recipientPubkey) {
      return { ok: false, reason: "missing_params", guidance: "Provide relayMultiaddr (with /p2p/<peerId>) and recipientPubkey (hex)." };
    }
    const recipientAgent = agents.find((a) => a.pubkey === recipientPubkey);
    if (!recipientAgent) return { ok: false, reason: "agent_not_found", guidance: "No local agent matches recipientPubkey." };
    const res = await recoverParkedFromRelay(recipientAgent, relay.peerId, [relay.addr]);
    if (!res.ok) {
      const guidanceByReason: Record<string, string> = {
        signing_key_unavailable: `Signing key for '${recipientAgent.name}' is not loaded.`,
        cannot_unseal: `Agent '${recipientAgent.name}' key provider cannot open content seals.`,
        standing_receiver_unavailable: "The daemon's standing receiver is not ready yet; retry after startup.",
      };
      return { ok: false, reason: res.reason, guidance: guidanceByReason[res.reason] ?? "Recover failed." };
    }
    return { ok: true, recovered: res.recovered, pulled: res.pulled };
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
      dispatchSessionStateChangedWithTelegram(agentName, sessionId, "created", counterpartyPubkey);
    } else if (type === "destroyed") {
      const state = (params?.state as string) ?? "interrupted";
      const reason = (params?.reason as string) ?? state;
      logger.info("session.node.destroyed", { sessionId, agentName, reason });
      dispatchSessionStateChangedWithTelegram(agentName, sessionId, state, counterpartyPubkey);
    }

    return { ok: true };
  });

  // M8C-INBOX-1: test hook to enqueue a pending inbound session request (mirrors the real inbound
  // flow's enqueueInboundSession) so cello_check_notifications' pending_session_requests is testable
  // without standing up the full libp2p inbound path.
  handlers.set("__test_enqueue_inbound_session", async (params, _connectionId) => {
    const agentName = params?.agentName as string | undefined;
    const sessionIdHex = params?.sessionId as string | undefined;
    const counterpartyPubkeyHex = (params?.counterpartyPubkey as string) ?? "";
    if (!agentName || !sessionIdHex) {
      return { error: "missing_params", guidance: "Provide agentName and sessionId." };
    }
    enqueueInboundSession(agentName, { sessionIdHex, counterpartyPubkeyHex, genesisPrevRootHex: "" });
    // M8C-TTL-1: let a test backdate the just-enqueued entry's timestamp (simulating age) without
    // waiting real hours or faking global timers — enqueueInboundSession always stamps Date.now().
    const enqueuedAtOverride = params?.enqueuedAtOverride as number | undefined;
    if (enqueuedAtOverride !== undefined) {
      const q = inboundSessionQueues.get(agentName);
      const entry = q?.[q.length - 1];
      if (entry) entry.enqueuedAt = enqueuedAtOverride;
    }
    return { ok: true };
  });

  // M8C-INBOX-1 (reviewer F1): buffer a received message so a test can drive a live cello_receive
  // and assert the watermark advances (the N3 delivery-marks-read coupling), without a session tree.
  handlers.set("__test_buffer_received", async (params, _connectionId) => {
    const agentName = params?.agentName as string | undefined;
    const sessionId = params?.sessionId as string | undefined;
    const seq = params?.seq as number | undefined;
    const content = (params?.content as string) ?? "hello";
    if (!agentName || !sessionId || typeof seq !== "number") {
      return { error: "missing_params", guidance: "Provide agentName, sessionId, seq." };
    }
    sessionNodeManager.pushReceivedContentForTest(agentName, sessionId, seq, content, (params?.senderPubkey as string) ?? "cp");
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
      // CONN-001: send the rejection over the LOCAL responder agent's own stream (the agent whose
      // pubkey is counterpartyPubkey — the stream this request arrived on). If unresolved, sendOver
      // reports a send failure rather than throwing.
      const sent = await sendOver(agents.find((a) => a.pubkey === counterpartyPubkey)?.name ?? "", {
        type: "seal_interrupted_rejection",
        sessionId,
        initiatorPubkey,
        reason,
      });
      // fallback-finder LOW: don't log the rejection as delivered when the send failed (e.g. no local
      // agent for counterpartyPubkey, or a transient send error) — the counterparty would otherwise
      // appear rejected but only ever see a timeout.
      if (sent.ok) {
        logger.warn("session.interrupted.request.rejected", { sessionId, reason, correlationId });
      } else {
        logger.warn("session.interrupted.request.rejection.send.failed", { sessionId, reason, sendReason: sent.reason, correlationId });
      }
    };

    // DOD-LOOP-1: resolve the addressed local agent FIRST — the composite (agent, session_id) key
    // needs it. The request must be addressed to one of our agents (counterpartyPubkey is OUR
    // pubkey from the initiator's perspective).
    const localAgent = agents.find((a) => a.pubkey === counterpartyPubkey);
    if (!localAgent) { await reject("unknown_counterparty"); return; }

    const localRecord = sessionNodeManager.getSessionRecord(localAgent.name, sessionId);
    if (!localRecord) { await reject("session_not_found"); return; }
    // DAEMON-004: an 'active' session is eligible too (the active-session seal
    // reuses this exchange). We still never re-process a terminal 'sealed' row or
    // an already-pending one.
    if (localRecord.status !== "interrupted" && localRecord.status !== "active") {
      await reject("session_not_interrupted");
      return;
    }
    // From our perspective the initiator is our counterparty.
    if (localRecord.counterparty_pubkey !== initiatorPubkey) { await reject("initiator_mismatch"); return; }

    // DAEMON-004 (SI-001): we sign over OUR OWN daemon-owned tree, never the
    // initiator-supplied root.
    //
    // round-2 finding #6: for an ACTIVE session the daemon ALWAYS binds its own tree
    // root — even the canonical EMPTY-tree root when no content has flowed — never the
    // initiator-supplied `merkleRootReq`. Echoing the caller's root would let an
    // initiator dictate the root a responder signs (the SI-001 trust hole). Only a
    // LEGACY 'interrupted' session that predates DAEMON-004 (no tree ever persisted)
    // falls back to message_count + the supplied root (SESSION-001 behavior).
    const ownTree = sessionNodeManager.getSessionTree(localAgent.name, sessionId);
    const isActive = localRecord.status === "active";
    const useOwnTree = isActive || ownTree.size() > 0;
    const ownLeafCount = useOwnTree ? ownTree.size() : (localRecord.message_count ?? 0);
    const ownRoot = useOwnTree ? sessionNodeManager.getSessionTreeRootHex(localAgent.name, sessionId) : merkleRootReq;

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
      agentName: localAgent.name,
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
    const sendResult = await sendOver(localAgent.name, ack);
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

  // CELLO-M7-CONN-001 (DOD-CONN-2): the inbound seal_interrupted_request responder is now
  // wired PER-AGENT (wirePerAgentSessionInbound, below) onto each agent's own signaling
  // manager — not once on the keystone — so every agent (not just the primary) receives it
  // on its own authenticated stream.

  // ─── Seam 2: inbound session establishment (counterparty side) ─────────────
  //
  // When agent A initiates a session, the directory FROST-signs a SessionAssignment
  // and PUSHES it to the counterparty B over B's directory signaling stream (an
  // unsolicited `session_assignment` frame). The daemon turns that frame into a live
  // inbound session: it resolves which local agent is participant_b, calls
  // SessionNodeManager.acceptSession (which hands off the standing receiver node bound
  // to A's session peer id), and enqueues an inbound session event that a blocked
  // cello_await_session call returns. This is the inbound mirror of cello_initiate_session.
  interface InboundSessionEvent {
    sessionIdHex: string;
    counterpartyPubkeyHex: string;
    genesisPrevRootHex: string;
    // MONIKER-2 AC2: the initiator's offered name — already validated at the wire boundary
    // (extractInboundSessionAssignment), so downstream can never observe an invalid value.
    // null = absent or rejected; an unverified display hint either way, never identity.
    offeredMoniker?: string | null;
    // M8C-TTL-1: when this event was queued (not set for events handed straight to a blocked
    // waiter — those are delivered instantly and never sit in the queue this TTL governs).
    enqueuedAt?: number;
  }
  // MONIKER-2 AC2b: the initiator's validated offered name. Session-scoped display material ONLY
  // (spec: promotion to a stored pet name needs an explicit operator action). In-memory by design —
  // a restart degrades the label to fingerprint, never worse.
  //
  // DOD-MONIKER-6 (spec §10): keyed by (agentName, sessionIdHex), NEVER sessionIdHex alone. A box
  // is written by the RECEIVING side and holds the CALLER's name, so it is meaningful only to the
  // agent it was written for. Keyed by session id alone, a daemon hosting both participants hands
  // the initiator the box filled in for her counterparty — she is told she messaged herself — and
  // either agent's state change or request expiry silently drops the other's name.
  const offeredMonikers = new Map<string, string>();
  const offerKey = (agentName: string, sessionIdHex: string): string => `${agentName}:${sessionIdHex}`;
  // Expired requests move HERE (from inboundSessionQueues) rather than vanishing — visible via
  // cello_check_notifications so the operator can see what they missed, not just silence.
  const expiredSessionRequests = new Map<string, Array<{ sessionIdHex: string; counterpartyPubkeyHex: string; expiredAt: number }>>();
  // A blocked cello_await_session waiter. connectionId is carried so the disconnect
  // hook can evict waiters belonging to a dead connection (otherwise enqueue would hand
  // an inbound event to a closed connection and the event would be lost — review H2).
  interface InboundSessionWaiter {
    connectionId: string;
    deliver: (e: InboundSessionEvent | null) => void; // clears its own timeout; null = evicted
  }
  // Per-agent FIFO queue (events accepted while no cello_await_session is blocked) and
  // the per-agent list of blocked waiters. Inbound sessions are addressed to a specific
  // local agent (participant_b), so both are keyed by agent name.
  const inboundSessionQueues = new Map<string, InboundSessionEvent[]>();
  const inboundSessionWaiters = new Map<string, InboundSessionWaiter[]>();
  // Session ids whose acceptInboundAssignment is in flight (the accept step is async
  // because it may wait for the standing receiver to rebuild). Guards against two
  // simultaneous frames for the SAME session both passing the getSessionRecord check
  // before either has inserted the row (review M1, race half).
  const inboundInFlight = new Set<string>();
  // Inbound accepts are SERIALIZED through this chain. acceptSession synchronously
  // consumes the single standing receiver and rebuilds a replacement asynchronously;
  // running two accepts concurrently would let the second pass its readiness check on
  // the receiver the first is about to consume, then fail on the consumed receiver
  // (review M2, race). Serializing makes the second accept wait for the first's rebuild.
  let inboundAcceptChain: Promise<void> = Promise.resolve();

  function enqueueInboundSession(agentName: string, event: InboundSessionEvent): void {
    const waiters = inboundSessionWaiters.get(agentName);
    if (waiters && waiters.length > 0) {
      // Hand straight to the oldest blocked waiter (deliver clears its own timeout).
      const w = waiters.shift()!;
      w.deliver(event);
      return;
    }
    const q = inboundSessionQueues.get(agentName) ?? [];
    q.push({ ...event, enqueuedAt: Date.now() }); // M8C-TTL-1: stamp queue entry time
    inboundSessionQueues.set(agentName, q);
  }

  // M8C-TTL-1 (reviewer HIGH fix, aed2d71f, D19): expiredSessionRequests is a lasting log, not a
  // consumed queue (unlike inboundSessionQueues, nothing ever drains it) — a whitelisted CONTACT-1
  // contact is EXEMPT from ABUSE-1's acceptance bounds ("bounded only by disk"), so they can push
  // unlimited accepted sessions the operator never claims, each becoming a permanent, unremovable
  // entry every 24h for the life of the daemon process. Capped the same way STATUS_RESUMABLE_CAP
  // bounds the interrupted-sessions list — keep only the MOST RECENT N per agent.
  const EXPIRED_SESSION_REQUESTS_CAP = 20;
  // M8C-TTL-1: move any queue entries past the TTL into expiredSessionRequests (visible via
  // INBOX), instead of leaving them to sit forever or vanish silently. Called lazily on every
  // read of the queue (cello_await_session's immediate-check, cello_check_notifications) rather
  // than on a timer — no background sweep needed, and it's always correct-as-of-the-read.
  function reapExpiredInboundSessions(agentName: string): void {
    const q = inboundSessionQueues.get(agentName);
    if (!q || q.length === 0) return;
    const now = Date.now();
    const live: InboundSessionEvent[] = [];
    let expiredList = expiredSessionRequests.get(agentName);
    for (const e of q) {
      if (e.enqueuedAt !== undefined && now - e.enqueuedAt > INBOUND_SESSION_TTL_MS) {
        if (!expiredList) { expiredList = []; expiredSessionRequests.set(agentName, expiredList); }
        expiredList.push({ sessionIdHex: e.sessionIdHex, counterpartyPubkeyHex: e.counterpartyPubkeyHex, expiredAt: now });
        if (expiredList.length > EXPIRED_SESSION_REQUESTS_CAP) {
          expiredList.splice(0, expiredList.length - EXPIRED_SESSION_REQUESTS_CAP); // keep newest N
        }
        logger.info("session.request.expired", { agentName, sessionId: e.sessionIdHex, enqueuedAt: e.enqueuedAt });
        // MONIKER-2 AC2b (review F1): the offer's display name expires with the offer.
        if (offeredMonikers.delete(offerKey(agentName, e.sessionIdHex))) {
          logger.debug("moniker.offer.dropped", { agentName, sessionId: e.sessionIdHex, state: "expired" });
        }
      } else {
        live.push(e);
      }
    }
    inboundSessionQueues.set(agentName, live);
  }

  // Pull the fields out of a pushed session_assignment frame. Returns null when the frame
  // carries no usable assignment object / is missing the essential ids (the handler then
  // ignores it rather than throwing). Field-level validity (peer id, signature type) is
  // checked in the handler so it can emit a distinct, diagnosable event per failure.
  function extractInboundSessionAssignment(frame: Record<string, unknown>):
    | {
        sessionIdHex: string;
        participantAPubkeyHex: string;
        participantBPubkeyHex: string;
        initiatorPeerId: string;
        // DOD-INBOUND-GUARD-1: the responder's accepted session endpoint. The directory omits
        // this field when the offer was never accepted (offer-accept timeout → "empty defaults"),
        // so null/"" here means NOBODY accepted — the initiator's F13 guard refuses the same
        // assignment on its side, and the handler must refuse it here too. null when absent.
        counterpartySessionPeerId: string | null;
        sessionTimestamp: number;
        signatureType: string | null;
        signerPubkeyHex: string | null;
        relayPeerId: string;
        relayAddrs: string[];
        // MONIKER-2 AC2: the initiator's offered name, validated ONCE here at the wire
        // boundary — downstream code can never observe an invalid moniker. null when
        // absent (older client) or invalid; monikerRejected distinguishes the two so the
        // caller can log `moniker.rejected` (invalid) vs stay silent (absent).
        offeredMoniker: string | null;
        monikerRejected: boolean;
        monikerRejectReason: "not_string" | "length" | "charset" | null;
      }
    | null {
    const raw = frame["assignment"];
    if (!raw || typeof raw !== "object") return null;
    const a = raw as Record<string, unknown>;
    const pa = a["participant_a"] as Record<string, unknown> | undefined;
    const pb = a["participant_b"] as Record<string, unknown> | undefined;
    const sessionIdHex = frameValueToHex(a["session_id"]);
    const participantAPubkeyHex = pa ? frameValueToHex(pa["pubkey"]) : null;
    const participantBPubkeyHex = pb ? frameValueToHex(pb["pubkey"]) : null;
    if (!sessionIdHex || !participantAPubkeyHex || !participantBPubkeyHex) return null;
    // M7 DOD-SPINE-6 / MSG-001-3b: relay endpoint so the receiver also connects to the
    // relay witness (so the relay can deliver the initiator's witnessed leaves to it).
    const relayEndpoint = a["relay_endpoint"] as Record<string, unknown> | undefined;
    const relayPeerId =
      relayEndpoint && typeof relayEndpoint["peer_id"] === "string" ? relayEndpoint["peer_id"] : "";
    const relayAddrs =
      relayEndpoint && Array.isArray(relayEndpoint["multiaddrs"])
        ? (relayEndpoint["multiaddrs"] as unknown[]).filter((m): m is string => typeof m === "string")
        : [];
    // MONIKER-2 AC2: validate the offered name ONCE, at this wire boundary.
    const monikerResult = extractOfferedMoniker(a);
    return {
      sessionIdHex,
      participantAPubkeyHex,
      participantBPubkeyHex,
      initiatorPeerId:
        typeof a["initiator_session_peer_id"] === "string" ? a["initiator_session_peer_id"] : "",
      counterpartySessionPeerId:
        typeof a["counterparty_session_peer_id"] === "string" ? a["counterparty_session_peer_id"] : null,
      sessionTimestamp: typeof a["session_timestamp"] === "number" ? a["session_timestamp"] : 0,
      signatureType: typeof a["signature_type"] === "string" ? a["signature_type"] : null,
      // M7 legibility-TBS-binding (responder verify): the FROST-signed assignment embeds the
      // initiator's primary (group) pubkey as `signer_pubkey` — the key that signs the seal.
      // The responder stores it so it can verify the bilateral seal signature locally, not just
      // accept it (session.ts: "embedded so the counterparty can verify").
      signerPubkeyHex: a["signer_pubkey"] !== undefined ? frameValueToHex(a["signer_pubkey"]) : null,
      relayPeerId,
      relayAddrs,
      offeredMoniker: monikerResult.offeredMoniker,
      monikerRejected: monikerResult.rejected,
      monikerRejectReason: monikerResult.reason ?? null,
    };
  }

  // Wait (bounded) for THIS AGENT's standing receiver to be ready. acceptSession consumes the
  // agent's standing receiver and rebuilds a replacement asynchronously, so a burst of inbound
  // assignments for that agent would otherwise drop all but the first (review M2). Polling the
  // per-agent readiness lets each accept proceed once the prior rebuild completes. Must check the
  // OWNING agent — `getStandingReceiverReady()` with no arg returns true if ANY agent has one,
  // which in the loopback case (alice + bob on one daemon) would falsely pass while bob's own SR
  // is still mid-rebuild and drop bob's session (DOD-LOOP-1).
  async function waitForStandingReceiver(agentName: string, maxWaitMs = 3_000, stepMs = 25): Promise<boolean> {
    if (sessionNodeManager.getStandingReceiverReady(agentName)) return true;
    const deadline = Date.now() + maxWaitMs;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, stepMs));
      if (sessionNodeManager.getStandingReceiverReady(agentName)) return true;
    }
    return sessionNodeManager.getStandingReceiverReady(agentName);
  }

  async function acceptInboundAssignment(
    parsed: NonNullable<ReturnType<typeof extractInboundSessionAssignment>>,
    agentName: string,
    correlationId: string,
  ): Promise<void> {
    try {
      // M8C-ABUSE-1 + DOD-TIER-2/3: bound acceptance by the sender's TIER — a per-sender cap that is
      // the sender's tier cap (BLOCKED 0 → refused here, indistinguishably from an over-cap stranger),
      // plus a global anti-swarm cap that applies only to the UNKNOWN-tier stranger pool. No tier is
      // unbounded (INV-TIER-BOUND); KNOWN+ are exempt from the GLOBAL pool only, not from their own
      // cap. Checked FIRST, before any standing-receiver work, so a refusal is cheap.
      // CC-10: reap provably-dead ghosts for THIS agent before counting — otherwise invisible
      // interrupted 0-received sessions (post-restart shape) consume the sender's budget forever
      // and lock the stranger out with no list read ever clearing them. Safe here: abandonSession
      // flips the DB status synchronously, so the bound query below sees the reaped state.
      reapDeadHalfOpenSessions(agentName);
      const bound = sessionNodeManager.checkUnknownSenderAcceptanceBound(agentName, parsed.participantAPubkeyHex);
      if (!bound.ok) {
        logger.warn("session.inbound.accept.failed", {
          sessionId: parsed.sessionIdHex,
          agentName,
          reason: bound.reason,
          correlationId,
        });
        return;
      }
      // DOD-RENAME-1 AC1 (review F1 / DEC-AB-4): record the offered name as the rename baseline the
      // moment the offer passes the acceptance gate — an ALLOWED peer (the bound check let them
      // through) is tracked even if session formation transiently fails below. Deliberately AFTER the
      // bound check, not at the raw parse point: a BLOCKED or over-cap peer must NOT be able to drive
      // the operator's rename baseline or push notices into their inbox. Guarded by offeredMoniker !==
      // null so a silent offer never clears the baseline (AC5).
      if (parsed.offeredMoniker !== null) {
        sessionNodeManager.recordOfferedMoniker(agentName, parsed.participantAPubkeyHex, parsed.offeredMoniker);
      }
      // M8B F14 (fix 2): KICK creation before polling — an inbound offer arriving while no
      // receiver exists and none is being created must trigger the ensure itself (the doc
      // comment's "retries on demand" made true), instead of polling a creation nobody
      // started and dropping the offer. Fire-and-forget: the poll below observes readiness.
      void sessionNodeManager.ensureStandingReceiverForAgent(agentName).catch((err: unknown) => {
        logger.warn("session.standing_receiver.ensure.failed", {
          agentName,
          reason: err instanceof Error ? err.message : String(err),
          correlationId,
        });
      });
      // M2: do not drop the session if this agent's standing receiver is mid-rebuild.
      const ready = await waitForStandingReceiver(agentName);
      if (!ready) {
        logger.warn("session.inbound.accept.failed", {
          sessionId: parsed.sessionIdHex,
          agentName,
          reason: "standing_receiver_unavailable",
          correlationId,
        });
        return;
      }
      // M7 DOD-SPINE-6 / MSG-001-3b: relay witness for the receiver. Build from the
      // inbound assignment's relay endpoint + this agent's K_local + the 16-byte session id.
      const kp = keyProviders.get(agentName);
      let relayParams: RelayConnectParams | undefined;
      if (kp && parsed.relayPeerId && parsed.relayAddrs.length > 0) {
        relayParams = {
          relayPeerId: parsed.relayPeerId,
          relayAddrs: parsed.relayAddrs,
          keyProvider: kp,
          senderPubkey: await kp.getPublicKey(),
          sessionIdBytes: new Uint8Array(Buffer.from(parsed.sessionIdHex, "hex")),
        };
      }
      const result = await sessionNodeManager.acceptSession(
        parsed.sessionIdHex,
        agentName,
        parsed.participantAPubkeyHex, // the initiator is OUR counterparty
        parsed.initiatorPeerId,
        correlationId,
        relayParams,
      );
      if (!result.ok) {
        logger.warn("session.inbound.accept.failed", {
          sessionId: parsed.sessionIdHex,
          agentName,
          reason: result.reason,
          correlationId,
        });
        return;
      }
      // M7 legibility-TBS-binding (responder verify): store the initiator's primary (the seal
      // signer, carried as signer_pubkey on the FROST-signed assignment) so the bilateral seal
      // signature can be verified locally rather than accepted on faith.
      if (parsed.signerPubkeyHex) {
        sessionNodeManager.recordCounterpartyPrimary(agentName, parsed.sessionIdHex, parsed.signerPubkeyHex);
      }

      // H1: genesis_prev_root is the canonical two-party genesis value — the SAME value
      // baked into the FROST-signed session-establishment TBS and derived by the initiator
      // and directory — NOT the daemon's (empty) tree root. computeGenesisPrevRoot sorts
      // the pubkeys internally, so natural (A, B) order is correct.
      const genesisPrevRootHex = Buffer.from(
        computeGenesisPrevRoot(
          Buffer.from(parsed.participantAPubkeyHex, "hex"),
          Buffer.from(parsed.participantBPubkeyHex, "hex"),
          Buffer.from(parsed.sessionIdHex, "hex"),
          parsed.sessionTimestamp,
        ),
      ).toString("hex");

      logger.info("session.inbound.accepted", {
        sessionId: parsed.sessionIdHex,
        agentName,
        sessionPeerId: result.peerId,
        correlationId,
      });
      // MONIKER-2 AC2: a present-but-invalid moniker is a red flag (the sender runs modified
      // code) — logged with the spec'd fields and NEVER the raw value. Not grounds to refuse
      // the session (version skew is real; refusing hands strangers a DoS lever).
      if (parsed.monikerRejected) {
        logger.info("moniker.rejected", {
          agentName,
          pubkey: parsed.participantAPubkeyHex,
          reason: parsed.monikerRejectReason ?? "invalid",
          correlationId,
        });
      }
      // MONIKER-2 AC2b: display material for THIS offer/session only (never persisted, never
      // auto-written to contacts — AC3). Session-scoped: MONIKER-4's dispatcher resolves
      // whoLabel from here; entries are dropped when the session's terminal state dispatches.
      // DOD-MONIKER-6: scoped to `agentName` — the agent this offer was received FOR.
      if (parsed.offeredMoniker !== null) {
        offeredMonikers.set(offerKey(agentName, parsed.sessionIdHex), parsed.offeredMoniker);
        // (DOD-RENAME-1's rename-baseline update runs earlier, right after the acceptance bound — see
        // the recordOfferedMoniker call there. This map is only the session-scoped display material.)
      }
      enqueueInboundSession(agentName, {
        sessionIdHex: parsed.sessionIdHex,
        counterpartyPubkeyHex: parsed.participantAPubkeyHex,
        genesisPrevRootHex,
        offeredMoniker: parsed.offeredMoniker,
      });
      dispatchSessionStateChangedWithTelegram(
        agentName,
        parsed.sessionIdHex,
        "created",
        parsed.participantAPubkeyHex,
      );
      // M8C-TGDOOR-1: session requests ALWAYS ring (DoD) — no coalescing, unlike message-waiting.
      void sendTelegramDoorbell(agentName, parsed.sessionIdHex, "session_request", "New session request");
      // M8C-AWAY-1: an unattended agent auto-acks a fresh inbound session request. Fire-and-forget
      // (sendAwayResponse never throws) — best-effort, must not delay/block acceptance completion.
      void sendAwayResponse(agentName, parsed.sessionIdHex, "request");
      // CC-1 (2026-07-07): do NOT auto-add the requester here. Accepting the *connection* must not
      // grant *trust*. The old auto-add promoted any stranger who knocked once to "known" (Level-4
      // fast-track), which defeated BOTH the screening layer AND the ABUSE-1 acceptance caps
      // (a higher tier raises the per-sender cap, so auto-promoting a stranger would have let their
      // sessions 2+ ride a larger bound — DOD-TIER-2). Promotion to "known" now requires operator engagement only:
      // an outbound cello_initiate_session (below, ~3137), the operator replying INTO the session via
      // cello_send, or an explicit cello_contact_add. An unattended stranger is never auto-whitelisted.
      // See docs/planning/.../2026-07-07_1700_four-level-screening-policy.md (D21).
    } finally {
      inboundInFlight.delete(parsed.sessionIdHex);
    }
  }

  function handleInboundSessionAssignment(frame: Record<string, unknown>): void {
    // M4: one correlationId minted per inbound flow, threaded through EVERY event below.
    const correlationId = randomUUID();
    const parsed = extractInboundSessionAssignment(frame);
    if (!parsed) {
      logger.warn("session.inbound.assignment.malformed", {
        reason: "missing_assignment_or_ids",
        correlationId,
      });
      return;
    }

    // L1: refuse M1 single-key assignments outright (downgrade guard). Distinct from the
    // deferred FROST verification below — track it so SESSION-004's re-home keeps it.
    if (parsed.signatureType === "single") {
      logger.warn("session.inbound.assignment.refused", {
        sessionId: parsed.sessionIdHex,
        reason: "unsupported_signature_type",
        correlationId,
      });
      return;
    }

    // M3: the initiator session peer id is the AC-015 hand-off gate (acceptSession passes
    // it to gater.setAllowedPeer). An empty value would gate the handed-off receiver to "",
    // defeating "only the initiator may connect". The dead stack treated this as malformed.
    if (!parsed.initiatorPeerId) {
      logger.warn("session.inbound.assignment.malformed", {
        sessionId: parsed.sessionIdHex,
        reason: "missing_initiator_peer_id",
        correlationId,
      });
      return;
    }

    // Resolve which local agent is participant_b. participant pubkeys are the agents'
    // K_local identity pubkeys (same convention as the seal-interrupted responder's
    // counterparty match above). If none of our agents is the counterparty, this
    // assignment is not for this daemon — drop it.
    const localAgent = agents.find((ag) => ag.pubkey === parsed.participantBPubkeyHex);
    if (!localAgent) {
      logger.debug("session.inbound.not_local", {
        sessionId: parsed.sessionIdHex,
        counterpartyPubkey: parsed.participantBPubkeyHex,
        correlationId,
      });
      return;
    }

    // DOD-INBOUND-GUARD-1 (D3): the receive-side mirror of the initiator's F13 guard (~3189).
    // An empty counterparty endpoint means the offer-accept never happened (this agent's standing
    // receiver was not up when the directory's session_offer arrived) and the directory signed the
    // assignment anyway, with "empty defaults". The initiator refuses that assignment and creates
    // NO session — accepting it here builds a phantom session whose away-reply lands in the
    // initiator's transcript with no session row: permanently unread AND unreadable. Refuse it
    // loudly, before any session state exists. Nothing legitimate is lost — a session whose
    // initiator has no address to dial is unusable by construction.
    if (!parsed.counterpartySessionPeerId) {
      logger.warn("session.inbound.assignment.incomplete", {
        agentName: localAgent.name,
        sessionId: parsed.sessionIdHex,
        correlationId,
      });
      return;
    }

    // M1: idempotency — a retransmitted assignment for an already-known session (persisted
    // row OR currently in flight) must not double-accept (orphaned node) or double-enqueue.
    if (inboundInFlight.has(parsed.sessionIdHex) || sessionNodeManager.getSessionRecord(localAgent.name, parsed.sessionIdHex)) {
      logger.info("session.inbound.duplicate.ignored", {
        sessionId: parsed.sessionIdHex,
        agentName: localAgent.name,
        correlationId,
      });
      return;
    }

    // SECURITY — DEFERRED (SESSION-004 re-home): the directory's FROST threshold signature
    // on the assignment (directory_signature over the TBS, verified against signer_pubkey)
    // is NOT yet verified here. The old client's receiveSessionAssignment performed that
    // check; it must be re-homed natively before this path faces a real (untrusted)
    // directory. Until then we accept directory-pushed assignments on trust — the in-process
    // seam tests inject trusted frames.
    // M8B F15: logged at DEBUG with an "expected" note — it fires on EVERY healthy inbound
    // session, and at WARN it read as a failure and actively misled live diagnosis. The
    // deferred-verification state is a known, tracked gap (SESSION-004), not a per-session
    // anomaly.
    logger.debug("session.inbound.assignment.unverified", {
      sessionId: parsed.sessionIdHex,
      agentName: localAgent.name,
      note: "FROST assignment signature verification deferred to SESSION-004 re-home (expected on every inbound session until SESSION-004)",
      correlationId,
    });

    inboundInFlight.add(parsed.sessionIdHex);
    // Serialize: the next accept does not begin until this one (and any standing-receiver
    // rebuild it triggers) settles. A throw inside one accept must not break the chain.
    const agentName = localAgent.name;
    inboundAcceptChain = inboundAcceptChain
      .then(() => acceptInboundAssignment(parsed, agentName, correlationId))
      .catch((err: unknown) => {
        inboundInFlight.delete(parsed.sessionIdHex);
        logger.error("session.inbound.accept.error", {
          sessionId: parsed.sessionIdHex,
          agentName,
          error: err instanceof Error ? err.message : String(err),
          correlationId,
        });
      });
  }

  // CELLO-M7-CONN-001 (DOD-CONN-2): wire the inbound session/seal responders onto a GIVEN
  // signaling manager. Called for EVERY agent's own per-agent manager (via getAgentSignaling)
  // so each agent receives inbound session_assignment + seal_interrupted_request on its OWN
  // authenticated stream — closing the SPINE-5 gap where only the primary (whose stream WAS
  // the keystone) received them. A frame arrives on exactly one agent's stream, so there is no
  // double-dispatch; each handler resolves the local agent internally and that resolution
  // matches the stream the directory routed the frame to.
  // CELLO-M8-TRUST-001: open + verify + store + ACK a sealed trust signal pushed from the directory
  // pickup queue. The daemon is the ONLY party that can open the seal (k_local — SI-001); it verifies
  // the recomputed hash against the directory's anchor before storing, and ACKs only on success so the
  // directory deletes the ciphertext (AC-001/AC-002). open-fail / hash-mismatch / store-fail → NO ACK
  // (the directory keeps the pickup for a later retry; the signal is re-mintable).
  async function handleTrustSignalPickup(
    frame: Record<string, unknown>,
    keyProvider: import("@cello-protocol/crypto").KeyProvider,
    mgr: SignalingManager,
    agentName: string,
  ): Promise<void> {
    const id = typeof frame["id"] === "string" ? frame["id"] : null;
    const signalKind = typeof frame["signal_kind"] === "string" ? frame["signal_kind"] : null;
    const signalHash = typeof frame["signal_hash"] === "string" ? frame["signal_hash"] : null;
    const ciphertext = frame["ciphertext"];
    if (!id || !signalKind || !signalHash || !(ciphertext instanceof Uint8Array)) {
      // Neither stores nor ACKs → the directory retains the row and re-delivers. Log it: a PERMANENTLY
      // malformed frame would otherwise be re-delivered forever with zero daemon-side signal (fallback-finder).
      logger.warn("daemon.trust_signal.malformed", {
        agentName,
        hasId: !!id,
        hasSignalKind: !!signalKind,
        hasSignalHash: !!signalHash,
        ciphertextOk: ciphertext instanceof Uint8Array,
      });
      return;
    }
    if (!keyProvider.openContentSeal) {
      // A session-node stub key cannot open content seals. No ACK → the directory re-delivers; log so a
      // pickup persistently routed to a stub-key agent is visible rather than a silent forever-retry.
      logger.warn("daemon.trust_signal.no_content_key", { agentName, signalKind, correlationId: id });
      return;
    }
    // The pickup id correlates the directory's deliver/ack with the daemon's receive (TRUST-001 obs).
    const correlationId = id;

    let recovered: Uint8Array | null;
    try {
      recovered = await keyProvider.openContentSeal(ciphertext);
    } catch {
      recovered = null;
    }
    if (!recovered) {
      logger.warn("daemon.trust_signal.open_failed", { agentName, signalKind, correlationId });
      return;
    }
    const recomputed = Buffer.from(cryptoHash(recovered)).toString("hex");
    if (recomputed !== signalHash) {
      logger.error("daemon.trust_signal.hash_mismatch", { agentName, signalKind, correlationId });
      return;
    }
    try {
      const store = new DbIdentityStore(sessionNodeManager.getDb(), logger);
      store.storeTrustSignal({ signalHash, agentId: null, signalKind, payload: recovered });
    } catch (err) {
      logger.error("daemon.trust_signal.store_failed", {
        agentName,
        signalKind,
        correlationId,
        error: err instanceof Error ? err.message : String(err),
      });
      return;
    }
    logger.info("daemon.trust_signal.received", { agentName, signalKind, verified: true, correlationId });
    // DOD-SENDRAW-1: sendRaw never throws — a discarded result hid every failed ack, leaving the
    // sender to retransmit against a daemon that believed it had answered.
    const ackRes = await mgr.sendRaw({ type: "trust_signal_ack", id });
    if (!ackRes.ok) {
      logger.warn("daemon.trust_signal.ack_send_failed", {
        agentName,
        signalKind,
        correlationId,
        detail: ackRes.reason ?? "send_not_ok",
        ...(ackRes.guidance ? { guidance: ackRes.guidance } : {}),
      });
    }
  }

  function wirePerAgentSessionInbound(mgr: SignalingManager): void {
    mgr.registerInboundHandler((frame) => {
      if (frame["type"] !== "seal_interrupted_request") return;
      void handleInboundSealInterruptedRequest(frame as Record<string, unknown>);
    });
    mgr.registerInboundHandler((frame) => {
      if (frame["type"] !== "session_assignment") return;
      handleInboundSessionAssignment(frame as Record<string, unknown>);
    });
  }
  // CONN-001: test path only — the shared manager's inbound session/seal responders. Production
  // wires them per-agent in getAgentSignaling (each agent receives on its own stream).
  if (sharedSignaling) wirePerAgentSessionInbound(sharedSignaling);

  // M7 DOD-SPINE-7 / CELLO-M7-CONN-001: the seal-completion listeners (session_sealed /
  // seal_unilateral_confirmed / seal_unilateral_notification) are registered PER-AGENT inside
  // getAgentSignaling (the directory routes each over the session-owning agent's authenticated
  // stream), and on the shared manager for the test path via wireSharedHandlers. No keystone, no
  // runtime election — a fresh-install agent gets them when it comes online (create/start).

  // cello_await_session — the counterparty's blocking pull for the next inbound session.
  // Returns immediately if one is already queued for the current agent (FIFO), otherwise
  // blocks until one arrives or timeout_ms elapses.
  handlers.set("cello_await_session", async (params, connectionId) => {
    const connState = perConnectionState.get(connectionId);
    // CC-3 / M8C-AUTOSTART-1 F18: resolve the target agent — explicit { agent } wins, else this
    // connection's current agent, else the sole online agent (removes the no_current_agent papercut
    // after a /mcp reconnect when exactly one agent is online). 2+ online with none selected → null.
    const agentName = resolveCurrentAgent(connState, params?.agent as string | undefined);
    if (!agentName) {
      return NO_CURRENT_AGENT_RESPONSE;
    }
    const timeoutMs = typeof params?.["timeout_ms"] === "number" ? (params["timeout_ms"] as number) : 30_000;

    const toResponse = (e: InboundSessionEvent) => ({
      type: "new_session",
      session_id: e.sessionIdHex,
      counterparty_pubkey: e.counterpartyPubkeyHex,
      genesis_prev_root: e.genesisPrevRootHex,
      // MONIKER-2: validated-at-boundary display hint; null = absent or rejected.
      offered_moniker: e.offeredMoniker ?? null,
    });

    reapExpiredInboundSessions(agentName); // M8C-TTL-1: don't hand back a stale expired entry
    const queued = inboundSessionQueues.get(agentName);
    if (queued && queued.length > 0) {
      return toResponse(queued.shift()!);
    }

    const event = await new Promise<InboundSessionEvent | null>((resolve) => {
      const waiters = inboundSessionWaiters.get(agentName) ?? [];
      const waiter: InboundSessionWaiter = {
        connectionId,
        deliver: (e) => {
          clearTimeout(timer);
          resolve(e);
        },
      };
      waiters.push(waiter);
      inboundSessionWaiters.set(agentName, waiters);
      const timer = setTimeout(() => {
        const list = inboundSessionWaiters.get(agentName);
        if (list) {
          const idx = list.indexOf(waiter);
          if (idx !== -1) list.splice(idx, 1);
        }
        resolve(null);
      }, timeoutMs);
    });

    if (event === null) return { type: "timeout" };
    return toResponse(event);
  });

  // The two seal-initiation flows cello_close_session dispatches into (seal-flows.ts): the
  // counterparty is gone (seal-interrupted) or live (bilateral). Neither can notarize on its own —
  // the daemon holds no threshold signer, which IS the sovereign-node invariant.
  const { handleSealInterruptedFlow, handleActiveSealFlow } = createSealFlows({
    logger,
    sessionNodeManager,
    agents,
    getKeyProvider: (agentName: string) => keyProviders.get(agentName),
    signalingFor,
    sendOver,
  });

  // cello_send + cello_receive — the content path (session-content-handlers.ts). Two halves of one
  // state machine (the read cursor: send writes the tree, receive advances the cursor + watermark),
  // so they move together.
  registerSessionContentHandlers({
    handlers,
    logger,
    sessionNodeManager,
    securityGateway,
    retryQueue,
    getConnState: (connectionId) => perConnectionState.get(connectionId),
    resolveCurrentAgent,
    NO_CURRENT_AGENT_RESPONSE,
    getConnectionCursor,
    advanceConnectionCursor,
    safeCursorAdvance,
    clearTelegramRung,
  });

  // ─── M8C-INBOX-1 (N1/N4): cello_check_notifications — push-loss reconciler + poll-only inbox ───
  // Notifications are fire-and-forget (no ack, no redelivery); this is how a client discovers what
  // it missed while its shim was down/busy, and the primary inbox for poll-only clients (Bedrock,
  // cron). Content-free: pending session requests (from the in-memory queue, READ non-destructively —
  // cello_await_session owns draining) + unread message counts (derived from the persisted read
  // watermark, N2). No separate notification store; no ack verb (N4).
  handlers.set("cello_check_notifications", async (params, connectionId) => {
    const connState = perConnectionState.get(connectionId);
    const scope = params?.scope === "all" ? "all" : "current";

    let agentNames: string[];
    if (scope === "all") {
      agentNames = loadedAgents.map((a) => a.name);
    } else {
      // F18: an explicit current agent, else the sole-online agent; ambiguous → no_current_agent.
      const current = resolveCurrentAgent(connState);
      if (!current) {
        return {
          ok: false,
          reason: "no_current_agent",
          guidance: "No current agent for this connection. Call cello_use_agent to select one, or use scope:\"all\" to check every loaded agent.",
        };
      }
      agentNames = [current];
    }

    const agents = agentNames.map((agent) => {
      reapExpiredInboundSessions(agent); // M8C-TTL-1: expired ones surface below, not as "pending"
      const pending = (inboundSessionQueues.get(agent) ?? []).map((e) => ({
        session_id: e.sessionIdHex,
        from: e.counterpartyPubkeyHex,
      }));
      // M8C-TTL-1: expired requests stay VISIBLE (not silently dropped) — the operator can see
      // what they missed rather than a request just vanishing from the pending list.
      const expired = (expiredSessionRequests.get(agent) ?? []).map((e) => ({
        session_id: e.sessionIdHex,
        from: e.counterpartyPubkeyHex,
        expired_at: e.expiredAt,
      }));
      const unread = sessionNodeManager.getUnreadSummary(agent);
      const total_unread = unread.reduce((sum, u) => sum + u.unread_count, 0);
      // DOD-RENAME-1 AC3: pending rename notices surface HERE (the INBOX pull), never as a real-time
      // push. The offered name is rendered as an untrusted CLAIM (quoted, with the pubkey) plus the
      // command to adopt it — the daemon never auto-applies a self-declared name.
      const rename_notices = sessionNodeManager.getRenameNotices(agent).map((n) => ({
        pubkey: n.pubkey,
        your_name_for_them: n.moniker,
        claimed_name: n.offered_name,
        noticed_at: n.noticed_at,
        // Names the contact by the operator's OWN pet name (AC3); the self-declared name is a quoted,
        // untrusted claim; the adopt command carries its arguments so it is copy-pasteable.
        // The MCP call form below is translated WHOLE (arguments and all) for a CLI caller by
        // vocabulary.ts's CALL_FORMS — rewriting only the tool name would leave the tool's JSON
        // bolted onto a CLI verb, which looks like a command and is not one. `claimed_name` above
        // carries the peer's self-declared name UNTOUCHED, so the operator always has the raw value
        // even though the prose copy passes through the renderer.
        notice:
          `Your contact ${n.moniker !== null ? `"${n.moniker}" ` : ""}(${n.pubkey.slice(0, 16)}…) now calls themselves ` +
          `"${n.offered_name}" (self-declared — unverified). Adopt it: cello_contact_set_moniker ` +
          `{ pubkey: "${n.pubkey}", moniker: "${n.offered_name}" }, or ignore.`,
      }));
      return { agent, pending_session_requests: pending, expired_session_requests: expired, unread, total_unread, rename_notices };
    });

    const totalUnread = agents.reduce((sum, a) => sum + a.total_unread, 0);
    const totalPending = agents.reduce((sum, a) => sum + a.pending_session_requests.length, 0);
    // M8C-TTL-1 (reviewer finding, D19): surface expired-log size so unbounded growth (were the
    // cap ever removed or misconfigured) would be visible here, not just in an internal Map.
    const totalExpired = agents.reduce((sum, a) => sum + a.expired_session_requests.length, 0);
    logger.info("inbox.checked", { connectionId, scope, agentCount: agents.length, totalUnread, totalPending, totalExpired });
    return { ok: true, scope, agents };
  });

  // The address book — contacts, tiers, monikers, settings, the telegram token. Ten handlers, now
  // in contact-handlers.ts. Extracting them showed the address book closes over almost nothing: it
  // needs the session store, this connection's agent selection, a logger, and one callback to
  // restart the telegram poller. Nothing about sessions, seals, transport or ceremonies.
  registerContactHandlers({
    handlers,
    sessionNodeManager,
    getConnState: (connectionId) => perConnectionState.get(connectionId),
    resolveCurrentAgent,
    // cello_set_moniker was the one address-book handler reaching past the store for the raw SQLite
    // handle. Same construction, same behavior — the daemon owns the DB, so the daemon builds it.
    setAgentMoniker: (agentName, moniker) =>
      new DbIdentityStore(sessionNodeManager.getDb(), logger).setMoniker(agentName, moniker),
    logger,
    startTelegramPollerIfConfigured,
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

  // DOD-ONBOARD-HELP-1 §5 — render every response for the surface that asked.
  //
  // The daemon is where an operator actually MEETS the tool names: a refused send says "call
  // cello_receive first". Those strings are written with the canonical MCP names, so an MCP caller
  // gets them verbatim — but a CLI caller must be told `cello receive`, the thing they can type.
  // (P2-7 was the one-off report of this; it is a whole CLASS, and this closes the class.)
  //
  // Wrapping the handler map is the ONE choke point that has both the response and the connection's
  // clientType. Doing it per-handler would mean 60+ call sites, and the 61st would forget.
  const renderedHandlers = new Map<string, IpcHandler>();
  for (const [method, handler] of handlers) {
    renderedHandlers.set(method, async (params, connectionId) => {
      const result = await handler(params, connectionId);
      // Default to "cli": a connection that never sent ipc.connect has no recorded surface, and the
      // CLI verb is the safe answer — it is at least a real command an operator can run, whereas an
      // MCP tool name is useless in a terminal.
      const surface = perConnectionState.get(connectionId)?.clientType === "mcp" ? "mcp" : "cli";
      return renderForSurface(result, surface);
    });
  }

  // Create and start IPC server
  const ipcServer: IpcServer = createIpcServer(
    { socketPath, maxConnections, logger },
    renderedHandlers,
  );

  try {
    await ipcServer.start();
  } catch (err: unknown) {
    // As above: startDaemon's catch releases the singleton lock for us.
    await removeLockIfOwned(lockFilePath, process.pid, logger);
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
    dispatchSessionStateChangedWithTelegram(agentName, sessionId, state, counterpartyPubkey);
  });

  // M8C-MSGWAKE-1 (channel stage 2): per-message wake — a verified inbound message fires a
  // content-free `cello_message` doorbell to the current-agent connection(s). The shim's generic
  // bridge (WAKE) forwards it to a live --channels session as notifications/claude/channel.
  sessionNodeManager.setOnContentArrived((agentName, sessionId, senderPubkey) => {
    // MONIKER-4 AC2: the message doorbell names the sender the same way the session doorbell does.
    notificationDispatcher.dispatchCelloMessage(agentName, sessionId, senderPubkey, resolveWho(agentName, senderPubkey, sessionId));
    // M8C-AWAY-1: an unattended agent auto-acks an inbound message on an existing session.
    void sendAwayResponse(agentName, sessionId, "message");
    // M8C-TGDOOR-1: message-waiting — coalesced (ring-once-until-read) inside sendTelegramDoorbell.
    void sendTelegramDoorbell(agentName, sessionId, "message_waiting", "New message waiting");
  });

  // MCP-001: Clean up per-connection state when a connection disconnects
  // MCP-002: Also unregister from notification dispatcher
  ipcServer.onDisconnect((connectionId) => {
    perConnectionState.delete(connectionId);
    connectionCursors.delete(connectionId); // M8C-CURSOR-1: cursor is connection-scoped, dies with it
    notificationDispatcher.unregisterConnection(connectionId);
    // Seam 2 (review H2): evict any cello_await_session waiters owned by this connection.
    // Otherwise enqueueInboundSession would hand the next inbound session to a closed
    // connection's waiter and the event would be lost. deliver(null) clears the waiter's
    // timer and resolves its (now-orphaned) promise as a timeout.
    for (const [agentName, waiters] of inboundSessionWaiters) {
      const survivors: typeof waiters = [];
      for (const w of waiters) {
        if (w.connectionId === connectionId) w.deliver(null);
        else survivors.push(w);
      }
      if (survivors.length > 0) inboundSessionWaiters.set(agentName, survivors);
      else inboundSessionWaiters.delete(agentName);
    }
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

  // CELLO-M7-CONN-001 (DOD-CONN-3): background manifest polling runs daemon-level over
  // unauthenticated HTTP (startHttpManifestPoll above), NOT over a signaling stream. Its
  // lifecycle is the daemon's, not any agent connection's — so it polls even with zero agents.

  // Graceful shutdown
  async function stop(reason: string): Promise<void> {
    // M8C-TGDOOR-1: stop the single long-lived getUpdates poller (no-op if never started) — bump
    // the generation so the running loop's while-condition fails on its next check.
    stopTelegramPoller(); // M8C-TGDOOR-1: invalidate the poll loop; it exits on its next generation check
    // CELLO-M7-CONN-001: stop the HTTP manifest poll (sets the stopped flag so an in-flight
    // tick cannot re-arm, and cancels the scheduler). Belt-and-suspenders cancel for the
    // no-poll case (scheduler present but poll not started).
    stopHttpManifestPoll?.();
    if (manifestPollScheduler) {
      manifestPollScheduler.cancel();
    }
    logger.info("daemon.stopped", { pid: process.pid, reason });
    try {
      // stopAllSignaling() stops the shared manager AND every per-agent manager (best-effort). Do
      // not add a separate per-agent stop loop beside it: it would be redundant, and an unguarded
      // second stop() that throws would abort the rest of shutdown.
      await stopAllSignaling();
      // Gracefully mark active sessions interrupted (AC-009) before stopping IPC
      await sessionNodeManager.gracefulShutdown();
      await ipcServer.stop();
    } finally {
      // DOD-SINGLE-DAEMON-1: in a `finally`, because a throw anywhere above must not leave the lock
      // held. In the real binary the process exits and the kernel reclaims it — but an in-process
      // caller (vitest, an embedder) whose shutdown throws would otherwise find every subsequent
      // startDaemon in that process reporting "another daemon is already running", with the real
      // cause thrown away. That is the same leak F2 fixed on the startup path.
      //
      // DOD-DAEMON-CLEANUP-1 (AC1): the lock file goes only if it is still OURS. Another daemon may
      // have taken it over while we ran, and deleting a live daemon's lock is what makes `cello
      // logout` say "No daemon running" and the next `cello login` spawn a third one.
      await removeLockIfOwned(lockFilePath, process.pid, logger).catch(() => { /* best-effort */ });
      // Released LAST: while we hold it, no successor daemon can start, which is what lets
      // ipcServer.stop()'s socket re-check above be race-free.
      singletonLock.release();
    }
  }

  function getSessionNodeManager(): SessionNodeManager {
    return sessionNodeManager;
  }

  function getTransportSelector(): ITransportSelector {
    return transportSelector;
  }

  function getAutoNatService(): IAutoNatService {
    return autoNatService;
  }

  // M8C-TGDOOR-1: cold-capable — start the poller if a token was already configured from a
  // prior run, without waiting for any agent to come online or any client to attach.
  startTelegramPollerIfConfigured();

  return { stop, getStatus, getSessionNodeManager, getTransportSelector, getAutoNatService };
}
