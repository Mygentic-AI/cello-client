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
  DirectorySignalingState,
} from "./types.js";
import { loadAgents, type LoadedAgent } from "./agent-loader.js";
import { acquireLock, removeLockIfOwned } from "./lock-file.js";
import { acquireSingletonLock, type SingletonLock } from "./singleton-lock.js";
import { createIpcServer, type IpcServer, type IpcHandler } from "./ipc-server.js";
import { renderForSurface } from "./vocabulary.js";
import { SessionNodeManager } from "./session-node-manager.js";
import { type SecurityGatewayClient } from "@cello-protocol/gateway";
import { registerGatewayConfigHandlers } from "./gateway-config-handlers.js";
import { RetryQueue } from "./retry-queue.js";
import { NonceDedupStore } from "./nonce-dedup.js";
import { ContentParkClient } from "./content-park-client.js";
import { NotificationDispatcher } from "./notification-dispatcher.js";
import { createNode, SignalingManager, type ConnectResult, type CelloNode } from "@cello-protocol/transport";
import { createSignalingConnect } from "./signaling-connect.js";
import { DbRegistrationPersistence, DbIdentityStore } from "./db-identity-store.js";
import { DbManifestVersionStore } from "./manifest-version-store-db.js";
import { composeSealedSubmission, sendSealedSubmission, fetchSubmissionResults } from "./signal-submission.js";
import type { SubmissionOp, SignalSubjectKind } from "@cello-protocol/protocol-types";

/**
 * Cap on a refusal message (M10B-D4). Generous for prose — the point is not to police what the
 * operator writes, it is that an UNBOUNDED string reaches a signer, a sealer and a transport, and
 * fails in the transport where the error names the wrong subsystem.
 */
const MAX_SUBMISSION_BODY_CHARS = 4000;
import type { IManifestVersionStore } from "@cello-protocol/transport";
// CELLO-M7-MSG-001 (AC-013/AC-018): the single application content-size cap, enforced
// at the send point here (the receive point lives in the transport content decode).
import { sealParkEnvelope } from "./park-envelope.js";
import type { ISessionNodeFactory, SessionNodeConfig, RelayConnectParams } from "./session-node-manager.js";
import type { RelayAssignmentCarry } from "./session-relay-client.js";
import {
  resolveCelloEnv,
  createTransportSelector,
  isProductionVariant,
} from "./transport-composition.js";
import type { ITransportSelector } from "./transport-selector.js";
import { parseSessionAssignment } from "./session-assignment-parser.js";
import { whoLabel } from "./who-label.js";
import { wireSessionCeremonyHandler, wireSessionOfferHandler, wireSealCeremonyHandler, runAgentRefresh } from "./session-ceremony.js";
import { LocalAutoNatStub, type IAutoNatService } from "@cello-protocol/transport";
import { verifyStartupManifest, createConsortiumRouting } from "./consortium-bootstrap.js";
import { resolveDirectoryUrl } from "./directory-bootstrap.js";
import { registerContactHandlers } from "./contact-handlers.js";
import { createSealCoordinator } from "./seal-coordinator.js";
import { createTelegramDoorbell } from "./telegram-doorbell.js";
import { registerSessionContentHandlers } from "./session-content-handlers.js";
import { createSealFlows } from "./seal-flows.js";
import { registerCloseSessionHandler } from "./close-session-handler.js";
import { createInboundSessions } from "./inbound-sessions.js";
import { createOutboundSessions } from "./outbound-sessions.js";
import { registerSessionReadHandlers } from "./session-read-handlers.js";
import { registerAgentHandlers } from "./agent-handlers.js";
import { registerRegisterHandler } from "./register-handler.js";
import { registerInitiateSessionHandler } from "./initiate-session-handler.js";
import { createContentPark } from "./content-park.js";
import { createInboundSealRequestHandler } from "./inbound-seal-request.js";
import { registerNotificationHandlers } from "./notification-handlers.js";
import { TypeRegistry } from "./type-registry.js";
import { DbRegistryVersionStore } from "./registry-version-store-db.js";
import { startRegistryPoll } from "./registry-poll.js";
import { CONSENT_ACCEPTED } from "./consent-migration.js";
import { TrustSignalStore } from "./trust-signal-store.js";
import { countAttendance, ContentTakeLedger } from "./co-attendance.js";
import { FrontierMismatchStore, renderFrontierMismatch } from "./frontier-mismatch.js";
import { encodeCbor, decodeCbor } from "@cello-protocol/protocol-types";


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
  /**
   * DOD-REGISTRY-1: the in-memory type registry — classify signal types.
   */
  getTypeRegistry(): TypeRegistry;
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
export class ProductionSessionNodeFactory implements ISessionNodeFactory {
  async createNode(config: SessionNodeConfig) {
    // DOD-NAT-REACHABILITY-1: the STANDING RECEIVER — the node that accepts every
    // inbound session — must bind a ROUTABLE interface by default. The old
    // loopback default meant a node announced 127.0.0.1 and was dialable by
    // nobody unless the operator hand-set CELLO_LISTEN_ADDR (only the EC2 demo
    // agent ever did). CELLO_LISTEN_ADDR / CELLO_ANNOUNCE_ADDRS remain as
    // overrides for publicly-hosted agents (M6 parity). Ephemeral session nodes
    // (which dial OUT and need no inbound reachability) stay on loopback.
    const isReceiver = config.nodeType === "standing_receiver";
    const listenAddr = isReceiver
      ? (process.env["CELLO_LISTEN_ADDR"] ?? "/ip4/0.0.0.0/tcp/0")
      : "/ip4/127.0.0.1/tcp/0";
    const announce =
      isReceiver && process.env["CELLO_ANNOUNCE_ADDRS"]
        ? process.env["CELLO_ANNOUNCE_ADDRS"].split(",").map((s) => s.trim()).filter(Boolean)
        : undefined;
    return createNode({
      keyProvider: SESSION_NODE_KEY_STUB,
      // Circuit-relay listen entries (reservations) ride alongside the TCP
      // listener; the transport tolerates a dead relay (NO_FATAL) but still
      // fails loudly if the TCP bind itself is lost.
      listenAddresses: [listenAddr, ...(config.circuitRelayListenAddrs ?? [])],
      ...(announce ? { announceAddresses: announce } : {}),
      connectionGater: config.connectionGater,
      // Forward the role. After DOD-NAT-REACHABILITY-1, dcutr is on every node
      // type; nodeType's remaining transport effect is the HOP gate (client
      // types never advertise circuit-relay HOP).
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
  // cello_send and the inbound screen inside SessionNodeManager. REQUIRED (INV-9): there is no
  // fallback, because the fallback WAS the bug — an always-allow default that nothing in the
  // product ever overrode.
  // The type says required, but tests are excluded from typecheck and JS callers exist, so the
  // absence has to be LOUD here rather than a TypeError three lines later that names the wrong
  // subsystem. A test that genuinely does not screen says so by passing the passthrough client.
  if (!config.securityGateway) {
    throw new Error(
      "startDaemon: securityGateway is required (INV-9). The daemon no longer defaults to " +
        "always-allow screening, because that default shipped a security layer that never ran. " +
        "Pass a LocalSidecarGatewayClient in production, or new PassthroughGatewayClient() if " +
        "this caller deliberately does not screen.",
    );
  }
  const securityGateway: SecurityGatewayClient = config.securityGateway;
  // Observability: announce the mode the CLIENT declares (M9B-D11), never a ternary over the
  // config. The sidecar socket connects lazily on the first screen, so this reports which adapter
  // is wired, not a live socket handshake — but it reports it from the object that will do the
  // screening, so a wiring mistake shows up here instead of hiding behind a correct-looking line.
  logger.info("security.gateway.connected", { mode: securityGateway.mode });

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
  const { manifestVerified, verifiedManifestVersion, verifiedManifest } = await verifyStartupManifest({
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
  const { resolveConsortiumRoster, failoverEndpointResolver, getFailoverEndpoint, getUnresolvedNodes, stopHttpManifestPoll } =
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

  // DOD-REGISTRY-1: type registry poll — daemon-level, runs even with zero agents.
  // When registryPubkey is configured, the daemon polls GET /registry, verifies the inner
  // Ed25519 signature, and updates the in-memory TypeRegistry. A poll failure never blanks
  // classification (INV-TYPE-CARRY). Absent pubkey = polling disabled, all types unclassified.
  const typeRegistry = new TypeRegistry();
  let stopRegistryPoll: (() => void) | undefined;
  if (config.registryPubkey && config.registryPollScheduler) {
    const registryVersionStore = new DbRegistryVersionStore(sessionNodeManager.getDb(), logger);
    stopRegistryPoll = startRegistryPoll({
      scheduler: config.registryPollScheduler,
      directoryUrl: directoryHttpUrl ?? resolveDirectoryUrl(process.env),
      typeRegistry,
      registryVersionStore,
      registryPubkey: config.registryPubkey,
      logger,
      mintCorrelationId: () => randomUUID(),
    });
  }

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

  // Constructed HERE, before ANY boot-time caller. autoRecoverForAgent is invoked from an agent's
  // onConnected and from the seal-upgrade content gate — both of which run long before the IPC
  // handler map exists. Its handlers register later (phase 2), which is what lets this sit up here.
  const contentPark = createContentPark({
    logger,
    sessionNodeManager,
    agents,
    getKeyProvider: (agentName: string) => keyProviders.get(agentName),
  });
  const autoRecoverForAgent = (agentName: string): Promise<void> => contentPark.autoRecoverForAgent(agentName);

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

  // The two seal-initiation flows cello_close_session dispatches into (seal-flows.ts): the
  // counterparty is gone (seal-interrupted) or live (bilateral). Neither can notarize on its own —
  // the daemon holds no threshold signer, which IS the sovereign-node invariant.
  // DOD-FRONTIER-STRAND-1 AC3: mismatches observed during a seal exchange, retained so the session
  // list can show them. Detection is inherently at close time (the frontiers can only be compared
  // when the two sides talk); what was missing is that the answer was discarded the moment it was
  // produced, so the only way to see it again was to attempt another close.
  const frontierMismatches = new FrontierMismatchStore();

  const { handleSealInterruptedFlow, handleActiveSealFlow } = createSealFlows({
    logger,
    sessionNodeManager,
    agents,
    getKeyProvider: (agentName: string) => keyProviders.get(agentName),
    signalingFor,
    sendOver,
    recordFrontierMismatch: (agentName, sessionId, m) => frontierMismatches.record(agentName, sessionId, m, Date.now()),
    clearFrontierMismatch: (agentName, sessionId) => frontierMismatches.clear(agentName, sessionId),
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
      // DOD-NAT-REACHABILITY-1 (Phase 2): the directory's relay pool arrives with
      // signaling_auth_ok — feed it to the session node manager so this agent's
      // standing receiver reserves with those relays (and rebuilds if it came up
      // deaf because agent-online raced ahead of this connect).
      onRelayEndpoints: (endpoints) => {
        sessionNodeManager.setDirectoryRelayEndpoints(
          agentName,
          endpoints.map((e) => ({ relayPeerId: e.peerId, relayAddrs: e.addrs })),
        );
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
      onConnected: () => {
        void autoRecoverForAgent(agentName);
        // RE-REGISTER THE STANDING RECEIVER. The receiver's LIFETIME is tied to this daemon; its
        // REGISTRATION is tied to this stream, and the stream turns over roughly every 70 seconds.
        // ensureStandingReceiverForAgent ran only at agent start, so 46 of 48 reconnects in one hour
        // left every agent unregistered — the directory then answers `targetStreamFound: false` and
        // a session request fails with `target_offline`, while `cello status`, `agent.online` and the
        // directory's own agent_presence all still report the agent healthy. Silent, and it does not
        // self-heal: only a daemon restart recovered it (2026-07-31 incident).
        //
        // Guarded on onlineAgents because this fires on the FIRST connect too, and an agent that was
        // never started must not acquire a receiver here. Re-entry at start is harmless —
        // #ensureStandingReceiver returns immediately when one exists or is being created.
        if (onlineAgents.has(agentName)) {
          void sessionNodeManager.ensureStandingReceiverForAgent(agentName).catch((err: unknown) => {
            logger.warn("session.standing_receiver.reregister.failed", {
              agentName,
              error: err instanceof Error ? err.message : String(err),
            });
          });
        }
      },
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
  // DOD-COATTEND-VISIBLE-1: the COUNT, deliberately kept separate from the boolean above. Several
  // sessions attending one agent is legitimate and permanent (co-attendance, not exclusivity — spec
  // §3); what was missing is that nobody was ever TOLD. `isAttended` is left byte-identical because
  // M8C-AWAY-1's auto-ack suppression hangs off its early return, and both read the same
  // `currentAgent` map the doorbell routes on, so the count can never disagree with who gets woken.
  function attendanceCount(agentName: string): number {
    return countAttendance(perConnectionState, agentName);
  }
  // Which connection consumed which leaf, so the session that finds an empty buffer can be told
  // whether its counterparty is quiet or its sibling was faster. Written at the destructive drain in
  // session-content-handlers; read at that handler's timeout. Delivery itself is unchanged.
  const contentTakes = new ContentTakeLedger();
  // DOD-AWAY-WRAP-1 AC1: request text is a leave-a-message greeting; agentName is spliced in at
  // the call site so it names the specific away agent.
  // DOD-AWAY-ACK-ONESHOT-TEXT-1 (live defect 2026-07-24): the ack must state the one-shot rule —
  // without it a cooperative caller LLM has no reason to stop, sends a follow-up, and eats the
  // DOD-INBOX-ONESHOT-1 rejection the design itself invited.
  const AWAY_MESSAGE_TEXT = "Agent is currently away. Your message has been received and will be read when the operator returns. This inbox accepts one message per visit — please close the session now (send with signal: wrap) instead of sending more.";
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
    // DOD-AWAY-WRAP-1 AC2: if the triggering message carries [[WRAP]], the caller is done — skip the
    // away reply entirely and let the seal ceremony proceed. The dedupKey is intentionally NOT added
    // here: the WRAP path is a silent close, not an away period that should be deduped.
    if (kind === "message") {
      const latestHex = sessionNodeManager.peekLatestReceivedContentHex(agentName, sessionId);
      if (latestHex !== null) {
        const text = Buffer.from(latestHex, "hex").toString("utf8");
        // DOD-WRAP-SUBSTRING-1: match the APPENDED token, not any substring —
        // DOD-SIGNAL-TOKEN-1 always appends the real token at the END of the body. A substring
        // match would classify a mere mention of [[WRAP]] (sent signal:"over") as a close
        // signal, silently skipping both the away reply and the oneshot rejection.
        if (text.trimEnd().endsWith("[[WRAP]]")) {
          logger.info("session.away.response.skipped_wrap", { agentName, sessionId });
          return;
        }
      }
    }
    const dedupKey = `${agentName}:${sessionId}:${kind}`;
    // F3 fix: a dedicated guard prevents re-entry after the rejection fires — without it a
    // rapid-fire sender could trigger multiple rejection sends and concurrent seal submits while
    // the session remains active (seal failed). This key is never cleared (no re-attend resets
    // it — once rejected, the session is closing regardless).
    const rejectedKey = `${agentName}:${sessionId}:rejected`;
    if (awayAckSent.has(dedupKey)) {
      // DOD-INBOX-ONESHOT-1: a second inbound message while the first away ack is still live means
      // the caller ignored the leave-a-message instruction. Send one [[WRAP]]-bearing rejection and
      // immediately initiate the seal so the session closes without operator intervention.
      if (kind === "message" && !awayAckSent.has(rejectedKey)) {
        awayAckSent.add(rejectedKey); // guard BEFORE async work — concurrent arrivals must not re-enter
        const record2 = sessionNodeManager.getSessionRecord(agentName, sessionId);
        if (record2 && record2.status === "active") {
          // Reviewer F2: token at the END — the daemon's own output must honor the
          // DOD-SIGNAL-TOKEN-1 append-at-end contract that DOD-WRAP-SUBSTRING-1 detection
          // is anchored on (a counterparty daemon's end-anchored detector must see this close).
          const rejectText = "This inbox only accepts one message per visit. Closing. [[WRAP]]";
          const rejectBytes = new TextEncoder().encode(rejectText);
          const rejectHash = createHash("sha256").update(new Uint8Array([0x00])).update(rejectBytes).digest();
          // Best-effort: a send failure still triggers the seal — we are closing regardless.
          const sendResult = await sessionNodeManager.sendContent(agentName, sessionId, rejectBytes, new Uint8Array(rejectHash), randomUUID());
          if (sendResult.ok) {
            const rejectHashHex = Buffer.from(rejectHash).toString("hex");
            const { leafIndex } = sessionNodeManager.appendSessionLeaf(agentName, sessionId, "msg", rejectHashHex, randomUUID());
            sessionNodeManager.recordTranscriptMessage(agentName, sessionId, leafIndex, "sent", rejectBytes, randomUUID());
            logger.info("session.away.inbox.oneshot.rejected", { agentName, sessionId, sequenceNumber: leafIndex });
          } else {
            logger.warn("session.away.inbox.oneshot.reject_send_failed", { agentName, sessionId, reason: sendResult.reason });
          }
          // DOD-INBOX-ONESHOT-1 / DOD-SEAL-BILATERAL-TIMEOUT-1: initiate the seal via the
          // relay-mediated path (submitSealLeaf → bilateral wait → unilateral escalation).
          // The signaling-only path (handleActiveSealFlow) suffers a leaf_count_mismatch race:
          // this party's tree includes the just-sent rejection, but the counterparty's tree may
          // not have ingested it yet when the seal request arrives over the signaling channel.
          // The relay path avoids this entirely — it posts a SEAL ctrl leaf and waits for the
          // counterparty to independently co-seal; no bilateral leaf-count comparison needed.
          void (async () => {
            const correlationId = randomUUID();
            const sk = sealKey(agentName, sessionId);
            if (sealInterruptedInProgress.has(sk)) return;
            sealInterruptedInProgress.add(sk);
            try {
              let resolveSeal!: (c: { rootHex: string; legibility?: unknown }) => void;
              const sealedP = new Promise<{ rootHex: string; legibility?: unknown }>((r) => { resolveSeal = r; });
              pendingSealWaiters.set(sk, resolveSeal);

              const submit = await sessionNodeManager.submitSealLeaf(agentName, sessionId, correlationId);
              if (!submit.ok && submit.reason !== "responder_seal_already_submitted") {
                pendingSealWaiters.delete(sk);
                if (submit.reason === "relay_unavailable") {
                  const fallback = await handleActiveSealFlow(sessionId, record2, correlationId);
                  if (fallback.ok) {
                    logger.info("session.away.inbox.oneshot.seal_initiated", { agentName, sessionId, path: "signaling_fallback" });
                  } else {
                    logger.warn("session.away.inbox.oneshot.seal_initiate_failed", { agentName, sessionId, reason: fallback.reason, path: "signaling_fallback" });
                  }
                } else {
                  logger.warn("session.away.inbox.oneshot.seal_initiate_failed", { agentName, sessionId, reason: submit.reason });
                }
                return;
              }

              logger.info("session.away.inbox.oneshot.seal_initiated", { agentName, sessionId, path: "relay" });

              const bilateralTimeoutMs = Number(process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"]) || 660_000;
              let timer!: ReturnType<typeof setTimeout>;
              const timeoutP = new Promise<null>((r) => { timer = setTimeout(() => r(null), bilateralTimeoutMs); });
              const sealedCompletion = await Promise.race([sealedP, timeoutP]);
              clearTimeout(timer);
              pendingSealWaiters.delete(sk);

              if (sealedCompletion !== null) {
                logger.info("session.away.inbox.oneshot.sealed", { agentName, sessionId, sealedRoot: sealedCompletion.rootHex });
                return;
              }

              // Bilateral timeout — escalate to unilateral seal.
              const escalation = submit.ok
                ? { reportedRootHex: submit.reportedRootHex, sequenceNumber: submit.sequenceNumber }
                : submit.reason === "responder_seal_already_submitted" &&
                    typeof submit.reportedRootHex === "string" &&
                    typeof submit.sequenceNumber === "number"
                  ? { reportedRootHex: submit.reportedRootHex, sequenceNumber: submit.sequenceNumber }
                  : null;
              if (!escalation) {
                logger.warn("session.away.inbox.oneshot.seal_pending", { agentName, sessionId });
                return;
              }

              const sealAgentKp = keyProviders.get(agentName);
              const sealAgentPubkeyHex = sealAgentKp ? Buffer.from(await sealAgentKp.getPublicKey()).toString("hex") : "";
              const sealCarry = sealAgentPubkeyHex ? sessionNodeManager.getSealCarry(sealAgentPubkeyHex, sessionId) : [];
              const seal_leaves = sealCarry.map((l) => ({
                sequence_number: l.sequenceNumber,
                leaf_kind: l.leafKind,
                structure2_cbor: l.structure2Cbor,
                structure1_cbor: l.structure1Cbor,
                relay_id: l.relayId,
                relay_timestamp: l.relayTimestamp,
                relay_signature: l.relaySignatureHex ? new Uint8Array(Buffer.from(l.relaySignatureHex, "hex")) : undefined,
              }));

              let resolveUni!: (r: { ok: true; sealedRootHex: string; legibility?: unknown } | { ok: false; reason: string; remainingSeconds?: number }) => void;
              const uniP = new Promise<{ ok: true; sealedRootHex: string; legibility?: unknown } | { ok: false; reason: string; remainingSeconds?: number }>((r) => { resolveUni = r; });
              pendingUnilateralWaiters.set(sessionId, resolveUni);

              const sent = await sendOver(agentName, {
                type: "seal_unilateral",
                session_id: new Uint8Array(Buffer.from(sessionId, "hex")),
                reported_root: new Uint8Array(Buffer.from(escalation.reportedRootHex, "hex")),
                reported_seq: escalation.sequenceNumber,
                seal_leaves,
              });
              if (!sent.ok) {
                pendingUnilateralWaiters.delete(sessionId);
                logger.warn("session.away.inbox.oneshot.seal_unilateral_failed", { agentName, sessionId, reason: "send_failed" });
                return;
              }

              let uniTimer!: ReturnType<typeof setTimeout>;
              const uniTimeoutP = new Promise<{ ok: false; reason: string }>((r) => {
                uniTimer = setTimeout(() => r({ ok: false, reason: "seal_unilateral_timeout" }), 30_000);
              });
              const uniResult = await Promise.race([uniP, uniTimeoutP]);
              clearTimeout(uniTimer);
              pendingUnilateralWaiters.delete(sessionId);

              if (uniResult.ok) {
                logger.info("session.away.inbox.oneshot.sealed", { agentName, sessionId, sealedRoot: uniResult.sealedRootHex, sealType: "unilateral" });
              } else {
                logger.warn("session.away.inbox.oneshot.seal_unilateral_failed", { agentName, sessionId, reason: uniResult.reason });
              }
            } finally {
              sealInterruptedInProgress.delete(sealKey(agentName, sessionId));
            }
          })();
        }
      }
      return;
    }
    const record = sessionNodeManager.getSessionRecord(agentName, sessionId);
    if (!record || record.status !== "active") return;
    // Select the ack wording by whether the sender is a known contact — STRANGER_TEXT
    // ("Dispatched.") for unknown, system default for known. The inbound accept path does NOT
    // auto-add the sender: an unattended stranger STAYS unknown across every inbound interaction.
    // Promotion requires operator engagement — an outbound initiate, a cello_send reply, or an
    // explicit contact add. This is a plain read of current contact state; nothing downstream
    // depends on its ordering.
    const isKnown = sessionNodeManager.isKnown(agentName, record.counterparty_pubkey);
    // DOD-AWAY-WRAP-1 AC1: request kind uses a leave-a-message greeting that names the away agent.
    const systemDefault = kind === "request"
      ? `${agentName} is currently away. Leave a message (send with signal: wrap to close) and it will be read when they return.`
      : AWAY_MESSAGE_TEXT;
    awayAckSent.add(dedupKey); // guard BEFORE the async send — concurrent arrivals must not double-ack
    try {
      // DOD-AWAY-TIER-1: resolve most-specific-first — per-contact away_message → per-tier away
      // (settings) → agent default (settings) → the system default (code, per kind). Total.
      const awayText = sessionNodeManager.resolveAwayMessage(agentName, record.counterparty_pubkey)
        ?? (isKnown ? systemDefault : STRANGER_TEXT);
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

  // The OUTBOUND session path (outbound-sessions.ts): discovery, the session request, and cross-node
  // setup via a transient VISITING connection to the counterparty's home node.
  const { openVisitingConnection, crossNodeBrokerBySession, resolvedSessionNegotiator } = createOutboundSessions({
    logger,
    sessionNodeManager,
    getKeyProvider: (agentName: string) => keyProviders.get(agentName),
    getPersistence,
    getAgentSignaling: (agentName: string, kp, pubkeyHex: string) => getAgentSignaling(agentName, kp, pubkeyHex),
    waitForSignalingConnected,
    getFailoverEndpoint,
    resolveConsortiumRoster,
    registerSealListeners,
    sessionNegotiator,
    challengeVerifier,
    getManifestVersion: () => verifiedManifestVersion,
    loadedAgents,
  });
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
  // Fix #1 EXTENSION (cross-node seal-liveness) — the AUTO-ACKNOWLEDGE half.
  //
  // close-session-handler already re-opens a transient visiting connection to the broker for its
  // own path. The auto-ack path had no such guard, and it is the one that fires FIRST whenever the
  // counterparty closes first: it submits a seal leaf, the directory answers within ~60ms by pushing
  // `seal_verified` to the INITIATOR, finds no stream (the initiator released its visiting
  // connection after setup), ENQUEUES the frame, and then blocks waiting for a co-signature it never
  // asked for. Proven on GCP — leaf 18:41:56.555, directory `seal.certificate.deferred`
  // (initiator_stream_absent) 18:41:56.615, broker reconnect 18:42:01.529: five seconds too late.
  //
  // Returns null for same-node sessions (no broker entry) — those reach the initiator on its home
  // stream and need no visiting connection.
  sessionNodeManager.setEnsureSealBroker(async (agentName, sessionId) => {
    const brokerNode = crossNodeBrokerBySession.get(`${agentName}:${sessionId}`);
    if (!brokerNode) return null;
    const kp = keyProviders.get(agentName);
    if (!kp) {
      logger.warn("session.seal.autoack.broker.no_keyprovider", { agentName, brokerNode });
      return null;
    }
    const pubHex = Buffer.from(await kp.getPublicKey()).toString("hex");
    const roster = await resolveConsortiumRoster();
    const target = roster?.find((e) => e.nodeId === brokerNode) ?? null;
    if (!target) {
      logger.warn("session.seal.autoack.broker.unresolved", { agentName, brokerNode });
      return null;
    }
    const correlationId = randomUUID();
    const conn = openVisitingConnection(agentName, kp, pubHex, { peerId: target.peerId, multiaddr: target.multiaddr }, correlationId, brokerNode);
    if (await waitForSignalingConnected(conn.mgr, 10_000)) {
      logger.info("session.seal.autoack.broker.reconnected", { agentName, brokerNode, correlationId });
      return conn;
    }
    await conn.stop("autoack-seal-broker-unreachable");
    logger.warn("session.seal.autoack.broker.unreachable", { agentName, brokerNode, correlationId });
    return null;
  });

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

  const NO_CURRENT_AGENT_RESPONSE = {
    ok: false,
    reason: "no_current_agent",
    guidance: "No current agent is set for this connection. Call cello_start_agent to bring an agent online, then call cello_use_agent to set it as the current agent for this connection.",
  };

  // The inbound seal-interrupted REQUEST (inbound-seal-request.ts): the counterparty asks us to
  // co-sign the seal of a session neither side can finish normally. We answer with our own signed
  // leaf, or a rejection naming the exact mismatch — never a leaf we cannot corroborate.
  const { handleInboundSealInterruptedRequest } = createInboundSealRequestHandler({
    logger,
    sessionNodeManager,
    agents,
    getKeyProvider: (agentName: string) => keyProviders.get(agentName),
    sendOver,
    recordFrontierMismatch: (agentName, sessionId, m) => frontierMismatches.record(agentName, sessionId, m, Date.now()),
    clearFrontierMismatch: (agentName, sessionId) => frontierMismatches.clear(agentName, sessionId),
  });

  // ORDER IS LOAD-BEARING, in BOTH directions — and I got it wrong once already.
  //
  // The eager per-agent connect must run BEFORE `await flushAwaitingContent()`. That await does
  // real relay network I/O for every parked item, sequentially. Put the connect loop after it and
  // every agent's directory handshake is serialized behind the flush: on a daemon booting with
  // parked content and a slow relay, `agent.online` is delayed by the whole drain and NOTHING in
  // the log says the relay is the reason. Originally the two overlapped; they must keep doing so.
  //
  // But the loop's signaling wiring calls into the inbound-session module, which is a `const` now
  // (it was a hoisted function declaration, which is what silently made the old ordering work). So
  // the module is CONSTRUCTED here, immediately above the loop, rather than the loop being pushed
  // down below the module. Construction is synchronous and its deps are all ready — the handlers
  // it registers are fine this early because the handler map already exists.

  // Seam 2: inbound session establishment — the counterparty side (inbound-sessions.ts).
  const {
    registerHandlers: registerInboundSessionHandlers,
    wirePerAgentSessionInbound,
    handleTrustSignalPickup,
    enqueueInboundSession,
    reapExpiredInboundSessions,
    inboundSessionQueues,
    inboundSessionWaiters,
    expiredSessionRequests,
    offeredMonikers,
    offerKey,
  } = createInboundSessions({
    logger,
    sessionNodeManager,
    agents,
    getConnState: (connectionId) => perConnectionState.get(connectionId),
    resolveCurrentAgent,
    NO_CURRENT_AGENT_RESPONSE,
    getKeyProvider: (agentName: string) => keyProviders.get(agentName),
    sharedSignaling,
    handleInboundSealInterruptedRequest,
    reapDeadHalfOpenSessions,
    sendAwayResponse,
    dispatchSessionStateChangedWithTelegram,
    sendTelegramDoorbell,
  });

  if (!sharedSignaling) {
    for (const agent of loadedAgents) {
      getAgentSignaling(agent.name, agent.keyProvider, agent.pubkey);
    }
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
          // DOD-COATTEND-VISIBLE-1 AC2: how many sessions are driving this agent, including this
          // one. Live, not a high-water mark — it drops when a session disconnects. `selected` says
          // whether YOU hold it; this says whether anyone else does too.
          attendance: countAttendance(perConnectionState, a.name),
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
        // DOD-FRONTIER-STRAND-1 AC3: if a seal exchange has already proved the two sides disagree on
        // how many messages this session holds, SAY SO HERE. Otherwise a stranded session is listed
        // exactly like a healthy paused one, and the only way to learn it can never seal is to
        // attempt another close and read the error — which is how dbb93dfc… sat unnoticed a week.
        ...(() => {
          const m = frontierMismatches.get(row.agent_name, row.session_id);
          return m ? { frontierMismatch: renderFrontierMismatch(m, row.session_id) } : {};
        })(),
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

  // Agent lifecycle (agent-handlers.ts): create, remove, start, stop, select, list.
  registerAgentHandlers({
    handlers,
    logger,
    sessionNodeManager,
    agents,
    onlineAgents,
    getNotificationDispatcher: () => notificationDispatcher,
    getConnState: (connectionId) => perConnectionState.get(connectionId),
    perConnectionState,
    getAgentsForConnection,
    startAgentInternal,
    dropAgentSignaling,
    awayAckSent,
    keyProviders,
    loadedAgents,
    getAgentSignaling,
    waitForSignalingConnected,
    perAgentSignaling,
  });

  // `detail` carries the ACTUAL cause when one is known. The wire code stays `dkg_failed` — it is a
  // closed protocol union — but this string is a local daemon→IPC message, so it can say what really
  // happened instead of asserting a guess.
  const registrationGuidance = (reason: string, detail?: string): string => {
    switch (reason) {
      case "already_registered":
        return "This agent is already registered with the directory. No action needed.";
      case "directory_unreachable":
        return "The directory signaling stream is not connected (or its bootstrap endpoint could not be resolved). Wait for directory_signaling to show connected in cello status, then retry.";
      case "dkg_failed":
        // NOT "this usually means the pre-auth token". That diagnosis is confidently wrong for the
        // causes that actually occur — a colliding NODE_ID across two directory boxes, a commitment
        // that does not match the client's primary_pubkey, a node dropping mid-ceremony — and it sends
        // the operator to the wrong subsystem. The cause is now captured one call frame away
        // (registration.dkg.failed), so it is reported rather than guessed at.
        return detail
          ? `The FROST DKG ceremony with the directory failed: ${detail}`
          : "The FROST DKG ceremony with the directory failed, and no underlying cause was captured. Check the daemon log for registration.dkg.failed, which carries the reason.";
      case "timeout":
        return "The directory did not respond within the registration timeout. Retry once directory_signaling is connected.";
      default:
        return detail
          ? `Registration failed: ${reason} — ${detail}`
          : `Registration failed: ${reason}. Check the daemon logs (registration.* events).`;
    }
  };

  // cello_register (register-handler.ts): T-of-N DKG with the consortium. NO SINGLE NODE can
  // complete it alone — that is the sovereign-node invariant, and it is the point of the protocol.
  registerRegisterHandler({
    handlers,
    logger,
    keyProviders,
    getPersistence,
    getAgentSignaling,
    waitForSignalingConnected,
    dropAgentSignaling,
    startAgentInternal,
    directoryEndpointResolver,
    loadedAgents,
    registrationGuidance,
    manifestProvider,
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

  // ─── Trust-signal wallet (operator-facing, no agent scope required) ───
  handlers.set("wallet_list_signals", async (_params, _connectionId) => {
    const store = new TrustSignalStore(sessionNodeManager.getDb(), logger);
    const rows = store.listAllWalletSignals().map((r) => ({
      type: r.type,
      signal_hash: r.signalHash,
      subject_kind: r.subjectKind,
      subject: r.subject,
      issuer_kind: r.issuerKind,
      status: r.status,
      issued_at: r.issuedAt,
      expires_at: r.expiresAt,
      supersedes_hash: r.supersedesHash,
      default_present: r.defaultPresent,
      // M10B / DOD-END-ACCEPT-1 review F4. Without this the operator cannot distinguish a signal
      // that will be presented from one awaiting their decision — or one they already refused —
      // because `default_present: true` looks identical in all three cases. `default_present`
      // answers "include it by default"; this answers the prior question, "may it be presented at
      // all".
      consent_state: r.consentState,
      // M10B / DOD-END-COUNT-1. The operator holds an endorsement whose worth is CAPPED — a
      // recipient's floor excludes it from `min_count` — and until now nothing told them so. Two
      // endorsements looked identical in this list while one could clear a counterparty's bar and the
      // other could not, which is the kind of invisible difference that reads as the protocol being
      // arbitrary. It is a portal-attested envelope field, so surfacing it discloses nothing the
      // recipient will not already see.
      same_operator: r.sameOperator,
    }));
    return { ok: true, signals: rows };
  });

  handlers.set("wallet_view_signal", async (params, _connectionId) => {
    const prefix = typeof params?.hash_prefix === "string" ? params.hash_prefix : null;
    if (!prefix || prefix.length < 8) {
      return { ok: false, reason: "invalid_prefix", guidance: "hash_prefix must be at least 8 hex characters." };
    }
    const store = new TrustSignalStore(sessionNodeManager.getDb(), logger);
    let row;
    try {
      row = store.getWalletSignalByPrefix(prefix);
    } catch (err: unknown) {
      return { ok: false, reason: "ambiguous_prefix", guidance: err instanceof Error ? err.message : String(err) };
    }
    if (!row) {
      return { ok: false, reason: "signal_not_found", guidance: `No wallet signal with hash prefix '${prefix}'.` };
    }
    let payload: unknown;
    try {
      payload = decodeCbor(row.payload);
    } catch {
      payload = Buffer.from(row.payload).toString("hex");
    }
    return {
      ok: true,
      type: row.type,
      signal_hash: row.signalHash,
      subject_kind: row.subjectKind,
      subject: row.subject,
      issuer_kind: row.issuerKind,
      issuer_pubkey: row.issuerPubkey,
      schema_version: row.schemaVersion,
      status: row.status,
      default_present: row.defaultPresent,
      consent_state: row.consentState,  // review F4 — see wallet_list_signals
      issued_at: row.issuedAt,
      expires_at: row.expiresAt,
      supersedes_hash: row.supersedesHash,
      payload,
    };
  });

  handlers.set("wallet_enable_signal", async (params, _connectionId) => {
    const prefix = typeof params?.hash_prefix === "string" ? params.hash_prefix : null;
    if (!prefix || prefix.length < 8) {
      return { ok: false, reason: "invalid_prefix", guidance: "hash_prefix must be at least 8 hex characters." };
    }
    const store = new TrustSignalStore(sessionNodeManager.getDb(), logger);
    let row;
    try {
      row = store.getWalletSignalByPrefix(prefix);
    } catch (err: unknown) {
      return { ok: false, reason: "ambiguous_prefix", guidance: err instanceof Error ? err.message : String(err) };
    }
    if (!row) {
      return { ok: false, reason: "signal_not_found", guidance: `No wallet signal with hash prefix '${prefix}'.` };
    }
    // M10B / DOD-END-ACCEPT-1 review F4. Enabling a signal the subject has not accepted returned
    // `{ok: true, default_present: true}` — the daemon affirming it will now be presented, when it
    // never will. `default_present` selects from what is ELIGIBLE, and an unconsented signal is not
    // eligible; saying yes here is a hollow success on the one verb that does respond.
    if (row.consentState !== CONSENT_ACCEPTED) {
      return {
        ok: false,
        reason: "consent_pending",
        guidance:
          `This signal is '${row.consentState ?? "unset"}', not accepted, so it cannot be presented ` +
          "regardless of the default-present flag. Accept it first; enabling it changes nothing until then.",
      };
    }
    store.setDefaultPresent(row.signalHash, true);
    return { ok: true, signal_hash: row.signalHash, default_present: true };
  });

  handlers.set("wallet_disable_signal", async (params, _connectionId) => {
    const prefix = typeof params?.hash_prefix === "string" ? params.hash_prefix : null;
    if (!prefix || prefix.length < 8) {
      return { ok: false, reason: "invalid_prefix", guidance: "hash_prefix must be at least 8 hex characters." };
    }
    const store = new TrustSignalStore(sessionNodeManager.getDb(), logger);
    let row;
    try {
      row = store.getWalletSignalByPrefix(prefix);
    } catch (err: unknown) {
      return { ok: false, reason: "ambiguous_prefix", guidance: err instanceof Error ? err.message : String(err) };
    }
    if (!row) {
      return { ok: false, reason: "signal_not_found", guidance: `No wallet signal with hash prefix '${prefix}'.` };
    }
    store.setDefaultPresent(row.signalHash, false);
    return { ok: true, signal_hash: row.signalHash, default_present: false };
  });

  // ── M10B / DOD-END-SURFACE-1 — the consent verbs (D-23, M10B-D5) ───────────────────────────────
  //
  // SCOPED TO THE SELECTED AGENT, not to "the first loaded agent" the way wallet_revoke_signal is.
  // Consent is a decision the SUBJECT makes about an object a third party wrote concerning them, so
  // answering it on the wrong agent's behalf is not a cosmetic error — it is one agent deciding for
  // another. The presenting-agent pubkey is also what the store's queries scope on, and passing the
  // device-local agent_id instead now REFUSES rather than silently returning an empty queue.
  const resolveSelectedAgent = (connectionId: string):
    | { ok: true; name: string; pubkey: string }
    | { ok: false; reason: string; guidance: string } => {
    const name = perConnectionState.get(connectionId)?.currentAgent ?? null;
    if (!name) {
      return {
        ok: false,
        reason: "no_current_agent",
        // NOT "a consent decision belongs to…" — this resolver is shared with the attestation verbs
        // now, and `cello attestations issued` answered a plain "what happened to what I sent?" with
        // an explanation about consent. Guidance that describes a different verb is worse than none:
        // it sends the reader to fix something that was never wrong.
        guidance: "Select an agent first (cello_use_agent) — these act AS a specific agent, and the wrong one would answer on another agent's behalf.",
      };
    }
    const rec = loadedAgents.find((a) => a.name === name);
    if (!rec) {
      return { ok: false, reason: "agent_not_loaded", guidance: `Agent '${name}' is selected but not loaded on this daemon.` };
    }
    return { ok: true, name, pubkey: rec.pubkey };
  };


  /**
   * Compose → seal → send ONE submission on behalf of the selected agent, applying every guard that
   * must hold for any of them.
   *
   * Extracted because `refuse` and `issue` are the same journey with a different `op`, and a second
   * hand-written copy is how two paths that must agree stop agreeing. The guards are the point: an
   * agent that is not started must not be brought online by a side effect, an unbounded body must
   * not reach the transport, and the CAUSE of a refusal must survive to the operator. Duplicating
   * those means the next verb gets whichever subset its author remembered.
   *
   * INV-ATTRIBUTION holds BY CONSTRUCTION, and it did not before: this used to take the resolved
   * `sel` as a parameter, which is exactly a parameter through which a caller could name a different
   * identity. Both call sites happened to pass the right one, so the invariant held by CONVENTION
   * while the comment claimed structure — and the test that "pinned" it asserted the absence of two
   * identifiers that had never existed, so it could not fail. It now takes `connectionId` and
   * resolves the selection itself. There is no identity input left to get wrong.
   */
  async function submitForAgent(opts: {
    connectionId: string;
    op: SubmissionOp;
    subjectKind: SignalSubjectKind;
    subject: string;
    body: string;
    /** Prefixed onto every failure guidance so the operator knows what DID happen. */
    context: string;
  }): Promise<
    | { queued: true; stored: boolean; submissionId: string; storedWarning?: string }
    | { queued: false; reason: string; guidance: string }
  > {
    const { context } = opts;
    const resolved = resolveSelectedAgent(opts.connectionId);
    if (!resolved.ok) return { queued: false, reason: resolved.reason, guidance: `${context} ${resolved.guidance}` };
    const sel = resolved;
    if (opts.body.length > MAX_SUBMISSION_BODY_CHARS) {
      return { queued: false, reason: "message_too_long",
        guidance: `${context} it is ${opts.body.length} characters and the limit is ${MAX_SUBMISSION_BODY_CHARS}.` };
    }
    // `getAgentSignaling` is NOT a getter — for an agent with no manager it CONSTRUCTS one, which
    // dials and authenticates to the directory immediately and installs an unbounded reconnect loop.
    // Calling it on a stopped agent would silently bring it online: the directory would route
    // sessions to it while no standing receiver exists (`standing_receiver_unavailable`), and
    // `cello status` would still report it offline.
    if (!onlineAgents.has(sel.name)) {
      return { queued: false, reason: "agent_offline",
        guidance: `${context} agent '${sel.name}' is not started. Run cello_start_agent and try again — re-sending is safe, the submission id is derived from the content.` };
    }
    const kp = keyProviders.get(sel.name);
    if (!kp) {
      logger.warn("signal.submission.refused", { agentName: sel.name, reason: "key_provider_absent", op: opts.op });
      return { queued: false, reason: "key_provider_absent",
        guidance: `${context} no signing key is loaded for '${sel.name}'.` };
    }
    try {
      const composed = await composeSealedSubmission({
        manifest: verifiedManifest, keyProvider: kp, op: opts.op,
        subjectKind: opts.subjectKind, subject: opts.subject, body: opts.body,
        issuedAt: Math.floor(Date.now() / 1000), logger,
      });
      if (!composed.ok) {
        // ERRORS NAME THEIR CAUSE: manifest_unavailable / manifest_expired / intake_key_absent /
        // intake_key_malformed each say WHICH check refused, and that survives rather than
        // collapsing into a generic send failure that points at the network.
        return { queued: false, reason: composed.reason, guidance: `${context} ${composed.guidance}` };
      }
      const sent = await sendSealedSubmission({
        signaling: getAgentSignaling(sel.name, kp, sel.pubkey).signaling,
        submissionId: composed.submissionId, intakeKeyId: composed.intakeKeyId,
        ciphertext: composed.ciphertext, logger,
      });
      if (!sent.ok) {
        return { queued: false, reason: sent.reason, guidance: `${context} ${sent.guidance ?? sent.reason}` };
      }
      // F4: `sendSealedSubmission` ALREADY logs `signal.submission.queued` / `.duplicate`. Logging
      // `queued` again here doubled every count-based alarm and, worse, emitted `queued` right after
      // `duplicate` — partially erasing the very distinction the directory's queue repository exists
      // to preserve. A distinct name, only for what the send layer does not know (which agent, which
      // op).
      logger.info("signal.submission.attributed", {
        agentName: sel.name, op: opts.op, submissionId: composed.submissionId, stored: sent.stored,
      });
      // KEEP THE HANDLE, or a withdrawal has nothing to name. The submission id is content-derived,
      // so it is reproducible in principle — but only by re-composing the exact original body, which
      // the operator no longer has once they have sent it. Recorded in the SHARED path so every verb
      // added after this one is covered by construction, which is the same reasoning as the
      // `storedWarning` below.
      //
      // Best-effort on purpose: the submission IS accepted at this point, and failing the call over
      // a local bookkeeping write would turn a success into a reported failure and invite a re-send
      // of something already queued. Logged loudly instead.
      try {
        const store = new TrustSignalStore(sessionNodeManager.getDb(), logger);
        store.recordIssuedSubmission({
          agentId: sessionNodeManager.resolveAgentId(sel.name),
          submissionId: composed.submissionId,
          subjectPubkey: opts.subject,
          op: opts.op,
          intakeKeyId: composed.intakeKeyId,
          stored: sent.stored,
        });
      } catch (err: unknown) {
        logger.error("signal.submission.record_failed", {
          agentName: sel.name, submissionId: composed.submissionId,
          reason: err instanceof Error ? err.message : String(err),
        });
      }
      // F1: `stored: false` means a node reports it ALREADY HELD this submission id. That is either
      // a benign retry or single-node censorship — an operator pre-inserting garbage under a
      // clear-text id — and they are indistinguishable from here. Reporting it as unqualified
      // success is what makes the attack silent. The warning lives in the SHARED path, not at one
      // call site, because the refuse verb had it and the issue verb did not: the same omission
      // would otherwise be available to every verb added after this one.
      return {
        queued: true, stored: sent.stored, submissionId: composed.submissionId,
        ...(sent.stored ? {} : {
          storedWarning: "A directory node accepted it but reports it already held this submission id. If nothing arrives for the recipient, send it again — re-sending is safe, the submission id is derived from the content.",
        }),
      };
    } catch (err: unknown) {
      const reason = err instanceof Error ? err.message : String(err);
      logger.warn("signal.submission.refused", { agentName: sel.name, op: opts.op, reason });
      return { queued: false, reason, guidance: `${context} ${reason}` };
    }
  }

  /**
   * M10B / DOD-END-SURFACE-1 — issue a trust signal ABOUT a counterparty.
   *
   * NOTE WHAT IS NOT HERE: a `type` parameter, and the word "endorsement" anywhere in the path. The
   * submission wire carries no type field — the PORTAL decides what it mints from a submission — so
   * a second client-sourced type needs no new verb, no new parameter and no client change. That is
   * INV-ZEROBUMP holding by construction rather than by discipline, and it is what
   * `DOD-END-PLAYBOOK-1` has to prove with an empty diff.
   *
   * The subject is the counterparty's K_local pubkey: the only identifier a contact actually holds.
   * No account identifier crosses the wire — the portal resolves agent → account at intake, and the
   * directory is hash-only by design.
   */
  // M10B / DOD-END-SURFACE-1 — "see what I have submitted about others". The wallet list answers
  // "what do people say about ME"; this answers the other direction, and it is the prerequisite for
  // withdrawal: you cannot withdraw a submission you cannot name.
  // M10B / `M10B-D25r2` — collect this agent's outcomes from the directory and open any sealed
  // message with k_local. Separate from `wallet_list_issued` because it is a NETWORK call: listing
  // what you submitted must keep working when the directory is unreachable, and folding a fetch into
  // it would make a local read fail for a remote reason.
  handlers.set("wallet_fetch_results", async (_params, connectionId) => {
    const sel = resolveSelectedAgent(connectionId);
    if (!sel.ok) return sel;
    const kp = keyProviders.get(sel.name);
    if (!kp) {
      return { ok: false, reason: "agent_not_loaded",
        guidance: `Agent '${sel.name}' has no key loaded, so a sealed result could not be opened. Restart the daemon and select the agent again.` };
    }
    // ── ASK EVERY NODE, AND SAY WHICH ONES DID NOT ANSWER ─────────────────────────────────────────
    // An outcome is recorded on whichever node accepted the submission, and this agent is connected
    // to ONE node — routinely not the same one. Asking only home turns "your refusal is on another
    // node" into "you have no results", which is the answer that makes a counterparty look silent
    // when they were not.
    //
    // A NODE THAT DOES NOT ANSWER IS `unreachable`, NEVER an empty result. If a timeout collapsed
    // into "nothing here", a down node could silently produce a negative answer — the same lie in a
    // new place. The caller is told what was actually covered.
    const seen = new Map<string, ReturnType<typeof mapResult>>();
    const unreachable: string[] = [];
    function mapResult(r: { submissionId: string; outcome: string; reason: string | null; signalHash: string | null; message: string | null; createdAt: string }) {
      return {
        submission_id: r.submissionId,
        outcome: r.outcome,
        reason: r.reason,
        signal_hash: r.signalHash,
        message: r.message,
        created_at: r.createdAt,
      };
    }
    const opener = kp as { openContentSeal?: (c: Uint8Array) => Promise<Uint8Array | null> };

    // Home node first — it needs no connection and answers fastest.
    const home = await fetchSubmissionResults({
      signaling: getAgentSignaling(sel.name, kp, sel.pubkey).signaling,
      keyProvider: opener,
      logger,
    });
    if (home.ok) for (const r of home.results) seen.set(r.submissionId, mapResult(r));
    else unreachable.push("home");

    // Then every OTHER node in the consortium, over a transient visiting connection — the same
    // mechanism a cross-node session uses. Each is independent: one node refusing to answer must not
    // stop the others being asked.
    const roster = (await resolveConsortiumRoster().catch(() => null)) ?? [];
    for (const node of roster) {
      let visit: ReturnType<typeof openVisitingConnection> | null = null;
      try {
        visit = openVisitingConnection(
          sel.name, kp, sel.pubkey,
          { peerId: node.peerId, multiaddr: node.multiaddr },
          randomUUID(), node.nodeId,
        );
        // WAIT FOR THE CONNECTION BEFORE USING IT. openVisitingConnection returns SYNCHRONOUSLY and the
        // manager dials in the background, so asking it for results on the next line finds it still
        // connecting and gets `signaling_reconnecting` — every node, instantly. Observed live once the
        // environment was awake: three regions "unreachable" within 3ms of each other, which no real
        // network failure looks like. The seal-broker path above already does this; this one did not.
        if (!(await waitForSignalingConnected(visit.mgr, 10_000))) {
          logger.warn("signal.results.node.unreachable", { nodeId: node.nodeId, reason: "visiting_connect_timeout" });
          unreachable.push(node.nodeId);
          continue;
        }
        const r = await fetchSubmissionResults({ signaling: visit.mgr, keyProvider: opener, logger });
        if (r.ok) for (const x of r.results) { if (!seen.has(x.submissionId)) seen.set(x.submissionId, mapResult(x)); }
        else {
          // SAY WHY. `unreachable` is a list of node ids and nothing else, so a sweep that fails
          // everywhere reports "all three unreachable" with the cause discarded at the exact point it
          // was known — leaving the only evidence to be guessed at afterwards.
          logger.warn("signal.results.node.unreachable", { nodeId: node.nodeId, reason: r.reason });
          unreachable.push(node.nodeId);
        }
      } catch (err: unknown) {
        logger.warn("signal.results.node.unreachable", {
          nodeId: node.nodeId,
          reason: err instanceof Error ? err.message : String(err),
        });
        unreachable.push(node.nodeId);
      } finally {
        // ALWAYS torn down. A visiting connection left open holds a stream the directory will drain
        // its durable notification queue down — the bug this connection type has already caused once.
        await visit?.stop("results fetch complete").catch(() => {});
      }
    }

    if (seen.size === 0 && unreachable.length > 0 && unreachable.length >= roster.length) {
      // EVERY node we tried failed. Reporting an empty list here would be the exact lie this fan-out
      // exists to prevent.
      //
      // AN EMPTY ROSTER IS ITS OWN ANSWER. `resolveConsortiumRoster()` returns null when there is no
      // current manifest, and `?? []` turns "I do not know of any other nodes" into "there are no
      // other nodes" — so a daemon that cannot resolve the consortium at all reported "No directory
      // node answered (home)", which reads as one bad node rather than as no map. Chasing that cost
      // real time against a hibernated environment on 2026-07-31.
      const noRoster = roster.length === 0;
      return {
        ok: false,
        reason: noRoster ? "consortium_unresolved" : "results_unreachable",
        guidance: noRoster
          ? `This daemon cannot resolve any directory node right now, so there was nowhere to ask (${unreachable.join(", ")} also failed). Check that the directory is reachable — 'directory.consortium.node.unresolved' in the daemon log names each endpoint and why. Your outcomes are held until you collect them; nothing is lost.`
          : `No directory node answered (${unreachable.join(", ")}). Your outcomes are held until you collect them — nothing is lost. Retry when connectivity returns.`,
      };
    }
    return {
      ok: true,
      // WHAT WAS ACTUALLY COVERED. An empty list from a partial sweep means "nothing on the nodes we
      // reached", which is a different claim from "nothing exists".
      ...(unreachable.length > 0 ? { unreachable_nodes: unreachable } : {}),
      results: [...seen.values()],
    };
  });


  handlers.set("wallet_list_issued", async (_params, connectionId) => {
    const sel = resolveSelectedAgent(connectionId);
    if (!sel.ok) return sel;
    const store = new TrustSignalStore(sessionNodeManager.getDb(), logger);
    const rows = store.listIssuedSubmissions(sessionNodeManager.resolveAgentId(sel.name)).map((r) => ({
      submission_id: r.submissionId,
      subject_pubkey: r.subjectPubkey,
      op: r.op,
      intake_key_id: r.intakeKeyId,
      // FALSE means a node already held this id — a benign retry, or single-node censorship. The
      // operator sees the distinction here rather than only in the moment they submitted.
      stored: r.stored,
      submitted_at: r.submittedAt,
    }));
    return {
      ok: true,
      issued: rows,
      // NO BODY, and say so rather than letting its absence read as a bug. The text was the
      // operator's own words about a third party; keeping it on disk in the clear is exactly what
      // the sealed-submission path exists to prevent.
      note: "The text you wrote is NOT stored locally — only the handle, subject and verb. That is deliberate: your words about someone else are sealed to the portal and are not kept in the clear on this machine.",
    };
  });

  handlers.set("cello_attestations_issue", async (params, connectionId) => {
    const sel = resolveSelectedAgent(connectionId);
    if (!sel.ok) return sel;
    const subject = typeof params?.subject_pubkey === "string" ? params.subject_pubkey.toLowerCase() : "";
    if (!/^[0-9a-f]{64}$/.test(subject)) {
      return { ok: false, reason: "invalid_subject",
        guidance: "subject_pubkey must be the counterparty's 32-byte public key as 64 hex characters — run cello_contacts to see the peers you know." };
    }
    const body = typeof params?.body === "string" ? params.body.trim() : "";
    if (body.length === 0) {
      return { ok: false, reason: "empty_body",
        guidance: "An issued signal needs text — it is the claim you are making about them, in your own words." };
    }
    // SELF-ISSUANCE IS REFUSED AT THE SOURCE, and across EVERY agent on this daemon — not just the
    // selected one. The check used to compare against `sel.pubkey` alone, which let an operator
    // running two of their own agents issue from one about the other and sail through a guard whose
    // comment claimed certainty. That configuration is not exotic: solo multi-agent is CELLO's first
    // wedge, so it is the most likely way to hit this, not the least.
    //
    // The portal remains the real enforcer of INV-NO-SELF-STANDING — only it can see account
    // linkage, and only it can catch two agents under one account on different machines. But the
    // daemon knows its OWN agents with certainty, and refusing here gives the operator a real answer
    // now instead of a silent rejection at intake minutes later.
    const localSelf = loadedAgents.find((a) => a.pubkey.toLowerCase() === subject);
    if (localSelf) {
      return { ok: false, reason: "self_subject",
        guidance: localSelf.name === sel.name
          ? "An agent cannot issue a trust signal about itself — standing has to come from somebody else."
          : `'${sel.name}' and '${localSelf.name}' are both your agents on this machine, so a signal from one about the other would be you vouching for yourself. Standing has to come from somebody else.` };
    }
    const res = await submitForAgent({
      connectionId,
      op: "submit", subjectKind: "agent", subject, body,
      context: "The signal was NOT submitted:",
    });
    if (!res.queued) return { ok: false, reason: res.reason, guidance: res.guidance };
    return {
      ok: true, queued: true, stored: res.stored, submission_id: res.submissionId,
      // Deliberately NOT "issued". Nothing is minted yet: the portal must still drain, authenticate,
      // scan and mint, and the subject must then ACCEPT it before anyone else can see it. Reporting
      // this as a completed endorsement would promise three steps that have not happened.
      guidance: res.storedWarning
        ? `Submitted for '${sel.name}'. ${res.storedWarning}`
        : `Submitted for '${sel.name}'. The portal will scan and mint it, then the subject must ACCEPT it before it is visible to anyone — a signal they have not accepted is inert. Nothing here is final until they decide.`,
    };
  });

  /**
   * M10B / DOD-END-SURFACE-1 — per-counterparty presentation choice.
   *
   * `present: null` CLEARS the choice rather than setting it false. Those are different states and
   * the surface must keep them apart: cleared means "no opinion, use the signal's default", false
   * means "specifically not this person". An operator who could only toggle true/false would be
   * unable to undo an omission without first knowing what the default had been.
   */
  handlers.set("cello_contact_set_signal", async (params, connectionId) => {
    const sel = resolveSelectedAgent(connectionId);
    if (!sel.ok) return sel;
    const pubkey = typeof params?.pubkey === "string" ? params.pubkey.toLowerCase() : "";
    if (!/^[0-9a-f]{64}$/.test(pubkey)) {
      return { ok: false, reason: "invalid_pubkey", guidance: "pubkey must be the counterparty's 32-byte public key as 64 hex characters." };
    }
    const prefix = typeof params?.hash_prefix === "string" ? params.hash_prefix : "";
    if (prefix.length < 8) {
      return { ok: false, reason: "invalid_prefix", guidance: "hash_prefix must be at least 8 hex characters — see cello_trust_signals_list." };
    }
    const present = params?.present === null ? null : typeof params?.present === "boolean" ? params.present : undefined;
    if (present === undefined) {
      return { ok: false, reason: "invalid_present", guidance: "present must be true (show it to them), false (never show it to them), or null (clear the choice and fall back to the signal's default)." };
    }
    // Resolve the prefix against signals this agent actually holds, so a typo cannot silently write
    // a preference about a hash that does not exist and sit there doing nothing forever.
    const store = new TrustSignalStore(sessionNodeManager.getDb(), logger);
    const match = store.listAllWalletSignals().filter((r) => r.signalHash.startsWith(prefix));
    if (match.length === 0) {
      return { ok: false, reason: "signal_not_found", guidance: `No signal in this wallet starts with '${prefix}'.` };
    }
    if (match.length > 1) {
      return { ok: false, reason: "ambiguous_prefix", guidance: `'${prefix}' matches ${match.length} signals — use more characters.` };
    }
    sessionNodeManager.setContactSignalPref(sel.name, pubkey, match[0].signalHash, present);
    return {
      ok: true, signal_hash: match[0].signalHash, pubkey, present,
      guidance: present === null
        ? "Choice cleared — this signal now follows its own default for this contact."
        : present
          ? "This signal will be presented to this contact when a session forms, if you have accepted it."
          : "This signal will NOT be presented to this contact, whatever its default.",
    };
  });

  handlers.set("cello_attestation_consent_list", async (_params, connectionId) => {
    const sel = resolveSelectedAgent(connectionId);
    if (!sel.ok) return sel;
    const store = new TrustSignalStore(sessionNodeManager.getDb(), logger);
    const items = store.listPendingConsent(sel.pubkey).map((r) => {
      // THE PAYLOAD IS THE POINT OF THIS CALL. The operator is being asked to stand behind a claim
      // somebody else wrote about them, and they cannot make that decision from a byte count. An
      // earlier version returned `payload_bytes` while both surfaces instructed the operator to
      // "read the plaintext before accepting" — so following the instruction produced a number, and
      // accepting was necessarily blind. Decoded here, exactly as `wallet_view_signal` does it.
      //
      // Undecodable payloads fall back to hex rather than throwing: one unreadable item must not
      // make every other pending decision unreachable, and hex is honest about what it is.
      let payload: unknown;
      try {
        payload = decodeCbor(r.payload);
      } catch {
        payload = Buffer.from(r.payload).toString("hex");
      }
      return {
        signal_hash: r.signalHash,
        type: r.type,
        subject_kind: r.subjectKind,
        issuer_kind: r.issuerKind,
        issuer_pubkey: r.issuerPubkey,
        issued_at: r.issuedAt,
        // UNTRUSTED, and labelled as such on the way out. These are the issuer's own words, carried
        // verbatim and never restated in any other voice (INV-UNTRUSTED). A consuming model must
        // quote and attribute them — "<issuer> says: …" — never adopt them as its own statement.
        payload,
        payload_is_untrusted_text: true,
      };
    });
    // Seeing the list IS being told. Marking here rather than in cello_use_agent means the operator
    // is never marked notified about something they were not actually shown.
    store.markConsentNotified(sel.pubkey);
    return { ok: true, agent: sel.name, pending: items };
  });

  handlers.set("cello_attestation_consent_accept", async (params, connectionId) => {
    const sel = resolveSelectedAgent(connectionId);
    if (!sel.ok) return sel;
    const prefix = typeof params?.hash_prefix === "string" ? params.hash_prefix : null;
    if (!prefix || prefix.length < 8) {
      return { ok: false, reason: "invalid_prefix", guidance: "hash_prefix must be at least 8 hex characters." };
    }
    const store = new TrustSignalStore(sessionNodeManager.getDb(), logger);
    const item = store.listPendingConsent(sel.pubkey).find((r) => r.signalHash.startsWith(prefix));
    if (!item) {
      // Deliberately does NOT fall back to a wallet-wide lookup: a hash this agent has no pending
      // decision on is not this agent's to accept, and finding it anyway would be the cross-agent
      // decision this scoping exists to prevent.
      return { ok: false, reason: "not_pending_for_agent", guidance: `No pending consent item for '${sel.name}' with prefix '${prefix}'.` };
    }
    // The write RESULT is checked, not assumed. `setConsentState` returns false when zero rows
    // changed; reporting "accepted" regardless would tell the operator a decision was recorded that
    // was not, and the next presentation would silently omit it.
    if (!store.setConsentState(item.signalHash, "accepted")) {
      return { ok: false, reason: "consent_write_failed",
        guidance: `The acceptance was NOT recorded — the signal row changed underneath this call. Run cello_attestation_consent_list and retry.` };
    }
    return { ok: true, signal_hash: item.signalHash, consent_state: "accepted" };
  });

  handlers.set("cello_attestation_consent_refuse", async (params, connectionId) => {
    const sel = resolveSelectedAgent(connectionId);
    if (!sel.ok) return sel;
    const prefix = typeof params?.hash_prefix === "string" ? params.hash_prefix : null;
    if (!prefix || prefix.length < 8) {
      return { ok: false, reason: "invalid_prefix", guidance: "hash_prefix must be at least 8 hex characters." };
    }
    const store = new TrustSignalStore(sessionNodeManager.getDb(), logger);
    const item = store.listPendingConsent(sel.pubkey).find((r) => r.signalHash.startsWith(prefix));
    if (!item) {
      return { ok: false, reason: "not_pending_for_agent", guidance: `No pending consent item for '${sel.name}' with prefix '${prefix}'.` };
    }
    // ORDER IS LOAD-BEARING: the refusal is recorded FIRST and is never conditional on the message
    // getting out. A refusal that only takes effect if the network cooperates would leave a signal
    // Alice believes she rejected sitting in an unrefused state — the exact failure INV-CONSENT
    // exists to prevent. The message is a courtesy layered on top of a decision already made.
    //
    // And the write is CHECKED. The ordering above is worth nothing if nothing confirms the record
    // happened: without this, the code would go on to sign and send Bob a refusal message about a
    // decision that is not in the database.
    if (!store.setConsentState(item.signalHash, "refused")) {
      return { ok: false, reason: "consent_write_failed",
        guidance: `The refusal was NOT recorded — the signal row changed underneath this call. Run cello_attestation_consent_list and retry.` };
    }
    const refused = { ok: true as const, signal_hash: item.signalHash, consent_state: "refused" as const };

    // M10B-D4: the message back to the issuer is the subject's CHOICE. Silence is the default, and a
    // silent refusal tells Bob NOTHING — which is what keeps D-24 intact for anyone who wants it.
    const message = typeof params?.message === "string" ? params.message.trim() : "";
    if (message.length === 0) return { ...refused, message_queued: false };

    // ACCOUNT-SUBJECT ITEMS DO NOT GET A MESSAGE YET, and this is a refusal, not an oversight.
    //
    // `listPendingConsent` scopes with `(subject_kind <> 'agent' OR lower(subject) = ?)`, so EVERY
    // agent on this daemon can see — and therefore refuse — an account-subject item. The refusal
    // itself is defensible (it is the account's own decision, and any of its agents speaks for it),
    // but the MESSAGE is signed with THIS agent's K_local, so the issuer would receive a signed
    // statement from an agent that was not the subject of anything. Which agent may speak for an
    // account is an open question this milestone has not answered, and signing is not the place to
    // guess at it. So the decision stands and the courtesy is withheld, with the reason named.
    if (item.subjectKind !== "agent") {
      return { ...refused, message_queued: false, message_error: "account_subject_message_unsupported",
        guidance: `The refusal is recorded. Your message was NOT sent: this signal is about the ACCOUNT rather than about '${sel.name}', and a message would be signed by this agent alone — which agent may speak for an account is not yet settled.` };
    }

    // Rides the submission queue as the `refuse` op. The SUBJECT is the target signal hash (as it is
    // for a withdrawal — both verbs act on an existing signal), and `subject_kind` is carried from
    // the row rather than hardcoded: it is inside the TBS, so a hardcoded value would be a SIGNED
    // field asserting something false.
    const res = await submitForAgent({
      connectionId,
      op: "refuse", subjectKind: item.subjectKind, subject: item.signalHash, body: message,
      context: "The refusal is recorded. Your message was NOT sent:",
    });
    if (!res.queued) {
      return { ...refused, message_queued: false, message_error: res.reason, guidance: res.guidance };
    }
    // `message_queued`, NOT `issuer_notified`. A directory node acked a sealed blob; the portal has
    // not drained it, scanned it, minted it, or delivered anything to the issuer.
    //
    // `stored` is carried through rather than collapsed into plain success: it is the ONE signal
    // separating a benign duplicate from single-node censorship (an operator pre-inserting garbage
    // under a clear-text submission_id), and folding them together destroys the only information
    // that could ever tell them apart.
    return {
      ...refused, message_queued: true, stored: res.stored, submission_id: res.submissionId,
      ...(res.storedWarning ? { guidance: `The refusal is recorded. ${res.storedWarning}` } : {}),
    };
  });

  handlers.set("wallet_revoke_signal", async (params, _connectionId) => {
    const hashPrefix = typeof params?.hash_prefix === "string" ? params.hash_prefix : null;
    if (!hashPrefix || hashPrefix.length < 8) {
      return { ok: false, reason: "invalid_prefix", guidance: "hash_prefix must be at least 8 hex characters." };
    }
    const store = new TrustSignalStore(sessionNodeManager.getDb(), logger);
    let row;
    try {
      row = store.getWalletSignalByPrefix(hashPrefix);
    } catch (err: unknown) {
      return { ok: false, reason: "ambiguous_prefix", guidance: err instanceof Error ? err.message : String(err) };
    }
    if (!row) {
      return { ok: false, reason: "signal_not_found", guidance: `No wallet signal with hash prefix '${hashPrefix}'.` };
    }
    const signalHash = row.signalHash;

    // Find the first loaded agent to sign the revoke request.
    const firstAgent = loadedAgents[0];
    if (!firstAgent) {
      return { ok: false, reason: "no_agent", guidance: "No agent loaded. Run 'cello login' first." };
    }
    const kp = keyProviders.get(firstAgent.name);
    if (!kp) {
      return { ok: false, reason: "no_agent_key", guidance: "Agent key not available." };
    }

    // Build and sign the CBOR revoke request.
    const nowSec = Math.floor(Date.now() / 1000);
    const bodyBytes = encodeCbor({ v: 1, op: "revoke", signal_hash: signalHash, issued_at: nowSec });
    const sigBytes = await kp.sign(bodyBytes);
    const pubkeyHex = firstAgent.pubkey;
    const sigHex = Buffer.from(sigBytes).toString("hex");
    const bodyHex = Buffer.from(bodyBytes).toString("hex");

    // POST to all directory nodes (best-effort — all reachable nodes get the tombstone).
    const directoryUrl = resolveDirectoryUrl(process.env);
    const directoryUrls = [directoryUrl];
    const results: Array<{ url: string; ok: boolean; detail?: string }> = [];
    for (const url of directoryUrls) {
      try {
        const resp = await fetch(`${url}/internal/signal/revoke`, {
          method: "POST",
          headers: {
            "Content-Type": "application/cbor",
            "x-cello-signer-pubkey": pubkeyHex,
            "x-cello-signature": sigHex,
            "x-body-hex": bodyHex,
          },
          body: bodyBytes,
        });
        const json = await resp.json() as { ok?: boolean; error?: string; detail?: string };
        results.push({ url, ok: !!json.ok, detail: json.error ?? json.detail });
        if (!resp.ok && !json.ok) {
          logger.warn("signal.wallet.revoke.directory_rejected", { url, signalHash, detail: json.error ?? json.detail });
        }
      } catch (err: unknown) {
        const detail = err instanceof Error ? err.message : String(err);
        results.push({ url, ok: false, detail });
        logger.warn("signal.wallet.revoke.directory_unreachable", { url, signalHash, detail });
      }
    }

    // Always hard-delete locally regardless of directory result.
    const removed = store.removeWalletSignal(signalHash);
    logger.info("signal.wallet.revoked", { signalHash, directoryResults: results.map((r) => ({ url: r.url, ok: r.ok })) });
    return { ok: true, signal_hash: signalHash, removed_locally: removed, directory_results: results };
  });

  // ─── MCP-001: cello_status (per-connection perspective) ───
  /**
   * The directory-reachability block for `cello_status`, or undefined when every node resolves.
   *
   * Reports the LAST resolve sweep. An empty list is not proof of health — it also means no sweep
   * has run yet — so the shape says which nodes failed and why rather than asserting "all good".
   */
  function unresolvedNodesForStatus(): { directory_endpoints_unresolved: unknown } | undefined {
    const failures = getUnresolvedNodes();
    if (failures.length === 0) return undefined;
    return {
      directory_endpoints_unresolved: {
        nodes: failures.map((f) => ({ node: f.nodeId, endpoint: f.endpoint, reason: f.reason, detail: f.detail })),
        guidance:
          "This daemon cannot resolve these directory endpoints, so the consortium roster is short and " +
          "threshold ceremonies will fail — sessions surface that as counterparty_offline, " +
          "directory_below_threshold, or ceremony_exhausted, none of which name the real cause. " +
          "Agents can still show 'online': signaling dials multiaddrs and does not need DNS. " +
          "If reason is dns_error after a directory restart or wake, the resolver is holding a cached " +
          "negative answer — flush it (macOS: sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder). " +
          "Verify with node -e 'require(\"dns\").lookup(host,console.log)', NOT dig: dig bypasses the " +
          "cache this daemon is stuck behind, so it reports success while the daemon still fails.",
      },
    };
  }

  handlers.set("cello_status", async (_params, connectionId) => {
    return {
      daemon: "running",
      directory_signaling: directorySignalingStatus(),
      // CAN I ACTUALLY REACH THE DIRECTORY — not just "is my socket up?".
      //
      // These are different facts and they diverged for an hour on 2026-07-31. libp2p signaling
      // dials multiaddrs from the bundled manifest, so it stayed connected and every agent reported
      // online, while a cached NXDOMAIN meant nothing that needed the HTTP endpoint resolved. The
      // roster came back empty, so every threshold ceremony failed — surfacing to the operator as
      // counterparty_offline, then directory_below_threshold, then ceremony_exhausted. Three errors,
      // none of them naming DNS, while the reason sat in the log 26 times per node.
      //
      // Omitted entirely when nothing is failing, so a healthy status stays quiet.
      ...(unresolvedNodesForStatus() ?? {}),
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

  // cello_initiate_session (initiate-session-handler.ts). The relay witness is BEST-EFFORT: a
  // session with no relay still runs on the direct content path. Degraded, never blocked.
  registerInitiateSessionHandler({
    handlers,
    logger,
    sessionNodeManager,
    getConnState: (connectionId) => perConnectionState.get(connectionId),
    resolveCurrentAgent,
    NO_CURRENT_AGENT_RESPONSE,
    resolvedSessionNegotiator,
    transportSelector,
    autoNatService,
    buildRelayConnectParams,
    getRelayCircuitAddress,
  });

  // cello_close_session (close-session-handler.ts). Fifteen dependencies — a long list, but a KNOWN
  // one, which is the whole difference from a closure over 73 shared locals.
  registerCloseSessionHandler({
    handlers,
    logger,
    sessionNodeManager,
    getConnState: (connectionId) => perConnectionState.get(connectionId),
    resolveCurrentAgent,
    NO_CURRENT_AGENT_RESPONSE,
    getKeyProvider: (agentName: string) => keyProviders.get(agentName),
    signalingFor,
    sendOver,
    waitForSignalingConnected,
    openVisitingConnection,
    crossNodeBrokerBySession,
    sealKey,
    sealInterruptedInProgress,
    pendingSealWaiters,
    pendingUnilateralWaiters,
    handleSealInterruptedFlow,
    handleActiveSealFlow,
    resolveConsortiumRoster,
  });

  // ─── MCP-001: stubs for tools registered in cello-mcp.ts but not yet implemented ───
  // These return not_implemented (same as session tools) so LLMs get consistent guidance.
  for (const tool of ["cello_backup", "cello_restore", "cello_get_inclusion_proof"]) {
    handlers.set(tool, async (_params, _connectionId) => {
      return { ok: false, reason: "not_implemented", guidance: `'${tool}' is not yet implemented in the daemon. This feature will be available in a future milestone.` };
    });
  }

  // DOD-M9B-SURFACE-1: the security layer's control surface. Registered here, defined in its own
  // module — it needs the cello dir, a logger, and the connection's client type, and nothing else
  // about sessions or ceremonies.
  const disposeGatewayConfigStores = registerGatewayConfigHandlers({
    handlers,
    celloDir,
    logger,
    getClientType: (connectionId) => perConnectionState.get(connectionId)?.clientType,
    ...(config.restartSecurityGateway ? { restartSecurityGateway: config.restartSecurityGateway } : {}),
  });

  // The session READ surface (session-read-handlers.ts): sealed receipt, transcript, list, name.
  // All four read the PERSISTED store, so they survive a restart and a fresh connection.
  registerSessionReadHandlers({
    handlers,
    logger,
    sessionNodeManager,
    loadedAgents,
    getConnState: (connectionId) => perConnectionState.get(connectionId),
    resolveCurrentAgent,
    NO_CURRENT_AGENT_RESPONSE,
    resolveWho,
    safeCursorAdvance,
    safeWatermarkAdvance,
    reapDeadHalfOpenSessions,
    frontierMismatches,
  });
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

  contentPark.registerHandlers(handlers);
  registerInboundSessionHandlers(handlers);

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

  // TTL-terminal-reap: seed a session row at a given terminal status so tests can assert that
  // reapExpiredInboundSessions drops the matching inbound queue entry without waiting 24h.
  handlers.set("__test_insert_session_row", async (params, _connectionId) => {
    const agentName = params?.agentName as string | undefined;
    const sessionId = params?.sessionId as string | undefined;
    const status = params?.status as string | undefined;
    const counterpartyPubkey = (params?.counterpartyPubkey as string) ?? "testpubkey";
    if (!agentName || !sessionId || !status) {
      return { error: "missing_params", guidance: "Provide agentName, sessionId, status." };
    }
    const db = sessionNodeManager.getDb();
    const now = Date.now();
    const agentRow = db.prepare("SELECT agent_id FROM agents WHERE agent_name = ?").get(agentName) as { agent_id: string } | undefined;
    if (!agentRow) return { error: "agent_not_found" };
    db.prepare(
      "INSERT OR REPLACE INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)"
    ).run(sessionId, agentRow.agent_id, counterpartyPubkey, status, now, now);
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


  // CELLO-M7-CONN-001 (DOD-CONN-2): the inbound seal_interrupted_request responder is now
  // wired PER-AGENT (wirePerAgentSessionInbound, below) onto each agent's own signaling
  // manager — not once on the keystone — so every agent (not just the primary) receives it
  // on its own authenticated stream.




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
    attendanceCount,
    contentTakes,
  });

  // cello_check_notifications (notification-handlers.ts): the push-loss reconciler. Notifications are
  // fire-and-forget, so a client that was away can miss one entirely — this is how it finds out, by
  // ASKING from persisted state rather than trusting that a push arrived.
  registerNotificationHandlers({
    handlers,
    logger,
    sessionNodeManager,
    getConnState: (connectionId) => perConnectionState.get(connectionId),
    resolveCurrentAgent,
    loadedAgents,
    agents,
    reapExpiredInboundSessions,
    inboundSessionQueues,
    expiredSessionRequests,
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
    agents,
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
    // DOD-COATTEND-VISIBLE-1 (review HIGH): the take ledger is connection-scoped for the SAME
    // reason and must die with the connection too. Leaving it behind made every reconnect look
    // like a theft: a fresh connection starts at cursor -1, so every take a now-dead connection
    // ever recorded sits above that bar and was reported as "another session took it" — on the
    // `cello` CLI, which opens a fresh connection per command, that fired on ordinary use, forever,
    // with no live sibling anywhere. A signal that fires on the normal case is not a signal, and
    // this one would have taught the operator to disbelieve the real theft it exists to announce.
    contentTakes.forget(connectionId);
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
    stopRegistryPoll?.();
    if (config.registryPollScheduler) {
      config.registryPollScheduler.cancel();
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
      // DOD-M9B-WIRE-1: tear down whatever the composition root started alongside us — today the
      // screening sidecar. Two reasons it is HERE and not only in the bin's signal handler:
      // `cello logout` stops the daemon through the IPC `shutdown` verb, which reaches this
      // function and never touches the signal path; and a spawned child's stdio pipes keep this
      // process's event loop alive, so a daemon stopped that way would never actually exit.
      //
      // FIRST in the finally, BEFORE the singleton lock is released (review F4). The comment below
      // states the property the lock provides — "while we hold it, no successor daemon can start"
      // — and the sidecar teardown needs exactly that property: the `shutdown` verb acknowledges
      // immediately without awaiting this drain, so `cello logout && cello login` can race a new
      // daemon into existence. Releasing the lock first would let its gateway spawn while ours
      // still holds gateway.db's write lock, which the 3s busy_timeout usually hides — making the
      // failure intermittent rather than absent.
      if (config.onShutdown) {
        await config.onShutdown().catch((err: unknown) => {
          logger.error("daemon.shutdown.hook_failed", {
            error: err instanceof Error ? err.message : String(err),
          });
        });
      }
      // AFTER onShutdown, never before (review F9). onShutdown is `stopSecurityLayer`, which awaits
      // the sidecar's exit — so by here we ARE the last holder, and the last closer is the one that
      // may safely checkpoint and unlink (measured, review M1). Reversed, these handles would close
      // while the sidecar is still writing, which is the F1/F2 defect exactly.
      disposeGatewayConfigStores();
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

  function getTypeRegistry(): TypeRegistry {
    return typeRegistry;
  }

  // M8C-TGDOOR-1: cold-capable — start the poller if a token was already configured from a
  // prior run, without waiting for any agent to come online or any client to attach.
  startTelegramPollerIfConfigured();

  return { stop, getStatus, getSessionNodeManager, getTransportSelector, getAutoNatService, getTypeRegistry };
}
