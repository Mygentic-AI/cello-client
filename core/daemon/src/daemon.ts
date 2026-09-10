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
import type {
  DaemonConfig,
} from "./types.js";
import { RestartSealResolver } from "./restart-seal-resolver.js";
import { removeLockIfOwned } from "./lock-file.js";
import { acquireSingletonLock, type SingletonLock } from "./singleton-lock.js";
import { type IpcHandler } from "./ipc-server.js";
import { SealFailureStore } from "./seal-failure-store.js";
import { SessionNodeManager } from "./session-node-manager.js";
import { registerGatewayConfigHandlers } from "./gateway-config-handlers.js";
import { NonceDedupStore } from "./nonce-dedup.js";
import { NotificationDispatcher } from "./notification-dispatcher.js";
import { DbIdentityStore } from "./db-identity-store.js";

// CELLO-M7-MSG-001 (AC-013/AC-018): the single application content-size cap, enforced
// at the send point here (the receive point lives in the transport content decode).
import type { ITransportSelector } from "./transport-selector.js";
import { LocalAutoNatStub, type IAutoNatService } from "@cello-protocol/transport";
import { resolveDirectoryUrl } from "./directory-bootstrap.js";
import { registerContactHandlers } from "./contact-handlers.js";
import { registerSignalHandlers } from "./signal-handlers.js";
import { registerTestHandlers } from "./test-handlers.js";
import { registerAgentAdminHandlers } from "./agent-admin-handlers.js";
import { registerStatusHandler } from "./status-handler.js";
import { registerBackupRestoreHandlers } from "./backup-restore-handlers.js";
import { createDocumentWiring } from "./document-wiring.js";
import { createSignalingWiring } from "./signaling-wiring.js";
import { createAttendanceWiring } from "./attendance-wiring.js";
import { startBootCore } from "./boot-core.js";
import { startBootAgents } from "./boot-agents.js";
import { startBootConnectionState } from "./boot-connection-state.js";
import { startBootParkedContent } from "./boot-parked-content.js";
import { startBootSweeps } from "./boot-sweeps.js";
import { createSessionViews } from "./session-views.js";
import { createAgentSelection } from "./agent-selection-root.js";
import { createStartAgent } from "./start-agent.js";
import { createSessionNotify } from "./session-notify.js";
import { createConnectionAgents } from "./connection-agents.js";
import { createDirectoryConnect } from "./directory-connect.js";
import { createUnresolvedNodesReport } from "./unresolved-nodes-report.js";
import { createDocumentSurface } from "./document-surface.js";
import { createIpcSurface } from "./ipc-surface.js";
import { createDaemonStatusReport } from "./daemon-status-report.js";
import { createWhoResolver } from "./who-resolver.js";
import { NO_CURRENT_AGENT_RESPONSE, registrationGuidance } from "./operator-guidance.js";
import { wireDisconnectCleanup } from "./disconnect-cleanup.js";
import { createSealCoordinator } from "./seal-coordinator.js";
import { createTelegramDoorbell } from "./telegram-doorbell.js";
import { registerSessionContentHandlers } from "./session-content-handlers.js";
// `wireContentHash` is no longer imported here: every outbound hash in this file now comes from
// `SessionNodeManager.contentHashForSession`, which returns the hash and its ALGORITHM together
// (`DOD-M15-SEALWIRE-1` part B2b). A direct call would be a hash computed without deciding — or
// recording — how it was made, which is the state that made a version skew look like a tamper.
import { ReconcileScheduler } from "./document-reconcile-scheduler.js";
import { createSealFlows } from "./seal-flows.js";
import { registerCloseSessionHandler } from "./close-session-handler.js";
import { createInboundSessions } from "./inbound-sessions.js";
import { createOutboundSessions } from "./outbound-sessions.js";
import { registerSessionReadHandlers } from "./session-read-handlers.js";
import { registerInclusionProofHandlers } from "./inclusion-proof-handlers.js";
import { pullSealCertificate } from "./seal-certificate-pull.js";
import { registerAgentHandlers } from "./agent-handlers.js";
import { registerRegisterHandler } from "./register-handler.js";
import { registerInitiateSessionHandler } from "./initiate-session-handler.js";
import { createInboundSealRequestHandler } from "./inbound-seal-request.js";
import { registerNotificationHandlers } from "./notification-handlers.js";
import { TypeRegistry } from "./type-registry.js";
import { DbRegistryVersionStore } from "./registry-version-store-db.js";
import { startRegistryPoll } from "./registry-poll.js";
import { countAttendance } from "./co-attendance.js";
import { FrontierMismatchStore } from "./frontier-mismatch.js";


// 040-DAEMONROOT unit 8: three things that were never composition — the handle's shape, the session
// node factory, and a duplicate constant — left this file. Re-exported so every importer, including
// `@cello-protocol/daemon` consumers and the tests that construct a factory directly, is unchanged.
export type { DaemonHandle } from "./daemon-handle.js";
export { ProductionSessionNodeFactory } from "./session-node-factory.js";
// M8C-TTL-1: ONE definition now. daemon.ts held a second copy of this constant with the same value
// while `inbound-sessions.ts` — the file that actually enforces the TTL — held the first. Two
// definitions of one contract is how the two stop agreeing; the runtime always used that one, and
// this re-export is what kept the test that imports it from here working.
export { INBOUND_SESSION_TTL_MS } from "./inbound-sessions.js";
import type { DaemonHandle } from "./daemon-handle.js";
import { extractErrorMessage } from "./error-message.js";

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
    celloDir, socketPath, lockFilePath, maxConnections, logger,
    manifestProvider, manifestPollScheduler,
    directoryHttpUrl,
    signalingConnect, challengeVerifier, directoryEndpointResolver,
    sessionNegotiator, getRelayCircuitAddress, telegramBotClient: injectedTelegramBotClient,
  } = config;

  // 040-DAEMONROOT unit 7 (phase 1): transport, gateway, session manager, the manifest gate, the
  // roster sweep and the type registry → boot-core.ts. Three inputs, everything below comes out.
  const {
    transportSelector, securityGateway, sessionNodeManager,
    manifestOrigin, manifestVerified, verifiedManifest, verifiedManifestVersion,
    rosterSweepScheduler, stopRosterSweep, stopHttpManifestPoll,
    resolveConsortiumRoster, failoverEndpointResolver, getFailoverEndpoint, getUnresolvedNodes,
    getUnresolvedSweptAt, getDeclaredNodeCount,
    // A READER, not a value: the sweep writes it after this returns, and `cello status` reads it
    // later still. A snapshot here reports a healthy roster through every sweep failure.
    lastRosterSweepError,
  } = await startBootCore({ config, logger, directoryHttpUrl });

  // DOD-REGISTRY-1: type registry poll — daemon-level, runs even with zero agents.
  // When registryPubkey is configured, the daemon polls GET /registry, verifies the inner
  // Ed25519 signature, and updates the in-memory TypeRegistry. A poll failure never blanks
  // classification (INV-TYPE-CARRY). Absent pubkey = polling disabled, all types unclassified.
  const typeRegistry = new TypeRegistry();
  let stopRegistryPoll: (() => void) | undefined;
  // DOD-M12B-RESTART-SEAL-1: assigned as the last act of boot, stopped in stop().
  let restartSealResolver: RestartSealResolver | undefined;
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

  // 040-DAEMONROOT unit 7 (phase 2): the agents this daemon holds, their keys, the content park,
  // the reconnect drain and the submission retry queue → boot-agents.ts.
  const {
    loadedAgents, getPersistence, agents, keyProviders, contentPark,
    autoRecoverForAgent, onSignalingConnected, submissionRetries, recordIssuedSubmission,
  } = await startBootAgents({
    config, logger, sessionNodeManager, securityGateway,
    // GETTERS: all FOUR are declared below this call and read inside callbacks that run after boot.
    // Three are `const`, so by value they are a temporal-dead-zone crash at boot, not a silent
    // absence — the silent shape is a `let` assigned further down, which this file still has two of
    // (`reconcileScheduler`, `documentOwnerKeyForHook`).
    getFlushAwaitingContent: () => flushAwaitingContent,
    getOnlineAgents: () => onlineAgents,
    getSharedSignaling: () => sharedSignaling,
    getPerAgentSignaling: () => perAgentSignaling,
  });

  // DOD-M15-SEAL-FAILED-TERMINAL-1: a seal that ended without a receipt is discoverable rather than
  // being a line in daemon.log. In memory on purpose — a restart makes "failed" the WRONG answer,
  // because the boot sweep plus the restart seal resolver retry the session, so a marker whose
  // lifetime is the process matches the lifetime of the condition it describes.
  //
  // Declared HERE rather than 600 lines below because the seal coordinator writes to it: a
  // directory refusal must survive the close call waiting on it (DOD-M15-SEALPARTIES-1).
  // Created HERE, not where the seal code used to sit (~2,500 lines down), because the listeners
  // are wired into every signaling manager below — and the originals were FUNCTION DECLARATIONS,
  // so hoisting silently let them be CALLED 1,900 lines before they were DEFINED. A const in their
  // place lands in the temporal dead zone and every one of those calls throws. The dependency on
  // hoisting was real, load-bearing and invisible; naming the construction point makes it explicit.
  // ─── The seal cluster (seal-coordinator.ts) ───
  // Bilateral seal, unilateral escalation, and the returning-absent-party upgrade: five pieces of
  // state and the listeners that drive them. Already seal-private; now that is enforced by a module
  // boundary rather than by convention. cello_close_session still drives the waiters directly.
  //
  const sealFailures = new SealFailureStore();
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
    recoverContent: (agentName: string) => autoRecoverForAgent(agentName, "seal_upgrade_gate"),
    // DOD-M15-SEALPARTIES-1: a directory refusal has to outlive the close call that is waiting on
    // it — both surfaces read this store, and a close that already returned has nowhere else to
    // leave the answer. `kind` carries a DIRECTORY REFUSAL through as terminal (see the store).
    recordSealFailure: (agentName: string, sessionId: string, reason: string, kind: "unresolved" | "refused") =>
      sealFailures.record(agentName, sessionId, reason, new Date().toISOString(), kind),
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
    // 040-DAEMONROOT unit 5: these two live in signaling-wiring.ts, which is constructed BELOW
    // this call. They were function declarations in one scope, so hoisting made a direct reference
    // work; across a module boundary it cannot. Resolved at CALL time instead — seal flows only run
    // long after boot, so the indirection costs nothing and the alternative is a captured undefined.
    signalingFor: (agentName: string) => signalingFor(agentName),
    sendOver: (agentName: string, frame: Record<string, unknown>) => sendOver(agentName, frame),
    recordFrontierMismatch: (agentName, sessionId, m) => frontierMismatches.record(agentName, sessionId, m, Date.now()),
    clearFrontierMismatch: (agentName, sessionId) => frontierMismatches.clear(agentName, sessionId),
  });

  // 040-DAEMONROOT unit 13: how this daemon reaches a directory, and what it tells a relay about
  // itself when it gets there → directory-connect.ts.
  const { buildRelayConnectParams, noSharedDirectoryNode, sharedSignaling } =
    createDirectoryConnect({
      logger, keyProviders, signalingConnect, directoryEndpointResolver,
    });

  // 040-DAEMONROOT unit 5: per-agent directory signaling → signaling-wiring.ts.
  const {
    perAgentSignaling, getAgentSignaling, waitForSignalingConnected, dropAgentSignaling,
    signalingFor, sendOver, directorySignalingStatus, stopAllSignaling, registerPickupListener,
  } = createSignalingWiring({
    logger, sessionNodeManager, loadedAgents, keyProviders, sharedSignaling, noSharedDirectoryNode,
    verifiedManifestVersion, getPersistence, onSignalingConnected, resolveConsortiumRoster,
    failoverEndpointResolver, getFailoverEndpoint, sealFailures, submissionRetries,
    registerSealListeners, challengeVerifier, directoryEndpointResolver,
    // Built ~1,200 lines BELOW this call, and only ever READ when a manager is constructed, which
    // is later still. Getters because a by-value read here is a temporal-dead-zone crash at boot —
    // both are `const`, so it fails loudly with the right name rather than going quiet. (The shape
    // that goes quiet is `let x;`: still `undefined`, no error. That is unit 4's defect, and this
    // is not it.)
    getWirePerAgentSessionInbound: () => wirePerAgentSessionInbound,
    getHandleTrustSignalPickup: () => handleTrustSignalPickup, getSweepTrustSignals: () => sweepTrustSignalsAndTick,
  });

  // CELLO-M7-CONN-001 (DOD-CONN-1, code-review HIGH): in PRODUCTION, bring up EACH loaded agent's OWN
  // directory connection at startup. A registered agent must have a directory presence whenever the
  // daemon runs — so the directory can route inbound session_assignment/seal to it (notably after a
  // restart, where login does NOT auto-start agents), and `cello status` reflects directory_signaling
  // as soon as the daemon is up. This replaces the pre-CONN-001 keystone (which connected only the
  // loaded PRIMARY at startup) with a per-agent connection for EVERY loaded agent. Idempotent with the
  // create/register/start connect (getAgentSignaling caches per agent).

  // 040-DAEMONROOT unit 7 (phase 3): what the daemon remembers per IPC CONNECTION rather than per
  // agent — the selection, the online sets, and the two read positions → boot-connection-state.ts.
  const {
    perConnectionState, onlineAgents, explicitlyOfflineAgents, forgetConnection,
    getConnectionCursor, advanceConnectionCursor, safeCursorAdvance,
    getDeliveryBookmark, advanceDeliveryBookmark, safeWatermarkAdvance,
  } = startBootConnectionState({ sessionNodeManager });

  // 040-DAEMONROOT unit 6: attendance, the away reply and the one-shot rejection →
  // attendance-wiring.ts.
  const { attendanceCount, sendAwayResponse, contentTakes, backgroundSeals, awayAckSent } =
    createAttendanceWiring({
      logger, sessionNodeManager, perConnectionState, keyProviders, securityGateway,
      handleActiveSealFlow, sealKey, sealInterruptedInProgress, pendingSealWaiters,
      pendingUnilateralWaiters, sendOver,
    });

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

  // 040-DAEMONROOT unit 18: what to CALL a counterparty in a message an operator reads →
  // who-resolver.ts.
  const { resolveWho } = createWhoResolver({
    logger, sessionNodeManager,
    // Resolved at call time: the offer map is built below this, and a label is only ever rendered
    // while serving a request.
    getOfferedMoniker: (agentName, sessionIdHex) =>
      offeredMonikers.get(offerKey(agentName, sessionIdHex)) ?? null,
  });

  // SYNC-P5: assigned when the document layer is wired (below); the state-change hook runs for
  // sessions, which exist only after startup completes — the guard covers the boot window where
  // agent restoration can dispatch state events before the scheduler exists.
  let reconcileScheduler: ReconcileScheduler | undefined;
  let documentOwnerKeyForHook: ((agentName: string) => string | null) | undefined;

  // 040-DAEMONROOT unit 11: telling the operator a session changed, and staying quiet when the
  // daemon's own delivery worker caused it → session-notify.ts.
  const {
    deliveryOpens, pubkeyOfAgent, isDeliveryOpenInFlight, isDeliveryOpenToAgent,
    dispatchSessionStateChangedWithTelegram,
  } = createSessionNotify({
    logger, loadedAgents, resolveWho, sendTelegramDoorbell, clearTelegramRung,
    // GETTERS. The first two are `let`s ASSIGNED far below — the one shape that fails silently, and
    // the shape unit 4 shipped. The other three are `const`s declared below, which would crash at
    // boot; getters because they must be, not because getters are safer.
    getNotificationDispatcher: () => notificationDispatcher,
    getReconcileScheduler: () => reconcileScheduler,
    getDocumentOwnerKeyFor: () => documentOwnerKeyForHook,
    getOfferedMonikers: () => offeredMonikers,
    getOfferKey: () => offerKey,
  });



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
  const { openVisitingConnection, crossNodeBrokerBySession, resolvedSessionNegotiator, runDiscoveryLookup, sweepTrustSignalsAndTick, trustSignalSweepTicker } = createOutboundSessions({
    logger,
    sessionNodeManager,
    getKeyProvider: (agentName: string) => keyProviders.get(agentName),
    getPersistence,
    getAgentSignaling: (agentName: string, kp, pubkeyHex: string) => getAgentSignaling(agentName, kp, pubkeyHex),
    waitForSignalingConnected,
    getFailoverEndpoint,
    resolveConsortiumRoster,
    registerSealListeners,
    registerPickupListener,
    sessionNegotiator,
    challengeVerifier,
    getManifestVersion: () => verifiedManifestVersion,
    loadedAgents,
    // DOD-M15-ERRSTRING-1: so a session failure can say "and 2 of your 5 directories are
    // unreachable", which is very often the actual cause and was reported nowhere the operator
    // was looking.
    getUnresolvedNodes,
    getDeclaredNodeCount, getOnlineAgents: () => onlineAgents,
    // DOD-M15-SEALPARTIES-1: the visiting stream runs the seal ceremony too, so it needs the same
    // failure sink — otherwise a cross-node close that dies leaves no trace while a same-node one does.
    recordSealFailure: (name: string, sid: string, reason: string, kind: "unresolved" | "refused") =>
      sealFailures.record(name, sid, reason, new Date().toISOString(), kind),
  });
  // 040-DAEMONROOT unit 7 (phase 4): parked content and every path that gets it moving again — the
  // retry queue, the park timers, the startup sweep and the flush → boot-parked-content.ts.
  const { retryQueue, parkRetryTimers, flushAwaitingContent } =
    startBootParkedContent({
      config, logger, sessionNodeManager, agents, keyProviders,
      resolveConsortiumRoster, waitForSignalingConnected,
      // Plain values: the outbound-session module is constructed 27 lines ABOVE this call. An
      // earlier version passed getters and said the opposite in three places.
      openVisitingConnection, crossNodeBrokerBySession,
    });


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
    recordRefusal,
    reapExpiredInboundSessions,
    inboundSessionQueues,
    inboundSessionWaiters,
    expiredSessionRequests,
    refusedSessionRequests,
    offeredMonikers,
    offerKey,
  } = createInboundSessions({
    logger,
    sessionNodeManager,
    agents,
    isExplicitlyOffline: (agentName: string) => explicitlyOfflineAgents.has(agentName),
    // M12-P18: lets the responder send a refusal reason back to a TRUSTED sender.
    sendOver,
    getConnState: (connectionId) => perConnectionState.get(connectionId),
    // 040-DAEMONROOT unit 10b: the selection rule lives in agent-selection-root.ts, constructed
    // BELOW this consumer, and it is only ever called while serving a request.
    resolveCurrentAgent: (connState: Parameters<typeof resolveCurrentAgent>[0], explicitAgent?: string) =>
      resolveCurrentAgent(connState, explicitAgent),
    NO_CURRENT_AGENT_RESPONSE,
    getKeyProvider: (agentName: string) => keyProviders.get(agentName),
    sharedSignaling,
    handleInboundSealInterruptedRequest,
    // 040-DAEMONROOT unit 10: the reaper lives in session-views.ts, which is constructed BELOW this
    // consumer. It is only ever called while serving a request, so it resolves at call time.
    reapDeadHalfOpenSessions: (agentName?: string) => reapDeadHalfOpenSessions(agentName),
    sendAwayResponse,
    dispatchSessionStateChangedWithTelegram,
    sendTelegramDoorbell,
    isDeliveryOpenToAgent,
  });

  if (!sharedSignaling) {
    for (const agent of loadedAgents) {
      getAgentSignaling(agent.name, agent.keyProvider, agent.pubkey);
    }
  }

  await flushAwaitingContent();

  const nonceDedupStore = new NonceDedupStore(sessionNodeManager.getDb(), logger);
  nonceDedupStore.loadFromDb();

  // 040-DAEMONROOT unit 12: the agent list from ONE connection's point of view → connection-agents.ts.
  const { getAgentsForConnection } = createConnectionAgents({
    agents, perConnectionState, onlineAgents, sessionNodeManager,
    // A getter: the session views are constructed below this call, and the agent list is only ever
    // built while serving a request.
    agentStateFor: (a) => agentStateFor(a),
  });

  // 040-DAEMONROOT unit 10: the views the daemon builds of its own sessions and agents →
  // session-views.ts. `getStatus` stays here, where its breadth is honest, and calls in.
  const {
    buildInterruptedSessions, reapDeadHalfOpenSessions, buildActiveSessions,
    agentStateFor,
  } = createSessionViews({
    logger, sessionNodeManager, perConnectionState, onlineAgents, explicitlyOfflineAgents,
    perAgentSignaling, sharedSignaling, frontierMismatches, sealKey, sealInterruptedInProgress,
    pendingSealWaiters,
  });

  // 040-DAEMONROOT unit 17: the whole-daemon status the CLI renders → daemon-status-report.ts.
  const { getStatus } = createDaemonStatusReport({
    sessionNodeManager, retryQueue, agents, agentStateFor, buildInterruptedSessions,
    buildActiveSessions, directorySignalingStatus, manifestOrigin,
    // Resolved at call time: the report it produces is built below this, and a status is only ever
    // rendered later. By value it would be undefined and every status would silently omit the block
    // that says a directory node could not be resolved.
    unresolvedNodesForStatus: () => unresolvedNodesForStatus(),
    manifestProvider, directoryHttpUrl, challengeVerifier,
  });

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

  // 040-DAEMONROOT unit 10c: bringing an agent online, and reporting whether it can be REACHED →
  // start-agent.ts.
  const { startAgentInternal } = createStartAgent({
    logger, sessionNodeManager, agents, onlineAgents, explicitlyOfflineAgents, keyProviders,
    getAgentSignaling, autoRecoverForAgent, flushAwaitingContent,
    // A GETTER: the dispatcher is built ~575 lines below and is only touched when an agent is
    // actually started, which is always later.
    getNotificationDispatcher: () => notificationDispatcher,
  });

  // 040-DAEMONROOT unit 10b: which agent a call is for, and what to tell an operator whose agent is
  // not registered → agent-selection-root.ts.
  const { fallbackNoticeStore, resolveCurrentAgent } =
    createAgentSelection({ logger, onlineAgents });

  // Agent lifecycle (agent-handlers.ts): create, remove, start, stop, select, list.
  registerAgentHandlers({
    handlers,
    logger,
    sessionNodeManager,
    agents,
    onlineAgents,
    explicitlyOfflineAgents,
    getNotificationDispatcher: () => notificationDispatcher,
    getConnState: (connectionId) => perConnectionState.get(connectionId),
    perConnectionState,
    getAgentsForConnection,
    startAgentInternal,
    dropAgentSignaling, stopSweepTick: (n: string) => trustSignalSweepTicker.stop(n),
    awayAckSent,
    keyProviders,
    loadedAgents,
    getAgentSignaling,
    waitForSignalingConnected,
    perAgentSignaling,
  });

  // 040-DAEMONROOT unit 19: what the daemon says when a call cannot proceed → operator-guidance.ts.

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


  // 040-DAEMONROOT unit 3: share rotation and relay receipts → agent-admin-handlers.ts.
  registerAgentAdminHandlers({
    handlers, logger, sessionNodeManager, loadedAgents,
    getConnState: (connectionId) => perConnectionState.get(connectionId),
    resolveCurrentAgent, getPersistence, getAgentSignaling, waitForSignalingConnected,
    resolveConsortiumRoster, getFailoverEndpoint, sealFailures,
  });

  // ─── Trust-signal wallet (operator-facing, no agent scope required) ───
  // 040-DAEMONROOT unit 1: the trust-signal, attestation and consent handlers moved to
  // signal-handlers.ts, with the two helpers only they used. What stays here is the wiring.
  registerSignalHandlers({
    handlers,
    logger,
    sessionNodeManager,
    keyProviders,
    onlineAgents,
    loadedAgents,
    getConnState: (connectionId) => perConnectionState.get(connectionId),
    getAgentSignaling,
    openVisitingConnection,
    waitForSignalingConnected,
    resolveConsortiumRoster,
    verifiedManifest,
    submissionRetries,
    recordIssuedSubmission,
  });

  // 040-DAEMONROOT unit 14: the directory-reachability block a status read carries, and the rule for
  // when it says nothing → unresolved-nodes-report.ts.
  const { unresolvedNodesForStatus } = createUnresolvedNodesReport({
    getUnresolvedNodes, getUnresolvedSweptAt, lastRosterSweepError,
    manifestConfigured: manifestProvider !== undefined,
  });

  // `unresolvedNodesForStatus` is a module rather than a closure because it has TWO consumers:
  // this handler and the daemon-wide getStatus() the CLI renders.
  registerStatusHandler({
    handlers, getAgentsForConnection, directorySignalingStatus, manifestOrigin, manifestProvider,
    directoryHttpUrl, challengeVerifier, unresolvedNodesForStatus, buildInterruptedSessions, buildActiveSessions,
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
  const { openSessionFor } = registerInitiateSessionHandler({
    handlers,
    logger,
    sessionNodeManager,
    // SYNC-P5 (R39, review F5): the INITIATOR-side reachable trigger — the inbound side fires
    // from the session-state dispatch; without this half, only the answering daemon reconciled
    // on session-up and the initiator waited out a sweep interval.
    onSessionOpened: (agentName, counterpartyPubkey) => {
      if (!reconcileScheduler || !documentOwnerKeyForHook) return;
      // DOD-M12B-DELIVERY-QUIET-1: the INITIATOR half of the same circularity. This hook fires
      // inside openSessionAs, which the delivery worker's adapter brackets with begin/release — so
      // the intent is still in flight here and the check needs no plumbing of its own. Resetting
      // the backoff on a session WE opened to deliver a frame wipes a refusal the peer may have
      // given seconds ago and immediately sweeps every document, which opens more sessions.
      // We are the OPENER here, so our own pubkey goes first — the mirror of the inbound half above.
      if (isDeliveryOpenInFlight(pubkeyOfAgent(agentName), counterpartyPubkey)) {
        logger.debug("document.reconcile.reachable_trigger_skipped", {
          agentName, reason: "session_opened_by_document_delivery",
        });
        return;
      }
      const ownerAgentId = documentOwnerKeyForHook(agentName);
      if (ownerAgentId === null) return;
      logger.info("document.reconcile.reachable_trigger_fired", {
        agentName, trigger: "outbound_session_opened", peer: counterpartyPubkey.slice(0, 16),
      });
      void reconcileScheduler
        .onReachable(ownerAgentId, counterpartyPubkey.toLowerCase())
        .catch((err: unknown) => {
          logger.warn("document.reconcile.reachable_trigger_failed", {
            agentName, reason: extractErrorMessage(err),
          });
        });
    },
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
    // DOD-M15-CLOSEWAIT-1 review MEDIUM-6: a detached seal tail is registered here so stop() can
    // drain it, like every other background worker. Self-evicting, so a long-running daemon does not
    // accumulate settled promises.
    sealFailures,
    registerBackgroundSeal: (p) => {
      backgroundSeals.add(p);
      void p.finally(() => backgroundSeals.delete(p));
    },
    // M12-P14: the pre-seal readiness gate drains the parked mailbox before judging, so a close
    // does not refuse over content the relay is still holding for us.
    recoverParkedContent: (agentName: string, trigger: string) => autoRecoverForAgent(agentName, trigger),
    // DOD-TERMINAL-STATE-DIVERGENCE-1: the same pull `cello_sealed_receipt` uses, now also available
    // to the close — which is where the operator actually gets stranded.
    pullSealCertificate: (agentName: string, sessionIdHex: string) =>
      pullSealCertificate(
        {
          logger,
          sessionNodeManager,
          signalingFor,
          sendOver,
          getPersistence,
          getAgentPubkeyHex: (name) => loadedAgents.find((a) => a.name === name)?.pubkey,
        },
        agentName,
        sessionIdHex,
      ),
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
    // The seal path's fallback when crossNodeBrokerBySession is empty — which it is after every
    // restart, and a restart is what makes a session interrupted. Without this wired the handler
    // silently keeps the pre-0.0.141 behaviour and its unit tests still pass, because they inject it.
    runDiscoveryLookup,
    crossNodeBrokerBySession,
    sealKey,
    sealInterruptedInProgress,
    pendingSealWaiters,
    pendingUnilateralWaiters,
    handleSealInterruptedFlow,
    handleActiveSealFlow,
    resolveConsortiumRoster,
  });

  // 040-DAEMONROOT unit 3: backup and restore → backup-restore-handlers.ts.
  registerBackupRestoreHandlers({ handlers, logger, celloDir });

  // DOD-M15-INCLUSION-1: prove one message sits under the certified root, and check such a proof.
  //
  // This replaces the last entry of the MCP-001 `not_implemented` stub loop, which by the end held
  // exactly one tool — `cello_get_inclusion_proof` — so the loop goes with it rather than being left
  // as an empty scaffold that reads like other tools are still pending.
  registerInclusionProofHandlers({
    handlers,
    logger,
    sessionNodeManager,
    getConnState: (connectionId) => perConnectionState.get(connectionId),
    resolveCurrentAgent,
    NO_CURRENT_AGENT_RESPONSE,
  });

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
    // DOD-M15-CLOSEWAIT-1 HIGH-2: the SAME predicate cello_status uses, so the two surfaces cannot
    // disagree. Both maps — pendingSealWaiters is the active close, the other the interrupted one.
    isSealing: (agentName, sessionId) =>
      pendingSealWaiters.has(sealKey(agentName, sessionId)) ||
      sealInterruptedInProgress.has(sealKey(agentName, sessionId)),
    // DOD-M15-SEAL-FAILED-TERMINAL-1: the SAME store the close handler writes, so a failure recorded
    // by the detached tail is the one the receipt surface reads.
    getSealFailure: (agentName, sessionId) => sealFailures.get(agentName, sessionId),
    getConnState: (connectionId) => perConnectionState.get(connectionId),
    resolveCurrentAgent,
    NO_CURRENT_AGENT_RESPONSE,
    resolveWho,
    safeCursorAdvance,
    safeWatermarkAdvance,
    reapDeadHalfOpenSessions,
    frontierMismatches,
    attendanceCount,
    // DOD-TERMINAL-STATE-DIVERGENCE-1: the pull twin of the session_sealed push. Wired HERE, at the
    // composition root, because it needs the agent's own signaling stream and its persistence — the
    // read handlers hold neither, and giving them the whole daemon to reach one function is how a
    // read surface acquires a network dependency nobody expects.
    pullSealCertificate: (agentName, sessionIdHex) =>
      pullSealCertificate(
        {
          logger,
          sessionNodeManager,
          signalingFor,
          sendOver,
          getPersistence,
          getAgentPubkeyHex: (name) => loadedAgents.find((a) => a.name === name)?.pubkey,
        },
        agentName,
        sessionIdHex,
      ),
  });
  // 040-DAEMONROOT unit 2: the test-support verbs moved to test-handlers.ts. The two production
  // registrations that sat between them stay here — they are real surfaces, not test scaffolding.
  registerTestHandlers({
    handlers,
    logger,
    sessionNodeManager,
    retryQueue,
    nonceDedupStore,
    deliveryOpens,
    pubkeyOfAgent,
    dispatchSessionStateChangedWithTelegram,
    enqueueInboundSession,
    recordRefusal,
    inboundSessionQueues,
    getConnState: (connectionId) => perConnectionState.get(connectionId),
  });

  contentPark.registerHandlers(handlers);
  registerInboundSessionHandlers(handlers);


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
    getDeliveryBookmark,
    advanceDeliveryBookmark,
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
    refusedSessionRequests,
    // §16.5's passive notification, wired 2026-08-08. Both halves existed with no production caller
    // — nothing wrote a notice and nothing read one — so an agent learned a document had changed
    // only by polling, and `cello_doc_read` cleared rows that could never exist.
    documentNotices: (ownerAgentId) => documentLayer.notifications.pending(ownerAgentId),
    ownerKeyFor: (agentName) =>
      loadedAgents.find((a) => a.name === agentName)?.pubkey?.toLowerCase() ?? null,
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

  // 040-DAEMONROOT unit 16: the handler map as the IPC server sees it, and the server itself →
  // ipc-surface.ts.
  const { ipcServer } = createIpcSurface({
    logger, socketPath, maxConnections, handlers, perConnectionState, fallbackNoticeStore,
    // A GETTER: `stop` is defined below this surface and the `shutdown` verb calls it.
    getStop: () => stop,
  });


  // THE SOCKET OPENS LAST — see the deferred start below. Accepting clients here would accept
  // `cello_start_agent`, which brings an agent online, creates its standing receiver, and drains
  // parked content — all of it arriving before the document frame hook exists.

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

  // 040-DAEMONROOT unit 4: the document layer and its per-agent carrier → document-wiring.ts.
  const { documentLayer, documentOwnerKeyFor, documentTransportFor } = createDocumentWiring({
    logger, sessionNodeManager, loadedAgents, keyProviders,
    securityGateway, celloDir: config.celloDir,
    deliveryOpens, pubkeyOfAgent, openSessionFor, perAgentSignaling, runDiscoveryLookup,
    // The scheduler does not exist yet — it is built below, from this layer's sweep targets. A
    // getter is what keeps the refusal backoff alive; the value would be a captured `undefined`.
    getReconcileScheduler: () => reconcileScheduler,
    notificationDispatcher,
    getCloseSessionHandler: () => handlers.get("cello_close_session"),
  });

  // 040-DAEMONROOT unit 15: the document operator surface and the sweep that keeps shared documents
  // converging → document-surface.ts.
  const {
    reconcileSweepTimer, reconcileScheduler: builtReconcileScheduler,
  } = createDocumentSurface({
    logger, handlers, loadedAgents, keyProviders, perConnectionState, perAgentSignaling,
    resolveCurrentAgent, documentLayer, documentOwnerKeyFor, documentTransportFor,
  });
  // The scheduler is produced by the surface and assigned back here, because two modules built
  // EARLIER hold getters over this binding. They read at call time, which is always after this.
  reconcileScheduler = builtReconcileScheduler;

  documentOwnerKeyForHook = documentOwnerKeyFor;

  // ── THE SOCKET OPENS ONLY NOW, and the ordering is load-bearing (2026-08-16). ──
  //
  // This used to run ~120 lines earlier, immediately after the server was created — before
  // `setOnDocumentFrame` above. That opened a window on every daemon start: a client connects,
  // calls `cello_start_agent`, the agent comes online, its standing receiver drains whatever the
  // relay parked — and any DOCUMENT frame in that drain found `#onDocumentFrame` still unset. The
  // routing fork in session-node-manager treats an unconsumed frame as conversation, so those
  // frames were appended as `msg` leaves, written to the durable transcript, rang the doorbell,
  // and were handed to the agent by `cello_receive` as raw canonical CBOR.
  //
  // Reported from the live fleet by a counterparty who pasted the bytes back
  // (`dtyperdocument_reconcile…`), reproduced in `j-stale-session.spine.test.ts`, and it is why
  // documents accumulated unaccepted: the frames were not lost in transit, they were EATEN as
  // messages, so the document layer never saw them while the sender was told they were delivered.
  //
  // The comment at that fork claimed an unwired hook "cannot change the conversation path". It
  // can, and did. Nothing between here and the server's creation needs a live socket, so the
  // honest fix is to finish wiring before anyone can knock.
  try {
    await ipcServer.start();
  } catch (err: unknown) {
    // As above: startDaemon's catch releases the singleton lock for us.
    await removeLockIfOwned(lockFilePath, process.pid, logger);
    throw err;
  }


  // 040-DAEMONROOT unit 20: what the daemon forgets, and what it says, when a connection closes →
  // disconnect-cleanup.ts.
  wireDisconnectCleanup({
    ipcServer,
    getConnState: (connectionId: string) => perConnectionState.get(connectionId),
    countAttendanceFor: (agentName: string) => countAttendance(perConnectionState, agentName),
    forgetConnection,
    forgetTakeLedger: (connectionId: string) => contentTakes.forget(connectionId),
    inboundSessionWaiters,
    // A GETTER, though the dispatcher is a const 82 lines ABOVE — so that moving its construction
    // below this line cannot break the disconnect path silently. Reason in full at the dep.
    getNotificationDispatcher: () => notificationDispatcher,
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
  // DOD-LOGOUT-EXIT-1: the onStopped hook ends the process in the binary, so it fires at most once
  // per daemon no matter how many times stop() is called.
  let stoppedHookFired = false;

  async function stop(reason: string): Promise<void> {
    clearInterval(reconcileSweepTimer);
    clearInterval(revivalBoundSweepTimer);
    // DOD-M15-RELAYABUSE-1: scheduled park retries. Unref'd, so they never held the process open —
    // cleared so an in-process restart cannot leave one draining into a torn-down manager.
    for (const t of parkRetryTimers) clearTimeout(t);
    parkRetryTimers.clear();
    // DOD-M12B-SHUTDOWN-1: clearing the timer only stops the NEXT tick. The pass already running
    // walks every agent, and each step dials a peer and opens a session — which is why a daemon
    // reported down, with its socket already removed, was still logging `document.reconcile.sweep`
    // 30 seconds later and had to be signalled to exit. This is what stops the pass in flight, and
    // it also blocks `onReachable`, so a session tearing down during shutdown cannot hand the
    // sweeper a fresh reason to dial on the way out.
    // `?.` is a TYPE requirement, not a runtime one: TypeScript discards the narrowing of a
    // captured `let` inside a hoisted function declaration, though it keeps it in the arrow a few
    // lines up. The scheduler is in fact always wired by the time this can run — the IPC socket,
    // the only route to `stop` besides the returned handle, opens after it.
    reconcileScheduler?.stop();
    // DOD-M12B-SHUTDOWN-1: the scheduler is one of FOUR callers of initiateReconcile. `nudgeSeats`
    // and the two invite notices reach it directly, and every document verb is still served while
    // the rest of this function runs — the IPC server is the last thing stopped. Refusing at the
    // choke point is what actually closes "no new outbound work".
    documentLayer?.stopReconciling();
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
    // DOD-M15-STALEROSTER-1: same discipline as the manifest poll — the stop function sets the
    // flag so an in-flight sweep cannot re-arm, and the belt-and-suspenders cancel covers the
    // scheduler-without-sweep case.
    stopRosterSweep?.();
    rosterSweepScheduler?.cancel();
    stopRegistryPoll?.();
    if (config.registryPollScheduler) {
      config.registryPollScheduler.cancel();
    }
    // DOD-M12B-RESTART-SEAL-1: stop opening directory ceremonies. A seal is the most outbound thing
    // this daemon does, and DOD-M12B-SHUTDOWN-1's rule is that a shutdown which keeps starting new
    // outbound work is not draining. Above the `daemon.stopped` log with the other cancels, because
    // this is "stop making new work", not "tear down transports".
    await restartSealResolver?.stop();
    // DOD-M15-ENDORSE-RETRY-1: same rule, same place — stop making new outbound work. Nothing is
    // awaited: a submission send is one frame with an ack, not a ceremony, so cutting it leaves no
    // counterparty holding a half-finished exchange. What IS lost is the pending queue itself,
    // which is in memory by design (see submission-retry.ts) — re-sending is safe by the same
    // content-derived id.
    submissionRetries.stop();
    /**
     * DRAIN THE DETACHED SEAL TAILS — review MEDIUM-6, and it sits HERE for the same reason
     * `restartSealResolver.stop()` does: both are directory ceremonies that must not be cut with
     * the counterparty holding a commitment this side never acknowledged. Before
     * `stopAllSignaling()`, because that is what severs the transport underneath them.
     *
     * BOUNDED. A ceremony can legitimately wait eleven minutes for a counterparty, and a shutdown
     * must not. Past the bound they are abandoned deliberately and said out loud — the next boot
     * resolves them, which is exactly what the restart seal resolver is for.
     */
    if (backgroundSeals.size > 0) {
      const SHUTDOWN_SEAL_DRAIN_MS = 5_000;
      logger.info("session.seal.background.draining", { count: backgroundSeals.size, budgetMs: SHUTDOWN_SEAL_DRAIN_MS });
      const drained = await Promise.race([
        Promise.allSettled([...backgroundSeals]).then(() => true),
        new Promise<boolean>((r) => { const t = setTimeout(() => r(false), SHUTDOWN_SEAL_DRAIN_MS); (t as unknown as { unref?: () => void }).unref?.(); }),
      ]);
      if (!drained) {
        logger.warn("session.seal.background.abandoned", {
          count: backgroundSeals.size,
          impact:
            "shutdown did not wait for these seal ceremonies. Each session holds a durable commitment " +
            "but no receipt yet, and the counterparty may hold a commitment this side never acknowledged.",
          guidance: "The next daemon start resolves them via the restart seal resolver; no operator action is needed.",
        });
      }
    }
    logger.info("daemon.stopped", { pid: process.pid, reason });
    // DOD-LOGOUT-EXIT-1: what the teardown actually DID, carried to onStopped so the binary can
    // exit non-zero on a dirty stop. Without it a shutdown that threw halfway — sessions never
    // marked interrupted, database never checkpointed — would exit 0 and `cello logout` would
    // print "Daemon stopped.", which is this unit's own defect one level up.
    let teardownError: Error | undefined;
    try {
      // stopAllSignaling() stops the shared manager AND every per-agent manager (best-effort). Do
      // not add a separate per-agent stop loop beside it: it would be redundant, and an unguarded
      // second stop() that throws would abort the rest of shutdown.
      trustSignalSweepTicker.stopAll(); await stopAllSignaling();
      // Gracefully mark active sessions interrupted (AC-009) before stopping IPC
      await sessionNodeManager.gracefulShutdown();
      await ipcServer.stop();
    } catch (err: unknown) {
      // Recorded, then RE-THROWN below by the bare `throw` — the existing contract that a failed
      // stop() rejects is unchanged. This only makes the failure visible to onStopped as well.
      teardownError = err instanceof Error ? err : new Error(String(err));
      throw err;
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
            error: extractErrorMessage(err),
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
      // DOD-LOGOUT-EXIT-1: signal that this daemon is DONE — the binary's handler is
      // `process.exit(0)`, so nothing may be sequenced after this line.
      //
      // AFTER singletonLock.release(), never before: the process is about to end, and dying while
      // still holding the kernel lock would make the next `cello login` refuse to start beside a
      // daemon that no longer exists.
      //
      // Inside the `finally` so a throw anywhere above still ends the process. A shutdown that
      // fails halfway and leaves the daemon alive and on the network is the exact defect this line
      // closes — "it threw" is not a reason to keep talking to a directory.
      //
      // Guarded: `stop()` has no idempotence of its own, and a caller that stops twice (an IPC
      // shutdown followed by an embedder's own stop) must not exit twice.
      // The hook's own failure is NOT caught. It is the only call that ends the process, so
      // swallowing a throw here would leave the daemon alive and handle-free while every check
      // logout makes agrees it is gone — the original defect, reached through the new code. Letting
      // it propagate makes stop() reject, which is what lets logout time out and say so.
      if (!stoppedHookFired) {
        stoppedHookFired = true;
        await config.onStopped?.({ ok: teardownError === undefined, error: teardownError });
      }
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

  // DOD-M12B-RESTART-SEAL-1: seal the sessions the LAST shutdown orphaned.
  //
  // 114 of 118 interrupted sessions on one operator's machine were flipped by our own shutdown
  // sweep and then sat there, because nothing has ever moved a session out of `interrupted`. Their
  // only exit was a force-abandon, which forfeits the notarized receipt.
  //
  // Started last, like the Telegram poller, and resolved LAZILY out of the live `handlers` map: the
  // close handler is registered far earlier, but reading it inside the callback is what lets a test
  // swap it after boot and prove this wiring exists rather than assume it.
  restartSealResolver = new RestartSealResolver({
    logger,
    listRestartOrphans: () => sessionNodeManager.listRestartOrphanedSessions(),
    ...(config.restartSealInitialDelayMs !== undefined
      ? { initialDelayMs: config.restartSealInitialDelayMs }
      : {}),
    ...(config.restartSealStaggerMs !== undefined ? { staggerMs: config.restartSealStaggerMs } : {}),
    sealSession: async (agentName, sessionId) => {
      const close = handlers.get("cello_close_session");
      if (!close) return { ok: false, reason: "close_handler_missing" };
      const res = (await close({ session_id: sessionId, agent: agentName }, `restart-seal-${sessionId}`)) as
        | Record<string, unknown>
        | undefined;

      // SUCCESS IS A RECEIPT, NOT AN `ok`. The interrupted close answers `ok: true` for a bilateral
      // COMMITMENT that nobody has notarized — `seal_interrupted_pending`, the status this resolver
      // exists to stop producing. Reading `ok` as success logged "resolved" for 137 sessions that
      // got no receipt at all. `sealed_root` is present only when a notarization actually happened.
      if (typeof res?.["sealed_root"] === "string" && (res["sealed_root"] as string).length > 0) {
        return { ok: true };
      }
      // Everything the close computed about WHY, carried instead of collapsed. `reason` is an exit
      // point — `seal_interrupted_rejected_by_counterparty` alone stands for six distinct causes,
      // and the close already put the discriminating detail on the response.
      const detail: Record<string, unknown> = {};
      for (const k of ["rejection_reason", "your_leaf_count", "their_leaf_count", "diverging_leaf_index",
                       "seal_pending_reason", "seal_receipt", "missing_leaves", "held_messages", "status"]) {
        if (res?.[k] !== undefined) detail[k] = res[k];
      }
      const retry = res?.["retry_after_seconds"];
      return {
        ok: false,
        reason: (typeof res?.["seal_pending_reason"] === "string" ? res["seal_pending_reason"] as string : undefined)
          ?? (typeof res?.["reason"] === "string" ? res["reason"] as string : undefined)
          ?? "close_returned_no_receipt",
        ...(typeof retry === "number" ? { retryAfterSeconds: retry } : {}),
        ...(typeof res?.["guidance"] === "string" ? { guidance: res["guidance"] as string } : {}),
        ...(Object.keys(detail).length > 0 ? { detail } : {}),
      };
    },
    markGaveUp: (agentName, sessionId, reason) =>
      sessionNodeManager.markRestartSealGaveUp(agentName, sessionId, reason),
  });
  restartSealResolver.start();

  // 040-DAEMONROOT unit 9: the revival-bound sweep and its re-arming timer → boot-sweeps.ts.
  const { revivalBoundSweepTimer } = startBootSweeps({ logger, sessionNodeManager });

  /**
   * The live handler map.
   *
   * Exposed so the LATE-BINDING property can be asserted rather than assumed: dispatch resolves
   * from this map when a request arrives, and the only way to prove that is to register something
   * after `start()` has resolved and call it. The property is not decorative — a snapshot copy here
   * once made every `cello_doc_*` verb unreachable while the whole suite stayed green.
   *
   * Sits alongside `getSessionNodeManager` and `getTypeRegistry`, which are exposed for the same
   * reason. Production code has no business mutating it after boot.
   */
  const getHandlers = (): Map<string, IpcHandler> => handlers;

  return {
    /**
     * DOD-M12B-CLOSE-SILENT-WAIT-1 test seam: put a session into the state a normal close sits in
     * for up to eleven minutes, and emit the same start-of-wait line the close emits. Marks the
     * REAL waiter map the status surface reads, so a test cannot pass against a flag production
     * never sets.
     */
    markSealInFlightForTest(agentName: string, sessionId: string): void {
      const deadlineMs = Number(process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"]) || 660_000;
      pendingSealWaiters.set(sealKey(agentName, sessionId), () => {});
      logger.warn("session.seal.awaiting_counterparty", {
        sessionId, agentName, deadlineMs,
        impact: `this close will not answer for up to ${Math.round(deadlineMs / 60_000)} minutes while it waits for the counterparty, then it escalates to a unilateral seal and produces a real receipt. It is working. Do NOT force-abandon it — that forfeits the receipt this wait is earning.`,
      });
    },
    stop, getStatus, getSessionNodeManager, getTransportSelector, getAutoNatService, getTypeRegistry,
    getHandlers,
  };
}
