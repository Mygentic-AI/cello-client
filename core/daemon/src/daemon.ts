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
import { ContentParkClient } from "./content-park-client.js";
import { NotificationDispatcher } from "./notification-dispatcher.js";
import { createNode, SignalingManager, type ConnectResult, type CelloNode } from "@cello-protocol/transport";
import { createSignalingConnect, type SignalingAuthIdentity } from "./signaling-connect.js";
import { RegistrationManager } from "./registration-manager.js";
import { DaemonRegistrationContext } from "./registration-context.js";
import { FileRegistrationPersistence } from "./registration-persistence.js";
import { verify as ed25519Verify, sealToRecipient } from "@cello-protocol/crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { SealInterruptedLeaf } from "@cello-protocol/protocol-types";
// CELLO-M7-MSG-001 (AC-013/AC-018): the single application content-size cap, enforced
// at the send point here (the receive point lives in the transport content decode).
import { MAX_CONTENT_BYTES, computeGenesisPrevRoot } from "@cello-protocol/protocol-types";
import type { ISessionNodeFactory, SessionNodeConfig, RelayConnectParams } from "./session-node-manager.js";
import {
  resolveCelloEnv,
  createTransportSelector,
  isProductionVariant,
} from "./transport-composition.js";
import type { ITransportSelector, SessionNegotiator, SessionNegotiationResult } from "./transport-selector.js";
import { selectAdvertisedAddress } from "./transport-selector.js";
import { parseSessionAssignment, sessionRequestErrorReason } from "./session-assignment-parser.js";
import { wireSessionCeremonyHandler, wireSessionOfferHandler, wireSealCeremonyHandler, verifyUnilateralCertificate, verifyBilateralSealCertificate } from "./session-ceremony.js";
import type { LegibilityForHash } from "./seal-legibility-tbs.js";
import { reDeriveFrontiers, findInflatedFrontier, type SealFrontierLeaf } from "./seal-frontier-verify.js";
import { LocalAutoNatStub, type IAutoNatService } from "@cello-protocol/transport";

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
    return createNode({
      keyProvider: SESSION_NODE_KEY_STUB,
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      connectionGater: config.connectionGater,
      // CELLO-M7-TRANSPORT-001: forward the role so AutoNAT/dcutr are configured
      // correctly (session nodes get dcutr; standing receivers do not).
      nodeType: config.nodeType,
    });
  }
}

export async function startDaemon(config: DaemonConfig): Promise<DaemonHandle> {
  const {
    celloDir, socketPath, lockFilePath, maxConnections, version, logger,
    manifestProvider, manifestRootKeys, manifestThreshold,
    manifestVersionStore, manifestPollScheduler,
    signalingConnect, challengeVerifier, directoryEndpointResolver, sessionNodeFactory,
    sessionNegotiator, getRelayCircuitAddress,
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
    return {
      relayPeerId: endpoint.peer_id,
      relayAddrs: endpoint.multiaddrs,
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      sessionIdBytes: assignment.session_id,
    };
  };

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
    // DOD-AUTH-2: the keystone manager (primary agent's directory door) carries the
    // manifest-poll deps so it re-polls the directory on its live stream and adopts a
    // newer signed manifest. The SAME shared manifestProvider instance the startup load
    // + challengeVerifier use, so an adopted manifest updates the cache step-6 reads from.
    // All optional — undefined on the M6 backward-compat path → polling is simply off.
    pollScheduler: manifestPollScheduler,
    manifestProvider,
    manifestVersionStore,
    rootKeys: manifestRootKeys,
    threshold: manifestThreshold,
  });

  // ─── Per-agent directory signaling (multi-agent: one signaling stream per agent) ──
  // The keystone `signalingManager` above authenticates as the PRIMARY agent (first
  // loaded, sorted) and is the daemon's directory door for that agent. But the
  // directory routes EVERY signaling frame — dkg_complete, register_success, and
  // inbound session_request — by the pubkey that AUTHENTICATED the stream it arrived
  // on. So a non-primary agent registering over the primary's stream has its
  // dkg_complete misrouted (the directory keys `#pendingDkgComplete` by the stream's
  // authed pubkey, which is the primary's, not the registrant's) and the registration
  // times out after a completed DKG. The fix is the M7 intent: each agent gets its OWN
  // directory signaling stream, authenticated as itself, so the directory routes its
  // frames to it. This realises the "Online — directory connection active, per agent"
  // model the keystone note (at `primaryAgent` above) flagged as the follow-on.
  //
  // The primary agent reuses the keystone manager; every other agent gets a dedicated
  // SignalingManager authed as that agent. Managers are created lazily (on first
  // registration / online) and kept connected for the agent's directory presence.
  interface AgentSignaling {
    signaling: SignalingManager;
    getNode: () => CelloNode | null;
  }
  const perAgentSignaling = new Map<string, AgentSignaling>();

  /**
   * Return the directory signaling stream for `agentName`, authenticated as that
   * agent. The primary agent reuses the keystone manager + its published node; any
   * other agent gets (and caches) a dedicated manager. Falls back to the keystone
   * manager when no production bootstrap resolver is configured (in-process tests
   * inject a single `signalingConnect` and never exercise the per-agent path).
   *
   * SCOPE (SPINE-5 follow-on): this wires per-agent signaling for REGISTRATION (the
   * registration reply frames are routed via the per-agent DaemonRegistrationContext's
   * own inbound handler). The daemon's INBOUND SESSION handlers (session_assignment /
   * session_request, registerInboundHandler below) are still attached to the keystone
   * `signalingManager` only — so a NON-primary agent can register but cannot yet RECEIVE
   * inbound sessions on its dedicated stream (frames there are unhandled). Not a
   * regression (before this, a non-primary agent could not register at all); closing it
   * is SPINE-5, which attaches the session inbound handlers per-agent. Tracked in the
   * M7 build journal + DoD SPINE-5 scope note.
   */
  function getAgentSignaling(
    agentName: string,
    agentKeyProvider: import("@cello-protocol/crypto").KeyProvider,
    agentPubkeyHex: string,
  ): AgentSignaling {
    if (primaryAgent && agentName === primaryAgent.name) {
      return { signaling: signalingManager, getNode: getDirectoryNode };
    }
    const existing = perAgentSignaling.get(agentName);
    if (existing) return existing;
    if (!directoryEndpointResolver) {
      return { signaling: signalingManager, getNode: getDirectoryNode };
    }
    let nodeRef: CelloNode | null = null;
    const connect = createSignalingConnect({
      getDirectoryEndpoint: directoryEndpointResolver,
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
    });
    const entry: AgentSignaling = { signaling: mgr, getNode: () => nodeRef };
    perAgentSignaling.set(agentName, entry);
    logger.info("agent.signaling.created", { agentName, agentPubkey: agentPubkeyHex });
    // DOD-SPINE-5: answer the directory's delegated-signing `ceremony_request` on THIS
    // agent's stream (the session FROST ceremony — the per-agent counterpart to SPINE-4's
    // registration routing). Unregistered implicitly when the manager is stopped.
    wireSessionCeremonyHandler({
      agentName,
      agentDir: join(celloDir, "agents", agentName),
      agentPubkeyHex,
      getNode: entry.getNode,
      getDirectoryEndpoint: async () => (directoryEndpointResolver ? (await directoryEndpointResolver()) ?? null : null),
      signaling: mgr,
      logger,
    });
    // DOD-SPINE-7: coordinate the SEAL FROST ceremony on this agent's stream too.
    wireSealCeremonyHandler({
      agentName,
      agentDir: join(celloDir, "agents", agentName),
      agentPubkeyHex,
      getNode: entry.getNode,
      getDirectoryEndpoint: async () => (directoryEndpointResolver ? (await directoryEndpointResolver()) ?? null : null),
      signaling: mgr,
      logger,
    });
    // DOD-SPINE-7: and resolve session_sealed for this agent's sessions on its own stream.
    registerSessionSealedListener(mgr, agentName, agentPubkeyHex);
    // SESSION-002: resolve seal_unilateral_confirmed (verify the cert) on this agent's stream.
    registerUnilateralConfirmedListener(mgr, agentName, agentPubkeyHex);
    // WIRE-002: answer the directory's session_offer on this agent's stream (advertise the
    // standing-receiver session endpoint so the assignment carries a reachable counterparty).
    wireSessionOfferHandler({
      agentName,
      getStandingReceiverEndpoint: () => sessionNodeManager.getStandingReceiverInfo(agentName),
      signaling: mgr,
      logger,
    });
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
   * for an agent that is not registered/online. No-op for the primary (it reuses the
   * keystone manager, which is never stored here) and for agents with no dedicated
   * manager. On a later retry, getAgentSignaling re-creates it.
   */
  async function dropAgentSignaling(agentName: string): Promise<void> {
    const entry = perAgentSignaling.get(agentName);
    if (!entry) return;
    perAgentSignaling.delete(agentName);
    await entry.signaling.stop();
    logger.info("agent.signaling.dropped", { agentName });
  }

  // DOD-SPINE-5: the PRIMARY agent registers + initiates over the keystone signaling
  // stream (not a per-agent one), so wire its ceremony_request handler on the keystone
  // manager too — otherwise a primary-agent initiator's session ceremony would time out.
  if (primaryAgent) {
    wireSessionCeremonyHandler({
      agentName: primaryAgent.name,
      agentDir: join(celloDir, "agents", primaryAgent.name),
      agentPubkeyHex: primaryAgent.pubkey,
      getNode: getDirectoryNode,
      getDirectoryEndpoint: async () => (directoryEndpointResolver ? (await directoryEndpointResolver()) ?? null : null),
      signaling: signalingManager,
      logger,
    });
    // DOD-SPINE-7: the primary agent also coordinates the SEAL FROST ceremony on the keystone.
    wireSealCeremonyHandler({
      agentName: primaryAgent.name,
      agentDir: join(celloDir, "agents", primaryAgent.name),
      agentPubkeyHex: primaryAgent.pubkey,
      getNode: getDirectoryNode,
      getDirectoryEndpoint: async () => (directoryEndpointResolver ? (await directoryEndpointResolver()) ?? null : null),
      signaling: signalingManager,
      logger,
    });
    wireSessionOfferHandler({
      agentName: primaryAgent.name,
      getStandingReceiverEndpoint: () => sessionNodeManager.getStandingReceiverInfo(primaryAgent.name),
      signaling: signalingManager,
      logger,
    });
  }

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
    contentTtfMs: config.contentTtfMs,
    // CELLO-M7-TRANSPORT-001: directory-node AutoNAT probers (SI-002). The
    // directory connection (SIGNAL-001) is not yet wired into the daemon, so the
    // prober set is empty — AutoNAT cannot run and the standing receiver reports
    // the conservative default + transport.autonat.unavailable (AC-004/DB-001).
    autoNatProbers: () => [],
  });
  await sessionNodeManager.initialize();

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
  // with no initiator session Peer ID), then parses the returned assignment. Ported from
  // core/client `initiateSession` (NOT imported — that stack is dead). Tests still inject
  // their own `sessionNegotiator`; the binary now gets a real one instead of
  // directory_signaling_not_configured.
  // M3: a `session_assignment` frame carries no echoed request id, so two overlapping
  // initiations on ONE agent's stream would race to resolve on whichever assignment
  // arrives first — request A could complete with B's assignment. Guard with a per-agent
  // single-flight slot (genuine single-slot, as the prior comment falsely claimed). Cross-
  // agent concurrency is unaffected (separate streams). A directory-side echoed request id
  // would allow true concurrency later; this is the correct minimum.
  const negotiationInProgress = new Set<string>();
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

      // Single-flight claimed (above) → safe to register one inbound handler for this
      // agent's reply; unregistered + slot released in finally.
      negotiationInProgress.add(ctx.agentName);
      let resolveFrame!: (f: Record<string, unknown>) => void;
      const pending = new Promise<Record<string, unknown>>((r) => {
        resolveFrame = r;
      });
      const unregister = signaling.registerInboundHandler((frame) => {
        const t = frame["type"];
        if (t === "session_assignment" || t === "session_request_error") resolveFrame(frame);
      });
      try {
        const sent = await signaling.sendRaw({
          type: "session_request",
          target_pubkey: new Uint8Array(Buffer.from(targetHex, "hex")),
          initiator_session_peer_id: sr.peerId,
          initiator_session_addrs: sr.addrs,
          // WIRE-002 opt-in: ask the directory to run the session_offer→accept round-trip so
          // the assignment carries the counterparty's reachable session endpoint.
          wants_session_offer: true,
        });
        if (!sent.ok) {
          return {
            ok: false,
            reason: sent.reason ?? "directory_unreachable",
            guidance: sent.guidance ?? "Could not send session_request over the directory signaling stream.",
          };
        }
        let timer!: ReturnType<typeof setTimeout>;
        const timeoutP = new Promise<Record<string, unknown>>((r) => {
          timer = setTimeout(() => r({ type: "__timeout__" }), 30_000);
        });
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
        logger.info("session.negotiate.assignment.received", {
          agentName: ctx.agentName,
          correlationId: ctx.correlationId,
          signatureType: assignment.signature_type,
        });
        return { ok: true, assignment };
      } finally {
        unregister();
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
  sessionNodeManager.setAwaitingAckHooks({
    onPersisted: (agentName, sessionId, contentHashHex) => {
      retryQueue.markContentAcked(agentName, sessionId, Buffer.from(contentHashHex, "hex"));
    },
    onTtf: (agentName, sessionId, contentHashHex, content) => {
      retryQueue.enqueueAwaitingContent(agentName, sessionId, Buffer.from(contentHashHex, "hex"), content);
    },
  });

  // MSG-001-3b (2b): the LIVE content-park deposit. On a not-confirmed send (direct delivery
  // failed, or TTF with no `persisted` ACK) the session manager calls this with the recipient +
  // the session's relay endpoint; we seal the content to the recipient (E2E — the relay never sees
  // plaintext, INV-3) and deposit it to that relay's store-and-forward mailbox via the standing
  // receiver node. The recipient pulls + recovers it at the witnessed sequence (R1) on next online.
  sessionNodeManager.setContentParkHook(async ({ sessionId, recipientPubkeyHex, relayPeerId, relayAddrs, contentHashHex, content, structure1Cbor, structure2Cbor }) => {
    const node = sessionNodeManager.getStandingReceiverNode();
    if (!node) {
      logger.warn("content.park.deposit.failed", { sessionId, contentHash: contentHashHex, reason: "standing_receiver_unavailable" });
      return;
    }
    const recipientPubkey = Buffer.from(recipientPubkeyHex, "hex");
    // DOD-MSG-4 (2b): seal the ORDERING ENVELOPE (content + the relay's signed Structure2), not bare
    // content, so the parked entry is self-ordering on recover. The relay still holds only ciphertext.
    const ciphertext = sealToRecipient(recipientPubkey, sessionNodeManager.encodeParkEnvelope(content, structure1Cbor, structure2Cbor));
    const client = new ContentParkClient({ relayPeerId, relayAddrs: [...relayAddrs], logger });
    const res = await client.deposit(node, {
      recipientPubkey,
      contentHash: Buffer.from(contentHashHex, "hex"),
      sessionId: Buffer.from(sessionId, "hex"),
      ciphertext,
    });
    if (res.ok) {
      logger.info("content.park.deposited", { sessionId, contentHash: contentHashHex, recipientPubkey: recipientPubkeyHex.slice(0, 16) });
    } else {
      logger.warn("content.park.deposit.failed", { sessionId, contentHash: contentHashHex, reason: res.reason });
    }
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
    const ep = sessionNodeManager.getPersistedRelayEndpoint(entry.agentName, entry.sessionId);
    const record = sessionNodeManager.getSessionRecord(entry.agentName, entry.sessionId);
    if (!ep) return { parked: false, error: "no_persisted_relay_endpoint" };
    if (!record?.counterparty_pubkey) return { parked: false, error: "no_counterparty" };
    // DOD-LOOP-1: the re-park must originate from the session's OWNING agent (the original
    // sender), so use THAT agent's standing-receiver node — not "any" agent's. Post-DOD-LOOP-1 the
    // owning agent's SR exists only once it is online, which is why the native flush is
    // (re-)triggered per-agent on agent-online (see flushAwaitingContent / cello_start_agent), not
    // only at pre-IPC startup when no agent is online yet.
    const node = sessionNodeManager.getStandingReceiverNode(record.agent_name);
    if (!node) return { parked: false, error: "standing_receiver_unavailable" };
    const recipientPubkey = Buffer.from(record.counterparty_pubkey, "hex");
    // DOD-MSG-4 (2b): seal the envelope shape too (content only — the durable awaiting queue does not
    // persist the ordering record, so a crash-backstop re-park recovers in arrival order; the common
    // live-park path above carries the full Structure2). Keeps ONE envelope format on the recover side.
    const ciphertext = sealToRecipient(recipientPubkey, sessionNodeManager.encodeParkEnvelope(entry.contentBlob));
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
  // that agent is online. `filterAgent` scopes the drain to one agent's sessions on the agent-
  // online re-run; with no filter it attempts all (the pre-IPC pass / injected-target test path).
  async function flushAwaitingContent(filterAgent?: string): Promise<void> {
    const all = retryQueue.getAwaitingSessions();
    const sessions = filterAgent === undefined
      ? all
      : all.filter((s) => s.agentName === filterAgent);
    if (sessions.length === 0) return;
    const parkFn = config.contentParkFn ?? startupParkFn;
    if (!parkFn) {
      const pendingCount = sessions.reduce((n, s) => n + retryQueue.getAwaitingDepth(s.agentName, s.sessionId), 0);
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
        parkedTotal += await retryQueue.drainAwaitingToPark(s.agentName, s.sessionId, parkFn);
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
      ...(filterAgent !== undefined ? { agentName: filterAgent } : {}),
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
    // DOD-LOOP-1: tear down this agent's standing receiver (fire-and-forget, never throws out).
    void sessionNodeManager.removeStandingReceiverForAgent(name).catch(() => { /* best-effort */ });
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
      return { ok: false, reason: "missing_preauth_token", guidance: "Registration requires a 'preAuthToken' issued by the CELLO Operations Agent (Telegram). Obtain one, then retry cello_register." };
    }
    const keyProvider = keyProviders.get(name);
    if (!keyProvider) {
      return { ok: false, reason: "agent_not_found", guidance: `Agent '${name}' has no local K_local key loaded. Its key must exist at ~/.cello/agents/${name}/key before registration — create it and restart the daemon, then retry cello_register.` };
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

      // Multi-agent: register over THIS agent's own directory signaling stream (authed
      // as this agent), so the directory routes its dkg_complete/register_success back
      // to it. The primary agent reuses the keystone stream; any other agent gets a
      // dedicated one. The DKG's FROST streams open on this agent's directory node.
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
          guidance: `Agent '${name}' could not establish its directory signaling stream within 10s. Check CELLO_DIRECTORY_URL and that the directory is reachable, then retry cello_register.`,
        };
      }

      const persistence = new FileRegistrationPersistence({ agentDir: join(celloDir, "agents", name), logger });
      const ctx = new DaemonRegistrationContext({
        signaling: agentSignaling,
        getDirectoryNode: agentGetNode,
        getDirectoryEndpoint: () => directoryEndpoint,
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

  // DOD-LOOP-1: daemon-level seal bookkeeping is keyed by (agentName, sessionId), NOT sessionId
  // alone — two of the operator's agents can hold both ends of the same session_id on one daemon
  // (loopback), and each end seals independently. Keying by session_id alone would let A's close
  // block B's (false seal_interrupted_in_progress) and make their seal waiters collide.
  const sealKey = (agentName: string, sessionId: string): string => `${agentName}\x1f${sessionId}`;

  // M7-SESSION-001: tracks seal-interrupted flows currently in progress.
  // Prevents duplicate concurrent seal-interrupted attempts for the same (agent, session) (AC-011).
  const sealInterruptedInProgress = new Set<string>();

  // M7 DOD-SPINE-7: relay-mediated bilateral seal. cello_close_session registers a waiter
  // per session_id (hex); the directory's session_sealed frame — delivered over the agent's
  // signaling stream after FROST notarization, once BOTH parties have submitted their SEAL
  // ctrl leaf — resolves it with the sealed_root.
  // M7-SESSION-004: the bilateral seal resolves with the sealed_root AND the legibility
  // certificate (receipt-not-assent, per-party frontiers, attestation modes, final_message).
  type SealCompletion = { rootHex: string; legibility?: unknown };
  const pendingSealWaiters = new Map<string, (completion: SealCompletion) => void>();

  // M7 DOD-SPINE-7: register the session_sealed completion handler on a signaling seam (keystone
  // for the primary agent, per-agent for the rest — the directory routes session_sealed to the
  // session-owning agent's authenticated stream). Function declaration so getAgentSignaling
  // (defined earlier, called at runtime) can wire it per-agent.
  function registerSessionSealedListener(signaling: SignalingManager, agentName: string, agentPubkeyHex: string): () => void {
    return signaling.registerInboundHandler((frame) => {
      if (frame["type"] !== "session_sealed") return;
      const sidHex = frameValueToHex(frame["session_id"]);
      const rootHex = frameValueToHex(frame["sealed_root"]);
      if (!sidHex || !rootHex) return;
      void (async () => {
        const toU8 = (v: unknown): Uint8Array | null =>
          v instanceof Uint8Array ? v : Buffer.isBuffer(v) ? new Uint8Array(v as Buffer) : null;

        // M7 legibility-TBS-binding: when THIS party is the seal's signer (the initiator, whose
        // group key produced the FROST signature), verify the signature over the legibility-bound
        // TBS. A tampered legibility (answered / content_frontier_seq / attestation_mode, carried
        // unsigned on the frame) changes the hash → the signature fails → the seal is REJECTED. The
        // non-initiator does not hold the signer's key, so it accepts (verified:false): the frame
        // arrived over the authenticated Noise channel, and the binding lets any out-of-band holder
        // of the initiator's primary verify an exported cert.
        if (frame["signature_type"] === "frost") {
          const sessionIdBytes = toU8(frame["session_id"]);
          const sealedRootBytes = toU8(frame["sealed_root"]);
          const frostSig = toU8(frame["frost_signature"]);
          const signerPubkey = toU8(frame["signer_pubkey"]);
          const leafCount = typeof frame["leaf_count"] === "number" ? frame["leaf_count"] : null;
          const ctRaw = frame["close_timestamp"];
          const closeTs = typeof ctRaw === "number" ? ctRaw : typeof ctRaw === "bigint" ? Number(ctRaw) : null;
          if (!sessionIdBytes || !sealedRootBytes || !frostSig || !signerPubkey || leafCount === null || closeTs === null) {
            logger.error("session.sealed.signature.invalid", { sessionId: sidHex, reason: "missing_certificate_fields" });
            return;
          }
          const record = sessionNodeManager.getSessionRecord(agentName, sidHex);
          const verdict = await verifyBilateralSealCertificate(
            { agentDir: join(celloDir, "agents", agentName), agentPubkeyHex, logger, counterpartyPrimaryHex: record?.counterparty_primary_pubkey ?? null },
            {
              sessionId: sessionIdBytes,
              sealedRoot: sealedRootBytes,
              leafCount,
              closeTimestamp: closeTs,
              frostSignature: frostSig,
              signerPubkey,
              signatureType: "frost",
              legibility:
                frame["legibility"] && typeof frame["legibility"] === "object"
                  ? (frame["legibility"] as LegibilityForHash)
                  : null,
            },
          );
          if (!verdict.ok) {
            // tamper-evidence: do NOT mark sealed, do NOT resolve the waiter as success.
            logger.error("session.sealed.signature.invalid", { sessionId: sidHex, reason: verdict.reason });
            return;
          }
          logger.info("session.sealed.signature.checked", { sessionId: sidHex, verified: verdict.verified });
        }

        // M7-SESSION-004 (AC-005): normalise the wire legibility (Uint8Array pubkeys → hex) into a
        // JSON-safe certificate and persist it with the sealed record so it survives a restart and
        // is readable via cello_get_sealed_receipt — receipt-not-assent, per-party frontiers,
        // attestation modes, and final_message.answered.
        const legibility = normalizeLegibility(frame["legibility"]);
        logger.info("session.sealed.received", {
          sessionId: sidHex,
          sealedRoot: rootHex,
          hasLegibility: legibility !== undefined,
          finalMessageAnswered:
            legibility && typeof legibility === "object" && "final_message" in legibility
              ? (legibility as { final_message?: { answered?: boolean } }).final_message?.answered
              : undefined,
        });
        // DOD-LEG-2 (SI-002): independently re-derive each party's content_frontier_seq from the
        // signed leaves the directory shipped, and REJECT the certificate if any published frontier
        // is inflated beyond what the signed leaves support. The client does NOT trust the directory
        // for the frontier VALUE — only for transporting signed bytes it re-checks itself. When no
        // frontier_leaves are present (a pre-LEG-2 directory), the guard is skipped (backward-compat).
        const frontierLeavesRaw = frame["frontier_leaves"];
        if (legibility !== undefined && Array.isArray(frontierLeavesRaw) && frontierLeavesRaw.length > 0) {
          const toU8 = (v: unknown): Uint8Array => (v instanceof Uint8Array ? v : new Uint8Array(v as ArrayLike<number>));
          const leaves: SealFrontierLeaf[] = frontierLeavesRaw.map((l) => {
            const o = l as Record<string, unknown>;
            return {
              structure1_cbor: toU8(o["structure1_cbor"]),
              sender_pubkey: toU8(o["sender_pubkey"]),
              sender_signature: toU8(o["sender_signature"]),
            };
          });
          const rederived = reDeriveFrontiers(leaves);
          if (!rederived.ok) {
            logger.error("seal.certificate.frontier.unverifiable", { sessionId: sidHex, reason: rederived.reason });
            return;
          }
          const participants =
            (legibility as { participants?: Array<{ pubkey: string; content_frontier_seq: number }> }).participants ?? [];
          const inflated = findInflatedFrontier(participants, rederived.frontiers);
          if (inflated) {
            // The directory published a frontier higher than the signed leaves support — refuse the
            // seal (do NOT persist, do NOT resolve the close as success), exactly like a bad signature.
            logger.error("seal.certificate.frontier.unverifiable", {
              sessionId: sidHex,
              party: inflated.party,
              publishedFrontier: inflated.publishedFrontier,
              derivedFrontier: inflated.derivedFrontier,
            });
            return;
          }
          logger.info("seal.certificate.frontier.verified", {
            sessionId: sidHex,
            parties: participants.length,
          });
        }

        if (legibility !== undefined) {
          try {
            sessionNodeManager.recordSealCertificate(agentName, sidHex, rootHex, JSON.stringify(legibility));
          } catch (error) {
            logger.warn("seal.certificate.persist.failed", {
              sessionId: sidHex,
              reason: error instanceof Error ? error.message : String(error),
            });
          }
        }
        const waiter = pendingSealWaiters.get(sealKey(agentName, sidHex));
        if (waiter) {
          pendingSealWaiters.delete(sealKey(agentName, sidHex));
          waiter({ rootHex, legibility });
        }
        // Mark the session sealed + tear the node down (idempotent — safe if already gone).
        void sessionNodeManager.destroySessionNode(agentName, sidHex, "sealed");
      })();
    });
  }

  // SESSION-002 (DOD-SEAL): cello_close_session escalates to a UNILATERAL seal when the
  // counterparty never co-closes. The waiter is resolved by the seal_unilateral_confirmed
  // listener AFTER it verifies the certificate signature (channel-independent), or by
  // seal_unilateral_too_early (grace not elapsed). Keyed by session_id hex.
  type UnilateralResult = { ok: true; sealedRootHex: string } | { ok: false; reason: string };
  const pendingUnilateralWaiters = new Map<string, (r: UnilateralResult) => void>();

  // SESSION-002: per-agent listener for the unilateral certificate. Verifies the FROST
  // signature over the rebuilt TBS against the agent's own primary_pubkey BEFORE resolving
  // the close as sealed (SI-003: a channel-swapped sealed_root fails the signature check).
  function registerUnilateralConfirmedListener(
    signaling: SignalingManager,
    agentName: string,
    agentPubkeyHex: string,
  ): () => void {
    return signaling.registerInboundHandler((frame) => {
      const ftype = frame["type"];
      if (ftype !== "seal_unilateral_confirmed" && ftype !== "seal_unilateral_too_early") return;
      const sidHex = frameValueToHex(frame["session_id"]);
      if (!sidHex) return;
      const waiter = pendingUnilateralWaiters.get(sidHex);
      if (!waiter) return;

      if (ftype === "seal_unilateral_too_early") {
        pendingUnilateralWaiters.delete(sidHex);
        waiter({ ok: false, reason: "seal_unilateral_too_early" });
        return;
      }

      void (async () => {
        const toU8 = (v: unknown): Uint8Array | null =>
          v instanceof Uint8Array ? v : Buffer.isBuffer(v) ? new Uint8Array(v as Buffer) : null;
        const sessionId = toU8(frame["session_id"]);
        const sealedRoot = toU8(frame["sealed_root"]);
        const frostSig = toU8(frame["frost_signature"]);
        const leafCount = typeof frame["leaf_count"] === "number" ? frame["leaf_count"] : null;
        const tsRaw = frame["close_timestamp"];
        const closeTs = typeof tsRaw === "number" ? tsRaw : typeof tsRaw === "bigint" ? Number(tsRaw) : null;
        const sigType = frame["signature_type"];
        if (!sessionId || !sealedRoot || !frostSig || leafCount === null || closeTs === null ||
            (sigType !== "frost" && sigType !== "single")) {
          logger.warn("session.unilateral.certificate.invalid", { sessionId: sidHex, reason: "malformed_certificate" });
          pendingUnilateralWaiters.delete(sidHex);
          waiter({ ok: false, reason: "malformed_certificate" });
          return;
        }
        const result = await verifyUnilateralCertificate(
          { agentDir: join(celloDir, "agents", agentName), agentPubkeyHex, logger },
          { sessionId, sealedRoot, leafCount, closeTimestamp: closeTs, frostSignature: frostSig, signatureType: sigType },
        );
        pendingUnilateralWaiters.delete(sidHex);
        if (!result.ok) {
          // SI-003: do NOT mark sealed when the certificate signature does not verify.
          logger.warn("session.unilateral.certificate.invalid", { sessionId: sidHex, reason: result.reason, signatureType: sigType });
          waiter({ ok: false, reason: `certificate_invalid:${result.reason}` });
          return;
        }
        logger.info("session.unilateral.certificate.verified", { sessionId: sidHex, signatureType: sigType, party: "present" });
        void sessionNodeManager.destroySessionNode(agentName, sidHex, "sealed");
        waiter({ ok: true, sealedRootHex: Buffer.from(sealedRoot).toString("hex") });
      })();
    });
  }

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
  // NOTE: cello_await_session is NOT in this stub list — Seam 2 registers a real
  // handler for it below (inbound session establishment), with its own inline
  // no_current_agent guard.
  const SESSION_TOOLS_REQUIRING_AGENT = [
    "cello_receive_session",
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
    if (!connState || !connState.currentAgent) {
      return NO_CURRENT_AGENT_RESPONSE;
    }
    const agentName = connState.currentAgent;
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
    if (!connState || !connState.currentAgent) {
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

    // DOD-LOOP-1: scope the lookup to the current agent — the composite (agent, session_id) key IS
    // the ownership scope. A session_id owned only by a DIFFERENT agent does not exist in this
    // agent's namespace (returns null → session_not_found), which is correct for loopback (two
    // agents can hold the same session_id on one daemon).
    const record = sessionNodeManager.getSessionRecord(connState.currentAgent, sessionId);
    if (!record) {
      return {
        ok: false,
        reason: "session_not_found",
        guidance: "No session found with this ID. Check cello_list_sessions for active and interrupted sessions.",
      };
    }

    // Ownership: redundant now that the lookup is agent-scoped (record.agent_name === currentAgent),
    // kept as a defensive invariant.
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
    if (sealInterruptedInProgress.has(sealKey(record.agent_name, sessionId))) {
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
      try {
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
          // M7-SESSION-004 (AC-006): return the legibility certificate on the seal completion so
          // a reader gets it on the same surface that proves the seal — receipt-not-assent,
          // per-party frontiers, attestation modes, and final_message.answered.
          return { ok: true, sealed_root: sealedCompletion.rootHex, legibility: sealedCompletion.legibility };
        }

        // M7-UPGRADE-002: if THIS close fell through via the auto-ack 'already submitted' path, we
        // hold no local reported_root to escalate with — and we should not need to: the
        // counterparty's SEAL ctrl leaf is what triggered our auto-ack, so its seal is already on
        // the relay and the bilateral seal should finalize. A timeout here is unexpected; report it
        // as pending rather than escalating to a unilateral seal with no root.
        if (!submit.ok) {
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
        const sent = await signalingManager.sendRaw({
          type: "seal_unilateral",
          session_id: new Uint8Array(Buffer.from(sessionId, "hex")),
          reported_root: new Uint8Array(Buffer.from(submit.reportedRootHex, "hex")),
          reported_seq: submit.sequenceNumber,
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
          return { ok: true, sealed_root: uniResult.sealedRootHex, seal_type: "unilateral" };
        }
        if (uniResult.reason === "seal_unilateral_too_early") {
          return {
            ok: false,
            reason: "seal_counterparty_pending",
            guidance: "Your SEAL leaf is recorded, but the counterparty has not closed and the directory's delivery-grace window has not yet elapsed, so a unilateral seal is not yet allowed. Retry cello_close_session after the grace period, or once the counterparty closes.",
          };
        }
        return {
          ok: false,
          reason: uniResult.reason,
          guidance: "The unilateral seal did not complete (the directory could not verify the reported root, or the certificate failed verification). Confirm your messages reached the relay (cello_list_sessions) before retrying cello_close_session.",
        };
      } finally {
        sealInterruptedInProgress.delete(sealKey(record.agent_name, sessionId));
      }
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
      return { ok: false, reason: "missing_session_id", guidance: "Provide the session_id (hex) of the sealed session. Check cello_list_sessions for sealed sessions." };
    }
    // DOD-LOOP-1: the certificate is keyed by (agent, session_id) — read the current agent's.
    const connState = perConnectionState.get(connectionId);
    if (!connState || !connState.currentAgent) {
      return NO_CURRENT_AGENT_RESPONSE;
    }
    const cert = sessionNodeManager.getSealCertificate(connState.currentAgent, sessionId);
    if (!cert) {
      return {
        ok: false,
        reason: "sealed_receipt_not_found",
        guidance: "No sealed certificate is recorded for this session. It may not be sealed yet, or the session_id is wrong — close it with cello_close_session and confirm it reports sealed, then retry.",
      };
    }
    return { ok: true, session_id: sessionId, sealed_root: cert.sealed_root, legibility: cert.legibility };
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
    const agentName = (params?.agentName as string | undefined)
      ?? perConnectionState.get(connectionId)?.currentAgent ?? "";
    retryQueue.enqueueAwaitingContent(agentName, sessionId, Buffer.from(contentHashHex, "hex"), Buffer.from(contentHex, "hex"));
    return { queued: true, awaitingDepth: retryQueue.getAwaitingDepth(agentName, sessionId) };
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
      ?? perConnectionState.get(connectionId)?.currentAgent ?? "";
    retryQueue.markContentAcked(agentName, sessionId, Buffer.from(contentHashHex, "hex"));
    return { acked: true, awaitingDepth: retryQueue.getAwaitingDepth(agentName, sessionId) };
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
  ): Promise<{ ok: true; recovered: number; pulled: number } | { ok: false; reason: string }> {
    const kp = keyProviders.get(recipientAgent.name);
    if (!kp) return { ok: false, reason: "signing_key_unavailable" };
    if (!kp.openContentSeal) return { ok: false, reason: "cannot_unseal" };
    const node = sessionNodeManager.getStandingReceiverNode();
    if (!node) return { ok: false, reason: "standing_receiver_unavailable" };
    const recipientPubkey = recipientAgent.pubkey ?? "";
    const client = new ContentParkClient({ relayPeerId, relayAddrs, logger });
    const entries = await client.pull(node, Buffer.from(recipientPubkey, "hex"), kp);
    let recovered = 0;
    for (const e of entries) {
      const unsealed = await kp.openContentSeal(e.ciphertext);
      if (!unsealed) {
        logger.warn("content.recover.unseal_failed", { sessionId: e.sessionIdHex, contentHash: e.contentHashHex });
        continue;
      }
      // DOD-MSG-4 (2b): the unsealed blob is the ordering envelope (content + the relay's signed
      // Structure2). Extract the content; if the record is present, verify it and feed the strict-in-
      // order gate the canonical sequence BEFORE ingest — so recovered messages order the same way a
      // direct frame does (closes review finding #3). Old/bare-content seals decode to content alone.
      const env = sessionNodeManager.decodeParkEnvelope(unsealed);
      const contentHashBytes = Buffer.from(e.contentHashHex, "hex");
      if (env.structure1Cbor && env.structure2Cbor) {
        sessionNodeManager.recordOrderingRecord(recipientAgent.name, e.sessionIdHex, env.structure1Cbor, env.structure2Cbor, contentHashBytes);
      }
      const ingest = sessionNodeManager.ingestReceivedContent(recipientAgent.name, e.sessionIdHex, env.content, contentHashBytes);
      if (ingest.ok && ingest.held) {
        // DOD-MSG-4 (review finding #4): a held entry is NOT yet an appended leaf — its sequence is
        // the FUTURE canonical index, not a completed recovery. Do not count it as recovered; log it
        // distinctly so the tally reflects leaves actually written, not content still queued in memory.
        logger.info("content.recover.held", { sessionId: e.sessionIdHex, contentHash: e.contentHashHex, canonicalSeq: ingest.sequenceNumber });
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
        logger.warn("content.recover.ingest_failed", { sessionId: e.sessionIdHex, contentHash: e.contentHashHex, reason: ingest.reason });
      }
    }
    return { ok: true, recovered, pulled: entries.length };
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
    // Review #2: emit the completion event UNCONDITIONALLY (not only when total > 0) so a clean
    // "nothing parked" run is observable and distinct from an all-failed run.
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

  // ─── Seam 2: inbound session establishment (counterparty side) ─────────────
  //
  // When agent A initiates a session, the directory FROST-signs a SessionAssignment
  // and PUSHES it to the counterparty B over B's directory signaling stream (an
  // unsolicited `session_assignment` frame). The daemon turns that frame into a live
  // inbound session: it resolves which local agent is participant_b, calls
  // SessionNodeManager.acceptSession (which hands off the standing receiver node bound
  // to A's session peer id), and enqueues an inbound session event that a blocked
  // cello_await_session call returns. This is the inbound mirror of cello_initiate_session.
  //
  // Reference (Option A native re-home): the dead client stack did this in
  // core/client/src/frame-dispatch.ts (session_assignment → receiveSessionAssignment)
  // and core/adapter-claude-code/src/server.ts (sessionEventQueue + cello_await_session).
  // We reimplement natively here — the daemon never imports @cello-protocol/client.
  interface InboundSessionEvent {
    sessionIdHex: string;
    counterpartyPubkeyHex: string;
    genesisPrevRootHex: string;
  }
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
    q.push(event);
    inboundSessionQueues.set(agentName, q);
  }

  // CBOR-decoded byte fields arrive as Uint8Array or Buffer; a field may also already be
  // a hex string. Hex strings are lowercased so the case-sensitive agent-pubkey match
  // (agents store lowercase hex) cannot silently miss (review L2).
  function frameValueToHex(v: unknown): string | null {
    if (v instanceof Uint8Array) return Buffer.from(v).toString("hex");
    if (Buffer.isBuffer(v)) return Buffer.from(v as Buffer).toString("hex");
    if (typeof v === "string") return v.toLowerCase();
    return null;
  }
  // M7-SESSION-004 (AC-005): normalise the wire `legibility` object — CBOR-decoded, so pubkeys
  // arrive as Uint8Array/Buffer — into a JSON-safe certificate with hex-encoded pubkeys. Returns
  // undefined for an absent or structurally-implausible object (pre-M7 frame, or a malformed
  // field), in which case nothing is persisted and the seal still completes. The receipt-not-
  // assent constants (attests/implies_assent/disclaimer) and the integers/booleans are carried
  // verbatim; only the byte fields are re-encoded. The daemon never invents or alters the
  // certificate's meaning — it is the directory's derivation, surfaced.
  function normalizeLegibility(raw: unknown): unknown | undefined {
    if (!raw || typeof raw !== "object") return undefined;
    const o = raw as Record<string, unknown>;
    if (o["attests"] !== "receipt") return undefined;
    const participantsRaw = o["participants"];
    const finalRaw = o["final_message"];
    if (!Array.isArray(participantsRaw) || !finalRaw || typeof finalRaw !== "object") return undefined;
    // Review finding (low): the disclaimer is the human-readable half of the receipt-not-assent
    // property; a non-string value means a malformed/tampered frame, so REJECT the whole cert
    // rather than surfacing an empty disclaimer (implies_assent:false alone is the machine-readable
    // half, but we do not surface a half-formed certificate).
    if (typeof o["disclaimer"] !== "string" || o["disclaimer"].length === 0) return undefined;
    // Review finding (low): validate attestation_mode against the closed enum — never surface an
    // arbitrary string from a malformed frame on the cert read surface (defensive parity with the
    // coerced fields). An out-of-enum value rejects the whole cert.
    const VALID_MODES = new Set(["live", "recovered", "absent"]);
    const participants: Array<{
      pubkey: string | null; content_frontier_seq: number | null; last_authored_seq: number | null; attestation_mode: string;
    }> = [];
    for (const p of participantsRaw) {
      const pp = p as Record<string, unknown>;
      const mode = pp["attestation_mode"];
      if (typeof mode !== "string" || !VALID_MODES.has(mode)) return undefined;
      participants.push({
        pubkey: frameValueToHex(pp["pubkey"]),
        content_frontier_seq: typeof pp["content_frontier_seq"] === "number" ? pp["content_frontier_seq"] : null,
        last_authored_seq: typeof pp["last_authored_seq"] === "number" ? pp["last_authored_seq"] : null,
        attestation_mode: mode,
      });
    }
    const fm = finalRaw as Record<string, unknown>;
    const final_message = {
      sender_pubkey: frameValueToHex(fm["sender_pubkey"]),
      seq: typeof fm["seq"] === "number" ? fm["seq"] : null,
      answered: fm["answered"] === true,
    };
    return {
      attests: "receipt" as const,
      implies_assent: false as const,
      disclaimer: o["disclaimer"],
      participants,
      final_message,
    };
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
        sessionTimestamp: number;
        signatureType: string | null;
        signerPubkeyHex: string | null;
        relayPeerId: string;
        relayAddrs: string[];
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
    return {
      sessionIdHex,
      participantAPubkeyHex,
      participantBPubkeyHex,
      initiatorPeerId:
        typeof a["initiator_session_peer_id"] === "string" ? a["initiator_session_peer_id"] : "",
      sessionTimestamp: typeof a["session_timestamp"] === "number" ? a["session_timestamp"] : 0,
      signatureType: typeof a["signature_type"] === "string" ? a["signature_type"] : null,
      // M7 legibility-TBS-binding (responder verify): the FROST-signed assignment embeds the
      // initiator's primary (group) pubkey as `signer_pubkey` — the key that signs the seal.
      // The responder stores it so it can verify the bilateral seal signature locally, not just
      // accept it (session.ts: "embedded so the counterparty can verify").
      signerPubkeyHex: a["signer_pubkey"] !== undefined ? frameValueToHex(a["signer_pubkey"]) : null,
      relayPeerId,
      relayAddrs,
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
      enqueueInboundSession(agentName, {
        sessionIdHex: parsed.sessionIdHex,
        counterpartyPubkeyHex: parsed.participantAPubkeyHex,
        genesisPrevRootHex,
      });
      notificationDispatcher.dispatchSessionStateChanged(
        agentName,
        parsed.sessionIdHex,
        "created",
        parsed.participantAPubkeyHex,
      );
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
    // seam tests inject trusted frames. This is logged loudly, never silent.
    logger.warn("session.inbound.assignment.unverified", {
      sessionId: parsed.sessionIdHex,
      agentName: localAgent.name,
      note: "FROST assignment signature verification deferred to SESSION-004 re-home",
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

  signalingManager.registerInboundHandler((frame) => {
    if (frame["type"] !== "session_assignment") return;
    handleInboundSessionAssignment(frame);
  });

  // M7 DOD-SPINE-7: session_sealed listener. The directory delivers this over the SESSION-OWNING
  // agent's signaling stream after the relay-mediated bilateral seal notarizes. Registered on the
  // keystone (primary agent) here AND per-agent in getAgentSignaling — for a non-primary agent the
  // directory routes session_sealed to its per-agent stream, so a keystone-only listener would
  // leave that agent's close waiter unresolved (reviewer finding). Resolve the close waiter with
  // the sealed_root and mark the session sealed. Guarded on primaryAgent: the keystone listener now
  // needs the primary agent's name/pubkey to verify the seal signature (legibility-TBS-binding), and
  // with no agents there are no keystone sessions to seal anyway.
  if (primaryAgent) {
    registerSessionSealedListener(signalingManager, primaryAgent.name, primaryAgent.pubkey);
    // SESSION-002: the keystone counterpart for the unilateral certificate listener — the
    // primary agent closes over the keystone stream, so the directory routes its
    // seal_unilateral_confirmed there (mirrors the session_sealed keystone listener above).
    registerUnilateralConfirmedListener(signalingManager, primaryAgent.name, primaryAgent.pubkey);
  }

  // cello_await_session — the counterparty's blocking pull for the next inbound session.
  // Returns immediately if one is already queued for the current agent (FIFO), otherwise
  // blocks until one arrives or timeout_ms elapses. Response shape matches the established
  // contract (core/adapter-claude-code/src/server.ts) so the E2E fixture migration is drop-in.
  handlers.set("cello_await_session", async (params, connectionId) => {
    const connState = perConnectionState.get(connectionId);
    if (!connState || !connState.currentAgent) {
      return NO_CURRENT_AGENT_RESPONSE;
    }
    const agentName = connState.currentAgent;
    const timeoutMs = typeof params?.["timeout_ms"] === "number" ? (params["timeout_ms"] as number) : 30_000;

    const toResponse = (e: InboundSessionEvent) => ({
      type: "new_session",
      session_id: e.sessionIdHex,
      counterparty_pubkey: e.counterpartyPubkeyHex,
      genesis_prev_root: e.genesisPrevRootHex,
    });

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
    const reloadedTree = sessionNodeManager.getSessionTree(record.agent_name, sessionId);
    const hasOwnTree = reloadedTree.size() > 0;
    const ownLeafCount = hasOwnTree ? reloadedTree.size() : (record.message_count ?? 0);
    const effectiveRoot = hasOwnTree
      ? sessionNodeManager.getSessionTreeRootHex(record.agent_name, sessionId)
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
        agentName: record.agent_name,
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
  // round-2 [medium]: the IPC return status MUST match the persisted row. The
  // active-seal flow advances the session to 'seal_interrupted_pending' (the same
  // non-terminal bilateral-commitment state the interrupted flow uses); returning
  // a distinct 'seal_initiated' here meant the close response and a subsequent
  // cello_status / cello_list_sessions showed two names for one state. One name.
  type ActiveSealResult =
    | { ok: true; sessionId: string; status: "seal_interrupted_pending"; rootHex: string }
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
    const ownRootHex = sessionNodeManager.getSessionTreeRootHex(record.agent_name, sessionId);
    const leafCount = sessionNodeManager.getSessionTree(record.agent_name, sessionId).size();
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
      agentName: record.agent_name,
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

    // round-2 finding #5: the session is now frozen at 'seal_interrupted_pending'.
    // Retire its live libp2p node so no further inbound content can arrive (which
    // ingestReceivedContent now also rejects) and so the node is not leaked per
    // active close. retireSessionNode stops the node WITHOUT changing the DB status.
    await sessionNodeManager.retireSessionNode(record.agent_name, sessionId);

    return { ok: true, sessionId, status: "seal_interrupted_pending", rootHex: ownRootHex };
  }

  // ─── CELLO-M7-DAEMON-004: cello_send (live send + daemon-owned tree append) ──
  handlers.set("cello_send", async (params, connectionId) => {
    const connState = perConnectionState.get(connectionId);
    if (!connState || !connState.currentAgent) return NO_CURRENT_AGENT_RESPONSE;

    // round-2 BLOCKING: read the snake_case public field cello-mcp.ts actually sends.
    const sessionId = params?.session_id as string | undefined;
    const contentStr = typeof params?.content === "string" ? params.content : undefined;
    if (!sessionId || contentStr === undefined) {
      return { ok: false, reason: "missing_params", guidance: "Provide 'session_id' (hex) and 'content' (string) parameters." };
    }

    // DOD-LOOP-1: the (agent, session_id) lookup is itself the ownership scope.
    const record = sessionNodeManager.getSessionRecord(connState.currentAgent, sessionId);
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

    // CELLO-M7-MSG-001 (AC-013/AC-018/AC-021): enforce the 1 MB application content cap
    // BEFORE any transmission or hash/leaf production. This replaces the silent oversize
    // decode-failure → desync: the send is rejected with a distinct, diagnosable reason
    // and actionable guidance; no content frame is transmitted, no leaf is appended, and
    // the session stays usable.
    if (contentBytes.length > MAX_CONTENT_BYTES) {
      logger.warn("content.rejected.too_large", {
        sessionId,
        contentSize: contentBytes.length,
        cap: MAX_CONTENT_BYTES,
        correlationId,
      });
      return {
        ok: false,
        reason: "content_too_large",
        guidance: `This message is ${contentBytes.length} bytes, over the ${MAX_CONTENT_BYTES}-byte (1 MB) per-message content cap. Split it into multiple messages each under the cap, or use the large-object/file transfer path for large payloads (not cello_send). Nothing was sent and the session is still active — retry with smaller content.`,
      };
    }

    const contentHash = createHash("sha256").update(new Uint8Array([0x00])).update(contentBytes).digest();
    const contentHashHex = Buffer.from(contentHash).toString("hex");
    const recipientPubkey = record.counterparty_pubkey;

    const sendResult = await sessionNodeManager.sendContent(record.agent_name, sessionId, contentBytes, new Uint8Array(contentHash), correlationId);
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
    const { leafIndex, newRootHex } = sessionNodeManager.appendSessionLeaf(record.agent_name, sessionId, "msg", contentHashHex, correlationId);
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

    // round-2 BLOCKING: read the snake_case public field cello-mcp.ts actually sends.
    const sessionId = params?.session_id as string | undefined;
    if (!sessionId) {
      return { ok: false, reason: "missing_params", guidance: "Provide 'session_id' (hex) to receive content for a specific session." };
    }
    const record = sessionNodeManager.getSessionRecord(connState.currentAgent, sessionId);
    if (!record) {
      return { ok: false, reason: "session_not_found", guidance: "No session found with this ID. Check cello_list_sessions." };
    }
    if (record.agent_name !== connState.currentAgent) {
      return { ok: false, reason: "session_not_owned", guidance: "This session belongs to a different agent. Call cello_use_agent to switch to the agent that owns it, then retry." };
    }

    const entry = sessionNodeManager.takeReceivedContent(connState.currentAgent, sessionId);
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

  // M7-MANIFEST-002 / DOD-AUTH-2: background manifest polling is now ACTIVE. The keystone
  // SignalingManager (constructed above with the poll deps) calls startPolling() when its
  // stream reaches connected — it re-polls the directory on the randomized 6–12h interval
  // and adopts a newer signed manifest (handleManifestPollResponse). No separate wiring
  // needed here; poll lifecycle = the keystone connection lifecycle.

  // Graceful shutdown
  async function stop(reason: string): Promise<void> {
    // Cancel any pending manifest poll timer
    if (manifestPollScheduler) {
      manifestPollScheduler.cancel();
    }
    logger.info("daemon.stopped", { pid: process.pid, reason });
    // Stop SignalingManager (flushes pending ops with shutdown error, cancels reconnect loop)
    await signalingManager.stop();
    // Stop every per-agent signaling stream too (multi-agent), so no agent's directory
    // node / reconnect loop is orphaned past shutdown.
    for (const entry of perAgentSignaling.values()) {
      await entry.signaling.stop();
    }
    // Gracefully mark active sessions interrupted (AC-009) before stopping IPC
    await sessionNodeManager.gracefulShutdown();
    await ipcServer.stop();
    await removeLock(lockFilePath, logger);
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

  return { stop, getStatus, getSessionNodeManager, getDirectoryNode, getTransportSelector, getAutoNatService };
}
