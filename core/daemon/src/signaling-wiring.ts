/**
 * One directory signaling stream per agent, authenticated as that agent.
 *
 * The directory routes EVERY frame — `dkg_complete`, `register_success`, an inbound
 * `session_assignment`, a seal — by the pubkey that authenticated the stream it arrived on. So each
 * agent must hold its own; there is no shared connection borrowing one agent's identity. The single
 * shared manager that appears below exists only for the in-process test path.
 *
 * ⚠️ FOURTEEN DEPENDENCIES, TWO OVER THE ORDER'S BOUND, RECORDED. Every one is reached by
 * `getAgentSignaling`, which is not a lookup: for an agent with no manager it CONSTRUCTS one, and
 * that construction is where registration, inbound sessions, seals, the reconnect drain and the
 * submission retry queue all get wired. Splitting the file would split that constructor, and a
 * half-wired manager is the defect the CONN-001 comments below spend forty lines describing.
 *
 * ⚠️ THIS MODULE IS BUILT AFTER TWO OF ITS CONSUMERS ARE. `createSealFlows` (seal flows) and the
 * registration retry both take `signalingFor` / `sendOver` / `dropAgentSignaling`, and they are
 * constructed EARLIER in the boot sequence than this. As function declarations inside one function
 * that worked by hoisting; across a module boundary it cannot, so those three call sites now pass a
 * lambda that resolves through this module at CALL time. They are only ever invoked after boot, so
 * the indirection costs nothing — and it is the same shape unit 4 had to use for a scheduler built
 * after its consumer.
 */
import { SignalingManager } from "@cello-protocol/transport";
import type { CelloNode, IDirectoryChallengeVerifier } from "@cello-protocol/transport";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { LoadedAgent } from "./agent-loader.js";
import type { DirectorySignalingState, Logger } from "./types.js";
import type { DbRegistrationPersistence } from "./db-identity-store.js";
import type { ConsortiumEndpoint } from "./directory-bootstrap.js";
import type { DirectoryEndpoint } from "./signaling-connect.js";
import type { SubmissionRetryQueue } from "./submission-retry.js";
import type { SealFailureStore } from "./seal-failure-store.js";
import type { KeyProvider } from "@cello-protocol/crypto";
import { createSignalingConnect } from "./signaling-connect.js";
import { wireSessionCeremonyHandler, wireSessionOfferHandler, wireSealCeremonyHandler } from "./session-ceremony.js";
import { relayOnlyState } from "./relay-only.js";

/** One agent's directory stream and the libp2p node behind it. */
export interface AgentSignaling {
  signaling: SignalingManager;
  getNode: () => CelloNode | null;
}

export interface SignalingWiringDeps {
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  /** The LIVE registry — a manager is built for an agent created after boot without a restart. */
  loadedAgents: ReadonlyArray<LoadedAgent>;
  keyProviders: Map<string, KeyProvider>;
  /** Present ONLY on the in-process test path; undefined in production, where every agent dials. */
  sharedSignaling: SignalingManager | undefined;
  noSharedDirectoryNode: () => CelloNode | null;
  verifiedManifestVersion: number;
  getPersistence: (agentName: string) => DbRegistrationPersistence;
  onSignalingConnected: (agentName: string) => void | Promise<void>;
  resolveConsortiumRoster: () => Promise<ConsortiumEndpoint[] | null>;
  failoverEndpointResolver: (() => Promise<DirectoryEndpoint | null>) | undefined;
  /** Wired onto each new manager so a seal that arrives on it is heard. */
  registerSealListeners: (mgr: SignalingManager, agentName: string, agentPubkeyHex: string) => void;
  getFailoverEndpoint: () => Promise<{ peerId: string; multiaddr?: string } | null>;
  sealFailures: SealFailureStore;
  submissionRetries: SubmissionRetryQueue;
  challengeVerifier: IDirectoryChallengeVerifier | undefined;
  directoryEndpointResolver: (() => Promise<DirectoryEndpoint | null>) | undefined;
  /**
   * ⚠️ GETTERS, NOT VALUES, AND THE REASON IS THE DEFECT UNIT 4 SHIPPED. Both come from
   * `createInboundSessions`, constructed roughly 1,200 lines BELOW this wiring, so at construction
   * they do not exist. `getAgentSignaling` reads them only when it BUILDS a manager, which is always
   * later, so resolving at call time is both correct and the only thing that works. Passed by value
   * they would be `undefined` forever, and a non-primary agent would never receive an inbound session
   * on its own stream — the exact failure the CONN-001 block below exists to prevent.
   */
  getWirePerAgentSessionInbound: () => (mgr: SignalingManager, agentName: string) => void;
  getHandleTrustSignalPickup: () => (
    frame: Record<string, unknown>,
    keyProvider: KeyProvider,
    mgr: SignalingManager,
    agentName: string,
  ) => void | Promise<void>;
}

export function createSignalingWiring(deps: SignalingWiringDeps) {
  const {
    logger, sessionNodeManager, loadedAgents, keyProviders, sharedSignaling, noSharedDirectoryNode,
    verifiedManifestVersion, getPersistence, onSignalingConnected, resolveConsortiumRoster,
    failoverEndpointResolver, getFailoverEndpoint, sealFailures, submissionRetries,
    challengeVerifier, directoryEndpointResolver, registerSealListeners,
    getWirePerAgentSessionInbound, getHandleTrustSignalPickup,
  } = deps;

  // ─── Per-agent directory signaling (CONN-001: one signaling stream per agent) ──
  // CELLO-M7-CONN-001 (DOD-CONN-1): the directory routes EVERY signaling frame —
  // dkg_complete, register_success, inbound session_assignment, seal — by the pubkey that
  // AUTHENTICATED the stream it arrived on. So each agent MUST get its OWN directory stream,
  // authenticated as itself. There is no shared "keystone" connection borrowing one agent's
  // identity. In production every agent has its own manager (built below); the only shared
  // manager is the in-process test path's `sharedSignaling`. Managers are created lazily (on
  // first registration / online / create) and kept connected for the agent's directory presence.

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
      // DOD-M15-RELAYSLOTS-1: and the credential those relays require. Same frame, same cadence as
      // the endpoints above — every connect and every reconnect, which is what keeps a token that
      // expires within the hour current for a receiver that lives much longer than that.
      onOnlineToken: (token) => {
        sessionNodeManager.setDirectoryOnlineToken(agentName, token);
      },
      // Review M1: and when there is none, WHY — so the operator surface can say "this directory
      // does not know this agent" instead of "check your directory connection" about a connection
      // that just succeeded.
      onOnlineTokenAbsent: (reason) => {
        sessionNodeManager.setDirectoryOnlineTokenAbsent(agentName, reason);
      },
    });
    const mgr = new SignalingManager({
      connect,
      logger,
      maxReconnectAttempts: Number.MAX_SAFE_INTEGER,
      maxBackoffMs: 30_000,
      // Two things happen when this agent's directory signaling reaches 'connected' (the first
      // connect AND every reconnect after a drop), and the ORDER is the contract — see
      // reconnect-drain.ts.
      //
      // RE-REGISTER THE STANDING RECEIVER (2026-07-31 incident). The receiver's LIFETIME is tied to
      // this daemon; its REGISTRATION is tied to this stream, and the stream turns over roughly
      // every 70 seconds. ensureStandingReceiverForAgent ran only at agent start, so 46 of 48
      // reconnects in one hour left every agent unregistered — the directory then answers
      // `targetStreamFound: false` and a session request fails with `target_offline`, while
      // `cello status`, `agent.online` and the directory's own agent_presence all still report the
      // agent healthy. Only a daemon restart recovered it.
      //
      // THEN DRAIN (M8C-RELAYWAKE-1, "check relay on wakeup"): re-pull this agent's parked mailbox
      // from every relay it has session history with, so a message parked while signaling was down
      // is not left until the next agent start. The drain needs the node the ensure builds, which
      // is why it no longer runs beside it.
      //
      // AND THIRD, DOD-M15-ENDORSE-RETRY-1: re-send any sealed submission that reached no node.
      // Deliberately outside `createReconnectDrain`'s ensure→drain contract and after it: that
      // ordering exists because the drain needs the standing receiver the ensure rebuilds, and a
      // submission needs neither — it needs only the stream that just came up.
      onConnected: () => {
        onSignalingConnected(agentName);
        submissionRetries.onSignalingConnected(agentName);
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
      // DOD-M15-SEALWIRE-1 bullet 2 (review F1): the co-sign path must check the root before this
      // agent's key endorses it. Same predicate as the receiving path — one implementation, so the
      // two halves cannot drift about what a mismatch is.
      verifyCertifiedRoot: (pub, sid, root, leaves) => sessionNodeManager.verifyCertifiedRoot(pub, sid, root, leaves),
      keyProvider: agentKeyProvider,
      getNode: entry.getNode,
      getDirectoryEndpoint: getFailoverEndpoint,
      getConsortiumEndpoints: resolveConsortiumRoster,
      signaling: mgr,
      logger,
      // DOD-M15-SEALPARTIES-1: where a dead seal ceremony leaves its mark, so `cello_sealed_receipt`
      // can say it FAILED and why instead of falling through to "no receipt yet".
      recordSealFailure: (name: string, sid: string, reason: string) =>
        sealFailures.record(name, sid, reason, new Date().toISOString(), "unresolved"),
    });
    // DOD-SPINE-7: coordinate the SEAL FROST ceremony on this agent's stream too.
    wireSealCeremonyHandler({
      agentName,
      persistence: getPersistence(agentName),
      agentPubkeyHex,
      // DOD-M15-SEALWIRE-1 bullet 2 (review F1): the co-sign path must check the root before this
      // agent's key endorses it. Same predicate as the receiving path — one implementation, so the
      // two halves cannot drift about what a mismatch is.
      verifyCertifiedRoot: (pub, sid, root, leaves) => sessionNodeManager.verifyCertifiedRoot(pub, sid, root, leaves),
      keyProvider: agentKeyProvider,
      getNode: entry.getNode,
      getDirectoryEndpoint: getFailoverEndpoint,
      getConsortiumEndpoints: resolveConsortiumRoster,
      signaling: mgr,
      logger,
      // DOD-M15-SEALPARTIES-1: where a dead seal ceremony leaves its mark, so `cello_sealed_receipt`
      // can say it FAILED and why instead of falling through to "no receipt yet".
      recordSealFailure: (name: string, sid: string, reason: string) =>
        sealFailures.record(name, sid, reason, new Date().toISOString(), "unresolved"),
    });
    // DOD-SPINE-7: and resolve session_sealed for this agent's sessions on its own stream.
    registerSealListeners(mgr, agentName, agentPubkeyHex);
    // WIRE-002: answer the directory's session_offer on this agent's stream (advertise the
    // standing-receiver session endpoint so the assignment carries a reachable counterparty).
    wireSessionOfferHandler({
      agentName,
      getStandingReceiverEndpoint: () => sessionNodeManager.getStandingReceiverInfo(agentName),
      admitOfferedDialer: (peerId, sessionIdHex) => sessionNodeManager.admitOfferedDialer(agentName, peerId, sessionIdHex),
      // DOD-M15-RELAYONLY-1: lets the handler tell "no addresses because relay-only filtered them"
      // from "no addresses yet", which need opposite answers — a refusal, and the pre-existing path.
      isRelayOnly: () => relayOnlyState((key) => sessionNodeManager.getSetting(agentName, key), sessionNodeManager.hasDatabase()) !== "off",
      signaling: mgr,
      logger,
    });
    // CELLO-M8-TRUST-001: receive sealed trust signals pushed from the directory pickup queue on
    // THIS agent's stream. Open with k_local, verify the recomputed hash against the directory
    // anchor, store locally, then ACK (so the directory deletes the ciphertext). The daemon is the
    // ONLY party that can open the seal (SI-001); a hash mismatch is rejected without storing/ACKing.
    mgr.registerInboundHandler((frame) => {
      if (frame["type"] !== "trust_signal_pickup") return;
      void getHandleTrustSignalPickup()(frame as Record<string, unknown>, agentKeyProvider, mgr, agentName);
    });
    /**
     * DOD-M15-SEALPARTIES-1 Part 0: take the relay credential off `register_success`.
     *
     * `onOnlineToken` above catches every signaling auth and reconnect, and misses the one case that
     * matters most: a brand-new agent. Its daemon opens this very stream in order TO register (the
     * DKG runs over it), so the auth that created the stream happened while the directory still had
     * no profile for the key and correctly issued nothing. A healthy stream never re-authenticates,
     * so without this the agent holds no relay credential for the life of the daemon — no circuit
     * reservation, unwitnessed leaves, and a close that fails with `seal_persist_failed`.
     *
     * A frame with no token is left alone rather than clearing what is held: the directory that
     * issues here is the same one whose auth_ok issues, so overwriting a good token with an absence
     * would turn one directory's minting failure into a reachability outage the operator cannot
     * explain. The absence is already reported by the directory's own `online_token.failed`.
     */
    mgr.registerInboundHandler((frame) => {
      if (frame["type"] !== "register_success") return;
      const raw = frame["online_token"];
      const token = raw instanceof Uint8Array ? raw : Buffer.isBuffer(raw) ? new Uint8Array(raw) : undefined;
      if (token && token.length > 0) {
        sessionNodeManager.setDirectoryOnlineToken(agentName, token);
        logger.info("directory.online_token.received", { agentName, source: "register_success", bytes: token.length });
        return;
      }
      logger.warn("directory.online_token.absent", {
        agentName,
        source: "register_success",
        impact: "this agent just registered and was handed no relay online token, so no relay will " +
          "let it hold a circuit reservation until its directory signaling stream reconnects and " +
          "re-issues one. Until then it is reachable only over a direct connection, and a session " +
          "it does hold cannot get its leaves witnessed.",
      });
    });
    // CELLO-M7-CONN-001 (DOD-CONN-2): inbound session_assignment + seal_interrupted_request
    // on THIS agent's own stream, so a non-primary agent receives inbound sessions (SPINE-5).
    getWirePerAgentSessionInbound()(mgr, agentName);
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
      // DOD-M15-SEALWIRE-1 bullet 2 (review F1): gate the co-signature on the root check.
      verifyCertifiedRoot: (pub, sid, root, leaves) => sessionNodeManager.verifyCertifiedRoot(pub, sid, root, leaves),
      keyProvider: agent.keyProvider,
      getNode: noSharedDirectoryNode,
      getDirectoryEndpoint: getFailoverEndpoint,
      getConsortiumEndpoints: resolveConsortiumRoster,
      signaling: mgr,
      logger,
      // DOD-M15-SEALPARTIES-1: where a dead seal ceremony leaves its mark, so `cello_sealed_receipt`
      // can say it FAILED and why instead of falling through to "no receipt yet".
      recordSealFailure: (name: string, sid: string, reason: string) =>
        sealFailures.record(name, sid, reason, new Date().toISOString(), "unresolved"),
    });
    wireSealCeremonyHandler({
      agentName: agent.name,
      persistence: getPersistence(agent.name),
      agentPubkeyHex: agent.pubkey,
      // DOD-M15-SEALWIRE-1 bullet 2 (review F1): gate the co-signature on the root check.
      verifyCertifiedRoot: (pub, sid, root, leaves) => sessionNodeManager.verifyCertifiedRoot(pub, sid, root, leaves),
      keyProvider: agent.keyProvider,
      getNode: noSharedDirectoryNode,
      getDirectoryEndpoint: getFailoverEndpoint,
      getConsortiumEndpoints: resolveConsortiumRoster,
      signaling: mgr,
      logger,
      // DOD-M15-SEALPARTIES-1: where a dead seal ceremony leaves its mark, so `cello_sealed_receipt`
      // can say it FAILED and why instead of falling through to "no receipt yet".
      recordSealFailure: (name: string, sid: string, reason: string) =>
        sealFailures.record(name, sid, reason, new Date().toISOString(), "unresolved"),
    });
    wireSessionOfferHandler({
      agentName: agent.name,
      getStandingReceiverEndpoint: () => sessionNodeManager.getStandingReceiverInfo(agent.name),
      admitOfferedDialer: (peerId, sessionIdHex) => sessionNodeManager.admitOfferedDialer(agent.name, peerId, sessionIdHex),
      // DOD-M15-RELAYONLY-1 — see the note on the sibling call site above.
      isRelayOnly: () => relayOnlyState((key) => sessionNodeManager.getSetting(agent.name, key), sessionNodeManager.hasDatabase()) !== "off",
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

  return {
    perAgentSignaling,
    getAgentSignaling,
    waitForSignalingConnected,
    dropAgentSignaling,
    signalingFor,
    sendOver,
    directorySignalingStatus,
    stopAllSignaling,
  };
}
