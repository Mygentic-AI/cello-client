/**
 * The OUTBOUND session path: discovery, the session request, and cross-node setup.
 *
 * DOD-SPINE-5. The initiator asks the directory to find the counterparty, requests a session, and —
 * when the counterparty lives on a DIFFERENT directory node — opens a transient VISITING connection
 * to that node to broker the handshake.
 *
 * The visiting connection is the subtle part, and it has already produced one serious bug: it is a
 * fully authenticated stream, so the directory will drain its DURABLE notification queue down it.
 * Anything a home stream must handle, a visiting stream must handle too (see registerSealListeners,
 * which is why the seal listeners are a single bundle and not three separate registrations).
 */
import { SignalingManager, type CelloNode } from "@cello-protocol/transport";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { Logger } from "./types.js";
import type { DirectoryEndpoint } from "./signaling-connect.js";
import type { DbRegistrationPersistence } from "./db-identity-store.js";
import type { ConsortiumEndpoint } from "./directory-bootstrap.js";
import type { SessionNegotiator, SessionNegotiationResult } from "./transport-selector.js";
import { classifyOnlineResult, type DiscoveryOutcome } from "./cross-node-negotiation.js";
import { parseDiscoveryLookupResult, discoveryLookupErrorReason, parseSessionAssignment, sessionRequestErrorReason, resolveOutboundMoniker } from "./session-assignment-parser.js";
import { DbIdentityStore } from "./db-identity-store.js";
import { createSignalingConnect } from "./signaling-connect.js";
import type { IDirectoryChallengeVerifier } from "@cello-protocol/transport";
import { wireSessionCeremonyHandler, wireSealCeremonyHandler } from "./session-ceremony.js";
import { TrustSignalStore } from "./trust-signal-store.js";
import { TIER } from "./contacts-tier-migration.js";
import { encodeTrustSignalEnvelope } from "@cello-protocol/protocol-types";

export interface OutboundSessionDeps {
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  getKeyProvider: (agentName: string) => KeyProvider | undefined;
  getPersistence: (agentName: string) => DbRegistrationPersistence;
  getAgentSignaling: (agentName: string, keyProvider: KeyProvider, pubkeyHex: string) => { signaling: SignalingManager; getNode: () => CelloNode | null };
  waitForSignalingConnected: (mgr: SignalingManager, timeoutMs: number) => Promise<boolean>;
  getFailoverEndpoint: () => Promise<DirectoryEndpoint | null>;
  resolveConsortiumRoster: () => Promise<ConsortiumEndpoint[] | null>;
  /** The WHOLE seal listener bundle — a visiting stream needs every one of them. */
  registerSealListeners: (signaling: SignalingManager, agentName: string, agentPubkeyHex: string) => () => void;
  sessionNegotiator?: SessionNegotiator;
  /** Step-6 directory identity proof (undefined on the in-process test path). */
  challengeVerifier?: IDirectoryChallengeVerifier;
  getManifestVersion: () => number;
  /** The agents loaded from the encrypted store at boot. */
  loadedAgents: ReadonlyArray<{ name: string; pubkey: string }>;
}

export function createOutboundSessions(deps: OutboundSessionDeps) {
  const {
    logger, sessionNodeManager, getKeyProvider, getPersistence, getAgentSignaling,
    waitForSignalingConnected, getFailoverEndpoint, resolveConsortiumRoster,
    registerSealListeners, sessionNegotiator, challengeVerifier, getManifestVersion, loadedAgents,
  } = deps;

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
    // DOD-PRESENT-1: selective disclosure — present wallet signals to KNOWN+ contacts, nothing to
    // UNKNOWN/BLOCKED. A failure reading the wallet must never block the session (same rule as moniker).
    let trustSignals: Array<{ hash: string; blob: Uint8Array }> | undefined;
    try {
      const tier = sessionNodeManager.getTier(agentName, targetHex);
      if (tier >= TIER.KNOWN) {
        const store = new TrustSignalStore(sessionNodeManager.getDb(), logger);
        const eligible = store.listAllActive();
        if (eligible.length > 0) {
          trustSignals = eligible.map((s) => ({
            hash: s.signalHash,
            blob: encodeTrustSignalEnvelope({
              subject_kind: s.subjectKind,
              subject: s.subject,
              issuer_kind: s.issuerKind,
              issuer_pubkey: s.issuerPubkey,
              type: s.type,
              schema_version: s.schemaVersion,
              payload: s.payload,
              issued_at: s.issuedAt,
              expires_at: s.expiresAt,
              supersedes_hash: s.supersedesHash === null ? null : new Uint8Array(Buffer.from(s.supersedesHash, "hex")),
            }),
          }));
          logger.info("signal.presentation.attached", {
            agentName, target: targetHex.slice(0, 16), count: trustSignals.length, correlationId,
          });
        }
      }
    } catch (err: unknown) {
      logger.warn("signal.presentation.read_failed", {
        agentName,
        reason: err instanceof Error ? err.message : String(err),
        correlationId,
      });
      trustSignals = undefined;
    }
    try {
      const sent = await signaling.sendRaw({
        type: "session_request",
        target_pubkey: new Uint8Array(Buffer.from(targetHex, "hex")),
        initiator_session_peer_id: sr.peerId,
        initiator_session_addrs: sr.addrs,
        wants_session_offer: true,
        ...(moniker !== undefined ? { moniker } : {}),
        ...(trustSignals !== undefined ? { trust_signals: trustSignals } : {}),
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
      getManifestVersion,
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
      const kp = getKeyProvider(ctx.agentName);
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
  return { openVisitingConnection, crossNodeBrokerBySession, resolvedSessionNegotiator };
}
