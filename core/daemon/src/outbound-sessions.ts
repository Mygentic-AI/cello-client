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
import { createHash } from "node:crypto";
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
import { verifyAssignmentSignature } from "./assignment-verify.js";
import { createSignalingConnect } from "./signaling-connect.js";
import type { IDirectoryChallengeVerifier } from "@cello-protocol/transport";
import { wireSessionCeremonyHandler, wireSealCeremonyHandler } from "./session-ceremony.js";
import { TrustSignalStore } from "./trust-signal-store.js";
import { TIER } from "./contacts-tier-migration.js";
import { encodeTrustSignalEnvelope, hashTrustSignalEnvelope } from "@cello-protocol/protocol-types";

export interface OutboundSessionDeps {
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  getKeyProvider: (agentName: string) => KeyProvider | undefined;
  getPersistence: (agentName: string) => DbRegistrationPersistence;
  getAgentSignaling: (agentName: string, keyProvider: KeyProvider, pubkeyHex: string) => { signaling: SignalingManager; getNode: () => CelloNode | null };
  waitForSignalingConnected: (mgr: SignalingManager, timeoutMs: number) => Promise<boolean>;
  getFailoverEndpoint: () => Promise<DirectoryEndpoint | null>;
  resolveConsortiumRoster: () => Promise<ConsortiumEndpoint[] | null>;
  /**
   * DOD-M15-ERRSTRING-1 — the nodes whose bootstrap probe failed in the last sweep.
   *
   * Needed here because a SHORT ROSTER is the cause the DoD line asks these errors to name ("a
   * roster below threshold says so"), and the negotiator otherwise sees only the reachable subset —
   * it cannot tell three-of-three from three-of-five. Reachable + unresolved is the declared count,
   * and majority(declared) is the threshold a ceremony needs.
   */
  getUnresolvedNodes?: () => ReadonlyArray<{ nodeId: string; reason: string }>;
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
    getUnresolvedNodes,
  } = deps;

  /**
   * A sentence naming the roster shortfall, or "" when the roster is whole.
   *
   * DOD-M15-ERRSTRING-1's first clause: **a roster below threshold says so.** Every failure below
   * used to stay silent about it, so an operator holding "the session did not establish" had no way
   * to know the real cause was that two of their five directories were unreachable — and a threshold
   * ceremony needs a majority. `cello_status` reported it; the error they were actually holding did
   * not, and the error is what people act on.
   *
   * Appended rather than substituted: it is CONTEXT for the observation, never a replacement for it.
   * Overwriting the observed reason with "roster short" would be the same defect this line closes,
   * pointing the other way.
   */
  function rosterShortfallNote(reachable: number): string {
    const unresolved = getUnresolvedNodes?.() ?? [];
    if (unresolved.length === 0) return "";
    const declared = reachable + unresolved.length;
    const threshold = Math.floor(declared / 2) + 1;
    const names = unresolved.map((u) => `${u.nodeId} (${u.reason})`).join(", ");
    const belowThreshold = reachable < threshold;
    return (
      ` ALSO: ${unresolved.length} of this consortium's ${declared} directory nodes were unreachable at the last sweep — ${names}.` +
      (belowThreshold
        ? ` That leaves ${reachable} reachable against a threshold of ${threshold}, so signing ceremonies CANNOT complete and this failure is very likely a symptom of that, not of anything to do with your counterparty. Fix the roster first.`
        : ` ${reachable} of ${threshold} needed are still reachable, so ceremonies can still complete — but the margin is thin.`)
    );
  }

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
    signalFilter?: { include?: string[]; exclude?: string[] },
  ): Promise<SessionNegotiationResult> {
    let resolveFrame!: (f: Record<string, unknown>) => void;
    const pending = new Promise<Record<string, unknown>>((r) => { resolveFrame = r; });
    const unregister = signaling.registerInboundHandler((frame) => {
      const t = frame["type"];
      // M12-P18: a trusted counterparty may answer with WHY it refused (over-cap etc.) instead of
      // the directory's generic error. Resolve on it too, so the reason reaches the operator.
      if (t === "session_assignment" || t === "session_request_error" || t === "session_refused") resolveFrame(frame);
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
        // DOD-END-SCOPE-FIX-1: the wallet is daemon-wide and shared by every agent on the device,
        // so the presenting agent's own K_local pubkey is what makes an agent-subject signal his to
        // present. It is the SAME value an agent-subject envelope's `subject` holds — the directory
        // authenticates the signaling stream with this key and resolves it against
        // `agent_profiles.k_local_pubkey`, which is the column it joins `subject` on.
        const agentRec = loadedAgents.find((a) => a.name === agentName);
        if (!agentRec) {
          // Not reachable through a loaded agent's own session, and refusing is the only safe
          // answer: an unresolved presenter cannot be scoped, and presenting unscoped is the defect.
    // NOTE: this throw is CAUGHT by this function's own catch below and downgraded to a warn — the
      // session then forms with no signals. Not a refusal of the session; a refusal to PRESENT.
      throw new Error(`presenting agent '${agentName}' is not loaded — cannot scope the wallet`);
        }
        const store = new TrustSignalStore(sessionNodeManager.getDb(), logger);
        const eligible = store.listAllActive({
          presentingAgentPubkeyHex: agentRec.pubkey,
          include: signalFilter?.include,
          exclude: signalFilter?.exclude,
        });
        // M10B / DOD-END-SURFACE-1 — the per-counterparty choice, applied LAST and only ever to
        // NARROW. `listAllActive` has already enforced consent (accepted-only, in SQL) and the
        // caller's per-call filter; this can drop a signal from that set but can never add one, so
        // an explicit `present: true` for a contact cannot resurrect something consent excluded.
        // A signal with no recorded choice keeps whatever the previous stages decided.
        const prefs = sessionNodeManager.getContactSignalPrefs(agentName, targetHex);
        const selected = prefs.size === 0 ? eligible : eligible.filter((s) => prefs.get(s.signalHash) !== false);
        const omittedByContact = eligible.length - selected.length;
        if (omittedByContact > 0) {
          logger.info("signal.presentation.contact_omitted", {
            agentName, target: targetHex.slice(0, 16), omitted: omittedByContact, correlationId,
          });
        }
        if (selected.length > 0) {
          // ── PRESENT NOTHING YOU CANNOT REPRODUCE ────────────────────────────────────────────────
          // Presentation re-encodes the envelope from the WALLET ROW and sends the notarized hash
          // beside it. If any stored field does not round-trip, the bytes and the hash disagree — and
          // the only party that finds out is the RECIPIENT, who logs `hash_mismatch` and drops it. From
          // the presenter's side that is indistinguishable from success: the session forms, the log
          // says `attached: 1`, and the operator's endorsement silently never counts anywhere.
          //
          // So the presenter re-derives its own hash and refuses to send a signal it cannot reproduce,
          // naming the two hashes. A wallet round-trip defect is now a loud error at the party that
          // owns the row, not a silent rejection one hop away.
          const reproducible: typeof selected = [];
          for (const s of selected) {
            const blob = encodeTrustSignalEnvelope({
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
              // THE STORED VALUE, never a literal. Re-encoding with the wrong value changes the
              // envelope bytes, so the hash stops matching what the directory notarized and the
              // recipient rejects a perfectly valid signal.
              same_operator: s.sameOperator,
            });
            const derived = Buffer.from(hashTrustSignalEnvelope({
              subject_kind: s.subjectKind, subject: s.subject, issuer_kind: s.issuerKind,
              issuer_pubkey: s.issuerPubkey, type: s.type, schema_version: s.schemaVersion,
              payload: s.payload, issued_at: s.issuedAt, expires_at: s.expiresAt,
              supersedes_hash: s.supersedesHash === null ? null : new Uint8Array(Buffer.from(s.supersedesHash, "hex")),
              same_operator: s.sameOperator,
            })).toString("hex");
            if (derived !== s.signalHash) {
              logger.error("signal.presentation.unreproducible", {
                agentName,
                notarized: s.signalHash.slice(0, 16),
                derived: derived.slice(0, 16),
                type: s.type,
                issuerKind: s.issuerKind,
                sameOperator: s.sameOperator,
                expiresAt: s.expiresAt,
                issuedAt: s.issuedAt,
                subjectKind: s.subjectKind,
                subject: s.subject,
                issuerPubkey: s.issuerPubkey.slice(0, 16),
                supersedesHash: s.supersedesHash,
                schemaVersion: s.schemaVersion,
                payloadLen: s.payload.length,
                payloadSha: createHash("sha256").update(Buffer.from(s.payload)).digest("hex").slice(0, 16),
                correlationId,
              });
              continue;
            }
            reproducible.push({ ...s, presentedBlob: blob } as typeof s & { presentedBlob: Uint8Array });
          }
          trustSignals = reproducible.map((s) => ({
            hash: s.signalHash,
            blob: (s as typeof s & { presentedBlob: Uint8Array }).presentedBlob,
          }));
          if (trustSignals.length === 0) {
            // EVERY selected signal failed its own reproducibility check. "attached: 0" would be a lie
            // in the one case that matters most — the wallet held presentable rows and not one of them
            // could be re-encoded — and it reads identically to holding nothing at all.
            logger.error("signal.presentation.all_unreproducible", {
              agentName, target: targetHex.slice(0, 16), selected: selected.length, correlationId,
            });
            trustSignals = undefined;
          } else {
            logger.info("signal.presentation.attached", {
              agentName,
              target: targetHex.slice(0, 16),
              count: trustSignals.length,
              // Non-zero means some rows were selected and then dropped — visible here rather than only
              // in the per-signal errors above.
              ...(selected.length !== trustSignals.length ? { droppedUnreproducible: selected.length - trustSignals.length } : {}),
              correlationId,
            });
          }
        } else {
          // A ZERO-ROW PRESENTATION IS THE FAILURE THIS UNIT EXISTS TO PREVENT, so it must not be
          // the one outcome that emits nothing. Without this line "the operator holds no signals"
          // and "the operator's signals no longer match their key" are the same observation: silence
          // plus a session that formed normally. The second is reachable — a key rotation, a
          // re-registration, a signal minted against a stale `k_local_pubkey` — and it is exactly
          // the shape the DoD describes as "goes green while matching ZERO rows in production".
          // `heldTotal` is what makes them distinguishable: 0 means nothing to present, >0 means the
          // wallet has rows that this agent's scoping excluded.
          logger.info("signal.presentation.none_eligible", {
            agentName,
            target: targetHex.slice(0, 16),
            heldTotal: store.listAllWalletSignals().length,
            // Three different silences that used to look identical. `eligibleBeforeContactPrefs > 0`
            // with nothing sent means the OPERATOR omitted them for this counterparty — a choice, not
            // a fault — and without this field it reads the same as a scoping bug.
            eligibleBeforeContactPrefs: eligible.length,
            contactPrefsApplied: prefs.size,
            filter: signalFilter ?? null,
            correlationId,
          });
        }
      }
    } catch (err: unknown) {
      // DEGRADES, it does not refuse — and the comment on the throw above used to claim otherwise.
      // A wallet read that fails (including the deliberate "agent not loaded" throw, which is
      // annotated "refusing is the only safe answer") lands here, is downgraded to a warn, and the
      // session proceeds with NO signals attached. That behaviour is CORRECT — presenting unscoped is
      // the actual danger and presenting nothing is safe — but the code and the comment disagreed
      // about which one happens, and a comment that misdescribes the control flow is worse than
      // either, because the next reader trusts it instead of the code.
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
      // M12-P18: the COUNTERPARTY refused, and told us why (only KNOWN+ senders get this — a
      // stranger still gets silence, so no block/throttle oracle). Surface their guidance verbatim.
      if (frame["type"] === "session_refused") {
        const reason = typeof frame["reason"] === "string" ? frame["reason"] : "refused_by_counterparty";
        const guidance = typeof frame["guidance"] === "string"
          ? frame["guidance"]
          : `The counterparty refused this session (${reason}).`;
        return { ok: false, reason, guidance };
      }
      const raw = frame["assignment"] as Record<string, unknown> | undefined;
      const assignment = raw ? parseSessionAssignment(raw) : null;
      if (!assignment) {
        return { ok: false, reason: "assignment_parse_failed", guidance: "The directory's session_assignment was missing or malformed." };
      }
      /**
       * DOD-M15-ASSIGN-1 — VERIFY THE SIGNATURE BEFORE ANYTHING TRUSTS THE ASSIGNMENT.
       *
       * WHAT THIS STOPS, stated first because an earlier draft of this note undersold it into
       * sounding like paperwork: **without it, whichever directory node this daemon is talking to
       * can hand it a permission slip naming any peer id and addresses it likes, and the daemon
       * dials them.** One compromised directory could put an operator into a session with an
       * impostor, and everything downstream would look normal — the impostor is a real agent
       * signing with its own real key. Verification means a single node cannot do that: the slip
       * must carry a threshold signature from this agent's own quorum, which no one node can
       * produce. That is the forgery-resistance property FROST exists for, and it was claimed in
       * the design and enforced nowhere.
       *
       * THE BOUND, equally explicit: a THRESHOLD of this agent's own directories, colluding, could
       * still sign an assignment naming the wrong counterparty. That is the designed-for limit, not
       * the everyday one. The substitution is caught at ingest by the wrong-signer check
       * (`DOD-M15-FRAME-1`) and closed by relay corroboration (`DOD-M15-CORROBORATE-1`).
       */
      const verified = await verifyAssignmentSignature(assignment, getPersistence(agentName), logger, agentName, correlationId);
      if (!verified.ok) {
        return { ok: false, reason: verified.reason, guidance: verified.guidance };
      }
      logger.info("session.negotiate.assignment.received", { agentName, correlationId, signatureType: assignment.signature_type, signatureVerified: true });
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
    signalFilter?: { include?: string[]; exclude?: string[] },
  ): Promise<SessionNegotiationResult> {
    const roster = await resolveConsortiumRoster();
    const target = roster?.find((e) => e.nodeId === owningNodeId) ?? null;
    if (!target) {
      /**
       * DOD-M15-ERRSTRING-1 (review F1) — THIS IS NOT A MANIFEST MISS, and calling it one sent
       * operators to investigate consortium membership over a lost packet.
       *
       * `resolveConsortiumRoster()` returns the REACHABLE subset: `manifestNodesToEndpoints` drops
       * any node whose `/bootstrap` probe failed. So absence from this list has two very different
       * causes and this code cannot tell them apart —
       *   1. our own probe of that node did not answer during the last sweep (the common one, and
       *      before `DOD-M15-BOOTSTRAP-1` a single lost packet was enough to produce it);
       *   2. the node genuinely is not in the signed manifest.
       * The old message asserted (2) unconditionally, in the words "It may have left the
       * consortium." The comment above it asserted the same thing to the next reader.
       *
       * Named for what was observed — it is not in the roster we could reach — with both causes in
       * the order they actually occur, and the check that separates them.
       */
      logger.warn("session.crossnode.failed", {
        agentName,
        brokerNode: owningNodeId,
        reason: "home_node_not_in_reachable_roster",
        rosterSize: roster?.length ?? 0,
        correlationId,
      });
      return {
        ok: false,
        reason: "home_node_not_in_reachable_roster",
        guidance:
          `The counterparty's home node (${owningNodeId}) is not in the set of directory nodes this daemon ` +
          "could reach. Most often that means our own probe of it did not answer, not that it has left the " +
          "consortium. Run cello_status: if it appears under directory_endpoints_unresolved, the problem is the " +
          "path from here to it (attempts:1 there means it answered and the answer was unusable; 2 or more means " +
          "it never answered). Only if it is absent from the manifest altogether has it actually left.",
      };
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
      const result = await runSessionRequestOverSignaling(visiting.mgr, targetHex, sr, correlationId, agentName, signalFilter);
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
      // include_signals / exclude_signals: validated against the wallet below and passed to
      // runSessionRequestOverSignaling so the presentation layer applies them.
      const includeRaw = ctx.params["include_signals"];
      const excludeRaw = ctx.params["exclude_signals"];
      const includeTypes = Array.isArray(includeRaw) ? (includeRaw as unknown[]).filter((s): s is string => typeof s === "string") : undefined;
      const excludeTypes = Array.isArray(excludeRaw) ? (excludeRaw as unknown[]).filter((s): s is string => typeof s === "string") : undefined;

      // Validate include/exclude type strings against what THIS agent can actually present.
      //
      // Not against the whole wallet: the wallet is daemon-wide, so `listAllWalletSignals()` spans
      // every agent on the device. Validating against it means Alice's `--include track_record`
      // passes because BOB holds one, and she then presents nothing with no error and no guidance —
      // the daemon telling her the type is fine and then silently omitting it. Before presentation
      // was scoped that filter would have presented Bob's signal; scoping turned a leak into a lie,
      // and this turns the lie back into the `unknown_signal_type` message that already exists.
      // (It also stops the validator being a cross-agent enumeration oracle.)
      if (includeTypes || excludeTypes) {
        const store = new TrustSignalStore(sessionNodeManager.getDb(), logger);
        const presenter = loadedAgents.find((a) => a.name === ctx.agentName);
        if (!presenter) {
          return {
            ok: false,
            reason: "agent_not_found",
            guidance: `Agent '${ctx.agentName}' is not loaded on this daemon.`,
          };
        }
        const known = new Set(store.listPresentableTypes(presenter.pubkey));
        const check = includeTypes ?? excludeTypes ?? [];
        const unknown = check.filter((t) => !known.has(t));
        if (unknown.length > 0) {
          return {
            ok: false,
            reason: "unknown_signal_type",
            guidance: `Signal type(s) not found in wallet: ${unknown.map((t) => `'${t}'`).join(", ")}. See 'cello trust-signals list' for valid types. Use --include type1,type2 or --exclude type1,type2.`,
          };
        }
      }
      const signalFilter: { include?: string[]; exclude?: string[] } | undefined =
        includeTypes || excludeTypes ? { include: includeTypes, exclude: excludeTypes } : undefined;

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
        // Reachable-node count for `rosterShortfallNote`. Read once here rather than per failure
        // path so every message quotes the same sweep, and a null roster (no manifest yet) reads as
        // zero reachable rather than throwing on a path that is already failing.
        const rosterSizeForNote = (await resolveConsortiumRoster())?.length ?? 0;
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
            return await runSessionRequestOverSignaling(signaling, targetHex, sr, ctx.correlationId, ctx.agentName, signalFilter);
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
            logger.info("directory.discovery.lookup.retry", { agentName: ctx.agentName, attempt, kind: "online_no_owner", homeNodeId, correlationId: ctx.correlationId });
            if (attempt < MAX_ATTEMPTS) { await sleepMs(backoffs[attempt - 1]); continue; }
            /**
             * DOD-M15-ERRSTRING-1 — NAME WHAT WAS OBSERVED. This returned `counterparty_offline`,
             * and its own guidance said the opposite in the next sentence: *the directory reported
             * the counterparty ONLINE*. The counterparty is not the broken thing here; the
             * directory answered "online" and then named nobody who could serve them.
             *
             * That mismatch is the whole defect this line exists to close. An operator told
             * "counterparty offline" goes and asks their counterparty to check — the one place the
             * fault is not.
             */
            return {
              ok: false,
              reason: "directory_named_no_home",
              guidance:
                `The directory node you are connected to (${homeNodeId}) says this counterparty is online but names ` +
                "no node that holds them, three times running. That is a directory-side inconsistency, not the " +
                "counterparty being offline — there is nothing for them to fix on their side. Retry in a minute; " +
                "if it repeats, that node's presence data is out of sync and cello_status will show which other " +
                "directories are available." +
                rosterShortfallNote(rosterSizeForNote),
            };
          }

          const result =
            action.kind === "same_node"
              // SAME-NODE: the target is on the node we're already connected to. The existing path runs
              // unchanged — ZERO visiting connections, ZERO new frames beyond the one discovery_lookup.
              ? await runSessionRequestOverSignaling(signaling, targetHex, sr, ctx.correlationId, ctx.agentName, signalFilter)
              // CROSS-NODE: reach into the target's home over a transient visiting connection.
              : await runCrossNodeSetup(ctx.agentName, kp, agentRec.pubkey, action.owningNodeId, targetHex, sr, ctx.correlationId, signalFilter);

          // RETRY triggers: (a) the broker reported target_offline (stale replicated presence or a
          // re-home between discovery and the request); (b) a transient visiting-connection failure
          // (cross-region blip). Both re-discover → retry, bounded.
          if (!result.ok && (result.reason === "target_offline" || result.reason === "visiting_connection_unreachable")) {
            logger.info("session.crossnode.stale_discovery_retry", { agentName: ctx.agentName, attempt, reason: result.reason, correlationId: ctx.correlationId });
            if (attempt < MAX_ATTEMPTS) { await sleepMs(backoffs[attempt - 1]); continue; }
            /**
             * DOD-M15-ERRSTRING-1 (review F2) — KEEP THE UPSTREAM OBSERVATION. This branch used to
             * rewrite `target_offline` into `counterparty_offline`, and that rewrite is the most
             * likely source of the 2026-08-16 incident.
             *
             * What the home node actually reported is `targetStreamFound === false`: it has no live
             * stream registered for that agent. At least four different conditions produce it, and
             * only one of them is "the counterparty is offline":
             *   - their standing receiver's REGISTRATION lapsed on a signaling reconnect — this
             *     daemon's own notes record 46 of 48 reconnects in one hour leaving every agent
             *     unregistered, while `cello status`, `agent.online` and the directory's own
             *     presence table all still showed them healthy;
             *   - the node garbage-collected the stream;
             *   - the agent is re-homing between discovery and the request;
             *   - they really are offline.
             *
             * Collapsing all four into "counterparty_offline" tells the operator to go and ask a
             * person whose side is working, about a registration on OUR side of a stream on the
             * DIRECTORY's side. Invariant 3 prescribes the fix literally: do not overwrite the
             * upstream descriptive error.
             */
            return result.reason === "visiting_connection_unreachable"
              ? { ok: false, reason: "visiting_connection_unreachable", guidance: "The counterparty's home node was reachable at discovery but its visiting connection could not be established after several attempts. Retry shortly." }
              : {
                  ok: false,
                  reason: "home_node_reports_no_receiver",
                  guidance:
                    `The counterparty's home node (${action.kind === "cross_node" ? action.owningNodeId : homeNodeId}) reports no live receiver registered for them, ` +
                    "after several attempts. This is NOT the same as them being offline, and it is most often not their fault: " +
                    "the commonest cause is their receiver's registration lapsing on a signaling reconnect, which leaves their " +
                    "own cello_status showing perfectly healthy. Retry in a minute — a re-registration usually clears it. " +
                    "If it persists, have them restart their agent so it re-registers; only if that fails is their daemon actually down.",
                };
          }
          return result;
        }
        /**
         * DOD-M15-ERRSTRING-1 — UNREACHABLE BACKSTOP, and it is worth saying so precisely because
         * the previous value made it look like a live path.
         *
         * Every branch in the loop above either `continue`s (only while `attempt < MAX_ATTEMPTS`) or
         * returns, and the body ends in `return result`. So the loop cannot complete normally; this
         * exists because the compiler cannot see that. It was checked by trace, not assumed — an
         * earlier draft of this comment claimed this line was the catch-all behind the 2026-08-16
         * incident, and it is not: the reachable false-offline was the no-home branch above.
         *
         * It still must not say `counterparty_offline`. A backstop that fires is by definition a
         * case nobody predicted, which is the worst possible moment to assert a specific party is
         * at fault — and if this ever DOES appear in a log, "the cause was not one this daemon can
         * name" is exactly the truth the reader needs.
         */
        return {
          ok: false,
          reason: "session_setup_exhausted",
          guidance:
            "Three attempts to set up the session all failed, and the cause was not one this daemon can name — " +
            "so it is deliberately not guessing that the counterparty is offline. Retry in a minute. If it repeats: " +
            "run cello_status to check your own directory connection first (a node below threshold or mid-restart " +
            "presents exactly like this), and only then ask the counterparty to check theirs." +
            rosterShortfallNote(rosterSizeForNote),
        };
      } finally {
        negotiationInProgress.delete(ctx.agentName);
      }
    },
  };

  // DAEMON-003: Initialize RetryQueue and NonceDedupStore (AC-008).
  return {
    openVisitingConnection,
    crossNodeBrokerBySession,
    resolvedSessionNegotiator,
    // M14 / DOD-DOC-DELIVERY-2: exposed for the document delivery worker, the first NON-HANDLER
    // consumer of this module. It needs the same 3-state discovery answer `cello_initiate_session`
    // uses — online / offline / unknown_agent, kept distinct from "the lookup itself failed" — and
    // a second implementation of that distinction is how the two drift until one starts reporting a
    // directory outage as the peer being offline.
    runDiscoveryLookup,
  };
}
