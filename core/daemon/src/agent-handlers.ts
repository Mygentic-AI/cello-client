/**
 * Agent lifecycle: create, remove, start, stop, select, list.
 *
 * The one rule that governs all of them: an agent's identity is its KEY, not its name. A name is a
 * mutable display label that can be reused after retirement, so nothing here may treat a name as
 * proof of who someone is — cello_remove_agent submits a signed revocation precisely because
 * deleting a row locally would leave the directory believing the key is still live.
 *
 * cello_use_agent is the selector, and its failure mode is the interesting one: after a stop, the
 * connection's selection is CLEARED, and a cleared selection must NEVER silently fall back to
 * "the only agent online" — that is how a write lands on the wrong agent (fixed in f00b534, and
 * the reason resolveCurrentAgent distinguishes "never chose" from "choice taken away").
 */
import type { StartAgentResult } from "./start-agent.js";
import type { IpcHandler } from "./ipc-server.js";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { AgentInfo, Logger } from "./types.js";
import type { ConnState } from "./contact-handlers.js";
import type { NotificationDispatcher } from "./notification-dispatcher.js";
import { MONIKER_RE, validateMoniker, buildAgentRevocationTbs } from "@cello-protocol/protocol-types";
import { DbIdentityStore, DbRegistrationPersistence } from "./db-identity-store.js";
import type { LoadedAgent } from "./agent-loader.js";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { SignalingManager, CelloNode } from "@cello-protocol/transport";
import { generateKLocalSeed, InMemoryKeyProvider } from "@cello-protocol/crypto";

import { TrustSignalStore } from "./trust-signal-store.js";
import { currentCaller } from "./caller-identity.js";
import type { HolderRegistry } from "./holder-registry.js";
import { noAgentsGuidance } from "./onboarding-guidance.js";
import { extractErrorMessage } from "./error-message.js";

export interface AgentHandlerDeps {
  handlers: Map<string, IpcHandler>;
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  agents: AgentInfo[];
  onlineAgents: Set<string>;
  /** M12-P16: agents an operator deliberately took offline — the inbound refusal keys on THIS. */
  explicitlyOfflineAgents: Set<string>;
  /** LAZY: the dispatcher is constructed late in startDaemon. These handlers only touch it at
   *  request time, so a getter avoids a temporal-dead-zone crash at registration. */
  getNotificationDispatcher: () => NotificationDispatcher;
  getConnState: (connectionId: string) => ConnState | undefined;
  perConnectionState: Map<string, { currentAgent: string | null; clearedAgent?: string; clientType: string }>;
  getAgentsForConnection: (connectionId: string) => AgentInfo[];
  /**
   * ⚠️ THE THREE-WAY UNION, NOT `{ ok: true }`. The readiness half is the point: an agent can be
   * online and DEAF — marked started while its standing receiver never came up — and the two states
   * render identically at every surface without it. Declared narrow, dropping it is invisible to the
   * type checker.
   */
  startAgentInternal: (name: string) => StartAgentResult;
  dropAgentSignaling: (agentName: string) => Promise<void>;
  /**
   * 048-SWEEPTICK: end this agent's collection tick. Wired to REMOVAL, deliberately not to offline.
   *
   * An offline agent's tick is already inert — it checks `isAgentOnline` before every sweep and does
   * no round trips — and cancelling it there would be wrong rather than tidy: `cello_set_agent_offline`
   * leaves the signaling manager connected, so a later `cello_start_agent` finds the cached manager
   * and fires no `onConnected` (start-agent.ts:92 → getAgentSignaling's early return). Nothing would
   * ever re-arm it, and the agent would silently drop back to collect-on-reconnect.
   *
   * A REMOVED agent is never coming back, so its timer is the one that should genuinely stop.
   */
  stopSweepTick: (agentName: string) => void;
  awayAckSent: Set<string>;
  keyProviders: Map<string, KeyProvider>;
  loadedAgents: LoadedAgent[];
  getAgentSignaling: (agentName: string, keyProvider: KeyProvider, pubkeyHex: string) => { signaling: SignalingManager; getNode: () => CelloNode | null };
  waitForSignalingConnected: (mgr: SignalingManager, timeoutMs: number) => Promise<boolean>;
  perAgentSignaling: Map<string, unknown>;
  /**
   * M16 033-CHANNELVIEW: is this identity a broadcast channel? Two uses: no `agent_state_changed`
   * (offline/removed) may ring for a channel, and `cello_use_agent` on a channel is refused — a
   * channel is administered by an agent, never selected as one. Reads the DB row live.
   */
  isChannelAgent: (agentName: string) => boolean;
  /** M15D: who holds each agent. `cello_use_agent` takes a hold; release and stop drop it. */
  registry: HolderRegistry;
}

export function registerAgentHandlers(deps: AgentHandlerDeps): void {
  const {
    handlers, logger, sessionNodeManager, agents, onlineAgents, explicitlyOfflineAgents, getNotificationDispatcher,
    getConnState, perConnectionState, getAgentsForConnection, startAgentInternal,
    dropAgentSignaling, stopSweepTick, awayAckSent, keyProviders, loadedAgents, getAgentSignaling,
    waitForSignalingConnected, perAgentSignaling, isChannelAgent, registry,
  } = deps;

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
      // The LOAD outcome, not the operator-facing state — that is derived per call by
      // resolveAgentState. This agent has just been created and has no FROST share, so it derives as
      // `unregistered` until `cello register-agent` runs. It used to be recorded as "registered"
      // here, which was false at the moment it was written: nobody could reach this agent yet.
      agents.push({ name, state: "stopped", pubkey: pubkeyHex });
      // CELLO-M7-CONN-001 (DOD-CONN-1, supersedes ONBOARD-001 keystone election): on a fresh install
      // the daemon started with zero agents, so there were no directory connections. Bring up THIS
      // agent's OWN directory connection now (production: getAgentSignaling creates + connects a
      // dedicated manager authenticated as this agent; the directory door becomes active with no
      // restart). There is no shared keystone to elect into. In the test path getAgentSignaling returns
      // the already-present shared manager (no-op).
      getAgentSignaling(name, keyProvider, pubkeyHex);
      // "initiated" not "established": getAgentSignaling starts the connection but does not await it
      // (the SignalingManager emits directory.signaling.connected on the state transition; the
      // handshake itself is directory.signaling.authenticated — 058-LOGNAME).
      logger.info("agent.directory.connection.initiated", { agentName: name, agentPubkey: pubkeyHex });
    } catch (err: unknown) {
      logger.error("persist.identity.persist.failed", { agentName: name, error: extractErrorMessage(err) });
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
          logger.warn("agent.revocation.signaling_teardown_failed", { agentName, error: extractErrorMessage(err) });
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
    // M16 033-CHANNELVIEW: captured BEFORE any retire — `isChannelAgent` filters retired rows out, so
    // read once here or the removal doorbell guard below can no longer tell a channel from an agent.
    const wasChannel = isChannelAgent(name);

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
          logger.warn("agent.removal.receiver_teardown_failed", { agentName: name, agentId, error: extractErrorMessage(err) });
        });
      }
      // Stop+forget the retired agent's dedicated per-agent signaling manager (review HIGH-1).
      await dropAgentSignaling(name).catch((err) => {
        logger.warn("agent.removal.signaling_teardown_failed", { agentName: name, agentId, error: extractErrorMessage(err) });
      });
      // 048-SWEEPTICK: and its collection tick, which would otherwise outlive the agent for the life
      // of the daemon — skipping every five minutes for a name that no longer exists.
      stopSweepTick(name);
      registry.clearAgent(name); // before the roster forgets its key
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
          getNotificationDispatcher().dispatchAgentCurrentChanged(connId, name, null);
        }
      }
      // agent.removal.retired (observability): never log key material — only the name + agent_id.
      logger.info("agent.removal.retired", { agentName: name, agentId });
      // M16 033-CHANNELVIEW: no agent_state_changed for a channel — it was never shown as an agent.
      if (!wasChannel) getNotificationDispatcher().dispatchAgentStateChanged(name, "offline", "removed");
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

  // ─── MCP-001: cello_set_agent_offline — renamed on BOTH the tool and the wire ───
  //
  // NO LEGACY WIRE ALIAS, and no second name for this anywhere. One operator, no install base:
  // an alias is permanent debt bought for nobody, and a verb that exists under two names is how
  // both humans and AI coders end up calling the wrong one. connect and daemon are promoted and
  // reinstalled together, and the version gate an alias would have complemented does not even
  // exist — cello-mcp.ts checks `ipc.connect` for a `version_mismatch` reason NOTHING here
  // returns.
  //
  // A genuinely mismatched shim now fails loudly and correctly: `Unknown method:
  // cello_set_agent_offline`, whose guidance already names the cause (shim/daemon version skew) and
  // the fix (`cello logout && cello login`). Loud and fixable beats silent and permanent.
  //
  // The TOOL was renamed because the old name described the wrong axis and cost real confusion.
  // There are two independent things an operator does to an agent:
  //
  //   lifecycle  — cello_start_agent  / cello_set_agent_offline    (offline ⇄ online)
  //   attendance — cello_use_agent    / cello_stop_using_agent  (who this connection drives)
  //
  // "stop_agent" reads as the opposite of "use_agent" — stop using it — but it is the opposite of
  // "start_agent". An operator wanting to step away from an agent so its AWAY path could fire ran
  // it and took the agent fully offline instead, at which point inbound sessions were refused with
  // `counterparty_did_not_accept` and the away reply could never be produced. The two states look
  // alike from outside (nobody is answering) and behave nothing alike.
  //
  // The deselect half genuinely did not exist: `cello_use_agent` requires a name, so a connection
  // could SWITCH agents but never LET GO of one. The only way to clear a selection was to shut the
  // agent down, which is why the two verbs collapsed into each other.
  handlers.set("cello_set_agent_offline", async (params, _connectionId) => {
    const name = params?.name as string | undefined;
    if (!name) {
      return { ok: false, reason: "missing_params", guidance: "Provide 'name' parameter with the agent name to stop." };
    }
    const agent = agents.find((a) => a.name === name);
    if (!agent || agent.state === "load_failed") {
      return { ok: false, reason: "agent_not_found", guidance: `Agent '${name}' does not exist. Check agent names with cello_agents.` };
    }
    // M12-P16: record the OPERATOR'S INTENT first, before any bookkeeping check can short-circuit.
    // The idempotent early-return below keys on `onlineAgents`, which answers "was this agent started
    // through cello_start_agent" — not "is it reachable". An agent serving traffic without ever
    // entering that set (a standing receiver built directly, an auto-start path) would take the
    // early return, report `ok: true`, and keep answering: the switch pressed, nothing switched off.
    // Intent is not conditional on internal state.
    explicitlyOfflineAgents.add(name);
    if (!onlineAgents.has(name)) {
      // Idempotent — already registered/offline, no event
      return { ok: true };
    }
    onlineAgents.delete(name);
    /**
     * DOD-M15-AWAYSCOPE-1 — say OFFLINE before the sessions are torn down, not after.
     *
     * ⚠️ THE ORDERING IS THE WHOLE POINT. The teardown below destroys every session node for this
     * agent, and the relay client rides on the node — announce afterwards and there is nothing left
     * to announce through. The counterparty would be left reading the last thing they were told,
     * which is 'unattended': "nobody is watching, it will be read later". That is the opposite of
     * what an operator reaching for a kill switch means, and 'offline' exists as a third value
     * precisely so the two cannot be confused.
     *
     * Best-effort, like every attendance notice — the send is not awaited and may lose the race with
     * the teardown. The failure mode is the counterparty reading 'gone' once the relay loses the
     * connection, which is true and is the next-best thing to hear.
     */
    sessionNodeManager.announceAttendance(name, "offline");
    // DOD-LOOP-1: tear down this agent's standing receiver. AWAITED and LOGGED, matching
    // cello_remove_agent — a teardown that did not happen must be VISIBLE. Fire-and-forget with a
    // swallowed catch reported the agent offline while its receiver could still be live and bound
    // to it: a stopped agent that can still be handed an inbound session, with nothing in the log.
    await sessionNodeManager.removeStandingReceiverForAgent(name).catch((err) => {
      logger.warn("agent.stop.receiver_teardown_failed", { agentName: name, error: extractErrorMessage(err) });
    });

    // M12-P16: OFFLINE MEANS STOP TALKING.
    //
    // Tearing down the standing receiver only stops NEW inbound sessions. Direct delivery goes to
    // the per-session node, so an agent reported `offline` kept accepting content on every session
    // it already had, appending leaves, running its away logic and REPLYING. Measured live across
    // two machines on 2026-08-05; the whole exchange is in the counterparty's transcript. The CLI's
    // own help promises "It stops accepting anything until restarted", and an operator reaching for
    // this is reaching for a kill switch — one that keeps answering while reporting success is worse
    // than none at all.
    //
    // Scoped to THIS agent's sessions: another agent on the same daemon is still online and its
    // conversations must not be collateral. `interrupted` is the honest status — this side stopped
    // participating. Not `sealed` (nothing was agreed with the counterparty) and not `abandoned`
    // (terminal, forfeits the receipt); an interrupted session can still be sealed later, which
    // M12-P15 is what makes reliably possible.
    const ownSessions = sessionNodeManager.getSessionsByStatus("active").filter((r) => r.agent_name === name);
    for (const s of ownSessions) {
      try {
        await sessionNodeManager.destroySessionNode(name, s.session_id, "interrupted");
      } catch (err: unknown) {
        // Never let one stuck session leave the agent half-offline: the others must still be torn
        // down, and the failure must be visible rather than swallowed into a green `{ ok: true }`.
        logger.error("agent.stop.session_teardown_failed", {
          agentName: name, sessionId: s.session_id,
          impact: "this session may still accept content from the counterparty while the agent reports offline",
          error: extractErrorMessage(err),
        });
      }
    }
    if (ownSessions.length > 0) {
      logger.info("agent.stop.sessions_interrupted", { agentName: name, count: ownSessions.length });
    }
    logger.info("agent.offline", { agentName: name, reason: "stopped" });
    // MCP-002: Broadcast agent_state_changed to ALL connections — EXCEPT a channel (M16
    // 033-CHANNELVIEW): a channel is not an agent and rings no online/offline doorbell.
    if (!isChannelAgent(name)) getNotificationDispatcher().dispatchAgentStateChanged(name, "offline", "stopped");

    // Nobody holds or listens to a stopped agent; clear it from every connection that had it.
    registry.clearAgent(name);
    for (const [connId, state] of perConnectionState) {
      if (state.currentAgent === name) {
        state.currentAgent = null;
        state.clearedAgent = name; // this connection HAD an intent; do not guess a replacement
        getNotificationDispatcher().dispatchAgentCurrentChanged(connId, name, null);
        logger.info("agent.current.switched", { connectionId: connId, fromAgent: name, toAgent: null });
      }
    }
    return { ok: true };
  });

  // ─── cello_stop_using_agent handler — the missing half of cello_use_agent ───
  //
  // `cello_use_agent` requires a name, so a connection could SWITCH agents but never LET GO of one.
  // The only way to clear a selection was `cello_set_agent_offline`, which takes the agent OFFLINE —
  // a different axis entirely, and the confusion that named this handler into existence.
  //
  // The gap was not cosmetic. An attended agent never sends its away reply (`isAttended` suppresses
  // it), so an operator who wanted to step away had exactly two options: shut the agent down, which
  // makes it unreachable and refuses inbound sessions outright, or select some OTHER agent — which
  // is impossible if you only have one. A single-agent operator had no route to "away" at all.
  //
  // Releasing does NOT touch the agent's lifecycle: it stays online with its standing receiver, so
  // it can still accept inbound sessions and answer them with its away message. That is the whole
  // point — this is how an operator becomes reachable-but-absent rather than simply gone.
  handlers.set("cello_stop_using_agent", async (_params, connectionId) => {
    const connState = getConnState(connectionId);
    if (!connState) {
      return { ok: false, reason: "connection_not_registered", guidance: "Send ipc.connect frame before calling agent tools." };
    }
    const caller = currentCaller();
    const fromAgent = connState.currentAgent ?? registry.heldBy(caller.key) ?? null;

    // CLEARED ON BOTH BRANCHES. `clearedAgent` means "this connection's choice was taken away from
    // it, do not guess a replacement". A release is the opposite: the operator chose to hold nothing.
    delete connState.clearedAgent;

    if (!fromAgent) {
      return { ok: true, released: null, guidance: "This connection was not attending any agent. Nothing to release." };
    }
    connState.currentAgent = null;
    const held = connState.clientType === "hermes"
      ? registry.dropListener(fromAgent, connectionId)
      : registry.release(fromAgent, caller);
    getNotificationDispatcher().dispatchAgentCurrentChanged(connectionId, fromAgent, null);
    logger.info("agent.current.released", { connectionId, fromAgent, held });
    return {
      ok: true,
      released: fromAgent,
      // The sole-online fallback still resolves an unnamed call to this agent if it is the only one
      // online, so "step away" is said with that caveat rather than as "nothing acts as it now".
      guidance:
        `No longer attending '${fromAgent}'. It stays ONLINE and reachable — inbound sessions now get ` +
        `its away message instead of a live reply. NOTE: if it is the only agent online, agent-scoped ` +
        `calls without an explicit 'agent' still resolve to it; pass 'agent' explicitly, or take it ` +
        `offline with cello_set_agent_offline if you want those calls to refuse.`,
    };
  });

  // ─── cello_use_agent: take the agent's hold (M15D exclusive attendance) ───
  //
  // An agent has zero or one holder (`holder-registry.ts`). Another caller's hold is refused
  // `agent_held` unless `force: true`, which takes it and tells the old holder. The Hermes cello
  // bridge listens instead of holding. Nothing auto-starts: an offline agent is refused.
  handlers.set("cello_use_agent", async (params, connectionId) => {
    const name = params?.name as string | undefined;
    if (!name) {
      return { ok: false, reason: "missing_params", guidance: "Provide 'name' parameter with the agent name to use." };
    }
    const agent = agents.find((a) => a.name === name);
    if (!agent || agent.state === "load_failed") {
      return { ok: false, reason: "agent_not_found", guidance: `Agent '${name}' does not exist. Create it with 'cello create-agent ${name}', register it, then retry — or check names with cello_agents.` };
    }
    // M16 033-CHANNELVIEW: a channel is an identity the daemon administers, not an agent anyone
    // attends.
    if (isChannelAgent(name)) {
      return { ok: false, reason: "channel_not_an_agent", guidance: `'${name}' is a channel, not an agent. Select the agent that administers it; channel commands take the channel's key.` };
    }
    const connState = getConnState(connectionId);
    if (!connState) {
      return { ok: false, reason: "connection_not_registered", guidance: "Send ipc.connect frame before calling agent tools." };
    }
    if (!onlineAgents.has(name)) {
      return {
        ok: false,
        reason: "agent_offline",
        agent: name,
        guidance: `'${name}' is offline. Start it with cello_start_agent, then select it. Your current agent is unchanged.`,
      };
    }
    const caller = currentCaller();
    const force = params?.["force"] === true;
    // `trigger: "replay"` is the plugin re-selecting after a reconnect, or the CLI re-selecting its
    // saved agent for one command. A replay never takes a held agent: it selects it for reading, and
    // the guard refuses anything that acts as it.
    const claimed = params?.trigger;
    const trigger = claimed === undefined ? "explicit" : claimed === "replay" ? "replay" : "unrecognized";
    const fromAgent = connState.currentAgent;
    const listener = connState.clientType === "hermes";
    let role: "holder" | "listener" | "reader";
    let tookOverFrom: string | undefined;

    if (listener) {
      if (fromAgent === name) {
        return { ok: false, reason: "agent_already_current", guidance: `Agent '${name}' is already the current agent for this connection. No action needed — you can proceed with session operations.` };
      }
      if (fromAgent) registry.dropListener(fromAgent, connectionId);
      registry.setListener(name, connectionId);
      role = "listener";
    } else {
      if (fromAgent === name && registry.check(name, caller).ok && registry.holderView(name) !== null) {
        return { ok: false, reason: "agent_already_current", guidance: `Agent '${name}' is already the current agent for this connection. No action needed — you can proceed with session operations.` };
      }
      // Sockets that stay open receive doorbells. A CLI command or a one-shot web call does not.
      const channel = connState.clientType === "endpoint" || connState.clientType === "cli" ? undefined : connectionId;
      const taken = registry.take(name, caller, { force, ...(channel !== undefined ? { channel } : {}) });
      if (!taken.ok) {
        const h = taken.holder;
        if (trigger === "replay") {
          role = "reader";
        } else {
          logger.info("agent.attend.refused", { connectionId, method: "cello_use_agent", agentName: name, reason: "agent_held", holderLabel: h.label, callerLabel: caller.label });
          return {
            ok: false,
            reason: "agent_held",
            agent: name,
            holder: h,
            guidance:
              `'${name}' is being used by ${h.label} (since ${h.since}, last active ${h.last_active}). Nothing changed. ` +
              `To take it over, call cello_use_agent again with force: true (cello use-agent --force) — ${h.label} will be told. ` +
              `Or choose a different agent.`,
          };
        }
      } else {
        role = "holder";
        if (taken.displaced) {
          tookOverFrom = taken.displaced.label;
          for (const ch of taken.displaced.channels) getNotificationDispatcher().dispatchAgentDisplaced(ch, name, caller.label);
          logger.warn("agent.attend.displaced", { connectionId, agentName: name, fromLabel: taken.displaced.label, byLabel: caller.label });
        }
      }
    }

    connState.currentAgent = name;
    delete connState.clearedAgent;
    if (role !== "reader") {
      // A fresh hold opens a fresh away period: the next one gets its own ack.
      for (const key of Array.from(awayAckSent)) {
        if (key.startsWith(`${name}:`)) awayAckSent.delete(key);
      }
    }
    getNotificationDispatcher().dispatchAgentCurrentChanged(connectionId, fromAgent, name);
    logger.info("agent.current.switched", { connectionId, fromAgent, toAgent: name, trigger, role });
    const result: Record<string, unknown> = { ok: true, role, holder: registry.holderView(name) };
    if (tookOverFrom !== undefined) {
      result["took_over_from"] = tookOverFrom;
      result["took_over_guidance"] = `You took '${name}' over from ${tookOverFrom}, which has been told and can no longer send, receive or close as it.`;
    }
    if (role === "reader") {
      const h = registry.holderView(name)!;
      result["holder_guidance"] =
        `'${name}' is held by ${h.label}. This connection can read as it, but sending, receiving and closing are refused ` +
        `until you take it over with cello_use_agent and force: true (cello use-agent --force).`;
    }
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
      logger.warn("agent.registration.read.failed", { agentName: name, reason: extractErrorMessage(err) });
      result["warning"] = "registration_unknown";
      result["warning_guidance"] = `Agent '${name}' is selected, but its registration status could not be read — run 'cello status' to check whether it is registered with the directory.`;
    }
    // ─── M10B / DOD-END-PENDING-1 — tell the operator a decision is waiting ────────────────────
    // The clause: "on selecting an agent with pending items, the operator is told they are waiting."
    //
    // COUNT ONLY, and do NOT mark notified here. Marking on selection would mark them told about
    // something they were never shown — the nudge says a number, the LIST is what shows the items,
    // and `cello_endorsement_consent_list` is what records that they saw it. The two lifetimes stay separate
    // (M10B-D5): the notification goes quiet once seen, the ITEMS persist until decided.
    //
    // A failure here must NOT break selection, for the same reason the registration read above does
    // not: the agent IS selected. But it must not read as "nothing pending" either — an unknown is
    // surfaced as an unknown (§5a), because silence is exactly how an endorsement dies unnoticed.
    try {
      const rec = loadedAgents.find((a) => a.name === name);
      if (rec) {
        const pending = new TrustSignalStore(sessionNodeManager.getDb(), logger).countUnnotifiedConsent(rec.pubkey);
        if (pending > 0) {
          result["pending_consent"] = pending;
          result["pending_consent_guidance"] =
            `${pending} item${pending === 1 ? "" : "s"} awaiting your decision for '${name}'. ` +
            `Run cello_endorsement_consent_list to read ${pending === 1 ? "it" : "them"} and accept or refuse.`;
        }
      }
    } catch (err: unknown) {
      logger.warn("signal.consent.count_failed", {
        agentName: name, reason: extractErrorMessage(err),
      });
      result["pending_consent"] = "unknown";
      result["pending_consent_guidance"] =
        `Could not read pending consent items for '${name}' — run cello_endorsement_consent_list to check directly.`;
    }
    return result;
  });

  // ─── MCP-001: cello_list_agents handler ───
  /**
   * M15D: a stream-holding web session registers its socket as this agent's live event channel, so
   * doorbells reach it and the agent counts as reachable. Endpoint sockets only; the caller must
   * hold the agent or find it unheld (no force here — taking over is `cello_use_agent`).
   */
  handlers.set("agent.attend", async (params, connectionId) => {
    const connState = getConnState(connectionId);
    if (connState?.clientType !== "endpoint") {
      return { ok: false, reason: "endpoint_only", guidance: "agent.attend is for the web endpoint's stream sessions. A local session uses cello_use_agent." };
    }
    const caller = currentCaller();
    const name = typeof params?.["agent"] === "string" ? (params["agent"] as string) : registry.heldBy(caller.key);
    if (!name || !loadedAgents.some((a) => a.name === name)) {
      return { ok: false, reason: "no_current_agent", guidance: "Name the agent to attend, or select one with cello_use_agent first." };
    }
    if (!onlineAgents.has(name)) {
      return { ok: false, reason: "agent_offline", agent: name, guidance: `'${name}' is offline. Start it with cello_start_agent, then retry.` };
    }
    const taken = registry.take(name, caller, { channel: connectionId });
    if (!taken.ok) {
      return {
        ok: false, reason: "agent_held", agent: name, holder: taken.holder,
        guidance: `'${name}' is being used by ${taken.holder.label}. Take it over with cello_use_agent and force: true, then retry.`,
      };
    }
    connState.currentAgent = name;
    logger.info("agent.attend.channel", { connectionId, agentName: name, callerLabel: caller.label });
    return { ok: true, agent: name, holder: registry.holderView(name) };
  });

  handlers.set("cello_list_agents", async (_params, connectionId) => {
    const agents = getAgentsForConnection(connectionId);
    // An empty roster is the one answer that needs words rather than data. The CLI imports
    // NO_AGENTS_GUIDANCE directly (cli depends on daemon), but `connect` depends on no
    // @cello-protocol package at all — so the shim can only learn this over the wire, and an
    // operator who never opens a terminal would otherwise get an empty list and no explanation
    // of the cohort gate standing between them and a registration token.
    if (agents.length === 0) return { agents, onboarding: noAgentsGuidance() };
    return { agents };
  });

  // ─── M7-REGISTRATION (Action 2): cello_register handler ───
  // Registers a LOADED agent (one with a K_local `key` under ~/.cello/agents/<name>/)
  // with the directory: ML-DSA keygen → register_request → FROST DKG → register_success,
  // persisting the ML-DSA keypair, FROST share, registration state, and agent→user link.
  // Invoked with a paired device's grant.
  // Single-flight guard (M1): the directory's registration reply frames
  // (dkg_ready / register_success / register_error) carry NO agent identifier, so
  // two concurrent registrations over the one shared directory signaling stream
  // would each arm a resolver and both receive the same reply — cross-wiring the
  // ceremonies. Serialize registration daemon-wide (it is a rare, once-per-agent,
  // human-initiated operation). This is the registration analogue of the
  // sealInterruptedInProgress guard, but global rather than per-key because the
  // frames are not agent-tagged.
}
