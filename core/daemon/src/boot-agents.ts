/**
 * Phase 2 of boot: the agents this daemon holds, and everything that acts on their behalf.
 *
 * Identities loaded from the encrypted `agents` table, their signing keys, the content park and its
 * recovery path, the reconnect drain, and the queue that retries a submission the directory would
 * not take. Phase 1 built the machinery; this is where it acquires subjects.
 *
 * ⚠️ FOUR VALUES ARRIVE AS GETTERS BECAUSE THEY DO NOT EXIST YET — `flushAwaitingContent`,
 * `onlineAgents`, `sharedSignaling` and `perAgentSignaling`, all declared BELOW this phase and all
 * read from callbacks that run long after boot.
 *
 * **They are LOUD, not silent, and the difference is the thing to remember.** Three of the four are
 * `const`, so a by-value pass is a temporal-dead-zone `ReferenceError` at boot — every test red
 * immediately. (An earlier version of this comment said `onlineAgents` would "freeze as an empty
 * set". It would not: it is a `const` below the call, and it is a `Set`, so even declared above it
 * would pass by reference and track later additions. Wrong twice over.)
 *
 * **The SILENT shape is a `let` that is assigned further down** — still `undefined`, no error, no
 * type complaint. That is what unit 4 shipped. Two of them are still live in the composition root
 * and every later phase crosses them: `reconcileScheduler` and `documentOwnerKeyForHook`. The test
 * to apply is "is this a `let` assigned below?", not "would this value freeze?" — the freezing cases
 * announce themselves.
 */
import { loadAgents } from "./agent-loader.js";
import { DbRegistrationPersistence } from "./db-identity-store.js";
import { createContentPark } from "./content-park.js";
import { createReconnectDrain } from "./reconnect-drain.js";
import { SubmissionRetryQueue } from "./submission-retry.js";
import type { PendingSubmission } from "./submission-retry.js";
import { TrustSignalStore } from "./trust-signal-store.js";
import { sendSealedSubmission } from "./signal-submission.js";
import { extractErrorMessage } from "./error-message.js";
import type { SubmissionOp } from "@cello-protocol/protocol-types";
import type { AgentInfo, DaemonConfig, Logger } from "./types.js";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { SecurityGatewayClient } from "@cello-protocol/gateway";
import type { SignalingManager } from "@cello-protocol/transport";

export interface BootAgentsDeps {
  config: DaemonConfig;
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  securityGateway: SecurityGatewayClient;
  /**
   * ⚠️ THE THREE BELOW ARE GETTERS AND MUST STAY THAT WAY. All three are declared BELOW this phase
   * in the composition root and read from inside callbacks that run long after boot. By value,
   * `onlineAgents` freezes as the empty set it is at construction — every agent reads as offline and
   * no submission ever sends — and the other two freeze as `undefined`.
   */
  getFlushAwaitingContent: () => (agentName: string) => Promise<void>;
  getOnlineAgents: () => ReadonlySet<string>;
  getSharedSignaling: () => SignalingManager | undefined;
  getPerAgentSignaling: () => Map<string, { signaling: SignalingManager }>;
}

export async function startBootAgents(deps: BootAgentsDeps) {
  const {
    config, logger, sessionNodeManager, securityGateway,
    getFlushAwaitingContent, getOnlineAgents, getSharedSignaling, getPerAgentSignaling,
  } = deps;

  // Load agent identities from the encrypted `agents` table (PERSIST-002 AC-007 — one path).
  // (The encrypted store + lock were established above, before manifest verification.)
  const { loaded: loadedAgents, failed: failedAgents } = await loadAgents(sessionNodeManager.getDb(), logger);

  // PERSIST-002: per-agent DB-backed identity persistence. The registration handler and the
  // ceremony/seal signer-reconstruction load the FROST share (and persist the identity) through this
  // seam — the encrypted `agents` row, never a flat file.
  const getPersistence = (agentName: string): DbRegistrationPersistence =>
    new DbRegistrationPersistence({ db: sessionNodeManager.getDb(), agentName, logger });

  // Build agent state. `state` here is the LOAD outcome only — whether the identity opened at all.
  // The state an operator sees is derived per call by resolveAgentState (agent-state.ts), because
  // most of what it depends on (started, signaling, attendance, paused) changes while the daemon
  // runs and cannot be baked into a record at boot.
  const agents: AgentInfo[] = [
    ...loadedAgents.map((a) => ({
      name: a.name,
      state: "stopped" as const,
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
  // DOD-M15-EPHEMERAL-AUTH-1: the session manager signs each session's throwaway key with the
  // agent's identity, so it needs the same providers. Injected here rather than through the
  // constructor because this map is built after the manager exists — the same reason
  // `setParkedDrainHook` is a setter.
  sessionNodeManager.setKeyProviderResolver((agentName: string) => keyProviders.get(agentName));

  // Constructed HERE, before ANY boot-time caller. autoRecoverForAgent is invoked from an agent's
  // onConnected and from the seal-upgrade content gate — both of which run long before the IPC
  // handler map exists. Its handlers register later (phase 2), which is what lets this sit up here.
  const contentPark = createContentPark({
    logger,
    sessionNodeManager,
    agents,
    getKeyProvider: (agentName: string) => keyProviders.get(agentName),
    // M12-P17: annexed content bypasses the live inbound funnel, so it is screened here instead.
    securityGateway,
  });
  const autoRecoverForAgent = (agentName: string, trigger?: string): Promise<void> =>
    contentPark.autoRecoverForAgent(agentName, trigger);

  // DOD-PARK-DRAIN-1: drain where the parking actually happens. Content parks when the RELAY link
  // drops, and the manager tells us on every event that changes this agent's ability to pull — the
  // first ensure, a reservation LOST, a reservation REGAINED, the slow backstop sweep. (056-SLOTDEAD:
  // was "watchdog rebuild, auth_ok rebuild"; neither exists, and the pair names the cause instead.)
  sessionNodeManager.setParkedDrainHook((agentName: string, reason: string) => {
    // M12-P12 (review F1): the SENDER half of the same event. A refused park deposit leaves a
    // durable retry_queue row, and until this call existed the only things that drained it were a
    // daemon restart and cello_start_agent — so the fix made a lost message restart-recoverable
    // while the DoD line promises "no restart". A lost reservation is where parking actually happens,
    // so it is where the re-park fires (056-SLOTDEAD: was "the watchdog rebuild", now deleted).
    void getFlushAwaitingContent()(agentName).catch((err: unknown) => {
      logger.warn("content.park.flush.failed", { agentName, trigger: reason, stage: "drain_hook", error: extractErrorMessage(err) });
    });
    void autoRecoverForAgent(agentName, reason).catch((err: unknown) => {
      // autoRecoverForAgent catches per-relay errors internally; this is the backstop, and it uses
      // extractErrorMessage because the transport rejects with structured plain objects that
      // String() renders as "[object Object]" — the reason 100+ real failures were undiagnosable.
      logger.warn("content.recover.auto.failed", { agentName, trigger: reason, stage: "drain_hook", error: extractErrorMessage(err) });
    });
  });

  // DOD-PARK-DRAIN-1: what an agent's signaling reconnect does — ensure THEN drain, never both at
  // once. Constructed here, beside the content park it drains; `onlineAgents` is read inside the
  // callback (at connect time), never during this construction, so its later declaration is not a
  // temporal-dead-zone hazard.
  const onSignalingConnected = createReconnectDrain({
    logger,
    isAgentOnline: (agentName: string) => getOnlineAgents().has(agentName),
    ensureStandingReceiver: (agentName: string) => sessionNodeManager.ensureStandingReceiverForAgent(agentName),
    drainParked: (agentName: string) => autoRecoverForAgent(agentName, "signaling_reconnect"),
    // M12-P12 (review F1): ordered AFTER ensureStandingReceiver by createReconnectDrain's own
    // ensure→drain contract — a re-park needs the receiver that the ensure step rebuilds.
    flushSender: (agentName: string) => getFlushAwaitingContent()(agentName),
  });

  /**
   * DOD-M15-ENDORSE-RETRY-1 — sealed submissions whose send reached no directory node.
   *
   * The consortium has three nodes and a submission used to die with whichever one this daemon
   * happened to be connected to. It is held here instead and re-sent when the SignalingManager
   * reconnects — that reconnect IS the failover, and nothing in this daemon picks a node for a
   * submission (`sendSealedSubmission`'s header rules that out). Safe because `submission_id` is
   * derived from the signed plaintext: a second node stores it once and the portal mints once.
   */
  const submissionRetries = new SubmissionRetryQueue({
    logger,
    send: async (pending: PendingSubmission) => {
      /**
       * THE AGENT MUST STILL BE HERE TO SIGN, and this failure has its own name.
       *
       * It borrowed `submission_refused_by_node` at first, which states that a directory node
       * decoded, evaluated and refused the submission — none of which happened. Stacked on the
       * give-up reason it produced, the operator saw two labels both pointing at the directory for
       * a cause that is entirely local (review M5).
       *
       * Neither branch is reachable in this daemon today — nothing removes from `keyProviders` or
       * `loadedAgents` — so this is a guard against a future unload path rather than a live case.
       * That is said plainly instead of being implied by a comment describing a state the code
       * cannot reach.
       */
      /**
       * READ the agent's manager; never CREATE one, and this ONE guard is the whole check.
       *
       * `getAgentSignaling` is not a getter — for an agent with no manager it constructs one, which
       * dials, authenticates, and installs an unbounded reconnect loop. `dropAgentSignaling` exists
       * to stop and forget a manager for an agent whose registration failed terminally, and a
       * background retry that silently rebuilt it would undo that decision from a timer nobody is
       * watching.
       *
       * It replaces a `keyProviders` + `loadedAgents` pair that is now dead: the manager was built
       * WITH this agent's key provider and pubkey, so its presence is the accurate statement of
       * "this daemon can still send as this agent", and nothing prunes either of those two maps.
       *
       * There is always a manager here in practice — the first-pass send built one before this
       * submission could ever have been held. Its absence means it was deliberately dropped, and
       * the right answer is to stop trying, not to resurrect it.
       */
      // The SAME resolution `getAgentSignaling` performs, minus the construction: the shared
      // manager first (the in-process path, where `getPerAgentSignaling()` is never populated at all),
      // then this agent's own. Reading only the per-agent map would refuse every retry on the
      // shared path — which is how this fix first failed its own live test.
      const existing = getSharedSignaling()
        ? { signaling: getSharedSignaling()! }
        : getPerAgentSignaling().get(pending.agentName);
      if (!existing) {
        return {
          ok: false as const,
          reason: "submission_agent_unloaded" as const,
          guidance:
            `The directory connection for '${pending.agentName}' has been torn down, so the held ` +
            "submission cannot be sent. Start the agent with cello_start_agent and issue it again — " +
            "re-sending is safe, the submission id is derived from the content.",
        };
      }
      return sendSealedSubmission({
        signaling: existing.signaling,
        submissionId: pending.submissionId,
        intakeKeyId: pending.intakeKeyId,
        ciphertext: pending.ciphertext,
        logger,
      });
    },
    onAccepted: (pending, stored) => {
      // THE STABLE ID THE ENQUEUE CAPTURED, not a re-resolution from the mutable name (review M6).
      // `agentName` is a display label and is reusable after a retire; re-deriving it here would
      // write the accepted row under a different agent's id if a name were retired and reused
      // inside the retry window. The correct value is already in the struct.
      recordIssuedSubmission(pending.agentName, pending.agentId, {
        submissionId: pending.submissionId,
        subject: pending.subject,
        op: pending.op,
        intakeKeyId: pending.intakeKeyId,
        stored,
      });
    },
    ...(config.submissionRetryIntervalsMs?.staggerMs === undefined
      ? {}
      : { staggerMs: config.submissionRetryIntervalsMs.staggerMs }),
    ...(config.submissionRetryIntervalsMs?.localPreconditionRetryMs === undefined
      ? {}
      : { localPreconditionRetryMs: config.submissionRetryIntervalsMs.localPreconditionRetryMs }),
  });

  /**
   * KEEP THE HANDLE, or a withdrawal has nothing to name. The submission id is content-derived and
   * so reproducible in principle, but only by re-composing the exact original body — which the
   * operator no longer has once they have sent it.
   *
   * Best-effort on purpose: the submission IS accepted by the time this runs, and failing the call
   * over a local bookkeeping write would turn a success into a reported failure and invite a
   * re-send of something already queued. Logged loudly instead.
   *
   * Shared by the first-pass send and the retry, so the two cannot drift about what a landed
   * submission records.
   */
  function recordIssuedSubmission(
    agentName: string,
    /** The STABLE key, supplied by the caller. Never re-derived from `agentName` here — that is a
     *  display label, and this table is keyed by identity. */
    agentId: string,
    s: { submissionId: string; subject: string; op: SubmissionOp; intakeKeyId: string; stored: boolean },
  ): void {
    try {
      const store = new TrustSignalStore(sessionNodeManager.getDb(), logger);
      store.recordIssuedSubmission({
        agentId,
        submissionId: s.submissionId,
        subjectPubkey: s.subject,
        op: s.op,
        intakeKeyId: s.intakeKeyId,
        stored: s.stored,
      });
    } catch (err: unknown) {
      logger.error("signal.submission.record_failed", {
        agentName,
        submissionId: s.submissionId,
        reason: extractErrorMessage(err),
      });
    }
  }

  return {
    loadedAgents, getPersistence, agents, keyProviders, contentPark,
    autoRecoverForAgent, onSignalingConnected, submissionRetries, recordIssuedSubmission,
  };
}
