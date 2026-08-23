/**
 * cello_close_session — the bilateral close, and every way it can fail.
 *
 * M7 error discipline: each distinct failure cause produces a DISTINCT error code
 * (session_already_sealed, seal_in_progress, seal_interrupted_counterparty_unavailable,
 * seal_interrupted_rejected_by_counterparty, signaling_reconnecting). A close that fails must tell
 * the operator WHY, not merely that it failed — this handler exists as much for its error paths as
 * for its happy path.
 *
 * SI-001: there is NO auto-seal on a session_interrupted receipt. The operator must close
 * explicitly. A daemon that sealed on its own would notarize a conversation nobody chose to end.
 *
 * SI-001 IS NARROWER THAN IT READS, and the boundary matters (DOD-M12B-RESTART-SEAL-1, 2026-08-17;
 * RESTATED 2026-08-18 for DOD-M12B-PENDING-RESOLVE-1). SI-001 governs a LIVE interruption — the
 * relay says the counterparty vanished while the operator is at the keyboard and may still want to
 * wait. `restart-seal-resolver.ts` seals TWO different populations, and the test that licenses both
 * is **somebody chose to end this**, not "we caused it":
 *
 *   1. `interrupted` with `interrupted_by = 'local'` — OUR OWN stop destroyed it, and it cannot be
 *      resumed because the transport keypairs died with the process. The only alternative is
 *      force-abandon, which forfeits the receipt: the choice is seal-or-abandon, not seal-or-resume.
 *   2. `seal_interrupted_pending` — a seal commitment nobody asked the directory to notarize.
 *
 * **The old sentence here — "nothing the counterparty caused is auto-sealed" — is no longer true,
 * and saying so plainly matters because this paragraph is what a future widening will cite.** A
 * responder-side pending row is created by a request the COUNTERPARTY sent. What licenses it is not
 * that we caused it but that they explicitly asked to seal; an initiator-side row is licensed by
 * their signed leaf. Either way the conversation is one somebody chose to end, which is exactly what
 * SI-001 protects against — and SI-001 itself holds unchanged for a live interruption.
 *
 * This was on my DO-NOT-CUT list. It has fifteen dependencies — a long list, but a KNOWN one, and
 * that is the entire difference from a closure over 73 shared locals.
 */
import { randomUUID } from "node:crypto";

/**
 * DOD-M12B-ABANDON-NOTIFY-1 — how long the courtesy notice may delay a force-abandon.
 *
 * Force-abandon is the operator's escape hatch out of a session that can never seal, and it must
 * always return. Telling the counterparty is worth a moment; it is not worth the escape hatch.
 */
const ABANDON_NOTICE_DEADLINE_MS = 3_000;
import { SignalingManager } from "@cello-protocol/transport";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { IpcHandler } from "./ipc-server.js";
import type { SessionNodeManager } from "./session-node-manager.js";
import { classifyOnlineResult, type DiscoveryOutcome } from "./cross-node-negotiation.js";
import type { Logger, SessionRecord } from "./types.js";
import type { ConnState } from "./contact-handlers.js";
import { validateSessionName } from "./session-name.js";
import type { SealFlowResult, ActiveSealResult } from "./seal-flows.js";
import type { SealCompletion, UnilateralResult } from "./seal-coordinator.js";
import { escalateToUnilateralSeal as runUnilateralEscalation, UNILATERAL_SEAL_TIMEOUT_MS } from "./seal-escalation.js";
import { describeSealCommitted } from "./close-commitment.js";
import type { DirectoryEndpoint } from "./signaling-connect.js";
import type { ConsortiumEndpoint } from "./directory-bootstrap.js";

export interface CloseSessionDeps {
  handlers: Map<string, IpcHandler>;
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  /** M12-P14: drain this agent's parked mailbox before judging seal readiness (contentPark.autoRecoverForAgent). */
  recoverParkedContent?: (agentName: string, trigger: string) => Promise<void>;
  getConnState: (connectionId: string) => ConnState | undefined;
  resolveCurrentAgent: (connState: ConnState | undefined, explicitAgent?: string) => string | null;
  NO_CURRENT_AGENT_RESPONSE: unknown;
  getKeyProvider: (agentName: string) => KeyProvider | undefined;
  signalingFor: (agentName: string) => SignalingManager | undefined;
  sendOver: (agentName: string, frame: Record<string, unknown>) => Promise<{ ok: boolean; reason?: string }>;
  waitForSignalingConnected: (mgr: SignalingManager, timeoutMs: number) => Promise<boolean>;
  openVisitingConnection: (agentName: string, agentKeyProvider: KeyProvider, agentPubkeyHex: string, endpoint: DirectoryEndpoint, correlationId: string, nodeId: string) => { mgr: SignalingManager; stop: (reason: string) => Promise<void> };
  /**
   * ASK the directory for a seal certificate this daemon was never pushed
   * (`DOD-TERMINAL-STATE-DIVERGENCE-1`).
   *
   * The `session_sealed` frame is pushed ONCE. If this daemon's stream was down at that instant it
   * is gone — the re-delivery queue is per-node and clients roam. The session IS notarized and the
   * counterparty holds a receipt; this side holds a non-terminal row and, without asking, can never
   * produce one.
   *
   * Wired here because THIS is where the operator gets stuck: they run a close, it fails, and the
   * failure is indistinguishable from "the seal has not happened". Asking turns that into "it
   * happened, here is your receipt". The directory is not trusted for the answer — the certificate
   * is re-verified against its FROST signature before anything is recorded.
   */
  pullSealCertificate?: (agentName: string, sessionIdHex: string) => Promise<{ ok: boolean; reason?: string }>;
  /**
   * Ask the directory where an agent is homed RIGHT NOW. Needed because `crossNodeBrokerBySession`
   * is in-memory and a restart empties it — and a restart is what makes a session interrupted.
   */
  runDiscoveryLookup?: (
    signaling: SignalingManager,
    targetHex: string,
    timeoutMs: number,
    correlationId: string,
  ) => Promise<DiscoveryOutcome>;
  /** sessionId → the broker node id that brokered this cross-node session. */
  crossNodeBrokerBySession: Map<string, string>;
  /**
   * DOD-M15-CLOSEWAIT-1 review MEDIUM-6: hand a detached seal tail to the daemon so `stop()` can
   * drain it. Optional so an embedder or a test harness constructs without one — but when it is
   * absent the tail is genuinely untracked, which is why the daemon always passes it.
   */
  registerBackgroundSeal?: (p: Promise<unknown>) => void;
  /**
   * DOD-M15-SEAL-FAILED-TERMINAL-1: record/clear the last background ceremony failure, so
   * `cello_sealed_receipt` can tell a DEAD seal from a slow one.
   *
   * REQUIRED, not optional — review HIGH-3. Optionality made a missing wiring silent: deleting the
   * daemon's `getSealFailure` line left tests, lint and typecheck all green while the whole unit was
   * inert. There is exactly one composition root, so optionality buys nothing and costs the compiler
   * the ability to catch a wiring that was never done. (`RestartSealResolverDeps.markGaveUp` makes
   * the same argument in its own docstring.)
   */
  sealFailures: {
    record: (a: string, s: string, reason: string, at: string, kind: "unresolved" | "threw") => void;
    clear: (a: string, s: string) => void;
  };
  // ── the seal cluster (seal-coordinator.ts) ──
  sealKey: (agentName: string, sessionId: string) => string;
  sealInterruptedInProgress: Set<string>;
  pendingSealWaiters: Map<string, (completion: SealCompletion) => void>;
  pendingUnilateralWaiters: Map<string, (r: UnilateralResult) => void>;
  /** The verified consortium roster, re-resolved at ceremony time. */
  resolveConsortiumRoster: () => Promise<ConsortiumEndpoint[] | null>;
  /**
   * DOD-M12B-INTERRUPTED-ESCALATE-1: how long to wait for the directory's answer to a
   * `seal_unilateral` request. Default 30_000. Injectable because this wait now sits on the
   * INTERRUPTED close path too, and a suite that exercises it should not spend half a minute per
   * case discovering that a stub never answers.
   */
  unilateralTimeoutMs?: number;
  // ── the two seal-initiation flows (seal-flows.ts) ──
  handleSealInterruptedFlow: (sessionId: string, record: SessionRecord, correlationId: string, merkleRootAtInterruption: string, via?: SignalingManager) => Promise<SealFlowResult>;
  handleActiveSealFlow: (sessionId: string, record: SessionRecord, correlationId: string) => Promise<ActiveSealResult>;
}


export function registerCloseSessionHandler(deps: CloseSessionDeps): void {
  const {
    resolveConsortiumRoster,
    handlers, logger, sessionNodeManager, getConnState, resolveCurrentAgent,
    NO_CURRENT_AGENT_RESPONSE, getKeyProvider, signalingFor, sendOver, waitForSignalingConnected,
    openVisitingConnection, runDiscoveryLookup, crossNodeBrokerBySession, sealKey, sealInterruptedInProgress,
    registerBackgroundSeal, sealFailures,
    pendingSealWaiters, pendingUnilateralWaiters, handleSealInterruptedFlow, handleActiveSealFlow,
    recoverParkedContent,
  } = deps;
  const UNILATERAL_TIMEOUT_MS = deps.unilateralTimeoutMs ?? UNILATERAL_SEAL_TIMEOUT_MS;

  /**
   * How long the seal path waits to learn where the counterparty is homed.
   *
   * DELIBERATELY SHORT, and not the 10s the session negotiator uses. This lookup is a point-read of
   * replicated presence — milliseconds against a healthy directory — and it sits in front of EVERY
   * interrupted close, including same-node ones that need no dial at all. Borrowing the negotiator's
   * 10s added ten seconds to every such close and pushed the unilateral-escalation tests past their
   * budget: the seal did not break, it just arrived too late to matter.
   *
   * A directory that cannot answer within this window is one we would not want to wait on anyway —
   * the close proceeds on the home stream, exactly as it did before the lookup existed.
   */
  const SEAL_DISCOVERY_TIMEOUT_MS = 2_500;

  /**
   * Open a transient visiting connection to the node that BROKERED this session, when that is not
   * the node this agent is homed on. Returns null for a same-node session (the ordinary case) and
   * whenever the connection cannot be established — in both the caller proceeds on the home stream.
   *
   * WHY THE CLIENT HAS TO DIAL. Directories never forward signaling to each other; the M12 journal
   * struck that out as a channel that does not exist. A directory routes a frame by looking up a
   * stream IT holds, and a daemon holds its stream to its own home node — so seal frames pushed by
   * the broker reach a party only if that party holds a stream to the BROKER. Without this the
   * close times out reporting the counterparty unavailable while they are online and waiting.
   *
   * SHARED BY BOTH SEAL PATHS ON PURPOSE. This lived inline in the active branch, gated on
   * `status === "active"`, and the interrupted branch sent the same frames without it — which is
   * precisely the defect (two agents on two nodes, symmetric timeout, 2026-08-07). One
   * implementation is what stops that divergence coming back.
   */
  async function openSealBrokerConnection(
    agentName: string,
    sessionId: string,
    correlationId: string,
    /** Only set on the RETRY, after a home-stream attempt already failed — see the call site. */
    discoverVia?: { counterpartyPubkeyHex: string },
  ): Promise<{ mgr: SignalingManager; stop: (reason: string) => Promise<void> } | null> {
    let brokerNodeForSeal = crossNodeBrokerBySession.get(`${agentName}:${sessionId}`);

    // THE MAP DOES NOT SURVIVE THE RESTART THAT CREATES THE CONDITION. It is in-memory, populated
    // while a session is brokered, and emptied by a daemon restart — which is exactly what flips a
    // live session to `interrupted`. Gating on it alone meant the dial never fired for the case it
    // was added for (shipped as 0.0.140 and disproved against real stranded sessions the same hour).
    //
    // The answer is NOT to persist the broker. The node that brokered the session hours ago need
    // not be where the counterparty lives now — agents re-home. What matters at seal time is where
    // they are NOW, which any directory can answer from replicated presence. Classified by the same
    // `classifyOnlineResult` the outbound path uses, so "same node" and "offline" mean here exactly
    // what they mean there.
    if (!brokerNodeForSeal && discoverVia && runDiscoveryLookup) {
      const sig = signalingFor(agentName);
      if (sig) {
        const disc = await runDiscoveryLookup(sig, discoverVia.counterpartyPubkeyHex, SEAL_DISCOVERY_TIMEOUT_MS, correlationId);
        if (disc.kind === "result") {
          const action = classifyOnlineResult(disc.state, disc.owningNodeIds, sig.currentDirectoryNodeId ?? null);
          // Only `cross_node` warrants a dial. `same_node` already has the right stream, and
          // `offline` is a real answer — dialling their node cannot conjure a stream they do not have.
          if (action.kind === "cross_node") brokerNodeForSeal = action.owningNodeId;
        } else {
          // A lookup that did not answer is the pre-fix behaviour, not a new failure: proceed on the
          // home stream. Logged so it stays distinguishable from "the counterparty is on our node".
          logger.warn("session.seal.broker.discovery_failed", { agentName, sessionId, kind: disc.kind, correlationId });
        }
      }
    }

    // Same-node session, or nowhere to dial: the home stream is already the right one.
    if (!brokerNodeForSeal) return null;

    const sealKp = getKeyProvider(agentName);
    if (!sealKp) {
      // Never skip the cross-node reconnect silently — without a key provider the seal reverts to
      // the pre-fix timeout, and this log is what keeps that distinguishable from an ordinary
      // counterparty-didn't-close timeout.
      logger.warn("session.seal.broker.no_keyprovider", { agentName, brokerNode: brokerNodeForSeal, correlationId });
      return null;
    }

    const sealPubHex = Buffer.from(await sealKp.getPublicKey()).toString("hex");
    const roster = await resolveConsortiumRoster();
    const brokerTarget = roster?.find((e) => e.nodeId === brokerNodeForSeal) ?? null;
    if (!brokerTarget) {
      logger.warn("session.seal.broker.unresolved", { agentName, brokerNode: brokerNodeForSeal, correlationId });
      return null;
    }

    const conn = openVisitingConnection(
      agentName, sealKp, sealPubHex,
      { peerId: brokerTarget.peerId, multiaddr: brokerTarget.multiaddr },
      correlationId, brokerNodeForSeal,
    );
    if (await waitForSignalingConnected(conn.mgr, 10_000)) {
      logger.info("session.seal.broker.reconnected", { agentName, brokerNode: brokerNodeForSeal, correlationId });
      return conn;
    }
    // Tear the half-open connection down rather than leaking it, and proceed degraded.
    await conn.stop("seal-broker-unreachable");
    logger.warn("session.seal.broker.unreachable", { agentName, brokerNode: brokerNodeForSeal, correlationId });
    return null;
  }

  // ─── M7-SESSION-001: cello_close_session ────────────────────────────────────
  // M7 error discipline: each distinct failure cause produces a distinct error code.
  // AC-010: session_already_sealed
  // AC-011: seal_in_progress
  // AC-012: seal_interrupted_counterparty_unavailable
  // AC-013: seal_interrupted_rejected_by_counterparty
  // DB-001: signaling_reconnecting
  // SI-001: no auto-seal on session_interrupted receipt; operator must call explicitly
  /**
   * DOD-TERMINAL-STATE-DIVERGENCE-1 — close failures that might mean "it is ALREADY sealed, you were
   * just never told".
   *
   * `session_sealed` is pushed once. Miss it and this side holds a non-terminal row while the
   * counterparty holds a receipt, and every close from here fails in a way that reads exactly like
   * "the seal has not happened yet". These are the reasons where that is a live possibility:
   *
   *   - the counterparty REJECTED our seal request. It does that when it considers the session
   *     already finished, which is precisely the divergence.
   *   - the unilateral escalation TIMED OUT with no answer.
   *   - the relay says the session is sealed or gone — terminal, so nothing more can be added, which
   *     also means whatever exists is final.
   *
   * NOT included: `session_not_found`, `invalid_session_id`, an abandoned session, or a refusal we
   * generated locally. Asking there would be noise on a question already answered.
   */
  const MAY_ALREADY_BE_SEALED = new Set([
    "seal_interrupted_rejected_by_counterparty",
    "seal_unilateral_timeout",
    "session_seal_already_pending",
    "session_sealed",
    /**
     * DOD-M15-TERMINAL-REASON-1. Without this, a close on a session the relay REFUSED skips
     * `pullSealCertificate` entirely — the one probe that distinguishes "never sealed" from "sealed
     * and you were never told". Losing it here is how a close ends with no receipt and no
     * explanation of why.
     */
    "seal_refused",
    "relay_session_gone",
  ]);

  /**
   * The close, wrapped so a failure gets ONE chance to discover the seal already happened.
   *
   * Wrapped rather than patched into each exit: this handler has six failure returns and a seventh
   * would be added without the recovery. The operator's experience is what matters here — they ran a
   * close, it failed, and the answer they get should be a receipt if one exists.
   */
  const closeSession = async (params: Record<string, unknown> | undefined, connectionId: string): Promise<unknown> => {
    const first = await runClose(params, connectionId);
    const failed = first as { ok?: boolean; reason?: string };
    if (failed?.ok !== false || !deps.pullSealCertificate) return first;
    if (!MAY_ALREADY_BE_SEALED.has(String(failed.reason))) return first;

    const connState = getConnState(connectionId);
    const agentName = resolveCurrentAgent(connState, params?.agent as string | undefined);
    // `session_id` — the IPC parameter name. The MCP tool's `cello_session_id` is translated by the
    // shim, and reading that name here would have found nothing and silently skipped the recovery.
    const sessionId = typeof params?.session_id === "string" ? params.session_id : "";
    if (!agentName || sessionId.length === 0) return first;

    const pulled = await deps.pullSealCertificate(agentName, sessionId);
    if (!pulled.ok) {
      // Said out loud. "We asked and there is none" is a different fact from "we never asked", and
      // an operator deciding whether to force-abandon needs to know which one they have.
      logger.info("seal.certificate.pull.none_on_close", {
        agentName, sessionId, closeReason: failed.reason, pullReason: pulled.reason ?? "",
      });
      return {
        ...(first as Record<string, unknown>),
        seal_lookup: pulled.reason === "not_found" ? "asked_none_exists" : `asked_${pulled.reason ?? "failed"}`,
      };
    }

    const recovered = sessionNodeManager.getSealCertificate(agentName, sessionId);
    if (!recovered) return first;
    logger.info("seal.certificate.recovered_on_close", {
      agentName, sessionId, sealedRoot: recovered.sealed_root,
      impact: "the seal existed and this side had never been told; the close now returns the receipt",
    });
    return {
      ok: true,
      sessionId,
      sealed_root: recovered.sealed_root,
      recovered: true,
      guidance:
        "This session was ALREADY sealed — the notarization existed and this daemon had never been " +
        "told, which is why the close appeared to fail. The certificate has been fetched and " +
        "verified against its signature, and is now held locally. Read it with cello_sealed_receipt.",
    };
  };

  handlers.set("cello_close_session", closeSession);

  /**
   * DOD-M12B-SEAL-ESCALATE-DUP-1: the body lives in `seal-escalation.ts` so the away/one-shot path
   * in `daemon.ts` shares it. It used to be a second copy, and it missed every refusal this
   * milestone added.
   */
  const escalateToUnilateralSeal = (
    record: SessionRecord,
    sessionId: string,
    escalation: { reportedRootHex: string; sequenceNumber: number },
    correlationId: string,
    opts: { refuseOnUnusableCarry: boolean } = { refuseOnUnusableCarry: false },
  ) =>
    runUnilateralEscalation(
      {
        logger, sessionNodeManager, sendOver, pendingUnilateralWaiters, sealKey, getKeyProvider,
        timeoutMs: UNILATERAL_TIMEOUT_MS,
        onSealed: (a, sid) => { crossNodeBrokerBySession.delete(`${a}:${sid}`); },
      },
      record.agent_name, sessionId, escalation, correlationId, opts,
    );

  /**
   * Post this side's SEAL ctrl leaf (or recover the one a previous run already posted) and ask the
   * directory to notarize. `null` means there was nothing to escalate with — the caller keeps its
   * own result rather than inventing a failure.
   *
   * SHARED so a third copy cannot appear. It has two callers: the interrupted close, and the
   * `seal_interrupted_pending` close that used to be refused outright.
   */
  const submitAndEscalate = async (
    record: SessionRecord,
    sessionId: string,
    correlationId: string,
  ): Promise<
    | { ok: true; sealed_root: string; seal_type: "unilateral"; legibility?: unknown }
    | { ok: false; reason: string; retry_after_seconds?: number; guidance: string }
    /** No root/sequence to escalate with, AND WHY. `reason` is `submitSealLeaf`'s own — never a
     *  label invented here. Seven distinct conditions produce this, most of them transient and
     *  LOCAL (`standing_receiver_unavailable` right after a boot, `relay_unavailable`, a dial that
     *  failed, our own database refusing a read). Collapsing them into one relay-shaped sentence
     *  told the operator a receipt was permanently gone when they only needed to start the agent. */
    | { escalated: false; reason: string }
  > => {
    const submitted = await sessionNodeManager.submitSealLeaf(record.agent_name, sessionId, correlationId);
    if (submitted.ok || submitted.reason === "responder_seal_already_submitted") {
      logger.info("session.interrupted.seal.leaf.submitted", {
        agentName: record.agent_name, sessionId, correlationId,
      });
    } else {
      logger.warn("session.interrupted.seal.leaf.submit_failed", {
        agentName: record.agent_name, sessionId, reason: submitted.reason, correlationId,
        impact:
          "both sides hold a signed commitment, but no notarization was requested — this session has no receipt and cannot get one once the relay drops it",
      });
    }

    // The root and sequence the directory verifies against. `responder_seal_already_submitted`
    // carries them from the FIRST submit — from THIS process's memory, or recovered from the
    // durable carry after a restart — so a repeat close can still escalate (M8B FINDING-1).
    const escalation = submitted.ok
      ? { reportedRootHex: submitted.reportedRootHex, sequenceNumber: submitted.sequenceNumber }
      : typeof submitted.reportedRootHex === "string" && typeof submitted.sequenceNumber === "number"
        ? { reportedRootHex: submitted.reportedRootHex, sequenceNumber: submitted.sequenceNumber }
        : null;
    // `submitted.ok` always yields an escalation above, so this is only ever the failure reason.
    // Kept as a total expression rather than a cast: if submitSealLeaf's contract is ever loosened,
    // this names the new case instead of building `{reportedRootHex: undefined}` and throwing at
    // `Buffer.from` several frames away.
    if (!escalation) return { escalated: false, reason: submitted.ok ? "submit_returned_no_root" : submitted.reason };

    return await escalateToUnilateralSeal(record, sessionId, escalation, correlationId, {
      refuseOnUnusableCarry: true,
    });
  };

  const runClose = async (params: Record<string, unknown> | undefined, connectionId: string): Promise<unknown> => {
    const connState = getConnState(connectionId);
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
      // A session that reached a seal attempt (interrupted / seal_interrupted_pending) MIGHT have
      // been notarized on the counterparty's side without this side ever learning — the
      // no-pull-twin divergence. A half-open ghost never got that far and forfeits nothing. Warning
      // on both would put the same paragraph on the ninety routine force-abandons that cost nothing
      // and the one that cost a receipt, which buries the only occurrence that matters.
      const mayHaveSealed = record.status === "interrupted" || record.status === "seal_interrupted_pending";
      // ONE id for the close and every line the notice emits, so they can be joined. Minting a
      // fresh one inside the notice call meant its sent/failed/skipped lines belonged to no flow.
      const correlationId = randomUUID();
      // DOD-M12B-ABANDON-NOTIFY-1: TELL THEM FIRST, while the session node still exists — the
      // abandon tears it down, and after that there is no stream to tell them on. Awaited so the
      // answer can be honest about whether they were reached, but it can only ever return: it never
      // throws and never blocks the abandon, which is the operator's escape hatch and must not
      // depend on the counterparty being reachable.
      //
      // Without this the other side keeps its half live, keeps retrying delivery into it, and keeps
      // trying to re-establish — which is what produced the 2026-08-17 storm, where the operator saw
      // connection requests from agents nobody was driving.
      // DELIBERATELY FAIL-OPEN, and this is the one place in the milestone where that is right:
      // force-abandon is the operator's escape hatch out of a session that can never seal, and it
      // must not become conditional on a courtesy. The notice already handles its own failures; this
      // catches the unexpected — an absent method, a throw from the transport layer — so that no
      // fault in telling the counterparty can prevent the operator from ending their own session.
      let notice: { told: boolean; reason: string } = { told: false, reason: "not_attempted" };
      try {
        // A HARD DEADLINE, not just a catch. The catch covers a throw; it does not cover a hang,
        // and `stream.close()` waits for the write buffer to drain with no timeout anywhere in the
        // chain — so a half-dead connection could sit here indefinitely on the one call that must
        // always return. Force-abandon is the escape hatch; it does not get to be slow either.
        notice = await Promise.race([
          sessionNodeManager.notifyCounterpartyAbandon(record.agent_name, sessionId, correlationId),
          new Promise<{ told: boolean; reason: string }>((resolve) => {
            const t = setTimeout(() => resolve({ told: false, reason: "notice_timeout" }), ABANDON_NOTICE_DEADLINE_MS);
            t.unref?.();
          }),
        ]);
      } catch (err: unknown) {
        logger.warn("session.abandon.notice.threw", {
          agentName: record.agent_name, sessionId, correlationId,
          error: err instanceof Error ? err.message : String(err),
          impact: "the counterparty was not told and may keep calling; the abandon itself proceeds",
        });
      }
      const told = notice.told;
      await sessionNodeManager.abandonSession(record.agent_name, sessionId);
      /**
       * FORGET ANY SEAL FAILURE — review MEDIUM-5.
       *
       * An abandoned session is TERMINAL: there is no ceremony to retry and no receipt to obtain.
       * Leaving the marker made two surfaces contradict each other — `cello_sealed_receipt` reported
       * `seal_failed` and told the agent to *"call cello_close_session again"*, while
       * `cello_close_session` refused with `session_abandoned` and *"it is terminal… it cannot be
       * closed."* A refused loop, and exactly the contradicting-surfaces pair the previous unit's
       * review flagged, reintroduced one unit later.
       */
      sealFailures.clear(record.agent_name, sessionId);
      logger.info("session.force_abandoned", {
        agentName: record.agent_name,
        sessionId,
        priorStatus: record.status,
        counterpartyNotified: told,
        counterpartyNoticeReason: notice.reason,
        correlationId,
        // Makes the destructive case findable in a log instead of reconstructable by hand, which is
        // how the 2026-08-06 incident had to be traced.
        mayHaveForfeitedSeal: mayHaveSealed,
      });
      return {
        ok: true,
        status: "abandoned",
        reason: "force_abandoned",
        counterparty_notified: told,
        counterparty_notice_reason: notice.reason,
        guidance: `Session ${sessionId} was force-abandoned — marked terminal locally with no bilateral seal. Use force only for a half-open session that cannot be sealed; a normal close (no force) still attempts the seal so both parties get a notarized receipt.` +
          (told
            ? ` The notice was sent — a counterparty running a current client will stop calling this session. There is no acknowledgement for it, so if connection attempts keep arriving they are on an older build that does not understand it.`
            : notice.reason === "no_local_node"
              ? ` They were NOT told: this side had already torn the session down, so there was nothing to send the notice on. Their half stays open and they may go on retrying delivery and re-dialling until they give up. If connection attempts keep arriving from them, that is why — it is not a network fault.`
              : ` They were NOT told (${notice.reason}), so their half stays open: they may go on retrying delivery and re-dialling this session until they give up. If connection attempts keep arriving from them, that is why.`) +
          (mayHaveSealed
            ? ` This session had reached a seal attempt (prior status: ${record.status}), so if the counterparty did notarize it, this side's half is now PERMANENTLY forfeited and cannot be recovered from here. Their copy, if it exists, is the only remaining one — ask them for their sealed_root and record it with the operator.`
            : ""),
      };
    }

    // M12-P14: do not ask for a seal we already know cannot be granted.
    //
    // Placed AFTER the force branch on purpose — force is the operator's deliberate escape hatch and
    // must never be gated — and before every seal path, because both the interrupted and the active
    // flows sign this side's frontier.
    //
    // A short chain produces `leaf_count_mismatch` at the counterparty, which is correct and
    // TERMINAL: nothing in the protocol backfills a missing leaf, so the session's only remaining
    // exit is a force-abandon with no notarized receipt. Refusing here costs the operator a retry;
    // not refusing costs them the receipt permanently.
    // Review HIGH-3: scoped to the two statuses that can actually seal. Unconditional, it also fired
    // for `seal_interrupted_pending` — displacing that status's accurate answer ("awaiting FROST
    // notarization") with `session_incomplete`, and offering force:true against a seal that is
    // mid-notarization. That is the same error substitution e3da3b4 exists to remove, reintroduced
    // one branch earlier in the same handler. (markInterruptedWithDetails does not evict the caches,
    // so the signals survive into that status and the branch was genuinely reachable.)
    const sealable = record.status === "active" || record.status === "interrupted";
    let readiness = sealable
      ? sessionNodeManager.sealReadiness(record.agent_name, sessionId)
      // DOD-M15-DIVERGE-1: `diverged: false` for the same reason every other field here is a
      // no-op value — this branch is the NOT-sealable statuses, where readiness is never consulted
      // and both gates below are skipped. It asserts nothing about the record; it keeps the shape.
      : { ready: true, treeSize: 0, highWaterSeq: -1, heldCount: 0, missingLeaves: 0, heldOwn: 0, heldReceived: 0, diverged: false };
    // Review HIGH-1: the guidance used to promise "the daemon pulls missing content automatically"
    // while nothing on this path pulled anything — autoRecoverForAgent fires on signaling reconnect,
    // seal-upgrade and agent start, none of which a close triggers. So the operator waited for an
    // event that would never happen, retried, got the same refusal, and reached for force:true — the
    // terminal receipt-less outcome this gate exists to prevent. Drain FIRST, then judge, which is
    // the sequence seal-upgrade.ts already documents: "Recover content -> consult the gate -> REFUSE".
    // Review LOW-10: skip the drain for a diverged record. `diverged` is now a term in `ready`, so
    // without this a diverged session pays a relay round trip that cannot change the answer — the
    // gap the drain fills is not the condition that refused it.
    if (sealable && !readiness.ready && !readiness.diverged && recoverParkedContent) {
      try {
        await recoverParkedContent(record.agent_name, "close_readiness_gate");
        readiness = sessionNodeManager.sealReadiness(record.agent_name, sessionId);
      } catch (err: unknown) {
        // A drain failure is not a reason to block the close: re-judging on the pre-drain readiness
        // is the same answer we would have given anyway, and it is still the honest one.
        logger.warn("session.seal.readiness.drain.failed", {
          agentName: record.agent_name, sessionId,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
    /**
     * DOD-M15-DIVERGE-1 — a PERMANENT parting gets its own answer, before the transient one.
     *
     * `#diverged` is set when an ack came back behind this side's frontier, which proves the tree
     * and the relay's counter can never agree on a root again. It was detected correctly, logged at
     * ERROR, and reached exactly one consumer: the text `cello status` prints. This gate — the one
     * place the fact changes an outcome — could not see it, so the operator learned only when the
     * counterparty answered `leaf_count_mismatch`, by which point the receipt was gone.
     *
     * BRANCHED, NOT FOLDED INTO `session_incomplete`, and that is the whole point of the ordering.
     * The refusal below tells the operator to "wait a moment and close again" and says the daemon
     * just pulled from the relay — true and useful for a session waiting on arrival, and false for
     * this one. Nothing backfills a position the relay already assigned to something else, so a
     * retry loop on that guidance ends where every one of them ends: `force: true`, terminal, no
     * receipt. Substituting a transient explanation for a permanent condition is the error class
     * this whole milestone exists to remove; doing it inside its own fix would be the worst place.
     *
     * The ERROR log at the detection site STAYS. This is the second half of it, not a relocation:
     * the log is the forensic record and this is the control. (M15-PROCEDURE §2b, Invariant 2.)
     */
    if (sealable && readiness.diverged) {
      logger.warn("session.seal.blocked_diverged", {
        agentName: record.agent_name, sessionId,
        treeSize: readiness.treeSize, highWaterSeq: readiness.highWaterSeq,
        // Review MEDIUM-5: the same four counters the sibling refusal carries. Without them a
        // session that is BOTH diverged and gapped reported its gap on no surface at all — this
        // branch preempts the incomplete one, and `sealReadinessView` short-circuits to `unknown`.
        heldCount: readiness.heldCount, missingLeaves: readiness.missingLeaves,
        heldOwn: readiness.heldOwn, heldReceived: readiness.heldReceived,
        impact: "this side's tree holds a leaf at a position the relay assigned to something else; the relay's ordering is what gets notarized, so a bilateral seal may be refused and this side cannot tell in advance",
      });
      return {
        ok: false,
        reason: "session_record_diverged",
        tree_size: readiness.treeSize,
        relay_high_water: readiness.highWaterSeq,
        held_messages: readiness.heldCount,
        missing_leaves: readiness.missingLeaves,
        held_own: readiness.heldOwn,
        held_received: readiness.heldReceived,
        // Review HIGH-1: SAY WHAT WAS MEASURED, NOT WHAT IS PREDICTED. The earlier wording asserted
        // the counterparty would refuse with `leaf_count_mismatch` and that force was the only exit.
        // Neither is established here. What is measured is that THIS tree parted from THE RELAY's
        // counter. The bilateral check compares LEAF COUNT, not the root (`seal-flows.ts`:
        // "Merkle-root agreement is NOT verified at this leaf-exchange layer"), and both sides
        // append a behind-frontier leaf at the tail — so if the counterparty skewed the same way
        // the counts still agree and the seal can succeed. Predicting their refusal was an
        // over-claim, and offering force-abandon as "the only exit" pointed at the one irreversible
        // action while the codebase's own mismatch handling leaves the session retryable.
        guidance:
          `This side's record no longer agrees with the relay's ordering — your tree holds ${readiness.treeSize} message(s) and the relay's counter is at ${readiness.highWaterSeq + 1}. ` +
          `The relay's ordering is what gets notarized, so sealing now may be refused. It may also succeed: the bilateral check compares message COUNTS, not contents, so if the counterparty's record skewed the same way the counts still match. This side cannot tell which from here. ` +
          `What is certain is that this will not resolve on its own — nothing backfills or re-numbers a leaf, so waiting does not change it. ` +
          `Compare message counts with the counterparty before deciding; cello_transcript ${sessionId} shows your full record and it stays readable whatever you choose. ` +
          `cello_close_session ${sessionId} { force: true } ends the session with NO notarized receipt and cannot be undone — the last resort, not the next step.`,
      };
    }
    if (sealable && !readiness.ready) {
      logger.warn("session.seal.blocked_incomplete", {
        agentName: record.agent_name, sessionId,
        treeSize: readiness.treeSize, highWaterSeq: readiness.highWaterSeq,
        heldCount: readiness.heldCount, missingLeaves: readiness.missingLeaves,
        heldOwn: readiness.heldOwn, heldReceived: readiness.heldReceived,
      });
      // DOD-M12B-INDEX-1: SAY WHOSE MESSAGES ARE WAITING. Our own held sends block the seal exactly
      // as received ones do, but calling them "received message(s) waiting behind a gap" tells the
      // operator to wait for content that is already in hand — and the relay pull this gate performs
      // first can never resolve it. They retry, get the identical refusal, and reach for force:true:
      // the receipt-less exit this gate exists to prevent.
      const waiting =
        (readiness.heldReceived > 0 ? `, and ${readiness.heldReceived} received message(s) are waiting behind a gap` : "") +
        (readiness.heldOwn > 0 ? `, and ${readiness.heldOwn} of YOUR OWN message(s) are waiting for their place in the record (they were delivered — the counterparty has them)` : "");
      return {
        ok: false,
        reason: "session_incomplete",
        missing_leaves: readiness.missingLeaves,
        held_messages: readiness.heldCount,
        held_own: readiness.heldOwn,
        held_received: readiness.heldReceived,
        guidance:
          `This side of the conversation is incomplete, so sealing now would produce a chain the counterparty cannot co-sign — and that refusal is terminal, leaving a force-abandon with no notarized receipt as the only way out. ` +
          `You hold ${readiness.treeSize} message(s); the relay has witnessed ${readiness.highWaterSeq + 1}` +
          waiting +
          `. Everything here is waiting on an earlier message from the counterparty that has not arrived; the daemon just pulled from the relay and the gap is still there, so wait a moment and close again. If it does not resolve, cello_transcript ${sessionId} shows what did arrive, and cello_close_session ${sessionId} { force: true } abandons it terminally (no receipt).`,
      };
    }

    /**
     * AC-011: a seal attempt is already running for this session.
     *
     * DOD-M15-CLOSEWAIT-1 review HIGH-3 rewrote this, because the change made it COMMON and the old
     * wording did not survive contact:
     *
     *   - it said *"wait for `session.interrupted.sealed` to appear in the daemon logs"*. That event
     *     is emitted NOWHERE in the tree — grep finds it only inside this string. An operator would
     *     tail a log for a line that cannot arrive.
     *   - it named the seal-INTERRUPTED subsystem, but the common case now is an ACTIVE session
     *     whose background ceremony is mid-flight. Wrong subsystem, on the path an operator most
     *     often reaches.
     *   - it was hard to reach before, because the first close held the caller for the whole
     *     ceremony. Now the operator has their terminal back for up to eleven minutes, and
     *     re-closing is the obvious move.
     */
    if (sealInterruptedInProgress.has(sealKey(record.agent_name, sessionId))) {
      return {
        ok: false,
        reason: "seal_in_progress",
        seal_status: "committed",
        guidance:
          "A seal ceremony is ALREADY RUNNING for this session — your commitment is recorded and " +
          "there is nothing to retry. This is the normal state after a close: the close answers as " +
          "soon as the commitment is durable and notarizes in the background, which waits for the " +
          "counterparty and can take several minutes. Fetch the result with cello_sealed_receipt " +
          `(session_id ${sessionId}); a seal_in_progress answer there means the same thing — still ` +
          "running, not failed. Do NOT re-close with { force: true } to hurry it: forcing ABANDONS " +
          "the session and permanently forfeits the receipt this ceremony is about to produce.",
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
      // CROSS-NODE: dial the broker for the duration of the seal, exactly as the active path does.
      // This branch sends the same seal frames and used to send them without the dial, so an
      // interrupted close between two agents on different nodes timed out on BOTH sides while each
      // counterparty was online — the frames were pushed to a stream the broker did not hold.
      let sealBrokerConn: { mgr: SignalingManager; stop: (reason: string) => Promise<void> } | null = null;

      // THE BILATERAL COMMITMENT IS NOT THE SEAL.
      //
      // Exactly one thing in the system causes a notarization: a SEAL ctrl leaf posted to the
      // RELAY, which hands the chain to a directory for the FROST round once both sides have
      // posted. The ACTIVE close does that below. This branch never did — it exchanged signed
      // leaves with the counterparty over the directory's signaling pass-through, stored both
      // halves, set the session to `seal_interrupted_pending` and returned. The directory only
      // FORWARDS those frames; it reads nothing out of them and starts nothing on the back of them.
      // So an interrupted session reached a mutually signed record that nobody was ever asked to
      // notarize, and sat there until the relay swept it.
      //
      // BEST-EFFORT, deliberately. The commitment has already SUCCEEDED and is durable on both
      // sides. The relay drops a session 24 hours after its last message, so this call will often
      // arrive to find it gone — and turning that into a reported FAILURE is precisely what sends an
      // operator to force:true, which permanently forfeits the half they still hold. A missing
      // notarization is a lesser harm than a destroyed commitment, so the close keeps its result and
      // the shortfall is logged rather than raised.
      //
      // No waiter is registered and nothing is awaited: the counterparty may not close for hours, and
      // blocking a close on that would be a worse lie than returning the honest pending status. When
      // their leaf does land, the already-wired session_sealed listener records the certificate.
      //
      // DOD-M12B-INTERRUPTED-ESCALATE-1: submitting the leaf was never enough, and this is where
      // the receipt actually gets earned. The relay notarizes only once BOTH parties have posted a
      // SEAL ctrl leaf, and the responder never posts one — `inbound-seal-request.ts` persists its
      // commitment, acks, and stops. So waiting for the relay round here is waiting for something
      // that cannot happen. The escalation asks the directory to notarize with the counterparty
      // ABSENT, which is precisely what a unilateral seal is for.
      const notarize = async (result: SealFlowResult): Promise<unknown> => {
        // WHEN IT IS ALLOWED TO ESCALATE, and this is a trust decision, not a retry policy:
        //   result.ok                                  — both sides signed the same root. Agreed.
        //   seal_interrupted_counterparty_unavailable  — they never answered. The exact case the
        //                                                unilateral seal exists for.
        // NEVER after `seal_interrupted_rejected_by_counterparty`. A rejection means the two trees
        // DISAGREE (leaf_count_mismatch, a diverging index). Notarizing our own root over their
        // stated objection is the one thing a trust layer must not do, however stuck the session is.
        const mayEscalate = result.ok || result.reason === "seal_interrupted_counterparty_unavailable";
        if (!mayEscalate) return result;

        // DOD-M12B-SEAL-BILATERAL-FIRST-1 — a BILATERAL seal is already running; do not take the
        // worse artifact instead. The counterparty answered that it is on the relay's bilateral
        // ceremony and was waiting for our half, which the flow just submitted. Escalating now asks
        // the directory to notarize with that counterparty marked ABSENT — for a peer that is
        // demonstrably present. The ACTIVE close gives a bilateral round eleven minutes before it
        // escalates; this path was giving it none, and for any orphan older than the delivery grace
        // (every one of the measured 26) the escalation is allowed, so the downgrade was certain.
        if (result.ok && result.ceremony === "relay_bilateral") {
          logger.info("session.seal.bilateral.in_flight", {
            agentName: record.agent_name, sessionId, correlationId,
            impact: "our half is submitted and the relay has both parties' leaves; the bilateral receipt is the better artifact and is already coming",
          });
          return {
            ...(result as Record<string, unknown>),
            seal_receipt: "bilateral_in_flight",
            guidance:
              "The counterparty is running the relay's bilateral seal and was waiting for this side's half, which has now been submitted. That produces a BILATERAL receipt — a better artifact than the unilateral one a close would otherwise take, and it does not record the counterparty as absent. Watch for the seal to land (cello_sessions) and read it with cello_sealed_receipt.",
          };
        }

        const uni = await submitAndEscalate(record, sessionId, correlationId);
        if ("escalated" in uni) {
          // THE REASON IS IN HAND — do not drop it. `result.ok` is true here (the bilateral
          // commitment succeeded), so returning it bare makes the restart-seal resolver log
          // `resolved` and dequeue a session that got NO notarization: the system reporting health
          // it does not have. Same shape the pending branch was blocked for.
          if (!result.ok) return result;
          return {
            ...(result as Record<string, unknown>),
            seal_receipt: "outstanding",
            seal_pending_reason: uni.reason,
            guidance:
              `The bilateral commitment is recorded, but this side could not post the SEAL leaf a notarization is requested with: ${uni.reason}. ` +
              `That is usually local and temporary — an agent that is not started yet (cello_start_agent), or a relay this daemon cannot currently reach (cello_status). ` +
              `Retry cello_close_session once the daemon reports healthy.`,
          };
        }
        if (uni.ok) return uni; // A REAL RECEIPT — the whole point of this line.

        // BEST-EFFORT, and the commitment STANDS. Turning a successful commitment into a reported
        // failure is exactly what sends an operator to `force: true`, which permanently forfeits the
        // half they still hold — the comment above says so and it is still true. What changes is
        // that the answer now says a receipt is OUTSTANDING rather than implying one exists, and
        // carries the directory's own countdown so a caller that can wait does not have to guess.
        logger.info("session.interrupted.seal.escalation.pending", {
          agentName: record.agent_name, sessionId, reason: uni.reason, correlationId,
          ...(uni.retry_after_seconds !== undefined ? { retryAfterSeconds: uni.retry_after_seconds } : {}),
        });
        return {
          ...(result as Record<string, unknown>),
          seal_receipt: "outstanding",
          seal_pending_reason: uni.reason,
          ...(uni.retry_after_seconds !== undefined ? { retry_after_seconds: uni.retry_after_seconds } : {}),
          guidance: uni.guidance,
        };
      };

      try {
        // Pre-dial ONLY from memory. This costs nothing when the map is empty, so the seal waiter
        // still registers immediately — a bilateral seal that lands promptly must not be missed
        // because we were off looking something up.
        sealBrokerConn = await openSealBrokerConnection(record.agent_name, sessionId, correlationId);
        const first = await handleSealInterruptedFlow(sessionId, record, correlationId, merkleRootAtInterruption);

        // DISCOVER-AND-RETRY, and only on the one reason that discovery can actually fix. After a
        // restart the broker map is empty, so the attempt above went out on the home stream and the
        // brokering node had no stream for the counterparty to push to. Asking where they are NOW
        // and dialling there is the repair — paid for only on the path that just failed, never on
        // the happy path, and never delaying the waiter.
        const counterparty = (record as { counterparty_pubkey?: string }).counterparty_pubkey;
        if (first.ok || first.reason !== "seal_interrupted_counterparty_unavailable" || !counterparty || sealBrokerConn) {
          return await notarize(first);
        }
        sealBrokerConn = await openSealBrokerConnection(
          record.agent_name, sessionId, correlationId, { counterpartyPubkeyHex: counterparty },
        );
        // Escalate even here: discovery found nowhere to dial, which is the STRONGEST case for a
        // unilateral seal, not a reason to give up on the receipt.
        if (!sealBrokerConn) return await notarize(first);
        logger.info("session.seal.broker.retry_after_discovery", { agentName: record.agent_name, sessionId, correlationId });
        // OVER THE VISITING CONNECTION. Dialling their node is only half of it — the request must
        // be SENT there too. Sent on the home stream it reaches our own node, which holds no stream
        // for a counterparty homed elsewhere, logs "target offline" and answers nothing.
        return await notarize(
          await handleSealInterruptedFlow(sessionId, record, correlationId, merkleRootAtInterruption, sealBrokerConn.mgr),
        );
      } finally {
        // Release the transient connection; the seal result stands either way.
        if (sealBrokerConn) {
          try { await sealBrokerConn.stop("seal-complete"); }
          catch (err: unknown) { logger.warn("session.seal.broker.release_failed", { sessionId, reason: err instanceof Error ? err.message : String(err) }); }
        }
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
      let sealBrokerConn: { mgr: SignalingManager; stop: (reason: string) => Promise<void> } | null = null;
      // DOD-M15-CLOSEWAIT-1: set when the seal tail is handed to a background task, so the enclosing
      // finally does not release a broker connection that ceremony still needs.
      let handedOff = false;
      /**
       * The caller may still ASK to block. Default is the new contract (answer on commitment);
       * `wait_for_seal: true` restores the inline behaviour for a script that genuinely wants the
       * receipt in one call and will wait up to eleven minutes for it. Opt-IN rather than opt-out,
       * because the default has to be the one that does not freeze an interactive operator.
       */
      const waitForSeal = params?.["wait_for_seal"] === true;
      try {
        // Memory only, deliberately. An ACTIVE session has not been through the restart that
        // empties the broker map, so the entry is there when it is needed — and a lookup here would
        // sit in front of the waiter registration two lines below, which is what must not happen.
        sealBrokerConn = await openSealBrokerConnection(record.agent_name, sessionId, correlationId);
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

          // THE SEAL MAY HAVE ALREADY SUCCEEDED, so returning the raw reason is an exit-point label
          // with the wrong diagnosis attached: the guidance below blames relay reachability when the
          // relay was fine and the seal is notarized and DURABLE. The operator who asked to close is
          // told it failed and gets no root — the receipt being the whole point of closing.
          //
          // HOW the window opens (corrected — my first version named a mechanism that does not
          // exist): it is NOT that teardown precedes the status flip. In `destroySessionNode` the
          // flip happens BEFORE `#activeNodes.delete`, so that ordering is safe. The real producers
          // are (a) `record` is a snapshot taken at the top of this handler, before a broker dial that
          // can take up to 10s, so it can be stale by now; and (b) `retireSessionNode` stops the node
          // WITHOUT changing the DB status, and `destroySessionNode` then early-returns above the
          // flip. Both parties closing at once is the ordinary case, so whichever call arrives second
          // meets it.
          //
          // SCOPED to that reason. This previously fired on EVERY `!submit.ok`, while justifying
          // itself for one — and a future failure (a tree mismatch, a signing failure) would have been
          // absorbed into `ok:true` with an old root and never surfaced.
          //
          // Why this is not the fetched-receipt path wearing a different hat — the distinction is
          // narrower than I first wrote, so stated exactly: the stored cert passed the
          // field-completeness gate, passed the independent frontier re-derivation (the client never
          // takes the directory's word for that value), and where this agent holds the signer key it
          // was cryptographically verified. None of those were true of a fetched root. It is also not
          // a new claim — `cello_get_sealed_receipt` already returns this exact cert with no status
          // gate. Honest caveat: for a NON-initiator the stored cert is recorded `verified:false`,
          // so it is ultimately directory-attested over an authenticated channel — the same trust the
          // ordinary bilateral close already returns, not a new one introduced here.
          // M12-P15 (review HIGH-3): this used to key on `session_node_unavailable` ALONE. That was
          // the only reason submitSealLeaf could give when the node was gone — until M12-P15 taught
          // it to fall back to a detached transport, after which it can no longer produce that
          // string at all and this recovery went DEAD. The ordinary double-close then dialled the
          // relay, submitted a second ctrl leaf to a session the relay had already destroyed on
          // seal, and told the operator the close failed — the M12 defect back under a new label.
          // The question this branch actually asks is "we could not submit; is the seal already
          // durable?", so it keys on every reason that means exactly that. A stored certificate is
          // the answer either way, and consulting it is cheap.
          const SEAL_MAY_ALREADY_BE_DURABLE = new Set([
            "session_node_unavailable",
            "no_persisted_relay_endpoint",
            "standing_receiver_unavailable",
            "relay_client_unavailable",
            "relay_unavailable",
            "relay_session_gone",
            "session_not_found",
          ]);
          const localCert =
            SEAL_MAY_ALREADY_BE_DURABLE.has(submit.reason)
              ? sessionNodeManager.getSealCertificate(record.agent_name, sessionId)
              : null;
          if (localCert?.sealed_root) {
            logger.info("session.seal.completed", {
              sessionId, sealedRoot: localCert.sealed_root, role: "already_sealed_locally", correlationId,
            });
            crossNodeBrokerBySession.delete(`${record.agent_name}:${sessionId}`);
            return { ok: true, sealed_root: localCert.sealed_root, legibility: localCert.legibility };
          }

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
        // DOD-SEAL-BILATERAL-TIMEOUT-1: default is 660 s (11 min) — deliberately just over
        // the directory's deliveryGraceSeconds default (600 s / 10 min), so the bilateral
        // timeout always expires AFTER the grace window. This makes seal_unilateral_too_early
        // structurally unreachable under normal configuration; override via the env var for
        // tests or operators who need a shorter window.
        const bilateralTimeoutMs = Number(process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"]) || 660_000;
        // DOD-M12B-CLOSE-SILENT-WAIT-1: SAY SO BEFORE THE SILENCE, not after it.
        //
        // This call is about to block for up to eleven minutes and return nothing. Measured
        // 2026-08-17: seal leaf submitted 16:48:55, ceremony completed 17:00:01 — and the operator
        // saw a frozen command for all of it. They concluded it was broken and force-abandoned
        // seventeen sessions, which forfeits the exact receipt this wait is earning. The log is what
        // a second window can read while the first is blocked, so it has to carry both facts: how
        // long this can legitimately take, and what forcing costs.
        logger.warn("session.seal.awaiting_counterparty", {
          sessionId, agentName: record.agent_name, deadlineMs: bilateralTimeoutMs, correlationId,
          impact: `the seal is waiting for the counterparty for up to ${Math.round(bilateralTimeoutMs / 60_000)} minutes, then escalates to a unilateral seal and produces a real receipt. It is working. Do NOT force-abandon it — that forfeits the receipt this wait is earning.`,
        });

        /**
         * DOD-M15-CLOSEWAIT-1 — THE TAIL, EXTRACTED SO IT CAN OUTLIVE THE RESPONSE.
         *
         * Everything from here to the escalation is "wait for the counterparty, then escalate if
         * they never came". It ran inline, which is why the caller sat on a frozen command for up to
         * eleven minutes while it worked correctly — and why one operator force-abandoned seventeen
         * sessions, forfeiting the exact receipts the wait was earning.
         *
         * Extracting it changes nothing about WHAT is signed or in what order: same race, same
         * escalation, same leaf. It changes only who waits for it. (Decisions Carried #4.)
         *
         * `rec`/`sid` are captured because TypeScript discards the narrowing of `record` and
         * `sessionId` inside a nested function.
         */
        const rec = record;
        const sid = sessionId;
        const awaitSealAndEscalate = async (): Promise<unknown> => {
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
        // seal. The body now lives in escalateToUnilateralSeal so the INTERRUPTED branch can reach
        // it too — it never could, and that is why an interrupted session could not get a receipt.
        return await escalateToUnilateralSeal(rec, sid, escalation, correlationId);
        };

        /**
         * OWNERSHIP OF THE BROKER CONNECTION MOVES WITH THE TAIL.
         *
         * This is the one genuinely dangerous part of the change. The enclosing `finally` releases
         * `sealBrokerConn`; if it ran while the tail was still going, the background seal would lose
         * the connection it is waiting on. So the tail releases it itself, and the enclosing
         * `finally` stands down via `handedOff`.
         *
         * PRECISELY WHAT IS LOST, corrected after review: not a corrupted seal. The escalation goes
         * over the HOME stream, so it still completes. What this connection carries is the
         * `seal_verified` / `session_sealed` push for a CROSS-NODE bilateral seal — so releasing it
         * early silently downgrades every cross-node close from a bilateral receipt to a unilateral
         * one, eleven minutes later. Quieter than corruption, and still worth the guard.
         */
        const finishSeal = async (): Promise<unknown> => {
          try {
            return await awaitSealAndEscalate();
          } finally {
            if (sealBrokerConn) {
              try { await sealBrokerConn.stop("seal-complete"); }
              catch (err: unknown) { logger.warn("session.seal.broker.release_failed", { sessionId: sid, reason: err instanceof Error ? err.message : String(err) }); }
              sealBrokerConn = null;
            }
            sealInterruptedInProgress.delete(sealKey(rec.agent_name, sid));
          }
        };

        /**
         * A NEW CEREMONY IS STARTING, so any previous failure verdict is now false.
         *
         * ABOVE the `waitForSeal` branch — review MEDIUM-4. It used to sit below, so the clear ran
         * only on the handed-off path: a blocking re-close (which the MCP tool exposes and the
         * document-delivery seal uses) left the old marker in place, and a stale `seal_failed` from
         * half an hour earlier was then reported as the current state. That is `STALEROSTER-1`'s
         * defect, in the store whose own docstring says it avoids it.
         */
        sealFailures.clear(rec.agent_name, sid);

        if (waitForSeal) return await finishSeal();

        handedOff = true;
        /**
         * Detached deliberately, and never awaited. A rejection must not become an unhandled
         * rejection — and must not be silent either: the operator has already been told the seal is
         * running, so a failure they never hear about is the worst of both worlds.
         */
        const tail = finishSeal();
        /**
         * TRACKED FOR SHUTDOWN — review MEDIUM-6.
         *
         * `stop()` cancels or awaits every other background worker: the reconcile scheduler, the
         * telegram poller, the manifest poll, the roster sweep. `RestartSealResolver.stop()` goes
         * further and AWAITS its in-flight seal, with a comment saying exactly why — *"severing
         * signaling under a half-finished seal-interrupted exchange leaves the counterparty holding
         * a commitment we never acknowledged… permanently divergent."*
         *
         * A detached, untracked ceremony was the one background task that could be cut at an
         * arbitrary point by `cello logout`. Recoverable on the next boot, but recoverable is not
         * the same as not breaking it.
         */
        registerBackgroundSeal?.(tail);
        void tail.then(
          (result) => {
            const r = result as { ok?: boolean; reason?: string };
            if (r?.ok) {
              sealFailures.clear(rec.agent_name, sid);
              logger.info("session.seal.background.completed", { sessionId: sid, agentName: rec.agent_name, correlationId });
            }
            else {
              /**
               * THE BRANCH PRODUCTION ACTUALLY TAKES — review HIGH-1.
               *
               * `escalateToUnilateralSeal` contains zero `throw`s: all nine of its failure paths
               * RESOLVE with `{ ok: false, reason }`. So recording only in the `.catch` below meant
               * every ordinary dead ceremony went unrecorded and `cello_sealed_receipt` kept
               * answering `not_sealed_yet` — the very answer this unit exists to replace. The log
               * line three lines down said so out loud the whole time.
               */
              sealFailures.record(rec.agent_name, sid, r?.reason ?? "seal_unresolved", new Date().toISOString(), "unresolved");
              logger.warn("session.seal.background.unresolved", {
              sessionId: sid, agentName: rec.agent_name, correlationId, reason: r?.reason,
              impact: "the close already answered; this session holds a durable commitment but has no receipt yet.",
              guidance: "cello_sealed_receipt now reports seal_failed with this reason; a daemon restart also retries it.",
              });
            }
          },
          (err: unknown) => {
            // RECORDED FOR THE RESPONSE, not only the log. The caller already holds `ok: true`, so a
            // failure that lives only in daemon.log is one the agent has no way to discover.
            sealFailures.record(rec.agent_name, sid, err instanceof Error ? err.message : String(err), new Date().toISOString(), "threw");
            logger.error("session.seal.background.failed", {
            sessionId: sid, agentName: rec.agent_name, correlationId,
            error: err instanceof Error ? err.message : String(err),
            impact: "the close already answered ok; the notarization did NOT complete and no receipt exists.",
            guidance: "The commitment is durable — a daemon restart resolves it via the restart seal resolver.",
            });
          },
        );
        return describeSealCommitted({ sessionId: sid, deadlineMs: bilateralTimeoutMs });
      } finally {
        // Fix #1: release the transient broker seal-connection (best-effort; the seal result stands).
        //
        // DOD-M15-CLOSEWAIT-1: skipped when the tail was handed to a background task, which owns
        // this cleanup itself. Releasing here would pull the transport out from under a ceremony
        // still in flight — the one way this change could corrupt a seal rather than merely report
        // it differently.
        if (!handedOff) {
          if (sealBrokerConn) {
            try { await sealBrokerConn.stop("seal-complete"); }
            catch (err: unknown) { logger.warn("session.seal.broker.release_failed", { sessionId, reason: err instanceof Error ? err.message : String(err) }); }
          }
          sealInterruptedInProgress.delete(sealKey(record.agent_name, sessionId));
        }
      }
    }

    // DOD-M12B-PENDING-EXIT-1 — `seal_interrupted_pending` had NO exit, and the refusal below told
    // the operator it was "awaiting FROST notarization". It was not awaiting anything: nobody ever
    // requests that notarization. The relay stamps a chain only once BOTH parties have posted a
    // SEAL ctrl leaf, and the responder never posts one — `inbound-seal-request.ts` persists its
    // commitment, acks, and stops. Measured: 26 sessions idle in this status for 0.5 to 10.5 days.
    //
    // WHY THIS IS SAFE, stated accurately — the obvious answer is the wrong one. It is NOT that
    // "both sides signed the same root": the escalation reports the tree root WITH the SEAL ctrl
    // leaf appended, which is by construction not the committed root, and a responder-side row
    // never even receives the initiator's leaf. It is safe because **the directory rebuilds the
    // tree from relay-witnessed leaves and verifies their signatures** — it never consults the
    // commitment. The commitment is what makes it legitimate to ASK, not what makes it verifiable.
    // And re-entering cannot post a second ctrl leaf, because `submitSealLeaf` recovers the one a
    // previous run posted from the durable carry rather than posting again.
    if (record.status === "seal_interrupted_pending") {
      // The AC-011 check at the top of the handler already refuses a concurrent attempt on this
      // same key, for every status — so no second check is needed here, only the add/release pair
      // that makes THIS attempt visible to it.
      const key = sealKey(record.agent_name, sessionId);
      sealInterruptedInProgress.add(key);
      const correlationId = randomUUID();
      try {
        const uni = await submitAndEscalate(record, sessionId, correlationId);
        if ("escalated" in uni) {
          // NAME THE CAUSE `submitSealLeaf` GAVE, never a label invented here. Most of these are
          // transient and local — `standing_receiver_unavailable` is simply "the agent is not
          // started yet", which a freshly booted daemon reports for every session. The genuinely
          // permanent case (the relay released the session) has its own reason,
          // `seal_carry_empty`, raised inside the escalation where it is actually known.
          return {
            ok: false,
            reason: uni.reason,
            guidance:
              `This session holds a bilateral commitment, but no notarization could be requested for it: ${uni.reason}. ` +
              `That is usually local and temporary — an agent that is not started yet (cello_start_agent), or a relay this daemon cannot currently reach (cello_status). ` +
              `The conversation is intact either way; retry cello_close_session once the daemon reports healthy.`,
          };
        }
        if (uni.ok) return uni;
        return {
          ok: false,
          reason: uni.reason,
          ...(uni.retry_after_seconds !== undefined ? { retry_after_seconds: uni.retry_after_seconds } : {}),
          guidance: uni.guidance,
        };
      } finally {
        sealInterruptedInProgress.delete(key);
      }
    }

    // Any other status — nothing to do.
    return {
      ok: false,
      reason: "session_not_closeable",
      guidance: `Session is in status '${record.status}', which cannot be closed via cello_close_session. Check cello_sessions.`,
    };
  };
}
