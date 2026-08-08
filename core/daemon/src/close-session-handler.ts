/**
 * cello_close_session — the bilateral close, and every way it can fail.
 *
 * M7 error discipline: each distinct failure cause produces a DISTINCT error code
 * (session_already_sealed, seal_interrupted_in_progress, seal_interrupted_counterparty_unavailable,
 * seal_interrupted_rejected_by_counterparty, signaling_reconnecting). A close that fails must tell
 * the operator WHY, not merely that it failed — this handler exists as much for its error paths as
 * for its happy path.
 *
 * SI-001: there is NO auto-seal on a session_interrupted receipt. The operator must close
 * explicitly. A daemon that sealed on its own would notarize a conversation nobody chose to end.
 *
 * This was on my DO-NOT-CUT list. It has fifteen dependencies — a long list, but a KNOWN one, and
 * that is the entire difference from a closure over 73 shared locals.
 */
import { randomUUID } from "node:crypto";
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
  // ── the seal cluster (seal-coordinator.ts) ──
  sealKey: (agentName: string, sessionId: string) => string;
  sealInterruptedInProgress: Set<string>;
  pendingSealWaiters: Map<string, (completion: SealCompletion) => void>;
  pendingUnilateralWaiters: Map<string, (r: UnilateralResult) => void>;
  /** The verified consortium roster, re-resolved at ceremony time. */
  resolveConsortiumRoster: () => Promise<ConsortiumEndpoint[] | null>;
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
    pendingSealWaiters, pendingUnilateralWaiters, handleSealInterruptedFlow, handleActiveSealFlow,
    recoverParkedContent,
  } = deps;

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
  // AC-011: seal_interrupted_in_progress
  // AC-012: seal_interrupted_counterparty_unavailable
  // AC-013: seal_interrupted_rejected_by_counterparty
  // DB-001: signaling_reconnecting
  // SI-001: no auto-seal on session_interrupted receipt; operator must call explicitly
  handlers.set("cello_close_session", async (params, connectionId) => {
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
      await sessionNodeManager.abandonSession(record.agent_name, sessionId);
      logger.info("session.force_abandoned", {
        agentName: record.agent_name,
        sessionId,
        priorStatus: record.status,
        // Makes the destructive case findable in a log instead of reconstructable by hand, which is
        // how the 2026-08-06 incident had to be traced.
        mayHaveForfeitedSeal: mayHaveSealed,
      });
      return {
        ok: true,
        status: "abandoned",
        reason: "force_abandoned",
        guidance: `Session ${sessionId} was force-abandoned — marked terminal locally with no bilateral seal. Use force only for a half-open session that cannot be sealed; a normal close (no force) still attempts the seal so both parties get a notarized receipt.` +
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
      : { ready: true, treeSize: 0, highWaterSeq: -1, heldCount: 0, missingLeaves: 0 };
    // Review HIGH-1: the guidance used to promise "the daemon pulls missing content automatically"
    // while nothing on this path pulled anything — autoRecoverForAgent fires on signaling reconnect,
    // seal-upgrade and agent start, none of which a close triggers. So the operator waited for an
    // event that would never happen, retried, got the same refusal, and reached for force:true — the
    // terminal receipt-less outcome this gate exists to prevent. Drain FIRST, then judge, which is
    // the sequence seal-upgrade.ts already documents: "Recover content -> consult the gate -> REFUSE".
    if (sealable && !readiness.ready && recoverParkedContent) {
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
    if (sealable && !readiness.ready) {
      logger.warn("session.seal.blocked_incomplete", {
        agentName: record.agent_name, sessionId,
        treeSize: readiness.treeSize, highWaterSeq: readiness.highWaterSeq,
        heldCount: readiness.heldCount, missingLeaves: readiness.missingLeaves,
      });
      return {
        ok: false,
        reason: "session_incomplete",
        missing_leaves: readiness.missingLeaves,
        held_messages: readiness.heldCount,
        guidance:
          `This side of the conversation is incomplete, so sealing now would produce a chain the counterparty cannot co-sign — and that refusal is terminal, leaving a force-abandon with no notarized receipt as the only way out. ` +
          `You hold ${readiness.treeSize} message(s); the relay has witnessed ${readiness.highWaterSeq + 1}` +
          (readiness.heldCount > 0 ? `, and ${readiness.heldCount} received message(s) are waiting behind a gap` : "") +
          `. The daemon just pulled from the relay and the gap is still there, so the content is not available yet — wait a moment and close again. If it does not resolve, cello_transcript ${sessionId} shows what did arrive, and cello_close_session ${sessionId} { force: true } abandons it terminally (no receipt).`,
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
      const notarize = async (result: SealFlowResult): Promise<SealFlowResult> => {
        if (!result.ok) return result;
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
        return result;
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
        if (!sealBrokerConn) return first;
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
        const sealAgentKp = getKeyProvider(record.agent_name);
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
}
