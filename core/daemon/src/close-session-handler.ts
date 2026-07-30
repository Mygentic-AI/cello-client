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
  getConnState: (connectionId: string) => ConnState | undefined;
  resolveCurrentAgent: (connState: ConnState | undefined, explicitAgent?: string) => string | null;
  NO_CURRENT_AGENT_RESPONSE: unknown;
  getKeyProvider: (agentName: string) => KeyProvider | undefined;
  signalingFor: (agentName: string) => SignalingManager | undefined;
  sendOver: (agentName: string, frame: Record<string, unknown>) => Promise<{ ok: boolean; reason?: string }>;
  waitForSignalingConnected: (mgr: SignalingManager, timeoutMs: number) => Promise<boolean>;
  openVisitingConnection: (agentName: string, agentKeyProvider: KeyProvider, agentPubkeyHex: string, endpoint: DirectoryEndpoint, correlationId: string, nodeId: string) => { mgr: SignalingManager; stop: (reason: string) => Promise<void> };
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
  handleSealInterruptedFlow: (sessionId: string, record: SessionRecord, correlationId: string, merkleRootAtInterruption: string) => Promise<SealFlowResult>;
  handleActiveSealFlow: (sessionId: string, record: SessionRecord, correlationId: string) => Promise<ActiveSealResult>;
}


export function registerCloseSessionHandler(deps: CloseSessionDeps): void {
  const {
    resolveConsortiumRoster,
    handlers, logger, sessionNodeManager, getConnState, resolveCurrentAgent,
    NO_CURRENT_AGENT_RESPONSE, getKeyProvider, signalingFor, sendOver, waitForSignalingConnected,
    openVisitingConnection, crossNodeBrokerBySession, sealKey, sealInterruptedInProgress,
    pendingSealWaiters, pendingUnilateralWaiters, handleSealInterruptedFlow, handleActiveSealFlow,
  } = deps;

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
      await sessionNodeManager.abandonSession(record.agent_name, sessionId);
      logger.info("session.force_abandoned", { agentName: record.agent_name, sessionId, priorStatus: record.status });
      return {
        ok: true,
        status: "abandoned",
        reason: "force_abandoned",
        guidance: `Session ${sessionId} was force-abandoned — marked terminal locally with no bilateral seal. Use force only for a half-open session that cannot be sealed; a normal close (no force) still attempts the seal so both parties get a notarized receipt.`,
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
      // Fix #1 (cross-node seal-liveness): if this session was brokered by another node, the seal_verified
      // + session_sealed frames are pushed by that BROKER — but the initiator released its visiting
      // connection after setup, so on the home stream they never arrive and close times out. Re-open a
      // transient visiting connection to the broker (seal-capable — openVisitingConnection now wires the
      // seal handlers) for the duration of the seal, then release it in finally. Same-node sessions have
      // no entry here and use the home stream unchanged.
      let sealBrokerConn: { stop: (reason: string) => Promise<void> } | null = null;
      try {
        const brokerNodeForSeal = crossNodeBrokerBySession.get(`${record.agent_name}:${sessionId}`);
        if (brokerNodeForSeal) {
          const sealKp = getKeyProvider(record.agent_name);
          if (!sealKp) {
            // Fallback-finder #1: never skip the cross-node reconnect silently — without a key provider
            // we cannot open the broker connection, so the seal will revert to the pre-fix timeout. Log
            // WHY so it is not indistinguishable from a normal counterparty-didn't-close timeout.
            logger.warn("session.seal.broker.no_keyprovider", { agentName: record.agent_name, brokerNode: brokerNodeForSeal, correlationId });
          } else {
            const sealPubHex = Buffer.from(await sealKp.getPublicKey()).toString("hex");
            const roster = await resolveConsortiumRoster();
            const brokerTarget = roster?.find((e) => e.nodeId === brokerNodeForSeal) ?? null;
            if (!brokerTarget) {
              logger.warn("session.seal.broker.unresolved", { agentName: record.agent_name, brokerNode: brokerNodeForSeal, correlationId });
            } else {
              const conn = openVisitingConnection(record.agent_name, sealKp, sealPubHex, { peerId: brokerTarget.peerId, multiaddr: brokerTarget.multiaddr }, correlationId, brokerNodeForSeal);
              if (await waitForSignalingConnected(conn.mgr, 10_000)) {
                sealBrokerConn = conn;
                logger.info("session.seal.broker.reconnected", { agentName: record.agent_name, brokerNode: brokerNodeForSeal, correlationId });
              } else {
                await conn.stop("seal-broker-unreachable");
                logger.warn("session.seal.broker.unreachable", { agentName: record.agent_name, brokerNode: brokerNodeForSeal, correlationId });
              }
            }
          }
        }
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
