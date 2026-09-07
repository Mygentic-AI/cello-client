/**
 * The views the daemon builds of its own sessions and agents.
 *
 * Which sessions are interrupted and can still be resumed, which are live, whether a given session
 * could be sealed right now, and what state each agent is in. Plus the half-open reaper, which is
 * here rather than with the sweeps because "which sessions are live" and "which sessions are dead
 * but still listed" are the same question asked twice — separating them is how a list starts
 * reporting sessions that no longer exist.
 *
 * ⚠️ THE CONTEXT IS DESIGNED, NOT LIFTED. An attempt to move the whole status cluster — these
 * builders plus `getStatus` — found TWENTY free names, because `getStatus` reads from every part of
 * the daemon by construction. That is the composition root with an extra hop. The builders alone
 * need what is listed below and nothing else; `getStatus` stays in the root, where its breadth is
 * honest, and calls in.
 */
import type {
  ActiveSessionInfo, AgentInfo, AgentState, InterruptedSessionInfo, Logger, SealReadinessView,
} from "./types.js";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { SignalingManager } from "@cello-protocol/transport";
import type { SealCompletion } from "./seal-coordinator.js";
import type { FrontierMismatchStore } from "./frontier-mismatch.js";
import { countAttendance } from "./co-attendance.js";
import { renderFrontierMismatch } from "./frontier-mismatch.js";
import { resolveAgentState } from "./agent-state.js";

export interface SessionViewsDeps {
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  /** Live containers, shared by reference: a copy freezes attendance and every agent reads unattended. */
  perConnectionState: ReadonlyMap<string, { currentAgent: string | null }>;
  onlineAgents: ReadonlySet<string>;
  explicitlyOfflineAgents: ReadonlySet<string>;
  perAgentSignaling: ReadonlyMap<string, { signaling: SignalingManager }>;
  /** Present only on the in-process test path. */
  sharedSignaling: SignalingManager | undefined;
  frontierMismatches: FrontierMismatchStore;
  sealKey: (agentName: string, sessionId: string) => string;
  sealInterruptedInProgress: ReadonlySet<string>;
  pendingSealWaiters: ReadonlyMap<string, (completion: SealCompletion) => void>;
}

export function createSessionViews(deps: SessionViewsDeps) {
  const {
    logger, sessionNodeManager, perConnectionState, onlineAgents, explicitlyOfflineAgents,
    perAgentSignaling, sharedSignaling, frontierMismatches, sealKey, sealInterruptedInProgress,
    pendingSealWaiters,
  } = deps;

  // M7-SESSION-001 AC-006/AC-007 (and M-1 PULL): build the interrupted_sessions
  // array from SQLite. Shared by both getStatus() (daemon-wide) and the
  // cello_status MCP handler (per-connection) so live MCP clients see the same
  // interrupted sessions a CLI `cello status` would.
  // `cello status` is a health snapshot, not a session archive. It surfaces ONLY genuinely
  // RESUMABLE sessions (interrupted with messages exchanged) — never failed inits (interrupted,
  // 0 messages — a dead handshake), which classify as "failed" and would otherwise accumulate
  // unbounded and confuse. The list is also capped; the full, queryable history is `cello sessions`
  // / cello_list_sessions (with filter + limit flags).
  const STATUS_RESUMABLE_CAP = 10;
  /**
   * DOD-M12B-SEAL-STUCK-1 — ask the seal gate for ONE session, and never let the answer take the
   * status response with it.
   *
   * This runs per session on every `cello status` and every `cello_status`, and it touches the
   * database. An unguarded throw here rejects the whole response, after which the CLI finds the
   * singleton lock still held and prints `daemon: "broken_shutdown"` — telling the operator their
   * healthy daemon has failed to stop, over one session row it could not read. There is a
   * documented precedent in this codebase for exactly that shape.
   *
   * A failure yields `unknown`, never `ready`: "we could not check" must not read as "safe to
   * close", because a close on a short chain is terminal.
   */
  function probeSealReadiness(agentName: string, sessionId: string): SealReadinessView {
    try {
      return sessionNodeManager.sealReadinessView(agentName, sessionId);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      logger.warn("session.seal.readiness.probe.failed", { agentName, sessionId, error: message });
      return { state: "unknown", reason: `probe_failed: ${message}` };
    }
  }

  function buildInterruptedSessions(): InterruptedSessionInfo[] {
    return sessionNodeManager
      .getSessionsByStatus("interrupted")
      .filter((row) => (row.message_count ?? 0) > 0) // resumable only — drop failed 0-message inits
      .slice(0, STATUS_RESUMABLE_CAP)
      .map((row) => ({
        sessionId: row.session_id,
        agentName: row.agent_name,
        counterpartyPubkey: row.counterparty_pubkey,
        messageCount: row.message_count ?? 0,
        interruptedAt: row.interrupted_at ?? new Date(row.updated_at).toISOString(),
        // DOD-SESSION-NAME-1 (AC-A11): an interrupted session is one you may want to resume or seal
        // — the name is how you tell which one it was.
        sessionName: row.session_name ?? null,
        // DOD-M12B-SEAL-STUCK-1: the same answer the active list carries, for the same reason —
        // an interrupted session can seal, so it can also be blocked from sealing by a gap, and
        // that is knowable here instead of only after a failed close. A plain property, never a
        // spread: a spread bypasses excess-property checking, which is how `frontierMismatch`
        // below came to typecheck while no renderer could read it.
        sealReadiness: probeSealReadiness(row.agent_name, row.session_id),
        // DOD-FRONTIER-STRAND-1 AC3: if a seal exchange has already proved the two sides disagree on
        // how many messages this session holds, SAY SO HERE. Otherwise a stranded session is listed
        // exactly like a healthy paused one, and the only way to learn it can never seal is to
        // attempt another close and read the error — which is how dbb93dfc… sat unnoticed a week.
        ...(() => {
          const m = frontierMismatches.get(row.agent_name, row.session_id);
          return m ? { frontierMismatch: renderFrontierMismatch(m, row.session_id) } : {};
        })(),
      }));
  }

  // CC-5/F21: reap dead half-open sessions on READ (compute-on-read, like reapExpiredInboundSessions —
  // no background timer). A session the standing receiver opened from an inbound offer the initiator
  // ABANDONED stays "active" forever (the counterparty never joins), clutters the open/active lists, and
  // its normal close fires an unsealable bilateral seal. Mark such a session terminal ("abandoned") once
  // it is PROVABLY dead: counterparty never established (liveness != "alive" AND 0 RECEIVED messages —
  // message_count alone counts our own auto-"Dispatched." ack, so it is NOT the signal) + age past the
  // grace TTL (a genuinely fresh session still setting up must survive).
  // CC-10 (live 2026-07-08 Phase-2 block): scan 'interrupted' too, not just 'active'. A daemon restart
  // flips dead half-opens to 'interrupted'; those classify as "failed" (invisible in every list) yet
  // still count toward the unknown-sender acceptance bound (D18 deliberately counts 'interrupted') — so
  // a stranger whose first handshakes died was silently locked out FOREVER. Reaping only 0-RECEIVED
  // ghosts keeps D18 intact: the disconnect-evasion attacker's sessions always carry received content.
  const HALF_OPEN_TTL_MS = Number(process.env["CELLO_HALF_OPEN_TTL_MS"]) || 5 * 60 * 1000;
  function reapDeadHalfOpenSessions(agentName?: string): void {
    const now = Date.now();
    const candidates = [...sessionNodeManager.getSessionsByStatus("active"), ...sessionNodeManager.getSessionsByStatus("interrupted")];
    for (const row of candidates) {
      if (agentName !== undefined && row.agent_name !== agentName) continue;
      if (now - row.created_at <= HALF_OPEN_TTL_MS) continue; // too young — may just be setting up
      // DOD-M12B-ACK-1: 'impaired' counts as live HERE. This reaper's question is "did the
      // counterparty ever establish?", and impaired means it did — the connection is up, only
      // delivery on it is failing. Reaping on impaired would abandon exactly the sessions this
      // milestone exists to repair.
      const liveness = sessionNodeManager.getSessionLiveness(row.agent_name, row.session_id);
      if (liveness === "alive" || liveness === "impaired") continue; // live
      /**
       * DOD-M12B-REAP-HELD-1 — count HELD frames too, or an interrupted conversation reads as a
       * dead handshake.
       *
       * OBSERVED LIVE 2026-08-18: this line abandoned session `d28db475…` — twenty leaves in the
       * chain plus sixteen verified frames still held, ten of them from the counterparty — while the
       * restart-seal resolver was actively trying to notarize it. The receipt was forfeited and the
       * held content annexed.
       *
       * `countReceivedMessages` asks the TRANSCRIPT, and held content never reaches the transcript;
       * it waits in `held_content` until it can join the chain. So the very condition that holds
       * content — an interrupted session — is the condition that hides the counterparty's messages
       * from this test, and a real conversation becomes indistinguishable from an offer nobody
       * answered. `countEstablishedReceived` asks both places.
       */
      if (sessionNodeManager.countEstablishedReceived(row.agent_name, row.session_id) > 0) continue; // counterparty spoke
      // Non-awaited: abandonSession flips the DB status synchronously (before its first await), so THIS
      // read reflects it; the async node teardown finishes in the background. CC-10 reviewer LOW: only
      // log "reaped" if the status flip actually wrote — a swallowed write failure already logs
      // session.status.write.failed, and reporting success over it would hide a still-counting ghost.
      void sessionNodeManager.abandonSession(row.agent_name, row.session_id)
        .then((flipped) => {
          if (flipped) {
            logger.info("session.half_open.reaped", { agentName: row.agent_name, sessionId: row.session_id, priorStatus: row.status, ageMs: now - row.created_at });
          }
        })
        .catch((err: unknown) => {
          logger.warn("session.half_open.reap.failed", { agentName: row.agent_name, sessionId: row.session_id, reason: err instanceof Error ? err.message : String(err) });
        });
    }
  }

  // M8B F16: per-session liveness for ACTIVE sessions, shared by both status surfaces
  // ("status" for the CLI, "cello_status" for MCP). The signal (session.liveness.changed,
  // tracked in the node manager) existed but nothing consumed it — a dead counterparty
  // was invisible to the operator.
  function buildActiveSessions(): ActiveSessionInfo[] {
    reapDeadHalfOpenSessions(); // CC-5/F21: drop provably-dead half-open sessions before surfacing active ones
    return sessionNodeManager.getSessionsByStatus("active").map((row) => {
      // DOD-M12B-SEAL-STUCK-1: ask the SAME gate the close path asks, so the surface and the
      // refusal can never disagree. Computed here rather than cached because the answer changes
      // the moment a gap fills, and a stale "stuck" is its own lie.
      return {
        sessionId: row.session_id,
        agentName: row.agent_name,
        counterpartyPubkey: row.counterparty_pubkey,
        liveness: sessionNodeManager.getSessionLiveness(row.agent_name, row.session_id),
        sessionName: row.session_name ?? null, // DOD-SESSION-NAME-1 (AC-A11)
        sealReadiness: probeSealReadiness(row.agent_name, row.session_id),
        // DOD-M12B-CLOSE-SILENT-WAIT-1: both flows, because either can be the one blocking the
        // operator's command — `pendingSealWaiters` is the active close, `sealInterruptedInProgress`
        // the interrupted one.
        sealing:
          pendingSealWaiters.has(sealKey(row.agent_name, row.session_id)) ||
          sealInterruptedInProgress.has(sealKey(row.agent_name, row.session_id)),
      };
    });
  }

  /**
   * The state an operator sees, for one agent — used by BOTH status surfaces.
   *
   * Deliberately one function. The daemon-wide status and the per-connection `cello_status` used to
   * compute this separately, and separate copies of a truth claim are how the directory-health block
   * came to exist on one surface and not the other earlier today.
   */
  function agentStateFor(a: AgentInfo): AgentState {
    return resolveAgentState({
      loadFailed: a.state === "load_failed",
      // `unregistered` is BUILT and tested (agent-state.ts) and deliberately NOT EMITTED yet.
      //
      // The truthful signal is whether the DKG left a FROST share — registration's durable product,
      // rather than a flag anyone could forget to set. But every test fixture creates an agent
      // WITHOUT one, so switching this on relabels the agents in 29 tests across 8 files, and the
      // alternative — fabricating share material in fixtures — plants fake crypto material that a
      // later reader takes for real. Neither is worth it for a state that lasts the few seconds
      // between `cello create-agent` and `cello register-agent`.
      //
      // So the daemon asserts exactly what it asserted before this change: a loaded agent is treated
      // as registered. That is not a regression, and it is not silent — it is this comment. The VALUE
      // stays in AgentState, so turning it on once fixtures can register for real is a one-line
      // change here and NOT a second wire change for every consumer.
      hasFrostShare: true,
      deliberatelyOffline: explicitlyOfflineAgents.has(a.name),
      started: onlineAgents.has(a.name),
      // This agent's OWN stream where it has one — an agent whose connection is severed while its
      // siblings are fine must not read as healthy.
      //
      // Falls back to the shared manager, mirroring directorySignalingStatus(): production gives
      // every agent its own connection, but the M6 back-compat/test path has ONE shared manager and
      // no per-agent entry at all. Reading only the per-agent map there returns undefined for every
      // agent, so all of them reported `connecting` — which then made isAgentReady false and refused
      // real commands with `selected_agent_offline`. Absent is not the same as disconnected.
      signalingConnected:
        (perAgentSignaling.get(a.name)?.signaling.status ?? sharedSignaling?.status) === "connected",
      attendance: countAttendance(perConnectionState, a.name),
    });
  }

  // `probeSealReadiness` is NOT returned: its only caller is `buildInterruptedSessions`, which
  // moved with it. Returning it would make a private helper reachable for no consumer.
  return { buildInterruptedSessions, reapDeadHalfOpenSessions, buildActiveSessions, agentStateFor };
}
