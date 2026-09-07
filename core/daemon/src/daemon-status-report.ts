/**
 * The whole-daemon status — what `cello status` at a terminal renders.
 *
 * The widest READ in the daemon, and this module is where that breadth is honest: it takes eleven
 * readers and writes nothing. The per-connection view is a different surface with a different answer
 * (`status-handler.ts`), and the difference is deliberate — collapsing them is how an operator ends
 * up reading another connection's state as their own.
 *
 * This is the surface that was silent on 2026-07-31 while every session failed, which is why the
 * unresolved-node block below it emits on every state except "we looked recently and all is well".
 */
import { classifyManifestValidity, describeManifestValidity, type ManifestOrigin } from "./manifest-validity.js";
import { describeDirectoryAuth } from "./directory-auth-posture.js";
import { resolveDirectoryUrl } from "./directory-bootstrap.js";
import type {
  ActiveSessionInfo, AgentInfo, AgentState, DaemonStatusResponse, DirectorySignalingState,
  InterruptedSessionInfo,
} from "./types.js";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { RetryQueue } from "./retry-queue.js";
import type { ConsortiumManifest } from "@cello-protocol/protocol-types";

export interface DaemonStatusDeps {
  sessionNodeManager: SessionNodeManager;
  retryQueue: RetryQueue;
  /** The live registry — a copy reports a roster that stopped changing at boot. */
  agents: ReadonlyArray<AgentInfo>;
  agentStateFor: (a: AgentInfo) => AgentState;
  buildInterruptedSessions: () => InterruptedSessionInfo[];
  buildActiveSessions: () => ActiveSessionInfo[];
  directorySignalingStatus: () => DirectorySignalingState;
  /** Emits on every state except "looked recently, all well" — see the header. */
  unresolvedNodesForStatus: () => { directory_endpoints_unresolved: unknown } | undefined;
  manifestOrigin: ManifestOrigin;
  manifestProvider: { getCurrentManifest: () => Pick<ConsortiumManifest, "not_before" | "expires"> | null } | undefined;
  directoryHttpUrl: string | undefined;
  /** Its ABSENCE is the reportable state: no verifier means authentication is not enforced. */
  challengeVerifier: unknown;
}

export function createDaemonStatusReport(deps: DaemonStatusDeps) {
  const {
    sessionNodeManager, retryQueue, agents, agentStateFor, buildInterruptedSessions,
    buildActiveSessions, directorySignalingStatus, unresolvedNodesForStatus, manifestOrigin,
    manifestProvider, directoryHttpUrl, challengeVerifier,
  } = deps;

  // Build status response factory
  function getStatus(): DaemonStatusResponse {
    // M7-SESSION-001 AC-006/AC-007: surface interrupted sessions
    const interrupted_sessions: InterruptedSessionInfo[] = buildInterruptedSessions();

    return {
      daemon: "running",
      directory_signaling: directorySignalingStatus(),
      // CAN I ACTUALLY REACH THE DIRECTORY — the same block cello_status carries, and for longer.
      //
      // This is the CLI's surface (`cello status`), and it is the one an operator at a terminal
      // actually runs — it is what was run on 2026-07-31 while every session failed. It was silent,
      // because this block existed on the MCP tool only. The agent list below says `online` and
      // `standing_receiver_ready: true` whether or not a single directory endpoint resolves, so
      // without this the two states render identically and the operator believes the healthy one.
      //
      // Omitted entirely when nothing is failing, so a healthy status stays quiet.
      ...(unresolvedNodesForStatus() ?? {}),
      // DOD-M15-MANIFEST-EXPIRY-LIVE-1: contributes NOTHING while the manifest is comfortably in
      // window. A field present on every status read for the years a manifest is valid is furniture,
      // not a warning, and it teaches the reader to skip the block that matters.
      ...(describeManifestValidity(
        classifyManifestValidity(manifestProvider?.getCurrentManifest() ?? null, Date.now()),
        manifestOrigin,
      ) ?? {}),
      // DOD-M15-DIRAUTH-1: the posture is STATED, in both directions. Unlike every other field in
      // this milestone the healthy case is reported too — the defect is precisely that "enforced"
      // and "skipped" differ only by the absence of a log line, so an operator must be able to
      // confirm it is on, not merely fail to find evidence that it is off.
      ...describeDirectoryAuth({
        verifierPresent: challengeVerifier !== undefined,
        directoryUrl: directoryHttpUrl ?? resolveDirectoryUrl(process.env),
        // Review F5: with neither set, `resolveDirectoryUrl` re-picks a RANDOM bundled endpoint on
        // every call, so there is no configured URL to quote or to blame.
        urlExplicitlyConfigured: directoryHttpUrl !== undefined || process.env["CELLO_DIRECTORY_URL"] !== undefined,
      }),
      // M8B F14 (fix 5): per-agent standing-receiver readiness, so a deaf agent (online but
      // no armed receiver) is visible in cello_status instead of hiding behind the ANY-agent
      // aggregate below (kept for backward compatibility).
      // CC-8 (F5 parity): the CLI `cello status` surface must show online vs registered like the MCP
      // cello_status does. The stored `a.state` is stale — it stays "registered" even when the agent is
      // online, because startAgentInternal only adds to onlineAgents and never mutates the record — so
      // derive readiness from onlineAgents here, exactly as getAgentsForConnection (F5) already does for
      // the MCP surface. A load_failed agent keeps its state so a broken agent stays visible as broken.
      // (No `selected` here: this is the daemon-wide surface; selection is a per-connection concept and
      // the CLI opens an ephemeral connection that never runs cello_use_agent — see M8C-DECISIONS D24.)
      agents: agents.map((a) => ({
        ...a,
        state: agentStateFor(a),
        standing_receiver_ready: sessionNodeManager.getStandingReceiverReady(a.name),
        standing_receiver_reachability: sessionNodeManager.getStandingReceiverReachability(a.name),
        // DOD-M15-RELAYSLOTS-1: the same cause-and-advice on the daemon-wide surface — see the note
        // on the MCP one above. Two surfaces, one reason to exist.
        ...(sessionNodeManager.getStandingReceiverRefusal(a.name)
          ? { standing_receiver_refusal: sessionNodeManager.getStandingReceiverRefusal(a.name) }
          : {}),
      })),
      standing_receiver_ready: sessionNodeManager.getStandingReceiverReady(),
      retryQueueDepth: retryQueue.getTotalDepth(),
      interrupted_sessions,
      // M8B F16: per-session liveness so a counterparty-gone session is visible.
      active_sessions: buildActiveSessions(),
    };
  }

  return { getStatus };
}
