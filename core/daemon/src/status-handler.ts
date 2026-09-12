/**
 * `cello_status` — what ONE CONNECTION can see of this daemon, from its own perspective.
 *
 * The widest read in the daemon and one of the narrowest dependency lists: nine values, every one a
 * reader, nothing written. It reports the agents this connection may act as, its directory
 * signaling, where the consortium manifest came from, unresolved directory nodes, interrupted
 * sessions and live ones.
 *
 * ⚠️ `unresolvedNodesForStatus` DID NOT COME WITH IT, and that is deliberate. The daemon-wide
 * `getStatus()` — what `cello status` at a terminal renders — calls the same helper, and it is the
 * surface that was silent on 2026-07-31 while every session failed. A helper with two consumers
 * moves only when both move; here it is injected instead.
 */
import { classifyManifestValidity, describeManifestValidity, type ManifestOrigin } from "./manifest-validity.js";
import { describeDirectoryAuth } from "./directory-auth-posture.js";
import { describeConsortiumFingerprint, type EnforcedConsortium } from "./consortium-fingerprint.js";
import { resolveDirectoryUrl } from "./directory-bootstrap.js";
import type { IpcHandler } from "./ipc-server.js";
import type { AgentInfo, ActiveSessionInfo, DirectorySignalingState, InterruptedSessionInfo } from "./types.js";
import type { IDirectoryChallengeVerifier } from "@cello-protocol/transport";
import type { ConsortiumManifest } from "@cello-protocol/protocol-types";

export interface StatusHandlerDeps {
  handlers: Map<string, IpcHandler>;
  /** Every agent this CONNECTION may act as — not every agent the daemon holds. */
  getAgentsForConnection: (connectionId: string) => AgentInfo[];
  directorySignalingStatus: () => DirectorySignalingState;
  /** Where the verified manifest came from, for a reader deciding how much the rest is worth. */
  manifestOrigin: ManifestOrigin;
  manifestProvider: { getCurrentManifest: () => Pick<ConsortiumManifest, "not_before" | "expires"> | null } | undefined;
  /** The configured directory URL, or undefined when nothing was configured. */
  directoryHttpUrl: string | undefined;
  /**
   * The directory challenge verifier, or undefined when this daemon holds none. TYPED, not
   * `unknown`: the posture line an operator reads is derived from `!== undefined`, so a dep loose
   * enough to accept `null` or the wrong variable would report `directory_authentication: enforced`
   * on a daemon that enforces nothing — the failure `DOD-M15-DIRAUTH-1` exists to prevent.
   */
  challengeVerifier: IDirectoryChallengeVerifier | undefined;
  /** The root keys and threshold actually handed to the verifier — see daemon-status-report.ts. */
  enforcedConsortium: EnforcedConsortium;
  /** Emits ONLY when something is wrong or nothing has looked recently enough to say. */
  unresolvedNodesForStatus: () => { directory_endpoints_unresolved: unknown } | undefined;
  buildInterruptedSessions: () => InterruptedSessionInfo[];
  /**
   * DOD-M15-AWAYSCOPE-1: the ENRICHED build. `cello_status` is an agent-facing surface and the
   * agent is exactly the reader that must not have to send a message to find out whether the far
   * side is attended — that is the defect this order closes.
   */
  buildActiveSessions: () => Promise<ActiveSessionInfo[]>;
}

export function registerStatusHandler(deps: StatusHandlerDeps): void {
  const {
    handlers, getAgentsForConnection, directorySignalingStatus, manifestOrigin, manifestProvider,
    directoryHttpUrl, challengeVerifier, unresolvedNodesForStatus, buildInterruptedSessions, buildActiveSessions,
    enforcedConsortium,
  } = deps;

  handlers.set("cello_status", async (_params, connectionId) => {
    return {
      daemon: "running",
      directory_signaling: directorySignalingStatus(),
      // CAN I ACTUALLY REACH THE DIRECTORY — not just "is my socket up?".
      //
      // These are different facts and they diverged for an hour on 2026-07-31. libp2p signaling
      // dials multiaddrs from the bundled manifest, so it stayed connected and every agent reported
      // online, while a cached NXDOMAIN meant nothing that needed the HTTP endpoint resolved. The
      // roster came back empty, so every threshold ceremony failed — surfacing to the operator as
      // counterparty_offline, then directory_below_threshold, then ceremony_exhausted. Three errors,
      // none of them naming DNS, while the reason sat in the log 26 times per node.
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
      // DOD-M15-CONSORTIUM-FINGERPRINT-1 — WHICH consortium this client accepts a manifest from.
      ...describeConsortiumFingerprint(enforcedConsortium),
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
      agents: getAgentsForConnection(connectionId),
      // M-1 PULL: live MCP clients must see interrupted sessions too, exactly as
      // the daemon-wide getStatus() surfaces them.
      interrupted_sessions: buildInterruptedSessions(),
      // M8B F16: per-session liveness on the MCP surface too.
      active_sessions: await buildActiveSessions(),
    };
  });
}
