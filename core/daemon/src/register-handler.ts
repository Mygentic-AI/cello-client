/**
 * cello_register — DKG with the directory consortium.
 *
 * The one invariant, and it is the whole reason CELLO exists: NO SINGLE NODE can complete this
 * ceremony alone. Registration runs a T-of-N distributed key generation across the consortium
 * roster, so a compromised directory cannot forge an identity. If the code below ever lets one node
 * produce a valid ceremony output, that is a security violation regardless of whether tests pass.
 *
 * registrationInProgress is a plain guard, not a lock: a second concurrent register for the same
 * agent would race two DKGs against the same slot.
 */
import type { IpcHandler } from "./ipc-server.js";
import type { Logger } from "./types.js";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { SignalingManager, CelloNode } from "@cello-protocol/transport";
import type { DbRegistrationPersistence } from "./db-identity-store.js";
import type { IManifestProvider } from "@cello-protocol/transport";
import { manifestNodesToEndpoints } from "./directory-bootstrap.js";
import { DaemonRegistrationContext } from "./registration-context.js";
import { RegistrationManager } from "./registration-manager.js";

export interface RegisterHandlerDeps {
  handlers: Map<string, IpcHandler>;
  logger: Logger;
  keyProviders: Map<string, KeyProvider>;
  getPersistence: (agentName: string) => DbRegistrationPersistence;
  getAgentSignaling: (agentName: string, keyProvider: KeyProvider, pubkeyHex: string) => { signaling: SignalingManager; getNode: () => CelloNode | null };
  waitForSignalingConnected: (mgr: SignalingManager, timeoutMs: number) => Promise<boolean>;
  dropAgentSignaling: (agentName: string) => Promise<void>;
  startAgentInternal: (name: string) => { ok: true } | { ok: false; reason: string; guidance: string };
  directoryEndpointResolver?: () => Promise<import("./signaling-connect.js").DirectoryEndpoint | null>;
  loadedAgents: Array<{ name: string; pubkey: string; keyProvider: KeyProvider }>;
  registrationGuidance: (reason: string) => string;
  manifestProvider?: IManifestProvider;
}

export function registerRegisterHandler(deps: RegisterHandlerDeps): void {
  const {
    handlers, logger, keyProviders, getPersistence,
    getAgentSignaling, waitForSignalingConnected, dropAgentSignaling, startAgentInternal,
    directoryEndpointResolver, loadedAgents, registrationGuidance, manifestProvider,
  } = deps;

  // A second concurrent register for the same agent would race two DKGs against the same slot.
  let registrationInProgress = false;

  handlers.set("cello_register", async (params, _connectionId) => {
    const name = params?.agent as string | undefined;
    const preAuthToken = params?.preAuthToken as string | undefined;
    const phoneStub = (params?.phoneStub as string | undefined) ?? "";
    if (!name) {
      return { ok: false, reason: "missing_params", guidance: "Provide 'agent' (the agent name to register) and 'preAuthToken' (the pre-authorization ticket from the CELLO Operations Agent)." };
    }
    if (!preAuthToken) {
      return { ok: false, reason: "missing_preauth_token", guidance: "Registration requires a 'preAuthToken' issued by the CELLO Operations Agent (Telegram). Obtain one, then retry 'cello register-agent'." };
    }
    const keyProvider = keyProviders.get(name);
    if (!keyProvider) {
      return { ok: false, reason: "agent_not_found", guidance: `Agent '${name}' does not exist. Create it first with 'cello create-agent ${name}', then retry 'cello register-agent'.` };
    }
    if (!directoryEndpointResolver) {
      return { ok: false, reason: "directory_unreachable", guidance: "The daemon has no directory endpoint resolver configured, so it cannot reach the directory to register." };
    }
    // M1: claim the single-flight slot synchronously (no await between the check
    // and the set) so two concurrent calls cannot both proceed.
    if (registrationInProgress) {
      return { ok: false, reason: "registration_already_in_progress", guidance: "Another agent registration is already in progress on this daemon. Registration runs one at a time because the directory's reply frames are not agent-tagged. Wait for it to finish (check the daemon logs for registration.succeeded/failed), then retry." };
    }
    registrationInProgress = true;
    try {
      // Resolve the directory endpoint once for this registration (the context's
      // getDirectoryEndpoint is synchronous; the daemon's resolver is async).
      // FINDING-4 scope note: this uses the PRIMARY resolver directly (not the roster-aware
      // failover resolver — registration is deliberately out of FINDING-4's "signaling +
      // ceremony" scope). Because that primary is now built with staleFallback:false (so the
      // failover wrapper sees a dead primary as null), a transient /bootstrap blip here resolves
      // to null → directory_unreachable rather than riding through on a stale last-known-good;
      // registration is a rare, manual, retryable op, so failing fast (retry) is acceptable. With
      // a manifest configured the DKG fans out over the independently-probed roster regardless of
      // this endpoint. The endpoint is stable for one registration — if it changed mid-flow the
      // DKG streams would break anyway.
      const ep = await directoryEndpointResolver();
      if (!ep || !ep.multiaddr) {
        // FROST DKG must dial the directory's /cello/frost/1.0.0 — a dialable
        // multiaddr is required (DirectoryEndpoint.multiaddr is optional for the
        // already-connected signaling case, but registration needs to open streams).
        return { ok: false, reason: "directory_unreachable", guidance: "Could not resolve a dialable directory bootstrap endpoint (GET /bootstrap). Check CELLO_DIRECTORY_URL and network connectivity, then retry." };
      }
      const directoryEndpoint = { peer_id: ep.peerId, multiaddrs: [ep.multiaddr] };

      // Multi-agent: register over THIS agent's own directory signaling stream (authed
      // as this agent), so the directory routes its dkg_complete/register_success back
      // to it. CONN-001: every agent has its own dedicated stream (no shared keystone). The
      // DKG's FROST streams open on this agent's directory node.
      const agentRecord = loadedAgents.find((a) => a.name === name);
      const agentPubkeyHex = agentRecord?.pubkey ?? Buffer.from(await keyProvider.getPublicKey()).toString("hex");
      const { signaling: agentSignaling, getNode: agentGetNode } = getAgentSignaling(name, keyProvider, agentPubkeyHex);

      // A non-primary agent's stream connects lazily — wait for it before the DKG
      // (RegistrationManager returns directory_unreachable if signaling isn't connected).
      const signalingConnected = await waitForSignalingConnected(agentSignaling, 10_000);
      if (!signalingConnected) {
        // Distinct cause → distinct code (M7 error discipline): this is specifically the
        // per-agent signaling stream failing to come up in time, not a missing/unresolvable
        // directory endpoint. Drop the manager so it doesn't reconnect forever for an
        // unregistered agent (it is re-created on the next cello_register).
        await dropAgentSignaling(name);
        return {
          ok: false,
          reason: "directory_signaling_timeout",
          guidance: `Agent '${name}' could not establish its directory signaling stream within 10s. Check CELLO_DIRECTORY_URL and that the directory is reachable, then retry 'cello register-agent'.`,
        };
      }

      const persistence = getPersistence(name);
      // DOD-DKG-1: resolve the full consortium roster from the VERIFIED manifest so the DKG fans
      // across all N directory nodes. Re-resolved here (ceremony time) for fresh failover
      // coordinates. NULL when NO manifest is configured (→ single-node DKG, M6/M7 back-compat);
      // a (possibly EMPTY) array when a manifest IS configured. The null-vs-empty distinction is
      // load-bearing: an empty roster (consortium configured but unreachable) must REFUSE in
      // registration-manager, NOT downgrade to single-node (code-reviewer B1 / fallback-finder).
      const currentManifest = manifestProvider?.getCurrentManifest();
      const consortiumRoster = currentManifest
        ? await manifestNodesToEndpoints(currentManifest.nodes, { logger })
        : null;
      const ctx = new DaemonRegistrationContext({
        signaling: agentSignaling,
        getDirectoryNode: agentGetNode,
        getDirectoryEndpoint: () => directoryEndpoint,
        getConsortiumEndpoints: () => consortiumRoster,
        keyProvider,
        persistence,
        logger,
      });
      try {
        const result = await new RegistrationManager(ctx).register(phoneStub, preAuthToken);
        if ("error" in result) {
          logger.warn("registration.failed", { agentName: name, reason: result.error });
          // Terminal failure for THIS agent — drop its dedicated signaling manager so it
          // does not reconnect forever for an unregistered agent (re-created on retry).
          await dropAgentSignaling(name);
          return { ok: false, reason: result.error, guidance: registrationGuidance(result.error) };
        }
        // PERSIST-002 (AC-013): the identity row (K_local + share + ML-DSA + registration) is durably
        // committed at this point (RegistrationManager awaits the persist before returning success).
        // SI-001: never log a secret — only the agent name + PUBLIC key.
        logger.info("persist.identity.persisted", { agentName: name, agentPubkey: agentPubkeyHex });
        // CC-2 (2026-07-07): registration succeeded — arm this agent's standing receiver NOW so a
        // brand-new agent can receive inbound immediately. Without this the agent reports
        // standing_receiver_ready:false and cannot receive until the operator restarts (logout/login),
        // so a fresh registration looks broken. Uses the SAME idempotent path login and cello_use_agent
        // arm through (startAgentInternal → onlineAgents + directory signaling + ensureStandingReceiver +
        // agent_state_changed). A start failure must NOT fail the (already durably persisted)
        // registration — surface it as a warning and let the operator recover via login.
        const armResult = startAgentInternal(name);
        if (!armResult.ok) {
          logger.warn("registration.standing_receiver.arm_failed", { agentName: name, reason: armResult.reason });
        } else {
          // arm_INITIATED, not armed: startAgentInternal returns ok once the agent is online + signaling
          // is up, but ensureStandingReceiverForAgent runs fire-and-forget (its own failure emits
          // session.standing_receiver.ensure.failed) — so this event marks the start, not readiness.
          logger.info("registration.standing_receiver.arm_initiated", { agentName: name });
        }
        // Capture-now-or-lose-it: persist the agent→user link (using it is future
        // trust-layer work). L1: the agent is already registered at this point —
        // a link-write failure must NOT be reported as a registration failure.
        // Surface it as a non-fatal warning so the operator knows the link wasn't
        // captured (re-registering with the same token re-attempts it).
        try {
          await persistence.persistAgentUserLink({ agentId: result.agent_id, preAuthToken, linkedAt: Date.now() });
          logger.info("registration.succeeded", { agentName: name, agentId: result.agent_id, primaryPubkey: result.primary_pubkey });
          return { ok: true, agent_id: result.agent_id, primary_pubkey: result.primary_pubkey };
        } catch (linkErr: unknown) {
          logger.warn("registration.user_link.capture_failed", {
            agentName: name,
            agentId: result.agent_id,
            error: linkErr instanceof Error ? linkErr.message : String(linkErr),
          });
          logger.info("registration.succeeded", { agentName: name, agentId: result.agent_id, primaryPubkey: result.primary_pubkey });
          return {
            ok: true,
            agent_id: result.agent_id,
            primary_pubkey: result.primary_pubkey,
            warning: "agent_user_link_not_captured",
          };
        }
      } finally {
        ctx.dispose();
      }
    } finally {
      registrationInProgress = false;
    }
  });
}
