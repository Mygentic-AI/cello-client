/**
 * cello_register — DKG with the directory consortium.
 *
 * The one invariant, and it is the whole reason CELLO exists: NO SINGLE NODE can complete this
 * ceremony alone. Registration runs a T-of-N distributed key generation across the consortium
 * roster, so a compromised directory cannot forge an identity. If the code below ever lets one node
 * produce a valid ceremony output, that is a security violation regardless of whether tests pass.
 *
 * registrationInProgress is DAEMON-WIDE, and the reason matters: the directory's registration reply
 * frames (dkg_ready / register_success / register_error) carry NO AGENT IDENTIFIER. Two concurrent
 * registrations over the one shared signaling stream would each arm a resolver and both receive the
 * same reply — CROSS-WIRING THE CEREMONIES. It is the registration analogue of the
 * sealInterruptedInProgress guard, but global rather than per-key precisely because the frames are
 * not agent-tagged. Do not "improve" it into a per-agent map.
 */
import { Buffer } from "node:buffer";
import type { IpcHandler } from "./ipc-server.js";
import type { Logger } from "./types.js";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { SignalingManager, CelloNode } from "@cello-protocol/transport";
import type { DbRegistrationPersistence } from "./db-identity-store.js";
import type { IManifestProvider } from "@cello-protocol/transport";
import { manifestNodesToEndpoints } from "./directory-bootstrap.js";
import { DaemonRegistrationContext } from "./registration-context.js";
import { RegistrationManager } from "./registration-manager.js";
import { validatorNodes } from "@cello-protocol/protocol-types";
import { classifyManifestValidity } from "./manifest-validity.js";

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
  registrationGuidance: (reason: string, detail?: string) => string;
  manifestProvider?: IManifestProvider;
}

export function registerRegisterHandler(deps: RegisterHandlerDeps): void {
  const {
    handlers, logger, keyProviders, getPersistence,
    getAgentSignaling, waitForSignalingConnected, dropAgentSignaling, startAgentInternal,
    directoryEndpointResolver, loadedAgents, registrationGuidance, manifestProvider,
  } = deps;

  // Single-flight guard (M1): the directory's registration reply frames (dkg_ready /
  // register_success / register_error) carry NO agent identifier, so two concurrent registrations
  // over the one shared directory signaling stream would each arm a resolver and both receive the
  // same reply — cross-wiring the ceremonies. Serialize registration daemon-wide (it is a rare,
  // once-per-agent, human-initiated operation). This is the registration analogue of the
  // sealInterruptedInProgress guard, but GLOBAL rather than per-key because the frames are not
  // agent-tagged. A per-agent guard would reintroduce the cross-wiring it exists to prevent.
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
        // The primary resolver uses staleFallback:false, so a transient /bootstrap blip returns null
        // here. Registration is a rare manual operation — failing fast with a clear retry message is
        // correct. (Signaling has richer failover because it runs continuously; registration runs once.)
        return { ok: false, reason: "directory_unreachable", guidance: "Could not reach a directory node to start registration — this is often a transient network blip. Wait a few seconds and retry. If it persists, check your internet connection." };
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
      // DOD-DKG-1 + M12 ROLE-MANIFEST-1: resolve the consortium roster from the VERIFIED
      // manifest, restricted to VALIDATOR-role nodes — replicas hold no shares and take no part
      // in a DKG, so including one would either strand registration on a quorum-count mismatch
      // or deal a share to a share-less node. The directory computes its quorum over validators
      // too; the two sides must agree on N. Re-resolved here (ceremony time) for fresh failover
      // coordinates. NULL when NO manifest is configured (→ single-node DKG, M6/M7 back-compat);
      // a (possibly EMPTY) array when a manifest IS configured. The null-vs-empty distinction is
      // load-bearing: an empty roster (consortium configured but unreachable) must REFUSE in
      // registration-manager, NOT downgrade to single-node (code-reviewer B1 / fallback-finder).
      const currentManifest = manifestProvider?.getCurrentManifest();
      /**
       * DOD-M15-EXPIRY-CONSUMER-POLICY-1 — this consumer PROCEEDS on a lapsed manifest, and that is
       * now a decision rather than an omission. Written down because the split looked accidental:
       * `signal-submission` REFUSES on expiry while this, the higher-stakes consumer, did not even
       * look.
       *
       * **Why it proceeds.** Startup already fails closed on an expired manifest, so a lapsed one
       * exists only inside a LONG-RUNNING daemon. Refusing here sends the operator to the one remedy
       * `signal-submission`'s own guidance warns against — *"a restart without a REPLACEMENT does not
       * reload anything: the daemon refuses to come back and every agent goes offline."* So refusing
       * would brick a running operator to close a window that needs a roster CHANGE to be
       * exploitable at all: the risk is dealing a share to a validator removed since the manifest
       * lapsed, not expiry itself.
       *
       * **Why `signal-submission` is different, and why "make them consistent" would be wrong.** It
       * uses the manifest's PORTAL INTAKE KEY, and a rotated key means a message the portal cannot
       * open and cannot attribute — unattributable poison, its own word, with no error anywhere.
       * Different field, different failure, different answer.
       *
       * **What was actually missing was not the gate — it was the RECORD.** `cello_status` already
       * reports an expired manifest, so the STATE was visible; nothing said a FROST share had been
       * dealt against one. That is what this event is.
       */
      const manifestValidity = classifyManifestValidity(currentManifest ?? null, Date.now());
      /**
       * ⚠️ NOT ONLY `expired` — review F7. `unreadable_window` (a window field that does not parse)
       * and `not_yet_valid` (a wrong clock, or a manifest rotated in early) both reached the DKG
       * with no event at all. `unreadable_window` matters more than it looks: since the startup gate
       * was hardened it cannot start a daemon, but a manifest POLLED IN after startup can still put
       * a running daemon into it.
       */
      const lapsed = manifestValidity.state === "expired"
        || manifestValidity.state === "unreadable_window"
        || manifestValidity.state === "not_yet_valid";
      if (lapsed) {
        logger.warn("registration.manifest.lapsed", {
          agent: name,
          state: manifestValidity.state,
          window: manifestValidity.state === "expired" ? manifestValidity.expires : manifestValidity.notBefore,
          validators: currentManifest ? validatorNodes(currentManifest.nodes).length : 0,
          /**
           * ⚠️ THIS USED TO SAY "a share MAY BE DEALT to a node that is no longer authorized", and
           * that over-claimed in the very case it named. Review traced the path: a validator removed
           * since the lapse is either unreachable — dropped at the dial layer by the peerId
           * cross-check against the signed manifest — or reachable but absent from the DIRECTORY's
           * current manifest, in which case the roster/participants counts disagree and registration
           * REFUSES with `dkg_below_threshold`. **Dealing a share to a de-authorized node is not
           * reachable through this path.** The event was about to be emitted alongside a FAILED
           * registration while telling the operator a share may have gone somewhere.
           *
           * What it says now is what is actually true, and it is still worth saying: this event is
           * emitted immediately before that refusal, so it is the line that explains an otherwise
           * bare `dkg_below_threshold` — which names an exit point and not a cause.
           */
          /**
           * ⚠️ ONE CAUSE OF A MULTI-CAUSE EXIT — pass 2, and the previous wording inverted the
           * redundancy invariant in prose. `dkg_below_threshold` comes from a single comparison
           * (`roster.length !== participants`) whose own comment names TWO causes: a node we reported
           * is now unreachable, OR a manifest version skew. **An unreachable node is the routine
           * one** — under the sovereign-node design a node being down is the expected steady state,
           * not the exception. Saying "THIS is the cause" and "replace the trust anchor rather than
           * retrying" told the operator to replace a threshold-signed anchor in the case where the
           * correct move is to retry.
           */
          impact:
            "the consortium roster this registration works from came from a manifest whose validity " +
            "window is not currently open. This is ONE possible cause of a subsequent " +
            "dkg_below_threshold — a directory node being momentarily unreachable is the more common " +
            "one, and is expected rather than exceptional.",
          guidance:
            "Registration was NOT blocked here — blocking it would strand a running daemon, since a " +
            "restart without a replacement manifest does not come back. If it then fails with " +
            "dkg_below_threshold: RETRY FIRST, because an unreachable node is the usual cause. " +
            "Replace the trust anchor only if cello_status shows the manifest window is the " +
            "discrepancy.",
        });
      }
      const consortiumRoster = currentManifest
        ? await manifestNodesToEndpoints(validatorNodes(currentManifest.nodes), { logger })
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
          // `detail` is the underlying cause when the manager captured one — the wire `reason` stays
          // the closed union, the guidance gets to be accurate.
          return {
            ok: false,
            reason: result.error,
            guidance: registrationGuidance(result.error, (result as { detail?: string }).detail),
          };
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
