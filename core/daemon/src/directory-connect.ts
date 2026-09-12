/**
 * How this daemon reaches a directory, and what it tells a relay about itself when it gets there.
 *
 * The relay-witness connect parameters — who is asking, over which circuit, with which online token
 * — and the default signaling connect that carries them. Also the single shared signaling manager,
 * which exists ONLY on the in-process test path: in production every agent dials its own, because
 * the directory routes by the pubkey that authenticated the stream.
 */
import { SignalingManager, type CelloNode, type ConnectResult } from "@cello-protocol/transport";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { Logger } from "./types.js";
import type { DirectoryEndpoint } from "./signaling-connect.js";
import type { RelayConnectParams } from "./session-node-manager.js";
import type { RelayAssignmentCarry } from "./session-relay-client.js";
import { parseSessionAssignment } from "./session-assignment-parser.js";

export interface DirectoryConnectDeps {
  logger: Logger;
  keyProviders: Map<string, KeyProvider>;
  /** Test seam. Its ABSENCE is what puts the daemon on the production per-agent path. */
  signalingConnect: ConstructorParameters<typeof SignalingManager>[0]["connect"] | undefined;
  directoryEndpointResolver: (() => Promise<DirectoryEndpoint | null>) | undefined;
}

export function createDirectoryConnect(deps: DirectoryConnectDeps) {
  const { logger, keyProviders, signalingConnect, directoryEndpointResolver } = deps;

  // M7 DOD-SPINE-6 / MSG-001-3b: assemble the relay-witness connect params for a
  // session node from the FROST-signed assignment (relay endpoint + 16-byte session id)
  // and the acting agent's K_local. Returns undefined when the agent key or relay
  // endpoint is missing — the session then runs on the direct content path without a
  // relay witness (degraded, never blocked).
  const buildRelayConnectParams = async (
    agentName: string,
    assignment: NonNullable<ReturnType<typeof parseSessionAssignment>>,
  ): Promise<RelayConnectParams | undefined> => {
    const kp = keyProviders.get(agentName);
    const endpoint = assignment.relay_endpoint;
    if (!kp || !endpoint || !endpoint.peer_id || !endpoint.multiaddrs || endpoint.multiaddrs.length === 0) {
      return undefined;
    }
    // FED-OPTIONB-SETUP-001 (Option B): when the directory included the per-node relay-assignment
    // signature, carry the assignment so the client presents it to its chosen relay (replacing the
    // directory→relay dial). Built only for relay-mode assignments that carry relay_directory_signature;
    // absent ⇒ the client skips client_record_assignment (direct/legacy/pre-M8B).
    const relayDirSig = assignment.relay_directory_signature;
    // FED-OPTIONB-SETUP-001 (fallback-finder #1/#5): a relay-mode assignment MUST carry a
    // relay_directory_signature — the directory always signs one. If it is absent or malformed (the
    // parser dropped it to undefined) for a relay-mode session, the session silently degrades to "no
    // relay witness" and looks indistinguishable from a legitimate direct-mode session. Warn LOUD so the
    // missing/corrupt witness has a named cause (this is the only diagnosable signal on a PURE RECEIVER,
    // which never submits and so never surfaces relay_unavailable). Unwitnessed is an allowed sovereign-
    // redundancy state, but it must not be invisible.
    if (assignment.transport_mode === "relay" && !relayDirSig) {
      logger.warn("session.relay.assignment.signature.missing", {
        agentName,
        sessionId: Buffer.from(assignment.session_id).toString("hex").slice(0, 16),
        reason: "relay_mode_assignment_without_directory_signature",
      });
    }
    /**
     * 069-ORDERPROOF: the carry now exists for EITHER of two independent reasons — something to
     * present to the relay, or the name of the relay whose ordering attestations this session will
     * accept. Requiring both would mean a session that knows its relay but has no per-node
     * signature verifies nothing at all, which hands the relay a way to opt out of being checked.
     */
    const relayAnchorHex =
      assignment.relay_id && /^[0-9a-f]{64}$/i.test(assignment.relay_id) ? assignment.relay_id : undefined;
    const carry: RelayAssignmentCarry | undefined = relayDirSig || relayAnchorHex
      ? {
          participantA: assignment.participant_a.pubkey,
          participantB: assignment.participant_b.pubkey,
          sessionTimestamp: assignment.session_timestamp,
          initiatorSessionPeerId: assignment.initiator_session_peer_id,
          counterpartySessionPeerId: assignment.counterparty_session_peer_id,
          ...(relayDirSig ? { assignmentSignature: relayDirSig } : {}),
          ...(relayAnchorHex ? { relayPubkeyHex: relayAnchorHex } : {}),
        }
      : undefined;
    return {
      relayPeerId: endpoint.peer_id,
      relayAddrs: endpoint.multiaddrs,
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      sessionIdBytes: assignment.session_id,
      assignment: carry,
    };
  };

  // M7-SIGNAL-001: Instantiate SignalingManager — owns directory signaling stream lifecycle.
  const defaultConnect = async (): Promise<ConnectResult> => {
    throw new Error("directory_signaling_not_configured");
  };

  // CELLO-M7-CONN-001 (DOD-CONN-1): the keystone is DELETED. There is no shared directory
  // connection borrowing the "primary" agent's identity. In PRODUCTION every agent operates its
  // OWN directory signaling connection authenticated as itself (getAgentSignaling / signalingFor);
  // removing any agent tears down only that agent's own connection, so the daemon never holds a
  // connection authenticated as a removed agent (the Demo1 stranding bug). A single SHARED manager
  // exists ONLY for the IN-PROCESS TEST path (NOT back-compat — there is no old client, and Rule F deletes back-compat on sight) (a single injected signalingConnect,
  // no per-agent isolation) — in production it is undefined.
  //
  // The SHARED (in-process test / pre-resolver) signaling path has no directory-facing node of its
  // own: nodes are per-agent, published by each agent's manager (getAgentSignaling → `nodeRef`).
  // There is nothing to return here, and saying so explicitly is the point.
  //
  // Consequence, and it is load-bearing: session-ceremony's hydrateShareAndStubs leaves
  // `directoryNodeStubs` UNDEFINED when getNode() is null, so FrostThresholdSigner runs with an
  // EMPTY set of counterparties and its pre-check (reachable < threshold-1) REFUSES. That is the
  // sovereign-node invariant holding — a daemon with no directory nodes must never sign alone. Do
  // NOT "fix" an empty stub set by substituting in-process stubs; that converts a refusal into a
  // forged seal. Pinned by frost.test.ts, "SOVEREIGN-NODE INVARIANT".
  const noSharedDirectoryNode = (): CelloNode | null => null;

  // H1: a long-running daemon must ride out directory outages — notably the 25-30 min multi-region
  // directory deploy. Use an effectively-unbounded reconnect budget with a capped backoff so each
  // connection keeps retrying and reconnects within ~maxBackoffMs of the directory returning.
  const sharedSignaling: SignalingManager | undefined = directoryEndpointResolver
    ? undefined
    : new SignalingManager({
        connect: signalingConnect ?? defaultConnect,
        logger,
        maxReconnectAttempts: Number.MAX_SAFE_INTEGER,
        maxBackoffMs: 30_000,
      });

  // `defaultConnect` is not returned: its only consumer is the shared manager built here.
  return { buildRelayConnectParams, noSharedDirectoryNode, sharedSignaling };
}
