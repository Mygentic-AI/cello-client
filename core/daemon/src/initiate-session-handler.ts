/**
 * cello_initiate_session — the initiator's entry point.
 *
 * Asks the negotiator to find the counterparty and broker a session (cross-node if they live on a
 * different directory node), then stands up the local session node and the relay witness.
 *
 * The relay witness is BEST-EFFORT by design: a session with no relay still runs on the direct
 * content path. Degraded, never blocked — refusing to open a session because the witness is
 * unavailable would hand any relay outage a veto over the whole protocol.
 */
import { randomUUID } from "node:crypto";
import type { IpcHandler } from "./ipc-server.js";
import type { SessionNodeManager, RelayConnectParams } from "./session-node-manager.js";
import type { Logger } from "./types.js";
import type { ConnState } from "./contact-handlers.js";
import { selectAdvertisedAddress, type ITransportSelector, type SessionNegotiator } from "./transport-selector.js";
import { TIER } from "./contacts-tier-migration.js";
import { isRelayOnly, shouldDialCounterparty } from "./relay-only.js";
import type { SessionAssignment } from "@cello-protocol/protocol-types";
import type { IAutoNatService } from "@cello-protocol/transport";

export interface InitiateSessionDeps {
  /**
   * SYNC-P5 (R39, review F5): an OUTBOUND session succeeding is the initiator-side
   * party-became-reachable signal — fired after the session is usable, best-effort.
   */
  onSessionOpened?(agentName: string, counterpartyPubkey: string): void;
  handlers: Map<string, IpcHandler>;
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  getConnState: (connectionId: string) => ConnState | undefined;
  resolveCurrentAgent: (connState: ConnState | undefined, explicitAgent?: string) => string | null;
  NO_CURRENT_AGENT_RESPONSE: unknown;
  resolvedSessionNegotiator: SessionNegotiator;
  transportSelector: ITransportSelector;
  autoNatService: IAutoNatService;
  buildRelayConnectParams: (agentName: string, assignment: SessionAssignment) => Promise<RelayConnectParams | undefined>;
  getRelayCircuitAddress?: () => string;
}

/**
 * Registers `cello_initiate_session` and returns the agent-scoped opener behind it, so a worker can
 * open a session without an IPC connection. See `openSessionAs`.
 */
export function registerInitiateSessionHandler(deps: InitiateSessionDeps): {
  /**
   * The raw opener. `params` is forwarded to the negotiator as MCP wire names — an INTERNAL caller
   * should use `openSessionFor` instead, which cannot get those names wrong.
   */
  openSessionAs(
    agentName: string,
    params: Record<string, unknown> | undefined,
  ): Promise<Record<string, unknown>>;
  /**
   * Open a session as `agentName` with a counterparty, named in TypeScript rather than in wire
   * strings.
   *
   * This exists because the wire names are not guessable and a wrong one fails silently-ish: the
   * negotiator reads `target_pubkey` (falling back to `counterparty_pubkey`) and nothing else, so a
   * caller passing `pubkey` gets `invalid_target_pubkey` — an error that sends whoever reads it to
   * look at the PEER's key when the bug is in the caller's own field name. The same class of defect
   * already exists one seam over in the close handler (`session_id` vs `sessionId`).
   */
  openSessionFor(
    agentName: string,
    target: { targetPubkey: string },
  ): Promise<Record<string, unknown>>;
} {
  const {
    handlers, logger, sessionNodeManager, getConnState, resolveCurrentAgent,
    NO_CURRENT_AGENT_RESPONSE, resolvedSessionNegotiator, transportSelector, autoNatService,
    buildRelayConnectParams, getRelayCircuitAddress,
  } = deps;

  // ─── CELLO-M7-TRANSPORT-001: cello_initiate_session ─────────────────────────
  // Direct-P2P-by-default transport selection (AC-005/AC-006/AC-008/AC-010c).
  // Flow:
  //   1. Require a current agent.
  //   2. Mint a correlationId for the whole session-establishment flow.
  //   3. Read the standing receiver's AutoNAT dialability → choose the advertised
  //      address (direct when dialable, relay circuit otherwise — AC-004/AC-019).
  //   4. Negotiate the FROST-signed SessionAssignment via the directory
  //      (sessionNegotiator — WIRE-001/SIGNAL-001). When no negotiator is wired,
  //      return directory_signaling_not_configured (graceful — the transport
  //      adapters ARE wired; this proves it does not crash with "adapter not wired").
  //   5. Drive the transport selector to dial the counterparty using the
  //      assignment's authoritative transport_mode (SI-001). Map the TransportResult
  //      to the MCP response.
  /**
   * Open a session AS a named agent — the handler body, minus the connection.
   *
   * Extracted for M14 / DOD-DOC-DELIVERY-2: §16.4's premise is a daemon that opens a session with no
   * agent attention on either end, and until now this path existed only as an IPC handler, reachable
   * only by an agent calling `cello_initiate_session`. A worker had nothing to call.
   *
   * The split is exactly at the connection boundary: the handler resolves WHICH agent from the
   * connection's state, and everything after that is agent-scoped and identical for both callers.
   * Deliberately one implementation rather than two — session establishment is where the transport
   * mode, the FROST-signed assignment and the counterparty binding are decided, and a second copy
   * would drift on precisely those.
   */
  async function openSessionAs(
    agentName: string,
    params: Record<string, unknown> | undefined,
  ): Promise<Record<string, unknown>> {
    const correlationId = randomUUID();

    // AC-004/AC-019: the advertised address is chosen from the standing receiver's
    // current dialability. Not dialable (or AutoNAT unavailable) → relay circuit.
    const dialability = autoNatService.getDialability();
    const relayCircuitAddr = getRelayCircuitAddress ? getRelayCircuitAddress() : "";
    const advertisedAddress = selectAdvertisedAddress(dialability, relayCircuitAddr);

    // resolvedSessionNegotiator is always defined (the daemon builds a real internal
    // negotiator when none is injected), so directory_signaling_not_configured no longer
    // fires on the live binary — session_request is actually negotiated with the directory.
    const negotiation = await resolvedSessionNegotiator.negotiate({
      agentName,
      correlationId,
      advertisedAddress,
      params: params ?? {},
    });
    if (!negotiation.ok) {
      return { ok: false, reason: negotiation.reason, guidance: negotiation.guidance };
    }

    // SI-001: the selector consumes the assignment's signed transport_mode as the
    // sole dial authority — never inferred from address format.
    const assignment = negotiation.assignment;

    // M8B F13: validate-what-you-receive at the trust boundary. When the responder cannot
    // proceed it aborts SILENTLY (session-ceremony.ts wireSessionOfferHandler sends nothing)
    // and the directory folds an EMPTY counterparty endpoint into the FROST-signed
    // assignment. Accepting that assignment produced a false ok:true + a phantom session
    // whose failure only surfaced on the first cello_send. Reject it HERE — before any
    // local session state exists — covering every cause of a missing accept (abort,
    // offline, crash, timeout) without needing a directory change.
    if (!assignment.counterparty_session_peer_id) {
      logger.warn("session.initiate.counterparty_unavailable", {
        sessionId: Buffer.from(assignment.session_id).toString("hex"),
        agentName,
        correlationId,
      });
      return {
        ok: false,
        reason: "counterparty_unavailable",
        guidance: "The counterparty did not accept the session offer (it may be offline or unable to receive). No session was established. Verify the counterparty agent is online (its operator can check cello_status), then retry cello_initiate_session.",
      };
    }

    const result = await transportSelector.dial(assignment, { correlationId });
    const sessionId = Buffer.from(assignment.session_id).toString("hex");

    if (!result.ok) {
      // Terminal: both direct and relay failed (AC-008). Pass the error through.
      return { ok: false, reason: result.reason, guidance: result.guidance };
    }

    // SEAM (initiate → DAEMON-004 session-core): transport is now established, but the
    // session does not yet exist in the daemon's session-core. Without this, initiate
    // would set up a connection no session can use and a subsequent cello_send would
    // report session_not_found. Create the DAEMON-004 session node + DB row, bound (via
    // its connection gater) to the counterparty's negotiated session peer id, so the
    // session is queryable and usable (cello_send / cello_receive / cello_close_session).
    //
    // NOTE (seam 1b, next): the session node N_A created here does NOT yet share the
    // connection that transportSelector.dial established on the separate transportDialer
    // node — so its content newStream cannot ride that link until the dial is routed
    // THROUGH N_A. Tracked as the dialer/session-node reconciliation; this seam only
    // establishes that initiate creates the session-core session.
    // The initiator's session row must record WHO this session is with, so an interrupted
    // initiator session surfaces its counterparty at next login (DOD-INT-1). The public
    // tool param is `target_pubkey` (the counterparty's K_local) — the same field the
    // negotiator reads above; `counterparty_pubkey` is the legacy fallback. Reading only
    // the legacy field stored an EMPTY counterparty on every initiator session.
    const counterpartyPubkey =
      typeof params?.target_pubkey === "string"
        ? params.target_pubkey
        : typeof params?.counterparty_pubkey === "string"
          ? params.counterparty_pubkey
          : "";
    const counterpartyPeerId = assignment.counterparty_session_peer_id ?? "";
    // M7 DOD-SPINE-6 / MSG-001-3b: relay witness params from the FROST-signed assignment
    // + this agent's K_local. N_A connects to the relay and submits message-leaf hashes.
    const relayParams = await buildRelayConnectParams(agentName, assignment);
    const created = await sessionNodeManager.createSessionNode(
      sessionId,
      agentName,
      counterpartyPubkey,
      counterpartyPeerId,
      correlationId,
      // Reuse the standing receiver as N_A so its peer id matches the session endpoint the
      // negotiator advertised — the counterparty's gater admits the dial (WIRE-002).
      true,
      relayParams,
    );
    if (!created.ok) {
      return { ok: false, reason: created.reason, guidance: created.guidance };
    }

    // SEAM 1b: the session node N_A must hold the connection its content stream rides — so
    // dial the counterparty THROUGH N_A. The counterparty's advertised SESSION addresses are
    // the source of truth for dialability (a NATed node advertises a relay-circuit address; a
    // directly-reachable one — localhost or a public addr — advertises a direct multiaddr), so
    // attempt the dial whenever the assignment carries counterparty session addrs, regardless
    // of the transport_mode LABEL (the local selector stub labels everything "relay" even when
    // the addrs are directly dialable). A failure is NOT fatal: per the dead-channel contract,
    // the session stays active and a later cello_send queues the content in the durable retry
    // queue until a route exists (the relay-park path is MSG-001-3b).
    const counterpartyAddrs = assignment.counterparty_session_addrs ?? [];
    // DOD-M15-RELAYONLY-1: the OTHER half of the control. Suppressing our own published addresses
    // stops them dialing US; this stops us handing our IP to THEM. Both are needed, because the
    // counterparty may not be relay-only themselves — they will still advertise addresses, and the
    // gate below is otherwise satisfied by exactly that.
    const relayOnly = isRelayOnly((key) => sessionNodeManager.getSetting(agentName, key));
    if (relayOnly && counterpartyAddrs.length > 0) {
      logger.info("session.initiate.direct_dial.suppressed", {
        sessionId,
        addrCount: counterpartyAddrs.length,
        impact: "relay-only is on: routing over the relay and not revealing this node's address",
        correlationId,
      });
    }
    if (shouldDialCounterparty(counterpartyAddrs, relayOnly)) {
      const connected = await sessionNodeManager.connectToCounterparty(agentName, sessionId, counterpartyAddrs);
      if (!connected.ok) {
        logger.warn("session.initiate.connect.failed", {
          sessionId,
          reason: connected.reason,
          error: connected.error,
          transportMode: assignment.transport_mode,
          correlationId,
        });
      }
    }

    // M8C-CONTACT-1 (D6): "initiating a session to X adds X" — pin at the pubkey the negotiator
    // actually used (not re-resolved later). DOD-TIER-4 AC3: a deliberate outbound initiate makes the
    // counterparty KNOWN, provenance 'initiated'. (Not WHITELISTED — auto-accept stays an explicit
    // cello_contact_set_tier act, design §1.)
    sessionNodeManager.addContact(agentName, counterpartyPubkey, undefined, "initiated", TIER.KNOWN);

    // AC-007: the session is usable immediately upon (relay) connection — the dcutr
    // upgrade runs in the background and is intentionally NOT awaited here.
    deps.onSessionOpened?.(agentName, counterpartyPubkey);
    return { ok: true, sessionId, transportMode: result.mode, correlationId };
  }

  handlers.set("cello_initiate_session", async (params, connectionId) => {
    const connState = getConnState(connectionId);
    // CC-3 / M8C-AUTOSTART-1 F18: resolve the target agent — explicit { agent } wins, else this
    // connection's current agent, else the sole online agent (removes the no_current_agent papercut
    // after a /mcp reconnect when exactly one agent is online). 2+ online with none selected → null.
    const agentName = resolveCurrentAgent(connState, params?.agent as string | undefined);
    if (!agentName) {
      return NO_CURRENT_AGENT_RESPONSE;
    }
    return openSessionAs(agentName, params);
  });

  return {
    openSessionAs,
    openSessionFor: (agentName, target) =>
      // The ONE place the wire name is written for internal callers.
      openSessionAs(agentName, { target_pubkey: target.targetPubkey }),
  };
}
