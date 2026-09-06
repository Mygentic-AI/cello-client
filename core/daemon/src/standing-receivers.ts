/**
 * CELLO Daemon — THE STANDING RECEIVER: THE NODE THAT IS ALWAYS LISTENING
 *
 * Split out of `session-node-manager.ts` by 037-SESSIONCORE. One pre-created node per agent with an
 * open gater, kept alive at all times and handed to the first inbound session — then immediately
 * replaced, so there is always one waiting.
 *
 * Moved verbatim, comments included.
 *
 * ⚠️ ITS ABSENCE IS THE FIRST SUSPECT WHEN A LIVE SESSION FAILS. `standing_receiver_unavailable`,
 * an empty counterparty peer id, `Invalid peer ID: ""` — all of them start here. The receiver is
 * created when the agent is STARTED, not at daemon boot, so an agent that was never started has no
 * receiver and nothing to hand an inbound session.
 */
import type { Logger } from "./types.js";
import { NodeAutoNatService, type CelloNode, type IAutoNatService } from "@cello-protocol/transport";
import { SessionConnectionGater } from "./session-connection-gater.js";
import { relayOnlyState, publishableEndpoint } from "./relay-only.js";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { ISessionNodeFactory } from "./session-node-types.js";
import { extractErrorMessage } from "./error-message.js";
import { randomBytes, randomUUID } from "node:crypto";
import {
  relayPeerIdOf,
  heldRelayIdsOf,
  CIRCUIT_RELAY_ID,
  SR_RESERVATION_MAX_RETRIES,
  REVIVE_RESERVATION_CANDIDATES,
  REVIVE_RESERVATION_TIMEOUT_MS,
  type SessionNodeConfig,
} from "./session-node-types.js";
import { STANDING_RECEIVER_AGENT_NAME } from "./types.js";
import type { SessionRecords } from "./session-records.js";
import type { ParkRecovery } from "./park-recovery.js";

/** What the standing receiver needs from the manager. */
export interface StandingReceiverContext {
  readonly logger: Logger;
  readonly records: SessionRecords;
  readonly park: ParkRecovery;
  readonly factory: ISessionNodeFactory;
  /** A function: the manager opens its database after construction. Re-exposed below as `#db`. */
  db(): DaemonDatabase | null;
  shuttingDown(): boolean;
  sessionKey(agentName: string, sessionId: string): string;

  /**
   * ⚠️ THESE MAPS ARE SHARED BY REFERENCE, NOT OWNED HERE. The reservation watchdog, the relay
   * paths and session creation all read them and all stayed behind, so giving this module its own
   * copies would create two answers to "which agents have a receiver". Each is assigned exactly
   * once, at construction, so there is one object and no divergence.
   */
  readonly standingReceivers: Map<string, {
    node: CelloNode; gater: SessionConnectionGater; autoNat: NodeAutoNatService;
    seed: Uint8Array; relayPeerIds: string[];
  }>;
  readonly standingReceiverCreating: Set<string>;
  readonly agentsWantingReceiver: Set<string>;
  readonly standingReceiverRemoving: Set<string>;
  readonly srReservationRetry: Map<string, { attempts: number; nextAt: number; correlationId: string; lastReason?: string }>;
  readonly srLastRejectionReason: Map<string, string>;
  readonly srLastRespreadAt: Map<string, number>;
  readonly directoryRelayEndpoints: Map<string, Array<{ relayPeerId: string; relayAddrs: string[] }>>;
  readonly srRetryDelaysMs: number[];
  readonly srReservationTimeoutMs: number;
  readonly offeredDialer: Map<string, string>;
  /** The AutoNAT prober list, injected by the composition root. */
  autoNatProbers(): string[];

  proveToRelay(
    agentName: string,
    circuitAddr: string,
    node: CelloNode,
    correlationId: string,
    surfaceAsReceiverRefusal: boolean,
  ): Promise<"proven" | "refused_try_another_relay" | "refused_this_agent" | "unavailable">;
  reservationCircuitAddrs(agentName: string): { addrs: string[]; relayPeerIds: string[] };
  authenticateStandingReceiver(
    agentName: string,
    node: CelloNode,
    relayPeerId: string,
    heldCircuitAddr: string,
    correlationId: string,
  ): Promise<void>;
}

export class StandingReceivers {
  readonly #ctx: StandingReceiverContext;

  constructor(ctx: StandingReceiverContext) {
    this.#ctx = ctx;
  }

  /** A getter so the moved reads still say `this.#db` and narrow exactly as they did. */
  get #db(): DaemonDatabase | null {
    return this.#ctx.db();
  }

  async startReceiverNode(
    agentName: string,
    sessionId: string,
    gater: SessionConnectionGater,
    candidateCircuitAddrs: string[],
    correlationId: string,
  ): Promise<{ node: CelloNode; seed: Uint8Array }> {
    /**
     * 032-RELAYSPREAD — **ONE SEED FOR THE RECEIVER, REUSED ACROSS RELAYS**, replacing
     * DOD-M12B-SESSION-SEED-1's seed-per-candidate.
     *
     * The agent is ONE identity and must be dialable at ONE peer id through any of its circuits, so
     * every reservation this walk collects has to belong to the same key. A seed per relay would
     * give the agent a different peer id down each circuit — N half-agents, none of them the one
     * the counterparty was told to dial.
     *
     * ⚠️ THE RULE THIS REPLACES WAS RIGHT ABOUT ITS OWN CASE, so here is what changed and what did
     * not. Its hazard is real and survives: a rejected candidate is torn down while its `start()`
     * may still be in flight, so two nodes can briefly be live on this peer id. Two things bound it
     * now, and neither existed when that rule was written:
     *   - **THE ONE THAT CARRIES THE WEIGHT: DOD-M15-ASSIGN-1** made a standing receiver's gater
     *     admit NOBODY inbound until a session offer names the dialer. The old rule's stated danger
     *     — "sharing this gater, so it admits dials … an open endpoint under our advertised id" —
     *     is not true of this gater any more. `#startReceiverNode` has exactly one caller and it
     *     constructs that gater with `allowedPeerId: null` and an empty reserved set, so an
     *     overlapping candidate is an endpoint that refuses everyone.
     *   - the teardown is chained onto the candidate's OWN start promise (the `#buildRevivedNode`
     *     pattern, verified against libp2p 3.3.2: `stop()` returns immediately unless the status is
     *     `started`, and through the whole timeout window it is `starting`, so the old unawaited
     *     `stop()` stopped nothing). ⚠️ This bounds the LEAK, not the OVERLAP — a timed-out
     *     candidate is not awaited and the walk moves straight to the next one on the same seed, so
     *     overlap is the normal shape of that case, not a remote possibility. It guarantees the
     *     loser dies, and nothing more.
     * `#buildRevivedNode` already runs a fixed identity through this same walk for the same reason.
     */
    const receiverSeed = randomBytes(32);
    /** Circuit addresses whose relay ACTUALLY GRANTED this identity a reservation. */
    const grantedAddrs: string[] = [];
    // For `spread.grant_not_bound` below: the walk's own duration is measured against the relay's
    // two-minute proof memory, so it has to be a number rather than an inference.
    const walkStartedAt = Date.now();

    for (const circuitAddr of candidateCircuitAddrs) {
      const candidateSeed = receiverSeed;

      /**
       * DOD-M15-RELAYSLOTS-1 — **TWO ATTEMPTS PER RELAY: ask, prove, ask again.**
       *
       * The relay now refuses a reservation from a peer that has not shown it belongs to a
       * registered agent. A brand-new receiver has shown nothing, so its FIRST ask is refused —
       * expected, not a failure. It then authenticates over `/cello/relay/1.0.0`, which tells the
       * relay this transport identity is a registered agent's, and asks again on a fresh connection
       * carrying the SAME identity (that is what reusing `candidateSeed` buys).
       *
       * ⚠️ It has to be two connections, and that was measured rather than chosen. Taking the
       * reservation by hand on the same connection as the proof DOES get a slot — and libp2p then
       * announces no circuit address for it, because it only announces addresses for reservations
       * its own relay-discovery made. The agent would hold a slot nobody could dial through.
       */
      let candidateGranted = false;
      // Set when the relay refused the AGENT rather than being unwilling itself: every other relay
      // in the pool answers identically, so the walk ends here rather than reproducing it N times.
      let candidateRefusedAgent = false;
      for (let attempt = 0; attempt < 2; attempt++) {
      const candidate = await this.createAgentNode(agentName, {
        sessionId,
        connectionGater: gater,
        nodeType: "standing_receiver",
        circuitRelayListenAddrs: [circuitAddr],
        transportPrivateKey: candidateSeed,
      });
      let timer: ReturnType<typeof setTimeout> | undefined;
      const timedOut = Symbol("reservation_timeout");
      let outcome: "started" | typeof timedOut | "failed" = "failed";
      let error = "";
      // KEEP THE START PROMISE. Every candidate now carries the receiver's identity, so an
      // abandoned one must be reliably torn down rather than best-effort — and only its own start
      // promise says when it is stoppable (see the seed note above).
      const startP = candidate.start();
      try {
        outcome = await Promise.race([
          startP.then(() => "started" as const),
          new Promise<typeof timedOut>((resolve) => {
            timer = setTimeout(() => resolve(timedOut), this.#ctx.srReservationTimeoutMs);
          }),
        ]);
      } catch (err: unknown) {
        error = extractErrorMessage(err);
      } finally {
        if (timer !== undefined) clearTimeout(timer);
      }

      // The only proof that counts: the relay actually GRANTED the reservation.
      // start() resolving is not enough — a relay that is out of reservation slots
      // completes the handshake and simply grants nothing, leaving a node that looks
      // started and is reachable by nobody.
      if (outcome === "started" && candidate.listenAddresses().some((a) => a.includes("/p2p-circuit"))) {
        candidateGranted = true;
        // The probe has done its job: this relay grants THIS identity. Tear it down and ask the
        // next relay — the reservation is re-taken by the final node below, which is the only one
        // that can listen on every granted address at once. AWAITED, because the next probe comes
        // up on this same peer id.
        try { await candidate.stop(); } catch { /* it may never have finished starting */ }
        break;
      }

      /**
       * No reservation. On the FIRST attempt that is the expected answer for a receiver that has
       * not proved itself yet, so prove and go round once more. `proveReservation` opens its own
       * stream from this node, which is what binds this transport identity to the agent at the
       * relay; the relay remembers it across the reconnect below.
       */
      if (attempt === 0 && outcome === "started") {
        const verdict = await this.#ctx.proveToRelay(agentName, circuitAddr, candidate, correlationId, true);
        // AWAITED, not fire-and-forget: the retry rebuilds on this same transport identity, and two
        // live nodes sharing one peer id is the defect DOD-M12B-SESSION-SEED-1 exists to prevent.
        try { await candidate.stop(); } catch { /* it may never have finished starting */ }
        /**
         * DOD-M15-RELAYSLOTS-1 clause 9 — **A CLIENT-SIDE REFUSAL ENDS THE WALK.**
         *
         * `slot_cap_exceeded` and an expired or missing token are classified `tryAnotherRelay:
         * false` because they reproduce on every relay in the pool: the cap is per AGENT, and the
         * token comes from the directory, not from here. Walking on costs a node build and two
         * dials per remaining relay to arrive at the same answer, and it makes one client-side
         * fault look like a fleet-wide outage in the logs. The refusal is already recorded where
         * `cello_status` reads it, so stopping is not silence.
         */
        if (verdict === "refused_this_agent") {
          this.#ctx.srLastRejectionReason.set(agentName, "relay_refused_this_agent");
          this.#ctx.logger.warn("session.standing_receiver.relay.rejected", {
            agentName,
            circuitAddr,
            reason: "relay_refused_this_agent",
            attempts: attempt + 1,
            correlationId,
            impact: "the relay refused this AGENT rather than this relay being unwilling or " +
              "unwell, so every other relay would refuse it identically. Stopped here; " +
              "cello_status carries the cause and what to do about it.",
          });
          candidateRefusedAgent = true;
          break;
        }
        /**
         * ⚠️ RETRY ONLY WHAT A PROOF CAN FIX. The second attempt exists because the relay now
         * remembers this transport identity; if the proof did not land, it remembers nothing and
         * the retry is a node build and a dial spent to be refused identically. Only `proven`
         * earns the retry — everything else moves to the next relay.
         */
        if (verdict !== "proven") {
          this.#ctx.srLastRejectionReason.set(agentName, "relay_proof_refused");
          this.#ctx.logger.warn("session.standing_receiver.relay.rejected", {
            agentName,
            circuitAddr,
            reason: "relay_proof_refused",
            attempts: attempt + 1,
            correlationId,
            impact: "this relay would not take the agent's proof, so it will refuse the retry the " +
              "same way. Moving to the next relay rather than asking this one twice.",
          });
          break;
        }
        continue;
      }

      const rejectionReason =
        outcome === "started"
          ? /**
             * ⚠️ Review MEDIUM-7 — **"STARTED" DOES NOT MEAN THE RELAY ANSWERED.** A circuit listen
             * entry sets `FaultTolerance.NO_FATAL`, and `start()` only throws when the DIRECT
             * listener fails, so a relay that is simply DOWN resolves `started` with no circuit
             * address — indistinguishable, here, from a relay that answered and granted nothing.
             * Reporting that as `relay_granted_no_reservation` sends the operator to look at relay
             * capacity for what is a network fault. An open connection to the relay peer is the
             * thing that separates them, and we have one to ask.
             */
            (candidate.getConnections().some((c) => c.peerId === relayPeerIdOf(circuitAddr))
              ? "relay_granted_no_reservation"
              : "relay_unreachable")
          : outcome === "failed"
            ? "relay_unreachable"
            : "reservation_did_not_complete_in_time";
      this.#ctx.srLastRejectionReason.set(agentName, rejectionReason);
      this.#ctx.logger.warn("session.standing_receiver.relay.rejected", {
        agentName,
        circuitAddr,
        reason: rejectionReason,
        attempts: attempt + 1,
        ...(error !== "" ? { error } : {}),
        correlationId,
      });
      // Abandon it — but on its OWN settlement, never best-effort. `start()` may still be parked on
      // a dial, and this candidate carries the receiver's identity: an unawaited `stop()` on a node
      // whose status is still `starting` returns without stopping anything, and the node then goes
      // live on our peer id with nothing left holding a reference to kill it.
      void startP.then(
        () => candidate.stop().catch(() => { /* best-effort once it has settled */ }),
        () => { /* never started; nothing bound */ },
      );
      break;
      }
      if (candidateGranted) grantedAddrs.push(circuitAddr);
      // 032-RELAYSPREAD: DO NOT BREAK ON THE FIRST GRANT. The walk used to stop here, which is why
      // an agent held exactly one reservation and losing that relay cost it every NAT'd caller for
      // however long detection happened to take. It now asks every remaining relay.
      if (candidateRefusedAgent) break;
    }

    /**
     * THE RECEIVER, listening on EVERY granted circuit address.
     *
     * One node per agent, as before — what changed is how many circuits it announces. Each address
     * here belongs to a relay that granted THIS seed moments ago and therefore still remembers the
     * identity, so the final node's first ask is the one that succeeds; the two-attempt dance was
     * already paid per relay in the walk.
     *
     * ⚠️ RACED AGAINST A DEADLINE, and that is measured rather than cautious: `#buildRevivedNode`
     * records a live 2026-08-18 result where a node handed two relay addresses at once with no
     * deadline never finished starting at all (10,002ms and counting). Its identity was unproven at
     * both relays, which is not this case — but "not this case" is a prediction, and the standing
     * receiver is the thing that makes an agent reachable, so it does not wait on one.
     *
     * An empty `grantedAddrs` yields the plain TCP floor, exactly as before: reachable by peers
     * that can dial directly, and loud about it (`session.standing_receiver.reservation.none`).
     */
    const node = await this.createAgentNode(agentName, {
      sessionId,
      connectionGater: gater,
      nodeType: "standing_receiver",
      ...(grantedAddrs.length > 0 ? { circuitRelayListenAddrs: grantedAddrs } : {}),
      transportPrivateKey: receiverSeed,
    });
    if (grantedAddrs.length === 0) {
      await node.start();
      return { node, seed: receiverSeed };
    }
    /**
     * ⚠️ SLOW AND FAILED ARE DIFFERENT ANSWERS AND MUST NOT SHARE A BRANCH. Review F1: a single
     * `.catch(() => false)` around this race collapsed every `start()` REJECTION into the deadline
     * branch — and `CelloNodeImpl.start()` rejects by design, stopping the node and throwing
     * `listen_failed` when no direct (non-circuit) listener materialised. That is the guard the
     * transport keeps precisely so `FaultTolerance.NO_FATAL` cannot mask a real `EADDRINUSE`.
     *
     * Swallowed, it installed a STOPPED node as the agent's front door: no addresses to advertise,
     * `#tryCreateStandingReceiver` never saw a failure so the M8B F14 retry never fired, and the
     * operator was told the receiver "did not finish binding every circuit inside the deadline" and
     * "is reachable through those" — sending them to the relay fleet for a port held by an orphan
     * daemon on their own machine. The rejection is rethrown so it reaches
     * `session.node.create.failed` with its own cause, exactly as it does on the no-relay path.
     */
    let deadline: ReturnType<typeof setTimeout> | undefined;
    let startError: unknown;
    const started = node.start().then(
      () => "ok" as const,
      (err: unknown) => { startError = err; return "failed" as const; },
    );
    const outcome = await Promise.race([
      started,
      new Promise<"slow">((resolve) => {
        // Per granted relay: each circuit listener is its own dial and its own reservation, so a
        // pool of three must not be judged on a budget sized for one.
        deadline = setTimeout(() => resolve("slow"), this.#ctx.srReservationTimeoutMs * grantedAddrs.length);
      }),
    ]);
    if (deadline !== undefined) clearTimeout(deadline);
    if (outcome === "failed") throw startError;
    /**
     * GRANTED IN THE WALK, REFUSED AT INSTALL — a distinct fact and, until this line, an invisible
     * one. The receiver would simply report `reservationsHeld: 2` where 3 relays granted, with
     * nothing naming which relay went missing or why.
     *
     * ⚠️ IT HAS A KNOWN CAUSE AND A CROSS-REPO CLOCK. The walk stops the granted candidate and the
     * node below RE-ASKS, which works because the relay remembers the proof — for
     * `PROVEN_PEER_MEMORY_MS = 2 minutes` (`relay-connection-gater.ts`, trustless-cello). The walk
     * costs up to `#srReservationTimeoutMs` × 2 attempts per relay, so a pool of three at the
     * 15s default can spend 90 seconds before the final node asks relay 1 again. The earliest
     * proof can expire before it is used, and that is what this event catches.
     */
    const boundRelays = new Set(heldRelayIdsOf(node));
    const grantedButUnbound = grantedAddrs
      .map((a) => CIRCUIT_RELAY_ID.exec(a)?.[1])
      .filter((id): id is string => id !== undefined && !boundRelays.has(id));
    if (grantedButUnbound.length > 0) {
      this.#ctx.logger.warn("session.standing_receiver.spread.grant_not_bound", {
        agentName,
        relayPeerIds: grantedButUnbound,
        relaysGranted: grantedAddrs.length,
        reservationsHeld: boundRelays.size,
        walkMs: Date.now() - walkStartedAt,
        correlationId,
        impact: "these relays granted this agent a reservation during the walk and then bound no " +
          "circuit on the receiver itself, so the agent is reachable through fewer relays than it " +
          "earned. The relay remembers a proof for two minutes; if walkMs is near or past that, " +
          "the proof expired before the receiver asked and the walk is what needs shortening — " +
          "not the relay fleet.",
      });
    }
    if (outcome === "slow") {
      // NOT a teardown, and now this line means only what it says: the node is starting and has not
      // finished. It is installed with whatever circuits did materialise, because some reachability
      // beats none and the reservation watchdog is what settles the rest.
      this.#ctx.logger.warn("session.standing_receiver.spread.slow_start", {
        agentName,
        relaysGranted: grantedAddrs.length,
        circuitAddrs: node.listenAddresses().filter((a) => a.includes("/p2p-circuit")).length,
        budgetMs: this.#ctx.srReservationTimeoutMs * grantedAddrs.length,
        correlationId,
        impact: "the receiver did not finish binding every circuit it was granted inside the " +
          "deadline, so it is being installed with the circuits it has. It is reachable through " +
          "those; the reservation watchdog re-checks the rest on its next tick.",
      });
    }
    return { node, seed: receiverSeed };
  }
  /** One standing-receiver create attempt (extracted for the M8B F14 retry loop). */
  async tryCreateStandingReceiver(
    agentName: string,
    correlationId: string,
  ): Promise<{ outcome: "installed" | "aborted" } | { outcome: "failed"; error: string }> {
    const sessionId = `standing_receiver_${randomUUID()}`;
    const gater = new SessionConnectionGater({
      sessionId,
      // No named peer: admits NOBODY inbound until a session offer names the dialer, while leaving
      // this node's own outbound errands open (DOD-M15-ASSIGN-1). It does NOT mean "open".
      allowedPeerId: null,
      logger: this.#ctx.logger,
    });


    // DOD-NAT-REACHABILITY-1: reserve with the agent's known relays. The relay
    // peers are allowed OUTBOUND on the gater up front, so reservation refreshes
    // keep working after the receiver is claimed and setAllowedPeer() narrows
    // the inbound gate to the session counterparty.
    const reservations = this.#ctx.reservationCircuitAddrs(agentName);
    for (const relayPeerId of reservations.relayPeerIds) {
      gater.setAllowedOutboundPeer(relayPeerId);
    }

    let node: CelloNode;
    /**
     * DOD-M12B-SESSION-SEED-1 — the transport identity of this receiver.
     *
     * Minted ONCE inside `#startReceiverNode` and returned with the node, not minted here. It is
     * one seed for the whole walk (032-RELAYSPREAD): the receiver reserves with every relay that
     * grants, and an agent must be dialable at ONE peer id through any of its circuits, so every
     * reservation has to belong to the same key. What makes that safe is DOD-M15-ASSIGN-1 — the
     * gater above admits NOBODY inbound — not the teardown, which bounds how long a rejected
     * candidate lives rather than preventing it from overlapping. See the seed note in
     * `#startReceiverNode` for the full argument.
     *
     * FRESH EVERY TIME, which is the privacy property rather than an implementation detail. A
     * receiver serves at most one session (it is promoted into the session at handoff and replaced),
     * so no identifier is ever shared between two sessions and the 2026-04-11 rationale —
     * unlinkability of an agent's sessions to a passive observer — survives intact.
     */
    let seed: Uint8Array;
    try {
      ({ node, seed } = await this.startReceiverNode(agentName, sessionId, gater, reservations.addrs, correlationId));
    } catch (err: unknown) {
      // extractErrorMessage, NOT String(err): the transport throws structured
      // plain objects ({ reason, message }), and String() destroys both into
      // "[object Object]" — the loud failure must carry its cause.
      const error = extractErrorMessage(err);
      this.#ctx.logger.error("session.node.create.failed", {
        sessionId,
        agentName: `${STANDING_RECEIVER_AGENT_NAME}:${agentName}`,
        error,
        correlationId,
      });
      return { outcome: "failed", error };
    }

    // M2: gracefulShutdown may have begun while this node was starting (ensure runs un-awaited).
    // Don't install an orphan bound to a TCP port — stop it and bail.
    if (this.#ctx.shuttingDown()) {
      try { await node.stop(); } catch { /* best-effort */ }
      return { outcome: "aborted" };
    }

    // L1: the agent may have gone offline (cello_set_agent_offline → removeStandingReceiverForAgent)
    // while this ensure was parked on start(). Removal found no map entry to delete, so the
    // tombstone is how we learn of it — tear the fresh node down rather than install an SR for
    // an offline agent.
    if (this.#ctx.standingReceiverRemoving.has(agentName)) {
      this.#ctx.standingReceiverRemoving.delete(agentName);
      try { await node.stop(); } catch { /* best-effort */ }
      return { outcome: "aborted" };
    }

    // CELLO-M7-TRANSPORT-001: wrap in a NodeAutoNatService so its dialability drives session-
    // address advertisement and the transport.autonat.* events fire.
    const autoNat = new NodeAutoNatService({
      node,
      logger: this.#ctx.logger,
      nodeType: "standing_receiver",
      probers: this.#ctx.autoNatProbers(),
    });
    autoNat.emitInitialResult();

    /**
     * EVERY RELAY THE NODE ACTUALLY HOLDS A CIRCUIT WITH — derived from the addresses the node
     * holds, never from `reservations.addrs`.
     *
     * The old code read `reservations.addrs[0]`'s relay id as a fallback, and its own comment
     * called the hazard "dormant while the pool is size 1; the pool is designed to be larger."
     * THIS UNIT IS WHAT MAKES THE POOL LARGER, so the dormant case wakes up: candidate 0 refusing
     * while candidate 1 grants recorded a relay we are not connected to, the watchdog found it
     * absent on every tick forever, and it rebuilt on the 30-second grid — churning the very
     * reservations this unit exists to conserve. A candidate is a relay we ASKED; only a held
     * address is a relay that ANSWERED, and the fallback conflated the two.
     *
     * The fallback's own stated worry stands, and is answered by the count rather than by the
     * candidate list: if a transport ever reports a circuit address without the relay's peer id in
     * `/p2p/<id>/p2p-circuit` form, that address yields no id and is not counted as held — so the
     * receiver reads as degraded and gets rebuilt, instead of reading as healthy against a relay
     * nobody is connected to. Degrading toward "rebuild" is the safe direction; the other one is
     * the silent unreachability this whole file exists to kill.
     */
    const heldRelayPeerIds = heldRelayIdsOf(node);
    const circuitAddrs = heldRelayPeerIds.length;
    const heldCircuitAddrs = node.listenAddresses().filter((a) => a.includes("/p2p-circuit"));
    // DOD-M15-ASSIGN-1 review N3, widened by 032-RELAYSPREAD: the relays this receiver actually
    // reserved with earn the inbound AutoNAT carve-out — nothing else does. Populated only from
    // reservations that genuinely completed, so a directory that merely NAMES a relay cannot dial
    // in behind it, however many relays it names.
    gater.setReservedRelayPeers(heldRelayPeerIds);
    // The re-spread clock starts HERE, at the build, not at the epoch. Otherwise the first decay
    // re-spreads instantly — undoing the "a lost relay does not rebuild the receiver" rule seconds
    // after it fires, and changing the peer id of an agent that just lost one relay of three. The
    // ratchet this guards against runs over hours; nothing about it needs answering in a second.
    this.#ctx.srLastRespreadAt.set(agentName, Date.now());
    this.#ctx.standingReceivers.set(agentName, {
      node,
      gater,
      autoNat,
      seed,
      relayPeerIds: heldRelayPeerIds,
    });
    this.#ctx.logger.info("session.node.created", {
      sessionId,
      agentName: `${STANDING_RECEIVER_AGENT_NAME}:${agentName}`,
      sessionPeerId: node.getPeerId(),
      correlationId,
    });

    // DOD-M15-RELAYAUTH-1: authenticate to the reservation relay NOW, not when a session first
    // needs one. The relay times out a reservation nobody has proven key possession for
    // (relay-connection-gater.ts, trustless-cello) — proving it here, instead of waiting for a
    // real session to exist, is what keeps this reservation alive past that grace window.
    // Best-effort and unawaited: a failure here costs nothing beyond the relay's own grace-window
    // revoke, which the reservation watchdog already treats as an ordinary lost reservation.
    // ONCE PER HELD RELAY. Each relay revokes independently — it times out the reservation of any
    // peer that has not proven key possession TO IT — so proving to one of three and calling the
    // receiver authenticated would lose the other two circuits about fifteen seconds later, which
    // is the same silent unreachability with two more relays paying for it.
    for (const relayPeerId of heldRelayPeerIds) {
      const heldCircuitAddr = heldCircuitAddrs.find((a) => a.includes(`/p2p/${relayPeerId}/p2p-circuit`));
      if (heldCircuitAddr === undefined) continue;
      void this.#ctx.authenticateStandingReceiver(agentName, node, relayPeerId, heldCircuitAddr, correlationId)
        .catch((err: unknown) => {
          this.#ctx.logger.warn("session.standing_receiver.relay_auth.failed", {
            agentName,
            relayPeerId,
            error: extractErrorMessage(err),
            correlationId,
          });
        });
    }

    // DOD-NAT-REACHABILITY-1 observability: how reachable did this receiver come up? Zero held
    // while relays were offered means every relay refused or was unreachable — the agent is deaf
    // to NAT'd initiators (public ones can still connect directly). That must be LOUD, not a quiet
    // shrug.
    //
    // 032-RELAYSPREAD — TWO NUMBERS, SO TWO NAMES. Both events used to carry one field,
    // `reservationsRequested`, holding `reservations.addrs.length` — the size of the CANDIDATE
    // list, under a name that reads as a count of asks. That is why "the client already requests a
    // reservation with every relay it knows" read as true in an audit: the outcome was one and the
    // request was one too, and a single field could report neither.
    //   relaysOffered    — how many relays were in the candidate list (deduped by relay peer id in
    //                      `#reservationCircuitAddrs`, so it counts relays, not addresses).
    //   reservationsHeld — how many reservations this node actually holds, counted the only way
    //                      that proves a grant: ANNOUNCED /p2p-circuit listen addresses. `start()`
    //                      resolving is not enough — a relay out of reservation slots completes the
    //                      handshake, grants nothing, and leaves a node that looks started and is
    //                      dialable by nobody.
    this.#ctx.logger.info("session.standing_receiver.reachability", {
      agentName,
      relaysOffered: reservations.addrs.length,
      reservationsHeld: circuitAddrs,
      correlationId,
    });
    if (reservations.addrs.length > 0 && circuitAddrs === 0) {
      this.#ctx.logger.warn("session.standing_receiver.reservation.none", {
        agentName,
        relaysOffered: reservations.addrs.length,
        // Zero by this branch's own condition, and stated rather than implied: the event reads
        // "offered 3, held 0" on its own, without the reader having to find the gate above it.
        reservationsHeld: circuitAddrs,
        relayPeerIds: reservations.relayPeerIds,
        correlationId,
      });
    }

    // DOD-PARK-DRAIN-1: this agent has a receiver again — drain whatever parked while it did not.
    // Fired from the ONE place every path converges on (first ensure, the watchdog rebuild after a
    // lost reservation, and the auth_ok rebuild), because the defect this closes was a trigger
    // hooked to the wrong connection: content parks when the RELAY link dies, and the drain was
    // waiting on DIRECTORY SIGNALING to reconnect — which it never had to, having never dropped.
    this.#ctx.park.fireParkedDrain(agentName, "standing_receiver_ready");
    return { outcome: "installed" };
  }
  /**
   * DOD-LOOP-1: ensure the given agent has a standing receiver node (idempotent). Created when an
   * agent comes online (cello_start_agent) and replaced after it is handed off to a session. The
   * `#standingReceiverCreating` guard prevents two concurrent ensure() calls (e.g. the
   * cello_start_agent hook racing a consume-site retry) from building two nodes for one agent.
   *
   * M8B F14: a create failure no longer strands the agent deaf. Each ensure runs a BOUNDED
   * retry loop (`standingReceiverRetryDelaysMs`, default 1s/5s/15s) — covering the fixed-port
   * race where the consumed receiver still holds the port until its session node is torn down —
   * and when every attempt fails, fires the alarm-worthy `session.standing_receiver.dead`
   * (error level), distinct from the per-attempt `session.node.create.failed`. Re-arm is also
   * kicked from destroySessionNode/retireSessionNode (the moment the port frees) and from the
   * inbound accept path (ensure on demand), so one failure can never leave the agent deaf forever.
   */
  async ensureStandingReceiver(agentName: string, correlationId: string = randomUUID()): Promise<void> {
    if (this.#ctx.standingReceivers.has(agentName) || this.#ctx.standingReceiverCreating.has(agentName)) return;
    if (this.#ctx.shuttingDown()) return;
    // A fresh ensure request supersedes any pending removal (agent toggled offline→online).
    this.#ctx.standingReceiverRemoving.delete(agentName);
    this.#ctx.standingReceiverCreating.add(agentName);
    try {
      let lastError = "";
      for (let attempt = 0; attempt <= this.#ctx.srRetryDelaysMs.length; attempt++) {
        if (attempt > 0) {
          await new Promise((r) => setTimeout(r, this.#ctx.srRetryDelaysMs[attempt - 1]));
        }
        if (this.#ctx.shuttingDown()) return;
        // L1 tombstone: the agent went offline while we were creating / backing off.
        if (this.#ctx.standingReceiverRemoving.has(agentName)) {
          this.#ctx.standingReceiverRemoving.delete(agentName);
          return;
        }
        const result = await this.tryCreateStandingReceiver(agentName, correlationId);
        if (result.outcome !== "failed") return; // installed, or cleanly aborted (shutdown/offline)
        lastError = result.error;
      }
      // M8B F14 (fix 4): an agent that WANTS a receiver has none after every attempt — the
      // deaf-agent state. Fail LOUD so it is alarm-visible instead of a quiet degradation.
      this.#ctx.logger.error("session.standing_receiver.dead", {
        agentName,
        reason: lastError,
        attempts: this.#ctx.srRetryDelaysMs.length + 1,
        correlationId,
      });
    } finally {
      this.#ctx.standingReceiverCreating.delete(agentName);
    }
  }
  /**
   * Replace an agent's reservation-less standing receiver with one that reserves.
   *
   * Deliberately NOT removeStandingReceiverForAgent()+ensureStandingReceiverForAgent():
   * the public remove CLEARS #agentsWantingReceiver, so a cello_set_agent_offline landing in
   * the window while node.stop() is awaited would find no map entry and no creating
   * marker, leave no tombstone, and the re-ensure would then RESURRECT a receiver for
   * an agent that asked to go dark — accepting inbound sessions for an offline agent.
   * Here the want-flag is left intact and re-checked after the stop: a concurrent stop
   * clears it, and the rebuild correctly no-ops.
   */
  async rebuildStandingReceiver(agentName: string): Promise<void> {
    try {
      const sr = this.#ctx.standingReceivers.get(agentName);
      if (sr) {
        this.#ctx.standingReceivers.delete(agentName);
        /**
         * DOD-M12B-SESSION-SEED-1 (review F8): drop it zeroed, like every other seed.
         *
         * (review F7, STILL DECIDED AGAINST — deliberately NOT reusing this seed for the
         * replacement — but its stated blocker is GONE and the reason has changed. Restated rather
         * than reworded, because a decision whose premise has been reversed is a decision nobody
         * has actually made.)
         *
         * Reuse is attractive: this receiver's peer id may already be inside a `session_offer_accept`
         * the counterparty is acting on, and a rebuild in that window is the documented "we record
         * an identity that no longer exists… every send in this direction parks forever" defect.
         *
         * The old blocker was that a preserved identity would reach the candidate loop, whose
         * rejected candidates were stopped WITHOUT awaiting `start()`, putting two live nodes on one
         * advertised peer id. **032-RELAYSPREAD already crossed that line**: the walk now runs one
         * shared seed through every candidate, with a settlement-chained teardown, and it is safe
         * there because the receiver's gater admits nobody inbound.
         *
         * What still stops reuse HERE is different and is about the OLD node, not the new one. This
         * rebuild path awaits `sr.node.stop()`, but a stop can hang on a stuck libp2p teardown, and
         * handing the replacement the same identity before the previous receiver is provably dead
         * would put two nodes on a peer id a COUNTERPARTY has been told to dial — which is not the
         * candidate case at all: that node has a content handler and can be promoted. Doing it
         * safely needs a bounded, verified teardown first. Still follow-on work.
         */
        sr.seed.fill(0);
        try {
          sr.autoNat.stop();
          await sr.node.stop();
        } catch (err: unknown) {
          this.#ctx.logger.warn("session.standing_receiver.teardown.failed", {
            agentName,
            error: extractErrorMessage(err),
          });
        }
      }
      // The agent may have gone offline while we were stopping the old node. Its
      // want-flag is the authority — never resurrect a receiver it disowned.
      if (!this.#ctx.agentsWantingReceiver.has(agentName) || this.#ctx.shuttingDown()) return;
      await this.ensureStandingReceiver(agentName);
    } catch (err: unknown) {
      this.#ctx.logger.warn("session.standing_receiver.reservation.rebuild.failed", {
        agentName,
        error: extractErrorMessage(err),
      });
    }
  }
  /**
   * DOD-M12B-SESSION-SEED-1 — build a revived session node that is REACHABLE, without ever hanging.
   *
   * MEASURED 2026-08-18, live, three ways:
   *   - handed 2 relay addrs at once, no deadline:  `start()` never completes (10,002ms and counting)
   *   - handed none:                                `start()` in 1ms, but NOBODY can dial the node —
   *                                                 the counterparty's re-dial fails
   *                                                 `counterparty_dial_failed` and every message in
   *                                                 both directions has to go the relay park route
   *   - this:                                       one candidate at a time, each raced against its
   *                                                 own deadline, plain node as the floor
   *
   * The middle option is what shipped for one test run and it made the session half-dead: revived,
   * `active`, and unreachable. The first is what shipped before that and it hung. Neither is a
   * choice between "fast" and "reliable" — the per-candidate race is how `#startReceiverNode` has
   * always done it, and it is the shape that works in production every day.
   *
   * A FAILED CANDIDATE IS TORN DOWN AT SETTLEMENT. The first version awaited `stop()` immediately
   * and claimed that made seed reuse safe; it did not — `libp2p.stop()` returns at once unless the
   * node is `'started'`, and during the timeout window it is `'starting'` (review HIGH-3, verified
   * against libp2p 3.3.2). The teardown is now chained onto the candidate's OWN start promise, so it
   * runs whenever that settles, however late.
   *
   * A BRIEF OVERLAP IS THEREFORE POSSIBLE and is stated rather than denied: a candidate that grants
   * at 4s comes up on this session's peer id and is stopped immediately after. What is guaranteed is
   * that it dies, not that it never lives. The receiver path avoids even that by minting a seed per
   * candidate; here the identity is fixed, which is the whole point of a revival, so that option
   * does not exist.
   *
   * The floor is a plain node: a session that is usable over the relay park route beats no session.
   */
  async buildRevivedNode(
    sessionId: string,
    gater: SessionConnectionGater,
    seed: Uint8Array,
    candidateAddrs: string[],
    agentName: string,
  ): Promise<CelloNode> {
    for (const circuitAddr of candidateAddrs.slice(0, REVIVE_RESERVATION_CANDIDATES)) {
      /**
       * DOD-M15-RELAYSLOTS-1 — **A REVIVAL PROVES ITSELF TOO.**
       *
       * Review HIGH-3. The relay refuses a reservation to a peer that has not shown it belongs to
       * a registered agent, and it remembers a proof for two minutes. A revival is almost never
       * inside that window — the receiver last proved this peer id when the session was created,
       * possibly days ago — so without this loop every revived session was refused by every
       * candidate and came up on the plain floor: alive, `active`, and dialable by nobody, with
       * every message in both directions forced through the relay park route.
       *
       * Two attempts, exactly as `#startReceiverNode` does it, and for the same measured reason:
       * a reservation taken by hand on the same connection as the proof yields no dialable address.
       * The seed is fixed here — that is what a revival IS — so the second attempt necessarily
       * carries the identity the relay just recorded.
       */
      let revivedNode: CelloNode | undefined;
      let terminalRefusal = false;
      for (let attempt = 0; attempt < 2 && !terminalRefusal; attempt++) {
      const candidate = await this.createAgentNode(agentName, {
        sessionId,
        connectionGater: gater,
        nodeType: "session",
        inboundReachable: true,
        transportPrivateKey: seed,
        circuitRelayListenAddrs: [circuitAddr],
      });
      // KEEP THE START PROMISE. Review HIGH-3: `libp2p.stop()` opens with
      // `if (this.status !== 'started') return`, and during the whole timeout window the status is
      // `'starting'` — so awaiting `stop()` on a timed-out candidate stopped nothing and waited for
      // nothing. The abandoned `start()` stayed in flight, and if the relay answered late the node
      // went live holding THIS SESSION'S peer id, sharing the gater (so it admits the counterparty)
      // with no content handler registered, and with no reference left to stop it. Verified against
      // libp2p 3.3.2 rather than assumed.
      const startP = candidate.start();
      let startError: unknown;
      const started = await Promise.race([
        startP.then(() => true as const),
        new Promise<false>((res) => setTimeout(() => res(false), REVIVE_RESERVATION_TIMEOUT_MS).unref?.()),
      ]).catch((err: unknown) => { startError = err; return false as const; });

      if (started && candidate.listenAddresses().some((a) => a.includes("/p2p-circuit"))) {
        this.#ctx.logger.info("session.revive.reservation.granted", { agentName, sessionId, attempts: attempt + 1 });
        revivedNode = candidate;
        break;
      }

      /**
       * No reservation on the first attempt is the EXPECTED answer for a peer whose proof has
       * aged out. Prove and go round once more.
       *
       * Only when `started` is true: `libp2p.stop()` opens with `if (this.status !== 'started')
       * return`, so a timed-out candidate cannot be torn down here and rebuilding on its seed
       * would put two live nodes on one peer id. That case falls through to the settlement-chained
       * teardown below, which is the only thing that reliably kills a still-starting node.
       */
      if (attempt === 0 && started) {
        const verdict = await this.#ctx.proveToRelay(agentName, circuitAddr, candidate, sessionId, false);
        try { await candidate.stop(); } catch { /* best-effort */ }
        if (verdict === "refused_this_agent") {
          // The refusal is about this AGENT, so the remaining candidates would answer identically.
          terminalRefusal = true;
          this.#ctx.logger.warn("session.revive.reservation.declined", {
            agentName,
            sessionId,
            circuitAddr,
            reason: "relay_refused_this_agent",
            impact: "the relay refused this agent rather than being unwilling or unwell, so every " +
              "other relay refuses it the same way. The session comes up reachable only via the " +
              "relay park route; cello_status carries the cause.",
          });
          break;
        }
        // Only a landed proof earns the retry — see the same rule in `#startReceiverNode`.
        if (verdict !== "proven") {
          this.#ctx.logger.warn("session.revive.reservation.declined", {
            agentName,
            sessionId,
            circuitAddr,
            reason: "relay_proof_refused",
            impact: "this relay would not take the agent's proof, so asking it again would be " +
              "refused the same way. Trying the next relay.",
          });
          break;
        }
        continue;
      }

      // Started but granted nothing, or never started. Either way this node is not the one.
      //
      // Review MEDIUM-5: name WHICH of the three causes this was, the way `#startReceiverNode` does.
      // "declined" alone stood for a relay that is full, a relay that is unreachable, and a relay
      // that is merely slow — three different problems with three different responses, and the
      // thrown error was discarded entirely.
      const declineReason = started
        ? "relay_granted_no_reservation"
        : startError !== undefined
          ? "relay_unreachable"
          : "reservation_did_not_complete_in_time";
      const isLast = circuitAddr === candidateAddrs.slice(0, REVIVE_RESERVATION_CANDIDATES).at(-1);
      this.#ctx.logger.warn("session.revive.reservation.declined", {
        agentName,
        sessionId,
        circuitAddr,
        reason: declineReason,
        ...(startError !== undefined ? { error: extractErrorMessage(startError) } : {}),
        impact: isLast
          ? "no relay granted; the session comes up reachable only via the relay park route"
          : "trying the next relay",
      });
      // Teardown at SETTLEMENT, not now: a `stop()` issued while the node is still starting is a
      // no-op (see above), so the only way to guarantee this node dies is to wait for its own start
      // to finish first. Not awaited, so a hung start cannot hold the revival up — the point is that
      // the teardown eventually happens, not that it happens before the next candidate.
      void startP.then(
        () => candidate.stop().catch(() => { /* best-effort */ }),
        () => { /* never started; nothing bound */ },
      );
      break;
      }
      if (revivedNode) return revivedNode;
      if (terminalRefusal) break;
    }

    // THE FLOOR. No reservation, so the counterparty cannot dial us directly — but their messages
    // park at the relay and drain, which is how every message in the 2026-08-18 test arrived. A
    // session usable one way beats a session that never comes back.
    const plain = await this.createAgentNode(agentName, {
      sessionId,
      connectionGater: gater,
      nodeType: "session",
      inboundReachable: true,
      transportPrivateKey: seed,
    });
    await plain.start();
    if (candidateAddrs.length > 0) {
      this.#ctx.logger.warn("session.revive.reservation.none", {
        agentName,
        sessionId,
        candidates: candidateAddrs.length,
        impact: "the revived session holds no circuit address — the counterparty cannot dial it, so "
          + "delivery in both directions depends on relay store-and-forward until it is rebuilt",
      });
    }
    return plain;
  }
  /**
   * DOD-M15-RELAYONLY-1: build a transport node for THIS AGENT, with its privacy posture applied.
   *
   * ⚠️ THE CHOKE POINT FOR NODE CREATION, and it exists for the same reason as the one around
   * `getStandingReceiverInfo`. Five call sites construct nodes; passing `relayOnly` at each would be
   * a hand-kept list, and the SIXTH — added next month by someone who has never read this line —
   * would build a node that hole-punches its way to a direct connection for an operator who asked
   * never to be directly reachable. Here, a new caller inherits the posture instead of being told.
   *
   * `unknown` counts as ON, matching the publish and dial halves: a node that declines to hole-punch
   * is reachable over the relay, while a disclosed address cannot be recalled.
   */
  // ⚠️ NOT `async`. This wrapper sits in the standing-receiver startup path, and making it async
  // added ONE extra microtask hop before the receiver was installed in `#standingReceivers` — which
  // was enough for `createSessionNode` to run first and answer `standing_receiver_unavailable`. Two
  // tests in `msg-021-session-seed` caught it. Returning the factory's promise directly keeps the
  // await count identical to the call it replaced. **This is a real fragility in the install path,
  // not a quirk of the tests:** anything that adds a tick here re-breaks it.
  createAgentNode(agentName: string, config: SessionNodeConfig): Promise<CelloNode> {
    // ⚠️ THE POSTURE READ MUST NEVER COST US A NODE. This sits in the standing-receiver startup
    // path, whose caller treats a throw as "no receiver" and leaves the agent deaf to all inbound —
    // surfacing to the operator as `standing_receiver_unavailable`, which names the transport for a
    // fault in a settings lookup. `relayOnlyState` already absorbs a throwing GETTER; this absorbs
    // everything else, including a resolution failure for an agent row that is not there yet.
    //
    // The fallback is ON, not off: an agent whose posture we cannot read gets the private-but-
    // reachable node, because a node that declines to hole-punch still works over the relay while a
    // disclosed address cannot be recalled.
    let relayOnly = true;
    try {
      relayOnly = relayOnlyState((key) => this.#ctx.records.getSetting(agentName, key), this.#db !== null) !== "off";
    } catch (err) {
      this.#ctx.logger.warn("settings.relay_only.unreadable", {
        agentName,
        reason: err instanceof Error ? err.message : String(err),
        impact: "could not read this agent's relay-only posture, so the node is built WITHOUT the hole-punch",
      });
    }
    return this.#ctx.factory.createNode({ ...config, relayOnly });
  }
  /**
   * DOD-PARK-DRAIN-1 (review F6): why there is no standing-receiver node to dial from — named
   * precisely, because `standing_receiver_unavailable` is the exit-point label that stood in for
   * four different causes and misnamed this very incident 102 times.
   *
   * Only meaningful once `getStandingReceiverNode()` has returned null, which means NO agent on
   * this daemon has a ready receiver — the dial node is not agent-scoped.
   */
  standingReceiverAbsenceReason(
    agentName: string,
  ): "daemon_shutting_down" | "standing_receiver_creating" | "agent_offline" | "no_standing_receiver" {
    if (this.#ctx.shuttingDown()) return "daemon_shutting_down";
    if (this.#ctx.standingReceiverCreating.has(agentName)) return "standing_receiver_creating";
    if (!this.#ctx.agentsWantingReceiver.has(agentName)) return "agent_offline";
    return "no_standing_receiver";
  }
  getStandingReceiverInfo(agentName: string): { peerId: string; addrs: string[] } | null {
    // DOD-LOOP-1: the initiator advertises ITS OWN agent's standing receiver, which it then reuses
    // as the session node — so the advertised endpoint matches the node the counterparty dials.
    const sr = this.#ctx.standingReceivers.get(agentName);
    if (!sr) return null;
    // DOD-M15-RELAYONLY-1: THE CHOKE POINT. Every path that publishes this agent's session
    // addresses draws from here — `initiator_session_addrs` on the way out, and
    // `counterparty_session_addrs` when answering an offer — and this method has no other kind of
    // consumer: its whole purpose is to be advertised, as the docstring above says.
    //
    // The suppression lives HERE rather than at those call sites deliberately. Call-site gating
    // would be a hand-kept list, and a fourth publish path added later would leak the operator's IP
    // while every test stayed green. At the choke point a new caller inherits the protection
    // instead of having to be told about it.
    const endpoint = { peerId: sr.node.getPeerId(), addrs: sr.node.listenAddresses() };
    // ⚠️ TRI-STATE, not a boolean, and the third state is the one that matters. `getSetting` answers
    // `null` both for "unset" and for "there is no database", and reading the second as OFF fails
    // TOWARD DISCLOSURE: the standing receiver outlives the DB during shutdown, so an offer arriving
    // in that window would publish the operator's real addresses with relay-only switched on.
    // `relayOnlyState` also absorbs a THROW — `#requireAgentId` throws for a retired agent, and this
    // method is called from the offer ceremony inside a floating async with no catch, where the
    // throw becomes an unhandled rejection and the offer vanishes with no local log.
    // ⚠️ `!== null`, NOT `!== undefined`. The field is declared `DaemonDatabase | null` and is only
    // ever assigned on open or set to `null` on close — **it is never `undefined` at any point in
    // its lifetime**, so the first version of this line was a compile-time-constant `true` that
    // TypeScript had no reason to complain about, and the whole `"unknown"` branch was unreachable
    // dead code. The fix for the disclosure window silently did nothing, which is worse than not
    // having written it: the DoD said the window was closed and it was wide open.
    const state = relayOnlyState((key) => this.#ctx.records.getSetting(agentName, key), this.#db !== null);
    if (state === "unknown") {
      this.#ctx.logger.warn("settings.relay_only.unreadable", {
        agentName,
        impact:
          "cannot tell whether relay-only is on, so ONLY this agent's relay-circuit addresses are " +
          "published — never a direct one. Publishing a real address is irreversible and a narrowed " +
          "route is not, so this errs toward reachability loss rather than disclosure",
      });
    }
    // ONE filter, not two. The `unknown` branch used to build its own filtered object inline, which
    // put a second implementation inside the very method whose design rationale is that there is
    // exactly one — and the bypass guard could not see it.
    return publishableEndpoint(endpoint, state !== "off");
  }
  /** DOD-LOOP-1: whether the given agent has a standing receiver ready (any agent if omitted). */
  getStandingReceiverReady(agentName?: string): boolean {
    if (agentName !== undefined) return this.#ctx.standingReceivers.has(agentName);
    return this.#ctx.standingReceivers.size > 0;
  }
  /**
   * The standing receiver's libp2p node — a general-purpose node usable for OUTBOUND dials that
   * are not session-scoped (e.g. the content-park deposit/pull to the relay, MSG-001-3b). Its
   * gater admits nobody INBOUND until a session names them (DOD-M15-ASSIGN-1), but leaves these
   * outbound errands open. Returns null until the receiver is ready.
   */
  getStandingReceiverNode(agentName?: string): CelloNode | null {
    // With an agentName: that agent's own standing-receiver node (needed when the dial must
    // originate from a SPECIFIC agent — e.g. the startup content-park re-park, where the
    // depositor is the original sender). Without one: any ready standing receiver (outbound
    // content-park deposit/pull to the relay — open gater, not session-scoped).
    if (agentName !== undefined) return this.#ctx.standingReceivers.get(agentName)?.node ?? null;
    return this.anyStandingReceiver()?.node ?? null;
  }
  /**
   * First ready standing receiver (any agent) — for agent-agnostic OUTBOUND use. Its gater admits
   * nobody INBOUND until a session names them (DOD-M15-ASSIGN-1); outbound stays open, which is the
   * property these callers depend on.
   */
  anyStandingReceiver(): { node: CelloNode; gater: SessionConnectionGater; autoNat: NodeAutoNatService } | null {
    for (const sr of this.#ctx.standingReceivers.values()) return sr;
    return null;
  }
  /**
   * DOD-M12B-RESERVATION-RETRY-1 — whether a NAT'd peer can actually DIAL this agent.
   *
   * `standing_receiver_ready` answers "is there a receiver?", which is true for a plain TCP node
   * that no relay would give a circuit reservation to. Behind NAT that node is reachable by nobody,
   * and the difference was visible only in the log — where it was visible 481 times and nobody
   * acted. `"retrying"` and `"unreachable"` are the states an operator can do something about.
   *
   *   reserved    — holds a circuit reservation; a NAT'd peer can dial it.
   *   retrying    — no reservation yet, still re-asking on a backoff.
   *   unreachable — no circuit reservation and the automatic re-attempts are spent, so only peers
   *                 that can connect DIRECTLY will get in. It is not permanent: a directory
   *                 reconnect carrying a DIFFERENT relay pool re-arms the budget, because a relay we
   *                 have never tried is new information.
   *   absent      — no receiver at all (the agent is not online).
   */
  getStandingReceiverReachability(agentName: string): "reserved" | "retrying" | "unreachable" | "absent" {
    const sr = this.#ctx.standingReceivers.get(agentName);
    if (!sr) return "absent";
    // AT LEAST ONE. Holding two circuits and losing one leaves the agent perfectly dialable, so it
    // is not "retrying" — reporting it as such sends an operator hunting a fault that is not there.
    if (sr.relayPeerIds.length > 0) return "reserved";
    const retry = this.#ctx.srReservationRetry.get(agentName);
    return retry !== undefined && retry.attempts > SR_RESERVATION_MAX_RETRIES ? "unreachable" : "retrying";
  }
  /**
   * CELLO-M7-TRANSPORT-001: the AutoNAT service wrapping the current standing
   * receiver node, or null if the standing receiver is not ready. The composition
   * root uses this as the daemon's runtime IAutoNatService — its getDialability()
   * drives the SessionAssignment advertised address (AC-004/AC-019), and it is the
   * source of the transport.autonat.result / transport.autonat.unavailable events.
   */
  getStandingReceiverAutoNat(): IAutoNatService | null {
    // DOD-LOOP-1: the daemon-level autonat source is any ready standing receiver; null until one
    // exists (the composition root falls back to LocalAutoNatStub). Per-session advertised dialability
    // comes from the initiating agent's own SR via getStandingReceiverInfo, not this daemon-level value.
    return this.anyStandingReceiver()?.autoNat ?? null;
  }
  /**
   * Which peer this agent's standing receiver is currently admitting INBOUND — `null` for nobody.
   *
   * Read-only, and it answers a question the daemon otherwise cannot: *"whose dial would this
   * receiver accept right now?"* The gate is narrowed and re-closed from several paths (an offer
   * arrives, an assignment is refused, a session is promoted), and until now the only way to know
   * where it had ended up was to reproduce the sequence in your head.
   *
   * Added for `DOD-M15-RESPONDER-VERIFY-1`, where a refusal for one session was closing the gate a
   * DIFFERENT session had narrowed — a defect with no observable symptom short of the second
   * session's initiator being refused with "nothing invited it".
   */
  getStandingReceiverAllowedPeer(agentName: string): string | null {
    return this.#ctx.standingReceivers.get(agentName)?.gater.getAllowedPeerId() ?? null;
  }
  /**
   * DOD-M15-ASSIGN-1 — name the one peer allowed to dial this agent's standing receiver, at the
   * moment the directory's `session_offer` says who is coming.
   *
   * This is what makes the receiver's deny-by-default safe. The offer names
   * `initiator_session_peer_id`, and the responder answers it by advertising its OWN address in
   * `session_offer_accept`. Narrowing here — BEFORE that answer goes out — means the door opens to
   * exactly one peer at the same instant the address that reaches them is published, and never
   * before. The initiator cannot know where to dial until the accept it triggers has been sent.
   *
   * Returns WHICH failure it was, never a bare false (review F6). The caller reports a distinct
   * reason per cause: "no receiver" and "the directory named nobody" are different subsystems, and
   * collapsing them sent the operator to the directory for a local problem. This method never
   * widens the gate to compensate.
   *
   * Narrows INBOUND ONLY. The receiver is still the daemon's general-purpose dialer at this point
   * — no assignment exists yet — so revoking its outbound latitude here would break content
   * parking and restart-seal submission (review F2).
   */
  admitOfferedDialer(
    agentName: string,
    initiatorSessionPeerId: string,
    sessionIdHex: string,
  ): "narrowed" | "no_receiver" | "no_peer_named" {
    const sr = this.#ctx.standingReceivers.get(agentName);
    if (!sr) return "no_receiver";
    if (initiatorSessionPeerId === "") return "no_peer_named";
    sr.gater.admitInboundPeer(initiatorSessionPeerId);
    this.#ctx.offeredDialer.set(this.#ctx.sessionKey(agentName, sessionIdHex), initiatorSessionPeerId);
    return "narrowed";
  }
  /**
   * What the UNSIGNED offer claimed, so the SIGNED assignment can be checked against it.
   *
   * DOD-M15-OFFER-SIGNED-1. Decision 2 rules that the listening socket is "gated on the
   * assignment", and the gate is narrowed from `session_offer` — a frame carrying no signature —
   * because that is the only thing that arrives early enough. Timing forced the offer; it does not
   * excuse trusting it.
   *
   * Keeping what the offer said turns the two frames into a CHECK ON EACH OTHER. The assignment is
   * FROST-signed by the initiator's own threshold group, which no single directory can produce, and
   * it names the same peer id. A directory that says one peer in the offer and another in the
   * assignment is naming two different dialers for one session — which a truthful directory never
   * does, and which is exactly the move a compromised one would make to slip a peer past the gate
   * before the signed document arrives.
   */
  getOfferedDialer(agentName: string, sessionIdHex: string): string | null {
    return this.#ctx.offeredDialer.get(this.#ctx.sessionKey(agentName, sessionIdHex)) ?? null;
  }
  /** Forget the offered dialer for ONE session — called on BOTH the claim and the refusal paths. */
  clearOfferedDialer(agentName: string, sessionIdHex: string): void {
    this.#ctx.offeredDialer.delete(this.#ctx.sessionKey(agentName, sessionIdHex));
  }
  /**
   * RE-CLOSE the standing receiver — but ONLY if this session is still the one holding it.
   *
   * DOD-M15-OFFER-SIGNED-1 review F4, then N1. The first version closed the gate unconditionally,
   * and that was worse than the defect it fixed: an agent has ONE standing receiver with ONE allowed
   * peer, so a refusal for session P closed the gate that offer Q had narrowed. Q's initiator —
   * invited, legitimate — was then refused with *"nothing invited it"*, which this daemon had.
   *
   * That is the same cross-session interference F1 was written to remove, moved one method along,
   * and triggerable the same way: one bogus offer/assignment pair collapses a concurrent real
   * session.
   *
   * So the gate is closed only when it still names the peer THIS session opened it to. If a later
   * offer has already re-narrowed it, that offer owns the receiver and its narrowing stands.
   *
   * NO EVICTION SWEEP, deliberately (N4). The sweep evicts by "not the allowed peer", and
   * `getConnections()` returns OUTBOUND connections too — including the content-park and
   * restart-seal dials this node makes as the daemon's general-purpose dialer, whose targets are on
   * no allowlist by construction. Sweeping here hung those up, and the failure surfaced as
   * `relay_unavailable`: a transport label for a local decision, which is the exact substitution
   * that comment was written to prevent. The load-bearing control is `DOD-M15-FRAME-1`'s frame gate,
   * which refuses what an unauthorised peer sends; closing the door is enough here.
   */
  revokeOfferedDialer(agentName: string, sessionIdHex: string, offeredPeerId: string | null): void {
    this.clearOfferedDialer(agentName, sessionIdHex);
    const sr = this.#ctx.standingReceivers.get(agentName);
    if (!sr || offeredPeerId === null) return;
    if (sr.gater.getAllowedPeerId() !== offeredPeerId) {
      // A later offer already owns the receiver. Closing it would refuse THAT session's initiator.
      this.#ctx.logger.debug("session.gate.revoke.skipped", {
        agentName,
        sessionId: sessionIdHex,
        reason: "a later offer has re-narrowed this receiver; its narrowing stands",
      });
      return;
    }
    sr.gater.closeInbound();
  }
}
