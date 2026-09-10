/**
 * CELLO Daemon — THE STANDING RECEIVER: THE NODE THAT IS ALWAYS LISTENING
 *
 * Split out of `session-node-manager.ts` by 037-SESSIONCORE. One pre-created node per agent, kept
 * alive at all times and handed to the first inbound session — then immediately replaced, so there
 * is always one waiting.
 *
 * ⚠️ **ITS GATER IS NOT OPEN, and this sentence used to say it was.** `DOD-M15-ASSIGN-1` closed
 * exactly that: the gater admits NOBODY inbound until a session offer names the dialer, while
 * leaving this node's own outbound errands open (`allowedPeerId: null` — see the construction
 * below, which says the same thing in the imperative).
 *
 * The wrong version is called out rather than quietly corrected because of what believing it costs:
 * a reader who thinks the gater is open reads an unnamed-dialer rejection as a BUG and opens it, or
 * waves off the hardening as already done. It was inherited from the manager's own header, which is
 * corrected in the same commit.
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
  SR_RESERVATION_MAX_RETRIES,
  REVIVE_RESERVATION_CANDIDATES,
  REVIVE_RESERVATION_TIMEOUT_MS,
  RELEASE_TELL_BUDGET_MS,
  clientSideAskFault,
  holdsCircuit,
  stopWhenSettled,
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
  /** The AutoNAT prober list, injected by the composition root. */
  autoNatProbers(): string[];

  /**
   * 055-ONDEMAND — tell a relay this agent is done with its slot. Best-effort: a release that
   * could not be delivered costs a slot until its TTL and must never fail a seal.
   */
  tellRelayReleased(agentName: string, relayPeerId: string, node: CelloNode, correlationId: string): Promise<void>;
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

  /**
   * The dialer an inbound session offer named, per agent.
   *
   * ⚠️ OWNED HERE, not shared by reference like the other maps — because unlike them it has NO
   * reader left in the manager. It was passed across with the rest on the first pass; a review
   * measured that every read had moved with the four `*OfferedDialer` methods, so the by-reference
   * argument that is correct for the other nine does not apply to it.
   */
  readonly #offeredDialer = new Map<string, string>();

  constructor(ctx: StandingReceiverContext) {
    this.#ctx = ctx;
  }

  /** A getter so the moved reads still say `this.#db` and narrow exactly as they did. */
  get #db(): DaemonDatabase | null {
    return this.#ctx.db();
  }

  async #startReceiverNode(
    agentName: string,
    sessionId: string,
    gater: SessionConnectionGater,
    candidateCircuitAddrs: string[],
    correlationId: string,
  ): Promise<{ node: CelloNode; seed: Uint8Array }> {
    /**
     * 054-SRSPLIT — **ONE NODE. IT STARTS ON TCP, THEN TAKES ITS RESERVATIONS IN PLACE.**
     *
     * This used to be a walk of throwaway PROBE nodes — one built per relay to find out whether that
     * relay would grant, torn down, and then a FINAL node rebuilt carrying every granted address in
     * its constructor. The probes existed for exactly one reason: a circuit listener was fixed at
     * node creation, so the only way to ask a relay anything was to build a node to ask with.
     *
     * `listenOnCircuit` (unit 1) removed that constraint, and this is the simplification it unlocks:
     * build the receiver ONCE, and for each relay prove and ask on the node that will keep it.
     *
     * ⚠️ **AND IT CLOSES THE DEFECT UNIT 1 LEFT STANDING, which was recorded here rather than
     * fixed.** The final node was built with `circuitRelayListenAddrs`, so libp2p asked at start on
     * a fresh connection that had proved nothing on itself. It worked only because the relay
     * remembers a proof for `PROVEN_PEER_MEMORY_MS` — two minutes, in the OTHER repo — and when that
     * memory had expired the original refused-ask collision came back for the one node that IS the
     * agent's front door. There is no constructor-time ask left, so that dependency is gone, and
     * `spread.grant_not_bound` — the event that existed to catch the proof expiring between the walk
     * and the rebuild — has nothing left to report.
     *
     * ⚠️ **ONE SEED, and it still matters** (032-RELAYSPREAD). The agent is ONE identity and must be
     * dialable at ONE peer id through any of its circuits. That is now structural rather than
     * maintained: there is one node, so there is one key, and a second identity has nowhere to come
     * from. The old hazard this note used to carry — an abandoned probe still starting on the
     * receiver's seed — cannot occur, because no probe is built.
     */
    const receiverSeed = randomBytes(32);

    /**
     * Relay peers are allowed OUTBOUND before the node starts. Unchanged and load-bearing: our own
     * gater would otherwise refuse our own dial, and refreshes must keep working after
     * `setAllowedPeer()` narrows the inbound gate to a session counterparty (DOD-M15-ASSIGN-1).
     * The gater still admits NOBODY inbound here.
     */
    for (const addr of candidateCircuitAddrs) {
      const relayPeerId = relayPeerIdOf(addr);
      if (relayPeerId) gater.setAllowedOutboundPeer(relayPeerId);
    }

    const node = await this.createAgentNode(agentName, {
      sessionId,
      connectionGater: gater,
      nodeType: "standing_receiver",
      // NO `circuitRelayListenAddrs` — nothing is asked for at start. See the note above.
      transportPrivateKey: receiverSeed,
    });
    await node.start();

    /**
     * ⚠️ **THE WALK IS GONE — 055-ONDEMAND, and this is the capacity change itself.**
     *
     * The receiver used to visit every relay it had ever heard of and hold a slot on each, for the
     * life of the login, against the chance that somebody called. Demand was `agents × relays`, so
     * the tenth relay added a tenth of the fleet's demand and one relay's worth of capacity, and
     * the ratio `agents / slots-per-relay` never improved however many relays were run.
     *
     * **An idle agent now holds ZERO.** A reservation is taken when an offer arrives, on the relay
     * the directory names (`takeReservationForSession`), and given back at the seal. Demand becomes
     * `live sessions × 1`.
     *
     * **What makes that safe, and it is the reason this is not a reachability regression:**
     *   - The relay's MAILBOX consults no reservation. Deposit authenticates the depositor by their
     *     Noise peer id; pull is a signature challenge on the recipient and is an OUTBOUND dial. So
     *     store-and-forward keeps working with nothing held.
     *   - The WITNESS is a separate dial on the relay's own protocol. Nothing about the seal, the
     *     hash chain or the transcript depended on a reservation.
     *   - A cold call to a LOGGED-OUT agent was already refused with nothing queued, so no
     *     capability is lost — there was never an answering machine to lose.
     *
     * The candidate list is still passed in and still used: it is what the offer path reserves
     * against when it needs to, and what `cello_status` reports as relays this agent could use.
     */
    this.#ctx.logger.info("session.standing_receiver.idle", {
      agentName,
      relaysAvailable: candidateCircuitAddrs.length,
      correlationId,
      impact: "this agent holds no relay reservation while idle, by design. One is taken on the " +
        "relay the directory names when a session is offered, and given back at the seal.",
    });

    return { node, seed: receiverSeed };
  }

  /**
   * 054-SRSPLIT — **TAKE ONE RESERVATION, ON A NODE THAT IS ALREADY RUNNING.**
   *
   * The whole relay handshake for one relay: prove over `/cello/relay/1.0.0` on a connection we
   * open, then ask libp2p's own transport manager to listen on the circuit. The relay grants on the
   * first ask because it marks `slot.provenForReservation` per CONNECTION at auth time and libp2p's
   * reservation store reuses the open connection rather than dialling a new one (measured live
   * 2026-09-08; `DOD-M15-RELAYPROVE-ORDER-1`).
   *
   * ⚠️ **THE NODE IS NOT STOPPED BETWEEN THE PROOF AND THE ASK.** The relay marks the CONNECTION,
   * not the peer id, so closing it throws away the very thing that makes the ask succeed.
   */
  /**
   * 055-ONDEMAND — **take a reservation for a SESSION, on the relay the directory named.**
   *
   * The public face of `#takeReservation` for the offer path. An idle agent holds nothing, so this
   * is what makes it dialable, and it lasts only as long as the session that asked for it.
   *
   * Returns whether one was granted. A `false` is a degradation, not a failure: the counterparty
   * can still reach this agent directly, or through the relay's store-and-forward. The one caller
   * that must treat it as fatal is relay-only mode, which does so at its own guard.
   */
  async takeReservationForSession(agentName: string, circuitAddr: string, correlationId: string): Promise<boolean> {
    const sr = this.#ctx.standingReceivers.get(agentName);
    if (!sr) {
      this.#ctx.logger.warn("session.reservation.on_demand.no_receiver", {
        agentName,
        circuitAddr,
        correlationId,
        impact: "there is no standing receiver to hold a reservation, so this agent cannot be " +
          "dialled for this session; it is reachable through the relay's store-and-forward only.",
      });
      return false;
    }
    // The relay must be dialable BEFORE we dial it — our own gater refuses otherwise, which is the
    // same ordering the login walk uses and the one that cost a whole debugging session when it
    // was missing.
    const relayPeerId = relayPeerIdOf(circuitAddr);
    if (relayPeerId) sr.gater.setAllowedOutboundPeer(relayPeerId);
    const outcome = await this.#takeReservation(agentName, sr.node, circuitAddr, correlationId);
    /**
     * ⚠️ **THE RECEIVER'S RECORD OF WHAT IT HOLDS MUST FOLLOW, or two things go quietly wrong.**
     * `relayPeerIds` is what the reservation watchdog compares against to decide a reservation was
     * LOST, and what `cello_status` reports as reachability. Left at its build-time value — empty,
     * now that nothing is taken at login — the watchdog would see a held circuit it never recorded
     * and `cello_status` would call a reachable agent unreachable.
     *
     * Read from the NODE rather than appended to, and deduped by relay: libp2p announces one
     * address per relay listen address, so a five-address relay would otherwise count five times.
     */
    this.#ctx.standingReceivers.set(agentName, { ...sr, relayPeerIds: heldRelayIdsOf(sr.node) });
    return outcome === "granted";
  }

  /**
   * 055-ONDEMAND — **GIVE THE SLOT BACK AT THE SEAL, BY RECOMPUTING WHAT IS STILL NEEDED.**
   *
   * Two things happen, and only the first frees capacity:
   *   1. **Tell the relay.** `releaseReservation` on the authenticated stream is the ONLY thing that
   *      returns a slot to the table — a client closing its listener sends the relay nothing, and
   *      the relay frees one on its own only at the TTL (two hours) or under reaper pressure.
   *   2. **Recompute the local set.** `releaseAllCircuits()` is all-or-nothing because libp2p gives
   *      us nothing finer: every listener shares one reservation store, so closing any listener
   *      clears every entry's refresh timer (054-SRSPLIT review HIGH-2).
   *
   * ⚠️ **THAT IS WHY THIS IS A RECOMPUTE AND NOT A SUBTRACTION.** An agent with two live sessions on
   * two relays that sealed one would otherwise drop the OTHER session's circuit locally while the
   * relay still held it — a live session whose counterparty can no longer dial back, and no event
   * anywhere saying so. Dropping everything and re-taking what is still needed cannot drift; the
   * cost is a prove and an ask per surviving session, about three seconds, and it is idempotent.
   *
   * Best-effort throughout: a release that could not be delivered costs a slot until its TTL. It
   * must never fail a seal, which is why nothing here throws.
   */
  async releaseReservationsAfterSeal(
    agentName: string,
    stillNeededCircuitAddrs: readonly string[],
    correlationId: string,
  ): Promise<void> {
    const sr = this.#ctx.standingReceivers.get(agentName);
    if (!sr) return;
    const heldBefore = heldRelayIdsOf(sr.node);
    if (heldBefore.length === 0) return;

    // 1. Tell every relay we are done with. Precise, per-relay, and the only thing that frees.
    const stillNeededRelayIds = new Set(
      stillNeededCircuitAddrs.map((a) => relayPeerIdOf(a)).filter((id): id is string => id !== null),
    );
    for (const relayPeerId of heldBefore) {
      if (stillNeededRelayIds.has(relayPeerId)) continue;
      /**
       * ⚠️ **BOUNDED, BECAUSE THIS RUNS INSIDE A SEAL.** Telling the relay means dialling it, and a
       * relay that is unreachable would otherwise hold the seal open for as long as its dial takes.
       * A seal that waits on a courtesy is worse than a slot held until its TTL — measured the hard
       * way: unbounded, this hung fourteen unrelated suites at 237s each.
       */
      await Promise.race([
        this.#ctx.tellRelayReleased(agentName, relayPeerId, sr.node, correlationId),
        new Promise<void>((r) => setTimeout(r, RELEASE_TELL_BUDGET_MS).unref?.()),
      ]);
    }

    // 2. Recompute locally: drop everything, then re-take what other live sessions still need.
    try {
      await sr.node.releaseAllCircuits();
    } catch (err: unknown) {
      this.#ctx.logger.warn("session.reservation.release.local_failed", {
        agentName,
        correlationId,
        error: extractErrorMessage(err),
        impact: "this agent may still announce a circuit it no longer holds at the relay; the " +
          "watchdog rebuilds the receiver, which restores agreement.",
      });
      return;
    }
    for (const circuitAddr of stillNeededCircuitAddrs) {
      const outcome = await this.#takeReservation(agentName, sr.node, circuitAddr, correlationId);
      if (outcome !== "granted") {
        this.#ctx.logger.warn("session.reservation.retake.failed", {
          agentName,
          circuitAddr,
          correlationId,
          impact: "a session that is still live lost its circuit while another sealed, so its " +
            "counterparty cannot dial back until the receiver is rebuilt. Messages still reach it " +
            "through the relay's store-and-forward.",
        });
      }
    }
    // Same reason as the take path: the record follows the node, deduped by relay.
    const after = this.#ctx.standingReceivers.get(agentName);
    if (after) this.#ctx.standingReceivers.set(agentName, { ...after, relayPeerIds: heldRelayIdsOf(after.node) });
    this.#ctx.logger.info("session.reservation.released", {
      agentName,
      releasedRelays: heldBefore.filter((id) => !stillNeededRelayIds.has(id)),
      stillHeld: stillNeededCircuitAddrs.length,
      correlationId,
    });
  }

  async #takeReservation(
    agentName: string,
    node: CelloNode,
    circuitAddr: string,
    correlationId: string,
  ): Promise<"granted" | "refused_this_agent" | "declined"> {
    const verdict = await this.#ctx.proveToRelay(agentName, circuitAddr, node, correlationId, true);
    if (verdict === "refused_this_agent" || verdict === "refused_try_another_relay") {
      const reason = verdict === "refused_this_agent" ? "relay_refused_this_agent" : "relay_proof_refused";
      this.#ctx.srLastRejectionReason.set(agentName, reason);
      this.#ctx.logger.warn("session.standing_receiver.relay.rejected", {
        agentName,
        circuitAddr,
        reason,
        correlationId,
        impact: verdict === "refused_this_agent"
          ? "the relay refused this AGENT rather than being unwilling or unwell, so every other " +
            "relay would refuse it identically. Stopped here; cello_status carries the cause."
          : "this relay would not take the agent's proof. Moving to the next relay.",
      });
      return verdict === "refused_this_agent" ? "refused_this_agent" : "declined";
    }
    /**
     * ⚠️ **A PROOF THAT REACHED NO VERDICT IS NOT A REFUSAL** — `unavailable` means the relay never
     * answered (no client wired, or unreachable), and NOT every relay gates reservations. Refusing
     * to ask because our own proof path was unavailable would lose the ability to reserve with an
     * ungated relay entirely. The boundary is enforced in `proveToRelay`, which returns
     * `unavailable` for exactly this (review HIGH-1 on unit 1).
     */
    if (verdict === "unavailable") {
      this.#ctx.logger.warn("session.standing_receiver.prove.no_verdict", {
        agentName,
        circuitAddr,
        correlationId,
        impact: "no proof verdict was obtained from this relay. Asking for the reservation anyway: " +
          "a relay that does not gate them grants it, and one that does refuses an ask that cost a " +
          "single dial.",
      });
    }

    let askFault: string | undefined;
    let error = "";
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timedOut = Symbol("listen_timeout");
    let outcome: "asked" | typeof timedOut = timedOut;
    try {
      /**
       * ⚠️ **AN ABANDONED ASK NOW LANDS ON A NODE THAT LIVES ON** — review MEDIUM-5, and it is the
       * mirror image of the hazard the old probe teardown existed for.
       *
       * When a probe timed out it was destroyed, so a grant arriving late died with it. There is
       * one long-lived node now: a late grant ADDS a circuit address after the walk has counted
       * what it holds, so the receiver would advertise a relay that is in neither `sr.relayPeerIds`
       * nor the gater's reserved set — the ledger and the advertised addresses disagreeing, which
       * is what the watchdog then churns on.
       *
       * So a late grant is GIVEN BACK rather than kept. Releasing costs a dial; keeping it costs a
       * disagreement no operator can see, and a slot on a relay we already decided against.
       */
      const askP = node.listenOnCircuit(circuitAddr).then(() => "asked" as const);
      void askP.catch(() => { /* the race below reports it; this only stops an unhandled rejection */ });
      outcome = await Promise.race([
        askP,
        new Promise<typeof timedOut>((resolve) => {
          timer = setTimeout(() => resolve(timedOut), this.#ctx.srReservationTimeoutMs);
        }),
      ]);
      if (outcome === timedOut) {
        void askP.then(
          () => {
            this.#ctx.logger.warn("session.standing_receiver.reservation.late_grant_released", {
              agentName,
              circuitAddr,
              correlationId,
              impact: "this relay answered after the walk had moved on, so its circuit was not " +
                "counted or advertised. Given back rather than held: a slot nobody knows about is " +
                "one the relay cannot reuse and this agent cannot rely on. ⚠️ This drops EVERY " +
                "circuit — libp2p's reservation store is shared across listeners and cannot " +
                "release one — so the receiver is rebuilt by the watchdog, which is the correct " +
                "outcome: a walk whose result is already wrong should be redone, not patched.",
            });
            return node.releaseAllCircuits().catch(() => false);
          },
          () => { /* it failed rather than arriving late; the rejection is already reported */ },
        );
      }
    } catch (err: unknown) {
      error = extractErrorMessage(err);
      // A fault of OURS keeps its own name rather than being re-derived from the relay connection,
      // which is intact and irrelevant when the ask never left this process (review HIGH-2).
      askFault = clientSideAskFault(err);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }

    // The only proof that counts: an ANNOUNCED circuit address on this relay. `listen()` resolving
    // is not enough — a relay at its slot cap completes the handshake and grants nothing.
    const relayPeerId = relayPeerIdOf(circuitAddr);
    if (outcome === "asked" && node.listenAddresses().some(
      (a) => a.split("/").includes("p2p-circuit") && (relayPeerId === null || a.includes(`/p2p/${relayPeerId}/`)),
    )) {
      return "granted";
    }

    /**
     * ⚠️ **THE CONNECTION CHECK APPLIES TO BOTH OUTCOMES** — review MEDIUM-6.
     *
     * "Asked" does not mean the relay answered: a relay that is down yields no circuit address,
     * indistinguishable here from one that answered and granted nothing. An open connection is what
     * separates them, and we have one to ask.
     *
     * The first version of this rewrite applied that check only to the `asked` branch, so a HUNG
     * ask short-circuited to `reservation_did_not_complete_in_time` — latency — when the relay was
     * simply gone. That is a name for where the failure surfaced, not for what went wrong, in a
     * unit whose headline is that behaviour does not change.
     */
    const connectedToRelay = node.getConnections().some((c) => c.peerId === relayPeerId);
    const reason = askFault !== undefined
      ? askFault
      : !connectedToRelay
        ? "relay_unreachable"
        : outcome === "asked"
          ? "relay_granted_no_reservation"
          : "reservation_did_not_complete_in_time";
    this.#ctx.srLastRejectionReason.set(agentName, reason);
    this.#ctx.logger.warn("session.standing_receiver.relay.rejected", {
      agentName,
      circuitAddr,
      reason,
      ...(error !== "" ? { error } : {}),
      correlationId,
    });
    return "declined";
  }
  /** One standing-receiver create attempt (extracted for the M8B F14 retry loop). */
  async #tryCreateStandingReceiver(
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
      ({ node, seed } = await this.#startReceiverNode(agentName, sessionId, gater, reservations.addrs, correlationId));
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
        const result = await this.#tryCreateStandingReceiver(agentName, correlationId);
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
       * ⚠️ DOD-M15-RELAYPROVE-ORDER-1 — **ONE ATTEMPT NOW, exactly as `#startReceiverNode` does
       * it.** This used to be two: ask, be refused, prove, ask again, justified by *"a reservation
       * taken by hand on the same connection as the proof yields no dialable address."* That
       * described taking the slot over a raw HOP stream; asking libp2p's own transport manager
       * after the proof makes the reservation libp2p's own, and it announces the address. Measured
       * live 2026-09-08. So the candidate comes up with no circuit address, proves, and asks once.
       *
       * The seed is fixed here — that is what a revival IS — so this node carries the identity the
       * relay records, and it must STAY UP between the proof and the ask: the relay marks the
       * CONNECTION proven, and stopping the node closes it.
       */
      let revivedNode: CelloNode | undefined;
      let terminalRefusal = false;
      {
      const candidate = await this.createAgentNode(agentName, {
        sessionId,
        connectionGater: gater,
        nodeType: "session",
        inboundReachable: true,
        transportPrivateKey: seed,
        // NO `circuitRelayListenAddrs` — libp2p must not ask before the proof below has landed.
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

      /**
       * PROVE, THEN ASK — the same order as `#startReceiverNode`, for the same reason.
       *
       * `started` gates it because `libp2p.stop()` opens with `if (this.status !== 'started')
       * return`, so a timed-out candidate cannot be torn down here; that case falls through to the
       * settlement-chained teardown below, which is the only thing that reliably kills a
       * still-starting node.
       *
       * ⚠️ THE CANDIDATE IS NOT STOPPED BETWEEN THE PROOF AND THE ASK. It used to be, because the
       * ask came from a rebuilt node. The relay marks the CONNECTION proven, so stopping here
       * would throw away the very thing that makes the next line succeed.
       */
      let proofDeclined = false;
      /**
       * The ask's own promise, when one was made. The teardown below has to wait on THIS as well as
       * on `start()`: the node whose reservation is still in flight is the one that can come up
       * late holding this session's peer id, and `stop()` on a node mid-ask is the same no-op the
       * start-promise note describes.
       */
      let listenP: Promise<void> | undefined;
      /** Set when the ask failed for a fault of OURS, so it is not re-described as the relay's. */
      let askFault: string | undefined;
      if (started) {
        const verdict = await this.#ctx.proveToRelay(agentName, circuitAddr, candidate, sessionId, false);
        // A VERDICT DECLINES; NO VERDICT DOES NOT. `unavailable` means the relay never answered —
        // no client wired, or unreachable — and not every relay gates reservations, so the ask
        // still goes ahead. Same rule and same reasoning as `#startReceiverNode`.
        if (verdict === "refused_this_agent" || verdict === "refused_try_another_relay") {
          proofDeclined = true;
          // The agent-level refusal is about this AGENT, so the remaining candidates answer
          // identically.
          if (verdict === "refused_this_agent") terminalRefusal = true;
          this.#ctx.logger.warn("session.revive.reservation.declined", {
            agentName,
            sessionId,
            circuitAddr,
            reason: verdict === "refused_this_agent" ? "relay_refused_this_agent" : "relay_proof_refused",
            impact:
              verdict === "refused_this_agent"
                ? "the relay refused this agent rather than being unwilling or unwell, so every " +
                  "other relay refuses it the same way. The session comes up reachable only via " +
                  "the relay park route; cello_status carries the cause."
                : "this relay would not take the agent's proof. Trying the next relay.",
          });
          try { await candidate.stop(); } catch { /* best-effort */ }
        } else {
          /**
           * ASK — once, on the connection the proof was made on.
           *
           * ⚠️ **RACED AGAINST THE SAME DEADLINE `start()` USED TO CARRY, AND IT HAS TO BE.** The
           * measured production failure this whole loop exists for — 10,002ms and still waiting —
           * was a relay that never answered a reservation. That used to park `start()`, because a
           * circuit address in the constructor made start the moment libp2p asked. The ask is here
           * now, so a bare await here is the same hang with a new address: the revival never
           * returns and every send on that session is refused forever.
           *
           * A throw is not fatal — the grant check below is the only thing that decides, and it
           * reads the announced addresses.
           */
          // Wrapped, not bare: a node that cannot take the ask at all throws SYNCHRONOUSLY, and
          // `.catch()` on the race never sees that — it would escape the revival entirely.
          const asked = await (async () => {
            listenP = candidate.listenOnCircuit(circuitAddr);
            return Promise.race([
              listenP.then(() => true as const),
              new Promise<false>((res) => setTimeout(() => res(false), REVIVE_RESERVATION_TIMEOUT_MS).unref?.()),
            ]);
          })().catch((err: unknown) => {
            startError = err;
            // Review HIGH-2, same rule as the receiver walk: a fault of OURS keeps its own name.
            askFault = clientSideAskFault(err);
            return false as const;
          });
          if (!asked && askFault === undefined) {
            this.#ctx.logger.warn("session.revive.reservation.ask_timeout", {
              agentName,
              sessionId,
              circuitAddr,
              budgetMs: REVIVE_RESERVATION_TIMEOUT_MS,
              impact: "this relay took the proof and then never answered the reservation. Abandoned " +
                "on the deadline and trying the next relay — a relay that does not answer must not " +
                "be able to hold a session down.",
            });
          }
        }
      }

      if (!proofDeclined && started && holdsCircuit(candidate)) {
        this.#ctx.logger.info("session.revive.reservation.granted", { agentName, sessionId });
        revivedNode = candidate;
        break;
      }
      if (!proofDeclined) {
      // Started but granted nothing, or never started. Either way this node is not the one.
      //
      // Review MEDIUM-5: name WHICH of the three causes this was, the way `#startReceiverNode` does.
      // "declined" alone stood for a relay that is full, a relay that is unreachable, and a relay
      // that is merely slow — three different problems with three different responses, and the
      // thrown error was discarded entirely.
      const declineReason = askFault !== undefined
        // A client-side fault, checked FIRST: everything below infers a cause from the relay, and
        // the relay had nothing to do with an ask that never left this process (review HIGH-2).
        ? askFault
        : !started
        ? startError !== undefined
          ? "relay_unreachable"
          : "reservation_did_not_complete_in_time"
        : // Started, proved, asked — and the ask is where a slow relay now shows up. An ask still in
          // flight is "did not complete in time"; one that returned with nothing is a relay that
          // answered and granted nothing.
          listenP !== undefined && !holdsCircuit(candidate)
          ? "relay_granted_no_reservation"
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
      /**
       * Teardown at SETTLEMENT, not now: a `stop()` issued while the node is still starting is a
       * no-op (see above), so the only way to guarantee this node dies is to wait for its own work
       * to finish first. Not awaited, so a hung relay cannot hold the revival up — the point is that
       * the teardown eventually happens, not that it happens before the next candidate.
       *
       * ⚠️ **BOTH PROMISES, and the second one is new.** The abandoned candidate's outstanding work
       * used to be `start()`, because that is where the reservation was taken. It is the ASK now, so
       * waiting only on `start()` tears the node down while its reservation is still in flight —
       * and a late grant then brings a node up on THIS SESSION'S peer id, sharing the gater, with no
       * content handler and nothing holding a reference to kill it. That is the open endpoint
       * review HIGH-3 exists to prevent, reintroduced through a different promise.
       */
      stopWhenSettled(candidate, [startP, listenP], REVIVE_RESERVATION_TIMEOUT_MS * 2);
      }
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
        reason: extractErrorMessage(err),
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
    // content-park deposit/pull to the relay — not session-scoped, and OUTBOUND, which is the
    // half of the gater that is open; inbound admits nobody until a dialer is named).
    if (agentName !== undefined) return this.#ctx.standingReceivers.get(agentName)?.node ?? null;
    return this.#anyStandingReceiver()?.node ?? null;
  }
  /**
   * First ready standing receiver (any agent) — for agent-agnostic OUTBOUND use. Its gater admits
   * nobody INBOUND until a session names them (DOD-M15-ASSIGN-1); outbound stays open, which is the
   * property these callers depend on.
   */
  #anyStandingReceiver(): { node: CelloNode; gater: SessionConnectionGater; autoNat: NodeAutoNatService } | null {
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
    return this.#anyStandingReceiver()?.autoNat ?? null;
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
    this.#offeredDialer.set(this.#ctx.sessionKey(agentName, sessionIdHex), initiatorSessionPeerId);
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
    return this.#offeredDialer.get(this.#ctx.sessionKey(agentName, sessionIdHex)) ?? null;
  }
  /** Forget the offered dialer for ONE session — called on BOTH the claim and the refusal paths. */
  clearOfferedDialer(agentName: string, sessionIdHex: string): void {
    this.#offeredDialer.delete(this.#ctx.sessionKey(agentName, sessionIdHex));
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
