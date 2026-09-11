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
  OFFER_RESERVATION_GRACE_MS,
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
  /**
   * 055-ONDEMAND — has the session this offer was for actually started? Read when the abandoned-offer
   * timer fires, so a slot taken for an offer that went nowhere is given back.
   */
  sessionIsLive(agentName: string, sessionIdHex: string): boolean;
  /** 055-ONDEMAND — does any of this agent's live sessions hold a circuit right now? */
  anyLiveSessionHoldsCircuit(agentName: string): boolean;
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
  /**
   * 055-ONDEMAND — the abandoned-offer timers, keyed `agent::sessionIdHex`. See `#armOfferRelease`.
   */
  readonly #offerReleaseTimers = new Map<string, ReturnType<typeof setTimeout>>();

  /**
   * ⚠️ **AN OFFER THAT GOES QUIET MUST NOT KEEP A SLOT — `DOD-M15-OFFER-EXPIRY-1`, RELOCATED.**
   *
   * The story predicted this exactly: the permanently-open door units 2 and 3 removed does not take
   * the defect with it, it moves it somewhere more expensive. The responder reserves the moment an
   * offer arrives; an initiator that never dials — it aborted, the directory faulted — would leave a
   * slot held on a SHARED relay until its TTL, two hours by default. That is a cost on the exact
   * resource this whole story exists to conserve, and "released at seal" cannot cover it because
   * there is no seal.
   *
   * ⚠️ **THE BUDGET IS NOT THE DIRECTORY'S 2-SECOND ACCEPT CLOCK, and picking that would be worse
   * than not doing this at all.** The accept is only the start: the assignment still has to be
   * FROST-signed by a threshold of directory nodes and delivered to both parties before either
   * builds a session. Releasing on 2 s would take the slot out from under a session that was about
   * to begin — turning a rare abandoned offer into a common broken one.
   *
   * No cancellation plumbing: the timer ASKS whether the session started. A session that began and
   * has already sealed is also not live, and that case has already released through the seal path,
   * where the teardown releases from the session's own node.
   */
  #armOfferRelease(agentName: string, sessionIdHex: string, circuitAddr: string, correlationId: string): void {
    const key = `${agentName}::${sessionIdHex}`;
    const existing = this.#offerReleaseTimers.get(key);
    if (existing !== undefined) clearTimeout(existing);
    const timer = setTimeout(() => {
      this.#offerReleaseTimers.delete(key);
      if (this.#ctx.shuttingDown()) return;
      if (this.#ctx.sessionIsLive(agentName, sessionIdHex)) return; // it started; the seal owns it now
      this.#ctx.logger.warn("session.reservation.offer_abandoned", {
        agentName,
        sessionIdHex,
        circuitAddr,
        heldForMs: OFFER_RESERVATION_GRACE_MS,
        correlationId,
        impact: "a relay slot was taken to answer an offer that never became a session — the " +
          "initiator did not dial. Given back rather than held until the relay's TTL, which is " +
          "two hours and is a cost on every other agent that relay serves.",
      });
      /**
       * ⚠️ THE RECEIVER'S OWN NODE, and at this point that is the right one: the offer never became a
       * session, so nothing was promoted and the circuit is still on the standing receiver. (Had it
       * been promoted, `sessionIsLive` above would have returned and we would not be here.)
       */
      const sr = this.#ctx.standingReceivers.get(agentName);
      if (sr) {
        void this.releaseSessionReservation(agentName, sr.node, sessionIdHex, correlationId)
          .catch(() => { /* best-effort; the log above is the durable record */ });
      }
    }, OFFER_RESERVATION_GRACE_MS);
    timer.unref?.();
    this.#offerReleaseTimers.set(key, timer);
  }


  /**
   * 055-ONDEMAND — re-take a circuit on a node that already exists, for a live session that lost it.
   *
   * ⚠️ **IT PROVES OVER THE DELIVERY PATH TOO.** `DOD-M15-RELAYAUTH-1` applies identically here: a
   * holder that has not proven key possession has its reservation revoked inside the relay's grace
   * window, about fifteen seconds. The first version of the re-take called the low-level ask
   * directly and skipped it, so a re-taken circuit would have been revoked almost immediately while
   * the log said "granted" — the same defect this unit already fixed one function up.
   */
  async retakeReservationOn(agentName: string, node: CelloNode, circuitAddr: string, correlationId: string): Promise<boolean> {
    const relayPeerId = relayPeerIdOf(circuitAddr);
    const outcome = await this.#takeReservation(agentName, node, circuitAddr, correlationId);
    if (outcome !== "granted") return false;
    /**
     * ⚠️ **THE OTHER HALF OF `reservation_lost` — 056-SLOTDEAD, review F4.**
     *
     * The loss trigger fires the moment a reservation goes, which is exactly when the relay link is
     * down, so the pull it starts is aimed at a relay that cannot answer. Without something on the
     * recovery, content the counterparty parked during the outage waits for the slow periodic
     * backstop while the relay is healthy and this agent is connected to it again.
     *
     * **This path, and not the two that look like it.** The watchdog's `gained` branch was the
     * first attempt and never fired — a take records the new circuit on the receiver itself, so by
     * the next tick there is nothing left for the watchdog to see as gained; a test caught it, which
     * is the only reason it is not still in the tree looking correct. `takeReservationForSession`
     * was the second, and it double-drains: on a first login it fires moments after the install
     * drain, for the same empty mailbox.
     *
     * A re-take is unambiguous. It happens only when a session that HAD a circuit lost it, which is
     * exactly the outage whose recovery this is.
     */
    this.#ctx.park.fireParkedDrain(agentName, "reservation_regained");
    if (relayPeerId) {
      void this.#ctx.authenticateStandingReceiver(agentName, node, relayPeerId, circuitAddr, correlationId)
        .catch((err: unknown) => {
          this.#ctx.logger.warn("session.standing_receiver.relay_auth.failed", {
            agentName, relayPeerId, correlationId,
            error: extractErrorMessage(err),
            impact: "a live session re-took a circuit but did not prove key possession over the " +
              "delivery path, so the relay may revoke it inside its grace window.",
          });
        });
    }
    return true;
  }

  async takeReservationForSession(
    agentName: string,
    circuitAddr: string,
    correlationId: string,
    /**
     * ⚠️ **PRESENT ONLY ON THE OFFER PATH, AND THAT IS WHAT ARMS THE ABANDONED-OFFER RELEASE.**
     *
     * The first version reused `correlationId` for this, because the offer handler happens to pass
     * the session id as its correlation id. Two meanings in one parameter is how a value ends up
     * being trusted for something it was never chosen for: the watchdog's re-take passes a genuine
     * correlation id, and it would have armed a timer keyed on a string that is not a session.
     *
     * Absent for the re-take path, which is by definition for a session that is already live.
     */
    offerSessionIdHex?: string,
  ): Promise<boolean> {
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
    const heldNow = heldRelayIdsOf(sr.node);
    this.#ctx.standingReceivers.set(agentName, { ...sr, relayPeerIds: heldNow });
    /**
     * ⚠️ **A RELAY THAT GRANTED MUST BE ADMITTED INBOUND, OR THE RESERVATION BUYS NOTHING.**
     *
     * The gater's inbound carve-out is the security-sensitive half of a reservation: only relays
     * whose own grant is confirmed earn it, so a directory that merely NAMES a relay cannot dial us
     * through it. That set was built once from what the login walk held — empty now — so an
     * on-demand reservation would have been taken, announced, and then refused by OUR OWN gater
     * when the counterparty dialled through it.
     *
     * Recomputed from what the node HOLDS, never from what was asked: being named by the directory
     * must not buy a foothold, and under on-demand the directory is what names the relay.
     */
    sr.gater.setReservedRelayPeers(heldNow);

    /**
     * ⚠️ **DOD-M15-RELAYAUTH-1 STILL APPLIES, AND IT NO LONGER FIRES ON ITS OWN.**
     *
     * That auth is a SECOND proof, over the DELIVERY path, and it is what keeps the relay from
     * revoking a reservation whose holder has not proven key possession to it — the grace window is
     * about fifteen seconds. It used to run in the receiver build, over the circuits the login walk
     * had just collected. Nothing is collected there any more, so without this line an on-demand
     * reservation would be taken and then quietly revoked mid-session, and the agent would go
     * unreachable while every log said the reservation was granted.
     *
     * Best-effort and unawaited, exactly as it is in the build path: a failure here costs the
     * relay's own grace-window revoke, which the watchdog already treats as an ordinary loss.
     */
    if (outcome === "granted" && offerSessionIdHex !== undefined) {
      this.#armOfferRelease(agentName, offerSessionIdHex, circuitAddr, correlationId);
    }
    if (outcome === "granted" && relayPeerId) {
      void this.#ctx.authenticateStandingReceiver(agentName, sr.node, relayPeerId, circuitAddr, correlationId)
        .catch((err: unknown) => {
          this.#ctx.logger.warn("session.standing_receiver.relay_auth.failed", {
            agentName, relayPeerId, correlationId,
            error: extractErrorMessage(err),
            impact: "this agent has a reservation the relay may revoke within its grace window, " +
              "because key possession was not proven over the delivery path.",
          });
        });
    }
    return outcome === "granted";
  }

  /**
   * 055-ONDEMAND — **GIVE THIS SESSION'S SLOT BACK, FROM THE NODE THAT ACTUALLY HOLDS IT.**
   *
   * ⚠️ **THE FIRST VERSION LOOKED THE NODE UP BY AGENT NAME AND ALWAYS FOUND THE WRONG ONE.** When a
   * session opens, the standing receiver is PROMOTED: `session-lifecycle` deletes it from
   * `standingReceivers`, moves that exact node into `activeNodes`, and builds a fresh empty receiver
   * behind it. So by seal time `standingReceivers.get(agentName)` is the new idle node, holding
   * nothing — the release read `[]`, returned immediately, and told the relay nothing. The slot the
   * offer took lived on the promoted node and died with it, invisible to the relay, held for the
   * full TTL. **A release that always no-ops is worse than none: it logs success.**
   *
   * ⚠️ **AND THE CROSS-SESSION RECOMPUTE THE ORDER ASKED FOR IS UNNECESSARY, which is the good news
   * in the correction.** libp2p's shared `reservationStore` is shared *within one node*. Each live
   * session owns its OWN node, so sealing one cannot clear another session's refresh timers. There
   * is nothing to recompute: this node is being torn down anyway, so tell its relays and drop its
   * circuits. Re-deriving that removed a whole class of drift rather than managing it.
   */
  async releaseSessionReservation(
    agentName: string,
    node: CelloNode,
    sessionId: string,
    correlationId: string,
  ): Promise<void> {
    const held = heldRelayIdsOf(node);
    if (held.length === 0) return;
    for (const relayPeerId of held) {
      /**
       * ⚠️ BOUNDED, BECAUSE THIS RUNS INSIDE A TEARDOWN. Telling a relay means dialling it, and an
       * unreachable one would otherwise hold the seal open for as long as its dial takes. Measured
       * the hard way: unbounded, this hung fourteen unrelated suites at 237s each. A seal waiting on
       * a courtesy is worse than a slot held until its TTL.
       */
      await Promise.race([
        this.#ctx.tellRelayReleased(agentName, relayPeerId, node, correlationId),
        new Promise<void>((r) => setTimeout(r, RELEASE_TELL_BUDGET_MS).unref?.()),
      ]);
    }
    // Local half. The node is going away regardless; this stops it announcing a route it no longer
    // holds for whatever is left of its life.
    try {
      await node.releaseAllCircuits();
    } catch (err: unknown) {
      this.#ctx.logger.debug("session.reservation.release.local_failed", {
        agentName, sessionId, correlationId, error: extractErrorMessage(err),
        // The node is being torn down either way, so this costs nothing beyond a few more seconds
        // of announcing a route that is already gone at the relay. Deliberately NOT claiming the
        // watchdog repairs it (review MEDIUM-11): this unit removed the rebuild that used to.
        impact: "the session's node keeps announcing a circuit it has released, until it stops.",
      });
    }
    this.#ctx.logger.info("session.reservation.released", {
      agentName,
      sessionId,
      releasedRelays: held,
      correlationId,
      impact: "the slot this session borrowed is back in the relay's table, rather than held until " +
        "its two-hour TTL.",
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
     * ⚠️ **A RECEIVER IS INSTALLED HOLDING NOTHING, AND THAT IS NOW A CONSTANT — 056-SLOTDEAD.**
     *
     * This block used to derive what the node had come up holding: `heldRelayIdsOf(node)`, the
     * matching circuit addresses, the count for the reachability line, and the gater's inbound
     * carve-out. Every one of those read the result of the login walk. `#startReceiverNode` returns
     * a TCP-only node now (055-ONDEMAND), so all four were computing `[]` — reachable, referenced,
     * and unable to produce a different answer on any input.
     *
     * The distinction the deleted comment was defending — a CANDIDATE is a relay we asked, a HELD
     * address is one that answered — is still the rule, and it still lives in `heldRelayIdsOf`. It
     * is enforced where a reservation is actually taken (`takeReservationForSession`) and where one
     * is checked (the watchdog), which is where it belongs. Nothing is held here to check.
     *
     * The gater is left as constructed: its reserved set starts empty, and `takeReservationForSession`
     * widens it for the one relay that grants. Setting it to `[]` here only restated that.
     */
    this.#ctx.standingReceivers.set(agentName, {
      node,
      gater,
      autoNat,
      seed,
      relayPeerIds: [],
    });
    this.#ctx.logger.info("session.node.created", {
      sessionId,
      agentName: `${STANDING_RECEIVER_AGENT_NAME}:${agentName}`,
      sessionPeerId: node.getPeerId(),
      correlationId,
    });

    /**
     * ⚠️ **DOD-M15-RELAYAUTH-1'S INSTALL-TIME PROOF IS GONE — 056-SLOTDEAD, and it could not have
     * run since 055-ONDEMAND.**
     *
     * It read: *"authenticate to the reservation relay NOW, not when a session first needs one"* —
     * because the relay revokes a reservation whose holder has not proven key possession to it, and
     * a login-time slot had to survive that grace window with no session in sight. It looped over
     * the relays this receiver held. It holds none, so the loop's body never executed.
     *
     * **The requirement it served is not gone; it moved, and it moved to the stronger place.** A
     * reservation is now taken by `takeReservationForSession`, which proves FIRST and asks second on
     * the same connection (`DOD-M15-RELAYPROVE-ORDER-1`). "Proven before the slot exists" is
     * structural there, rather than a second best-effort call racing a grace window.
     */

    /**
     * DOD-NAT-REACHABILITY-1 observability: what did this receiver come up able to use?
     *
     * ⚠️ **`reservationsHeld` WAS DROPPED, NOT RENAMED — 056-SLOTDEAD.** It carried
     * `heldRelayIdsOf(node).length` and was the one number in this line an operator would act on.
     * Since 055-ONDEMAND a receiver is installed holding nothing by design, so it reported `0` on
     * every healthy login for every agent — a measurement that had become a constant while still
     * reading as a measurement. That is worse than not reporting it: the number an operator trusts
     * to mean "this agent is deaf" now means nothing at all.
     *
     * `relaysOffered` stays and is still a real count: how many relays are in the candidate list
     * (deduped by relay peer id in `reservationCircuitAddrs`, so it counts relays, not addresses).
     * **Zero of them is the condition worth seeing here** — an agent with no candidate cannot take a
     * slot when an offer arrives, and will refuse the call.
     *
     * What an agent actually holds is reported where it is now decided: `session.offer.reservation`
     * at the moment a slot is asked for, and `getStandingReceiverReachability` for `cello_status`.
     */
    this.#ctx.logger.info("session.standing_receiver.reachability", {
      agentName,
      relaysOffered: reservations.addrs.length,
      correlationId,
    });
    /**
     * ⚠️ **`reservation.none` IS NOT EMITTED AT BUILD ANY MORE — 055-ONDEMAND.**
     *
     * It means *"this agent is offered relays and holds none, so nobody behind NAT can dial it"* —
     * a warn that fired 481 times over 17 days and drove a whole retry story. Under on-demand,
     * holding none at build is the DESIGN: a slot is taken when an offer arrives and given back at
     * the seal. Leaving the warn here would fire it on every healthy login for every agent, which
     * is not a smaller version of the old problem but a worse one — an alarm that is wrong every
     * time trains its reader to ignore the one time it is right.
     *
     * The condition it named still has a home. `session.offer.reservation` reports `granted: false`
     * when an offer could not get a circuit — the moment it actually costs someone something — and
     * the watchdog's re-take path reports a live session that lost one.
     *
     * ⚠️ **AND ITS DEBUG-LEVEL REPLACEMENT WENT TOO — 056-SLOTDEAD, review F10.** A
     * `session.standing_receiver.idle_no_reservation` line survived here, guarded on
     * `reservations.addrs.length > 0 && circuitAddrs === 0`. The second term was always true once
     * the login walk was deleted, so the guard was really just "this agent has candidates" and the
     * line fired on every healthy install for every agent — a second event, under a name that reads
     * as a fault, asserting the same by-design state the `idle` line above already reports with its
     * `relaysAvailable` count. Two lines per install saying "normal" is how a log stops being read.
     */

    // DOD-PARK-DRAIN-1: this agent has a receiver again — drain whatever parked while it did not.
    // The defect this closes was a trigger hooked to the wrong connection: content parks when the
    // RELAY link dies, and the drain was waiting on DIRECTORY SIGNALING to reconnect — which it
    // never had to, having never dropped.
    //
    // 056-SLOTDEAD: this used to be the ONE place every path converged on, because a lost
    // reservation rebuilt the receiver and arrived back here. The rebuilds are gone, so this now
    // covers the INSTALL only, and the loss has its own trigger (`reservation_lost`) at the point
    // the loss is noticed.
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
    /**
     * ⚠️ **A LIVE SESSION'S CIRCUIT COUNTS — 055-ONDEMAND, and without this the field measures the
     * wrong node.**
     *
     * The standing receiver holds nothing while idle, by design. A session's circuit lives on the
     * SESSION's node: the receiver was promoted into it and replaced. Reading only the receiver
     * therefore reported `retrying` for an agent in a perfectly healthy conversation — a fault where
     * there is none, on the surface an operator checks first.
     */
    if (this.#ctx.anyLiveSessionHoldsCircuit(agentName)) return "reserved";
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
