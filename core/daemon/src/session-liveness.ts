/**
 * CELLO Daemon — IS THIS SESSION STILL ALIVE, AND IF NOT, WHY
 *
 * Split out of `session-node-manager.ts` by 037-SESSIONCORE. The connection-level liveness of a
 * session, and the IMPAIRMENT that explains a degraded one — which matters more than it sounds,
 * because "impaired, and here is the cause" is what an operator gets instead of silence when a
 * session is half-working.
 *
 * Moved verbatim, comments included.
 */
import type { Logger } from "./types.js";
import type { CelloNode } from "@cello-protocol/transport";
import { extractErrorMessage } from "./error-message.js";
import { REFUSAL_KINDS } from "./refusal-reasons.js";
import type { ActiveSessionEntry, SessionImpairment } from "./session-node-types.js";
import type { SessionQueries } from "./session-queries.js";
import type { RefusalNotices } from "./refusal-notices.js";
import type { SessionEphemerals } from "./session-ephemerals.js";
import type { SaltAgreementFrame } from "./session-salt-agreement.js";

/** What liveness needs from the manager. */
export interface SessionLivenessContext {
  readonly logger: Logger;
  readonly queries: SessionQueries;
  readonly notices: RefusalNotices;
  readonly ephemerals: SessionEphemerals;
  readonly counterpartyAddrs: Map<string, string[]>;
  sessionKey(agentName: string, sessionId: string): string;
  activeEntry(key: string): ActiveSessionEntry | undefined;
  sendSaltFrame(agentName: string, sessionId: string, correlationId?: string, override?: SaltAgreementFrame): Promise<void>;
}

export class SessionLiveness {
  readonly #ctx: SessionLivenessContext;

  constructor(ctx: SessionLivenessContext) {
    this.#ctx = ctx;
  }

  #sessionLiveness = new Map<string, "alive" | "impaired" | "gone">();
  #impairmentCause = new Map<string, SessionImpairment>();
  /**
   * M7-SESSION-003 AC-004: wire a session node's peer-connect / peer-disconnect
   * events to per-session direct-path liveness. onPeerConnect → 'alive',
   * onPeerDisconnect → 'gone', emitting session.liveness.changed at WARN. Combined
   * with the transport keepalive (AC-005), a peer that vanished without a clean
   * close still surfaces a disconnect and drives 'gone'.
   *
   * THE EVENT MUST BE FILTERED BY PEER (DOD-RELAY-KEEPALIVE-1 review, F2). The
   * original wiring acted on EVERY peer event this node saw, justified by "the
   * session node's gater restricts connections to the designated counterparty".
   * That stopped being true: the session node also dials the RELAY as its
   * Structure-2 witness (#connectSessionRelay), and the gater allows those peers
   * outbound. So a relay link dropping declared the counterparty dead — at WARN,
   * feeding the unilateral-seal gate — while the counterparty was sitting there
   * perfectly alive. During the 2026-08-04 incident, when the relay link churned
   * every 60-90 seconds, that fired continuously.
   *
   * `counterpartySessionPeerId` is the authority when known. When it is not (the
   * peer id can be absent on a session whose assignment has not landed yet),
   * every peer is honoured EXCEPT ones known to be relays for this session —
   * degrading to the old over-eager behaviour minus its one known false positive,
   * rather than to silence, because a liveness detector that never fires is worse
   * than one that fires too often.
   */
  wireSessionLiveness(
    agentName: string,
    sessionId: string,
    node: CelloNode,
    counterpartyPubkey: string,
    correlationId: string,
    counterpartySessionPeerId?: string,
  ): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    const isCounterparty = (peerId: string): boolean => {
      if (counterpartySessionPeerId) return peerId === counterpartySessionPeerId;
      const entry = this.#ctx.activeEntry(key);
      return entry?.relayPeerId !== peerId;
    };
    /**
     * Named rather than inline so the already-attached sweep below can invoke **this exact function**
     * instead of a second copy of it. A copy is what would drift: the two would have to be kept in
     * step by whoever edits either, and the failure would be silent.
     */
    const onCounterpartyAttached = (peerId: string): void => {
      /**
       * DOD-M12B-RESPONDER-ADDR-1 (review MEDIUM-4) — LEARN THE ADDRESS HERE, where it cannot race.
       *
       * The accept-time read was a race between two independent async chains: the responder accepts
       * off a signaling frame, while the initiator dials only after its own `createSessionNode`. If
       * accept looked before the dial landed it saw nothing, and the responder was back to holding
       * no address — the state that made every reply after an interruption park forever.
       *
       * This fires exactly when the counterparty connects: on both sides, on the first connection,
       * on every reconnect, and on a revived node too. It also REFRESHES, which the accept-time read
       * never did — a counterparty that rebuilds its receiver would otherwise leave us dialling a
       * dead address for the life of the session.
       */
      const observed = node
        .getConnections()
        .filter((c) => c.peerId === peerId && typeof c.remoteAddr === "string")
        .map((c) => c.remoteAddr as string);
      if (observed.length > 0) {
        this.#ctx.counterpartyAddrs.set(key, [...new Set(observed)]);
      }
      const prior = this.#sessionLiveness.get(key);
      this.#sessionLiveness.set(key, "alive");
      if (prior !== "alive") {
        this.#ctx.logger.info("session.liveness.changed", {
          sessionId,
          counterpartyPubkey,
          transportPath: "direct",
          liveness: "alive",
          observedBy: "session_node",
          correlationId,
        });
      }
      /**
       * DOD-M15-SEALWIRE-1 bullet 6 (part A) — ANNOUNCE OUR SALT STATE, here and nowhere else.
       *
       * This is the only hook that fires on BOTH sides for every way a session's direct path comes
       * up: the initiator's first dial, the responder's inbound connection, every reconnect, and a
       * revived node. `newStream` never dials — it only finds an already-open connection — so a
       * send placed at `createSessionNode` would be an announcement to a peer that is not attached
       * yet, and the responder's half has no dial of its own to hang one on at all.
       *
       * Fire-and-forget: a failed announcement must not turn a peer-connect handler into a rejected
       * promise, and there is nothing to await it. We re-announce on the next connect, and
       * `#handleSaltFrame` answers a peer contribution on a connection that is provably up — so a
       * single lost frame does not strand the agreement.
       */
      void this.#ctx.sendSaltFrame(agentName, sessionId, correlationId);
      // 007-CRYPTO: the signed ephemeral rides the SAME moment as the salt half — one connect, one
      // round trip, the same peer-to-peer content stream. Fire-and-forget for the same reason: a
      // failed announcement must not reject a peer-connect handler, and the next connect re-announces.
      void this.#ctx.ephemerals.sendEphemeralFrame(agentName, sessionId, correlationId);
    };
    node.onPeerConnect(onCounterpartyAttached);

    /**
     * ⚠️ THE CONNECT THAT ALREADY HAPPENED — `DOD-M15-SALTANNOUNCE-LATE-1`.
     *
     * `onPeerConnect` above is `addEventListener("peer:connect", …)` (`core/transport/src/node.ts`),
     * and **an event listener cannot fire for a connection that predates it.** On the
     * `reuseStandingReceiver` path this session does not build a node — it TAKES the standing
     * receiver's, which has been listening all along. So the ordinary sequence is:
     *
     *   1. `#tryCreateStandingReceiver` starts the node listening. It never calls this method, so
     *      there is no handler yet.
     *   2. The counterparty connects. `peer:connect` fires into nothing.
     *   3. The session promotes that same node and registers the handler — one step too late.
     *
     * The handler then never runs, and everything hanging off it is silently skipped: **the salt is
     * never announced** (`no_agreement_started`, the sender salts, the receiver holds none, and every
     * message between them is refused) **and the counterparty's address is never learned or
     * refreshed.** Measured live: `j-documents` 7 of 12 red, every failure a document update that
     * never arrived, with no error shown to either operator.
     *
     * ⚠️ THE COMMENT ON THE HANDLER ABOVE NAMES THE OPPOSITE HAZARD, AND IT IS ALSO RIGHT: *"a send
     * placed at `createSessionNode` would be an announcement to a peer that is not attached yet."*
     * Both are real, which is why this is a SWEEP AFTER REGISTERING rather than a move. Too-early
     * stays impossible — the sweep runs at the same point the handler is armed — and too-late stops
     * being invisible, because an already-open connection is now looked at instead of waited for.
     *
     * Idempotent by construction: it invokes the SAME handler the event would have, so a peer that
     * connects normally is unaffected, and a peer seen twice re-announces — which the announce path
     * already tolerates (*"we re-announce on every reconnect"*).
     */
    try {
      // `getConnections()` returns CONNECTIONS, and one peer can hold several — dedupe, or a peer
      // with two open connections would run the attach path twice for no reason.
      const attachedPeers = new Set(node.getConnections().map((c) => c.peerId));
      for (const peerId of attachedPeers) {
        if (!isCounterparty(peerId)) continue;
        this.#ctx.logger.info("session.liveness.peer_already_attached", {
          agentName, sessionId, peerId, correlationId,
          impact: "this counterparty connected BEFORE the session's liveness handler was registered — on the standing-receiver promotion path that is the ordinary case, not a rare one. Running the attach path for it now: without this the salt is never announced (every message from the peer is then refused) and the counterparty's address is never learned.",
        });
        onCounterpartyAttached(peerId);
      }
    } catch (err: unknown) {
      // Never let the sweep cost the caller its session: the handler is already armed, so a failure
      // here degrades to exactly the behaviour that shipped before this fix.
      this.#ctx.logger.warn("session.liveness.attached_sweep.failed", {
        agentName, sessionId, correlationId, error: extractErrorMessage(err),
        impact: "could not check for an already-attached counterparty. If one is attached, this session may never announce its salt and will refuse that peer's messages — the pre-fix behaviour.",
      });
    }

    node.onPeerDisconnect((peerId: string) => {
      if (!isCounterparty(peerId)) {
        // Not silence: a relay link dropping is a real event, it is simply not a
        // statement about the counterparty. It has its own signal
        // (session.standing_receiver.reservation.lost / session.relay.reader.ended).
        this.#ctx.logger.debug("session.liveness.unrelated_peer_disconnect", {
          sessionId,
          peerId,
          correlationId,
        });
        return;
      }
      const prior = this.#sessionLiveness.get(key);
      this.#sessionLiveness.set(key, "gone");
      if (prior !== "gone") {
        this.#ctx.logger.warn("session.liveness.changed", {
          sessionId,
          counterpartyPubkey,
          transportPath: "direct",
          liveness: "gone",
          observedBy: "session_node",
          correlationId,
        });
      }
    });
  }
  /**
   * M7-SESSION-003: read the direct-path counterparty liveness for a session.
   * 'unknown' when no session node observation has occurred yet.
   *
   * DOD-M12B-ACK-1: 'impaired' is DAEMON-LOCAL and deliberately not on the relay's
   * SessionLiveness wire type — the relay answers a different question (does it hold the
   * recipient's standing connection) and its three states are a deployed bilateral contract.
   */
  getSessionLiveness(agentName: string, sessionId: string): "alive" | "impaired" | "gone" | "unknown" {
    return this.#sessionLiveness.get(this.#ctx.sessionKey(agentName, sessionId)) ?? "unknown";
  }
  /**
   * DOD-M12B-ACK-1 — the connection is up and delivery on it is not working.
   *
   * Liveness is otherwise driven ONLY by libp2p peer-connect/peer-disconnect, so it answers "is
   * there a connection object?" while every surface that prints it is read as "can I talk to them?".
   * Measured 2026-08-17: one session reported `alive` for 70 minutes after every write had started
   * failing, another never stopped.
   *
   * ONLY 'gone' is protected, and 'gone' is NOT protected because a seal gate reads it — nothing in
   * the code does. It is protected because the receive surface turns 'gone' into "call
   * cello_close_session", and a failed write must never be able to produce that instruction.
   *
   * 'unknown' is DOWNGRADED just like 'alive', which is not obvious and is the point. A session
   * whose recorded `counterpartySessionPeerId` has gone stale never sees a matching peer-connect,
   * so it sits at 'unknown' while every send fails forever — the exact case documented at
   * #wireSessionLiveness — and the receive surface renders 'unknown' as healthy-and-quiet, which is
   * the 70-minute lie relocated one lane over. 'unknown' claims nothing; the surface built on it does.
   */
  markSessionImpaired(
    agentName: string,
    sessionId: string,
    opts: { cause: "direct_send" | "delivery_ack" | "content_key"; error: string; correlationId?: string },
  ): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    const prior = this.#sessionLiveness.get(key);
    if (prior === "gone") {
      // Declining is a decision, so it is logged. A silent early return here is the shape that let
      // the original defect hide for a day: nothing recorded that writes were failing on a session
      // every surface was still calling healthy.
      this.#ctx.logger.debug("session.liveness.impairment.declined", {
        sessionId, liveness: prior, cause: opts.cause, error: opts.error, correlationId: opts.correlationId,
      });
      return;
    }
    // The CAUSE is refreshed even when the state does not move, because the receive surface builds
    // its guidance from it and a stale cause would describe the wrong failure.
    this.#impairmentCause.set(key, { cause: opts.cause, retained: "unknown" });
    if (prior === "impaired") return;
    this.#sessionLiveness.set(key, "impaired");
    this.#ctx.logger.warn("session.liveness.changed", {
      sessionId,
      counterpartyPubkey: this.#ctx.queries.getSessionRecord(agentName, sessionId)?.counterparty_pubkey,
      transportPath: "direct",
      liveness: "impaired",
      observedBy: opts.cause,
      priorLiveness: prior ?? "unknown",
      // `reason` is a contract string and `error` is the message — the convention every other
      // failure log in this file follows. Collapsing them makes grouping by `reason` useless.
      reason: "write_failed",
      error: opts.error,
      correlationId: opts.correlationId,
    });
  }
  /**
   * DOD-M12B-ACK-1 — what became of the content whose send caused the impairment.
   *
   * The receive surface has no memory of the last send, so without this it can only guess — and the
   * guess it would make ("it was parked, do not resend") is FALSE in the two cases that matter
   * most: a refused park whose durable enqueue was dropped, and one that threw. In both the message
   * is gone and `cello_send` has already told the caller to send it again, so a receive that says
   * "do not resend" contradicts it later, while the agent is sitting there waiting.
   */
  noteImpairmentRetention(agentName: string, sessionId: string, retained: "parked" | "durable" | "lost"): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    const current = this.#impairmentCause.get(key);
    if (!current) return;
    this.#impairmentCause.set(key, { cause: current.cause, retained });
    /**
     * ─── DOD-M15-NO-SILENT-REFUSAL-1: the notice fires HERE, and ONLY on `lost` ─────────────────
     *
     * ⚠️ **THE FIRST VERSION WROTE IT ON THE IMPAIRMENT TRANSITION, WHICH IS A SUCCESS PATH.**
     *
     * A direct send failing is the ORDINARY case when a counterparty is offline: the message is
     * then parked with the relay and handed over when they come back, which is the leave-a-message
     * feature working exactly as designed. Writing a notice at that moment told the operator "a
     * message this side sent did not reach the counterparty" about a message that was in flight and
     * would arrive — while `cello_send` was simultaneously telling them it was parked. Two surfaces,
     * opposite stories, same message.
     *
     * By this line the outcome is known, and only one of the three is the operator's problem:
     *   - `parked`   — with the relay, delivered when they come back. Nothing to tell.
     *   - `durable`  — queued here, re-sent automatically. Nothing to tell.
     *   - `lost`     — it could not be queued anywhere. It is gone, and only a resend recovers it.
     *
     * A FAILED ACK takes none of these branches (it never reaches this method), and that is correct:
     * an acknowledgement this side owed them going missing costs the counterparty a redelivery, not
     * the operator a message.
     *
     * NOT retracted when the connection recovers, unlike the impairment state it rides on: a
     * recovered connection does not un-lose a message. That is also why the count is meaningful —
     * it is the number of messages lost in this conversation, and it only ever grows.
     */
    if (retained !== "lost") return;
    this.#ctx.notices.noteContentRefusal(agentName, sessionId, "outbound_message_lost", {
      kind: REFUSAL_KINDS.OUTBOUND,
      impact:
        "a message you sent could not be delivered and could not be saved to send later, so it is gone. Nothing was added to the conversation and the other person never saw it. Everything you sent before it is unaffected.",
      guidance:
        "Send it again. This is the one case where resending is right — there is no copy of it anywhere, so nothing will deliver it for you. If it keeps happening, the connection to this person is not working: check cello_status for this conversation before sending anything long.",
    });
  }
  /** DOD-M12B-ACK-1: why this session is impaired, for the surface that has to explain it. Null
   *  when it is not impaired — a caller must not narrate a failure that is not current. */
  getSessionImpairment(agentName: string, sessionId: string): SessionImpairment | null {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    if (this.#sessionLiveness.get(key) !== "impaired") return null;
    return this.#impairmentCause.get(key) ?? null;
  }
  /**
   * DOD-M12B-ACK-1 — a delivery landed, so the impairment is over.
   *
   * Without this an `impaired` flag is a one-way door: one bad write would make a session report a
   * broken conversation for the rest of its life, which is the same class of lie in the other
   * direction. Called from BOTH send paths — an agent that mostly listens sends content rarely and
   * ACKs constantly, so clearing only on content would leave exactly those sessions impaired
   * forever. Only clears 'impaired': a successful write says nothing about a connection libp2p has
   * already declared 'gone'.
   */
  clearSessionImpairment(agentName: string, sessionId: string, observedBy: "direct_send" | "delivery_ack", correlationId?: string): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    if (this.#sessionLiveness.get(key) !== "impaired") return;
    this.#sessionLiveness.set(key, "alive");
    this.#impairmentCause.delete(key);
    this.#ctx.logger.info("session.liveness.changed", {
      sessionId,
      counterpartyPubkey: this.#ctx.queries.getSessionRecord(agentName, sessionId)?.counterparty_pubkey,
      transportPath: "direct",
      liveness: "alive",
      observedBy,
      reason: "write_succeeded",
      correlationId,
    });
  }
  /** Test seam (same spirit as getDb()): seed per-session direct-path liveness, which is otherwise
   *  only set by the live node's onPeerConnect/onPeerDisconnect (#wireSessionLiveness). Lets a
   *  DB-seeded test exercise the CC-5 reaper's "alive counterparty must survive" gate without standing
   *  up a real libp2p peer connection. */
  markSessionLivenessForTest(agentName: string, sessionId: string, state: "alive" | "impaired" | "gone"): void {
    this.#sessionLiveness.set(this.#ctx.sessionKey(agentName, sessionId), state);
  }

  /**
   * Drop the liveness verdict for a torn-down session.
   *
   * The direct-path liveness flag goes because the seal gate has already read its verdict, so a
   * destroyed or retired session must not retain a stale alive/gone state that a later read could
   * mistake for a live one.
   *
   * ⚠️ **`#impairmentCause` IS DELIBERATELY LEFT ALONE — clearing it here loses an operator notice.**
   * It was added for symmetry and reverted. `getSessionImpairment` gates on liveness, so the cause
   * looks unreachable — but `noteImpairmentRetention` reads it UNGATED, and on the path where
   * `markSessionImpaired` declines because liveness is already `gone`, the retained cause is what
   * produces the `outbound_message_lost` notice: *"your message is gone, send it again."* Clearing
   * it here means the operator is told nothing instead. The cause is cleared where it should be,
   * in `clearSessionImpairment`.
   */
  evictSession(agentName: string, sessionId: string): void {
    this.#sessionLiveness.delete(this.#ctx.sessionKey(agentName, sessionId));
  }
}
