/**
 * CELLO Daemon — A SESSION'S LIFE, FROM OPENED TO GONE
 *
 * Split out of `session-node-manager.ts`, and the last of the four paths to leave it. Everything
 * that changes what a session IS rather than what it carries: opening one as the initiator,
 * accepting one as the responder, connecting to the counterparty, rebuilding a torn-down session on
 * the peer id the other side still holds, moving the row between `active`, `interrupted`, `sealed`
 * and `abandoned`, and tearing the node down when it ends.
 *
 * **Moved verbatim, comments included.**
 *
 * ⚠️ **REVIVAL IS THE HARD PART, FOR A SPECIFIC REASON.** A rebuilt session must come back on the
 * SAME transport peer id the counterparty was handed at establishment, or they can never dial back
 * and the conversation is one-way without saying so. Hence the durable session seed, the rule that
 * a terminal session never revives (its seed is destroyed with it), and the requirement that a
 * revival take every step establishment takes — `msg-022-session-rebuild.test.ts` derives those
 * steps from establishment and requires revival to match, because a revived session that behaves
 * differently from a fresh one is the defect.
 *
 * ⚠️ **WHAT DELIBERATELY STAYED ON THE MANAGER.** `gracefulShutdown` is PROCESS teardown and
 * `#evictSessionCaches` clears the eleven containers every collaborator shares; both would have had
 * to mutate manager state through this context, and neither is about one session. The seam: this
 * file owns what happens to A SESSION, the manager owns the process and the shared state. **The
 * freeze path is the one exception** — `#freezeSession` stayed there and the reader that refuses to
 * revive a frozen session is here, so this file holds the consumer and not the producer.
 */
import { randomUUID, randomBytes } from "node:crypto";
import * as lp from "it-length-prefixed";
import { encodeCbor } from "@cello-protocol/protocol-types";
import type { SessionAbandonedNotice } from "@cello-protocol/protocol-types";
import type { Stream } from "@libp2p/interface";
import { extractErrorMessage } from "./error-message.js";
import { SessionTree } from "./session-tree.js";
import { MAX_SESSION_NODES, type Logger } from "./types.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { SessionRecords } from "./session-records.js";
import type { SessionQueries } from "./session-queries.js";
import type { ParkRecovery } from "./park-recovery.js";
import type { HeldContent } from "./held-content.js";
import type { SessionLeafRecords } from "./session-leaf-records.js";
import type { StandingReceivers } from "./standing-receivers.js";
import type { SessionEphemerals } from "./session-ephemerals.js";
import type { SessionLiveness } from "./session-liveness.js";
import type { SessionContentIngest } from "./session-content-ingest.js";
import type { SessionContentSender } from "./session-content-send.js";
import type { SessionRelay } from "./session-relay.js";
import { SessionConnectionGater } from "./session-connection-gater.js";
import { NodeAutoNatService } from "@cello-protocol/transport";
import {
  SHUTDOWN_STEP_DEADLINE_MS,
  type AbandonNoticeResult,
  type ActiveSessionEntry,
  type CreateSessionResult,
  type RelayConnectParams,
  type SessionRevivalIdentity,
} from "./session-node-types.js";

/** What the session-lifecycle path needs from the manager. */
export interface SessionLifecycleContext {
  readonly logger: Logger;

  readonly records: SessionRecords;
  readonly queries: SessionQueries;
  readonly park: ParkRecovery;
  readonly held: HeldContent;
  readonly leafRecords: SessionLeafRecords;
  readonly receivers: StandingReceivers;
  readonly ephemerals: SessionEphemerals;
  readonly liveness: SessionLiveness;
  readonly contentIn: SessionContentIngest;
  readonly contentOut: SessionContentSender;
  readonly relay: SessionRelay;

  /** A function: the manager opens its database after construction. Re-exposed below as `#db`. */
  db(): DaemonDatabase | null;

  // ── Shared in-memory state: ONE object each, never a copy ───────────────────────────────────
  readonly activeNodes: Map<string, ActiveSessionEntry>;
  readonly standingReceivers: Map<string, {
    node: CelloNode; gater: SessionConnectionGater; autoNat: NodeAutoNatService;
    seed: Uint8Array; relayPeerIds: string[];
  }>;
  readonly standingReceiverCreating: Set<string>;
  readonly agentsWantingReceiver: Set<string>;
  readonly counterpartyAddrs: Map<string, string[]>;
  /**
   * ⚠️ THE DURABLE IDENTITY A REVIVAL COMES BACK ON. Without the seed a rebuilt node gets a fresh
   * key: it can dial the counterparty and they can never dial back — a session reporting itself
   * healthy while silently one-way. A terminal session's seed is destroyed with it, which is what
   * makes "terminal is terminal" enforceable rather than merely intended.
   */
  readonly sessionSeeds: Map<string, SessionRevivalIdentity>;
  readonly frozenSessions: Map<string, { reason: string; guidance: string }>;
  readonly sessionTerminal: Map<string, { type: "sealed"; unreadCount: number }>;

  // ── Settings and hooks the manager may change after construction ────────────────────────────
  readonly shuttingDown: boolean;
  readonly autoNatProbers: () => string[];
  readonly onSessionStateChanged:
    | ((agentName: string, sessionId: string, state: string, counterpartyPubkey: string | null) => void)
    | null;
  readonly onSessionTerminal: ((sessionId: string, terminalStatus: "sealed" | "abandoned") => void) | null;
  readonly retryDrainHook: ((agentName: string, sessionId: string) => void) | null;

  // ── Calls back into the manager ─────────────────────────────────────────────────────────────
  /** DOD-LOOP-1: (agentName, sessionId), never sessionId alone — see the manager's own note. */
  sessionKey(agentName: string, sessionId: string): string;
  requireAgentId(agentName: string): string;
  resolveAgentId(agentName: string): string;
  getSessionTree(agentName: string, sessionId: string): SessionTree;
  /**
   * ⚠️ STAYS ON THE MANAGER, and is reached rather than moved. It clears the shared maps every
   * collaborator writes — it is the method that proves how much of this class was one blob of
   * session state, and it belongs with whoever owns those maps.
   */
  evictSessionCaches(agentName: string, sessionId: string): void;
}

export class SessionLifecycle {
  readonly #ctx: SessionLifecycleContext;

  constructor(ctx: SessionLifecycleContext) {
    this.#ctx = ctx;
  }

  /** A getter so the moved queries still read `this.#db` and narrow exactly as they did. */
  get #db(): DaemonDatabase | null {
    return this.#ctx.db();
  }

  /**
   * The libp2p Peer ID of an active session's node (N_A for an initiated session), or
   * null if no active node exists for it. This is the initiator's session peer id that an
   * inbound session_assignment must carry to the counterparty (so the counterparty gates
   * its handed-off receiver to it). Read-only.
   */
  getSessionNodePeerId(agentName: string, sessionId: string): string | null {
    return this.#ctx.activeNodes.get(this.#ctx.sessionKey(agentName, sessionId))?.node.getPeerId() ?? null;
  }

  /**
   * Create a new outbound session node.
   * Called during cello_initiate_session.
   *
   * @param sessionId      Unique session ID (hex string)
   * @param agentName      Name of the initiating agent
   * @param counterpartyPubkey  Counterparty's K_local public key (hex)
   * @param counterpartyPeerId  Counterparty's session-layer Peer ID (for gater)
   * @param correlationId  Correlation ID minted at session initiation
   */
  async createSessionNode(
    sessionId: string,
    agentName: string,
    counterpartyPubkey: string,
    counterpartyPeerId: string,
    correlationId: string,
    reuseStandingReceiver = false,
    relay?: RelayConnectParams,
  ): Promise<CreateSessionResult> {
    // Cap enforcement (AC-006)
    if (this.#ctx.activeNodes.size >= MAX_SESSION_NODES) {
      this.#ctx.logger.warn("session.node.cap.reached", {
        agentName,
        currentCount: this.#ctx.activeNodes.size,
        maxCount: MAX_SESSION_NODES,
      });
      return {
        ok: false,
        reason: "max_sessions_reached",
        guidance:
          "The daemon has reached its maximum of 32 concurrent session nodes. " +
          "Close an existing session before starting a new one.",
      };
    }

    /**
     * ⚠️ THE "NO ASSIGNMENT" REFUSAL IS NOT HERE, AND THE PLACE IT MOVED TO IS THE POINT.
     *
     * `DOD-M15-SELFCHAIN-1`, ruled 2026-09-06: a session offered with no directory assignment is
     * suspicious and must be refused and surfaced. It was briefly enforced HERE, and that was the
     * wrong door: `createSessionNode` also runs on this agent's OWN outbound path, where the
     * counterparty has no say in whether an assignment exists. A refusal there fires on our own
     * initiations and says nothing about anyone's conduct.
     *
     * A counterparty can only attempt it INBOUND, so that is where it is refused and recorded —
     * see `inbound-sessions.ts`. What remains true here is the correctness backstop: a session with
     * no anchor cannot sign a chained message, so the SEND path refuses (`session_unchainable`)
     * rather than emitting a message whose place could never be proven.
     */

    // The session node N_A: either a FRESH ephemeral node (default), or — for the initiator
    // path (reuseStandingReceiver) — the standing receiver handed off as the session node. The
    // latter makes N_A's peer id equal the SESSION endpoint the initiator ADVERTISED to the
    // directory (its standing receiver), so the counterparty's connection gater (set to that
    // advertised peer id) admits N_A's dial. Mirrors acceptSession, which already hands off the
    // standing receiver on the receiver side. WIRE-001/INV-5: a fully-fresh ephemeral initiator
    // node would require advertising N_A's peer id pre-negotiation (a session-node lifecycle
    // split); the symmetric standing-receiver handoff is the consistent interim model.
    let node: CelloNode;
    let gater: SessionConnectionGater;
    let autoNat: NodeAutoNatService;
    // DOD-M12B-SESSION-SEED-1: whichever branch below runs, the session ends up owning a seed.
    // Promotion inherits the receiver's; a freshly-built node mints its own.
    let seed: Uint8Array;
    if (reuseStandingReceiver) {
      const sr = this.#ctx.standingReceivers.get(agentName);
      if (!sr) {
        // DOD-LOOP-1: this agent has no standing receiver ready — kick off (idempotent) creation
        // so a retry finds it, and report unavailable. Per-agent, so the initiator consuming its
        // OWN agent's receiver never contends with a co-resident responder agent (the loopback case).
        void this.#ctx.receivers.ensureStandingReceiver(agentName, correlationId);
        return {
          ok: false,
          reason: "standing_receiver_unavailable",
          guidance: "The standing receiver node is initializing (completes within 200ms). Retry the session in a moment.",
        };
      }
      ({ node, gater, autoNat, seed } = sr);
      gater.setAllowedPeer(counterpartyPeerId);
      await this.#evictPeersOutsideGate(node, gater, sessionId, counterpartyPeerId, "outbound_promotion");
      // Hand this agent's standing receiver off to this session; a replacement is spun up below.
      this.#ctx.standingReceivers.delete(agentName);
    } else {
      gater = new SessionConnectionGater({
        sessionId,
        allowedPeerId: counterpartyPeerId,
        logger: this.#ctx.logger,
      });
      try {
        seed = randomBytes(32);
        node = await this.#ctx.receivers.createAgentNode(agentName, { sessionId, connectionGater: gater, nodeType: "session", transportPrivateKey: seed });
        await node.start();
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : String(err);
        this.#ctx.logger.error("session.node.create.failed", {
          sessionId,
          agentName,
          error: errorMessage,
          correlationId,
        });
        return {
          ok: false,
          reason: "session_node_creation_failed",
          guidance:
            "Failed to create session transport node. The daemon logged the cause in " +
            "session.node.create.failed. Check that the system has available ports and sufficient memory.",
        };
      }
      // CELLO-M7-TRANSPORT-001: session nodes also need dialability awareness for the
      // dcutr decision path (AC-002). Wrap the node in a NodeAutoNatService and emit
      // its initial result (nodeType: 'session').
      autoNat = new NodeAutoNatService({
        node,
        logger: this.#ctx.logger,
        nodeType: "session",
        probers: this.#ctx.autoNatProbers(),
      });
      autoNat.emitInitialResult();
    }

    const peerId = node.getPeerId();
    const addrs = node.listenAddresses();

    // Persist to SQLite. D4 review F1: #insertSessionRow swallows the write failure (returns
    // false) — ignoring it let a session go fully live with NO sessions row, which after D4a means
    // every inbound message is refused session_orphaned while the session looks healthy to both
    // operators. A rowless session is a dead session by definition — fail ONCE, here, at creation.
    if (!this.#insertSessionRow(sessionId, agentName, counterpartyPubkey, "active")) {
      try {
        await node.stop();
      } catch (err: unknown) {
        this.#ctx.logger.warn("session.node.stop.failed", {
          sessionId,
          agentName,
          error: err instanceof Error ? err.message : String(err),
          correlationId,
        });
      }
      // The handed-off standing receiver was consumed above — rebuild it (idempotent).
      if (reuseStandingReceiver) void this.#ctx.receivers.ensureStandingReceiver(agentName, correlationId);
      return {
        ok: false,
        reason: "session_persist_failed",
        guidance:
          "The daemon could not persist the session row (see session.row.write.failed in the log). " +
          "The session was not created — a session without a durable row cannot receive content. " +
          "Check the daemon's database (disk space, permissions) and retry.",
      };
    }

    // Log observability event (session.node.created)
    //
    // `counterpartySessionPeerId` IS LOGGED because it is recorded here ONCE and never refreshed,
    // while a standing receiver is rebuilt with a fresh libp2p keypair on a lost relay reservation
    // and every lost reservation. If the peer rebuilds between advertising its endpoint and this
    // handoff, we record an identity that no longer exists — and since `newStream` never dials, it
    // only ever looks for an ALREADY-OPEN connection filed under exactly this string, so every send
    // in this direction parks forever while the reverse direction works fine.
    //
    // Both sides of a local session log this event, so recording the id we will dial makes that
    // mismatch a direct comparison in the log instead of an unfalsifiable hypothesis.
    this.#ctx.logger.info("session.node.created", {
      sessionId,
      agentName,
      sessionPeerId: peerId,
      counterpartySessionPeerId: counterpartyPeerId,
      correlationId,
    });

    // Add to active map (keyed by (agentName, sessionId) — DOD-LOOP-1)
    // 006-CRYPTO: the session's throwaway keypair is minted here, with the node, so "a session is
    // active" and "a session has a key" are the same moment. All THREE activation paths mint.
    this.#ctx.ephemerals.mintSessionEphemeral(agentName, sessionId);
    this.#ctx.activeNodes.set(this.#ctx.sessionKey(agentName, sessionId), {
      node,
      agentName,
      sessionId,
      counterpartyPubkey,
      gater,
      correlationId,
      counterpartySessionPeerId: counterpartyPeerId,
      autoNat,
    });
    this.#rememberSessionSeed(agentName, sessionId, seed, counterpartyPeerId, counterpartyPubkey);

    // DAEMON-004: register the content stream handler so inbound content_frames
    // are cross-checked, appended to the daemon-owned tree, and buffered.
    await this.#ctx.contentIn.registerContentHandler(agentName, sessionId, node, counterpartyPubkey);
    // M7-SESSION-003 AC-004: act on the session node's peer events for direct-path
    // liveness. The session connection IS the authority for a direct session.
    this.#ctx.liveness.wireSessionLiveness(agentName, sessionId, node, counterpartyPubkey, correlationId, counterpartyPeerId);

    // M7 DOD-SPINE-6 / MSG-001-3b: connect this session node to the relay as the
    // Structure-2 witness (non-fatal — direct content still works without it).
    if (relay) {
      await this.#ctx.relay.connectSessionRelay(sessionId, node, agentName, relay, correlationId);
    }

    // If we consumed this agent's standing receiver, spin up a replacement (async — do NOT await).
    if (reuseStandingReceiver) {
      void this.#ctx.receivers.ensureStandingReceiver(agentName, correlationId);
    }

    return { ok: true, peerId, addrs };
  }

  /**
   * Hand the standing receiver to an inbound session.
   * Called during cello_await_session.
   *
   * CRITICAL (AC-015): gater.setAllowedPeer() is called BEFORE returning
   * the node's multiaddr to the caller. This closes the window where an
   * unexpected peer could connect during the hand-off.
   */
  async acceptSession(
    sessionId: string,
    agentName: string,
    counterpartyPubkey: string,
    initiatorPeerId: string,
    correlationId: string,
    relay?: RelayConnectParams,
  ): Promise<CreateSessionResult> {
    // DOD-M15-OFFER-SIGNED-1 review N5: the offer record has done its job the moment this session is
    // claimed. Keying it by session (the F1 fix) removed the accidental bound that agent-keying gave
    // it — each new offer used to overwrite the last — so without a clear on the SUCCESS path the
    // map gained one permanent entry per offer ever received, on directory-supplied keys. Cleared
    // here rather than only on refusal, which is what the doc comment always claimed.
    this.#ctx.receivers.clearOfferedDialer(agentName, sessionId);
    const inboundSr = this.#ctx.standingReceivers.get(agentName);
    if (!inboundSr) {
      // DOD-LOOP-1: per-agent — kick off (idempotent) creation so a retry finds it.
      void this.#ctx.receivers.ensureStandingReceiver(agentName, correlationId);
      return {
        ok: false,
        reason: "standing_receiver_unavailable",
        guidance:
          "The standing receiver node is initializing (completes within 200ms). " +
          "Retry cello_await_session in a moment.",
      };
    }

    // Cap enforcement — inbound sessions count against the same limit (AC-006)
    if (this.#ctx.activeNodes.size >= MAX_SESSION_NODES) {
      this.#ctx.logger.warn("session.node.cap.reached", {
        agentName,
        currentCount: this.#ctx.activeNodes.size,
        maxCount: MAX_SESSION_NODES,
      });
      return {
        ok: false,
        reason: "max_sessions_reached",
        guidance:
          "The daemon has reached its maximum of 32 concurrent session nodes. " +
          "Close an existing session before starting a new one.",
      };
    }

    const { node, gater, autoNat, seed } = inboundSr;

    // AC-015: update gater BEFORE retrieving multiaddr / returning to caller
    gater.setAllowedPeer(initiatorPeerId);
    await this.#evictPeersOutsideGate(node, gater, sessionId, initiatorPeerId, "inbound_promotion");

    const peerId = node.getPeerId();
    const addrs = node.listenAddresses();

    // Persist to SQLite. D4 review F1 (same as createSessionNode): a swallowed row-write failure
    // must fail the accept ONCE here — after D4a a rowless session refuses every ingest. The
    // standing receiver (this node) is consumed and rebuilt rather than left with its gater
    // pointed at this initiator.
    if (!this.#insertSessionRow(sessionId, agentName, counterpartyPubkey, "active")) {
      this.#ctx.standingReceivers.delete(agentName);
      // DOD-M12B-SESSION-SEED-1 (review F8): this abort happens BEFORE `#rememberSessionSeed`, so
      // the identity is not being handed to a session — it is being discarded, and is zeroed like
      // any other discard. (The two PROMOTION sites deliberately do not zero: there the same bytes
      // become the session's.)
      inboundSr.seed.fill(0);
      try {
        await node.stop();
      } catch (err: unknown) {
        this.#ctx.logger.warn("session.node.stop.failed", {
          sessionId,
          agentName,
          error: err instanceof Error ? err.message : String(err),
          correlationId,
        });
      }
      void this.#ctx.receivers.ensureStandingReceiver(agentName, correlationId);
      return {
        ok: false,
        reason: "session_persist_failed",
        guidance:
          "The daemon could not persist the session row (see session.row.write.failed in the log). " +
          "The inbound session was not accepted — a session without a durable row cannot receive content. " +
          "Check the daemon's database (disk space, permissions).",
      };
    }

    // Log observability event. `counterpartySessionPeerId` for the same reason as the initiator
    // side: this is the identity every later send will look for an open connection under, it is
    // never refreshed, and the peer's standing receiver may already have been rebuilt under a new
    // one. The RESPONDER is the side that can go stale — only the initiator dials, so this is the
    // half that inherits an id it never verified.
    this.#ctx.logger.info("session.node.created", {
      sessionId,
      agentName,
      sessionPeerId: peerId,
      counterpartySessionPeerId: initiatorPeerId,
      correlationId,
    });

    // Remove this agent's standing receiver from the slot and add to active map. The handed-off
    // node keeps its AutoNAT service (it continues to surface dialability).
    this.#ctx.standingReceivers.delete(agentName);
    // 006-CRYPTO: the hand-off path. A session promoted out of the standing receiver is as new as
    // one opened outbound, so it mints here too.
    this.#ctx.ephemerals.mintSessionEphemeral(agentName, sessionId);
    this.#ctx.activeNodes.set(this.#ctx.sessionKey(agentName, sessionId), {
      node,
      agentName,
      sessionId,
      counterpartyPubkey,
      gater,
      correlationId,
      counterpartySessionPeerId: initiatorPeerId,
      autoNat,
    });
    this.#rememberSessionSeed(agentName, sessionId, seed, initiatorPeerId, counterpartyPubkey);

    // DAEMON-004: register the content stream handler for the inbound session.
    await this.#ctx.contentIn.registerContentHandler(agentName, sessionId, node, counterpartyPubkey);
    // M7-SESSION-003 AC-004: act on the inbound session node's peer events too.
    /**
     * DOD-M12B-RESPONDER-ADDR-1 — LEARN THE INITIATOR'S ADDRESS, because we will need it and this is
     * the only moment we have it.
     *
     * MEASURED LIVE 2026-08-18. After an interruption the responder's re-dial reported
     * `session.transport.redial.unavailable` — *"this side holds no address for the counterparty, so
     * every send parks until they re-establish"* — and every reply it tried to send failed. The
     * initiator can always come back because it kept the addresses it dialled; the responder dialled
     * nothing, so it kept nothing.
     *
     * In plain terms that meant: whoever ANSWERED a conversation could not restart it. Their replies
     * went nowhere until the other side spoke first.
     *
     * The live connection has known the address all along — the responder is holding it right now,
     * because the initiator just dialled in on it. `#counterpartyAddrs` is the same store the
     * initiator fills from its signed relay assignment, and `#evictSessionCaches` hands both to the
     * revival record on the way down, so this needs no separate lifetime.
     */
    const inboundAddrs = node
      .getConnections()
      .filter((c) => c.peerId === initiatorPeerId && typeof c.remoteAddr === "string")
      .map((c) => c.remoteAddr as string);
    if (inboundAddrs.length > 0) {
      this.#ctx.counterpartyAddrs.set(this.#ctx.sessionKey(agentName, sessionId), [...new Set(inboundAddrs)]);
      this.#ctx.logger.info("session.counterparty.addr.learned", {
        agentName,
        sessionId,
        addrs: inboundAddrs.length,
        source: "inbound_connection",
        impact: "this side can now re-dial after an interruption instead of parking every reply",
      });
    } else {
      // NOT A WARNING. Review MEDIUM-4: accept runs off a signaling frame and the initiator dials
      // separately, so "no connection yet" is the ordinary in-flight case — warning on it puts a
      // signal on the normal path, which is how the one occurrence that matters gets buried. The
      // race-free capture is in `#wireSessionLiveness`'s onPeerConnect, which fires when the dial
      // actually lands; this read is only a fast path for when it already has.
      this.#ctx.logger.debug("session.counterparty.addr.deferred", {
        agentName,
        sessionId,
        initiatorPeerId,
        impact: "no connection observed yet; the address is captured when the counterparty connects",
      });
    }

    this.#ctx.liveness.wireSessionLiveness(agentName, sessionId, node, counterpartyPubkey, correlationId, initiatorPeerId);

    // M7 DOD-SPINE-6 / MSG-001-3b: the receiver also connects to the relay witness so
    // the relay can deliver the initiator's witnessed leaves (leaf_deliver) to it.
    if (relay) {
      await this.#ctx.relay.connectSessionRelay(sessionId, node, agentName, relay, correlationId);
    }

    // Immediately spin up a replacement for THIS agent (async — do NOT await, AC-003)
    void this.#ctx.receivers.ensureStandingReceiver(agentName, correlationId);

    return { ok: true, peerId, addrs };
  }

  /**
   * Destroy a session node after seal or on error teardown.
   * Status written to SQLite.
   */
  async destroySessionNode(
    agentName: string,
    sessionId: string,
    reason: "sealed" | "interrupted" | "error",
  ): Promise<void> {
    // F1-b: record the terminal answer BEFORE the caches are evicted (and before the
    // early-return below), so a blocking cello_receive that was waiting when the seal fired
    // returns "session_sealed" (with how many buffered messages it never read) instead of
    // hanging to timeout or 404ing. Set even if the node was already retired — a late receive
    // on a sealed session should always learn it is sealed. The receiver (the party that races
    // the seal on cello_receive) is torn down through THIS path; the closer goes through
    // retireSessionNode and is not blocking on receive.
    if (reason === "sealed") {
      const tkey = this.#ctx.sessionKey(agentName, sessionId);
      // DOD-COATTEND-1: counted from the DURABLE read watermark, not the buffer's length.
      // Delivery no longer drains that buffer (it reads the transcript against a per-connection
      // bookmark), so its length is now "everything that ever arrived", not "what nobody read" —
      // reporting it would tell the operator every message of a healthy conversation went unread.
      const unreadCount = this.#ctx.records.getUnreadReceivedCount(agentName, sessionId);
      this.#ctx.sessionTerminal.set(tkey, { type: "sealed", unreadCount });
    }
    const entry = this.#ctx.activeNodes.get(this.#ctx.sessionKey(agentName, sessionId));
    if (!entry) return;

    entry.autoNat.stop();
    // M7 DOD-SPINE-6 / MSG-001-3b: close the relay witness stream so we don't leak it.
    this.#ctx.relay.detachSessionRelay(entry);
    try {
      await entry.node.stop();
    } catch (err: unknown) {
      this.#ctx.logger.error("session.node.stop.failed", {
        sessionId,
        agentName: entry.agentName,
        error: err instanceof Error ? err.message : String(err),
        correlationId: entry.correlationId,
      });
      // Fall through — still remove from active map and update DB
    }

    // Update SQLite — 'sealed' → 'sealed', 'interrupted'/'error' → 'interrupted'.
    // 'error' is not a valid SessionStatus in SQLite; error-torn-down sessions
    // surface as interrupted so AC-010 recovery handles them at next login.
    // The session.node.destroyed log preserves the original reason for observability.
    const dbStatus = reason === "sealed" ? "sealed" : "interrupted";
    // DOD-CAP-SELF-HEAL-1: OURS. Every caller of this with a non-sealed reason is a local teardown
    // — the operator's kill switch (`cello_set_agent_offline`), an internal error, a node replaced.
    // The counterparty did nothing, so they must not be charged a cap slot for it.
    this.updateSessionStatus(agentName, sessionId, dbStatus, dbStatus === "interrupted" ? "local" : undefined);

    this.#ctx.activeNodes.delete(this.#ctx.sessionKey(agentName, sessionId));
    // Evict the in-memory per-session caches on teardown. The tree is durable in
    // SQLite (getSessionTree reloads it on demand), and the received-content buffer
    // holds plaintext that must not linger after a session ends. Without this, both
    // maps grow unbounded by total sessions seen over a long-lived daemon.
    // (#evictSessionCaches also drops the M7-SESSION-003 liveness flag, so both the
    // destroy and retire teardown paths clear it — no stale verdict survives.)
    this.#ctx.evictSessionCaches(agentName, sessionId);

    this.#ctx.logger.info("session.node.destroyed", {
      sessionId,
      agentName: entry.agentName,
      reason,
    });

    // M8B F14 (fix 1): the torn-down node has just released its port — on a fixed-port
    // deployment this is the FIRST moment a previously-failed re-arm can succeed. Re-arm
    // the standing receiver for an online agent that has none (async, never awaited).
    this.#rearmAfterTeardown(agentName);
  }

  /**
   * M8B F14: re-arm an online agent's standing receiver after a session-node teardown
   * freed resources (notably the fixed port). No-op when the agent is offline, already
   * has a receiver, or one is being created. The re-arm is a NEW async flow — it mints
   * its own correlationId (via the ensure default) rather than inheriting the torn-down
   * session's.
   */
  #rearmAfterTeardown(agentName: string): void {
    if (this.#ctx.shuttingDown) return;
    if (!this.#ctx.agentsWantingReceiver.has(agentName)) return;
    if (this.#ctx.standingReceivers.has(agentName) || this.#ctx.standingReceiverCreating.has(agentName)) return;
    void this.#ctx.receivers.ensureStandingReceiver(agentName);
  }

  /**
   * round-2 finding #5: retire a session's live libp2p node WITHOUT changing its
   * DB status. Used after the active-session bilateral seal commitment has already
   * advanced the row to 'seal_interrupted_pending': the session is frozen, so we
   * stop the node and unregister its /cello/content handler (no more inbound leaves,
   * no leaked node per active close) but must NOT overwrite the pending/sealed status
   * the way destroySessionNode would. The durable tree stays in SQLite (getSessionTree
   * reloads it); the in-memory plaintext buffer is evicted.
   */
  async retireSessionNode(agentName: string, sessionId: string): Promise<void> {
    const entry = this.#ctx.activeNodes.get(this.#ctx.sessionKey(agentName, sessionId));
    if (!entry) return;
    this.#ctx.relay.detachSessionRelay(entry);
    try {
      await entry.node.stop();
    } catch (err: unknown) {
      this.#ctx.logger.error("session.node.stop.failed", {
        sessionId,
        agentName: entry.agentName,
        error: err instanceof Error ? err.message : String(err),
        correlationId: entry.correlationId,
      });
      // Fall through — still remove from active map.
    }
    this.#ctx.activeNodes.delete(this.#ctx.sessionKey(agentName, sessionId));
    this.#ctx.evictSessionCaches(agentName, sessionId);
    this.#ctx.logger.info("session.node.destroyed", {
      sessionId,
      agentName: entry.agentName,
      reason: "sealing",
    });
    // M8B F14 (fix 1): same re-arm point as destroySessionNode — the retired node freed its port.
    this.#rearmAfterTeardown(agentName);
  }

  /**
   * Graceful shutdown: mark all active sessions as interrupted, stop all nodes.
   * Called from the SIGTERM / cello logout path (AC-009).
   * SQLite writes complete before this method returns.
   */
  /**
   * DOD-M12B-SHUTDOWN-1 — wait for a teardown step, but never forever.
   *
   * Every step of shutdown used to be an unbounded `await` on libp2p. That is what makes "the
   * daemon acknowledged the request but is still running" possible: nothing on the daemon side
   * emits a word while it hangs, so the operator's own message ("it may be stuck closing sessions
   * or its database") was a guess. Past the deadline the step is ABANDONED and SAID — the resources
   * it was closing are reclaimed by the OS on exit, and an exit is worth more than a tidy one.
   */
  async boundedTeardown(work: Promise<unknown>, step: string, count: number): Promise<void> {
    if (count === 0) return;
    const started = Date.now();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<"timeout">((resolve) => {
      timer = setTimeout(() => resolve("timeout"), SHUTDOWN_STEP_DEADLINE_MS);
      timer.unref?.();
    });
    const outcome = await Promise.race([work.then(() => "done" as const), deadline]);
    if (timer) clearTimeout(timer);
    if (outcome === "timeout") {
      this.#ctx.logger.error("session.shutdown.step.timeout", {
        step, count, waitedMs: Date.now() - started,
        impact: "this teardown step did not finish and was abandoned so the daemon can exit; the OS reclaims what it held",
      });
    } else {
      this.#ctx.logger.debug("session.shutdown.step.done", { step, count, tookMs: Date.now() - started });
    }
  }

  /**
   * M7-SESSION-001: Mark a session as interrupted with message count and timestamp.
   * Called when a relay session_interrupted frame arrives or a relay stream closes.
   * Also tears down the in-memory session node if one exists for this sessionId.
   *
   * @param sessionId The hex session ID from the relay frame
   * @param messageCount Number of message leaves at interruption
   * @param source 'relay_frame' | 'stream_close'
   */
  async markInterruptedWithDetails(
    agentName: string,
    sessionId: string,
    messageCount: number,
    /**
     * WHAT ACTUALLY HAPPENED, and it is written to the row — review F3.
     *
     * `key_refused` is its own source rather than a borrowed `stream_close`, because the row's
     * `interrupted_by` is what an operator reads days later: labelling a key-authentication refusal
     * `relay_stream_close` sends them to the relay fleet for a fault in the payload.
     */
    source: "relay_frame" | "stream_close" | "key_refused",
  ): Promise<boolean> {
    if (!this.#db) return false;

    // H-3 SECURITY: only an 'active' session may transition to 'interrupted'.
    // A late or forged relay frame must NOT revert a 'sealed', 'seal_interrupted_pending',
    // or already-'interrupted' session back to 'interrupted'. This mirrors the
    // stream-close guard in `#watchRelayStream` (`session-relay.ts`) — the two paths must agree.
    // Not "below" any more: that invariant is now a claim about two FILES, so it is named.
    const existing = this.#ctx.queries.getSessionRecord(agentName, sessionId);
    if (!existing || existing.status !== "active") {
      this.#ctx.logger.warn("session.interrupt.ignored", {
        sessionId,
        source,
        currentStatus: existing?.status ?? "absent",
        reason: "session_not_active",
      });
      // FALSE, not void — the caller needs to know nothing was torn down (review F11).
      return false;
    }

    const now = Date.now();
    const interruptedAt = new Date(now).toISOString();

    // round-2 finding #7: the daemon-owned tree is the authoritative transcript
    // length. The `messageCount` arg comes from registerRelayStream time and defaults
    // to 0, so writing it blindly would clobber the column out of sync with the tree
    // (both seal flows prefer tree.size(), but the column must not lie). When a tree
    // exists for this session, persist its size; otherwise fall back to the arg.
    const treeSize = this.#ctx.getSessionTree(agentName, sessionId).size();
    const authoritativeCount = treeSize > 0 ? treeSize : messageCount;

    try {
      // The `AND status = 'active'` predicate is the authoritative guard: even if
      // the pre-check above raced (it cannot — DatabaseSync is synchronous), the
      // UPDATE only mutates a row that is still active.
      this.#db
        .prepare(
          // DOD-CAP-SELF-HEAL-1: labelled by SOURCE, because the two are not the same event.
          //
          //   relay_frame  — the relay telling us the counterparty went. THEIRS. The D18
          //                  disconnect-evasion move, and it must keep counting.
          //   stream_close — OUR witness stream to the relay ended. That fires on a relay restart,
          //                  a relay fleet roll, or a local network blip. Claiming the counterparty
          //                  did it means three relay deploys permanently refuse a peer who was
          //                  never involved — and relay deploys are routine, so it ratchets faster
          //                  than daemon restarts do.
          //
          // `relay_stream_close` is its own label and STILL COUNTS (the bound excuses only 'local'),
          // because an attacker who can disturb our relay link must not get a free cap reset. It is
          // recorded honestly rather than blamed on the wrong party.
          `UPDATE sessions SET status = 'interrupted', updated_at = ?, message_count = ?, interrupted_at = ?, interrupted_by = '${source === "relay_frame" ? "counterparty" : source === "key_refused" ? "key_refused" : "relay_stream_close"}' WHERE agent_id = ? AND session_id = ? AND status = 'active'`,
        )
        .run(now, authoritativeCount, interruptedAt, this.#ctx.requireAgentId(agentName), sessionId);
    } catch (err: unknown) {
      this.#ctx.logger.error("session.interrupt.db.write.failed", {
        sessionId,
        error: err instanceof Error ? err.message : String(err),
      });
    }

    // Look up the in-memory entry (keyed by (agent, session)) for teardown.
    const entry = this.#ctx.activeNodes.get(this.#ctx.sessionKey(agentName, sessionId));

    // Tear down the in-memory session node if it exists
    if (entry) {
      entry.autoNat.stop();
      this.#ctx.relay.detachSessionRelay(entry);
      try {
        await entry.node.stop();
      } catch (err: unknown) {
        this.#ctx.logger.error("session.node.stop.failed", {
          sessionId,
          agentName,
          error: err instanceof Error ? err.message : String(err),
          correlationId: entry.correlationId,
        });
        // Fall through — still remove from active map
      }
      this.#ctx.activeNodes.delete(this.#ctx.sessionKey(agentName, sessionId));
      /**
       * THE SECRET GOES WITH THE ENTRY — 006-CRYPTO, review pass 2 finding 2.
       *
       * This is the path an interrupted session actually takes, and it is the ORDINARY way a
       * session ends badly: a relay blip, a closed stream, a sleeping laptop. Because it does not
       * evict (see below) the secret used to survive here, and when the session later sealed
       * `destroySessionNode` returned at its `if (!entry) return` without evicting either — so the
       * receipt landed, the session was over, and the key stayed resident until the process exited.
       *
       * The reasons below for KEEPING the other caches do not transfer to key material: buffered
       * plaintext must stay drainable and TTF timers must stay armed, whereas a secret nothing
       * reads must not stay alive. A revived session mints a fresh one and re-keys, which is
       * Decisions Carried #5 and is only true because of this line.
       */
      this.#ctx.ephemerals.destroySessionEphemeralFor(agentName, sessionId, entry.correlationId);
      this.#ctx.logger.info("session.node.destroyed", {
        sessionId,
        agentName,
        reason: "interrupted",
      });
      // DELIBERATELY NOT #evictSessionCaches here (unlike destroySessionNode/retireSessionNode):
      // an interrupted session is not terminal. (1) #receivedContent must stay drainable — the
      // record survives, and cello_receive legitimately reads buffered unread messages after a
      // transient relay blip; evicting would silently discard deliverable plaintext. (2) Evict
      // also cancels armed TTF timers (`clearAwaitingForSession`, in `session-content-send.ts`) — on
      // a dying session the TTF
      // park backstop is exactly what must fire for un-acked content (MSG-001). The caches are
      // reclaimed when the session later seals (destroy/retire paths) or at daemon restart.
      // M8B F14 (fix 1): the relay-detected interruption is the THIRD teardown path that
      // frees the fixed port — it must re-arm too, or a session ending on a network blip
      // leaves the agent deaf again (review finding on the F14 fix).
      this.#rearmAfterTeardown(agentName);
    }

    this.#ctx.logger.warn("session.interrupted.detected", {
      sessionId,
      agentName,
      source,
    });

    // M7-SESSION-001 (M-1 PUSH): notify live MCP clients that this session is now
    // interrupted. Only fires on a real active→interrupted transition (the guard
    // above already returned for any non-active session).
    try {
      this.#ctx.onSessionStateChanged?.(
        agentName,
        sessionId,
        "interrupted",
        existing.counterparty_pubkey,
      );
    } catch (err: unknown) {
      this.#ctx.logger.debug("session.state.notify.failed", {
        sessionId,
        error: err instanceof Error ? err.message : String(err),
      });
    }
    return true;
  }

  /**
   * SEAM 1b (dialer ⇄ session-node reconciliation): dial the counterparty THROUGH
   * this session's OWN node, so the session node N_A holds the connection its content
   * newStream actually rides. TRANSPORT-001's transport selector dialed on a separate
   * (composition-root) node whose connection N_A could not use — the per-session node
   * must be the dialer. Direct mode only here (the default content path, Part 4 D-a);
   * relay-circuit + dcutr strategy via N_A is a later seam. Tries each addr in turn;
   * succeeds on the first connection, returns a named failure if none connect.
   */
  async connectToCounterparty(
    agentName: string,
    sessionId: string,
    addrs: string[],
  ): Promise<{ ok: true } | { ok: false; reason: string; error: string }> {
    const entry = this.#ctx.activeNodes.get(this.#ctx.sessionKey(agentName, sessionId));
    if (!entry) {
      return { ok: false, reason: "session_node_unavailable", error: "no active session node for this session" };
    }
    if (addrs.length === 0) {
      return { ok: false, reason: "no_counterparty_addrs", error: "the assignment carried no counterparty session addrs to dial" };
    }
    // DOD-NAT-REACHABILITY-1: a /p2p-circuit counterparty address is dialed
    // THROUGH its relay, so the gater must admit that relay peer OUTBOUND. The
    // relay id is embedded in the address, which arrived inside the FROST-signed
    // assignment — the same authorization rail as the assigned witness relay.
    for (const addr of addrs) {
      const viaRelay = addr.match(/\/p2p\/([^/]+)\/p2p-circuit/);
      if (viaRelay) entry.gater.setAllowedOutboundPeer(viaRelay[1]!);
    }
    // DOD-M15-RELAYAUTH-1 review H1: the RELAY's gater must also admit this dial, and it only does
    // so once it holds the assignment. Await that here — see the method's own comment for why the
    // counterparty presenting it cannot be relied on.
    await this.#ctx.relay.authorizeCircuitDialsToCounterparty(agentName, sessionId, entry, addrs);
    let lastError = "";
    for (const addr of addrs) {
      try {
        await entry.node.dial(addr);
        // DOD-M12B-REDIAL-1: keep them. They arrived in the signed assignment and were used once
        // and dropped, which is the reason nothing could ever dial this counterparty again.
        this.#ctx.counterpartyAddrs.set(this.#ctx.sessionKey(agentName, sessionId), [...addrs]);
        this.#ctx.logger.info("session.transport.connected", {
          sessionId,
          addr,
          correlationId: entry.correlationId,
        });
        return { ok: true };
      } catch (err: unknown) {
        // extractErrorMessage handles the transport's structured plain-object
        // throws (dial() never throws Error instances) — the old
        // `instanceof Error` idiom logged "[object Object]" on every dial
        // failure; try the next addr.
        lastError = extractErrorMessage(err);
      }
    }
    this.#ctx.logger.warn("session.transport.connect.failed", {
      sessionId,
      reason: "counterparty_dial_failed",
      error: lastError,
      correlationId: entry.correlationId,
    });
    return { ok: false, reason: "counterparty_dial_failed", error: lastError };
  }

  /**
   * DOD-M12B-ABANDON-NOTIFY-1 — tell the counterparty we have hung up. Best effort, never blocking.
   *
   * A force-abandon marks the session terminal HERE and did nothing else, so the other side kept
   * its half live, kept retrying delivery into it, and kept trying to re-establish — forever,
   * because nothing would ever answer. That is what produced the 2026-08-17 notification storm:
   * surviving halves calling continuously while the operator saw connection requests from agents
   * nobody was driving.
   *
   * BEST EFFORT, and every caller must treat it that way. A peer that is offline cannot be told, so
   * this is an improvement on silence rather than a guarantee — and it must never delay or fail the
   * abandon, which is the operator's escape hatch out of a session that can never seal.
   */
  async notifyCounterpartyAbandon(agentName: string, sessionId: string, correlationId?: string): Promise<AbandonNoticeResult> {
    const entry = this.#ctx.activeNodes.get(this.#ctx.sessionKey(agentName, sessionId));
    if (!entry) {
      // NAMES ITS CAUSE, and it is not the network. An `interrupted` session has no node — the
      // restart sweep and markInterrupted both tear it down — and `interrupted` is exactly the
      // status force-abandon exists for. Reporting this as "could not be reached" sends the
      // operator to debug a connection when the answer is in our own process. At INFO, not debug,
      // because it is the common case and it changes what the operator is told.
      this.#ctx.logger.info("session.abandon.notice.skipped", {
        agentName, sessionId, reason: "no_local_node", correlationId,
        impact: "this side had already torn the session down, so there was nothing to send on — the counterparty was not told",
      });
      return { told: false, reason: "no_local_node" };
    }
    let stream: Stream | undefined;
    try {
      // Through the RE-DIAL path, not a bare newStream. A session worth force-abandoning is very
      // often one whose connection blipped — the peer is online and calling us, which is the whole
      // complaint — so one demand-driven dial is the difference between telling them and not.
      stream = await this.#ctx.contentOut.openContentStream(agentName, sessionId, entry, correlationId);
      // Typed against protocol-types so the shape cannot drift from the declaration the receiving
      // side (and any second client implementation) reads.
      const notice: SessionAbandonedNotice = {
        type: "session_abandoned_notice",
        session_id: sessionId,
        ...(correlationId === undefined ? {} : { correlation_id: correlationId }),
      };
      const frame = encodeCbor(notice) as Uint8Array;
      stream.send(lp.encode.single(frame));
      await stream.close();
      this.#ctx.logger.info("session.abandon.notice.sent", { agentName, sessionId, correlationId });
      return { told: true, reason: "sent" };
    } catch (err: unknown) {
      if (stream !== undefined) {
        try { stream.abort(err instanceof Error ? err : new Error(String(err))); } catch { /* already gone */ }
      }
      this.#ctx.logger.warn("session.abandon.notice.failed", {
        agentName, sessionId, correlationId,
        error: err instanceof Error ? err.message : String(err),
        impact: "the counterparty was not told and may keep calling until it gives up",
      });
      return { told: false, reason: "send_failed" };
    }
  }

  /**
   * DOD-M12B-ABANDON-NOTIFY-1 — the receiving half: our counterparty has abandoned, so retire.
   *
   * RETIRING IS NOT DELETING. The counterparty walking away forfeits the notarized receipt; it must
   * not also cost the operator the record of what was actually said. The transcript and the tree
   * stay exactly as they are.
   *
   * Only an `active` or `interrupted` session moves. A SEALED session has a notarized receipt and
   * must never be turned into an abandoned one by a late or duplicated notice — that would destroy
   * the artifact this protocol exists to produce. An unknown session is refused rather than
   * created: an authenticated stream proves who is speaking, not that a session exists.
   */
  async retireOnCounterpartyAbandon(agentName: string, sessionId: string, correlationId?: string): Promise<boolean> {
    const record = this.#ctx.queries.getSessionRecord(agentName, sessionId);
    if (!record) {
      this.#ctx.logger.warn("session.abandon.notice.unknown_session", { agentName, sessionId, correlationId });
      return false;
    }
    if (record.status !== "active" && record.status !== "interrupted") {
      this.#ctx.logger.debug("session.abandon.notice.ignored", {
        agentName, sessionId, status: record.status, correlationId,
        reason: "session already terminal",
      });
      return false;
    }
    // THE TRANSPORT IS RETIRED. THE SESSION IS NOT.
    //
    // The first build flipped the status to `abandoned`, and that was wrong twice over. It handed
    // the abandoning party a button that DENIES US OUR RECEIPT: the unilateral seal exists for
    // exactly this case — "the counterparty never co-closes" — and produces a notarized certificate
    // after a grace period, but `cello_close_session` refuses an `abandoned` session outright. So
    // one frame from them destroyed a recovery path that already existed, remotely and for free.
    // Today the abandoner can only go silent, and going silent is what the unilateral seal was
    // built to survive.
    //
    // What the DoD actually asks for is that we stop calling them. That is a transport concern:
    // mark it, stop re-dialling, stop retrying delivery — and leave the session sealable.
    const marked = this.#ctx.queries.markCounterpartyAbandoned(agentName, sessionId);
    if (!marked) return false;
    // The addresses go, so the demand-driven re-dial has nothing to dial. This is the storm.
    const key = this.#ctx.sessionKey(agentName, sessionId);
    this.#ctx.counterpartyAddrs.delete(key);
    this.#ctx.logger.warn("session.counterparty.abandoned", {
      agentName, sessionId, priorStatus: record.status, correlationId,
      impact: "the counterparty ended this session on their side, so nothing more will arrive and replies cannot reach them — this side stops calling. The session is NOT terminal: a unilateral seal is still available, and the transcript is intact",
    });
    // AWAITED, and `retireSessionNode` NOT `destroySessionNode`. The latter writes the status back
    // — `error` maps to `interrupted` — a few hundred milliseconds later, which silently undid the
    // whole unit; the former is the method that tears a node down without touching the status, and
    // it is what the local force-abandon path already uses.
    await this.retireSessionNode(agentName, sessionId);
    return true;
  }

  /**
   * DOD-M15-FRAME-1 — NARROWING THE GATE DOES NOT EVICT ANYONE ALREADY INSIDE. This does.
   *
   * libp2p consults the gater only when a connection is ESTABLISHED, so narrowing it never evicts a
   * peer already attached. That is why this sweep exists and why it cannot be replaced by the gate.
   *
   * A peer that attached early can therefore hold its connection open, still be attached when the
   * receiver is promoted, and be sitting there when the content protocol activates. DOD-M15-ASSIGN-1
   * shrank who can get that foothold — an unclaimed standing receiver now admits nobody inbound,
   * where it used to admit everyone — but it did not, and could not, change the constraint above.
   *
   * That is the foothold the whole injection path depends on — placed before the door narrows. The
   * frame-level gate above refuses what they send; this closes the connection they send it on, so
   * the stranger is not merely ineffective but gone, and is not sitting there for the next protocol
   * to activate.
   *
   * BEST-EFFORT BY CONSTRUCTION, and it must stay that way. A failure to hang up one peer must not
   * fail the session setup that is mid-flight — the frame gate is the load-bearing control and it
   * does not depend on this succeeding. Relay peers are exempt: they are on the OUTBOUND allowlist
   * because reservation refreshes ride them, and hanging one up would cost the agent its inbound
   * reachability to remove a peer that cannot speak the content protocol anyway.
   */
  async #evictPeersOutsideGate(
    node: CelloNode,
    gater: SessionConnectionGater,
    sessionId: string,
    allowedPeerId: string,
    trigger: string,
  ): Promise<void> {
    let connections: Array<{ peerId: string }>;
    try {
      connections = node.getConnections();
    } catch (err: unknown) {
      this.#ctx.logger.debug("session.gate.evict.unavailable", {
        sessionId, trigger, error: extractErrorMessage(err),
      });
      return;
    }
    const toEvict = connections
      .map((c) => c.peerId)
      .filter((peerId) => peerId !== allowedPeerId && !gater.isAllowedOutboundPeer(peerId));
    /**
     * CONCURRENT AND CAPPED, because the count is ATTACKER-CONTROLLED (review F4).
     *
     * This runs inside `acceptSession`, before the session row is written, and the standing receiver
     * used to accept everyone (closed by DOD-M15-ASSIGN-1) — so opening N connections to an agent's advertised receiver used
     * to make every later session setup on that agent wait for N sequential graceful closes.
     * `hangUp` is libp2p's graceful close and takes no timeout, so the wait was unbounded in both
     * directions. Evicting an injection foothold must not itself become the way to stall an agent.
     *
     * The cap is a LOGGED truncation, never a silent one: what is left behind still cannot inject
     * (the frame gate refuses it and now hangs it up on first contact), and the next promotion
     * sweeps again — but an operator reading this needs to know the sweep did not finish.
     */
    const EVICT_CAP = 32;
    const batch = toEvict.slice(0, EVICT_CAP);
    if (toEvict.length > batch.length) {
      this.#ctx.logger.warn("session.gate.evict.capped", {
        sessionId, trigger, attached: toEvict.length, evicting: batch.length,
        impact: "more peers were attached outside the gate than one promotion evicts; the rest keep their connections until a later sweep, and are refused and hung up by the frame gate if they speak",
      });
    }
    await Promise.allSettled(batch.map(async (peerId) => {
      try {
        await node.hangUp(peerId);
        this.#ctx.logger.warn("session.gate.evicted", {
          sessionId, trigger, evictedPeerId: peerId, allowedPeerId,
          impact: "a peer attached to this node before the session narrowed its gate was disconnected; libp2p does not re-run the gater against live connections, so it would otherwise have stayed attached when the content protocol activated",
        });
      } catch (err: unknown) {
        // Best-effort: the frame gate still refuses anything this peer sends, and now hangs it up.
        this.#ctx.logger.debug("session.gate.evict.failed", {
          sessionId, trigger, peerId, error: extractErrorMessage(err),
        });
      }
    }));
  }

  /**
   * DOD-LOOP-1: public hook for the composition root to create an agent's standing receiver when
   * the agent comes online (cello_start_agent), and to tear it down when it goes offline.
   * M8B F14: also called from the inbound accept path (ensure on demand). Marks the agent as
   * WANTING a receiver, which arms the teardown re-arm in destroySessionNode/retireSessionNode.
   */
  /**
   * DOD-M12B-SESSION-SEED-1 test seam: the seed the agent's current standing receiver holds.
   *
   * The property under test — "the receiver built behind a promoted one never reuses its seed" — is
   * about an identity that by design never leaves the process, so there is no observable surface for
   * it short of a live two-node dial. Reading it here is the narrowest way to pin it.
   */
  /** DOD-M12B-SESSION-SEED-1: record the identity this session must be able to return at. */
  #rememberSessionSeed(
    agentName: string,
    sessionId: string,
    seed: Uint8Array,
    counterpartyPeerId: string,
    counterpartyPubkey: string,
  ): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    // Defensive: unreachable today because `insertSessionRow` PK-conflicts on a repeat, but an
    // overwrite that dropped a live seed un-zeroed would leave the one copy we are responsible for
    // in the heap with nothing tracking it.
    this.#ctx.sessionSeeds.get(key)?.seed.fill(0);
    // `counterpartyAddrs` starts empty: at creation the signed assignment has not necessarily
    // arrived yet. It is filled by `#evictSessionCaches` on the way down, which is the last moment
    // the live addresses exist.
    this.#ctx.sessionSeeds.set(key, { seed, counterpartyPeerId, counterpartyPubkey, counterpartyAddrs: [] });
  }

  /**
   * DOD-M12B-SESSION-SEED-1 — destroy a session's transport identity.
   *
   * Called from `#updateSessionStatus` on a terminal status, in the SAME step that writes it, so
   * there is no window in which a session is closed on paper and still revivable in memory.
   *
   * **WHAT THE ZERO-FILL DOES AND DOES NOT DO** — checked against the derivation, not assumed.
   * `createNode` hands the buffer to `generateKeyPairFromSeed`, and `@libp2p/crypto` COPIES it
   * (`uint8arrayConcat([seed, publicKeyRaw])`, then `Uint8Array.from`). Two consequences:
   *   - zeroing after the node has started is SAFE — the running node holds its own copy;
   *   - it does NOT erase the key from the heap. An identical usable copy is the first 32 bytes of
   *     `privateKey.raw` on the node object until that node is dropped.
   * So this removes OUR long-lived copy — the one that would otherwise sit in a map for the life of
   * the process, decoupled from any node — and that is worth doing. It is not a heap scrub, and
   * the DoD already says the bound rather than secrecy is the control.
   */
  destroySessionSeed(agentName: string, sessionId: string): void {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    const identity = this.#ctx.sessionSeeds.get(key);
    if (identity === undefined) return;
    identity.seed.fill(0);
    this.#ctx.sessionSeeds.delete(key);
    this.#ctx.logger.debug("session.seed.destroyed", { agentName, sessionId });
  }

  /**
   * DOD-M12B-SESSION-SEED-1 — bring an interrupted session back on the peer id it already has.
   *
   * THE DEFECT THIS CLOSES. `markInterruptedWithDetails` and `destroySessionNode` stop the node and
   * delete it from `#activeNodes`, and until now **nothing anywhere recreated one**. A laptop-close
   * session stayed stuck even though both processes were alive and both keypairs were still in
   * memory — the trace on 2026-08-17 found no missing transport capability, just a missing edge.
   *
   * TWO THINGS HAVE TO HAPPEN, and doing only one leaves the session exactly as stuck:
   *   1. the NODE comes back, at the same peer id, or the counterparty can never dial us again;
   *   2. the STATUS comes back to `active`, or every send still refuses with `session_not_active`.
   *
   * **DEMAND-DRIVEN ONLY.** Nothing calls this on a timer. That is the `REDIAL-1` discipline and it
   * is also Andre's tenet — a background rebuilder would hold a dialable endpoint open for a session
   * nobody is using, which is the "open connection a malicious agent can farm for" in as many words.
   *
   * **TERMINAL IS TERMINAL.** A sealed or abandoned session had its seed zeroed in the same step
   * that wrote its status, so there is nothing to come back on. This refuses by name rather than
   * minting a fresh identity — a revival that quietly mints would hand one session a second peer id
   * and break the invariant while appearing to work.
   *
   * Idempotent: a session that already has a live node returns ok without building a second one.
   */
  async reviveSessionNode(
    agentName: string,
    sessionId: string,
  ): Promise<{ ok: true; peerId: string } | { ok: false; reason: string; guidance?: string }> {
    const key = this.#ctx.sessionKey(agentName, sessionId);
    const live = this.#ctx.activeNodes.get(key);
    if (live) return { ok: true, peerId: live.node.getPeerId() };

    // PARITY with `acceptSession` — and the parity guard in msg-022 is what caught its absence.
    // A revived session's offer record has almost always been cleared already (it was cleared when
    // the session was first accepted), so this is usually a no-op. It is here because "usually a
    // no-op" is not a reason for establishment and revival to do different things: every divergence
    // between those two paths in this file has been a defect, and the guard exists because one of
    // them shipped past a green suite for two days.
    this.#ctx.receivers.clearOfferedDialer(agentName, sessionId);

    const record = this.#ctx.queries.getSessionRecord(agentName, sessionId);
    if (!record) return { ok: false, reason: "session_not_found" };
    /**
     * A REVIVED SESSION GETS ITS SEAL CHANCES BACK — `DOD-M15-SEAL-FAILED-TERMINAL-1` review
     * MEDIUM-6, and without this a receipt can be lost permanently and silently.
     *
     * `restart_seal_gave_up_at` is written when the restart resolver exhausts its attempts, and
     * NOTHING ever cleared it. Its stated purpose is narrow — *"a machine restarting ~6 times a day
     * must not re-run five ceremonies against a hopeless session on every boot"* — and a session
     * being revived is the opposite of hopeless: something is talking to it again.
     *
     * The path it closes: resolver gives up → the column is stamped → the session is REVIVED and
     * carries live traffic → it is closed → the background ceremony dies → the in-memory failure
     * marker is lost at the next restart → `listRestartOrphanedSessions` excludes the row forever on
     * this column → and `listExpiredUnrevivableSessions` explicitly INCLUDES
     * `restart_seal_gave_up_at IS NOT NULL`, so the revival sweep force-abandons it. Receipt gone,
     * with no surface having ever said so.
     *
     * Bounded, because revival is not a boot-loop: it takes a live counterparty or an operator read.
     */
    // One statement, gated in SQL rather than on a field: `SessionRecord` does not carry this column
    // and widening the type to read it once would spread it through every consumer. `changes` tells
    // us whether it actually cleared, so the log stays a signal instead of firing on every revival.
    const clearedGaveUp = this.#db
      ?.prepare(
        "UPDATE sessions SET restart_seal_gave_up_at = NULL, restart_seal_gave_up_reason = NULL " +
        "WHERE agent_id = ? AND session_id = ? AND restart_seal_gave_up_at IS NOT NULL",
      )
      .run(this.#ctx.resolveAgentId(agentName), sessionId);
    if ((clearedGaveUp?.changes ?? 0) > 0) {
      this.#ctx.logger.info("session.restart_seal.gave_up.cleared", {
        agentName, sessionId,
        impact: "this session is eligible for restart-seal recovery again — it is being revived, so it is not hopeless.",
      });
    }
    if (record.status === "sealed" || record.status === "abandoned" || record.status === "seal_interrupted_pending") {
      return {
        ok: false,
        reason: "session_terminal",
        guidance: `Session is '${record.status}'. A session that has ended cannot be revived; start a new one.`,
      };
    }
    /**
     * DOD-M15-FRAME-1 (review F1) — A DEFENSIVE FREEZE MUST NOT UNDO ITSELF ON THE NEXT READ.
     *
     * `#freezeOnIdentityFailure` tears the node down, and a teardown writes status `interrupted`.
     * `interrupted` is not terminal — it is the *revivable* status — so `reviveIfNeededForRead`
     * fired on the operator's very next `cello_receive`, rebuilt a node behind a gater allowing the
     * SAME counterparty peer, flipped the row back to `active`, and logged it as a success.
     *
     * The freeze therefore lasted until the next keystroke, while the log line said *"no further
     * content will be accepted on this session"*. A security decision that silently reverses itself,
     * with a message asserting the opposite, is a worse defect than the one the freeze was added to
     * fix — and it is the class this milestone exists to remove, reintroduced by its own fix.
     *
     * Checked BEFORE the cap and after the terminal statuses, so the answer names the freeze rather
     * than whatever else the session would have been refused for.
     *
     * In memory, and so lost on a daemon restart — the same bound as `DOD-M15-DIVERGE-DURABLE-1`
     * and for the same reason. The durable column is `DOD-M15-FREEZE-STATUS-1`; the reversibility
     * could not wait for it.
     */
    const frozen = this.#ctx.frozenSessions.get(key);
    if (frozen) {
      // The REASON and the GUIDANCE both come from the site that froze it. Hardcoding them here was
      // correct while an identity failure was the only way in, and became a false accusation the
      // moment a second one existed — see the note on `#frozenSessions` in `session-node-manager.ts`.
      return {
        ok: false,
        reason: frozen.reason,
        guidance:
          `${frozen.guidance} It is not revived automatically, and reading or sending will not clear it. ` +
          `Your transcript up to the freeze is intact: cello_transcript ${sessionId} reads it. ` +
          `To end the session and keep what it earned, close it — cello_close_session ${sessionId}. To talk to them again, start a fresh session rather than reviving this one.`,
      };
    }

    /**
     * THE CAP APPLIES TO A REVIVAL TOO (review: parity gap). Establishment refuses at
     * `MAX_SESSION_NODES` because each node is a real libp2p instance with listeners, connections
     * and a relay reservation. A revival builds exactly the same thing, so letting it past the cap
     * would let a daemon walk over the limit one reconnect at a time — and the limit exists to stop
     * a machine being taken down by its own session count.
     *
     * Refused by name, so the caller can say something true: this is a local resource limit, not a
     * problem with the session or the counterparty.
     */
    if (this.#ctx.activeNodes.size >= MAX_SESSION_NODES) {
      this.#ctx.logger.warn("session.revive.cap.reached", {
        agentName,
        sessionId,
        activeCount: this.#ctx.activeNodes.size,
        maxCount: MAX_SESSION_NODES,
        impact: "this session stays interrupted until another session ends and frees a node slot",
      });
      return {
        ok: false,
        reason: "session_node_cap_reached",
        guidance:
          `This daemon already holds ${MAX_SESSION_NODES} active session nodes, so this session ` +
          "cannot be brought back yet. Close a session you have finished with and try again.",
      };
    }

    const identity = this.#ctx.sessionSeeds.get(key);
    if (identity === undefined) {
      // The honest case: the daemon restarted, so the keypair is genuinely gone. That is
      // RESTART-SEAL-1's territory (resolve with a receipt), not a revival — and saying so is the
      // difference between an operator waiting for a reconnect that cannot happen and one closing
      // the session.
      return {
        ok: false,
        reason: "session_identity_lost",
        guidance:
          "This session's transport identity did not survive a daemon restart, so it cannot be " +
          "revived. It will be sealed automatically, or you can close it now to get its receipt.",
      };
    }

    const gater = new SessionConnectionGater({
      sessionId,
      allowedPeerId: identity.counterpartyPeerId,
      logger: this.#ctx.logger,
    });
    // The relay peers must be allowed OUTBOUND before the node starts, or the reservation the line
    // below depends on is refused by our own gater — the same ordering the receiver builder uses.
    const reservations = this.#ctx.relay.reservationCircuitAddrs(agentName);
    for (const relayPeerId of reservations.relayPeerIds) gater.setAllowedOutboundPeer(relayPeerId);

    let node: CelloNode;
    const t0 = Date.now();
    this.#ctx.logger.info("session.revive.node.building", {
      agentName,
      sessionId,
      circuitAddrs: reservations.addrs.length,
      relayPeerIds: reservations.relayPeerIds.length,
    });
    try {
      node = await this.#ctx.receivers.buildRevivedNode(sessionId, gater, identity.seed, reservations.addrs, agentName);
      this.#ctx.logger.info("session.revive.node.started", {
        agentName,
        sessionId,
        startMs: Date.now() - t0,
        listenAddrs: node.listenAddresses().length,
        circuitListen: node.listenAddresses().filter((a) => a.includes("/p2p-circuit")).length,
      });
    } catch (err: unknown) {
      this.#ctx.logger.error("session.revive.node.failed", {
        agentName,
        sessionId,
        error: err instanceof Error ? err.message : String(err),
        impact: "the session stays interrupted; the next send will attempt this again",
      });
      return { ok: false, reason: "session_node_creation_failed" };
    }

    const autoNat = new NodeAutoNatService({
      node,
      logger: this.#ctx.logger,
      nodeType: "session",
      probers: this.#ctx.autoNatProbers(),
    });
    autoNat.emitInitialResult();

    // DOD-M12B-SESSION-SEED-1: give the re-dial its addresses back BEFORE the session goes active,
    // so the first send after a revival has somewhere to go. Without this the send fails instantly
    // on a connection that was never made, and — measured live — is lost rather than parked.
    if (identity.counterpartyAddrs.length > 0) {
      this.#ctx.counterpartyAddrs.set(key, [...identity.counterpartyAddrs]);
    }
    const correlationId = randomUUID();
    /**
     * DOD-M12B-REVIVE-PARK-1 — RESTORE THE RELAY, or a revived session cannot park and every failed
     * send is declared lost.
     *
     * This is the defect behind five identical live failures on 2026-08-18. `#parkContent` opens
     * with `if (!hook || !entry || !entry.relayPeerId || !entry.relayAddrs) return "unconfigured"`,
     * and a revived entry carried none of it — so the park was skipped and the send fell through to
     * *"could NOT be queued for retry — it is lost. Send it again."* The relay was recorded on the
     * session row the whole time, and store-and-forward would have delivered the message: the
     * counterparty's own sends park through it successfully in the same minute.
     *
     * What it cost the operator: their reply was accepted, discarded, and they were told to retype
     * it — which is how a transcript gets duplicates of a message that was never lost in the first
     * place.
     *
     * Read from the row rather than carried in the revival record on purpose: the row is where the
     * relay assignment is durable, and it is the same source `getPersistedRelayEndpoint` already
     * serves the startup flush from — a path that exists precisely because in-memory entries are
     * gone by then, which is exactly the situation a revival is in.
     */
    // ONE lookup, and ONE event for the absent case (review LOW-8). This used to read the endpoint
    // here and again inside the relay reconnect, and both logged `session.revive.relay.absent` with
    // different `impact` text — one event name standing for two meanings, fired twice for a single
    // condition. `reconnectRevivedSessionRelay` (`session-relay.ts`) takes it as a parameter now.
    const persistedRelay = this.#ctx.queries.getPersistedRelayEndpoint(agentName, sessionId);
    // 006-CRYPTO: a REVIVED session mints a FRESH keypair and re-keys — Decisions Carried #5. That
    // holds because the interrupt path destroys the old secret when it drops the entry; until it
    // did, this call found the stale key still in the map and quietly kept it. The salt, which IS
    // persisted, is re-read from the row instead — opposite lifetimes, deliberately.
    this.#ctx.ephemerals.mintSessionEphemeral(agentName, sessionId);
    /**
     * AND ANNOUNCE IT — review F1, second half. Minting a fresh key achieves nothing on its own: the
     * COUNTERPARTY has to hear about it, and it is the side that did NOT restart, so it is not
     * tearing anything down or reconnecting. `#sendEphemeralFrame` otherwise rides `onPeerConnect`,
     * which does not fire again for a connection that never dropped — the ordinary shape when only
     * one end's witness stream closed, which is what a relay roll produces.
     *
     * Without this the two ends sit on different keys for the life of the session, every message
     * fails GCM, and the receiving operator is told the content may have been MODIFIED IN FLIGHT for
     * what is a local key skew. Deferred a tick so the revived node's handlers are registered before
     * the frame goes out.
     */
    setTimeout(() => { void this.#ctx.ephemerals.sendEphemeralFrame(agentName, sessionId, "revive-rekey"); }, 0);
    this.#ctx.activeNodes.set(key, {
      node,
      agentName,
      sessionId,
      counterpartyPubkey: identity.counterpartyPubkey,
      gater,
      correlationId,
      counterpartySessionPeerId: identity.counterpartyPeerId,
      autoNat,
      ...(persistedRelay
        ? { relayPeerId: persistedRelay.relayPeerId, relayAddrs: persistedRelay.relayAddrs }
        : {}),
    });
    await this.#ctx.contentIn.registerContentHandler(agentName, sessionId, node, identity.counterpartyPubkey);
    /**
     * review HIGH-2 — REWIRE LIVENESS, or this session can never be interrupted again.
     *
     * Both creation paths call this; the first build of the revival did not. Without it the revived
     * session is pinned `active`: a later disconnect fires no transition, no `session_state_changed`
     * reaches the MCP client, and the receive surface renders unknown liveness as healthy-and-quiet.
     * So the SECOND laptop close would leave the operator staring at a session that reports fine and
     * is dead — this milestone's founding defect, one revival later, and with no status change left
     * to trigger the next revival either.
     */
    this.#ctx.liveness.wireSessionLiveness(
      agentName,
      sessionId,
      node,
      identity.counterpartyPubkey,
      correlationId,
      identity.counterpartyPeerId,
    );

    // DOD-M12B-REVIVE-RELAY-1: the step revival skipped. Establishment connects the relay witness
    // here; without it the session comes back with no live inbound path at all.
    await this.#ctx.relay.reconnectRevivedSessionRelay(agentName, sessionId, node, gater, correlationId, persistedRelay);

    // THE REVERSE EDGE. A transport event took this session out of `active` and nothing has ever
    // put one back. Written after the node is live and its handler registered, so the row never
    // claims `active` for a session that cannot yet receive.
    //
    // review MEDIUM-3: the result is CHECKED. `#updateSessionStatus` returns false when the write
    // matched no row or the DB errored — and reporting revival ok on a row that still says
    // `interrupted` leaves a live, talking session where REVIVAL-BOUND-1's sweep can seal or abandon
    // it. Failing here means tearing the node back down rather than running in that split state.
    if (!this.updateSessionStatus(agentName, sessionId, "active")) {
      /**
       * DOD-M15-RELAYLEAK-1 (review MEDIUM-4) — **THIS TEARDOWN LEAKED THE EXACT THING THE LINE IS
       * ABOUT, THROUGH A DIFFERENT DOOR.**
       *
       * `reconnectRevivedSessionRelay` (`session-relay.ts`, not "above") has already called `registerSession` on the cached
       * relay client and hung it on this entry. Deleting the map key and stopping the node released
       * the daemon's own objects and left that registration standing with **no owner** — and
       * `detachSessionRelay` (`session-relay.ts`) closes a client only when `!hasSessions()`, so the orphaned
       * registration held that predicate false for the life of the process. The client, its
       * authenticated stream and its relay-side reservation were unreachable and immortal.
       *
       * The shutdown loop this line added does sweep it at exit, which is precisely why it had to be
       * fixed here too: a leak that is only cleaned up by process death is still a leak for every
       * hour the daemon is up.
       */
      /**
       * ⚠️ Review MEDIUM-2 — **THE ENTRY IS MATCHED BY IDENTITY, NOT BY KEY.** `reviveSessionNode`
       * has no in-flight guard: its `if (live) return` is separated from `#activeNodes.set` by the
       * whole node build, so two revivals for one key can both reach the `set` and the second
       * overwrites the first. Looking up by key alone would then hand THIS failing revival the
       * OTHER one's live entry, and detaching it would unregister a running session's leaf handler
       * — closing the client that session is using if it was the last one on it. Comparing `node`
       * costs one token and makes "the entry I created" provable rather than assumed.
       */
      const revivedEntry = this.#ctx.activeNodes.get(key);
      if (revivedEntry?.node === node) this.#ctx.relay.detachSessionRelay(revivedEntry);
      this.#ctx.activeNodes.delete(key);
      // 006-CRYPTO: the revival FAILED, so the key it just minted belongs to a session that never
      // came back. Dropping the entry without this would strand it for the daemon's lifetime.
      this.#ctx.ephemerals.destroySessionEphemeralFor(agentName, sessionId);
      try {
        await node.stop();
      } catch { /* best-effort: the status write already failed and is logged with its cause */ }
      return {
        ok: false,
        reason: "session_status_write_failed",
        guidance:
          "The session node was rebuilt but its status could not be written, so it was torn back " +
          "down rather than left live under an interrupted row. The daemon logged the cause.",
      };
    }

    // The messages that failed while this session was down were queued on a promise of "retried on
    // reconnect". This is that reconnect — fire it before anyone is told the session is back.
    if (this.#ctx.retryDrainHook !== null) {
      try {
        this.#ctx.retryDrainHook(agentName, sessionId);
      } catch (err: unknown) {
        this.#ctx.logger.warn("session.revive.retry_drain.failed", {
          agentName,
          sessionId,
          error: err instanceof Error ? err.message : String(err),
          impact: "messages queued while this session was down are still queued",
        });
      }
    }

    const peerId = node.getPeerId();
    this.#ctx.logger.info("session.revived", {
      agentName,
      sessionId,
      peerId,
      // The whole claim of this line, in the log: the id did not change, so the counterparty's
      // stored dial target is still correct and they do not need to be told anything.
      identityPreserved: true,
    });
    return { ok: true, peerId };
  }

  /**
   * DOD-M12B-SESSION-SEED-1 — the DEMAND edge: a send on an interrupted session revives it.
   *
   * One of TWO production callers of `reviveSessionNode` — `reviveIfNeededForRead` is the other —
   * and both are deliberately demand paths rather than timers. The `REDIAL-1` discipline and Andre's tenet say the same thing from two
   * directions: nothing may re-open on its own, because a background rebuilder would hold a dialable
   * endpoint open for a session nobody is using — the *"open connection a malicious agent can farm
   * for"*. The operator sending is the demand; there is no other trigger.
   *
   * A no-op for the normal case. An `active` session with a live node returns immediately without
   * touching it — this sits on the hot path of every send, and replacing a healthy node would be
   * churn that changes the peer id for no reason.
   */
  async reviveIfNeededForSend(
    agentName: string,
    sessionId: string,
  ): Promise<{ ok: true } | { ok: false; reason: string; guidance?: string }> {
    const record = this.#ctx.queries.getSessionRecord(agentName, sessionId);
    if (!record) return { ok: false, reason: "session_not_found" };
    // The overwhelmingly common case: nothing to do, and no node was disturbed to find that out.
    if (record.status === "active" && this.#ctx.activeNodes.has(this.#ctx.sessionKey(agentName, sessionId))) return { ok: true };

    const revived = await this.reviveSessionNode(agentName, sessionId);
    if (!revived.ok) {
      this.#ctx.logger.info("session.revive.declined", {
        agentName,
        sessionId,
        previousStatus: record.status,
        trigger: "send",
        reason: revived.reason,
      });
      return revived;
    }
    this.#ctx.logger.info("session.revived.on_demand", {
      agentName,
      sessionId,
      previousStatus: record.status,
      trigger: "send",
    });
    return { ok: true };
  }

  /**
   * DOD-M12B-SESSION-SEED-1 (case B) — the INBOUND half of the demand edge.
   *
   * `reviveIfNeededForSend` covers the operator waking first. Case B's triggers are symmetric — a
   * wifi hop, a relay restart, a directory node cycling — so half the time the COUNTERPARTY wakes
   * first. They send; we have no node yet, because revival is demand-driven and we have demanded
   * nothing. Their content parks at the relay, which is the backstop working as designed.
   *
   * Then the operator comes back and READS, and until now that told them nothing: the receive
   * handler reads the transcript and never gates on status, so it happily reports what is already
   * stored while messages sit parked, waiting for a node that will not exist until the operator
   * happens to SEND. An operator who only reads was stuck forever with a surface that looked fine.
   *
   * **WHY A READ MAY TRIGGER THIS AND AN INBOUND DIAL MAY NOT.** Andre's tenet is about what a
   * REMOTE party can cause: *"an open connection that a malicious agent can farm for."* Reviving
   * because a peer dialled us would hand that lever straight to the peer — a stranger could keep our
   * endpoints open indefinitely by poking dead sessions. A read is the OPERATOR asking, on their own
   * machine, for their own session: the same class of demand as a send, and the class the tenet
   * allows. That distinction is the whole reason this is a separate entry point rather than a
   * revival triggered from the inbound handler.
   */
  async reviveIfNeededForRead(
    agentName: string,
    sessionId: string,
  ): Promise<{ ok: true } | { ok: false; reason: string; guidance?: string }> {
    const record = this.#ctx.queries.getSessionRecord(agentName, sessionId);
    if (!record) return { ok: false, reason: "session_not_found" };
    if (record.status === "active" && this.#ctx.activeNodes.has(this.#ctx.sessionKey(agentName, sessionId))) return { ok: true };
    // Reading the transcript of an ended session is normal and must keep working — the CALLER does
    // not treat this refusal as an error, it just reads what is stored. What must not happen is the
    // read bringing the session back: the receipt is issued and the identity is gone.
    const revived = await this.reviveSessionNode(agentName, sessionId);
    if (!revived.ok) {
      // review MEDIUM-4: the absence of a success line was the only signal that a session could not
      // come back. `session_identity_lost` is the one an operator most needs, and it was generated
      // and destroyed one stack frame later with nothing written down.
      this.#ctx.logger.info("session.revive.declined", {
        agentName,
        sessionId,
        previousStatus: record.status,
        trigger: "read",
        reason: revived.reason,
      });
      return revived;
    }

    this.#ctx.logger.info("session.revived.on_demand", {
      agentName,
      sessionId,
      previousStatus: record.status,
      trigger: "read",
    });
    // Fetch what is waiting NOW. Review MEDIUM-5 corrected the claim this used to make: the drain
    // runs off the AGENT's standing receiver, not the session node, and the 5-minute backstop would
    // have delivered this content anyway. So this is an accelerator, not a rescue — worth having,
    // and worth describing accurately. (The send path deliberately does not fire one: the same
    // backstop covers it, at a cost of at most one interval.)
    this.#ctx.park.fireParkedDrain(agentName, "session_revived");
    return { ok: true };
  }

  #insertSessionRow(
    sessionId: string,
    agentName: string,
    counterpartyPubkey: string,
    status: "active" | "sealed" | "interrupted",
  ): boolean {
    if (!this.#db) return false;
    const now = Date.now();
    try {
      /**
       * ⚠️ THE SESSION'S STARTING POINT GOES IN AT INSERT — `DOD-M15-SELFCHAIN-1`.
       *
       * It is recorded before this row exists (the session open needs it before the node is built),
       * so an UPDATE at that moment has nothing to match. Writing it here is what puts it on disk,
       * and on disk is what lets the chain be resumed after a restart. `null` when nothing recorded
       * one, which is a session whose sends will be refused by name rather than silently unlinked.
       */
      const genesis = this.#ctx.leafRecords.genesisFor(agentName, sessionId);
      this.#db
        .prepare(
          `INSERT INTO sessions
           (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, genesis_prev_root)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(sessionId, this.#ctx.requireAgentId(agentName), counterpartyPubkey, status, now, now,
             genesis ? Buffer.from(genesis) : null);
      return true;
    } catch (err: unknown) {
      // D4 review F2: this helper serves the CREATE/ACCEPT paths (and interrupt-restore) — the old
      // event name `session.interrupt.db.write.failed` steered diagnosis to the interrupt path only.
      this.#ctx.logger.error("session.row.write.failed", {
        sessionId,
        agentName,
        status,
        error: err instanceof Error ? err.message : String(err),
      });
      return false;
    }
  }

  /** CC-5/F21: unilaterally mark a session locally-terminal ("abandoned") — retire its live node and
   *  set the DB status, with NO bilateral seal (a dead half-open handshake has nothing to notarize).
   *  Used by cello_close_session { force } and the dead-half-open reaper. Idempotent: a missing/already-
   *  abandoned session is a no-op. Resolves true iff the status flip was actually written (CC-10
   *  reviewer LOW: callers must not report a reap as successful when the write failed). */
  async abandonSession(agentName: string, sessionId: string): Promise<boolean> {
    // Status flip FIRST and synchronous (before the async node teardown yields), so a non-awaited
    // reaper call from a read path takes effect for the SAME read (the DB is updated before the await).
    const flipped = this.updateSessionStatus(agentName, sessionId, "abandoned");
    await this.retireSessionNode(agentName, sessionId);
    return flipped;
  }

  updateSessionStatus(
    agentName: string,
    sessionId: string,
    status: "active" | "sealed" | "interrupted" | "abandoned",
    // DOD-CAP-SELF-HEAL-1: who caused an interruption, when this call is the one causing it.
    // Omitting it leaves the column NULL, which the acceptance bound reads as the counterparty's —
    // so a LOCAL teardown that forgets to say so is charged to the peer. That is exactly how the
    // operator's own kill switch (`cello_set_agent_offline` → destroySessionNode) was locking out
    // a counterparty who had done nothing.
    interruptedBy?: "local",
  ): boolean {
    if (!this.#db) return false;
    /**
     * DOD-M12B-SESSION-SEED-1 (review F2) — the identity dies on terminal INTENT, not on a
     * successful UPDATE.
     *
     * The first build destroyed the seed only after the write landed. `#requireAgentId` THROWS for
     * a retired agent, so every terminal write for a revoked agent's sessions fell into the catch
     * and kept its transport identity for the life of the process — an identity whose agent has
     * just been revoked in the directory, held with nothing reporting it, and REVIVAL-BOUND-1's
     * sweep excludes retired agents so nothing else closed it either. The same held for a
     * `session.status.write.missed` and for any DB error.
     *
     * Coupling a security teardown to a database write is backwards: the write can fail, and the
     * failure is exactly when we least want a live key lying around. So it runs FIRST and
     * unconditionally, and if the write then fails the session is one we can no longer revive —
     * which is the safe direction, and is reported loudly below rather than inferred from the
     * absence of a debug line.
     */
    if (status === "sealed" || status === "abandoned") {
      this.destroySessionSeed(agentName, sessionId);
      // DOD-M15-DIVERGE-1: divergence stops being true HERE and only here. It used to be dropped by
      // `#evictSessionCaches` on every node teardown — including the one that writes `interrupted`,
      // which is a status the seal gate still acts on, so the fact was forgotten while it was still
      // load-bearing. A terminal status is the one point at which no future close can be refused,
      // so the flag has nothing left to protect.
      this.#ctx.records.clearDivergedMemo(agentName, sessionId);
      // DURABLE too (DOD-M15-DIVERGE-DURABLE-1) — otherwise a sealed session comes back after a
      // restart still carrying a refusal for a close that can no longer happen.
      // (agent_id, session_id) — see markSessionDiverged. Unkeyed, one side sealing cleared the
      // OTHER side's divergence on a loopback session.
      this.#db
        ?.prepare("UPDATE sessions SET diverged_at = NULL WHERE agent_id = ? AND session_id = ?")
        .run(this.#ctx.requireAgentId(agentName), sessionId);
    }
    // THE TERMINAL GUARD LIVES HERE, not in one wrapper, because there are three writers of
    // "sealed": markSealed, destroySessionNode, and retireSession on the witnessed-submit path.
    // Guarding only the wrapper asserts the invariant in a test while two other paths still break
    // it.
    //
    //   abandoned → sealed  REFUSED. A force-abandon is the documented way to give up a receipt.
    //     A certificate arriving afterwards must not silently overturn the operator's decision. The
    //     certificate is still stored by recordSealCertificate and stays retrievable.
    //   sealed → sealed     REFUSED. Nothing to write, and re-running the terminal disposition
    //     hooks for a no-op should not be reported as a status that landed.
    if (status === "sealed") {
      const current = this.#ctx.queries.getSessionRecord(agentName, sessionId)?.status;
      if (current === "abandoned" || current === "sealed") {
        this.#ctx.logger.info("session.seal.status.not_written", {
          agentName, sessionId, currentStatus: current,
          impact: current === "abandoned"
            ? "a certificate arrived for a session the operator force-abandoned; it is stored and retrievable, but the row keeps saying abandoned"
            : "already sealed — nothing to write",
        });
        return false;
      }
      if (current === undefined) {
        // ORDINARY, not an error. recordSealCertificate documents this case: the seal can arrive
        // before the row is persisted. Falling through would emit `session.status.write.missed` at
        // ERROR level for a shape the system expects.
        this.#ctx.logger.info("session.seal.status.no_row", {
          agentName, sessionId,
          impact: "no session row yet — the certificate is still recorded and retrievable",
        });
        return false;
      }
    }
    const now = Date.now();
    try {
      const res = this.#db
        .prepare(
          // DOD-M12B-REVIVAL-BOUND-1: this is the FOURTH writer of `status = 'interrupted'`, and
          // until now the only one that wrote no `interrupted_at`. That is where Entry 41's two
          // timestamp-less rows came from, and a row with no timestamp has no revival bound that
          // can be evaluated. `COALESCE` matches the three sibling producers: the FIRST
          // interruption is the clock, so re-entering the status cannot push the deadline out.
          status === "interrupted"
            ? (interruptedBy === undefined
              ? "UPDATE sessions SET status = ?, updated_at = ?, interrupted_at = COALESCE(interrupted_at, ?) WHERE agent_id = ? AND session_id = ?"
              : "UPDATE sessions SET status = ?, updated_at = ?, interrupted_at = COALESCE(interrupted_at, ?), interrupted_by = 'local' WHERE agent_id = ? AND session_id = ?")
            : (interruptedBy === undefined
              ? "UPDATE sessions SET status = ?, updated_at = ? WHERE agent_id = ? AND session_id = ?"
              : "UPDATE sessions SET status = ?, updated_at = ?, interrupted_by = 'local' WHERE agent_id = ? AND session_id = ?"),
        )
        .run(
          ...(status === "interrupted"
            ? [status, now, new Date(now).toISOString(), this.#ctx.requireAgentId(agentName), sessionId]
            : [status, now, this.#ctx.requireAgentId(agentName), sessionId]),
        ) as unknown as { changes?: number | bigint };
      // "Did not throw" is NOT "landed". An UPDATE whose WHERE matches no row — a wrong agent_id, a
      // session_id with no row — succeeds silently and changes nothing. Reporting that as a written
      // status flip is what let a disposition hook delete a live session's content, so the row count
      // is the answer to both questions.
      const landed = Number(res?.changes ?? 0) > 0;
      if (!landed) {
        this.#ctx.logger.error("session.status.write.missed", {
          sessionId,
          status,
          agentName,
          impact: (status === "sealed" || status === "abandoned")
            ? "no session row matched — the status was NOT changed and no disposition was run, AND "
              + "this session's transport identity has already been destroyed, so it can no longer "
              + "be revived even though its row still says it is open"
            : "no session row matched — the status was NOT changed and no disposition was run",
        });
        return false;
      }
      // DOD-RETRYQ-STRAND-1: only AFTER the status write actually landed. Disposing of durable
      // state on the strength of a write that did not land would discard content while the session
      // is still, on disk, drainable. 'interrupted' and 'seal_interrupted_pending' are deliberately
      // NOT terminal — both can still complete, and reaping them would destroy live content.
      if (status === "sealed" || status === "abandoned") {
        // DOD-M12B-STRAND-1: held frames outlive the chain that could have carried them.
        //
        // Once a session is terminal, `ingestReceivedContent` (in `session-content-ingest.ts`)
        // refuses it — and #releaseHeld is only
        // reachable from ingest — so no code path that exists can ever release a held frame again.
        // Left alone the rows sit on disk, unreachable by any surface, while the teardown alarm
        // reports `lost: 0`: a success message for content that has just become permanently
        // unreadable. The annex is the store built for exactly this shape.
        this.#ctx.held.annexHeldContentOnTerminal(agentName, sessionId, status);
        try {
          this.#ctx.onSessionTerminal?.(sessionId, status);
        } catch (hookErr: unknown) {
          // The status flip is the caller's contract and has already succeeded; a failing
          // disposition must not turn it into a reported failure. Named so the strand it leaves
          // behind is attributable rather than mysterious.
          this.#ctx.logger.error("session.terminal.disposition.failed", {
            sessionId,
            status,
            error: hookErr instanceof Error ? hookErr.message : String(hookErr),
            impact: "durable state keyed to this session was not disposed of and may strand",
          });
        }
      }
      return true;
    } catch (err: unknown) {
      // CC-5 (reviewer F-2): status-agnostic event + the actual target status in context — this method
      // now writes "abandoned" too, so labeling every failure "interrupt" was misleading.
      this.#ctx.logger.error("session.status.write.failed", {
        sessionId,
        status,
        error: err instanceof Error ? err.message : String(err),
      });
      return false;
    }
  }
}
