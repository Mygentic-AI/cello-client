/**
 * CELLO Daemon — SessionConnectionGater
 *
 * Implements the libp2p ConnectionGater interface to enforce per-session
 * peer allowlists on ephemeral session nodes.
 *
 * Two modes:
 *   1. Session node gater: allows exactly one counterparty Peer ID.
 *      Created with the counterparty's Peer ID at session node creation.
 *   2. Standing receiver gater: created with no allowed peer, which admits
 *      NOBODY inbound (DOD-M15-ASSIGN-1 — it used to admit everyone) while
 *      still permitting the outbound errands the receiver doubles as a dialer
 *      for. Call setAllowedPeer() before handing the node's multiaddr to the
 *      directory (AC-015); that is what opens the door, to exactly one peer.
 *   3. Directory node gater: delegates to DirectoryPeerIdProvider.
 *      Allows only known directory Peer IDs (MANIFEST-002 fills the real set).
 *
 * The gater uses denyInboundConnection (before Noise handshake) to reject
 * unexpected peers as early as possible. Since PeerId is not yet known at
 * that point, we use denyInboundEncryptedConnection (after Noise, before muxer)
 * which has the PeerId and still occurs before any streams are opened.
 *
 * Observability: session.node.connection.rejected (WARN) is logged with
 * sessionId, attemptedPeerId, and expectedPeerId.
 */

import type { ConnectionGater, MultiaddrConnection } from "@libp2p/interface";
import type { PeerId } from "@libp2p/interface";
import type { Logger } from "./types.js";

/**
 * Interface for providing directory Peer IDs to the directory-facing node gater.
 * Stub for DAEMON-002: MANIFEST-002 replaces with manifest-backed implementation.
 */
export interface DirectoryPeerIdProvider {
  isDirectoryPeer(peerId: string): boolean;
}

/** Permissive stub: allows all peers. Used for directory node in DAEMON-002. */
export class PermissiveDirectoryPeerIdProvider implements DirectoryPeerIdProvider {
  isDirectoryPeer(_peerId: string): boolean {
    return true;
  }
}

/** Restrictive stub: denies all peers. Used in unit tests (AC-016). */
export class EmptyDirectoryPeerIdProvider implements DirectoryPeerIdProvider {
  isDirectoryPeer(_peerId: string): boolean {
    return false;
  }
}

/**
 * SessionConnectionGater — enforces a single allowed Peer ID on a session node.
 *
 * Starts CLOSED to inbound (allowedPeerId = null) for the standing receiver;
 * setAllowedPeer(initiatorPeerId) names the one peer that may dial, and is
 * called before the node's multiaddr is returned to the caller (AC-015).
 */
export class SessionConnectionGater implements ConnectionGater {
  #allowedPeerId: string | null;
  /**
   * M7 DOD-SPINE-6 / DOD-NAT-REACHABILITY-1: additional peers the session node may
   * connect to OUTBOUND only. Originally a single slot for the relay witness
   * (Structure-2 hash submit); now a SET, because the node also dials independent
   * relays — its own reservation relays, and the relay embedded in the
   * counterparty's /p2p-circuit address (which rides the FROST-signed assignment,
   * so it is authorized by the same rail as the assigned witness). Kept
   * OUTBOUND-only so the INBOUND counterparty-only invariant (INV-5 — a session
   * node admits exactly one counterparty) is fully preserved.
   */
  readonly #allowedOutboundPeerIds = new Set<string>();
  readonly #sessionId: string;
  readonly #logger: Logger;

  /**
   * Is this node still acting as a STANDING RECEIVER, whose outbound dials are unrestricted?
   *
   * DOD-M15-ASSIGN-1 review F2. The outbound carve-out originally keyed off `#allowedPeerId ===
   * null`, which broke the moment `admitInboundPeer` narrowed the inbound gate at offer time: the
   * receiver was still the daemon's general-purpose dialer, but its outbound gate had silently
   * closed to everything except the named dialer and the reservation relays.
   *
   * What that cost, concretely: the content-park deposit/pull and the restart-seal submission both
   * dial relays that are NOT on the reservation list — the second one persisted from an EARLIER
   * session. So an agent that merely RECEIVED one inbound offer would quietly stop being able to
   * submit a seal, and the operator would see `relay_unavailable` — a transport label for what was
   * actually a local gater decision. A seal leaf that does not land is not a papercut.
   *
   * So the two things are now tracked separately: narrowing WHO MAY DIAL IN (INV-5) does not
   * revoke this node's own right to dial out. Only promotion into a session does that.
   */
  #standingReceiverOutbound: boolean;

  /**
   * The relays this receiver currently holds a live circuit reservation with. Empty by default.
   *
   * Review N3. The inbound AutoNAT carve-out below first keyed on `#allowedOutboundPeerIds`, and
   * that set is populated from the relay peer ids **the directory hands out at signaling-auth
   * time** — cumulatively, including relays whose reservation never completed. In a unit whose
   * entire threat model is "one compromised directory", that handed the adversary back a narrow
   * inbound foothold: name a relay, never complete a reservation, and dial in anyway.
   *
   * Entries added ONLY when a reservation actually succeeded is the honest version of the
   * justification the carve-out's comment makes — "a peer this node already dials and holds a
   * reservation with" — rather than a set that merely tends to contain those.
   *
   * 032-RELAYSPREAD widened this from ONE peer to a set, because the receiver now holds a
   * reservation with every relay that will grant one. **The BOUND did not widen with it, and that
   * is the security-sensitive part**: membership is still "this relay's own reservation is
   * confirmed held", never "this relay is in the pool". Widening it to the candidate list would
   * let a directory that merely NAMES a relay dial in behind the gate — the exact failure the
   * single-relay version was written to prevent, multiplied by the size of the pool.
   */
  readonly #reservedRelayPeerIds = new Set<string>();

  constructor(opts: {
    sessionId: string;
    allowedPeerId: string | null;
    logger: Logger;
  }) {
    this.#sessionId = opts.sessionId;
    this.#allowedPeerId = opts.allowedPeerId;
    // A gater built with no named peer is a standing receiver; one built naming its counterparty is
    // a session node, which has never been allowed to dial anywhere but its counterparty and relays.
    this.#standingReceiverOutbound = opts.allowedPeerId === null;
    this.#logger = opts.logger;
  }

  /**
   * PROMOTION — this node is now a session node serving exactly this counterparty.
   *
   * Narrows inbound AND ends the standing-receiver outbound latitude: from here the node may dial
   * only its counterparty and the relays explicitly added to the outbound allowlist.
   */
  setAllowedPeer(peerId: string): void {
    this.#allowedPeerId = peerId;
    this.#standingReceiverOutbound = false;
  }

  /**
   * DOD-M15-ASSIGN-1 — name the one peer that may dial IN, without promoting the node.
   *
   * Used when a `session_offer` names the initiator, before any assignment exists. The node is
   * still the daemon's general-purpose dialer at this point, so its outbound latitude is untouched;
   * see `#standingReceiverOutbound`.
   */
  admitInboundPeer(peerId: string): void {
    this.#allowedPeerId = peerId;
  }

  /**
   * Return to admitting NOBODY inbound — the resting state of an unclaimed receiver.
   *
   * DOD-M15-OFFER-SIGNED-1 review F4: when an offer is refused after the gate was already narrowed
   * to the peer it named, leaving that peer admitted means the code has declared someone
   * unauthorised and left the door open to exactly them. Outbound latitude is untouched; this node
   * is still the daemon's general-purpose dialer.
   */
  closeInbound(): void {
    this.#allowedPeerId = null;
  }

  /**
   * Record the relays this receiver holds LIVE circuit reservations with — the only peers that earn
   * the inbound AutoNAT carve-out.
   *
   * REPLACES the set rather than adding to it. A relay absent from `peerIds` loses its carve-out in
   * the same call that notices the reservation is gone, so the bound stays "holds one now" and
   * cannot drift into "granted one once". Pass `[]` when nothing is held.
   */
  setReservedRelayPeers(peerIds: readonly string[]): void {
    this.#reservedRelayPeerIds.clear();
    for (const peerId of peerIds) this.#reservedRelayPeerIds.add(peerId);
  }

  /**
   * M7 DOD-SPINE-6: permit an OUTBOUND connection to a relay peer (the assigned
   * witness, a reservation relay, or the relay inside the counterparty's circuit
   * address — all authorized by the signed assignment / directory rail). ADDITIVE:
   * each call widens the outbound set only. Does NOT widen the inbound allowlist.
   */
  setAllowedOutboundPeer(peerId: string): void {
    this.#allowedOutboundPeerIds.add(peerId);
  }

  /**
   * DOD-M15-FRAME-1: is this peer on the OUTBOUND allowlist?
   *
   * Read by the promotion-time eviction sweep, which disconnects peers that attached before the
   * gate narrowed — libp2p does not re-run a gater against connections that already exist. Relay
   * peers sit on this list because reservation refreshes ride them, and hanging one up would cost
   * the agent its inbound reachability to remove a peer that cannot speak the content protocol
   * anyway. Exposed as a question rather than by handing out the set, so the sweep cannot widen it.
   */
  isAllowedOutboundPeer(peerId: string): boolean {
    return this.#allowedOutboundPeerIds.has(peerId);
  }

  getSessionId(): string {
    return this.#sessionId;
  }

  getAllowedPeerId(): string | null {
    return this.#allowedPeerId;
  }

  /**
   * denyInboundEncryptedConnection — called after Noise handshake, before muxer.
   * This is the enforcement point for inbound connections: PeerId is known here.
   * Return true to DENY the connection.
   */
  denyInboundEncryptedConnection(peerId: PeerId, _maConn: MultiaddrConnection): boolean {
    return this.#denyIfNotAllowed(peerId, "inbound");
  }

  /**
   * denyOutboundEncryptedConnection — symmetric gate for outbound connections.
   * Session nodes should only connect to the designated counterparty.
   * Return true to DENY the connection.
   */
  denyOutboundEncryptedConnection(peerId: PeerId, _maConn: MultiaddrConnection): boolean {
    // Relay peers are an OUTBOUND-only allowance (the session node dials them).
    if (this.#allowedOutboundPeerIds.has(peerId.toString())) {
      return false; // allow
    }
    // Review F2: a standing receiver is also the daemon's dialer for errands that belong to no
    // session — content-park deposit/pull, restart-seal submission to a PRIOR session's relay.
    // Those targets are on no allowlist and cannot be, since they are chosen per errand.
    if (this.#standingReceiverOutbound) {
      return false; // allow — this node chose the dial; INV-5 governs who comes IN
    }
    return this.#denyIfNotAllowed(peerId, "outbound");
  }

  #denyIfNotAllowed(peerId: PeerId, direction: "inbound" | "outbound"): boolean {
    /**
     * DOD-M15-ASSIGN-1 — `null` ADMITS NOBODY INBOUND. It used to admit everyone, both ways.
     *
     * A standing receiver is built with `allowedPeerId: null` because the counterparty is unknown
     * until a session exists. Reading that as "allow all" is what put a real open door on every
     * operator's machine: a stranger could dial the receiver, hold the connection through
     * promotion — libp2p never re-runs a gater against a live connection — and then speak the
     * content protocol the moment it activated.
     *
     * NOBODY LEGITIMATELY DIALS AN UNCLAIMED RECEIVER. An inbound session begins with the directory
     * sending a `session_offer` that NAMES `initiator_session_peer_id`, and the responder narrows
     * the gate to that peer BEFORE it advertises its own address in `session_offer_accept`. So by
     * the time the initiator can know where to dial, the gate already names them. The window this
     * closes is the one where the receiver is up and no offer has arrived — where the only dialer
     * is, by construction, someone who was not invited.
     *
     * OUTBOUND STAYS OPEN WHILE UNCLAIMED, and that asymmetry is deliberate, not an oversight. The
     * standing receiver is also the daemon's general-purpose dialer for errands that belong to no
     * session — the content-park deposit and pull against the relay (MSG-001-3b). Those dials are
     * this agent choosing where to go; INV-5 governs who may come IN. Denying them would have cost
     * message parking to close a door nobody was standing at.
     */
    /**
     * Review F7: a RESERVATION RELAY dialling back is infrastructure, not a stranger.
     *
     * The standing receiver runs the libp2p AutoNAT *client*: it asks connected peers to dial its
     * observed address so it can learn whether it is publicly reachable. Its connected peers are
     * its own reservation relays. That dial-back arrives INBOUND, and the outbound allowlist was
     * only consulted on the outbound path — so it was refused, and refused repeatedly.
     *
     * Two costs, and the second is the quiet one. It logged `connection.rejected` on every probe
     * cycle, on the one line that is supposed to mean a stranger tried an unclaimed receiver — a
     * signal that fires on the normal case is not a signal. And AutoNAT answers repeated dial
     * failures by REMOVING the observed address, so an agent's own public address never becomes
     * verified and never reaches `listenAddresses()` — the array shipped in `session_offer_accept`.
     * We would have been advertising a shorter address list and blaming the network.
     *
     * These are peers this node already dials and holds reservations with. Admitting their
     * dial-back grants nothing it did not already have.
     *
     * SCOPED TWICE, and each scope closed a hole the previous version had.
     *
     * To the STANDING-RECEIVER ROLE: the first attempt admitted relays inbound on every gater, which
     * breaks INV-5 — a SESSION node admits exactly one counterparty, and the existing tests say so
     * in those words. A promoted node has no AutoNAT probe to answer, so it needs nothing here.
     *
     * To THE RELAYS HOLDING A LIVE RESERVATION (`#reservedRelayPeerIds`), not the outbound
     * allowlist. That allowlist is built from relay peer ids the DIRECTORY supplies, cumulatively,
     * including ones whose reservation never completed — so keying on it let a compromised
     * directory name a relay and dial in without ever holding a reservation. In a unit whose threat
     * model is exactly that adversary, the outbound allowlist was the wrong thing to trust, and it
     * still is: this set holds only relays whose own reservation was confirmed, however many relays
     * the pool names.
     */
    if (direction === "inbound" && this.#standingReceiverOutbound && this.#reservedRelayPeerIds.has(peerId.toString())) {
      return false; // allow — a relay we hold a live reservation with, answering a probe we started
    }
    if (this.#allowedPeerId === null) {
      if (direction === "outbound") return false; // allow — we chose this dial; INV-5 is inbound-only
      this.#logger.warn("session.node.connection.rejected", {
        sessionId: this.#sessionId,
        attemptedPeerId: peerId.toString(),
        expectedPeerId: "(none — receiver unclaimed)",
        impact:
          "a peer dialled a standing receiver that no session has claimed; nothing invited it, so it was refused before the muxer and it learned nothing",
      });
      return true; // DENY
    }
    const attemptedPeerId = peerId.toString();
    if (attemptedPeerId === this.#allowedPeerId) {
      return false; // allow
    }
    this.#logger.warn("session.node.connection.rejected", {
      sessionId: this.#sessionId,
      attemptedPeerId,
      expectedPeerId: this.#allowedPeerId,
    });
    return true; // deny
  }
}

/**
 * DirectoryConnectionGater — enforces directory-only connections on the
 * directory-facing node. Delegates to DirectoryPeerIdProvider.
 *
 * Logs session.node.connection.rejected (using sessionId='directory') when
 * a non-directory peer is denied.
 */
export class DirectoryConnectionGater implements ConnectionGater {
  readonly #provider: DirectoryPeerIdProvider;
  readonly #logger: Logger;

  constructor(provider: DirectoryPeerIdProvider, logger: Logger) {
    this.#provider = provider;
    this.#logger = logger;
  }

  denyInboundEncryptedConnection(peerId: PeerId, _maConn: MultiaddrConnection): boolean {
    return this.#denyIfNotDirectory(peerId);
  }

  denyOutboundEncryptedConnection(peerId: PeerId, _maConn: MultiaddrConnection): boolean {
    return this.#denyIfNotDirectory(peerId);
  }

  #denyIfNotDirectory(peerId: PeerId): boolean {
    const peerIdStr = peerId.toString();
    if (this.#provider.isDirectoryPeer(peerIdStr)) {
      return false; // allow
    }
    this.#logger.warn("session.node.connection.rejected", {
      sessionId: "__directory_facing__",
      attemptedPeerId: peerIdStr,
      expectedPeerId: "known_directory_peer",
    });
    return true; // deny
  }
}
