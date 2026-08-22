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

  constructor(opts: {
    sessionId: string;
    allowedPeerId: string | null;
    logger: Logger;
  }) {
    this.#sessionId = opts.sessionId;
    this.#allowedPeerId = opts.allowedPeerId;
    this.#logger = opts.logger;
  }

  /** Update the allowed Peer ID (called when standing receiver is claimed). */
  setAllowedPeer(peerId: string): void {
    this.#allowedPeerId = peerId;
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
