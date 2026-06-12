/**
 * CELLO Daemon — SessionConnectionGater
 *
 * Implements the libp2p ConnectionGater interface to enforce per-session
 * peer allowlists on ephemeral session nodes.
 *
 * Two modes:
 *   1. Session node gater: allows exactly one counterparty Peer ID.
 *      Created with the counterparty's Peer ID at session node creation.
 *   2. Standing receiver gater: starts OPEN (all peers allowed) because
 *      the counterparty is unknown at creation time. Call setAllowedPeer()
 *      before handing the node's multiaddr to the directory (AC-015).
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
 * Initially open (allowedPeerId = null) for the standing receiver. Close the
 * window by calling setAllowedPeer(initiatorPeerId) before returning the
 * node's multiaddr to the caller (AC-015).
 */
export class SessionConnectionGater implements ConnectionGater {
  #allowedPeerId: string | null;
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
    return this.#denyIfNotAllowed(peerId);
  }

  /**
   * denyOutboundEncryptedConnection — symmetric gate for outbound connections.
   * Session nodes should only connect to the designated counterparty.
   * Return true to DENY the connection.
   */
  denyOutboundEncryptedConnection(peerId: PeerId, _maConn: MultiaddrConnection): boolean {
    return this.#denyIfNotAllowed(peerId);
  }

  #denyIfNotAllowed(peerId: PeerId): boolean {
    // If no allowed peer set (fully open gater), allow all.
    if (this.#allowedPeerId === null) {
      return false;
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
    const peerIdStr = peerId.toString();
    if (this.#provider.isDirectoryPeer(peerIdStr)) {
      return false; // allow
    }
    this.#logger.warn("session.node.connection.rejected", {
      sessionId: "directory",
      attemptedPeerId: peerIdStr,
      expectedPeerId: "known_directory_peer",
    });
    return true; // deny
  }
}
