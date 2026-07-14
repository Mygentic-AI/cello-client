/**
 * CELLO Transport — types.ts
 *
 * Defines the CelloNode interface, CreateNodeOptions, StreamHandler, and structured
 * error types for the @cello-protocol/transport package.
 *
 * ARCHITECTURE NOTE (ADR-0001):
 * The KeyProvider is stored on CelloNode for use by higher layers (MSG-001 signing)
 * but is NEVER passed into libp2p's Noise handshake or peer identity. libp2p generates
 * its own internal Ed25519 keypair. This means:
 *   - node.getPeerId() returns the TRANSPORT peer ID (libp2p-managed)
 *   - KeyProvider.getPublicKey() returns K_local (CELLO signing identity)
 *   - These are always different keys serving different trust claims.
 */

import type { KeyProvider } from "@cello-protocol/crypto";
import type { ConnectionGater, Stream } from "@libp2p/interface";
import type { Dialability, Unsubscribe } from "./autonat.js";

// ─── Options ────────────────────────────────────────────────────────────────

export interface CreateNodeOptions {
  /**
   * The CELLO KeyProvider holding K_local (Ed25519 signing key).
   * Stored on the node for higher-layer use (MSG-001). NOT wired into libp2p
   * transport identity — see ADR-0001.
   */
  keyProvider: KeyProvider;
  /**
   * libp2p listen multiaddrs. Use '/ip4/127.0.0.1/tcp/0' for ephemeral port.
   */
  listenAddresses: string[];
  /**
   * Optional announce multiaddrs. When set, these are advertised to peers instead
   * of (or in addition to) the addresses derived from listenAddresses. Required when
   * the node is behind NAT/EIP and the listen address is a private IP (e.g. EC2
   * instance with an Elastic IP — the EIP is not on the interface, so libp2p would
   * announce the private IP without this override).
   */
  announceAddresses?: string[];
  /**
   * Optional pre-generated transport private key (raw Ed25519 seed, 32 bytes).
   * When provided, the node uses this key for its libp2p Peer ID instead of
   * generating a fresh one. Use this for services (directory, relay) that need
   * a stable Peer ID across restarts.
   */
  transportPrivateKey?: Uint8Array;
  /**
   * Optional libp2p ConnectionGater. When provided, the gater is installed on
   * the node to filter incoming and outgoing connections. Used by DAEMON-002
   * to enforce per-session peer allowlists on ephemeral session nodes.
   */
  connectionGater?: ConnectionGater;
  /**
   * CELLO-M7-TRANSPORT-001 / DOD-NAT-REACHABILITY-1: the role of this node,
   * which tunes the libp2p service set:
   *   - 'session'           — ephemeral per-session dialer.
   *   - 'standing_receiver' — pre-warmed inbound receiver.
   *   - undefined           — service node (directory, relay): additionally
   *                           serves circuit-relay HOP (see relayServer).
   * AutoNAT and dcutr are included for EVERY nodeType. dcutr on the standing
   * receiver is load-bearing: the inbound peer of a relayed connection is the
   * one that initiates the hole-punch upgrade.
   */
  nodeType?: "session" | "standing_receiver";
  /**
   * DOD-NAT-REACHABILITY-1: circuit-relay HOP server configuration.
   * By default HOP is served only by service nodes (nodeType === undefined) —
   * a client node must not advertise itself as a relay for strangers.
   * The CELLO relay passes `reservations` to raise the libp2p defaults, which
   * are sized for a public DHT (15 reservations, 2-minute/128-KiB connection
   * limits) and would cap CELLO's inbound reachability at toy scale.
   */
  relayServer?: {
    /** Force the HOP service on (true) or off (false) regardless of nodeType. */
    enabled: boolean;
    /** Passed through to circuitRelayServer({ reservations }). */
    reservations?: {
      maxReservations?: number;
      applyDefaultLimit?: boolean;
      reservationTtl?: number;
      defaultDurationLimit?: number;
      defaultDataLimit?: bigint;
    };
  };
  /**
   * CELLO-M7-SESSION-003 (AC-005): transport keepalive interval in milliseconds.
   * Wires libp2p's connectionMonitor pingInterval so that a counterparty that
   * vanishes WITHOUT a clean stream close (cable pulled / SIGKILL with no FIN) is
   * detected — the failed keepalive ping aborts the connection, surfacing a
   * libp2p peer:disconnect within a bounded window. This is the fourth keepalive
   * relationship (the peer↔peer SESSION connection) that the three-relationships
   * design (relay↔dir, client↔dir, client↔relay) did not cover.
   *
   * Injectable so tests can assert the dead-connection transition with a short
   * interval — no synthetic clock manipulation required. When undefined, libp2p's
   * default connectionMonitor interval applies.
   */
  keepAliveIntervalMs?: number;
}

// ─── StreamHandler ──────────────────────────────────────────────────────────

/**
 * Handler called when a remote peer opens a stream on a registered protocol.
 * The Stream object has `source` (AsyncIterable) and `sink` (async iterable consumer).
 * Use `it-length-prefixed` and `it-pipe` for framed I/O per the it-length-prefixed
 * varint-prefix convention (unsigned varint per https://github.com/multiformats/unsigned-varint).
 */
export type CelloStreamHandler = (stream: Stream) => void | Promise<void>;

// ─── CelloNode interface ─────────────────────────────────────────────────────

export interface CelloNode {
  /**
   * Start the node: begin listening on configured addresses.
   * After start(), the node is dialable by remote peers.
   */
  start(): Promise<void>;

  /**
   * Stop the node: close all streams and connections, release all resources.
   * After stop(), listenAddresses() returns [] and all operations fail with node_stopped.
   */
  stop(): Promise<void>;

  /**
   * Returns current listen multiaddrs as strings.
   * Returns [] before start() or after stop().
   */
  listenAddresses(): string[];

  /**
   * Connect to a remote peer by multiaddr string.
   * Returns the remote peer's transport PeerId as a string.
   * Fails with node_stopped if called after stop().
   */
  dial(multiaddr: string): Promise<{ peerId: string }>;

  /**
   * Register a stream handler for a protocol ID.
   * The handler is called when a remote peer opens a stream on this protocol.
   */
  handle(protocolId: string, handler: CelloStreamHandler, opts?: { maxInboundStreams?: number }): Promise<void>;

  /**
   * Open a new multiplexed stream to a connected remote peer.
   * Returns the libp2p Stream object for use with it-length-prefixed framing.
   *
   * Structured errors (thrown as plain objects):
   *   { reason: 'protocol_not_supported', protocolId, message }
   *   { reason: 'connection_lost', peerId, message }
   *   { reason: 'node_stopped', message }
   */
  newStream(peerId: string, protocolId: string): Promise<Stream>;

  /**
   * Returns the node's own transport PeerId as a string.
   * This is the libp2p-managed keypair identity, NOT derived from KeyProvider.
   * See ADR-0001.
   */
  getPeerId(): string;

  /**
   * Returns the libp2p protocol strings advertised by this node.
   * Used by tests to verify Noise is present and plaintext is absent (SI-001, SI-003).
   */
  getProtocols(): string[];

  /**
   * Returns basic info about all current connections.
   * Used by SI-001 test to verify connection-level encryption is Noise.
   * encryption is undefined when libp2p has not yet completed the security handshake.
   */
  getConnections(): Array<{ peerId: string; encryption: string | undefined }>;

  /**
   * CELLO-M7-TRANSPORT-001: true if there is at least one OPEN, non-relayed
   * (direct) connection to peerId. Used by the transport selector's dcutr path to
   * observe whether a relay-fallback connection has been hole-punch upgraded to
   * direct connectivity. A relayed connection's remote multiaddr contains
   * '/p2p-circuit'; a direct one does not.
   */
  hasDirectConnectionTo(peerId: string): boolean;

  /**
   * Subscribe to peer connect/disconnect events for observability logging.
   * Callback fires whenever a new libp2p connection is established or closed.
   */
  onPeerConnect(handler: (peerId: string) => void): void;
  onPeerDisconnect(handler: (peerId: string) => void): void;

  /**
   * Access the stored KeyProvider for higher-layer use (MSG-001 signing).
   * The transport layer itself never calls any methods on this object.
   */
  readonly keyProvider: KeyProvider;

  /**
   * CELLO-M7-TRANSPORT-001: current AutoNAT-derived dialability.
   * Returns { dialable: false, publicAddr: null } before the first probe cycle
   * completes (the conservative default that drives the relay fallback).
   */
  getDialability(): Dialability;

  /**
   * Observe dialability changes. The listener fires on each AutoNAT probe cycle
   * that changes the result. Returns an unsubscribe handle.
   */
  onDialabilityChange(listener: (d: Dialability) => void): Unsubscribe;
}

// ─── Structured error types ──────────────────────────────────────────────────

/**
 * Thrown (as a thrown plain object, not an Error instance) when a remote peer
 * does not support the requested protocol.
 */
export interface ProtocolNotSupportedError {
  reason: "protocol_not_supported";
  protocolId: string;
  message: string;
}

/**
 * Thrown when the connection to the remote peer has been lost.
 */
export interface ConnectionLostError {
  reason: "connection_lost";
  peerId: string;
  message: string;
}

/**
 * Thrown when the node has been stopped and operations are attempted.
 */
export interface NodeStoppedError {
  reason: "node_stopped";
  message: string;
}

/**
 * Thrown when the node fails to bind to a listen address.
 */
export interface ListenFailedError {
  reason: "listen_failed";
  multiaddr: string;
  message: string;
}

export type CelloTransportError =
  | ProtocolNotSupportedError
  | ConnectionLostError
  | NodeStoppedError
  | ListenFailedError;
