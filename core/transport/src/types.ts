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
import type { ResolvedConnectionMonitorConfig as ConnectionMonitorPolicy } from "./node.js";
// DOD-M15-IDLE-CONNS-1 — the sweep's report and its per-sweep census.
import type { IdleReapEvent, ConnectionCounts } from "./node.js";

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
   * AutoNAT dial-back RESPONDER (answering other peers' "can you dial me?" requests).
   * Defaults to service-node behaviour (`nodeType === undefined`), like `relayServer`.
   *
   * Set `{ enabled: false }` on any CLIENT node, INCLUDING ones that leave `nodeType` unset --
   * the directory-signaling node does exactly that, so the default alone would leave the responder
   * on. @libp2p/autonat's responder answers by calling openConnection(peer), which RETURNS AN
   * ALREADY-OPEN CONNECTION, and then closes it in a `finally`; on a client that is the connection
   * carrying directory signaling, so it dies with yamux GoAway. The PROBER half is unaffected --
   * it opens outbound streams and needs no inbound handler -- so getDialability()
   * (DOD-NAT-REACHABILITY-1) still works.
   */
  autonatResponder?: { enabled: boolean };
  /**
   * DOD-M15-RELAYONLY-1: NAT hole-punching (dcutr). Defaults to ENABLED, which is every existing
   * caller's behaviour and the right default — a direct connection is faster and cheaper than a
   * relayed one.
   *
   * ⚠️ Set `{ enabled: false }` on a node whose whole purpose is NOT to be directly reachable.
   * dcutr's job is to UPGRADE a relayed connection to a direct one, and the note beside its
   * registration says the standing receiver is *"the inbound side of a relayed connection, and the
   * inbound side starts the upgrade"*. So a relay-only agent would route its session over the relay
   * exactly as asked, and then hole-punch its way to a direct connection anyway — **disclosing the
   * very address the setting exists to hide, with no test able to see it, because nothing observes a
   * live upgrade.**
   *
   * Suppressing the published address is therefore not sufficient on its own: the address a peer
   * cannot be told, a hole-punch can still reveal.
   */
  holePunch?: { enabled: boolean };
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
  /**
   * DOD-RELAY-KEEPALIVE-1: policy for libp2p's connection monitor, which is on by default on
   * every node and, by default, ABORTS a whole connection after one ping that misses an
   * AdaptiveTimeout whose floor is 5 seconds.
   *
   * That is the prime suspect for the client↔relay link dying every 60-90 seconds on 2026-08-04:
   * the link was healthy, the ping merely slow (a WAN hop, a busy event loop, a relayed stream),
   * and the monitor severs on one miss.
   *
   * ATTRIBUTION IS NOT SETTLED, and this comment must not read as though it were. The incident's
   * error text — "The operation was aborted due to timeout" — is Node's generic message for ANY
   * timed-out AbortSignal, and this dependency tree has at least ten on the relay path (libp2p's
   * registrar, upgrader, connection negotiation and close, dial-queue, connection-pruner, plus
   * circuit-relay-v2's listen/reservation/hop timeouts). The observed symptom is *consistent
   * with* the connection monitor; which timeout actually fired is unresolved until
   * DEBUG=libp2p:connection-monitor* runs against the live relay. The policy below is worth
   * having either way — no timeout on a healthy link should cost the whole connection.
   *
   * Defaults live in resolveConnectionMonitorConfig. Override per node when one link needs a
   * different policy from the rest: the relay's client links must never be severed on a slow
   * ping (liveness there is the reservation TTL's job), while a session node keeps the abort so
   * counterparty_liveness still reaches 'gone' when a peer vanishes without a FIN.
   */
  connectionMonitor?: {
    /**
     * false → a failed ping is logged and the connection is left alone. Pinging CONTINUES: the
     * traffic doubles as a keepalive against network-level reapers (enterprise firewalls, NAT
     * conntrack). Default true — do not turn this off on a node whose peer liveness matters.
     */
    abortConnectionOnPingFailure?: boolean;
    /**
     * Floor for the adaptive ping deadline, replacing libp2p's 5s. Raise it for links whose
     * round trip is genuinely slow before concluding the peer is dead.
     */
    pingTimeoutMinMs?: number;
  };

  /**
   * DOD-M15-IDLE-CONNS-1 — override the DECLARED connection-manager limits for this node.
   *
   * Omit it and the declared block applies. Values live in `resolveConnectionLimits`; they are
   * libp2p's own defaults adopted deliberately, so this changes nothing today and makes a future
   * libp2p bump visible instead of silent. A relay legitimately carries far more connections than
   * an operator's laptop, which is what the override is for.
   */
  connectionLimits?: {
    maxConnections?: number;
    inboundConnectionThreshold?: number;
    maxIncomingPendingConnections?: number;
    inboundUpgradeTimeout?: number;
  };

  /**
   * DOD-M15-IDLE-CONNS-1 — run the idle-connection sweep on this node.
   *
   * OPT-IN, and deliberately so: the node that needs it is the one accepting inbound dials from
   * peers it did not choose (the standing receiver). A directory-signaling node's connections are
   * ones it dialled, and a relay's clients are governed by the reservation TTL — sweeping either
   * would hang up links their own subsystem is responsible for.
   */
  idleConnectionReaper?: {
    /**
     * How long a connection that has NEVER carried a stream may live. Default
     * `IDLE_CONNECTION_GRACE_MS`. NOT an idle timer: a connection that has ever spoken is never a
     * candidate again, because CELLO's per-message streams leave a busy session at zero streams
     * almost all of the time.
     */
    graceMs?: number;
    /** How often to look. Default `IDLE_CONNECTION_SWEEP_MS`. */
    sweepIntervalMs?: number;
    /**
     * Told when a connection is hung up, and when a sweep or a hang-up FAILS. Without it the reaper
     * is a guard nobody hears — the operator's next send returns `no_connection` and nothing names
     * the local timer that caused it.
     */
    onReaped?: (event: IdleReapEvent) => void;
    /** Told the connection census every sweep — the count the DoD line requires before any tuning. */
    onObserved?: (counts: ConnectionCounts) => void;
  };
}

// ─── StreamHandler ──────────────────────────────────────────────────────────

/**
 * Handler called when a remote peer opens a stream on a registered protocol.
 * The Stream object has `source` (AsyncIterable) and `sink` (async iterable consumer).
 * Use `it-length-prefixed` and `it-pipe` for framed I/O per the it-length-prefixed
 * varint-prefix convention (unsigned varint per https://github.com/multiformats/unsigned-varint).
 *
 * `remotePeerId` (M12 anti-entropy): the CONNECTION's authenticated remote PeerId
 * (`connection.remotePeer`, established by the Noise handshake) — never a wire claim. Handlers
 * that channel-bind an application-level identity to the transport identity (the AE mutual
 * handshake) MUST use this instead of any peer-supplied field. Optional second parameter, so
 * existing single-arg handlers are unaffected.
 */
export type CelloStreamHandler = (stream: Stream, remotePeerId?: string) => void | Promise<void>;

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
   *
   * `status` is the SOCKET status ('open' | 'closing' | 'closed'), which is NOT the muxer's.
   * libp2p checks the two separately when opening a stream, muxer first, so a connection can read
   * `open` here while every stream on it fails. Callers diagnosing a stream failure need this to
   * tell "dead muxer on a live socket" from "dead through" — see hangUp (DOD-M12-CONN-EVICT-1).
   */
  getConnections(): Array<{
    /** libp2p's per-CONNECTION id — a peer may hold several, and the activity bit is per connection. */
    id: string;
    peerId: string;
    encryption: string | undefined;
    remoteAddr?: string;
    status: string;
    /**
     * The MUXER's status — a different thing from `status` above, and the one the M12 Tier P5
     * failure lives in. A connection can read `status: "open"` while every stream on it fails,
     * because `newStream` checks the muxer first. `undefined` when it cannot be read; never
     * defaulted, because inventing "open" here would recreate the blindness it exists to remove.
     */
    muxerStatus?: string;
    /**
     * DOD-M15-IDLE-CONNS-1. Who dialled whom. The reaper only ever touches `inbound`: an outbound
     * connection is an errand this agent started, and hanging one up cancels our own work.
     */
    direction: "inbound" | "outbound";
    /** Epoch-ms the connection opened, from libp2p's own timeline. The reaper's clock. */
    openedAt: number;
    /** Live streams on this connection. Zero is what "authenticates to nothing" actually looks like. */
    streamCount: number;
  }>;

  /**
   * The connection-manager limits libp2p was given — the SAME object, not a rebuilt copy.
   *
   * Answerable at runtime for the reason the DoD line insists on: a cap set without measurement
   * breaks reachability, and until this existed there was no way to measure a healthy daemon's
   * connection count at all.
   */
  getConnectionLimits(): {
    maxConnections: number;
    inboundConnectionThreshold: number;
    maxIncomingPendingConnections: number;
    inboundUpgradeTimeout: number;
  };

  /**
   * Name the peers the idle sweep must never hang up — the relay this node holds a live reservation
   * with, and the peer the gate currently names (the admitted dialer, then the counterparty).
   *
   * A reservation connection is idle BY NATURE between refreshes, which is precisely the shape the
   * sweep hunts. And the node is REUSED across promotion, so without the second the sweep reaps the
   * counterparty mid-conversation. Settable rather than fixed at construction because both change.
   */
  setIdleReaperSpared(isSpared: (peerId: string) => boolean): void;

  /**
   * DOD-M12-CONN-EVICT-1: drop every connection to this peer.
   *
   * Needed because `dial()` resolves from libp2p's registry — it returns an existing connection
   * whenever one is registered for the peer and its socket status reads `open`, without inspecting
   * the muxer. A caller repairing a connection whose muxer has died must evict FIRST, or the dial
   * returns the same dead object and the repair silently accomplishes nothing.
   *
   * Resolves when no connection exists (a repair path may find it already gone).
   * Fails with { reason: 'invalid_peer_id' } if peerId does not parse.
   */
  hangUp(peerId: string): Promise<void>;

  /**
   * DOD-M15-RELAYSLOTS-1 — release the circuit RESERVATION this relay is holding for `peerId`.
   * Returns true if one was held and is now gone.
   *
   * ⚠️ **`hangUp` DOES NOT DO THIS, AND THAT IS THE WHOLE REASON THIS EXISTS.** Verified against
   * `@libp2p/circuit-relay-v2@4.2.3`: the server's `removeReservation` is called from exactly one
   * place — the catch when writing the confirmation frame fails — and there is no connection-close
   * or disconnect listener anywhere in its server. A reservation therefore survives its holder's
   * disconnect for the full `reservationTtl`, which defaults to TWO HOURS.
   *
   * The consequence, measured rather than assumed: a relay could evict a peer, watch its own ledger
   * drop, report itself well under capacity, and still be holding that reservation against libp2p's
   * 4096 limit for two hours. Every reclaim path the relay has — the grace-window revoke, the
   * reaper, the unproven-budget eviction — was freeing bookkeeping and not capacity.
   *
   * No-op on a node with no relay service, and on a peer holding no reservation.
   */
  releaseRelayReservation(peerId: string): boolean;


  /**
   * CELLO-M7-TRANSPORT-001: true if there is at least one OPEN, non-relayed
   * (direct) connection to peerId. Used by the transport selector's dcutr path to
   * observe whether a relay-fallback connection has been hole-punch upgraded to
   * direct connectivity. A relayed connection's remote multiaddr contains
   * '/p2p-circuit'; a direct one does not.
   */
  hasDirectConnectionTo(peerId: string): boolean;

  /**
   * DOD-M12B-ACK-1: how many streams for `protocolId` are currently live on the connections to
   * `peerId`, split by direction.
   *
   * libp2p caps streams PER PROTOCOL PER CONNECTION — 32 inbound, 64 outbound by default — and
   * enforces the cap after protocol negotiation has already succeeded, so a handler that forgets
   * to close its streams produces `Cannot write to a stream that is closed` on the far side and
   * nothing anywhere names the cap. Establishing that took a 6,451-record log measurement. This
   * exists so the two failure logs can carry the number instead, and so a test can assert that a
   * slot was RELEASED rather than that some particular count of messages happened to fit.
   *
   * Returns zeroes when there is no connection to the peer — "no streams" is the truthful answer
   * to "how many streams are open", and a diagnostic must never throw on the failure path it
   * exists to describe.
   */
  countProtocolStreams(peerId: string, protocolId: string): { inbound: number; outbound: number };

  /**
   * DOD-RELAY-KEEPALIVE-1: the connection-monitor policy this node is actually running.
   *
   * Answerable at runtime on purpose. The policy decides whether a slow ping costs the whole
   * connection, and getting it wrong is invisible from the outside — the node looks healthy right
   * up until it severs a link it should have kept. An operator (or a test) must be able to ask the
   * node rather than infer it from the call site that built it.
   */
  getConnectionMonitorPolicy(): ConnectionMonitorPolicy;

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
 *
 * DOD-M12B-REDIAL-1: this is `mapStreamError`'s CATCH-ALL, so it also covers a stream that failed
 * on a perfectly healthy connection. Do not treat it as "there is no connection" — that is
 * `no_connection` below, and the difference decides whether re-dialling can help.
 */
export interface ConnectionLostError {
  reason: "connection_lost";
  peerId: string;
  message: string;
}

/**
 * Thrown when there is NO open connection to the peer at all — the one condition a re-dial fixes.
 *
 * Kept distinct from `connection_lost` on purpose. Dialling in response to a stream-level failure
 * on a live connection cannot fix it, and shows the counterparty a connection request caused by a
 * defect on this side — which is the notification-storm shape DOD-M12B-REDIAL-1 exists to avoid.
 */
export interface NoConnectionError {
  reason: "no_connection";
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
