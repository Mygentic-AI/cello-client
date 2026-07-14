/**
 * CELLO Transport — node.ts
 *
 * createNode() and CelloNodeImpl: libp2p node bootstrap for the CELLO protocol.
 *
 * createNode() returns the node in STOPPED state — start() is a separate call.
 *
 * Stream framing: it-length-prefixed (unsigned varint prefix per multiformats spec).
 * Use lp.encode(source) / lp.decode(source) with it-pipe for composing pipelines.
 */

import { createLibp2p } from "libp2p";
import { tcp } from "@libp2p/tcp";
import { webSockets } from "@libp2p/websockets";
import { noise } from "@chainsafe/libp2p-noise";
import { yamux } from "@chainsafe/libp2p-yamux";
import { circuitRelayServer, circuitRelayTransport } from "@libp2p/circuit-relay-v2";
import { dcutr } from "@libp2p/dcutr";
import { autoNAT } from "@libp2p/autonat";
import { identify } from "@libp2p/identify";
import { generateKeyPair, generateKeyPairFromSeed } from "@libp2p/crypto/keys";
import { multiaddr } from "@multiformats/multiaddr";
import { peerIdFromString } from "@libp2p/peer-id";
import type { Libp2p, Stream, Connection, StreamHandler } from "@libp2p/interface";
import type { KeyProvider } from "@cello-protocol/crypto";
import type {
  CelloNode,
  CelloStreamHandler,
  CreateNodeOptions,
} from "./types.js";
import {
  type Dialability,
  type Unsubscribe,
  DEFAULT_DIALABILITY,
} from "./autonat.js";

// ─── Dialability helpers ──────────────────────────────────────────────────────

/**
 * Decide whether a multiaddr string represents a publicly-dialable address.
 *
 * AutoNAT confirms externally-reachable addresses. We treat an address as
 * publicly dialable when it is an IP transport address that is NOT loopback,
 * NOT in a private/link-local range, and NOT a circuit-relay address. This is
 * the same classification libp2p applies to surface externally-reachable
 * addresses via getMultiaddrs() after AutoNAT verification.
 */
function isPubliclyDialable(addr: string): boolean {
  if (addr.includes("/p2p-circuit")) return false; // relay address, not direct
  // Extract the IPv4/IPv6 host component.
  const ip4 = addr.match(/\/ip4\/([0-9.]+)/);
  const ip6 = addr.match(/\/ip6\/([0-9a-fA-F:]+)/);
  if (ip4) {
    const host = ip4[1]!;
    if (host === "127.0.0.1" || host.startsWith("127.")) return false; // loopback
    if (host.startsWith("10.")) return false; // private
    if (host.startsWith("192.168.")) return false; // private
    if (host.startsWith("169.254.")) return false; // link-local
    // 172.16.0.0 – 172.31.255.255 private range
    const m = host.match(/^172\.(\d+)\./);
    if (m) {
      const second = Number(m[1]);
      if (second >= 16 && second <= 31) return false;
    }
    if (host === "0.0.0.0") return false; // unspecified
    return true;
  }
  if (ip6) {
    const host = ip6[1]!.toLowerCase();
    if (host === "::1") return false; // loopback
    if (host.startsWith("fe80")) return false; // link-local
    if (host.startsWith("fc") || host.startsWith("fd")) return false; // unique-local
    if (host === "::") return false; // unspecified
    return true;
  }
  return false; // no IP transport component — not directly dialable
}

/** Extract the IPv4/IPv6 host component of a multiaddr string, or null. */
function extractHost(addr: string): string | null {
  const ip4 = addr.match(/\/ip4\/([0-9.]+)/);
  if (ip4) return ip4[1]!;
  const ip6 = addr.match(/\/ip6\/([0-9a-fA-F:]+)/);
  if (ip6) return ip6[1]!.toLowerCase();
  return null;
}

/**
 * Derive dialability from the node's current self-reported multiaddrs.
 *
 * Dialability MUST reflect AutoNAT dial-back confirmation, not mere
 * configuration. A node configured to listen on / announce
 * a public IP that is actually behind a firewall is NOT dialable — advertising
 * that unreachable direct address would deny service. We therefore exclude any
 * address whose host matches the node's own configured listen/announce hosts:
 * those are configured, not dial-back-confirmed. Only an address that appeared
 * dynamically (an AutoNAT-confirmed `observed` address — its host is not one we
 * configured) counts toward dialable:true.
 *
 * CELLO session and standing-receiver nodes listen on loopback
 * (/ip4/127.0.0.1/tcp/0), so in practice the only public address that can appear
 * in getMultiaddrs() is one AutoNAT confirmed — this exclusion simply makes the
 * invariant explicit and robust for any future public-bound node.
 */
function deriveDialability(addrs: string[], configuredHosts: ReadonlySet<string>): Dialability {
  const publicAddr =
    addrs.find((a) => {
      if (!isPubliclyDialable(a)) return false;
      const host = extractHost(a);
      // A public address on a host we explicitly configured is not proof of
      // external reachability — exclude it (AutoNAT must confirm an observed addr).
      return host !== null && !configuredHosts.has(host);
    }) ?? null;
  return { dialable: publicAddr !== null, publicAddr };
}

// ─── CelloNodeImpl ───────────────────────────────────────────────────────────

class CelloNodeImpl implements CelloNode {
  readonly #libp2p: Libp2p;
  readonly keyProvider: KeyProvider;
  // Dialability observable, updated on each AutoNAT probe cycle (surfaced by
  // libp2p as a 'self:peer:update' event).
  #dialability: Dialability = { ...DEFAULT_DIALABILITY };
  readonly #dialabilityListeners = new Set<(d: Dialability) => void>();
  // Hosts this node was explicitly configured to listen on / announce. These are
  // NOT dial-back-confirmed, so they are excluded from dialability — only
  // AutoNAT-confirmed observed addresses count.
  readonly #configuredHosts: ReadonlySet<string>;

  constructor(libp2p: Libp2p, keyProvider: KeyProvider, configuredHosts: ReadonlySet<string>) {
    this.#libp2p = libp2p;
    this.keyProvider = keyProvider;
    this.#configuredHosts = configuredHosts;
    // Recompute dialability whenever libp2p updates its self-reported addresses.
    // AutoNAT verification of an external address triggers a 'self:peer:update'.
    this.#libp2p.addEventListener("self:peer:update", () => {
      this.#recomputeDialability();
    });
  }

  #recomputeDialability(): void {
    const next = deriveDialability(this.listenAddresses(), this.#configuredHosts);
    if (
      next.dialable === this.#dialability.dialable &&
      next.publicAddr === this.#dialability.publicAddr
    ) {
      return; // no change — do not notify
    }
    this.#dialability = next;
    for (const l of this.#dialabilityListeners) l({ ...next });
  }

  getDialability(): Dialability {
    return { ...this.#dialability };
  }

  onDialabilityChange(listener: (d: Dialability) => void): Unsubscribe {
    this.#dialabilityListeners.add(listener);
    return () => {
      this.#dialabilityListeners.delete(listener);
    };
  }

  async start(): Promise<void> {
    await this.#libp2p.start();
  }

  async stop(): Promise<void> {
    await this.#libp2p.stop();
  }

  listenAddresses(): string[] {
    return this.#libp2p.getMultiaddrs().map((ma) => ma.toString());
  }

  async dial(multiaddrStr: string): Promise<{ peerId: string }> {
    if (this.#libp2p.status === "stopped") {
      throw { reason: "node_stopped", message: "Node is stopped" };
    }
    try {
      const ma = multiaddr(multiaddrStr);
      const conn: Connection = await this.#libp2p.dial(ma);
      return { peerId: conn.remotePeer.toString() };
    } catch (err) {
      // Re-throw structured errors as-is
      if (isStructuredError(err)) throw err;
      throw mapDialError(err);
    }
  }

  async handle(protocolId: string, handler: CelloStreamHandler, opts?: { maxInboundStreams?: number }): Promise<void> {
    // libp2p v3 StreamHandler receives (stream, connection); we only need stream
    const streamHandler: StreamHandler = (stream: Stream) => handler(stream);
    // DOD-NAT-REACHABILITY-1: every CELLO protocol must run over a LIMITED relayed
    // connection — a punch-failed session lives on one, and refusing the stream
    // there silently converts "NAT'd but online" into "unreachable" (the mailbox
    // then masks it). There is no CELLO protocol that should refuse a relayed
    // connection, so this is unconditional rather than a per-handler option.
    await this.#libp2p.handle(protocolId, streamHandler, { ...opts, runOnLimitedConnection: true });
  }

  async newStream(peerIdStr: string, protocolId: string): Promise<Stream> {
    if (this.#libp2p.status === "stopped") {
      throw { reason: "node_stopped", message: "Node is stopped" };
    }

    // Look up existing connections to this peer
    let peerId;
    try {
      peerId = peerIdFromString(peerIdStr);
    } catch {
      throw {
        reason: "connection_lost",
        peerId: peerIdStr,
        message: `Invalid peer ID: ${peerIdStr}`,
      };
    }

    const connections = this.#libp2p.getConnections(peerId);
    const openConn = connections.find(
      (c) => c.status === "open"
    );

    if (!openConn) {
      throw {
        reason: "connection_lost",
        peerId: peerIdStr,
        message: `No open connection to peer ${peerIdStr}`,
      };
    }

    try {
      // runOnLimitedConnection: see handle() — the relayed-fallback session must
      // be able to open CELLO streams in both directions.
      const stream = await openConn.newStream(protocolId, { runOnLimitedConnection: true });
      return stream;
    } catch (err) {
      if (isStructuredError(err)) throw err;
      throw mapStreamError(err, peerIdStr, protocolId);
    }
  }

  getPeerId(): string {
    return this.#libp2p.peerId.toString();
  }

  getProtocols(): string[] {
    return this.#libp2p.getProtocols();
  }

  getConnections(): Array<{ peerId: string; encryption: string | undefined }> {
    return this.#libp2p.getConnections().map((c) => ({
      peerId: c.remotePeer.toString(),
      encryption: c.encryption,
    }));
  }

  hasDirectConnectionTo(peerIdStr: string): boolean {
    let peerId;
    try {
      peerId = peerIdFromString(peerIdStr);
    } catch {
      return false;
    }
    return this.#libp2p.getConnections(peerId).some(
      (c) => c.status === "open" && !c.remoteAddr.toString().includes("/p2p-circuit"),
    );
  }

  onPeerConnect(handler: (peerId: string) => void): void {
    this.#libp2p.addEventListener("peer:connect", (evt) => {
      handler(evt.detail.toString());
    });
  }

  onPeerDisconnect(handler: (peerId: string) => void): void {
    this.#libp2p.addEventListener("peer:disconnect", (evt) => {
      handler(evt.detail.toString());
    });
  }
}

// ─── Error helpers ───────────────────────────────────────────────────────────

function isStructuredError(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    "reason" in err &&
    typeof (err as Record<string, unknown>).reason === "string"
  );
}

function mapDialError(err: unknown): unknown {
  const msg = err instanceof Error ? err.message : String(err);
  // Node stopped
  if (msg.includes("stopped") || msg.includes("not started")) {
    return { reason: "node_stopped", message: msg };
  }
  return { reason: "connection_lost", peerId: "unknown", message: msg };
}

function mapStreamError(
  err: unknown,
  peerId: string,
  protocolId: string
): unknown {
  // Check error name first — most reliable signal from libp2p
  if (err instanceof Error && err.name === "UnsupportedProtocolError") {
    return { reason: "protocol_not_supported", protocolId, message: err.message };
  }

  const msg = err instanceof Error ? err.message : String(err);

  // Protocol negotiation failure — match specific phrases, not generic "stream"
  if (
    msg.includes("unsupported protocol") ||
    msg.includes("not supported") ||
    msg.includes("protocol negotiation failed") ||
    msg.includes("multistream")
  ) {
    return { reason: "protocol_not_supported", protocolId, message: msg };
  }

  // Connection-level failure — explicit connection/reset/abort signals
  if (
    msg.includes("reset") ||
    msg.includes("connection closed") ||
    msg.includes("connection reset") ||
    msg.includes("aborted") ||
    msg.includes("connection lost")
  ) {
    return { reason: "connection_lost", peerId, message: msg };
  }

  // Default to connection_lost
  return { reason: "connection_lost", peerId, message: msg };
}

// ─── Factory ─────────────────────────────────────────────────────────────────

/**
 * Create a new CelloNode in stopped state.
 *
 * CRITICAL (ADR-0001 / SI-002):
 * - A fresh libp2p-managed Ed25519 keypair is generated here.
 * - This keypair drives the transport Peer ID and Noise handshake.
 * - keyProvider is stored but NEVER called during createNode() or start().
 * - The node's Peer ID will differ from any PeerId derived from keyProvider.
 *
 * Transport stack:
 *   - Transports: TCP + WebSockets
 *   - Security: Noise ONLY (XX pattern, RFC: https://noiseprotocol.org/noise.html)
 *   - Muxer: Yamux
 *   - Services: identify, circuitRelayServer (advertises HOP), AutoNAT, DCuTR
 *
 * NAT traversal:
 *   - autoNAT() is added to ALL nodes. On client nodes (session / standing
 *     receiver) it probes connected directory nodes for dial-back to determine
 *     dialability; on directory nodes it serves the responder role, answering
 *     dial-back requests. Protocol: /libp2p/autonat/1.0.0.
 *   - dcutr() is included on EVERY node type (DOD-NAT-REACHABILITY-1). The
 *     protocol's inbound peer is the one that STARTS the hole-punch upgrade
 *     (@libp2p/dcutr ignores connections with direction !== 'inbound'), and the
 *     inbound peer of a relayed connection is precisely the standing receiver.
 *     The old exclusion ("a receiver doesn't upgrade connections") had it exactly
 *     backwards and guaranteed the punch could never begin.
 *   - circuitRelayServer (HOP) is a SERVICE-node capability: included when
 *     nodeType is undefined (directory, relay) or when opts.relayServer.enabled
 *     is set. Client nodes (session / standing_receiver) no longer advertise
 *     themselves as relays for strangers.
 */
export async function createNode(opts: CreateNodeOptions): Promise<CelloNode> {
  // HOP relay: service nodes keep it (deployed-relay compatibility); client node
  // types must opt in explicitly via relayServer.
  const includeRelayServer = opts.relayServer?.enabled ?? opts.nodeType === undefined;
  const reservations = opts.relayServer?.reservations;
  // ADR-0001: generate a fresh keypair for libp2p transport identity.
  // keyProvider is intentionally NOT touched here — see SI-002.
  const transportKey = opts.transportPrivateKey
    ? await generateKeyPairFromSeed("Ed25519", opts.transportPrivateKey)
    : await generateKeyPair("Ed25519");

  const libp2p = await createLibp2p({
    start: false,
    privateKey: transportKey,
    addresses: {
      listen: opts.listenAddresses,
      ...(opts.announceAddresses?.length ? { announce: opts.announceAddresses } : {}),
    },
    transports: [
      tcp(),
      webSockets(),
      // Circuit relay transport enables dialing via relay addresses
      circuitRelayTransport(),
    ],
    connectionEncrypters: [
      // Noise ONLY — no plaintext. SI-001.
      // Noise XX pattern per https://noiseprotocol.org/noise.html
      noise(),
    ],
    // Cast: see the AutoNAT note below. yamux links uint8arraylist v2 while
    // libp2p core links v3; adding the AutoNAT service to the service map shifts
    // the inferred Components type so the muxer's Stream type no longer unifies.
    // Runtime interop is unaffected (all libp2p v3.x). Build-time-only.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    streamMuxers: [yamux() as any],
    services: {
      identify: identify(),
      // circuitRelayServer advertises CIRCUIT_RELAY_V2_HOP_PROTOCOL_ID — service
      // nodes only (see header). The relay passes `reservations` to raise
      // maxReservations / drop the default 2-min/128-KiB connection limits.
      ...(includeRelayServer
        ? { relay: circuitRelayServer(reservations ? { reservations } : {}) }
        : {}),
      // AutoNAT (RFC: https://libp2p.io/docs/concepts/nat/autonat/). Client role
      // probes connected directory nodes for dial-back; server role answers
      // probes (directory nodes). Protocol /libp2p/autonat/1.0.0.
      //
      // Cast: @libp2p/autonat@3.0.x links @libp2p/interface@3.2.2 (uint8arraylist
      // v2) while libp2p core links @libp2p/interface@3.2.4 (uint8arraylist v3).
      // The two copies are structurally identical at runtime (same libp2p v3.x
      // wire protocols) but TypeScript treats their Stream/Components types as
      // distinct. The cast erases the version-specific AutoNATComponents param so
      // the service-map inference does not surface this benign duplication. This
      // is a build-time-only concern; runtime interop is unaffected.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      autonat: autoNAT() as any,
      // DOD-NAT-REACHABILITY-1: dcutr on every node — the standing receiver is
      // the inbound side of a relayed connection, and the inbound side starts
      // the upgrade. See the header note.
      dcutr: dcutr(),
    },
    ...(opts.connectionGater ? { connectionGater: opts.connectionGater } : {}),
    // Keepalive ping interval, so a peer that vanished without a clean close is
    // detected within a bounded window. A failed
    // ping aborts the connection (abortConnectionOnPingFailure default true),
    // firing peer:disconnect → counterparty_liveness drives to 'gone'.
    ...(opts.keepAliveIntervalMs !== undefined
      ? { connectionMonitor: { pingInterval: opts.keepAliveIntervalMs } }
      : {}),
  });

  // Record the hosts this node was configured to listen on / announce.
  // deriveDialability excludes these so dialability reflects AutoNAT dial-back
  // confirmation, not configuration.
  const configuredHosts = new Set<string>();
  for (const a of [...opts.listenAddresses, ...(opts.announceAddresses ?? [])]) {
    const host = extractHost(a);
    if (host !== null) configuredHosts.add(host);
  }

  // Return node in STOPPED state — caller must call start()
  return new CelloNodeImpl(libp2p, opts.keyProvider, configuredHosts);
}
